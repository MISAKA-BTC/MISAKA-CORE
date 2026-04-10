// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! CoreThread — single-threaded dispatch wrapper for CoreEngine.
//!
//! Sui equivalent: consensus/core/src/core_thread.rs
//!
//! Ensures all mutations to CoreEngine happen on a single task,
//! eliminating data races. External callers interact via
//! `CoreThreadDispatcher` which sends commands over a channel.
//!
//! # Architecture
//!
//! ```text
//!   External callers                 CoreThread worker
//!        │                                │
//!        ├─ dispatcher.propose().await ──→ CoreCommand::Propose
//!        │                                │→ engine.propose_block()
//!        │                                │← oneshot reply
//!        │← VerifiedBlock ───────────────┘
//!        │
//!        ├─ dispatcher.process().await ──→ CoreCommand::Process
//!        │                                │→ engine.process_block()
//!        │← ProcessResult ───────────────┘
//! ```

use tokio::sync::{mpsc, oneshot};

use super::block_manager::BlockManager;
use super::core_engine::{CoreEngine, ProcessResult, ProposeContext};
use super::dag_state::DagState;
use crate::narwhal_types::block::VerifiedBlock;

/// Commands sent to the CoreThread worker.
pub enum CoreCommand {
    /// Propose a new block.
    Propose {
        context: ProposeContext,
        reply: oneshot::Sender<VerifiedBlock>,
    },
    /// Process an incoming block through the full pipeline.
    Process {
        block: VerifiedBlock,
        reply: oneshot::Sender<ProcessResult>,
    },
    /// Trigger leader timeout handling.
    HandleTimeout {
        round: u32,
        reply: oneshot::Sender<Option<VerifiedBlock>>,
    },
    /// Run a full GC cycle on DAG state.
    RunGc { reply: oneshot::Sender<()> },
    /// Graceful shutdown.
    Shutdown,
}

/// Async dispatcher that sends commands to the CoreThread worker.
///
/// This is the only public API for interacting with CoreEngine from
/// other tasks. All method calls are serialized through the channel.
#[derive(Clone)]
pub struct CoreThreadDispatcher {
    tx: mpsc::Sender<CoreCommand>,
}

impl CoreThreadDispatcher {
    /// Create a new dispatcher from an existing channel sender.
    pub fn new(tx: mpsc::Sender<CoreCommand>) -> Self {
        Self { tx }
    }

    /// Task A: Create a dispatcher that wraps an existing ConsensusMessage channel.
    ///
    /// This bridges the typed CoreCommand API to the existing untyped ConsensusMessage
    /// channel used by the runtime. Commands are translated:
    /// - propose_block → ConsensusMessage::ProposeBlock
    /// - process_block → ConsensusMessage::NewBlock
    /// - shutdown → ConsensusMessage::Shutdown
    pub fn from_consensus_channel(
        msg_tx: tokio::sync::mpsc::Sender<super::runtime::ConsensusMessage>,
    ) -> Self {
        // Create a bridging channel
        let (bridge_tx, mut bridge_rx) = mpsc::channel::<CoreCommand>(256);

        // Spawn a bridge task that translates CoreCommand → ConsensusMessage
        tokio::spawn(async move {
            while let Some(cmd) = bridge_rx.recv().await {
                match cmd {
                    CoreCommand::Propose { context, reply } => {
                        // Send propose via the consensus channel
                        let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                        let _ = msg_tx.try_send(super::runtime::ConsensusMessage::ProposeBlock {
                            context,
                            reply: resp_tx,
                        });
                        // Forward reply
                        if let Ok(block) = resp_rx.await {
                            let _ = reply.send(block);
                        }
                    }
                    CoreCommand::Process { block, reply } => {
                        let _ = msg_tx.try_send(super::runtime::ConsensusMessage::NewBlock(block));
                        // Process is fire-and-forget through the consensus channel
                        let _ = reply.send(super::core_engine::ProcessResult::default());
                    }
                    CoreCommand::Shutdown => {
                        let _ = msg_tx.try_send(super::runtime::ConsensusMessage::Shutdown);
                        break;
                    }
                    _ => {}
                }
            }
        });

        Self { tx: bridge_tx }
    }

    /// Propose a new block. Returns the signed VerifiedBlock.
    pub async fn propose_block(&self, context: ProposeContext) -> Result<VerifiedBlock, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(CoreCommand::Propose {
                context,
                reply: reply_tx,
            })
            .await
            .map_err(|_| "CoreThread worker stopped")?;
        reply_rx
            .await
            .map_err(|_| "CoreThread reply dropped".to_string())
    }

    /// Process an incoming block. Returns the full pipeline result.
    pub async fn process_block(&self, block: VerifiedBlock) -> Result<ProcessResult, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(CoreCommand::Process {
                block,
                reply: reply_tx,
            })
            .await
            .map_err(|_| "CoreThread worker stopped")?;
        reply_rx
            .await
            .map_err(|_| "CoreThread reply dropped".to_string())
    }

    /// Handle a leader timeout.
    pub async fn handle_timeout(&self, round: u32) -> Result<Option<VerifiedBlock>, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(CoreCommand::HandleTimeout {
                round,
                reply: reply_tx,
            })
            .await
            .map_err(|_| "CoreThread worker stopped")?;
        reply_rx
            .await
            .map_err(|_| "CoreThread reply dropped".to_string())
    }

    /// Trigger GC.
    pub async fn run_gc(&self) -> Result<(), String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(CoreCommand::RunGc { reply: reply_tx })
            .await
            .map_err(|_| "CoreThread worker stopped")?;
        reply_rx
            .await
            .map_err(|_| "CoreThread reply dropped".to_string())
    }

    /// Send shutdown signal.
    pub async fn shutdown(&self) -> Result<(), String> {
        self.tx
            .send(CoreCommand::Shutdown)
            .await
            .map_err(|_| "CoreThread already stopped".to_string())
    }
}

/// CoreThread worker configuration.
pub struct CoreThreadConfig {
    /// Channel capacity for commands.
    pub channel_capacity: usize,
}

impl Default for CoreThreadConfig {
    fn default() -> Self {
        Self {
            channel_capacity: 256,
        }
    }
}

/// Spawn the CoreThread worker task.
///
/// Returns a dispatcher for sending commands.
/// The worker owns `CoreEngine` and `DagState` exclusively.
pub fn spawn_core_thread(
    mut engine: CoreEngine,
    mut dag_state: DagState,
    config: CoreThreadConfig,
) -> (CoreThreadDispatcher, tokio::task::JoinHandle<()>) {
    let (tx, mut rx) = mpsc::channel::<CoreCommand>(config.channel_capacity);
    let dispatcher = CoreThreadDispatcher::new(tx);

    let handle = tokio::spawn(async move {
        tracing::info!("CoreThread worker started");
        let mut block_manager = BlockManager::new(engine.committee().clone());
        while let Some(cmd) = rx.recv().await {
            match cmd {
                CoreCommand::Propose { context, reply } => {
                    let block = engine.propose_block(&mut dag_state, context);
                    let _ = reply.send(block);
                }
                CoreCommand::Process { block, reply } => {
                    let result = engine.process_block(block, &mut block_manager, &mut dag_state);
                    let _ = reply.send(result);
                }
                CoreCommand::HandleTimeout { round, reply } => {
                    let block = if let Some((_r, _leader)) = engine.check_leader_timeout() {
                        engine.handle_leader_timeout(&mut dag_state)
                    } else {
                        None
                    };
                    let _ = round;
                    let _ = reply.send(block);
                }
                CoreCommand::RunGc { reply } => {
                    dag_state.full_gc();
                    let _ = reply.send(());
                }
                CoreCommand::Shutdown => {
                    tracing::info!("CoreThread worker shutting down");
                    break;
                }
            }
        }
        tracing::info!("CoreThread worker stopped");
    });

    (dispatcher, handle)
}

#[cfg(test)]
mod tests {
    use super::super::block_verifier::BlockVerifier;
    use super::super::dag_state::DagStateConfig;
    use super::*;
    use crate::narwhal_types::block::MlDsa65Verifier;
    use crate::narwhal_types::block::TestValidatorSet;
    use crate::narwhal_types::committee::Committee;

    fn test_setup() -> (CoreEngine, DagState) {
        let tvs = TestValidatorSet::new(4);
        let committee = tvs.committee();
        let chain_ctx = TestValidatorSet::chain_ctx();
        let verifier = tvs.verifier(0);
        let engine = CoreEngine::new(0, 0, committee.clone(), tvs.signer(0), verifier, chain_ctx);
        let dag = DagState::new(committee, DagStateConfig::default());
        (engine, dag)
    }

    #[tokio::test]
    async fn test_propose_via_dispatcher() {
        let (engine, dag) = test_setup();
        let (dispatcher, handle) = spawn_core_thread(engine, dag, CoreThreadConfig::default());

        let block = dispatcher
            .propose_block(ProposeContext::normal(vec![vec![1, 2, 3]], [0u8; 32]))
            .await;
        assert!(block.is_ok());
        let block = block.unwrap();
        assert_eq!(block.round(), 1);
        assert_eq!(block.author(), 0);

        dispatcher.shutdown().await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_gc_via_dispatcher() {
        let (engine, dag) = test_setup();
        let (dispatcher, handle) = spawn_core_thread(engine, dag, CoreThreadConfig::default());

        let result = dispatcher.run_gc().await;
        assert!(result.is_ok());

        dispatcher.shutdown().await.unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_shutdown() {
        let (engine, dag) = test_setup();
        let (dispatcher, handle) = spawn_core_thread(engine, dag, CoreThreadConfig::default());

        dispatcher.shutdown().await.unwrap();
        // Worker should exit cleanly
        handle.await.unwrap();

        // Further commands should fail
        let result = dispatcher
            .propose_block(ProposeContext::normal(vec![], [0u8; 32]))
            .await;
        assert!(result.is_err());
    }
}
