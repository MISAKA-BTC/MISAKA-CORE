// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! ConsensusRuntime — async event loop for Narwhal/Bullshark.
//!
//! Sui equivalent: consensus/core/core_thread.rs (~500 lines)
//!
//! Drives the consensus engine via tokio channels:
//! - Receives blocks from network
//! - Proposes blocks on round advancement
//! - Emits committed transactions for execution
//! - Handles timeouts for liveness

use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

use super::block_manager::{AncestorFetchRequest, BlockAcceptResult, BlockManager};
use super::core_engine::{CoreEngine, ProcessResult, ProposeContext};
use super::dag_state::{DagState, DagStateConfig};
use super::leader_schedule::{LeaderSchedule, ThresholdClock, TimeoutBackoff};
use super::metrics::ConsensusMetrics;
use super::store::ConsensusStore;
use crate::narwhal_ordering::linearizer::{CommitFinalizer, LinearizedOutput, Linearizer};
use crate::narwhal_ordering::universal_committer::UniversalCommitter;
use crate::narwhal_types::block::*;
use crate::narwhal_types::commit::CommittedSubDag;
use crate::narwhal_types::committee::Committee;

/// Messages sent to the consensus runtime.
#[derive(Debug)]
pub enum ConsensusMessage {
    /// A verified block received from a peer.
    NewBlock(VerifiedBlock),
    /// A verified block received from a peer where the caller needs
    /// accept/fetch outcomes back for network synchronization.
    ProcessNetworkBlock {
        block: VerifiedBlock,
        reply: oneshot::Sender<NetworkBlockOutcome>,
    },
    /// Request to propose a new block with these transactions.
    ProposeBlock {
        context: ProposeContext,
        reply: oneshot::Sender<VerifiedBlock>,
    },
    /// Force round advancement (timeout).
    RoundTimeout,
    /// Request current status.
    GetStatus(oneshot::Sender<ConsensusStatus>),
    /// Graceful shutdown.
    Shutdown,
}

/// Consensus status snapshot.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ConsensusStatus {
    pub current_round: Round,
    pub highest_accepted_round: Round,
    pub num_blocks: usize,
    pub num_commits: usize,
    pub num_suspended: usize,
    pub last_commit_index: Option<u64>,
}

/// Network-facing outcome for a processed peer block.
#[derive(Clone, Debug)]
pub struct NetworkBlockOutcome {
    pub accepted: Vec<BlockRef>,
    pub fetch_requests: Vec<AncestorFetchRequest>,
    pub highest_accepted_round: Round,
}

/// Configuration for the consensus runtime.
#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    /// Committee for the current epoch.
    pub committee: Committee,
    /// Our authority index.
    pub authority_index: AuthorityIndex,
    /// Leader round wave (standard = 2).
    pub leader_round_wave: u32,
    /// Round timeout base (ms).
    pub timeout_base_ms: u64,
    /// Round timeout max (ms).
    pub timeout_max_ms: u64,
    /// DAG state config.
    pub dag_config: DagStateConfig,
    /// Checkpoint interval (commits).
    pub checkpoint_interval: u64,
    /// Optional custom verifier (for tests). If None, uses MlDsa65Verifier.
    pub custom_verifier: Option<Arc<dyn SignatureVerifier>>,
}

/// The async consensus runtime.
///
/// Owns all consensus state and processes messages from a channel.
pub struct ConsensusRuntime {
    /// Core engine.
    core: CoreEngine,
    /// DAG state.
    dag_state: DagState,
    /// Block manager.
    block_manager: BlockManager,
    /// Universal committer.
    committer: UniversalCommitter,
    /// Linearizer.
    linearizer: Linearizer,
    /// Commit finalizer.
    commit_finalizer: CommitFinalizer,
    /// Threshold clock.
    threshold_clock: ThresholdClock,
    /// Timeout backoff.
    timeout: TimeoutBackoff,
    /// Committee.
    committee: Committee,
    /// Configuration.
    config: RuntimeConfig,
    /// Persistence store.
    store: Option<Arc<dyn ConsensusStore>>,
    /// Consensus metrics (shared for Prometheus export).
    metrics: Arc<ConsensusMetrics>,
    /// Channel to send committed outputs (bounded for backpressure).
    commit_tx: mpsc::Sender<LinearizedOutput>,
    /// Channel to broadcast proposed blocks (bounded for backpressure).
    block_broadcast_tx: mpsc::Sender<VerifiedBlock>,
}

struct ProcessedIncomingBlock {
    outputs: Vec<LinearizedOutput>,
    outcome: NetworkBlockOutcome,
}

impl ConsensusRuntime {
    /// Create a new runtime.
    pub fn new(
        config: RuntimeConfig,
        signer: Arc<dyn BlockSigner>,
        store: Option<Arc<dyn ConsensusStore>>,
        metrics: Arc<ConsensusMetrics>,
        commit_tx: mpsc::Sender<LinearizedOutput>,
        block_broadcast_tx: mpsc::Sender<VerifiedBlock>,
        chain_ctx: misaka_types::chain_context::ChainContext,
    ) -> Self {
        let committee = config.committee.clone();
        let leader_schedule = LeaderSchedule::new(committee.clone(), 1);

        // Build block verifier (production: MlDsa65Verifier, tests: custom)
        let sig_verifier: Arc<dyn SignatureVerifier> = config
            .custom_verifier
            .clone()
            .unwrap_or_else(|| Arc::new(crate::narwhal_types::block::MlDsa65Verifier));
        let verifier = super::block_verifier::BlockVerifier::new(
            committee.clone(),
            committee.epoch,
            sig_verifier,
            chain_ctx.clone(),
        );

        let mut core = CoreEngine::new(
            config.authority_index,
            committee.epoch,
            committee.clone(),
            signer,
            verifier,
            chain_ctx,
        );
        core.set_metrics(metrics.clone());

        Self {
            core,
            dag_state: DagState::new(committee.clone(), config.dag_config.clone()),
            block_manager: BlockManager::new(committee.clone()),
            committer: UniversalCommitter::new(
                committee.clone(),
                leader_schedule,
                1,
                config.leader_round_wave,
            ),
            linearizer: Linearizer::new(),
            commit_finalizer: CommitFinalizer::new(),
            threshold_clock: ThresholdClock::new(committee.clone()),
            timeout: TimeoutBackoff::new(config.timeout_base_ms, config.timeout_max_ms),
            committee,
            config,
            store,
            metrics,
            commit_tx,
            block_broadcast_tx,
        }
    }

    /// Run the consensus event loop.
    ///
    /// Processes messages from `msg_rx` until shutdown.
    pub async fn run(mut self, mut msg_rx: mpsc::Receiver<ConsensusMessage>) {
        info!(
            "Consensus runtime started (authority={}, committee={})",
            self.config.authority_index,
            self.config.committee.size()
        );

        let mut commits_since_checkpoint = 0u64;

        loop {
            let timeout_ms = self.timeout.timeout_ms();
            let timeout_duration = tokio::time::Duration::from_millis(timeout_ms);

            tokio::select! {
                msg = msg_rx.recv() => {
                    match msg {
                        Some(ConsensusMessage::NewBlock(block)) => {
                            let processed = self.process_incoming_block(block);
                            let outputs = processed.outputs;
                            commits_since_checkpoint += outputs.len() as u64;
                            for output in &outputs {
                                ConsensusMetrics::inc(&self.metrics.transactions_committed);
                            }
                            for output in outputs {
                                match self.commit_tx.try_send(output) {
                                    Ok(()) => {}
                                    Err(mpsc::error::TrySendError::Full(_)) => {
                                        warn!("Commit channel full — backpressure");
                                    }
                                    Err(mpsc::error::TrySendError::Closed(_)) => {
                                        warn!("Commit channel closed");
                                    }
                                }
                            }

                            // Update DAG gauge metrics
                            ConsensusMetrics::set(&self.metrics.dag_size_blocks, self.dag_state.num_blocks() as u64);
                            ConsensusMetrics::set(&self.metrics.dag_suspended_blocks, self.block_manager.num_suspended() as u64);
                            ConsensusMetrics::set(&self.metrics.highest_accepted_round, self.dag_state.highest_accepted_round() as u64);

                            // Periodic checkpoint
                            if commits_since_checkpoint >= self.config.checkpoint_interval {
                                self.flush_to_store();
                                ConsensusMetrics::inc(&self.metrics.store_checkpoints);
                                commits_since_checkpoint = 0;
                            }
                        }
                        Some(ConsensusMessage::ProcessNetworkBlock { block, reply }) => {
                            let processed = self.process_incoming_block(block);
                            commits_since_checkpoint += processed.outputs.len() as u64;
                            for output in &processed.outputs {
                                ConsensusMetrics::inc(&self.metrics.transactions_committed);
                            }
                            for output in processed.outputs {
                                match self.commit_tx.try_send(output) {
                                    Ok(()) => {}
                                    Err(mpsc::error::TrySendError::Full(_)) => {
                                        warn!("Commit channel full — backpressure");
                                    }
                                    Err(mpsc::error::TrySendError::Closed(_)) => {
                                        warn!("Commit channel closed");
                                    }
                                }
                            }

                            ConsensusMetrics::set(&self.metrics.dag_size_blocks, self.dag_state.num_blocks() as u64);
                            ConsensusMetrics::set(&self.metrics.dag_suspended_blocks, self.block_manager.num_suspended() as u64);
                            ConsensusMetrics::set(&self.metrics.highest_accepted_round, self.dag_state.highest_accepted_round() as u64);

                            if commits_since_checkpoint >= self.config.checkpoint_interval {
                                self.flush_to_store();
                                ConsensusMetrics::inc(&self.metrics.store_checkpoints);
                                commits_since_checkpoint = 0;
                            }

                            let _ = reply.send(processed.outcome);
                        }
                        Some(ConsensusMessage::ProposeBlock { context, reply }) => {
                            let (block, post_propose) = self.handle_propose(context);
                            ConsensusMetrics::inc(&self.metrics.blocks_proposed);
                            // Broadcast to peers
                            match self.block_broadcast_tx.try_send(block.clone()) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    warn!("Block broadcast channel full");
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    warn!("Block broadcast channel closed");
                                }
                            }
                            // Drain any commits produced by the post-propose
                            // commit cycle. This is how a single-validator
                            // node makes progress: there is no P2P loopback,
                            // so `process_block` is never called on our own
                            // blocks — we must drive the commit cycle here.
                            commits_since_checkpoint += post_propose.outputs.len() as u64;
                            for _ in &post_propose.outputs {
                                ConsensusMetrics::inc(
                                    &self.metrics.transactions_committed,
                                );
                            }
                            for output in post_propose.outputs {
                                match self.commit_tx.try_send(output) {
                                    Ok(()) => {}
                                    Err(mpsc::error::TrySendError::Full(_)) => {
                                        warn!("Commit channel full — backpressure");
                                    }
                                    Err(mpsc::error::TrySendError::Closed(_)) => {
                                        warn!("Commit channel closed");
                                    }
                                }
                            }
                            ConsensusMetrics::set(
                                &self.metrics.dag_size_blocks,
                                self.dag_state.num_blocks() as u64,
                            );
                            ConsensusMetrics::set(
                                &self.metrics.highest_accepted_round,
                                self.dag_state.highest_accepted_round() as u64,
                            );
                            if commits_since_checkpoint >= self.config.checkpoint_interval {
                                self.flush_to_store();
                                ConsensusMetrics::inc(&self.metrics.store_checkpoints);
                                commits_since_checkpoint = 0;
                            }
                            let _ = reply.send(block);
                        }
                        Some(ConsensusMessage::RoundTimeout) => {
                            self.timeout.record_timeout();
                            ConsensusMetrics::inc(&self.metrics.round_timeouts);
                            debug!("Round timeout (backoff: {}ms)", self.timeout.timeout_ms());
                        }
                        Some(ConsensusMessage::GetStatus(reply)) => {
                            let status = self.get_status();
                            let _ = reply.send(status);
                        }
                        Some(ConsensusMessage::Shutdown) | None => {
                            info!("Consensus runtime shutting down");
                            self.flush_to_store();
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(timeout_duration) => {
                    self.timeout.record_timeout();
                    debug!(
                        "Round {} timeout ({}ms)",
                        self.threshold_clock.current_round(),
                        timeout_ms
                    );
                }
            }
        }

        info!("Consensus runtime stopped");
    }

    /// Handle a new block from the network.
    ///
    /// Delegates to CoreEngine::process_block() which runs the full pipeline:
    /// verify → accept → commit → linearize → finalize
    fn process_incoming_block(&mut self, block: VerifiedBlock) -> ProcessedIncomingBlock {
        // CoreEngine handles the full pipeline
        let result = self
            .core
            .process_block(block, &mut self.block_manager, &mut self.dag_state);
        self.threshold_clock.set_round(self.core.current_round());

        // Persist write batch
        if let Some(store) = &self.store {
            let batch = self.dag_state.take_write_batch();
            if !batch.is_empty() {
                match store.write_batch(&batch) {
                    Ok(()) => ConsensusMetrics::inc(&self.metrics.wal_writes),
                    Err(e) => {
                        ConsensusMetrics::inc(&self.metrics.wal_write_errors);
                        error!("Failed to persist write batch: {}", e);
                    }
                }
            }
        }

        let accepted = result
            .accepted
            .iter()
            .map(VerifiedBlock::reference)
            .collect();
        let fetch_requests = self.block_manager.take_fetch_requests();
        let highest_accepted_round = self.dag_state.highest_accepted_round();

        ProcessedIncomingBlock {
            outputs: result.outputs,
            outcome: NetworkBlockOutcome {
                accepted,
                fetch_requests,
                highest_accepted_round,
            },
        }
    }

    /// Handle a proposal request.
    ///
    /// Returns the proposed block and the result of the post-propose commit
    /// cycle. `propose_block` already self-accepts the block into `dag_state`
    /// and updates the threshold clock, so we only need to drive the commit
    /// pipeline (steps 4–6 of `process_block`) here. Running the full
    /// `process_block` would hit the `BlockAcceptResult::Duplicate` early
    /// return because the block is already in `dag_state`.
    fn handle_propose(
        &mut self,
        context: ProposeContext,
    ) -> (VerifiedBlock, ProcessResult) {
        let block = self.core.propose_block(&mut self.dag_state, context);
        self.threshold_clock.set_round(self.core.current_round());
        let mut post_propose = ProcessResult::default();
        self.core
            .run_commit_cycle(&mut self.dag_state, &mut post_propose);
        self.threshold_clock.set_round(self.core.current_round());
        // Persist any DagState writes produced by the commit cycle.
        if let Some(store) = &self.store {
            let batch = self.dag_state.take_write_batch();
            if !batch.is_empty() {
                match store.write_batch(&batch) {
                    Ok(()) => ConsensusMetrics::inc(&self.metrics.wal_writes),
                    Err(e) => {
                        ConsensusMetrics::inc(&self.metrics.wal_write_errors);
                        error!("Failed to persist write batch after propose: {}", e);
                    }
                }
            }
        }
        (block, post_propose)
    }

    /// Flush pending writes to store.
    fn flush_to_store(&mut self) {
        if let Some(store) = &self.store {
            let batch = self.dag_state.take_write_batch();
            if !batch.is_empty() {
                if let Err(e) = store.write_batch(&batch) {
                    error!("Failed to flush to store: {}", e);
                }
            }
        }
    }

    /// Get current consensus status.
    fn get_status(&self) -> ConsensusStatus {
        ConsensusStatus {
            current_round: self.core.current_round(),
            highest_accepted_round: self.dag_state.highest_accepted_round(),
            num_blocks: self.dag_state.num_blocks(),
            num_commits: self.dag_state.num_commits(),
            num_suspended: self.block_manager.num_suspended(),
            last_commit_index: self.dag_state.last_commit_index(),
        }
    }
}

/// Channel capacity for bounded channels.
pub const COMMIT_CHANNEL_CAPACITY: usize = 1000;
pub const BLOCK_BROADCAST_CHANNEL_CAPACITY: usize = 500;
/// SEC-FIX: Consensus message channel capacity. Previously unbounded,
/// allowing OOM DoS via forged block spam. Now bounded to prevent
/// memory exhaustion. When full, new blocks from peers are dropped
/// (the peer should retry or be scored down).
pub const CONSENSUS_MSG_CHANNEL_CAPACITY: usize = 10_000;

/// Convenience: spawn the runtime as a tokio task.
///
/// Returns:
/// - msg_tx: send messages to the runtime (bounded, SEC-FIX: prevents OOM DoS)
/// - commit_rx: receive committed outputs (bounded, backpressure)
/// - block_rx: receive proposed blocks for broadcast (bounded, backpressure)
/// - metrics: shared metrics for Prometheus export
/// - handle: JoinHandle for the runtime task
///
/// Task A: Also returns a `CoreThreadDispatcher` that wraps the msg_tx channel,
/// providing typed async methods for external callers (narwhal_runtime_bridge).
pub fn spawn_consensus_runtime(
    config: RuntimeConfig,
    signer: Arc<dyn BlockSigner>,
    store: Option<Arc<dyn ConsensusStore>>,
    chain_ctx: misaka_types::chain_context::ChainContext,
) -> (
    mpsc::Sender<ConsensusMessage>,
    mpsc::Receiver<LinearizedOutput>,
    mpsc::Receiver<VerifiedBlock>,
    Arc<ConsensusMetrics>,
    tokio::task::JoinHandle<()>,
) {
    // SEC-FIX CRITICAL: Verify WAL store is provided in production.
    // Without WAL, crash recovery loses all commits since last snapshot,
    // causing UTXO/consensus state divergence.
    if store.is_none() {
        tracing::error!(
            "CONSENSUS RUNTIME: WAL store is None — crash recovery will be impossible! \
             This is acceptable ONLY in tests. Production MUST provide a WAL store."
        );
        #[cfg(not(test))]
        {
            // In non-test builds, check if this is a test context via env var
            if std::env::var("MISAKA_ALLOW_NO_WAL").is_err() {
                panic!(
                    "FATAL: Consensus runtime started without WAL store. \
                     Set MISAKA_ALLOW_NO_WAL=1 to override (testing only)."
                );
            }
        }
    }

    let (msg_tx, msg_rx) = mpsc::channel(CONSENSUS_MSG_CHANNEL_CAPACITY);
    let (commit_tx, commit_rx) = mpsc::channel(COMMIT_CHANNEL_CAPACITY);
    let (block_tx, block_rx) = mpsc::channel(BLOCK_BROADCAST_CHANNEL_CAPACITY);
    let metrics = Arc::new(ConsensusMetrics::new());

    let runtime = ConsensusRuntime::new(
        config,
        signer,
        store,
        metrics.clone(),
        commit_tx,
        block_tx,
        chain_ctx,
    );
    let handle = tokio::spawn(async move {
        runtime.run(msg_rx).await;
    });

    (msg_tx, commit_rx, block_rx, metrics, handle)
}

/// Task A: Convenience wrapper that also returns a CoreThreadDispatcher.
///
/// The dispatcher provides typed async methods (propose_block, process_block, etc.)
/// that serialize through the same msg_tx channel. External callers (narwhal_runtime_bridge)
/// should prefer this over raw ConsensusMessage sending.
pub fn spawn_consensus_runtime_with_dispatcher(
    config: RuntimeConfig,
    signer: Arc<dyn BlockSigner>,
    store: Option<Arc<dyn ConsensusStore>>,
    chain_ctx: misaka_types::chain_context::ChainContext,
) -> (
    super::core_thread::CoreThreadDispatcher,
    mpsc::Receiver<LinearizedOutput>,
    mpsc::Receiver<VerifiedBlock>,
    Arc<ConsensusMetrics>,
    tokio::task::JoinHandle<()>,
) {
    let (msg_tx, commit_rx, block_rx, metrics, handle) =
        spawn_consensus_runtime(config, signer, store, chain_ctx);

    // Wrap msg_tx in a typed dispatcher
    let dispatcher = super::core_thread::CoreThreadDispatcher::from_consensus_channel(msg_tx);

    (dispatcher, commit_rx, block_rx, metrics, handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(committee_size: usize) -> RuntimeConfig {
        RuntimeConfig {
            committee: Committee::new_for_test(committee_size),
            authority_index: 0,
            leader_round_wave: 2,
            timeout_base_ms: 2000,
            timeout_max_ms: 60_000,
            dag_config: DagStateConfig::default(),
            checkpoint_interval: 100,
            // Use MlDsa65Verifier in tests (production verification path)
            custom_verifier: Some(Arc::new(MlDsa65Verifier)),
        }
    }

    #[tokio::test]
    async fn test_runtime_shutdown() {
        let config = test_config(4);
        let signer: Arc<dyn BlockSigner> = Arc::new(MlDsa65TestSigner::generate());
        let (msg_tx, commit_rx, _block_rx, _metrics, handle) =
            spawn_consensus_runtime(config, signer, None, TestValidatorSet::chain_ctx());

        msg_tx.try_send(ConsensusMessage::Shutdown).unwrap();

        tokio::time::timeout(tokio::time::Duration::from_secs(5), handle)
            .await
            .expect("runtime didn't shut down")
            .unwrap();

        drop(commit_rx);
    }

    #[tokio::test]
    async fn test_runtime_status() {
        let config = test_config(4);
        let signer: Arc<dyn BlockSigner> = Arc::new(MlDsa65TestSigner::generate());
        let (msg_tx, _commit_rx, _block_rx, _metrics, handle) =
            spawn_consensus_runtime(config, signer, None, TestValidatorSet::chain_ctx());

        let (reply_tx, reply_rx) = oneshot::channel();
        msg_tx.try_send(ConsensusMessage::GetStatus(reply_tx)).unwrap();

        let status = reply_rx.await.unwrap();
        assert_eq!(status.current_round, 0);
        assert_eq!(status.num_blocks, 0);
        assert_eq!(status.num_commits, 0);

        msg_tx.try_send(ConsensusMessage::Shutdown).unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_runtime_propose_and_process() {
        let mut config = test_config(4);
        config.timeout_base_ms = 60_000; // long timeout to avoid interference
        let signer: Arc<dyn BlockSigner> = Arc::new(MlDsa65TestSigner::generate());
        let (msg_tx, _commit_rx, mut block_rx, metrics, handle) =
            spawn_consensus_runtime(config, signer, None, TestValidatorSet::chain_ctx());

        // Propose a block
        let (reply_tx, reply_rx) = oneshot::channel();
        msg_tx
            .try_send(ConsensusMessage::ProposeBlock {
                context: ProposeContext::normal(vec![vec![1, 2, 3]], [0u8; 32]),
                reply: reply_tx,
            })
            .unwrap();

        let block = reply_rx.await.unwrap();
        assert_eq!(block.round(), 1);
        assert_eq!(block.author(), 0);
        assert_eq!(block.transactions().len(), 1);

        // Should also receive the block on broadcast channel
        let broadcast = block_rx.recv().await.unwrap();
        assert_eq!(broadcast.round(), 1);

        // Verify metrics were updated
        assert!(ConsensusMetrics::get(&metrics.blocks_proposed) >= 1);

        msg_tx.try_send(ConsensusMessage::Shutdown).unwrap();
        handle.await.unwrap();
    }
}
