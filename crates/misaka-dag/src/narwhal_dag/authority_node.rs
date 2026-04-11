// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! AuthorityNode — top-level consensus lifecycle manager.
//!
//! Sui equivalent: `consensus/core/src/authority_node.rs`
//!
//! Encapsulates the full consensus startup, operation, epoch transition,
//! and shutdown sequence. Previously this logic was scattered across
//! `misaka-node/src/main.rs` (4,839 LOC), `narwhal_consensus.rs`,
//! `narwhal_runtime_bridge.rs`, `bft_event_loop.rs`, etc.
//!
//! With AuthorityNode, the node's main.rs reduces to:
//! ```ignore
//! let ctx = Context::new(...);
//! let node = AuthorityNode::start(ctx, store, network).await?;
//! // ... node runs until shutdown signal ...
//! node.stop().await;
//! ```

use std::sync::Arc;
use tokio::sync::watch;
use tracing::{error, info, warn};

use super::block_manager::BlockManager;
use super::block_verifier::BlockVerifier;
use super::commit_finalizer::CommitFinalizerV2;
use super::context::Context;
use super::core_engine::CoreEngine;
use super::dag_state::{DagState, DagStateConfig};
use super::leader_schedule::LeaderSchedule;
use super::metrics::ConsensusMetrics;
use super::runtime::{spawn_consensus_runtime, ConsensusRuntime, RuntimeConfig};
use super::slot_equivocation_ledger::SlotEquivocationLedger;
use super::store::ConsensusStore;
use crate::narwhal_ordering::linearizer::{CommitFinalizer, Linearizer};
use crate::narwhal_ordering::universal_committer::UniversalCommitter;
use crate::narwhal_types::block::*;
use crate::narwhal_types::commit::*;

/// Authority node state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityNodeState {
    /// Node is starting up (loading state, recovering WAL).
    Starting,
    /// Node is running normally (proposing, verifying, committing).
    Running,
    /// Epoch transition in progress.
    EpochTransition,
    /// Node is shutting down gracefully.
    ShuttingDown,
    /// Node has stopped.
    Stopped,
}

/// Configuration for an authority node.
#[derive(Clone, Debug)]
pub struct AuthorityNodeConfig {
    /// Data directory for persistence.
    pub data_dir: std::path::PathBuf,
    /// Consensus runtime configuration.
    pub runtime_config: RuntimeConfig,
    /// Whether to recover state from store on startup.
    pub recover_on_start: bool,
}

/// The top-level consensus orchestrator.
///
/// Owns the consensus runtime, DAG state, store, and all supporting
/// components. Provides a clean API for:
/// - Starting consensus
/// - Stopping gracefully
/// - Epoch transitions
/// - Status queries
pub struct AuthorityNode {
    /// Current consensus context (immutable per epoch).
    context: Context,
    /// Node state.
    state: AuthorityNodeState,
    /// Shutdown signal sender.
    shutdown_tx: watch::Sender<bool>,
    /// Shutdown signal receiver (cloneable).
    shutdown_rx: watch::Receiver<bool>,
    /// Consensus message channel sender.
    msg_tx: Option<tokio::sync::mpsc::Sender<super::runtime::ConsensusMessage>>,
    /// Committed output receiver.
    commit_rx:
        Option<tokio::sync::mpsc::Receiver<crate::narwhal_ordering::linearizer::LinearizedOutput>>,
    /// Block broadcast receiver.
    block_rx: Option<tokio::sync::mpsc::Receiver<VerifiedBlock>>,
    /// Runtime task handle.
    runtime_handle: Option<tokio::task::JoinHandle<()>>,
    /// Metrics.
    metrics: Arc<ConsensusMetrics>,
}

impl AuthorityNode {
    /// Start the authority node.
    ///
    /// This is the main entry point. It:
    /// 1. Creates the DAG state and store
    /// 2. Optionally recovers from persistent state
    /// 3. Spawns the consensus runtime
    /// 4. Returns the running node
    pub async fn start(
        context: Context,
        store: Option<Arc<dyn ConsensusStore>>,
        config: AuthorityNodeConfig,
    ) -> Result<Self, String> {
        info!(
            "AuthorityNode starting: authority={}, epoch={}, committee_size={}",
            context.own_index,
            context.epoch(),
            context.committee_size(),
        );

        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let runtime_config = config.runtime_config.clone();

        // Spawn the consensus runtime
        let (msg_tx, commit_rx, block_rx, metrics, runtime_handle) = spawn_consensus_runtime(
            runtime_config,
            context.signer.clone(),
            store,
            context.chain_ctx.clone(),
        );

        let node = Self {
            context,
            state: AuthorityNodeState::Running,
            shutdown_tx,
            shutdown_rx,
            msg_tx: Some(msg_tx),
            commit_rx: Some(commit_rx),
            block_rx: Some(block_rx),
            runtime_handle: Some(runtime_handle),
            metrics,
        };

        info!("AuthorityNode started successfully");
        Ok(node)
    }

    /// Stop the authority node gracefully.
    pub async fn stop(&mut self) {
        if self.state == AuthorityNodeState::Stopped {
            return;
        }

        info!("AuthorityNode stopping...");
        self.state = AuthorityNodeState::ShuttingDown;

        // Signal shutdown
        let _ = self.shutdown_tx.send(true);

        // Send shutdown to consensus runtime
        if let Some(msg_tx) = &self.msg_tx {
            let _ = msg_tx.try_send(super::runtime::ConsensusMessage::Shutdown);
        }

        // Wait for runtime to finish
        if let Some(handle) = self.runtime_handle.take() {
            match tokio::time::timeout(std::time::Duration::from_secs(30), handle).await {
                Ok(Ok(())) => info!("Consensus runtime stopped cleanly"),
                Ok(Err(e)) => error!("Consensus runtime panicked: {}", e),
                Err(_) => warn!("Consensus runtime shutdown timed out after 30s"),
            }
        }

        self.state = AuthorityNodeState::Stopped;
        info!("AuthorityNode stopped");
    }

    /// Execute an epoch transition.
    ///
    /// Builds a new Context for the next epoch and restarts the
    /// consensus runtime with the new committee.
    pub async fn transition_epoch(
        &mut self,
        new_context: Context,
        store: Option<Arc<dyn ConsensusStore>>,
        config: AuthorityNodeConfig,
    ) -> Result<(), String> {
        let old_epoch = self.context.epoch();
        let new_epoch = new_context.epoch();

        info!(
            "AuthorityNode: epoch transition {} → {}",
            old_epoch, new_epoch
        );

        self.state = AuthorityNodeState::EpochTransition;

        // Stop the current runtime
        self.stop().await;

        // Start with the new context
        let mut new_node = Self::start(new_context, store, config).await?;

        // Swap fields from new_node into self.
        // Mark new_node as Stopped so its Drop doesn't try to shutdown.
        self.context = new_node.context.clone();
        self.state = std::mem::replace(&mut new_node.state, AuthorityNodeState::Stopped);
        self.shutdown_tx = std::mem::replace(&mut new_node.shutdown_tx, watch::channel(true).0);
        self.shutdown_rx = std::mem::replace(&mut new_node.shutdown_rx, watch::channel(true).1);
        self.msg_tx = new_node.msg_tx.take();
        self.commit_rx = new_node.commit_rx.take();
        self.block_rx = new_node.block_rx.take();
        self.runtime_handle = new_node.runtime_handle.take();
        self.metrics = new_node.metrics.clone();

        info!(
            "AuthorityNode: epoch transition complete, now running epoch {}",
            new_epoch
        );

        Ok(())
    }

    /// Get the current node state.
    pub fn state(&self) -> AuthorityNodeState {
        self.state
    }

    /// Get the current context.
    pub fn context(&self) -> &Context {
        &self.context
    }

    /// Get a clone of the shutdown receiver (for other components to watch).
    pub fn shutdown_receiver(&self) -> watch::Receiver<bool> {
        self.shutdown_rx.clone()
    }

    /// Take the commit receiver (can only be taken once).
    pub fn take_commit_rx(
        &mut self,
    ) -> Option<tokio::sync::mpsc::Receiver<crate::narwhal_ordering::linearizer::LinearizedOutput>>
    {
        self.commit_rx.take()
    }

    /// Take the block broadcast receiver (can only be taken once).
    pub fn take_block_rx(&mut self) -> Option<tokio::sync::mpsc::Receiver<VerifiedBlock>> {
        self.block_rx.take()
    }

    /// Get the consensus message sender (for submitting blocks from peers).
    pub fn msg_sender(
        &self,
    ) -> Option<&tokio::sync::mpsc::Sender<super::runtime::ConsensusMessage>> {
        self.msg_tx.as_ref()
    }

    /// Get shared metrics.
    pub fn metrics(&self) -> &Arc<ConsensusMetrics> {
        &self.metrics
    }
}

impl Drop for AuthorityNode {
    fn drop(&mut self) {
        if self.state != AuthorityNodeState::Stopped {
            warn!("AuthorityNode dropped without explicit stop()");
            let _ = self.shutdown_tx.send(true);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_authority_node_start_stop() {
        let ctx = Context::new_for_test(4);
        let config = AuthorityNodeConfig {
            data_dir: std::path::PathBuf::from("/tmp/test-authority-node"),
            runtime_config: RuntimeConfig {
                committee: (*ctx.committee).clone(),
                authority_index: ctx.own_index,
                leader_round_wave: 2,
                timeout_base_ms: 60_000,
                timeout_max_ms: 120_000,
                dag_config: DagStateConfig::default(),
                checkpoint_interval: 100,
                custom_verifier: Some(ctx.sig_verifier.clone()),
                retention_rounds: 0,
            },
            recover_on_start: false,
        };

        let mut node = AuthorityNode::start(ctx, None, config).await.unwrap();
        assert_eq!(node.state(), AuthorityNodeState::Running);
        assert!(node.msg_sender().is_some());

        node.stop().await;
        assert_eq!(node.state(), AuthorityNodeState::Stopped);
    }

    #[tokio::test]
    async fn test_epoch_transition() {
        let ctx_epoch0 = Context::new_for_test(4);
        let config = AuthorityNodeConfig {
            data_dir: std::path::PathBuf::from("/tmp/test-epoch-transition"),
            runtime_config: RuntimeConfig {
                committee: (*ctx_epoch0.committee).clone(),
                authority_index: ctx_epoch0.own_index,
                leader_round_wave: 2,
                timeout_base_ms: 60_000,
                timeout_max_ms: 120_000,
                dag_config: DagStateConfig::default(),
                checkpoint_interval: 100,
                custom_verifier: Some(ctx_epoch0.sig_verifier.clone()),
                retention_rounds: 0,
            },
            recover_on_start: false,
        };

        let mut node = AuthorityNode::start(ctx_epoch0, None, config.clone())
            .await
            .unwrap();
        assert_eq!(node.context().epoch(), 0);

        // Transition to epoch 1
        let ctx_epoch1 = Context::new_for_test(4);
        node.transition_epoch(ctx_epoch1, None, config)
            .await
            .unwrap();
        assert_eq!(node.state(), AuthorityNodeState::Running);

        node.stop().await;
    }

    #[tokio::test]
    async fn test_graceful_shutdown_via_drop() {
        let ctx = Context::new_for_test(4);
        let config = AuthorityNodeConfig {
            data_dir: std::path::PathBuf::from("/tmp/test-drop"),
            runtime_config: RuntimeConfig {
                committee: (*ctx.committee).clone(),
                authority_index: ctx.own_index,
                leader_round_wave: 2,
                timeout_base_ms: 60_000,
                timeout_max_ms: 120_000,
                dag_config: DagStateConfig::default(),
                checkpoint_interval: 100,
                custom_verifier: Some(ctx.sig_verifier.clone()),
                retention_rounds: 0,
            },
            recover_on_start: false,
        };

        let node = AuthorityNode::start(ctx, None, config).await.unwrap();
        // Drop without explicit stop() — should warn but not panic
        drop(node);
    }
}
