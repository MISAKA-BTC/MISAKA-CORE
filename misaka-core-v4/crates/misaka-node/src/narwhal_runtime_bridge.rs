// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Narwhal Runtime Bridge — integrates Narwhal consensus into the node.
//!
//! Replaces GhostDAG as the sole consensus engine. Bridges between
//! the async consensus runtime and the node's existing subsystems:
//!
//! ```text
//!  ┌───────────────────────────────────────────────────────────┐
//!  │                     Node Runtime                          │
//!  │                                                           │
//!  │  ┌──────────┐   ┌─────────────────┐   ┌──────────────┐  │
//!  │  │ RPC/HTTP │──▶│ NarwhalBridge   │──▶│ UTXO State   │  │
//!  │  │ Endpoints│   │                 │   │ Manager      │  │
//!  │  └──────────┘   │ propose()       │   └──────────────┘  │
//!  │                  │ submit_block()  │                      │
//!  │  ┌──────────┐   │ get_status()    │   ┌──────────────┐  │
//!  │  │ P2P Net  │──▶│ subscribe()     │──▶│ Checkpoint   │  │
//!  │  │          │   │                 │   │ Finality     │  │
//!  │  └──────────┘   └───────┬─────────┘   └──────────────┘  │
//!  │                         │                                 │
//!  │                         ▼                                 │
//!  │              ConsensusRuntime (tokio)                      │
//!  │              ┌─────────────────────┐                      │
//!  │              │ CoreEngine          │                      │
//!  │              │ DagState            │                      │
//!  │              │ UniversalCommitter  │                      │
//!  │              │ Linearizer          │                      │
//!  │              │ WAL + Store         │                      │
//!  │              └─────────────────────┘                      │
//!  └───────────────────────────────────────────────────────────┘
//! ```

#[cfg(feature = "dag")]
use std::sync::Arc;
#[cfg(feature = "dag")]
use tokio::sync::{mpsc, oneshot, RwLock};
#[cfg(feature = "dag")]
use tracing::{error, info, warn};

#[cfg(feature = "dag")]
use misaka_dag::{
    narwhal_dag::runtime::{
        ConsensusMessage, ConsensusStatus, RuntimeConfig, spawn_consensus_runtime,
    },
    narwhal_dag::rocksdb_store::RocksDbConsensusStore,
    narwhal_dag::metrics::ConsensusMetrics,
    narwhal_dag::prometheus::PrometheusExporter,
    narwhal_dag::epoch::{EpochManager, build_committee},
    narwhal_dag::core_engine::ProposeContext,
    narwhal_ordering::linearizer::LinearizedOutput,
    Committee, VerifiedBlock, NarwhalBlock,
    narwhal_types::block::BlockSigner,
};

/// Narwhal runtime bridge — main integration point.
///
/// Replaces GhostDAG in main.rs. All node subsystems interact
/// with consensus through this bridge.
#[cfg(feature = "dag")]
pub struct NarwhalBridge {
    /// Channel to send messages to the consensus runtime.
    msg_tx: mpsc::Sender<ConsensusMessage>,
    /// Receiver for committed transactions (from linearizer).
    commit_rx: mpsc::Receiver<LinearizedOutput>,
    /// Receiver for blocks to broadcast.
    block_rx: mpsc::Receiver<VerifiedBlock>,
    /// Shared metrics for Prometheus export.
    metrics: Arc<ConsensusMetrics>,
    /// Runtime task handle.
    runtime_handle: tokio::task::JoinHandle<()>,
    /// Epoch manager.
    epoch_manager: EpochManager,
    /// Prometheus exporter.
    prometheus: PrometheusExporter,
}

#[cfg(feature = "dag")]
impl NarwhalBridge {
    /// Initialize the Narwhal consensus engine.
    ///
    /// This replaces `GhostDagEngine::new()` + `DagStateManager` in main.rs.
    pub fn init(
        data_dir: &std::path::Path,
        committee: Committee,
        authority_index: u32,
        signer: Arc<dyn BlockSigner>,
        chain_ctx: misaka_types::chain_context::ChainContext,
    ) -> Result<Self, anyhow::Error> {
        // Create persistence store (RocksDB — production default since Phase 1)
        let store_path = data_dir.join("narwhal_consensus");
        let store = RocksDbConsensusStore::open(&store_path)?;
        let store: Arc<dyn misaka_dag::narwhal_dag::store::ConsensusStore> = Arc::new(store);

        // Build runtime config
        let config = RuntimeConfig {
            committee: committee.clone(),
            authority_index,
            leader_round_wave: 2,
            timeout_base_ms: 2000,
            timeout_max_ms: 60_000,
            dag_config: misaka_dag::DagStateConfig::default(),
            checkpoint_interval: 100,
            custom_verifier: None, // use default MlDsa65Verifier
        };

        // Spawn consensus runtime
        let (msg_tx, commit_rx, block_rx, metrics, runtime_handle) =
            spawn_consensus_runtime(config, signer, Some(store), chain_ctx);

        // Epoch manager
        let epoch_manager = EpochManager::new(committee.epoch, committee.clone());

        // Prometheus exporter
        let prometheus = PrometheusExporter::new(metrics.clone())
            .with_label("authority", &authority_index.to_string());

        info!(
            "╔═══════════════════════════════════════════════════════════╗\n\
             ║  MISAKA Network — Narwhal/Bullshark Consensus            ║\n\
             ║  Authority: {:<4}  Committee: {:<4}  Epoch: {:<8}       ║\n\
             ╚═══════════════════════════════════════════════════════════╝",
            authority_index, committee.size(), committee.epoch,
        );

        Ok(Self {
            msg_tx,
            commit_rx,
            block_rx,
            metrics,
            runtime_handle,
            epoch_manager,
            prometheus,
        })
    }

    /// Submit a transaction for inclusion in the next block.
    pub fn submit_transaction(&self, tx_bytes: Vec<u8>) -> Result<(), String> {
        // SEC-FIX [Audit H4]: Proposer-side validation gate.
        // Same check as narwhal_consensus.rs — prevents malformed transactions
        // from bypassing mempool validation via the runtime bridge.
        match borsh::from_slice::<misaka_types::utxo::UtxoTransaction>(&tx_bytes) {
            Ok(tx) => {
                if let Err(e) = tx.validate_structure() {
                    return Err(format!("structural validation failed: {}", e));
                }
            }
            Err(e) => {
                return Err(format!("borsh decode failed: {}", e));
            }
        }

        // Transactions are queued; propose_block pulls from the queue.
        // For now, propose immediately with the single TX.
        let (reply_tx, _reply_rx) = oneshot::channel();
        self.msg_tx.try_send(ConsensusMessage::ProposeBlock {
            context: ProposeContext::normal(vec![tx_bytes], [0u8; 32]),
            reply: reply_tx,
        }).map_err(|e| format!("consensus runtime closed: {}", e))
    }

    /// Receive a block from a peer.
    pub fn receive_peer_block(&self, block: NarwhalBlock) -> Result<(), String> {
        let vb = VerifiedBlock::new_pending_verification(block);
        self.msg_tx.try_send(ConsensusMessage::NewBlock(vb))
            .map_err(|e| format!("consensus runtime closed: {}", e))
    }

    /// Get consensus status.
    pub async fn get_status(&self) -> Result<ConsensusStatus, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.msg_tx.try_send(ConsensusMessage::GetStatus(reply_tx))
            .map_err(|e| format!("consensus runtime closed: {}", e))?;
        reply_rx.await.map_err(|_| "status reply channel closed".to_string())
    }

    /// Poll for committed outputs (non-blocking).
    pub fn try_recv_committed(&mut self) -> Option<LinearizedOutput> {
        self.commit_rx.try_recv().ok()
    }

    /// Poll for blocks to broadcast (non-blocking).
    pub fn try_recv_broadcast(&mut self) -> Option<VerifiedBlock> {
        self.block_rx.try_recv().ok()
    }

    /// Get Prometheus metrics export.
    pub fn prometheus_export(&self) -> String {
        self.prometheus.export()
    }

    /// Shutdown the consensus engine.
    pub async fn shutdown(self) {
        let _ = self.msg_tx.try_send(ConsensusMessage::Shutdown);
        let _ = self.runtime_handle.await;
        info!("Narwhal consensus engine shut down");
    }

    /// Epoch manager reference.
    pub fn epoch_manager(&self) -> &EpochManager {
        &self.epoch_manager
    }

    /// Metrics reference.
    pub fn metrics(&self) -> &Arc<ConsensusMetrics> {
        &self.metrics
    }
}

/// Build a Committee from the node's validator configuration.
///
/// This replaces `build_committee()` in main.rs that used GhostDAG types.
#[cfg(feature = "dag")]
pub fn build_narwhal_committee(
    epoch: u64,
    validators: &[(String, Vec<u8>, u64)], // (hostname, public_key, stake)
) -> Committee {
    build_committee(epoch, validators)
}
