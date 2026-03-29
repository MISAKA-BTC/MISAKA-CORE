//! Wallet daemon — background service for continuous wallet operations.
//!
//! Runs as a long-lived process that:
//! - Maintains wRPC connection to node
//! - Processes incoming UTXO notifications
//! - Manages address discovery (gap limit)
//! - Handles transaction broadcasting and confirmation tracking
//! - Provides event stream to UI layer

use crate::balance_manager::{BalanceManager, TrackedUtxo, Outpoint, BalanceChangeEvent};
use crate::sync::{WalletSync, SyncConfig, SyncState, SyncProgress, ProcessedBlock};
use crate::address_manager::{AddressManager, AddressEntry};
use crate::wrpc_client::{WalletRpcClient, WrpcClientConfig};
use crate::metrics::{WalletMetrics, WalletMetricsSnapshot};
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use std::collections::HashMap;

/// Wallet daemon configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub rpc: WrpcClientConfig,
    pub sync: SyncConfig,
    pub auto_compound: bool,
    pub compound_threshold: usize,
    pub compound_min_utxos: usize,
    pub event_buffer_size: usize,
    pub background_scan_interval_ms: u64,
    pub address_discovery_batch: u32,
    pub maturity_poll_interval_ms: u64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            rpc: WrpcClientConfig::default(),
            sync: SyncConfig::default(),
            auto_compound: false,
            compound_threshold: 100,
            compound_min_utxos: 50,
            event_buffer_size: 1000,
            background_scan_interval_ms: 60_000,
            address_discovery_batch: 20,
            maturity_poll_interval_ms: 10_000,
        }
    }
}

/// Wallet daemon state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaemonState {
    Starting,
    Connecting,
    Syncing,
    Ready,
    Stopping,
    Stopped,
    Error,
}

/// Events emitted by the daemon to the UI layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonEvent {
    StateChanged(DaemonState),
    SyncProgress(SyncProgress),
    BalanceChanged(BalanceChangeEvent),
    TransactionConfirmed { tx_id: String, confirmations: u64 },
    TransactionFailed { tx_id: String, reason: String },
    AddressDiscovered { address: String, account_id: u64 },
    ConnectionLost { url: String },
    ConnectionRestored { url: String },
    CompoundCompleted { input_count: usize, output_count: usize, saved_mass: u64 },
    Error { message: String },
}

/// Pending outgoing transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingTransaction {
    pub tx_id: [u8; 32],
    pub account_id: u64,
    pub amount: u64,
    pub fee: u64,
    pub recipient: String,
    pub submitted_at: u64,
    pub confirmation_target: u64,
    pub locked_outpoints: Vec<Outpoint>,
    pub status: PendingTxStatus,
    pub broadcast_count: u32,
    pub last_broadcast: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PendingTxStatus {
    Broadcasting,
    InMempool,
    Confirming { confirmations: u64 },
    Confirmed,
    Failed,
    Replaced,
    TimedOut,
}

/// The wallet daemon.
pub struct WalletDaemon {
    config: DaemonConfig,
    state: std::sync::atomic::AtomicU8,
    rpc_client: Arc<WalletRpcClient>,
    balance_manager: Arc<BalanceManager>,
    sync_manager: parking_lot::Mutex<WalletSync>,
    address_manager: parking_lot::RwLock<AddressManager>,
    pending_txs: parking_lot::RwLock<HashMap<[u8; 32], PendingTransaction>>,
    metrics: Arc<WalletMetrics>,
    event_buffer: parking_lot::Mutex<Vec<DaemonEvent>>,
    accounts: parking_lot::RwLock<Vec<u64>>,
}

impl WalletDaemon {
    pub fn new(config: DaemonConfig) -> Self {
        let rpc_client = Arc::new(WalletRpcClient::new(config.rpc.clone()));
        Self {
            balance_manager: Arc::new(BalanceManager::new()),
            sync_manager: parking_lot::Mutex::new(WalletSync::new(config.sync.clone())),
            address_manager: parking_lot::RwLock::new(AddressManager::default()),
            pending_txs: parking_lot::RwLock::new(HashMap::new()),
            metrics: Arc::new(WalletMetrics::default()),
            event_buffer: parking_lot::Mutex::new(Vec::with_capacity(config.event_buffer_size)),
            accounts: parking_lot::RwLock::new(Vec::new()),
            rpc_client,
            config,
            state: std::sync::atomic::AtomicU8::new(0),
        }
    }

    /// Register an account for tracking.
    pub fn register_account(&self, account_id: u64, addresses: Vec<String>) {
        self.accounts.write().push(account_id);
        let mut sync = self.sync_manager.lock();
        sync.add_addresses(addresses.into_iter());
    }

    /// Submit a transaction for broadcasting.
    pub fn submit_transaction(&self, pending: PendingTransaction) -> Result<(), String> {
        let tx_id = pending.tx_id;
        // Lock the UTXOs
        self.balance_manager.lock_utxos(&pending.locked_outpoints)
            .map_err(|e| format!("failed to lock UTXOs: {}", e))?;

        self.pending_txs.write().insert(tx_id, pending);
        self.metrics.txs_sent.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Process a block notification from the node.
    pub fn process_block(&self, block: ProcessedBlock) {
        let mut sync = self.sync_manager.lock();
        let result = sync.process_block_batch(vec![block]);

        self.balance_manager.update_daa_score(result.new_last_score);
        self.metrics.sync_rounds.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Check pending transaction confirmations
        self.update_pending_txs(result.new_last_score);
    }

    /// Update pending transaction status.
    fn update_pending_txs(&self, current_score: u64) {
        let mut txs = self.pending_txs.write();
        let mut confirmed = Vec::new();
        let mut timed_out = Vec::new();

        for (tx_id, tx) in txs.iter_mut() {
            match tx.status {
                PendingTxStatus::InMempool | PendingTxStatus::Confirming { .. } => {
                    // Check if confirmed (simplified — would query node)
                    let age = current_score.saturating_sub(tx.confirmation_target);
                    if age > 100 {
                        tx.status = PendingTxStatus::TimedOut;
                        timed_out.push(*tx_id);
                    }
                }
                PendingTxStatus::Confirmed => {
                    confirmed.push(*tx_id);
                }
                _ => {}
            }
        }

        // Unlock UTXOs for timed-out transactions
        for tx_id in &timed_out {
            if let Some(tx) = txs.get(tx_id) {
                self.balance_manager.unlock_utxos(&tx.locked_outpoints);
                self.emit_event(DaemonEvent::TransactionFailed {
                    tx_id: hex::encode(tx_id),
                    reason: "timed out".to_string(),
                });
            }
        }
    }

    /// Get the sync progress.
    pub fn sync_progress(&self, network_score: u64) -> SyncProgress {
        self.sync_manager.lock().progress(network_score)
    }

    /// Get daemon state.
    pub fn state(&self) -> DaemonState {
        match self.state.load(std::sync::atomic::Ordering::Relaxed) {
            0 => DaemonState::Starting,
            1 => DaemonState::Connecting,
            2 => DaemonState::Syncing,
            3 => DaemonState::Ready,
            4 => DaemonState::Stopping,
            5 => DaemonState::Stopped,
            _ => DaemonState::Error,
        }
    }

    /// Drain pending events for the UI.
    pub fn drain_events(&self) -> Vec<DaemonEvent> {
        let mut events = self.event_buffer.lock();
        std::mem::take(&mut *events)
    }

    fn emit_event(&self, event: DaemonEvent) {
        let mut buffer = self.event_buffer.lock();
        if buffer.len() < self.config.event_buffer_size {
            buffer.push(event);
        }
    }

    /// Get metrics snapshot.
    pub fn metrics(&self) -> WalletMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Get pending transaction count.
    pub fn pending_tx_count(&self) -> usize {
        self.pending_txs.read().len()
    }

    /// Get balance for an account.
    pub fn get_balance(&self, account_id: u64) -> crate::balance_manager::DetailedBalance {
        self.balance_manager.get_balance(account_id)
    }

    /// Get all pending transactions.
    pub fn pending_transactions(&self) -> Vec<PendingTransaction> {
        self.pending_txs.read().values().cloned().collect()
    }
}
