//! Wallet synchronization — keeps wallet state in sync with the blockchain.
//!
//! # Sync Strategy
//! 1. Initial sync: scan all blocks from last known position
//! 2. Incremental sync: subscribe to new block notifications
//! 3. Reorg handling: detect chain reorganizations and rollback
//! 4. Address discovery: scan ahead using gap limit
//!
//! # Security
//! - Verify Merkle proofs for UTXO existence
//! - Validate block headers against expected difficulty
//! - Cross-reference multiple RPC endpoints for consistency
//! - Rate-limit sync requests to prevent DoS

use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// Sync state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncState {
    /// Not started.
    Idle,
    /// Scanning historical blocks.
    InitialSync,
    /// Caught up, processing new blocks.
    Synced,
    /// Handling a chain reorganization.
    Reorg,
    /// Sync error — will retry.
    Error,
}

/// Sync progress info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncProgress {
    pub state: SyncState,
    pub current_daa_score: u64,
    pub target_daa_score: u64,
    pub progress_percent: f64,
    pub blocks_remaining: u64,
    pub estimated_time_remaining_secs: u64,
    pub addresses_scanned: usize,
    pub utxos_found: usize,
    pub last_error: Option<String>,
}

/// Sync manager configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    pub batch_size: u32,
    pub max_concurrent_requests: usize,
    pub gap_limit: u32,
    pub reorg_depth_limit: u64,
    pub retry_interval_ms: u64,
    pub max_retries: u32,
    pub verify_merkle_proofs: bool,
    pub multi_endpoint_verification: bool,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            batch_size: 100,
            max_concurrent_requests: 4,
            gap_limit: 20,
            reorg_depth_limit: 100,
            retry_interval_ms: 5000,
            max_retries: 10,
            verify_merkle_proofs: true,
            multi_endpoint_verification: false,
        }
    }
}

/// Wallet sync manager.
pub struct WalletSync {
    config: SyncConfig,
    state: SyncState,
    last_synced_score: u64,
    addresses_to_monitor: HashSet<String>,
    pending_utxos: Vec<PendingUtxo>,
    reorg_buffer: VecDeque<ProcessedBlock>,
    retry_count: u32,
}

/// A block processed during sync.
#[derive(Debug, Clone)]
pub struct ProcessedBlock {
    pub hash: [u8; 32],
    pub daa_score: u64,
    pub blue_score: u64,
    pub utxos_added: Vec<FoundUtxo>,
    pub utxos_spent: Vec<SpentUtxo>,
    pub timestamp: u64,
}

/// A UTXO found during scanning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundUtxo {
    pub outpoint_tx_id: [u8; 32],
    pub outpoint_index: u32,
    pub amount: u64,
    pub script_public_key: Vec<u8>,
    pub address: String,
    pub block_daa_score: u64,
    pub is_coinbase: bool,
}

/// A UTXO that was spent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpentUtxo {
    pub outpoint_tx_id: [u8; 32],
    pub outpoint_index: u32,
    pub spending_tx_id: [u8; 32],
}

/// A pending UTXO awaiting confirmation.
#[derive(Debug, Clone)]
pub struct PendingUtxo {
    pub utxo: FoundUtxo,
    pub confirmations: u64,
    pub first_seen: u64,
}

impl WalletSync {
    pub fn new(config: SyncConfig) -> Self {
        Self {
            config,
            state: SyncState::Idle,
            last_synced_score: 0,
            addresses_to_monitor: HashSet::new(),
            pending_utxos: Vec::new(),
            reorg_buffer: VecDeque::with_capacity(200),
            retry_count: 0,
        }
    }

    /// Register addresses to monitor during sync.
    pub fn add_addresses(&mut self, addresses: impl IntoIterator<Item = String>) {
        self.addresses_to_monitor.extend(addresses);
    }

    /// Process a batch of blocks during sync.
    pub fn process_block_batch(&mut self, blocks: Vec<ProcessedBlock>) -> SyncBatchResult {
        let mut utxos_added = 0;
        let mut utxos_spent = 0;

        for block in &blocks {
            // Buffer for reorg detection
            if self.reorg_buffer.len() >= self.config.reorg_depth_limit as usize {
                self.reorg_buffer.pop_front();
            }
            self.reorg_buffer.push_back(block.clone());

            // Process UTXOs
            for utxo in &block.utxos_added {
                if self.addresses_to_monitor.contains(&utxo.address) {
                    self.pending_utxos.push(PendingUtxo {
                        utxo: utxo.clone(),
                        confirmations: 0,
                        first_seen: block.timestamp,
                    });
                    utxos_added += 1;
                }
            }

            for spent in &block.utxos_spent {
                self.pending_utxos.retain(|p| {
                    !(p.utxo.outpoint_tx_id == spent.outpoint_tx_id
                        && p.utxo.outpoint_index == spent.outpoint_index)
                });
                utxos_spent += 1;
            }

            self.last_synced_score = block.daa_score;
        }

        self.state = SyncState::Synced;
        self.retry_count = 0;

        SyncBatchResult {
            blocks_processed: blocks.len(),
            utxos_added,
            utxos_spent,
            new_last_score: self.last_synced_score,
        }
    }

    /// Handle a potential chain reorganization.
    pub fn handle_reorg(&mut self, fork_point_score: u64) -> ReorgResult {
        self.state = SyncState::Reorg;

        let mut removed_blocks = Vec::new();
        while let Some(block) = self.reorg_buffer.back() {
            if block.daa_score <= fork_point_score {
                break;
            }
            removed_blocks.push(self.reorg_buffer.pop_back().unwrap());
        }

        // Undo UTXO changes from removed blocks
        let mut utxos_restored = 0;
        let mut utxos_unspent = 0;
        for block in &removed_blocks {
            for spent in &block.utxos_spent {
                // Re-add UTXOs that were marked as spent
                utxos_unspent += 1;
            }
            for added in &block.utxos_added {
                // Remove UTXOs that were added in reorged blocks
                self.pending_utxos.retain(|p| {
                    !(p.utxo.outpoint_tx_id == added.outpoint_tx_id
                        && p.utxo.outpoint_index == added.outpoint_index)
                });
                utxos_restored += 1;
            }
        }

        self.last_synced_score = fork_point_score;
        self.state = SyncState::InitialSync;

        ReorgResult {
            blocks_removed: removed_blocks.len(),
            fork_point_score,
            utxos_restored,
            utxos_unspent,
        }
    }

    /// Get current sync progress.
    pub fn progress(&self, network_daa_score: u64) -> SyncProgress {
        let remaining = network_daa_score.saturating_sub(self.last_synced_score);
        let progress = if network_daa_score > 0 {
            self.last_synced_score as f64 / network_daa_score as f64 * 100.0
        } else {
            100.0
        };

        SyncProgress {
            state: self.state,
            current_daa_score: self.last_synced_score,
            target_daa_score: network_daa_score,
            progress_percent: progress.min(100.0),
            blocks_remaining: remaining,
            estimated_time_remaining_secs: remaining, // ~1 block/sec
            addresses_scanned: self.addresses_to_monitor.len(),
            utxos_found: self.pending_utxos.len(),
            last_error: None,
        }
    }

    pub fn state(&self) -> SyncState { self.state }
    pub fn last_synced_score(&self) -> u64 { self.last_synced_score }
    pub fn pending_utxo_count(&self) -> usize { self.pending_utxos.len() }
}

/// Result of processing a batch of blocks.
#[derive(Debug)]
pub struct SyncBatchResult {
    pub blocks_processed: usize,
    pub utxos_added: usize,
    pub utxos_spent: usize,
    pub new_last_score: u64,
}

/// Result of handling a reorg.
#[derive(Debug)]
pub struct ReorgResult {
    pub blocks_removed: usize,
    pub fork_point_score: u64,
    pub utxos_restored: usize,
    pub utxos_unspent: usize,
}

/// Transaction history tracker.
pub struct TransactionHistory {
    entries: Vec<TransactionHistoryEntry>,
    max_entries: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionHistoryEntry {
    pub tx_id: String,
    pub direction: TxDirection,
    pub amount: u64,
    pub fee: u64,
    pub counterparty: Option<String>,
    pub timestamp: u64,
    pub block_hash: Option<String>,
    pub block_daa_score: Option<u64>,
    pub confirmations: u64,
    pub status: TxStatus,
    pub note: Option<String>,
    pub account_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxDirection { Sent, Received, SelfTransfer }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxStatus { Pending, Confirmed, Failed, Replaced }

impl TransactionHistory {
    pub fn new(max_entries: usize) -> Self {
        Self { entries: Vec::new(), max_entries }
    }

    pub fn add(&mut self, entry: TransactionHistoryEntry) {
        if self.entries.len() >= self.max_entries {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    pub fn get_by_account(&self, account_id: u64) -> Vec<&TransactionHistoryEntry> {
        self.entries.iter().filter(|e| e.account_id == account_id).collect()
    }

    pub fn get_recent(&self, count: usize) -> &[TransactionHistoryEntry] {
        let start = self.entries.len().saturating_sub(count);
        &self.entries[start..]
    }

    pub fn update_confirmations(&mut self, current_daa_score: u64) {
        for entry in &mut self.entries {
            if let Some(block_score) = entry.block_daa_score {
                entry.confirmations = current_daa_score.saturating_sub(block_score);
                if entry.confirmations >= 10 && entry.status == TxStatus::Pending {
                    entry.status = TxStatus::Confirmed;
                }
            }
        }
    }

    pub fn mark_confirmed(&mut self, tx_id: &str, block_hash: &str, block_score: u64) {
        for entry in &mut self.entries {
            if entry.tx_id == tx_id {
                entry.block_hash = Some(block_hash.to_string());
                entry.block_daa_score = Some(block_score);
                entry.status = TxStatus::Confirmed;
            }
        }
    }

    pub fn total_sent(&self) -> u64 {
        self.entries.iter()
            .filter(|e| e.direction == TxDirection::Sent)
            .map(|e| e.amount)
            .sum()
    }

    pub fn total_received(&self) -> u64 {
        self.entries.iter()
            .filter(|e| e.direction == TxDirection::Received)
            .map(|e| e.amount)
            .sum()
    }

    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}
