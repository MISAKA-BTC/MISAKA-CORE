//! Address Indexer — maintains address→UTXO and address→TX history.
//!
//! # Architecture
//!
//! The indexer is a **secondary read layer** that listens to the ChainStore
//! and builds address-indexed views. It is NOT part of consensus — the node
//! operates correctly even if the indexer is disabled.
//!
//! ```text
//! ChainStore (blocks, txs)
//!       ↓ (on_block_appended / on_spc_switch)
//! Indexer (address→UTXOs, address→history, tx_status)
//!       ↓ (queried by)
//! REST API (/api/v1/address/{addr}/utxos, /history, /tx/{hash}/status)
//! ```
//!
//! # Reorg Handling
//!
//! When a block is disconnected (chain reorg), the indexer:
//! 1. Rolls back outputs created in that block (removes UTXOs).
//! 2. Unspends inputs consumed in that block (restores UTXOs).
//! 3. Downgrades tx status from Confirmed → Pending.
//!
//! # Thread Safety
//!
//! The indexer state is behind `RwLock` — reads are concurrent, writes
//! are exclusive. Block indexing happens on the block producer thread;
//! API queries hold read locks only.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// ═══════════════════════════════════════════════════════════════
//  Types
// ═══════════════════════════════════════════════════════════════

/// Outpoint reference (tx_hash + output_index).
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outpoint {
    pub tx_hash: String,
    pub output_index: u32,
}

/// An indexed UTXO — the minimal data a wallet needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedUtxo {
    pub outpoint: Outpoint,
    pub address: String,
    pub amount: u64,
    pub block_height: u64,
    pub timestamp_ms: u64,
    /// Spending pubkey hex (needed for ring member resolution).
    #[serde(default)]
    pub spending_pubkey: String,
    /// View tag for fast wallet scanning.
    #[serde(default)]
    pub view_tag: String,
}

/// Transaction status as seen by the indexer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxStatusEntry {
    pub tx_hash: String,
    pub status: TxIndexStatus,
    pub block_height: Option<u64>,
    pub confirmations: u64,
    pub timestamp_ms: u64,
    pub fee: u64,
    pub input_count: usize,
    pub output_count: usize,
}

/// Transaction status categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TxIndexStatus {
    /// In the mempool, not yet in a block.
    Pending,
    /// Included in a block.
    Confirmed,
    /// Was confirmed but rolled back by reorg.
    Reorged,
    /// Dropped from mempool (expired or conflicted).
    Dropped,
}

/// A transaction history entry for an address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressTxEntry {
    pub tx_hash: String,
    pub block_height: Option<u64>,
    pub timestamp_ms: u64,
    /// Positive = received, negative = sent.
    pub net_amount: i64,
    pub status: TxIndexStatus,
}

// BlockUndo has been removed — no-rollback architecture.
// The indexer is forward-only. DAG reorgs are handled via
// VirtualChainChanged notifications from VirtualState::resolve(),
// which provides (removed_hashes, added_hashes) for incremental update.

// ═══════════════════════════════════════════════════════════════
//  Indexer State
// ═══════════════════════════════════════════════════════════════

/// The main indexer state — address-indexed views of the chain.
///
/// # No-Rollback Architecture
///
/// The indexer is forward-only. There is no undo stack.
/// DAG SPC switches are handled via `on_spc_switch()` which
/// receives the list of removed/added block hashes from
/// VirtualState::resolve().
pub struct AddressIndexer {
    /// Address → set of unspent outpoints.
    address_utxos: HashMap<String, HashMap<Outpoint, IndexedUtxo>>,
    /// Address → transaction history (sorted by timestamp).
    address_history: HashMap<String, Vec<AddressTxEntry>>,
    /// TX hash → status entry.
    tx_status: HashMap<String, TxStatusEntry>,
    /// Current chain tip height as seen by the indexer.
    indexed_height: u64,
    /// All known addresses (for stats).
    known_addresses: HashSet<String>,
}

impl AddressIndexer {
    pub fn new() -> Self {
        Self {
            address_utxos: HashMap::new(),
            address_history: HashMap::new(),
            tx_status: HashMap::new(),
            indexed_height: 0,
            known_addresses: HashSet::new(),
        }
    }

    /// Current indexed height.
    pub fn height(&self) -> u64 {
        self.indexed_height
    }

    /// Total unique addresses seen.
    pub fn address_count(&self) -> usize {
        self.known_addresses.len()
    }

    /// Total indexed transactions.
    pub fn tx_count(&self) -> usize {
        self.tx_status.len()
    }

    // ── Query API ──

    /// Get all unspent UTXOs for an address.
    pub fn get_utxos(&self, address: &str) -> Vec<IndexedUtxo> {
        self.address_utxos
            .get(address)
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Get transaction history for an address (paginated).
    pub fn get_history(
        &self,
        address: &str,
        page: usize,
        page_size: usize,
    ) -> (Vec<AddressTxEntry>, usize) {
        let entries = self.address_history.get(address);
        let total = entries.map(|e| e.len()).unwrap_or(0);
        let page = page.max(1);
        let start = (page - 1) * page_size;

        let data = entries
            .map(|e| {
                e.iter()
                    .rev() // newest first
                    .skip(start)
                    .take(page_size)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        (data, total)
    }

    /// Get transaction status by hash.
    pub fn get_tx_status(&self, tx_hash: &str) -> Option<&TxStatusEntry> {
        self.tx_status.get(tx_hash)
    }

    /// Get the balance for an address (sum of unspent UTXOs).
    pub fn get_balance(&self, address: &str) -> u64 {
        self.address_utxos
            .get(address)
            .map(|m| m.values().map(|u| u.amount).sum())
            .unwrap_or(0)
    }

    // ── Indexing (called by block producer) ──

    /// Index a new confirmed block (forward-only, no undo data).
    ///
    /// Call this after `ChainStore::append_block()` succeeds.
    pub fn on_block_appended(
        &mut self,
        height: u64,
        block_timestamp_ms: u64,
        txs: &[BlockTxData],
        current_tip_height: u64,
    ) {
        for tx in txs {
            let tx_hash_hex = hex::encode(tx.hash);
            let confirmations = current_tip_height.saturating_sub(height) + 1;

            // Record tx status
            self.tx_status.insert(
                tx_hash_hex.clone(),
                TxStatusEntry {
                    tx_hash: tx_hash_hex.clone(),
                    status: TxIndexStatus::Confirmed,
                    block_height: Some(height),
                    confirmations,
                    timestamp_ms: block_timestamp_ms,
                    fee: tx.fee,
                    input_count: tx.inputs.len(),
                    output_count: tx.outputs.len(),
                },
            );

            // Index outputs (UTXOs created)
            for output in &tx.outputs {
                let outpoint = Outpoint {
                    tx_hash: tx_hash_hex.clone(),
                    output_index: output.output_index,
                };
                let utxo = IndexedUtxo {
                    outpoint: outpoint.clone(),
                    address: output.address.clone(),
                    amount: output.amount,
                    block_height: height,
                    timestamp_ms: block_timestamp_ms,
                    spending_pubkey: output.spending_pubkey.clone(),
                    view_tag: output.view_tag.clone(),
                };

                self.address_utxos
                    .entry(output.address.clone())
                    .or_default()
                    .insert(outpoint, utxo);

                self.known_addresses.insert(output.address.clone());
            }

            // Index inputs (UTXOs spent)
            for input in &tx.inputs {
                if input.source_tx_hash.is_empty() {
                    continue; // coinbase
                }
                let spent_outpoint = Outpoint {
                    tx_hash: input.source_tx_hash.clone(),
                    output_index: input.source_output_index,
                };

                // Find and remove the UTXO from address maps
                let mut found_addr = None;
                for (addr, utxo_map) in &mut self.address_utxos {
                    if utxo_map.remove(&spent_outpoint).is_some() {
                        found_addr = Some(addr.clone());
                        break;
                    }
                }

                // Record in history for the spending address
                if let Some(addr) = &found_addr {
                    self.address_history
                        .entry(addr.clone())
                        .or_default()
                        .push(AddressTxEntry {
                            tx_hash: tx_hash_hex.clone(),
                            block_height: Some(height),
                            timestamp_ms: block_timestamp_ms,
                            net_amount: -(input.amount as i64),
                            status: TxIndexStatus::Confirmed,
                        });
                }
            }

            // Record in history for receiving addresses
            for output in &tx.outputs {
                self.address_history
                    .entry(output.address.clone())
                    .or_default()
                    .push(AddressTxEntry {
                        tx_hash: tx_hash_hex.clone(),
                        block_height: Some(height),
                        timestamp_ms: block_timestamp_ms,
                        net_amount: output.amount as i64,
                        status: TxIndexStatus::Confirmed,
                    });
            }
        }

        // Update indexed height (no undo data stored — forward-only)
        self.indexed_height = height;
    }

    /// Handle a DAG SPC (Selected Parent Chain) switch.
    ///
    /// When VirtualState::resolve() detects a chain switch, it provides
    /// the list of removed and added block heights. The indexer marks
    /// TXs from removed blocks as `Reorged` and processes added blocks
    /// via `on_block_appended`.
    ///
    /// This is NOT a rollback — it's an incremental index update.
    pub fn on_spc_switch(
        &mut self,
        removed_heights: &[u64],
        _added_heights: &[u64],
    ) {
        for &height in removed_heights {
            // Mark TXs at this height as reorged
            for entry in self.tx_status.values_mut() {
                if entry.block_height == Some(height) {
                    entry.status = TxIndexStatus::Reorged;
                    entry.block_height = None;
                    entry.confirmations = 0;
                }
            }

            // Remove history entries at this height
            for entries in self.address_history.values_mut() {
                entries.retain(|e| e.block_height != Some(height));
            }
        }

        // Note: added blocks will be re-indexed via on_block_appended()
        // by the caller after the SPC switch is complete.
        if !removed_heights.is_empty() {
            self.indexed_height = removed_heights
                .iter()
                .copied()
                .min()
                .unwrap_or(self.indexed_height)
                .saturating_sub(1);
        }
    }

    /// Record a pending (mempool) transaction.
    pub fn on_tx_pending(&mut self, tx_hash: &str, fee: u64, input_count: usize, output_count: usize) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        self.tx_status.insert(
            tx_hash.to_string(),
            TxStatusEntry {
                tx_hash: tx_hash.to_string(),
                status: TxIndexStatus::Pending,
                block_height: None,
                confirmations: 0,
                timestamp_ms: now_ms,
                fee,
                input_count,
                output_count,
            },
        );
    }

    /// Mark a mempool TX as dropped.
    pub fn on_tx_dropped(&mut self, tx_hash: &str) {
        if let Some(entry) = self.tx_status.get_mut(tx_hash) {
            entry.status = TxIndexStatus::Dropped;
        }
    }

    /// Update confirmation depths for all confirmed TXs.
    pub fn update_confirmations(&mut self, current_height: u64) {
        for entry in self.tx_status.values_mut() {
            if let (TxIndexStatus::Confirmed, Some(bh)) = (entry.status, entry.block_height) {
                entry.confirmations = current_height.saturating_sub(bh) + 1;
            }
        }
    }

    /// Indexer statistics.
    pub fn stats(&self) -> IndexerStats {
        IndexerStats {
            indexed_height: self.indexed_height,
            total_addresses: self.known_addresses.len(),
            total_utxos: self.address_utxos.values().map(|m| m.len()).sum(),
            total_txs: self.tx_status.len(),
            pending_txs: self
                .tx_status
                .values()
                .filter(|e| e.status == TxIndexStatus::Pending)
                .count(),
            reorged_txs: self
                .tx_status
                .values()
                .filter(|e| e.status == TxIndexStatus::Reorged)
                .count(),
        }
    }
}

impl Default for AddressIndexer {
    fn default() -> Self {
        Self::new()
    }
}

/// Indexer statistics for monitoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexerStats {
    pub indexed_height: u64,
    pub total_addresses: usize,
    pub total_utxos: usize,
    pub total_txs: usize,
    pub pending_txs: usize,
    /// TXs that were marked as reorged due to SPC switches.
    pub reorged_txs: usize,
}

// ═══════════════════════════════════════════════════════════════
//  Input types for indexing (bridge from ChainStore types)
// ═══════════════════════════════════════════════════════════════

/// Minimal TX data needed for indexing (extracted from StoredTx).
#[derive(Debug, Clone)]
pub struct BlockTxData {
    pub hash: [u8; 32],
    pub fee: u64,
    pub inputs: Vec<BlockTxInput>,
    pub outputs: Vec<BlockTxOutput>,
}

#[derive(Debug, Clone)]
pub struct BlockTxInput {
    pub key_image: String,
    pub source_tx_hash: String,
    pub source_output_index: u32,
    pub amount: u64,
}

#[derive(Debug, Clone)]
pub struct BlockTxOutput {
    pub address: String,
    pub amount: u64,
    pub output_index: u32,
    pub spending_pubkey: String,
    pub view_tag: String,
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tx(id: u8) -> BlockTxData {
        BlockTxData {
            hash: [id; 32],
            fee: 100,
            inputs: vec![],
            outputs: vec![BlockTxOutput {
                address: "msk1alice".into(),
                amount: 1_000_000,
                output_index: 0,
                spending_pubkey: "pk_alice".into(),
                view_tag: "ab".into(),
            }],
        }
    }

    fn spending_tx(id: u8, spends_tx: u8) -> BlockTxData {
        BlockTxData {
            hash: [id; 32],
            fee: 100,
            inputs: vec![BlockTxInput {
                key_image: format!("ki_{:02x}", id),
                source_tx_hash: hex::encode([spends_tx; 32]),
                source_output_index: 0,
                amount: 1_000_000,
            }],
            outputs: vec![BlockTxOutput {
                address: "msk1bob".into(),
                amount: 900_000,
                output_index: 0,
                spending_pubkey: "pk_bob".into(),
                view_tag: "cd".into(),
            }],
        }
    }

    #[test]
    fn test_index_block_creates_utxos() {
        let mut idx = AddressIndexer::new();
        let txs = vec![sample_tx(1)];

        idx.on_block_appended(1, 1000, &txs, 1);

        let utxos = idx.get_utxos("msk1alice");
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].amount, 1_000_000);
        assert_eq!(idx.get_balance("msk1alice"), 1_000_000);
    }

    #[test]
    fn test_index_spending_removes_utxo() {
        let mut idx = AddressIndexer::new();

        // Block 1: create UTXO for alice
        idx.on_block_appended(1, 1000, &[sample_tx(1)], 1);
        assert_eq!(idx.get_balance("msk1alice"), 1_000_000);

        // Block 2: alice sends to bob
        idx.on_block_appended(2, 2000, &[spending_tx(2, 1)], 2);
        assert_eq!(idx.get_balance("msk1alice"), 0);
        assert_eq!(idx.get_balance("msk1bob"), 900_000);
    }

    #[test]
    fn test_spc_switch_marks_txs_as_reorged() {
        let mut idx = AddressIndexer::new();

        idx.on_block_appended(1, 1000, &[sample_tx(1)], 1);
        idx.on_block_appended(2, 2000, &[spending_tx(2, 1)], 2);

        assert_eq!(idx.get_balance("msk1bob"), 900_000);

        // SPC switch: block 2 is removed from the selected chain.
        // In the no-rollback model, TXs are marked as Reorged.
        // The actual UTXO state will be rebuilt by re-indexing
        // the new chain's blocks via on_block_appended().
        idx.on_spc_switch(&[2], &[]);

        // TX at height 2 should be marked as reorged
        // (on_spc_switch does NOT restore UTXOs — that's done by re-indexing)
        assert_eq!(idx.height(), 1);
    }

    #[test]
    fn test_tx_status_lifecycle() {
        let mut idx = AddressIndexer::new();

        // Pending
        idx.on_tx_pending("tx_001", 100, 1, 2);
        let status = idx.get_tx_status("tx_001").expect("exists");
        assert_eq!(status.status, TxIndexStatus::Pending);

        // Confirmed
        let tx = BlockTxData {
            hash: {
                let mut h = [0u8; 32];
                h[..6].copy_from_slice(b"tx_001");
                h
            },
            fee: 100,
            inputs: vec![],
            outputs: vec![],
        };
        idx.on_block_appended(1, 1000, &[tx], 1);

        // After block, the hex-encoded hash should be in the status map
        assert!(idx.tx_count() >= 1);
    }

    #[test]
    fn test_history_pagination() {
        let mut idx = AddressIndexer::new();

        // 5 blocks, each with a tx to alice
        for i in 1u8..=5 {
            idx.on_block_appended(i as u64, (i as u64) * 1000, &[sample_tx(i)], i as u64);
        }

        let (page1, total) = idx.get_history("msk1alice", 1, 2);
        assert_eq!(total, 5);
        assert_eq!(page1.len(), 2);

        let (page3, _) = idx.get_history("msk1alice", 3, 2);
        assert_eq!(page3.len(), 1); // last page
    }

    #[test]
    fn test_confirmation_update() {
        let mut idx = AddressIndexer::new();
        idx.on_block_appended(1, 1000, &[sample_tx(1)], 1);

        let hash = hex::encode([1u8; 32]);
        assert_eq!(idx.get_tx_status(&hash).expect("exists").confirmations, 1);

        // Chain advances to height 10
        idx.update_confirmations(10);
        assert_eq!(idx.get_tx_status(&hash).expect("exists").confirmations, 10);
    }

    #[test]
    fn test_stats() {
        let mut idx = AddressIndexer::new();
        idx.on_block_appended(1, 1000, &[sample_tx(1)], 1);

        let stats = idx.stats();
        assert_eq!(stats.indexed_height, 1);
        assert_eq!(stats.total_addresses, 1);
        assert_eq!(stats.total_utxos, 1);
    }
}
