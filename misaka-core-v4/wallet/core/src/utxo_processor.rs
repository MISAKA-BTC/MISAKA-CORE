//! # UTXO Processor — Real-Time Balance Tracking
//!
//! Kaspa-aligned UTXO processor that:
//! - Tracks owned UTXOs in real-time via RPC subscriptions
//! - Manages UTXO maturity (coinbase outputs need N confirmations)
//! - Provides balance queries by address
//! - Supports pending transaction tracking

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

pub type Hash = [u8; 32];

/// Coinbase maturity: number of confirmations before spendable.
pub const COINBASE_MATURITY: u64 = 100;

/// A tracked UTXO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedUtxo {
    /// Transaction hash that created this UTXO.
    pub tx_hash: Hash,
    /// Output index within the transaction.
    pub output_index: u32,
    /// Value in base units.
    pub amount: u64,
    /// Address this UTXO belongs to.
    pub address: String,
    /// Block blue score where this UTXO was confirmed.
    pub confirming_blue_score: u64,
    /// Whether this is a coinbase output.
    pub is_coinbase: bool,
    /// Whether this UTXO is currently used in a pending transaction.
    pub is_pending: bool,
}

impl TrackedUtxo {
    /// Check if this UTXO is mature (spendable).
    pub fn is_mature(&self, current_blue_score: u64) -> bool {
        if self.is_coinbase {
            current_blue_score >= self.confirming_blue_score + COINBASE_MATURITY
        } else {
            true // Non-coinbase UTXOs are immediately spendable.
        }
    }

    /// Outpoint key for deduplication.
    pub fn outpoint_key(&self) -> (Hash, u32) {
        (self.tx_hash, self.output_index)
    }
}

/// Balance summary for an address.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BalanceSummary {
    /// Total confirmed, mature balance.
    pub mature: u64,
    /// Pending (in mempool or immature coinbase).
    pub pending: u64,
    /// Number of UTXOs.
    pub utxo_count: usize,
}

/// UTXO processor for real-time balance tracking.
pub struct UtxoProcessor {
    /// Owned UTXOs indexed by outpoint (tx_hash, output_index).
    utxos: HashMap<(Hash, u32), TrackedUtxo>,
    /// Address → set of outpoints for fast balance queries.
    address_index: HashMap<String, HashSet<(Hash, u32)>>,
    /// Current virtual blue score.
    current_blue_score: u64,
    /// Pending transaction hashes.
    pending_txs: HashSet<Hash>,
}

impl UtxoProcessor {
    pub fn new() -> Self {
        Self {
            utxos: HashMap::new(),
            address_index: HashMap::new(),
            current_blue_score: 0,
            pending_txs: HashSet::new(),
        }
    }

    /// Update the current blue score (from subscription).
    pub fn set_blue_score(&mut self, score: u64) {
        self.current_blue_score = score;
    }

    /// Add a new UTXO (from subscription or scan).
    pub fn add_utxo(&mut self, utxo: TrackedUtxo) {
        let key = utxo.outpoint_key();
        self.address_index
            .entry(utxo.address.clone())
            .or_default()
            .insert(key);
        self.utxos.insert(key, utxo);
    }

    /// Remove a spent UTXO.
    pub fn remove_utxo(&mut self, tx_hash: Hash, output_index: u32) {
        let key = (tx_hash, output_index);
        if let Some(utxo) = self.utxos.remove(&key) {
            if let Some(set) = self.address_index.get_mut(&utxo.address) {
                set.remove(&key);
                if set.is_empty() {
                    self.address_index.remove(&utxo.address);
                }
            }
        }
    }

    /// Mark UTXOs as pending (used in a submitted but unconfirmed tx).
    pub fn mark_pending(&mut self, tx_hash: Hash, inputs: &[(Hash, u32)]) {
        self.pending_txs.insert(tx_hash);
        for key in inputs {
            if let Some(utxo) = self.utxos.get_mut(key) {
                utxo.is_pending = true;
            }
        }
    }

    /// Confirm a pending transaction.
    pub fn confirm_tx(&mut self, tx_hash: Hash) {
        self.pending_txs.remove(&tx_hash);
    }

    /// Get balance for a specific address.
    pub fn get_balance(&self, address: &str) -> BalanceSummary {
        let outpoints = match self.address_index.get(address) {
            Some(set) => set,
            None => return BalanceSummary::default(),
        };

        let mut mature = 0u64;
        let mut pending = 0u64;
        let mut count = 0;

        for key in outpoints {
            if let Some(utxo) = self.utxos.get(key) {
                count += 1;
                if utxo.is_pending || !utxo.is_mature(self.current_blue_score) {
                    pending += utxo.amount;
                } else {
                    mature += utxo.amount;
                }
            }
        }

        BalanceSummary {
            mature,
            pending,
            utxo_count: count,
        }
    }

    /// Get balances for multiple addresses.
    pub fn get_balances(&self, addresses: &[String]) -> HashMap<String, BalanceSummary> {
        addresses
            .iter()
            .map(|addr| (addr.clone(), self.get_balance(addr)))
            .collect()
    }

    /// Get all spendable (mature, non-pending) UTXOs for an address.
    pub fn get_spendable_utxos(&self, address: &str) -> Vec<TrackedUtxo> {
        let outpoints = match self.address_index.get(address) {
            Some(set) => set,
            None => return vec![],
        };

        outpoints
            .iter()
            .filter_map(|key| {
                let utxo = self.utxos.get(key)?;
                if !utxo.is_pending && utxo.is_mature(self.current_blue_score) {
                    Some(utxo.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Total number of tracked UTXOs.
    pub fn total_utxo_count(&self) -> usize {
        self.utxos.len()
    }

    /// Number of pending transactions.
    pub fn pending_tx_count(&self) -> usize {
        self.pending_txs.len()
    }

    /// Number of tracked addresses.
    pub fn tracked_address_count(&self) -> usize {
        self.address_index.len()
    }

    /// Process a UtxosChanged notification (bulk add/remove).
    pub fn process_utxo_change(&mut self, added: Vec<TrackedUtxo>, removed: Vec<(Hash, u32)>) {
        for key in removed {
            self.remove_utxo(key.0, key.1);
        }
        for utxo in added {
            self.add_utxo(utxo);
        }
    }
}

impl Default for UtxoProcessor {
    fn default() -> Self {
        Self::new()
    }
}
