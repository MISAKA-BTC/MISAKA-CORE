//! Full-featured transaction mempool with fee-rate ordering,
//! orphan management, replace-by-fee support, and UTXO tracking.

pub mod check_transaction_standard;
pub mod config;
pub mod handle_new_block;
pub mod model;
pub mod populate_entries;
pub mod remove_transaction;
pub mod replace_by_fee;
pub mod tx;
pub mod validate_and_insert;

use crate::errors::{MempoolRuleError, MiningError, MiningResult};
use crate::model::frontier::{FeeRateFrontier, FeeRateKey};
use crate::model::MiningCounters;
use config::MempoolConfig;
use model::orphan_pool::OrphanPool;
use model::tx::MempoolTransaction;
use model::utxo_set::MempoolUtxoSet;
use std::collections::HashMap;
use std::sync::Arc;

/// The transaction mempool.
pub struct Mempool {
    config: Arc<MempoolConfig>,
    /// All accepted (non-orphan) transactions.
    transactions: HashMap<[u8; 32], MempoolTransaction>,
    /// Orphan pool for transactions with missing inputs.
    orphan_pool: OrphanPool,
    /// Fee-rate ordered frontier for block template selection.
    frontier: FeeRateFrontier,
    /// UTXO set overlay for double-spend detection.
    utxo_set: MempoolUtxoSet,
    /// Mining counters.
    counters: Arc<MiningCounters>,
    /// Current mempool mass.
    total_mass: u64,
    /// Current mempool fee total.
    total_fees: u64,
}

impl Mempool {
    pub fn new(config: Arc<MempoolConfig>, counters: Arc<MiningCounters>) -> Self {
        Self {
            config,
            transactions: HashMap::new(),
            orphan_pool: OrphanPool::new(500),
            frontier: FeeRateFrontier::new(),
            utxo_set: MempoolUtxoSet::new(),
            counters,
            total_mass: 0,
            total_fees: 0,
        }
    }

    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }
    pub fn orphan_count(&self) -> usize {
        self.orphan_pool.len()
    }
    pub fn total_mass(&self) -> u64 {
        self.total_mass
    }
    pub fn total_fees(&self) -> u64 {
        self.total_fees
    }

    pub fn contains(&self, tx_id: &[u8; 32]) -> bool {
        self.transactions.contains_key(tx_id)
    }

    pub fn get(&self, tx_id: &[u8; 32]) -> Option<&MempoolTransaction> {
        self.transactions.get(tx_id)
    }

    pub fn contains_orphan(&self, tx_id: &[u8; 32]) -> bool {
        self.orphan_pool.contains(tx_id)
    }

    /// Insert a validated transaction into the mempool.
    pub fn insert(&mut self, tx: MempoolTransaction) -> MiningResult<()> {
        let tx_id = tx.tx_id;
        let mass = tx.mass;
        let fee = tx.fee;

        if self.total_mass + mass > self.config.max_mempool_mass {
            self.evict_lowest_fee_rate(mass)?;
        }

        let key = FeeRateKey {
            fee_rate: tx.fee_rate(),
            tx_id,
            mass,
        };
        self.frontier.insert(key, fee);
        self.total_mass += mass;
        self.total_fees += fee;

        // Track UTXO spending
        for input in &tx.input_outpoints {
            self.utxo_set.mark_spent(*input, tx_id);
        }

        self.transactions.insert(tx_id, tx);
        self.counters
            .tx_accepted_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Remove a transaction from the mempool.
    pub fn remove(&mut self, tx_id: &[u8; 32]) -> Option<MempoolTransaction> {
        if let Some(tx) = self.transactions.remove(tx_id) {
            let key = FeeRateKey {
                fee_rate: tx.fee_rate(),
                tx_id: *tx_id,
                mass: tx.mass,
            };
            self.frontier.remove(&key);
            self.total_mass = self.total_mass.saturating_sub(tx.mass);
            self.total_fees = self.total_fees.saturating_sub(tx.fee);

            for input in &tx.input_outpoints {
                self.utxo_set.unmark_spent(input);
            }

            Some(tx)
        } else {
            None
        }
    }

    /// Insert into orphan pool.
    pub fn insert_orphan(&mut self, tx: MempoolTransaction) -> MiningResult<()> {
        self.orphan_pool
            .insert(tx)
            .map_err(|_| MiningError::OrphanPoolFull(self.orphan_pool.len()))?;
        self.counters
            .orphans_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// Check if an outpoint is already spent in the mempool.
    pub fn is_spent(&self, outpoint: &[u8; 36]) -> bool {
        self.utxo_set.is_spent(outpoint)
    }

    /// Get spending transaction for an outpoint.
    pub fn spending_tx(&self, outpoint: &[u8; 36]) -> Option<[u8; 32]> {
        self.utxo_set.spending_tx(outpoint)
    }

    /// Select transactions for a block template.
    pub fn select_transactions(&self, max_mass: u64) -> Vec<[u8; 32]> {
        self.frontier
            .select(max_mass)
            .into_iter()
            .map(|k| k.tx_id)
            .collect()
    }

    /// Evict transactions with the lowest fee rate to make room.
    fn evict_lowest_fee_rate(&mut self, needed_mass: u64) -> MiningResult<()> {
        let mut freed = 0u64;
        let mut to_remove = Vec::new();

        // Collect lowest fee-rate transactions
        let all_keys: Vec<_> = self
            .frontier
            .select(self.total_mass)
            .into_iter()
            .rev()
            .collect();
        for key in all_keys {
            if freed >= needed_mass {
                break;
            }
            to_remove.push(key.tx_id);
            freed += key.mass;
        }

        for tx_id in to_remove {
            self.remove(&tx_id);
        }

        if self.total_mass + needed_mass > self.config.max_mempool_mass {
            return Err(MiningError::MempoolRule(MempoolRuleError::MassExceeded {
                mass: needed_mass,
                max: self.config.max_mempool_mass,
            }));
        }
        Ok(())
    }

    /// Try to resolve orphans after a new transaction is accepted.
    pub fn try_resolve_orphans(&mut self, new_tx_id: &[u8; 32]) -> Vec<MempoolTransaction> {
        self.orphan_pool.resolve_by_parent(new_tx_id)
    }

    /// Get a snapshot of mempool statistics.
    pub fn stats(&self) -> MempoolStats {
        MempoolStats {
            transaction_count: self.transactions.len(),
            orphan_count: self.orphan_pool.len(),
            total_mass: self.total_mass,
            total_fees: self.total_fees,
            min_fee_rate: self.frontier.min_fee_rate(),
            max_fee_rate: self.frontier.max_fee_rate(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MempoolStats {
    pub transaction_count: usize,
    pub orphan_count: usize,
    pub total_mass: u64,
    pub total_fees: u64,
    pub min_fee_rate: f64,
    pub max_fee_rate: f64,
}
