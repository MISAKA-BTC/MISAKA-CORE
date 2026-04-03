//! Transaction selector for block template construction.
//!
//! Implements a greedy knapsack algorithm that selects transactions
//! by fee rate while respecting mass limits and dependency ordering.

use crate::model::frontier::FeeRateKey;

/// Select transactions for a block template.
pub struct TransactionSelector {
    max_mass: u64,
    selected: Vec<FeeRateKey>,
    remaining_mass: u64,
    total_fees: u64,
}

impl TransactionSelector {
    pub fn new(max_mass: u64) -> Self {
        Self {
            max_mass,
            selected: Vec::new(),
            remaining_mass: max_mass,
            total_fees: 0,
        }
    }

    /// Try to add a transaction. Returns true if added.
    pub fn try_add(&mut self, key: FeeRateKey, fee: u64) -> bool {
        if key.mass > self.remaining_mass {
            return false;
        }
        self.remaining_mass -= key.mass;
        self.total_fees += fee;
        self.selected.push(key);
        true
    }

    /// Get selected transaction IDs.
    pub fn selected_tx_ids(&self) -> Vec<[u8; 32]> {
        self.selected.iter().map(|k| k.tx_id).collect()
    }

    pub fn total_mass(&self) -> u64 {
        self.max_mass - self.remaining_mass
    }
    pub fn total_fees(&self) -> u64 {
        self.total_fees
    }
    pub fn count(&self) -> usize {
        self.selected.len()
    }
    pub fn remaining_mass(&self) -> u64 {
        self.remaining_mass
    }

    /// Check if the template is full (< 1% remaining mass).
    pub fn is_full(&self) -> bool {
        self.remaining_mass < self.max_mass / 100
    }
}
