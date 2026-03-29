//! In-mempool UTXO spending tracker.

use std::collections::HashMap;

/// Tracks which outpoints are spent by which mempool transaction.
pub struct MempoolUtxoSet {
    spent: HashMap<[u8; 36], [u8; 32]>,
}

impl MempoolUtxoSet {
    pub fn new() -> Self { Self { spent: HashMap::new() } }

    pub fn mark_spent(&mut self, outpoint: [u8; 36], spender: [u8; 32]) {
        self.spent.insert(outpoint, spender);
    }

    pub fn unmark_spent(&mut self, outpoint: &[u8; 36]) {
        self.spent.remove(outpoint);
    }

    pub fn is_spent(&self, outpoint: &[u8; 36]) -> bool {
        self.spent.contains_key(outpoint)
    }

    pub fn spending_tx(&self, outpoint: &[u8; 36]) -> Option<[u8; 32]> {
        self.spent.get(outpoint).copied()
    }

    pub fn len(&self) -> usize { self.spent.len() }
}

impl Default for MempoolUtxoSet {
    fn default() -> Self { Self::new() }
}
