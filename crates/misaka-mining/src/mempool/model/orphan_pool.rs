//! Orphan transaction pool.

use super::tx::MempoolTransaction;
use std::collections::{HashMap, HashSet};

/// Pool for transactions whose inputs are not yet available.
pub struct OrphanPool {
    transactions: HashMap<[u8; 32], MempoolTransaction>,
    /// Map from missing parent tx_id to orphan tx_ids that depend on it.
    by_parent: HashMap<[u8; 32], HashSet<[u8; 32]>>,
    max_size: usize,
}

impl OrphanPool {
    pub fn new(max_size: usize) -> Self {
        Self {
            transactions: HashMap::new(),
            by_parent: HashMap::new(),
            max_size,
        }
    }

    pub fn insert(&mut self, tx: MempoolTransaction) -> Result<(), ()> {
        if self.transactions.len() >= self.max_size {
            self.evict_random();
        }
        if self.transactions.len() >= self.max_size {
            return Err(());
        }

        let tx_id = tx.tx_id;
        // Register parent dependencies
        for outpoint in &tx.input_outpoints {
            let parent_id = extract_parent_id(outpoint);
            self.by_parent.entry(parent_id).or_default().insert(tx_id);
        }

        self.transactions.insert(tx_id, tx);
        Ok(())
    }

    pub fn remove(&mut self, tx_id: &[u8; 32]) -> Option<MempoolTransaction> {
        if let Some(tx) = self.transactions.remove(tx_id) {
            for outpoint in &tx.input_outpoints {
                let parent_id = extract_parent_id(outpoint);
                if let Some(set) = self.by_parent.get_mut(&parent_id) {
                    set.remove(tx_id);
                    if set.is_empty() {
                        self.by_parent.remove(&parent_id);
                    }
                }
            }
            Some(tx)
        } else {
            None
        }
    }

    pub fn contains(&self, tx_id: &[u8; 32]) -> bool {
        self.transactions.contains_key(tx_id)
    }

    /// Get orphans that depend on a specific parent transaction.
    pub fn resolve_by_parent(&mut self, parent_tx_id: &[u8; 32]) -> Vec<MempoolTransaction> {
        let orphan_ids: Vec<[u8; 32]> = self
            .by_parent
            .remove(parent_tx_id)
            .unwrap_or_default()
            .into_iter()
            .collect();

        orphan_ids.iter().filter_map(|id| self.remove(id)).collect()
    }

    pub fn len(&self) -> usize {
        self.transactions.len()
    }
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    fn evict_random(&mut self) {
        // Remove the oldest orphan
        if let Some(tx_id) = self.transactions.keys().next().copied() {
            self.remove(&tx_id);
        }
    }
}

fn extract_parent_id(outpoint: &[u8; 36]) -> [u8; 32] {
    let mut id = [0u8; 32];
    id.copy_from_slice(&outpoint[..32]);
    id
}
