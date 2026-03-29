//! Transaction index: maps transaction IDs to their block location.

use std::collections::HashMap;
use parking_lot::RwLock;

/// Location of a transaction within a block.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TxLocation {
    pub block_hash: [u8; 32],
    pub block_daa_score: u64,
    pub index_in_block: u32,
}

/// Transaction index.
pub struct TxIndex {
    index: RwLock<HashMap<[u8; 32], TxLocation>>,
}

impl TxIndex {
    pub fn new() -> Self {
        Self { index: RwLock::new(HashMap::new()) }
    }

    pub fn insert(&self, tx_id: [u8; 32], location: TxLocation) {
        self.index.write().insert(tx_id, location);
    }

    pub fn get(&self, tx_id: &[u8; 32]) -> Option<TxLocation> {
        self.index.read().get(tx_id).cloned()
    }

    pub fn remove(&self, tx_id: &[u8; 32]) -> Option<TxLocation> {
        self.index.write().remove(tx_id)
    }

    pub fn contains(&self, tx_id: &[u8; 32]) -> bool {
        self.index.read().contains_key(tx_id)
    }

    /// Index all transactions from a block.
    pub fn index_block(&self, block_hash: [u8; 32], daa_score: u64, tx_ids: &[[u8; 32]]) {
        let mut idx = self.index.write();
        for (i, tx_id) in tx_ids.iter().enumerate() {
            idx.insert(*tx_id, TxLocation {
                block_hash,
                block_daa_score: daa_score,
                index_in_block: i as u32,
            });
        }
    }

    pub fn entry_count(&self) -> usize {
        self.index.read().len()
    }
}

impl Default for TxIndex {
    fn default() -> Self { Self::new() }
}
