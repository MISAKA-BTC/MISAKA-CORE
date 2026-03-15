//! Chain store — block headers + transaction index.

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};

/// Stored transaction summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTx {
    pub hash: [u8; 32],
    pub fee: u64,
    pub input_count: usize,
    pub output_count: usize,
    pub timestamp_ms: u64,
    pub status: String,
    pub key_images: Vec<[u8; 32]>,
    pub size: usize,
    pub has_payload: bool,
}

/// Stored block header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredBlockHeader {
    pub height: u64,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub timestamp_ms: u64,
    pub tx_count: usize,
    pub total_fees: u64,
    pub proposer_index: usize,
    pub state_root: [u8; 32],
}

impl StoredBlockHeader {
    pub fn compute_hash(
        height: u64, parent_hash: &[u8; 32], timestamp_ms: u64,
        tx_count: usize, state_root: &[u8; 32],
    ) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:block:v1:");
        h.update(height.to_le_bytes());
        h.update(parent_hash);
        h.update(timestamp_ms.to_le_bytes());
        h.update((tx_count as u64).to_le_bytes());
        h.update(state_root);
        h.finalize().into()
    }
}

/// Chain store.
pub struct ChainStore {
    blocks_by_height: HashMap<u64, StoredBlockHeader>,
    hash_to_height: HashMap<[u8; 32], u64>,
    /// TXs indexed by block height.
    txs_by_block: HashMap<u64, Vec<StoredTx>>,
    /// TX hash → block height index.
    tx_hash_to_block: HashMap<[u8; 32], u64>,
    /// All TXs in order (most recent first, capped).
    recent_txs: Vec<(StoredTx, u64)>, // (tx, block_height)
    pub tip_height: u64,
    pub tip_hash: [u8; 32],
}

impl ChainStore {
    pub fn new() -> Self {
        Self {
            blocks_by_height: HashMap::new(),
            hash_to_height: HashMap::new(),
            txs_by_block: HashMap::new(),
            tx_hash_to_block: HashMap::new(),
            recent_txs: Vec::new(),
            tip_height: 0,
            tip_hash: [0u8; 32],
        }
    }

    pub fn store_genesis(&mut self, timestamp_ms: u64) -> StoredBlockHeader {
        let state_root = [0u8; 32];
        let hash = StoredBlockHeader::compute_hash(0, &[0u8; 32], timestamp_ms, 0, &state_root);
        let header = StoredBlockHeader {
            height: 0, hash, parent_hash: [0u8; 32], timestamp_ms,
            tx_count: 0, total_fees: 0, proposer_index: 0, state_root,
        };
        self.blocks_by_height.insert(0, header.clone());
        self.hash_to_height.insert(hash, 0);
        self.tip_height = 0;
        self.tip_hash = hash;
        header
    }

    pub fn append_block(
        &mut self, tx_count: usize, total_fees: u64, proposer_index: usize,
        timestamp_ms: u64, txs: Vec<StoredTx>,
    ) -> StoredBlockHeader {
        let height = self.tip_height + 1;
        let state_root = {
            let mut h = Sha3_256::new();
            h.update(b"MISAKA:state:v1:");
            h.update(height.to_le_bytes());
            h.update(&self.tip_hash);
            h.finalize().into()
        };
        let hash = StoredBlockHeader::compute_hash(
            height, &self.tip_hash, timestamp_ms, tx_count, &state_root,
        );
        let header = StoredBlockHeader {
            height, hash, parent_hash: self.tip_hash, timestamp_ms,
            tx_count, total_fees, proposer_index, state_root,
        };

        // Index TXs
        for tx in &txs {
            self.tx_hash_to_block.insert(tx.hash, height);
            self.recent_txs.push((tx.clone(), height));
        }
        // Cap recent_txs at 10000
        if self.recent_txs.len() > 10_000 {
            self.recent_txs.drain(0..self.recent_txs.len() - 10_000);
        }
        self.txs_by_block.insert(height, txs);

        self.blocks_by_height.insert(height, header.clone());
        self.hash_to_height.insert(hash, height);
        self.tip_height = height;
        self.tip_hash = hash;
        header
    }

    pub fn get_by_height(&self, height: u64) -> Option<&StoredBlockHeader> {
        self.blocks_by_height.get(&height)
    }

    pub fn get_by_hash(&self, hash: &[u8; 32]) -> Option<&StoredBlockHeader> {
        self.hash_to_height.get(hash).and_then(|h| self.blocks_by_height.get(h))
    }

    pub fn get_latest(&self, count: usize) -> Vec<StoredBlockHeader> {
        let start = self.tip_height.saturating_sub(count as u64 - 1);
        (start..=self.tip_height).rev()
            .filter_map(|h| self.blocks_by_height.get(&h).cloned())
            .collect()
    }

    pub fn get_txs_for_block(&self, height: u64) -> Vec<StoredTx> {
        self.txs_by_block.get(&height).cloned().unwrap_or_default()
    }

    pub fn get_tx_by_hash(&self, hash: &[u8; 32]) -> Option<(StoredTx, u64)> {
        self.tx_hash_to_block.get(hash).and_then(|h| {
            self.txs_by_block.get(h)
                .and_then(|txs| txs.iter().find(|t| t.hash == *hash).map(|t| (t.clone(), *h)))
        })
    }

    pub fn get_recent_txs(&self, page: usize, page_size: usize) -> (Vec<(StoredTx, u64)>, usize) {
        let total = self.recent_txs.len();
        let start = (page - 1) * page_size;
        let data: Vec<_> = self.recent_txs.iter().rev().skip(start).take(page_size).cloned().collect();
        (data, total)
    }

    pub fn total_tx_count(&self) -> usize {
        self.recent_txs.len()
    }

    pub fn len(&self) -> usize { self.blocks_by_height.len() }
}
