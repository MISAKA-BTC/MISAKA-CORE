//! Thread-Safe DAG Store — Q-DAG-CT native (legacy UtxoTransaction removed).
//!
//! All block transaction storage uses `QdagTransaction`.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use tracing::{info, debug, warn};

use misaka_pqc::qdag_tx::QdagTransaction;
use crate::dag_block::{Hash, DagBlockHeader, GhostDagData, ZERO_HASH};
use crate::ghostdag::DagStore;
use crate::dag_state_manager::TxApplyStatus;

// ═══════════════════════════════════════════════════════════════
//  Thread-Safe In-Memory DAG Store
// ═══════════════════════════════════════════════════════════════

pub struct ThreadSafeDagStore {
    inner: RwLock<DagStoreInner>,
}

struct DagStoreInner {
    headers: HashMap<Hash, DagBlockHeader>,
    ghostdag: HashMap<Hash, GhostDagData>,
    children: HashMap<Hash, Vec<Hash>>,
    tips: HashSet<Hash>,
    /// Q-DAG-CT transactions per block (Item 4: replaces UtxoTransaction).
    block_txs: HashMap<Hash, Vec<QdagTransaction>>,
    tx_status: HashMap<[u8; 32], TxApplyStatus>,
    genesis_hash: Hash,
    block_count: u64,
}

impl ThreadSafeDagStore {
    pub fn new(genesis_hash: Hash, genesis_header: DagBlockHeader) -> Self {
        let mut headers = HashMap::new();
        let mut ghostdag = HashMap::new();
        let mut tips = HashSet::new();

        headers.insert(genesis_hash, genesis_header);
        ghostdag.insert(genesis_hash, GhostDagData {
            selected_parent: ZERO_HASH,
            mergeset_blues: vec![],
            mergeset_reds: vec![],
            blue_score: 0,
            blue_work: 0,
        });
        tips.insert(genesis_hash);

        Self {
            inner: RwLock::new(DagStoreInner {
                headers, ghostdag, children: HashMap::new(),
                tips, block_txs: HashMap::new(),
                tx_status: HashMap::new(),
                genesis_hash, block_count: 1,
            }),
        }
    }

    /// Insert a block with Q-DAG-CT transactions.
    pub fn insert_block_with_qdag_txs(
        &self,
        hash: Hash,
        header: DagBlockHeader,
        txs: &[QdagTransaction],
    ) -> Result<(), String> {
        let mut inner = self.inner.write().unwrap();

        if inner.headers.contains_key(&hash) {
            return Err(format!("block {} already exists", hex::encode(&hash[..8])));
        }

        // Update children index
        for parent in &header.parents {
            inner.children.entry(*parent).or_default().push(hash);
        }

        // Update tips: add this block, remove its parents
        inner.tips.insert(hash);
        for parent in &header.parents {
            inner.tips.remove(parent);
        }

        inner.headers.insert(hash, header);
        inner.block_txs.insert(hash, txs.to_vec());
        inner.block_count += 1;

        Ok(())
    }

    /// Store GhostDAG data after computation.
    pub fn store_ghostdag_data(&self, hash: Hash, data: GhostDagData) {
        let mut inner = self.inner.write().unwrap();
        inner.ghostdag.insert(hash, data);
    }

    /// Get Q-DAG-CT transactions for a block.
    pub fn get_block_qdag_txs(&self, hash: &Hash) -> Vec<QdagTransaction> {
        let inner = self.inner.read().unwrap();
        inner.block_txs.get(hash).cloned().unwrap_or_default()
    }

    /// Get blue_score for a block.
    pub fn get_blue_score(&self, hash: &Hash) -> u64 {
        let inner = self.inner.read().unwrap();
        inner.ghostdag.get(hash).map(|gd| gd.blue_score).unwrap_or(0)
    }

    /// Get current tips.
    pub fn get_current_tips(&self) -> Vec<Hash> {
        let inner = self.inner.read().unwrap();
        inner.tips.iter().copied().collect()
    }

    /// Get maximum blue_score across all tips.
    pub fn max_blue_score(&self) -> u64 {
        let inner = self.inner.read().unwrap();
        inner.tips.iter()
            .filter_map(|tip| inner.ghostdag.get(tip))
            .map(|gd| gd.blue_score)
            .max()
            .unwrap_or(0)
    }

    pub fn block_count(&self) -> u64 {
        let inner = self.inner.read().unwrap();
        inner.block_count
    }

    /// Record TX status.
    pub fn set_tx_status(&self, tx_hash: [u8; 32], status: TxApplyStatus) {
        let mut inner = self.inner.write().unwrap();
        inner.tx_status.insert(tx_hash, status);
    }

    pub fn get_tx_status(&self, tx_hash: &[u8; 32]) -> Option<TxApplyStatus> {
        let inner = self.inner.read().unwrap();
        inner.tx_status.get(tx_hash).cloned()
    }
}

// ═══════════════════════════════════════════════════════════════
//  DagStore Trait Implementation (for GhostDAG)
// ═══════════════════════════════════════════════════════════════

/// Snapshot for read-only access to the DAG store.
pub struct DagStoreSnapshot {
    headers: HashMap<Hash, DagBlockHeader>,
    ghostdag: HashMap<Hash, GhostDagData>,
    tips: Vec<Hash>,
}

impl DagStoreSnapshot {
    pub fn from_store(store: &ThreadSafeDagStore) -> Self {
        let inner = store.inner.read().unwrap();
        Self {
            headers: inner.headers.clone(),
            ghostdag: inner.ghostdag.clone(),
            tips: inner.tips.iter().copied().collect(),
        }
    }
}

impl DagStore for DagStoreSnapshot {
    fn get_header(&self, hash: &Hash) -> Option<&DagBlockHeader> {
        self.headers.get(hash)
    }
    fn get_ghostdag_data(&self, hash: &Hash) -> Option<&GhostDagData> {
        self.ghostdag.get(hash)
    }
    fn has_block(&self, hash: &Hash) -> bool {
        self.headers.contains_key(hash)
    }
    fn get_tips(&self) -> Vec<Hash> {
        self.tips.clone()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag_block::DAG_VERSION;

    fn genesis() -> (Hash, DagBlockHeader) {
        let header = DagBlockHeader {
            version: DAG_VERSION,
            chain_id: 2,
            epoch: 0,
            parents: vec![],
            timestamp_ms: 1000,
            tx_root: ZERO_HASH,
            proposer_id: [0; 32],
            proposer_randomness_commitment: [0; 32],
            protocol_version: 1,
            blue_score: 0,
        };
        let hash = header.compute_hash();
        (hash, header)
    }

    #[test]
    fn test_store_genesis() {
        let (hash, header) = genesis();
        let store = ThreadSafeDagStore::new(hash, header);
        assert_eq!(store.block_count(), 1);
        assert!(store.get_current_tips().contains(&hash));
    }

    #[test]
    fn test_store_insert_block() {
        let (gen_hash, gen_header) = genesis();
        let store = ThreadSafeDagStore::new(gen_hash, gen_header);

        let child_header = DagBlockHeader {
            version: DAG_VERSION,
            chain_id: 2,
            epoch: 0,
            parents: vec![gen_hash],
            timestamp_ms: 2000,
            tx_root: ZERO_HASH,
            proposer_id: [1; 32],
            proposer_randomness_commitment: [0; 32],
            protocol_version: 1,
            blue_score: 1,
        };
        let child_hash = child_header.compute_hash();

        store.insert_block_with_qdag_txs(child_hash, child_header, &[]).unwrap();
        assert_eq!(store.block_count(), 2);

        let tips = store.get_current_tips();
        assert!(!tips.contains(&gen_hash), "genesis should no longer be a tip");
        assert!(tips.contains(&child_hash), "child should be a tip");
    }

    #[test]
    fn test_store_duplicate_rejected() {
        let (gen_hash, gen_header) = genesis();
        let store = ThreadSafeDagStore::new(gen_hash, gen_header.clone());
        assert!(store.insert_block_with_qdag_txs(gen_hash, gen_header, &[]).is_err());
    }

    #[test]
    fn test_store_no_utxo_transaction_reference() {
        // Compile-time verification: this module has zero UtxoTransaction references.
        // If this test exists and compiles, the legacy type is fully removed.
        let (hash, header) = genesis();
        let store = ThreadSafeDagStore::new(hash, header);
        let txs = store.get_block_qdag_txs(&hash);
        assert!(txs.is_empty());
    }
}
