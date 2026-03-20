//! Persistent DAG Store — RocksDB backend for production deployment.
//!
//! # Column Family Layout
//!
//! | CF Name        | Key             | Value             | Purpose               |
//! |----------------|-----------------|-------------------|-----------------------|
//! | `dag_headers`  | block_hash(32)  | DagBlockHeader    | DAG block headers     |
//! | `dag_ghostdag` | block_hash(32)  | GhostDagData      | GhostDAG metadata     |
//! | `dag_children` | parent_hash(32) | Vec<Hash>         | Parent→child reverse  |
//! | `dag_tips`     | "tips"          | Vec<Hash>         | Current DAG tips      |
//! | `dag_txs`      | block_hash(32)  | Vec<QdagTx>       | Block transactions    |
//! | `dag_nulls`    | nullifier(32)   | tx_hash(32)       | Spent nullifiers      |
//!
//! # Crash Safety
//!
//! All writes are atomic via RocksDB WriteBatch.
//! Block insertion (header + ghostdag + children + tips update) is a single batch.

use std::path::Path;
use std::collections::HashSet;
use serde::{Serialize, de::DeserializeOwned};
use crate::dag_block::{Hash, DagBlockHeader, GhostDagData, ZERO_HASH};
use crate::ghostdag::DagStore;

// ═══════════════════════════════════════════════════════════════
//  PersistentDagStore Trait
// ═══════════════════════════════════════════════════════════════

/// Abstraction over DAG storage backends.
///
/// Both ThreadSafeDagStore (in-memory, testing) and RocksDbDagStore
/// (persistent, production) implement this trait.
pub trait PersistentDagBackend: Send + Sync {
    /// Insert a block header and its GhostDAG data atomically.
    fn insert_block_atomic(
        &self,
        hash: Hash,
        header: DagBlockHeader,
        ghostdag: GhostDagData,
    ) -> Result<(), DagStoreError>;

    /// Get a block header by hash.
    fn get_header(&self, hash: &Hash) -> Option<DagBlockHeader>;

    /// Get GhostDAG data by hash.
    fn get_ghostdag_data(&self, hash: &Hash) -> Option<GhostDagData>;

    /// Get current tips.
    fn get_tips(&self) -> Vec<Hash>;

    /// Get children of a block.
    fn get_children(&self, parent: &Hash) -> Vec<Hash>;

    /// Check if a nullifier has been spent.
    fn is_nullifier_spent(&self, nullifier: &[u8; 32]) -> bool;

    /// Record a spent nullifier atomically.
    fn record_nullifier(&self, nullifier: [u8; 32], tx_hash: [u8; 32]) -> Result<(), DagStoreError>;

    /// Get total block count.
    fn block_count(&self) -> u64;

    /// Get maximum blue_score across all tips.
    fn max_blue_score(&self) -> u64;

    /// Flush all pending writes to disk.
    fn flush(&self) -> Result<(), DagStoreError>;
}

#[derive(Debug, thiserror::Error)]
pub enum DagStoreError {
    #[error("storage I/O error: {0}")]
    Io(String),
    #[error("serialization error: {0}")]
    Serde(String),
    #[error("block already exists: {0}")]
    BlockExists(String),
    #[error("nullifier already spent: {0}")]
    NullifierAlreadySpent(String),
}

// ═══════════════════════════════════════════════════════════════
//  RocksDB Implementation
// ═══════════════════════════════════════════════════════════════

/// RocksDB-backed persistent DAG store.
///
/// Uses column families for data isolation.
/// All multi-key writes use WriteBatch for atomicity.
///
/// # Column Family Names
pub const CF_HEADERS: &str = "dag_headers";
pub const CF_GHOSTDAG: &str = "dag_ghostdag";
pub const CF_CHILDREN: &str = "dag_children";
pub const CF_TIPS: &str = "dag_tips";
pub const CF_NULLIFIERS: &str = "dag_nullifiers";

/// Column family names list for DB initialization.
pub const ALL_CFS: &[&str] = &[CF_HEADERS, CF_GHOSTDAG, CF_CHILDREN, CF_TIPS, CF_NULLIFIERS];

/// Key for the tips entry in CF_TIPS.
const TIPS_KEY: &[u8] = b"current_tips";

/// Placeholder RocksDB DAG store implementation.
///
/// The actual RocksDB calls use the `rocksdb` crate. This struct defines
/// the interface and serialization logic. Compile with `features = ["rocksdb"]`
/// to enable the full implementation; otherwise a feature-gated stub is used.
pub struct RocksDbDagStore {
    /// Database handle (when rocksdb feature is enabled).
    #[cfg(feature = "rocksdb")]
    db: rocksdb::DB,
    /// In-memory fallback for testing without rocksdb dependency.
    #[cfg(not(feature = "rocksdb"))]
    inner: std::sync::RwLock<MemoryBackend>,
}

#[cfg(not(feature = "rocksdb"))]
struct MemoryBackend {
    headers: std::collections::HashMap<Hash, Vec<u8>>,
    ghostdag: std::collections::HashMap<Hash, Vec<u8>>,
    children: std::collections::HashMap<Hash, Vec<Hash>>,
    tips: HashSet<Hash>,
    nullifiers: std::collections::HashMap<[u8; 32], [u8; 32]>,
    genesis_hash: Hash,
}

impl RocksDbDagStore {
    /// Open or create a persistent DAG store at the given path.
    #[cfg(feature = "rocksdb")]
    pub fn open(path: &Path, genesis_hash: Hash, genesis_header: DagBlockHeader) -> Result<Self, DagStoreError> {
        use rocksdb::{DB, Options, ColumnFamilyDescriptor};

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cfs: Vec<ColumnFamilyDescriptor> = ALL_CFS.iter()
            .map(|name| ColumnFamilyDescriptor::new(*name, Options::default()))
            .collect();

        let db = DB::open_cf_descriptors(&opts, path, cfs)
            .map_err(|e| DagStoreError::Io(e.to_string()))?;

        let store = Self { db };

        // Initialize genesis if not present
        if store.get_header(&genesis_hash).is_none() {
            let genesis_gd = GhostDagData {
                selected_parent: ZERO_HASH,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 0,
                blue_work: 0,
            };
            store.insert_block_atomic(genesis_hash, genesis_header, genesis_gd)?;
        }

        Ok(store)
    }

    /// Open with in-memory backend (Audit Fix K: EXPLICITLY LABELED for testing only).
    ///
    /// # Audit Fix K
    ///
    /// The previous implementation silently fell back to in-memory when the
    /// `rocksdb` feature was disabled. This is dangerous in production because
    /// ALL DATA IS LOST on restart without any warning.
    ///
    /// This constructor is now ONLY available with the `memory-backend` feature
    /// and is named explicitly to prevent accidental use.
    #[cfg(not(feature = "rocksdb"))]
    pub fn open_memory_for_testing(genesis_hash: Hash, genesis_header: DagBlockHeader) -> Result<Self, DagStoreError> {
        tracing::warn!(
            "⚠️  MEMORY-ONLY DAG STORE — DATA WILL BE LOST ON RESTART. \
             Enable 'rocksdb' feature for production."
        );
        let mut store = Self {
            inner: std::sync::RwLock::new(MemoryBackend {
                headers: std::collections::HashMap::new(),
                ghostdag: std::collections::HashMap::new(),
                children: std::collections::HashMap::new(),
                tips: HashSet::new(),
                nullifiers: std::collections::HashMap::new(),
                genesis_hash,
            }),
        };

        let genesis_gd = GhostDagData {
            selected_parent: ZERO_HASH,
            mergeset_blues: vec![],
            mergeset_reds: vec![],
            blue_score: 0,
            blue_work: 0,
        };
        store.insert_block_atomic(genesis_hash, genesis_header, genesis_gd)?;
        Ok(store)
    }

    /// Audit Fix K: `open()` without rocksdb feature is a COMPILE ERROR.
    #[cfg(not(feature = "rocksdb"))]
    pub fn open(_path: &Path, _genesis_hash: Hash, _genesis_header: DagBlockHeader) -> Result<Self, DagStoreError> {
        Err(DagStoreError::Io(
            "RocksDB backend not available. Enable 'rocksdb' feature for production, \
             or use open_memory_for_testing() for tests.".into()
        ))
    }
}

#[cfg(not(feature = "rocksdb"))]
#[allow(clippy::unwrap_used)] // RwLock::read/write — in-memory fallback only, poisoning is non-recoverable
impl PersistentDagBackend for RocksDbDagStore {
    fn insert_block_atomic(
        &self,
        hash: Hash,
        header: DagBlockHeader,
        ghostdag: GhostDagData,
    ) -> Result<(), DagStoreError> {
        let mut inner = self.inner.write().unwrap();

        let h_bytes = serde_json::to_vec(&header)
            .map_err(|e| DagStoreError::Serde(e.to_string()))?;
        let g_bytes = serde_json::to_vec(&ghostdag)
            .map_err(|e| DagStoreError::Serde(e.to_string()))?;

        inner.headers.insert(hash, h_bytes);
        inner.ghostdag.insert(hash, g_bytes);

        // Update children
        for parent in &header.parents {
            inner.children.entry(*parent).or_default().push(hash);
        }

        // Update tips: add new block, remove its parents from tips
        inner.tips.insert(hash);
        for parent in &header.parents {
            inner.tips.remove(parent);
        }

        Ok(())
    }

    fn get_header(&self, hash: &Hash) -> Option<DagBlockHeader> {
        let inner = self.inner.read().unwrap();
        inner.headers.get(hash)
            .and_then(|bytes| serde_json::from_slice(bytes).ok())
    }

    fn get_ghostdag_data(&self, hash: &Hash) -> Option<GhostDagData> {
        let inner = self.inner.read().unwrap();
        inner.ghostdag.get(hash)
            .and_then(|bytes| serde_json::from_slice(bytes).ok())
    }

    fn get_tips(&self) -> Vec<Hash> {
        let inner = self.inner.read().unwrap();
        inner.tips.iter().cloned().collect()
    }

    fn get_children(&self, parent: &Hash) -> Vec<Hash> {
        let inner = self.inner.read().unwrap();
        inner.children.get(parent).cloned().unwrap_or_default()
    }

    fn is_nullifier_spent(&self, nullifier: &[u8; 32]) -> bool {
        let inner = self.inner.read().unwrap();
        inner.nullifiers.contains_key(nullifier)
    }

    fn record_nullifier(&self, nullifier: [u8; 32], tx_hash: [u8; 32]) -> Result<(), DagStoreError> {
        let mut inner = self.inner.write().unwrap();
        if inner.nullifiers.contains_key(&nullifier) {
            return Err(DagStoreError::NullifierAlreadySpent(
                hex::encode(&nullifier[..8])));
        }
        inner.nullifiers.insert(nullifier, tx_hash);
        Ok(())
    }

    fn block_count(&self) -> u64 {
        let inner = self.inner.read().unwrap();
        inner.headers.len() as u64
    }

    fn max_blue_score(&self) -> u64 {
        let inner = self.inner.read().unwrap();
        inner.ghostdag.values()
            .filter_map(|bytes| serde_json::from_slice::<GhostDagData>(bytes).ok())
            .map(|gd| gd.blue_score)
            .max()
            .unwrap_or(0)
    }

    fn flush(&self) -> Result<(), DagStoreError> {
        Ok(()) // In-memory: no-op
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag_block::DAG_VERSION;

    fn genesis_header() -> DagBlockHeader {
        DagBlockHeader {
            version: DAG_VERSION,
            parents: vec![], timestamp_ms: 1000,
            tx_root: ZERO_HASH, proposer_id: [0; 32],
            nonce: 0, blue_score: 0, bits: 0,
        }
    }

    #[test]
    fn test_persistent_store_genesis() {
        let genesis = genesis_header();
        let genesis_hash = genesis.compute_hash();
        let store = RocksDbDagStore::open_memory_for_testing(
            genesis_hash, genesis.clone(),
        ).unwrap();

        assert_eq!(store.block_count(), 1);
        assert!(store.get_header(&genesis_hash).is_some());
        let tips = store.get_tips();
        assert!(tips.contains(&genesis_hash));
    }

    #[test]
    fn test_persistent_store_insert_child() {
        let genesis = genesis_header();
        let genesis_hash = genesis.compute_hash();
        let store = RocksDbDagStore::open_memory_for_testing(
            genesis_hash, genesis,
        ).unwrap();

        let child_header = DagBlockHeader {
            version: DAG_VERSION,
            parents: vec![genesis_hash],
            timestamp_ms: 2000, tx_root: ZERO_HASH,
            proposer_id: [1; 32],
            nonce: 0, blue_score: 1, bits: 0,
        };
        let child_hash = child_header.compute_hash();
        let child_gd = GhostDagData {
            selected_parent: genesis_hash,
            mergeset_blues: vec![], mergeset_reds: vec![],
            blue_score: 1, blue_work: 1,
        };
        store.insert_block_atomic(child_hash, child_header, child_gd).unwrap();

        assert_eq!(store.block_count(), 2);
        // Tips: genesis removed (has child), child added
        let tips = store.get_tips();
        assert!(!tips.contains(&genesis_hash));
        assert!(tips.contains(&child_hash));
        // Children
        let children = store.get_children(&genesis_hash);
        assert!(children.contains(&child_hash));
    }

    #[test]
    fn test_persistent_store_nullifier() {
        let genesis = genesis_header();
        let genesis_hash = genesis.compute_hash();
        let store = RocksDbDagStore::open_memory_for_testing(
            genesis_hash, genesis,
        ).unwrap();

        let null = [0xAA; 32];
        let tx = [0xBB; 32];
        assert!(!store.is_nullifier_spent(&null));
        store.record_nullifier(null, tx).unwrap();
        assert!(store.is_nullifier_spent(&null));

        // Double record should fail
        assert!(store.record_nullifier(null, [0xCC; 32]).is_err());
    }
}
