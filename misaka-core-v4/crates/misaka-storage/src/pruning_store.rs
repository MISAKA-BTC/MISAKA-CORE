//! # Pruning Store — Pruning Point UTXO Snapshots
//!
//! Manages pruning point state: the UTXO set snapshot at the current
//! pruning point, pruning proofs, and candidate pruning points.
//!
//! This enables new nodes to sync from the pruning point instead of
//! replaying the entire chain history.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::cache::{CachePolicy, MemSizeEstimate};
use crate::cached_access::{CachedDbAccess, CachedDbItem};
use crate::db_writer::{AtomicBatch, DirectDbWriter};
use crate::store_errors::StoreError;
use crate::store_registry::StorePrefixes;

pub type Hash = [u8; 32];

/// Pruning point metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruningPointInfo {
    /// The hash of the pruning point block.
    pub hash: Hash,
    /// Blue score at the pruning point.
    pub blue_score: u64,
    /// Timestamp of the pruning point.
    pub timestamp_ms: u64,
    /// SHA3-256 commitment to the UTXO set at this point.
    pub utxo_commitment: Hash,
    /// Number of UTXO entries at this point.
    pub utxo_count: u64,
}

/// A single UTXO entry in the pruning snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruningUtxoEntry {
    /// Outpoint: tx_hash + output_index.
    pub tx_hash: Hash,
    pub output_index: u32,
    /// The UTXO data.
    pub amount: u64,
    /// PQ-native address (ML-DSA-65 derived).
    pub address: Vec<u8>,
    /// Whether this is a coinbase output.
    pub is_coinbase: bool,
    /// Blue score of the block that created this UTXO.
    pub block_blue_score: u64,
}

impl MemSizeEstimate for PruningUtxoEntry {
    fn estimate_mem_bytes(&self) -> usize {
        32 + 4 + 8 + self.address.len() + 1 + 8 + 16
    }
}

impl MemSizeEstimate for PruningPointInfo {
    fn estimate_mem_bytes(&self) -> usize {
        32 + 8 + 8 + 32 + 8
    }
}

/// Pruning point store.
pub struct PruningStore {
    db: Arc<rocksdb::DB>,
    /// Current pruning point info.
    current: CachedDbItem<PruningPointInfo>,
    /// UTXO set at the pruning point.
    utxo_set: CachedDbAccess<Hash, PruningUtxoEntry>,
    /// Pruning proof data.
    proof: CachedDbItem<Vec<u8>>,
}

impl PruningStore {
    pub fn new(db: Arc<rocksdb::DB>) -> Self {
        let current_key = StorePrefixes::PruningPoint.prefix_bytes();
        let proof_key = StorePrefixes::PruningProof.prefix_bytes();

        Self {
            db: db.clone(),
            current: CachedDbItem::new(db.clone(), current_key),
            utxo_set: CachedDbAccess::new(
                db.clone(),
                CachePolicy::Tracked {
                    max_bytes: 256 * 1024 * 1024, // 256 MB cache for pruning UTXO
                    min_items: 1000,
                },
                StorePrefixes::PruningPointUtxoSet.prefix_bytes(),
            ),
            proof: CachedDbItem::new(db, proof_key),
        }
    }

    /// Get the current pruning point info.
    pub fn get_pruning_point(&self) -> Result<PruningPointInfo, StoreError> {
        self.current.read()
    }

    /// Set a new pruning point. This is an atomic operation that:
    /// 1. Updates the pruning point metadata
    /// 2. Replaces the UTXO set snapshot
    pub fn set_pruning_point(
        &self,
        info: &PruningPointInfo,
        utxo_entries: impl Iterator<Item = PruningUtxoEntry>,
    ) -> Result<(), StoreError> {
        let mut batch = AtomicBatch::new(self.db.clone());

        // Write pruning point info.
        self.current.write(batch.writer(), info)?;

        // Clear old UTXO set and write new one.
        self.utxo_set.delete_all(batch.writer())?;
        for entry in utxo_entries {
            self.utxo_set.write(batch.writer(), entry.tx_hash, entry)?;
        }

        batch.commit()?;

        info!(
            "Pruning point updated to {} (blue_score={}, utxo_count={})",
            hex::encode(&info.hash[..8]),
            info.blue_score,
            info.utxo_count
        );

        Ok(())
    }

    /// Store a pruning proof.
    pub fn set_pruning_proof(&self, proof_data: &[u8]) -> Result<(), StoreError> {
        let mut writer = DirectDbWriter::new(self.db.clone());
        self.proof.write(&mut writer, &proof_data.to_vec())
    }

    /// Get the pruning proof.
    pub fn get_pruning_proof(&self) -> Result<Vec<u8>, StoreError> {
        self.proof.read()
    }

    /// Iterate over the pruning point UTXO set.
    pub fn utxo_iterator(
        &self,
    ) -> impl Iterator<Item = Result<(Box<[u8]>, PruningUtxoEntry), StoreError>> + '_ {
        self.utxo_set.iterator()
    }

    /// Get a specific UTXO from the pruning snapshot.
    pub fn get_utxo(&self, tx_hash: Hash) -> Result<PruningUtxoEntry, StoreError> {
        self.utxo_set.read(tx_hash)
    }

    /// Check if a UTXO exists in the pruning snapshot.
    pub fn has_utxo(&self, tx_hash: Hash) -> Result<bool, StoreError> {
        self.utxo_set.has(tx_hash)
    }
}
