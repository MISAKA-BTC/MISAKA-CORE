#![allow(dead_code)]
//! UTXO diff store — stores the UTXO delta per chain block.

use super::ghostdag::Hash;
use misaka_database::prelude::*;
use misaka_database::registry::DatabaseStorePrefixes;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A UTXO diff (delta) representing added and removed entries.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct UtxoDiff {
    pub added: Vec<UtxoEntry>,
    pub removed: Vec<UtxoEntry>,
}
impl MemSizeEstimator for UtxoDiff {
    fn estimate_mem_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + (self.added.len() + self.removed.len()) * std::mem::size_of::<UtxoEntry>()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UtxoEntry {
    pub outpoint: Outpoint,
    pub amount: u64,
    pub script_public_key: Vec<u8>,
    pub block_daa_score: u64,
    pub is_coinbase: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Outpoint {
    pub transaction_id: Hash,
    pub index: u32,
}

#[derive(Clone)]
pub struct DbUtxoDiffsStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, UtxoDiff>,
}

impl DbUtxoDiffsStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self {
            db: db.clone(),
            access: CachedDbAccess::new(
                db,
                cache_policy,
                DatabaseStorePrefixes::UtxoDiffs.as_prefix(),
            ),
        }
    }
    pub fn insert_batch(
        &self,
        batch: &mut WriteBatch,
        hash: Hash,
        diff: UtxoDiff,
    ) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), hash, diff)
    }
    pub fn get(&self, hash: Hash) -> StoreResult<UtxoDiff> {
        self.access.read(hash)
    }
    pub fn delete_batch(&self, batch: &mut WriteBatch, hash: Hash) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), hash)
    }
}
