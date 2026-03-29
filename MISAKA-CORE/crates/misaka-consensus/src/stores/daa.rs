#![allow(dead_code)]
//! DAA (Difficulty Adjustment Algorithm) score store.

use super::ghostdag::Hash;
use misaka_database::prelude::*;
use misaka_database::registry::DatabaseStorePrefixes;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Wrapper to avoid orphan rule issues with MemSizeEstimator for u64
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
pub struct DaaScore(pub u64);
impl MemSizeEstimator for DaaScore {}

#[derive(Clone)]
pub struct DbDaaStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, DaaScore>,
}

impl DbDaaStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: db.clone(), access: CachedDbAccess::new(db, cache_policy,
            DatabaseStorePrefixes::DaaScores.as_prefix()) }
    }
    pub fn insert_batch(&self, batch: &mut WriteBatch, hash: Hash, daa_score: u64) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), hash, DaaScore(daa_score))
    }
    pub fn get(&self, hash: Hash) -> StoreResult<u64> { Ok(self.access.read(hash)?.0) }
}
