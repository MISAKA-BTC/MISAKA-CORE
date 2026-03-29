#![allow(dead_code)]
//! Block status store — tracks processing state of each block.

use super::ghostdag::Hash;
use misaka_database::prelude::*;
use misaka_database::registry::DatabaseStorePrefixes;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BlockStatus {
    /// Header only — not yet validated.
    StatusHeaderOnly = 0,
    /// Invalid block (permanently rejected).
    StatusInvalid = 1,
    /// Body validated in isolation.
    StatusBodyValid = 2,
    /// UTXO state verified — eligible for chain.
    StatusUTXOValid = 3,
    /// Disqualified from the selected chain.
    StatusDisqualifiedFromChain = 4,
}
impl MemSizeEstimator for BlockStatus {}

pub trait StatusesStoreReader {
    fn get(&self, hash: Hash) -> StoreResult<BlockStatus>;
    fn has(&self, hash: Hash) -> StoreResult<bool>;
}

#[derive(Clone)]
pub struct DbStatusesStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, BlockStatus>,
}

impl DbStatusesStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: db.clone(), access: CachedDbAccess::new(db, cache_policy,
            DatabaseStorePrefixes::Statuses.as_prefix()) }
    }

    pub fn set_batch(&self, batch: &mut WriteBatch, hash: Hash, status: BlockStatus) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), hash, status)
    }

    pub fn set(&self, hash: Hash, status: BlockStatus) -> StoreResult<()> {
        self.access.write(DirectDbWriter::new(self.db.clone()), hash, status)
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, hash: Hash) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), hash)
    }
}

impl StatusesStoreReader for DbStatusesStore {
    fn get(&self, hash: Hash) -> StoreResult<BlockStatus> { self.access.read(hash) }
    fn has(&self, hash: Hash) -> StoreResult<bool> { self.access.has(hash) }
}
