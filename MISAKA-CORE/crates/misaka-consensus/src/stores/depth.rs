#![allow(dead_code)]
//! Block depth store — merge depth for finality.

use super::ghostdag::Hash;
use misaka_database::prelude::*;
use misaka_database::registry::DatabaseStorePrefixes;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct BlockDepthData {
    pub merge_depth_root: Hash,
    pub finality_point: Hash,
}
impl MemSizeEstimator for BlockDepthData {}

#[derive(Clone)]
pub struct DbDepthStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, BlockDepthData>,
}

impl DbDepthStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: db.clone(), access: CachedDbAccess::new(db, cache_policy,
            DatabaseStorePrefixes::BlockDepth.as_prefix()) }
    }
    pub fn insert_batch(&self, batch: &mut WriteBatch, hash: Hash, data: BlockDepthData) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), hash, data)
    }
    pub fn get(&self, hash: Hash) -> StoreResult<BlockDepthData> { self.access.read(hash) }
}
