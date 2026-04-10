#![allow(dead_code, unused_imports)]
//! Reachability store — interval-based DAG reachability queries.

use super::ghostdag::Hash;
use misaka_database::prelude::*;
use misaka_database::registry::DatabaseStorePrefixes;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Interval assigned during tree-traversal for O(1) reachability queries.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, Default)]
pub struct ReachabilityInterval {
    pub start: u64,
    pub end: u64,
}
impl MemSizeEstimator for ReachabilityInterval {}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct ReachabilityData {
    pub interval: ReachabilityInterval,
    pub parent: Hash,
    pub children: Vec<Hash>,
    pub future_covering_set: Vec<Hash>,
}
impl MemSizeEstimator for ReachabilityData {
    fn estimate_mem_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + (self.children.len() + self.future_covering_set.len()) * 32
    }
}

pub trait ReachabilityStoreReader {
    fn get_interval(&self, hash: Hash) -> StoreResult<ReachabilityInterval>;
    fn get_parent(&self, hash: Hash) -> StoreResult<Hash>;
    fn get_children(&self, hash: Hash) -> StoreResult<Vec<Hash>>;
    fn get_future_covering_set(&self, hash: Hash) -> StoreResult<Vec<Hash>>;
    fn has(&self, hash: Hash) -> StoreResult<bool>;
}

#[derive(Clone)]
pub struct DbReachabilityStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, ReachabilityData>,
}

impl DbReachabilityStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self {
            db: db.clone(),
            access: CachedDbAccess::new(
                db,
                cache_policy,
                DatabaseStorePrefixes::Reachability.as_prefix(),
            ),
        }
    }

    pub fn insert_batch(
        &self,
        batch: &mut WriteBatch,
        hash: Hash,
        data: ReachabilityData,
    ) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), hash, data)
    }

    pub fn insert(&self, hash: Hash, data: ReachabilityData) -> StoreResult<()> {
        self.access
            .write(DirectDbWriter::new(self.db.clone()), hash, data)
    }

    pub fn set_interval(
        &self,
        batch: &mut WriteBatch,
        hash: Hash,
        interval: ReachabilityInterval,
    ) -> StoreResult<()> {
        let mut data = self.access.read(hash).unwrap_or_default();
        data.interval = interval;
        self.access.write(BatchDbWriter::new(batch), hash, data)
    }
}

impl ReachabilityStoreReader for DbReachabilityStore {
    fn get_interval(&self, hash: Hash) -> StoreResult<ReachabilityInterval> {
        Ok(self.access.read(hash)?.interval)
    }
    fn get_parent(&self, hash: Hash) -> StoreResult<Hash> {
        Ok(self.access.read(hash)?.parent)
    }
    fn get_children(&self, hash: Hash) -> StoreResult<Vec<Hash>> {
        Ok(self.access.read(hash)?.children)
    }
    fn get_future_covering_set(&self, hash: Hash) -> StoreResult<Vec<Hash>> {
        Ok(self.access.read(hash)?.future_covering_set)
    }
    fn has(&self, hash: Hash) -> StoreResult<bool> {
        self.access.has(hash)
    }
}
