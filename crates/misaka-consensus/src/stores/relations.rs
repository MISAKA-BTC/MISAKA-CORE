#![allow(dead_code)]
//! Block parent/child relations store.

use super::ghostdag::Hash;
use misaka_database::prelude::*;
use misaka_database::registry::DatabaseStorePrefixes;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Wrapper around Vec<Hash> for MemSizeEstimator.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct HashVec(pub Vec<Hash>);

impl MemSizeEstimator for HashVec {
    fn estimate_mem_bytes(&self) -> usize {
        std::mem::size_of::<Vec<Hash>>() + self.0.len() * 32
    }
}

pub trait RelationsStoreReader {
    fn get_parents(&self, hash: Hash) -> StoreResult<Vec<Hash>>;
    fn get_children(&self, hash: Hash) -> StoreResult<Vec<Hash>>;
    fn has(&self, hash: Hash) -> StoreResult<bool>;
}

#[derive(Clone)]
pub struct DbRelationsStore {
    db: Arc<DB>,
    parents_access: CachedDbAccess<Hash, HashVec>,
    children_access: CachedDbAccess<Hash, HashVec>,
}

impl DbRelationsStore {
    pub fn new(db: Arc<DB>, level: u8, cache_policy: CachePolicy) -> Self {
        Self {
            db: db.clone(),
            parents_access: CachedDbAccess::new(
                db.clone(),
                cache_policy,
                DatabaseStorePrefixes::RelationsParents.with_bucket(level),
            ),
            children_access: CachedDbAccess::new(
                db,
                cache_policy,
                DatabaseStorePrefixes::RelationsChildren.with_bucket(level),
            ),
        }
    }

    pub fn insert_batch(
        &self,
        batch: &mut WriteBatch,
        hash: Hash,
        parents: Vec<Hash>,
    ) -> StoreResult<()> {
        self.parents_access
            .write(BatchDbWriter::new(batch), hash, HashVec(parents.clone()))?;
        for parent in &parents {
            let mut children = self
                .children_access
                .read(*parent)
                .map(|h| h.0)
                .unwrap_or_default();
            children.push(hash);
            self.children_access
                .write(BatchDbWriter::new(batch), *parent, HashVec(children))?;
        }
        if !self.children_access.has(hash)? {
            self.children_access
                .write(BatchDbWriter::new(batch), hash, HashVec(Vec::new()))?;
        }
        Ok(())
    }
}

impl RelationsStoreReader for DbRelationsStore {
    fn get_parents(&self, hash: Hash) -> StoreResult<Vec<Hash>> {
        Ok(self.parents_access.read(hash)?.0)
    }
    fn get_children(&self, hash: Hash) -> StoreResult<Vec<Hash>> {
        Ok(self.children_access.read(hash)?.0)
    }
    fn has(&self, hash: Hash) -> StoreResult<bool> {
        self.parents_access.has(hash)
    }
}
