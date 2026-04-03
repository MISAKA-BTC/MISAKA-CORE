#![allow(dead_code)]
//! Pruning point store.

use super::ghostdag::Hash;
use misaka_database::prelude::*;
use misaka_database::registry::DatabaseStorePrefixes;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PruningPointInfo {
    pub pruning_point: Hash,
    pub candidate: Hash,
    pub index: u64,
}
impl MemSizeEstimator for PruningPointInfo {}

#[derive(Clone)]
pub struct DbPruningStore {
    db: Arc<DB>,
    item: CachedDbItem<PruningPointInfo>,
}

impl DbPruningStore {
    pub fn new(db: Arc<DB>) -> Self {
        let key = DatabaseStorePrefixes::PruningPoint.as_prefix();
        Self {
            db: db.clone(),
            item: CachedDbItem::new(db, key),
        }
    }
    pub fn get(&self) -> StoreResult<PruningPointInfo> {
        self.item.read()
    }
    pub fn set(&mut self, info: &PruningPointInfo) -> StoreResult<()> {
        self.item.write(DirectDbWriter::new(self.db.clone()), info)
    }
}
