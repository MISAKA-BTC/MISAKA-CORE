#![allow(dead_code, unused_imports)]
//! DAG tips store.

use super::ghostdag::Hash;
use misaka_database::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;

#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct TipsData {
    pub tips: Vec<Hash>,
}
impl MemSizeEstimator for TipsData {}

#[derive(Clone)]
pub struct DbTipsStore {
    db: Arc<DB>,
    item: CachedDbItem<TipsData>,
}

impl DbTipsStore {
    pub fn new(db: Arc<DB>) -> Self {
        let key = misaka_database::registry::DatabaseStorePrefixes::Tips.as_prefix();
        Self {
            db: db.clone(),
            item: CachedDbItem::new(db, key),
        }
    }

    pub fn get(&self) -> StoreResult<Vec<Hash>> {
        Ok(self.item.read().map(|d| d.tips).unwrap_or_default())
    }

    pub fn add_tip(&mut self, new_tip: Hash, parents: &[Hash]) -> StoreResult<Vec<Hash>> {
        let mut tips: Vec<Hash> = self.get()?;
        // Remove parents from tips (they are no longer tips)
        tips.retain(|t| !parents.contains(t));
        tips.push(new_tip);
        let data = TipsData { tips: tips.clone() };
        self.item
            .write(DirectDbWriter::new(self.db.clone()), &data)?;
        Ok(tips)
    }

    pub fn init(&mut self, initial_tips: &[Hash]) -> StoreResult<()> {
        let data = TipsData {
            tips: initial_tips.to_vec(),
        };
        self.item.write(DirectDbWriter::new(self.db.clone()), &data)
    }
}
