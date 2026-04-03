#![allow(dead_code)]
//! Virtual state store — represents the UTXO state of the virtual block.

use super::ghostdag::{GhostdagData, Hash};
use super::utxo_diffs::UtxoDiff;
use misaka_database::prelude::*;
use misaka_database::registry::DatabaseStorePrefixes;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct VirtualState {
    pub parents: Vec<Hash>,
    pub ghostdag_data: GhostdagData,
    pub daa_score: u64,
    pub bits: u32,
    pub past_median_time: u64,
    pub utxo_diff: UtxoDiff,
    pub accepted_tx_ids: Vec<Hash>,
    pub multiset_hash: Hash,
}
impl MemSizeEstimator for VirtualState {}

pub trait VirtualStateStoreReader {
    fn get(&self) -> StoreResult<VirtualState>;
}

#[derive(Clone)]
pub struct DbVirtualStateStore {
    db: Arc<DB>,
    item: CachedDbItem<VirtualState>,
}

impl DbVirtualStateStore {
    pub fn new(db: Arc<DB>) -> Self {
        let key = DatabaseStorePrefixes::VirtualState.as_prefix();
        Self {
            db: db.clone(),
            item: CachedDbItem::new(db, key),
        }
    }

    pub fn set(&mut self, state: &VirtualState) -> StoreResult<()> {
        self.item.write(DirectDbWriter::new(self.db.clone()), state)
    }
}

impl VirtualStateStoreReader for DbVirtualStateStore {
    fn get(&self) -> StoreResult<VirtualState> {
        self.item.read()
    }
}
