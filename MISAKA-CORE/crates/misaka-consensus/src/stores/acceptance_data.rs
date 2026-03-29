#![allow(dead_code)]
//! Acceptance data store — records which transactions were accepted per block.

use super::ghostdag::Hash;
use misaka_database::prelude::*;
use misaka_database::registry::DatabaseStorePrefixes;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MergesetBlockAcceptanceData {
    pub block_hash: Hash,
    pub accepted_transactions: Vec<AcceptedTxEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcceptedTxEntry {
    pub tx_id: Hash,
    pub index_within_block: u32,
    pub is_fee_output: bool,
}

/// Full acceptance data for a chain block.
pub type AcceptanceData = Vec<MergesetBlockAcceptanceData>;

#[derive(Clone, Serialize, Deserialize)]
struct AcceptanceDataWrapper(AcceptanceData);
impl MemSizeEstimator for AcceptanceDataWrapper {
    fn estimate_mem_bytes(&self) -> usize {
        self.0.iter().map(|b| b.accepted_transactions.len()).sum::<usize>()
            * std::mem::size_of::<AcceptedTxEntry>()
            + self.0.len() * std::mem::size_of::<MergesetBlockAcceptanceData>()
    }
}

#[derive(Clone)]
pub struct DbAcceptanceDataStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, AcceptanceDataWrapper>,
}

impl DbAcceptanceDataStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: db.clone(), access: CachedDbAccess::new(db, cache_policy,
            DatabaseStorePrefixes::AcceptanceData.as_prefix()) }
    }
    pub fn insert_batch(&self, batch: &mut WriteBatch, hash: Hash, data: AcceptanceData) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), hash, AcceptanceDataWrapper(data))
    }
    pub fn get(&self, hash: Hash) -> StoreResult<AcceptanceData> {
        Ok(self.access.read(hash)?.0)
    }
    pub fn delete_batch(&self, batch: &mut WriteBatch, hash: Hash) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), hash)
    }
}
