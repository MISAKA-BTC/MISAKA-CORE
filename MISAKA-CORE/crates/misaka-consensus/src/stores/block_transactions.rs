#![allow(dead_code)]
//! Block transactions store.

use super::ghostdag::Hash;
use misaka_database::prelude::*;
use misaka_database::registry::DatabaseStorePrefixes;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Lightweight transaction reference stored per block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredTransaction {
    pub tx_id: Hash,
    pub inputs: Vec<StoredTxInput>,
    pub outputs: Vec<StoredTxOutput>,
    pub gas_budget: u64,
    pub gas_price: u64,
    pub is_coinbase: bool,
    /// Serialized PQC signature bytes.
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredTxInput {
    pub previous_tx_id: Hash,
    pub previous_index: u32,
    pub sig_script: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredTxOutput {
    pub amount: u64,
    pub script_public_key: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BlockTransactions(pub Vec<StoredTransaction>);
impl MemSizeEstimator for BlockTransactions {
    fn estimate_mem_bytes(&self) -> usize {
        self.0.len() * 256 // rough estimate
    }
}

#[derive(Clone)]
pub struct DbBlockTransactionsStore {
    db: Arc<DB>,
    access: CachedDbAccess<Hash, BlockTransactions>,
}

impl DbBlockTransactionsStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self { db: db.clone(), access: CachedDbAccess::new(db, cache_policy,
            DatabaseStorePrefixes::BlockTransactions.as_prefix()) }
    }
    pub fn insert_batch(&self, batch: &mut WriteBatch, hash: Hash, txs: Vec<StoredTransaction>) -> StoreResult<()> {
        self.access.write(BatchDbWriter::new(batch), hash, BlockTransactions(txs))
    }
    pub fn get(&self, hash: Hash) -> StoreResult<Vec<StoredTransaction>> {
        Ok(self.access.read(hash)?.0)
    }
    pub fn delete_batch(&self, batch: &mut WriteBatch, hash: Hash) -> StoreResult<()> {
        self.access.delete(BatchDbWriter::new(batch), hash)
    }
}
