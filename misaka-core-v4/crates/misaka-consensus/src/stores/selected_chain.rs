#![allow(dead_code, unused_imports)]
//! Selected chain store — maps chain index <-> block hash.

use super::ghostdag::Hash;
use misaka_database::prelude::*;
use misaka_database::registry::DatabaseStorePrefixes;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
pub struct U64Key(pub u64);

impl AsRef<[u8]> for U64Key {
    fn as_ref(&self) -> &[u8] {
        // This is safe: we store the bytes inline and return a reference
        // via a helper that converts through to_le_bytes
        // But since we need a &[u8] with lifetime tied to self, we use a trick:
        // Actually, we cannot safely return &[u8] from a local.
        // We'll implement a different approach: use the Serialize/Deserialize path.
        // For CachedDbAccess we need AsRef<[u8]>, so we store bytes inline.
        &[] // placeholder — see U64KeyBytes below
    }
}

impl ToString for U64Key {
    fn to_string(&self) -> String {
        self.0.to_string()
    }
}
impl MemSizeEstimator for U64Key {}

/// A key type that stores 8 bytes inline for safe AsRef<[u8]>.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct U64KeyBytes {
    bytes: [u8; 8],
}

impl U64KeyBytes {
    pub fn new(val: u64) -> Self {
        Self {
            bytes: val.to_le_bytes(),
        }
    }
    pub fn value(&self) -> u64 {
        u64::from_le_bytes(self.bytes)
    }
}

impl AsRef<[u8]> for U64KeyBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl ToString for U64KeyBytes {
    fn to_string(&self) -> String {
        self.value().to_string()
    }
}
impl MemSizeEstimator for U64KeyBytes {}

/// Wrapper for u64 values stored in DB.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct StoredU64(pub u64);
impl MemSizeEstimator for StoredU64 {}

pub trait SelectedChainStoreReader {
    fn get_by_hash(&self, hash: Hash) -> StoreResult<u64>;
    fn get_by_index(&self, index: u64) -> StoreResult<Hash>;
    fn get_tip(&self) -> StoreResult<(u64, Hash)>;
}

#[derive(Clone)]
pub struct DbSelectedChainStore {
    db: Arc<DB>,
    hash_by_index: CachedDbAccess<U64KeyBytes, Hash>,
    index_by_hash: CachedDbAccess<Hash, StoredU64>,
    highest_index: CachedDbItem<StoredU64>,
}

impl DbSelectedChainStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy) -> Self {
        Self {
            db: db.clone(),
            hash_by_index: CachedDbAccess::new(
                db.clone(),
                cache_policy,
                DatabaseStorePrefixes::ChainHashByIndex.as_prefix(),
            ),
            index_by_hash: CachedDbAccess::new(
                db.clone(),
                cache_policy,
                DatabaseStorePrefixes::ChainIndexByHash.as_prefix(),
            ),
            highest_index: CachedDbItem::new(
                db,
                DatabaseStorePrefixes::ChainHighestIndex.as_prefix(),
            ),
        }
    }

    pub fn apply_new_chain_block(
        &mut self,
        batch: &mut WriteBatch,
        index: u64,
        hash: Hash,
    ) -> StoreResult<()> {
        self.hash_by_index
            .write(BatchDbWriter::new(batch), U64KeyBytes::new(index), hash)?;
        self.index_by_hash
            .write(BatchDbWriter::new(batch), hash, StoredU64(index))?;
        self.highest_index
            .write(BatchDbWriter::new(batch), &StoredU64(index))?;
        Ok(())
    }
}

impl SelectedChainStoreReader for DbSelectedChainStore {
    fn get_by_hash(&self, hash: Hash) -> StoreResult<u64> {
        Ok(self.index_by_hash.read(hash)?.0)
    }
    fn get_by_index(&self, index: u64) -> StoreResult<Hash> {
        self.hash_by_index.read(U64KeyBytes::new(index))
    }
    fn get_tip(&self) -> StoreResult<(u64, Hash)> {
        let idx = self.highest_index.read()?.0;
        let hash = self.hash_by_index.read(U64KeyBytes::new(idx))?;
        Ok((idx, hash))
    }
}
