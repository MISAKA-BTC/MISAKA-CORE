#![allow(dead_code)]
//! Typed header store with compact data caching.

use super::ghostdag::Hash;
use misaka_database::prelude::*;
use misaka_database::registry::DatabaseStorePrefixes;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// MISAKA block header (PQC-native).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header {
    pub hash: Hash,
    pub version: u16,
    pub parents: Vec<Hash>,
    pub hash_merkle_root: Hash,
    pub accepted_id_merkle_root: Hash,
    pub utxo_commitment: Hash,
    pub timestamp: u64,
    pub bits: u32,
    pub nonce: u64,
    pub daa_score: u64,
    pub blue_work: u128,
    pub blue_score: u64,
    pub pruning_point: Hash,
    pub pqc_signature: Vec<u8>,
    pub proposer_pk: Vec<u8>,
}

impl MemSizeEstimator for Header {
    fn estimate_mem_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.parents.len() * 32
            + self.pqc_signature.len()
            + self.proposer_pk.len()
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
pub struct CompactHeaderData {
    pub daa_score: u64,
    pub timestamp: u64,
    pub bits: u32,
    pub blue_score: u64,
}
impl MemSizeEstimator for CompactHeaderData {}

impl From<&Header> for CompactHeaderData {
    fn from(h: &Header) -> Self {
        Self {
            daa_score: h.daa_score,
            timestamp: h.timestamp,
            bits: h.bits,
            blue_score: h.blue_score,
        }
    }
}

pub trait HeaderStoreReader {
    fn get_daa_score(&self, hash: Hash) -> StoreResult<u64>;
    fn get_blue_score(&self, hash: Hash) -> StoreResult<u64>;
    fn get_timestamp(&self, hash: Hash) -> StoreResult<u64>;
    fn get_bits(&self, hash: Hash) -> StoreResult<u32>;
    fn get_header(&self, hash: Hash) -> StoreResult<Header>;
    fn get_compact_header_data(&self, hash: Hash) -> StoreResult<CompactHeaderData>;
    fn has(&self, hash: Hash) -> StoreResult<bool>;
}

#[derive(Clone)]
pub struct DbHeadersStore {
    db: Arc<DB>,
    headers_access: CachedDbAccess<Hash, Header>,
    compact_access: CachedDbAccess<Hash, CompactHeaderData>,
}

impl DbHeadersStore {
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy, compact_cache_policy: CachePolicy) -> Self {
        Self {
            db: db.clone(),
            headers_access: CachedDbAccess::new(
                db.clone(),
                cache_policy,
                DatabaseStorePrefixes::Headers.as_prefix(),
            ),
            compact_access: CachedDbAccess::new(
                db,
                compact_cache_policy,
                DatabaseStorePrefixes::HeadersCompact.as_prefix(),
            ),
        }
    }

    pub fn insert_batch(
        &self,
        batch: &mut WriteBatch,
        hash: Hash,
        header: Header,
    ) -> StoreResult<()> {
        if self.headers_access.has(hash)? {
            return Err(StoreError::HashAlreadyExists(hex::encode(hash)));
        }
        let compact: CompactHeaderData = (&header).into();
        self.headers_access
            .write(BatchDbWriter::new(batch), hash, header)?;
        self.compact_access
            .write(BatchDbWriter::new(batch), hash, compact)?;
        Ok(())
    }

    pub fn delete_batch(&self, batch: &mut WriteBatch, hash: Hash) -> StoreResult<()> {
        self.headers_access
            .delete(BatchDbWriter::new(batch), hash)?;
        self.compact_access
            .delete(BatchDbWriter::new(batch), hash)?;
        Ok(())
    }
}

impl HeaderStoreReader for DbHeadersStore {
    fn get_daa_score(&self, hash: Hash) -> StoreResult<u64> {
        Ok(self.compact_access.read(hash)?.daa_score)
    }
    fn get_blue_score(&self, hash: Hash) -> StoreResult<u64> {
        Ok(self.compact_access.read(hash)?.blue_score)
    }
    fn get_timestamp(&self, hash: Hash) -> StoreResult<u64> {
        Ok(self.compact_access.read(hash)?.timestamp)
    }
    fn get_bits(&self, hash: Hash) -> StoreResult<u32> {
        Ok(self.compact_access.read(hash)?.bits)
    }
    fn get_header(&self, hash: Hash) -> StoreResult<Header> {
        self.headers_access.read(hash)
    }
    fn get_compact_header_data(&self, hash: Hash) -> StoreResult<CompactHeaderData> {
        self.compact_access.read(hash)
    }
    fn has(&self, hash: Hash) -> StoreResult<bool> {
        self.headers_access.has(hash)
    }
}
