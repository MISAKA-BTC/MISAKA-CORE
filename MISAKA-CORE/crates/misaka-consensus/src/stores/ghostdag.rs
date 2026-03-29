#![allow(dead_code)]
//! Typed GhostDAG data store with caching.

use misaka_database::prelude::*;
use misaka_database::registry::DatabaseStorePrefixes;
use rocksdb::WriteBatch;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub type Hash = [u8; 32];
pub const ZERO_HASH: Hash = [0u8; 32];
pub type KType = u16;
pub type BlueWorkType = u128;

#[derive(Clone, Serialize, Deserialize, Default, Debug)]
pub struct GhostdagData {
    pub blue_score: u64,
    pub blue_work: BlueWorkType,
    pub selected_parent: Hash,
    pub mergeset_blues: Vec<Hash>,
    pub mergeset_reds: Vec<Hash>,
    pub blues_anticone_sizes: Vec<(Hash, KType)>,
}

impl MemSizeEstimator for GhostdagData {
    fn estimate_mem_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + (self.mergeset_blues.len() + self.mergeset_reds.len()) * 32
            + self.blues_anticone_sizes.len() * 34
    }
}

#[derive(Clone, Serialize, Deserialize, Copy, Debug)]
pub struct CompactGhostdagData {
    pub blue_score: u64,
    pub blue_work: BlueWorkType,
    pub selected_parent: Hash,
}
impl MemSizeEstimator for CompactGhostdagData {}

impl From<&GhostdagData> for CompactGhostdagData {
    fn from(v: &GhostdagData) -> Self {
        Self { blue_score: v.blue_score, blue_work: v.blue_work, selected_parent: v.selected_parent }
    }
}

impl GhostdagData {
    pub fn new(blue_score: u64, blue_work: BlueWorkType, selected_parent: Hash,
               mergeset_blues: Vec<Hash>, mergeset_reds: Vec<Hash>,
               blues_anticone_sizes: Vec<(Hash, KType)>) -> Self {
        Self { blue_score, blue_work, selected_parent, mergeset_blues, mergeset_reds, blues_anticone_sizes }
    }
    pub fn new_with_selected_parent(selected_parent: Hash, k: KType) -> Self {
        let mut mergeset_blues = Vec::with_capacity((k + 1) as usize);
        mergeset_blues.push(selected_parent);
        Self { blue_score: 0, blue_work: 0, selected_parent, mergeset_blues,
               mergeset_reds: Vec::new(), blues_anticone_sizes: vec![(selected_parent, 0)] }
    }
    pub fn genesis_data() -> Self { Self::default() }
    pub fn mergeset_size(&self) -> usize { self.mergeset_blues.len() + self.mergeset_reds.len() }
    pub fn add_blue(&mut self, block: Hash, blue_anticone_size: KType, sizes: &[(Hash, KType)]) {
        self.mergeset_blues.push(block);
        self.blues_anticone_sizes.push((block, blue_anticone_size));
        for &(hash, size) in sizes {
            if let Some(e) = self.blues_anticone_sizes.iter_mut().find(|(h, _)| *h == hash) { e.1 = size; }
        }
    }
    pub fn add_red(&mut self, block: Hash) { self.mergeset_reds.push(block); }
    pub fn finalize_score_and_work(&mut self, blue_score: u64, blue_work: BlueWorkType) {
        self.blue_score = blue_score; self.blue_work = blue_work;
    }
    pub fn get_blue_anticone_size(&self, hash: &Hash) -> Option<KType> {
        self.blues_anticone_sizes.iter().find(|(h, _)| h == hash).map(|(_, s)| *s)
    }
}

pub trait GhostdagStoreReader {
    fn get_blue_score(&self, hash: &Hash) -> StoreResult<u64>;
    fn get_blue_work(&self, hash: &Hash) -> StoreResult<BlueWorkType>;
    fn get_selected_parent(&self, hash: &Hash) -> StoreResult<Hash>;
    fn get_data(&self, hash: &Hash) -> StoreResult<GhostdagData>;
    fn get_compact_data(&self, hash: &Hash) -> StoreResult<CompactGhostdagData>;
    fn has(&self, hash: &Hash) -> StoreResult<bool>;
}

#[derive(Clone)]
pub struct DbGhostdagStore {
    db: Arc<DB>,
    full_access: CachedDbAccess<Hash, GhostdagData>,
    compact_access: CachedDbAccess<Hash, CompactGhostdagData>,
}

impl DbGhostdagStore {
    pub fn new(db: Arc<DB>, level: u8, cache_policy: CachePolicy) -> Self {
        Self {
            db: db.clone(),
            full_access: CachedDbAccess::new(db.clone(), cache_policy,
                DatabaseStorePrefixes::Ghostdag.with_bucket(level)),
            compact_access: CachedDbAccess::new(db, cache_policy,
                DatabaseStorePrefixes::GhostdagCompact.with_bucket(level)),
        }
    }
    pub fn insert_batch(&self, batch: &mut WriteBatch, hash: Hash, data: &GhostdagData) -> StoreResult<()> {
        let compact: CompactGhostdagData = data.into();
        self.full_access.write(BatchDbWriter::new(batch), hash, data.clone())?;
        self.compact_access.write(BatchDbWriter::new(batch), hash, compact)?;
        Ok(())
    }
    pub fn insert(&self, hash: Hash, data: &GhostdagData) -> StoreResult<()> {
        let compact: CompactGhostdagData = data.into();
        self.full_access.write(DirectDbWriter::new(self.db.clone()), hash, data.clone())?;
        self.compact_access.write(DirectDbWriter::new(self.db.clone()), hash, compact)?;
        Ok(())
    }
}

impl GhostdagStoreReader for DbGhostdagStore {
    fn get_blue_score(&self, hash: &Hash) -> StoreResult<u64> { Ok(self.compact_access.read(*hash)?.blue_score) }
    fn get_blue_work(&self, hash: &Hash) -> StoreResult<BlueWorkType> { Ok(self.compact_access.read(*hash)?.blue_work) }
    fn get_selected_parent(&self, hash: &Hash) -> StoreResult<Hash> { Ok(self.compact_access.read(*hash)?.selected_parent) }
    fn get_data(&self, hash: &Hash) -> StoreResult<GhostdagData> { self.full_access.read(*hash) }
    fn get_compact_data(&self, hash: &Hash) -> StoreResult<CompactGhostdagData> { self.compact_access.read(*hash) }
    fn has(&self, hash: &Hash) -> StoreResult<bool> { self.full_access.has(*hash) }
}
