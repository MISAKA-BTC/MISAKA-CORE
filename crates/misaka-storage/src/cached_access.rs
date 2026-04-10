//! # Cached DB Access — Typed Key-Value Store with LRU Cache
//!
//! Kaspa-aligned concurrent DB store with transparent caching.
//! Reads check cache first, writes update both cache and DB.
//! Supports iteration, batch writes, and range deletes.

use std::sync::Arc;

use serde::{de::DeserializeOwned, Serialize};

use crate::cache::{Cache, CachePolicy, MemSizeEstimate};
use crate::db_key::DbKey;
use crate::db_writer::DbWriter;
use crate::store_errors::StoreError;

/// A concurrent DB store with typed caching.
#[derive(Clone)]
pub struct CachedDbAccess<TKey, TData>
where
    TKey: Clone + std::hash::Hash + Eq + Send + Sync,
    TData: Clone + Send + Sync + MemSizeEstimate,
{
    db: Arc<rocksdb::DB>,
    cache: Cache<TKey, TData>,
    prefix: Vec<u8>,
}

impl<TKey, TData> CachedDbAccess<TKey, TData>
where
    TKey: Clone + std::hash::Hash + Eq + Send + Sync,
    TData: Clone + Send + Sync + MemSizeEstimate,
{
    pub fn new(db: Arc<rocksdb::DB>, cache_policy: CachePolicy, prefix: Vec<u8>) -> Self {
        Self {
            db,
            cache: Cache::new(cache_policy),
            prefix,
        }
    }

    /// Check if a key exists (cache or DB).
    pub fn has(&self, key: TKey) -> Result<bool, StoreError>
    where
        TKey: AsRef<[u8]>,
    {
        if self.cache.contains_key(&key) {
            return Ok(true);
        }
        let db_key = DbKey::new(&self.prefix, key);
        Ok(self.db.get_pinned(db_key)?.is_some())
    }

    /// Read a value (cache-first, then DB).
    pub fn read(&self, key: TKey) -> Result<TData, StoreError>
    where
        TKey: AsRef<[u8]>,
        TData: DeserializeOwned,
    {
        if let Some(data) = self.cache.get(&key) {
            return Ok(data);
        }
        let db_key = DbKey::new(&self.prefix, key.clone());
        if let Some(slice) = self.db.get_pinned(&db_key)? {
            let data: TData = bincode::deserialize(&slice)
                .map_err(|e| StoreError::DeserializeError(e.to_string()))?;
            self.cache.insert(key, data.clone());
            Ok(data)
        } else {
            Err(StoreError::KeyNotFound(hex::encode(db_key.as_ref())))
        }
    }

    /// Read from cache only (no DB fallback).
    pub fn read_from_cache(&self, key: &TKey) -> Option<TData> {
        self.cache.get(key)
    }

    /// Write a key-value pair (updates both cache and DB).
    pub fn write(&self, mut writer: impl DbWriter, key: TKey, data: TData) -> Result<(), StoreError>
    where
        TKey: AsRef<[u8]>,
        TData: Serialize,
    {
        let bin =
            bincode::serialize(&data).map_err(|e| StoreError::SerializeError(e.to_string()))?;
        self.cache.insert(key.clone(), data);
        writer.put(DbKey::new(&self.prefix, key), bin)?;
        Ok(())
    }

    /// Write many key-value pairs.
    pub fn write_many(
        &self,
        mut writer: impl DbWriter,
        iter: &mut (impl Iterator<Item = (TKey, TData)> + Clone),
    ) -> Result<(), StoreError>
    where
        TKey: AsRef<[u8]>,
        TData: Serialize,
    {
        let iter_clone = iter.clone();
        self.cache.insert_many(iter);
        for (key, data) in iter_clone {
            let bin =
                bincode::serialize(&data).map_err(|e| StoreError::SerializeError(e.to_string()))?;
            writer.put(DbKey::new(&self.prefix, key), bin)?;
        }
        Ok(())
    }

    /// Write many without caching (used for bulk import).
    pub fn write_many_uncached(
        &self,
        mut writer: impl DbWriter,
        iter: &mut impl Iterator<Item = (TKey, TData)>,
    ) -> Result<(), StoreError>
    where
        TKey: AsRef<[u8]>,
        TData: Serialize,
    {
        for (key, data) in iter {
            let bin =
                bincode::serialize(&data).map_err(|e| StoreError::SerializeError(e.to_string()))?;
            writer.put(DbKey::new(&self.prefix, key), bin)?;
        }
        self.cache.remove_all(); // Invalidate cache after uncached bulk write.
        Ok(())
    }

    /// Delete a key.
    pub fn delete(&self, mut writer: impl DbWriter, key: TKey) -> Result<(), StoreError>
    where
        TKey: AsRef<[u8]>,
    {
        self.cache.remove(&key);
        writer.delete(DbKey::new(&self.prefix, key))?;
        Ok(())
    }

    /// Delete all entries in this store (uses delete_range).
    pub fn delete_all(&self, mut writer: impl DbWriter) -> Result<(), StoreError>
    where
        TKey: AsRef<[u8]>,
    {
        self.cache.remove_all();
        let prefix_key = DbKey::prefix_only(&self.prefix);
        // Create end-of-range by incrementing last prefix byte.
        let mut end = self.prefix.clone();
        if let Some(last) = end.last_mut() {
            *last = last.wrapping_add(1);
        }
        writer.delete_range(prefix_key.as_ref(), &end)?;
        Ok(())
    }

    /// Iterate over all entries in this store.
    pub fn iterator(&self) -> impl Iterator<Item = Result<(Box<[u8]>, TData), StoreError>> + '_
    where
        TData: DeserializeOwned,
    {
        let prefix_key = DbKey::prefix_only(&self.prefix);
        let mut read_opts = rocksdb::ReadOptions::default();
        read_opts.set_iterate_range(rocksdb::PrefixRange(prefix_key.as_ref()));

        self.db
            .iterator_opt(
                rocksdb::IteratorMode::From(prefix_key.as_ref(), rocksdb::Direction::Forward),
                read_opts,
            )
            .map(move |result| match result {
                Ok((key_bytes, val_bytes)) => {
                    let data: TData = bincode::deserialize(&val_bytes)
                        .map_err(|e| StoreError::DeserializeError(e.to_string()))?;
                    let trimmed_key = key_bytes[self.prefix.len()..].into();
                    Ok((trimmed_key, data))
                }
                Err(e) => Err(StoreError::RocksDb(e.to_string())),
            })
    }

    /// Count entries.
    pub fn count(&self) -> usize
    where
        TData: DeserializeOwned,
    {
        self.iterator().count()
    }

    pub fn prefix(&self) -> &[u8] {
        &self.prefix
    }

    pub fn cache_len(&self) -> usize {
        self.cache.len()
    }
}

/// Single-value cached item (like Kaspa's CachedDbItem).
#[derive(Clone)]
pub struct CachedDbItem<T> {
    db: Arc<rocksdb::DB>,
    key: Vec<u8>,
    cached: Arc<parking_lot::RwLock<Option<T>>>,
}

impl<T: Clone + Serialize + DeserializeOwned> CachedDbItem<T> {
    pub fn new(db: Arc<rocksdb::DB>, key: Vec<u8>) -> Self {
        Self {
            db,
            key,
            cached: Arc::new(parking_lot::RwLock::new(None)),
        }
    }

    pub fn read(&self) -> Result<T, StoreError> {
        if let Some(item) = self.cached.read().clone() {
            return Ok(item);
        }
        if let Some(slice) = self.db.get_pinned(&self.key)? {
            let item: T = bincode::deserialize(&slice)
                .map_err(|e| StoreError::DeserializeError(e.to_string()))?;
            *self.cached.write() = Some(item.clone());
            Ok(item)
        } else {
            Err(StoreError::KeyNotFound(hex::encode(&self.key)))
        }
    }

    pub fn write(&self, mut writer: impl DbWriter, item: &T) -> Result<(), StoreError> {
        *self.cached.write() = Some(item.clone());
        let bin =
            bincode::serialize(item).map_err(|e| StoreError::SerializeError(e.to_string()))?;
        writer.put(&self.key, bin)?;
        Ok(())
    }

    pub fn update<F>(&self, mut writer: impl DbWriter, op: F) -> Result<T, StoreError>
    where
        F: FnOnce(T) -> T,
    {
        let mut guard = self.cached.write();
        let current = if let Some(item) = guard.take() {
            item
        } else if let Some(slice) = self.db.get_pinned(&self.key)? {
            bincode::deserialize(&slice).map_err(|e| StoreError::DeserializeError(e.to_string()))?
        } else {
            return Err(StoreError::KeyNotFound(hex::encode(&self.key)));
        };

        let updated = op(current);
        *guard = Some(updated.clone());
        let bin =
            bincode::serialize(&updated).map_err(|e| StoreError::SerializeError(e.to_string()))?;
        writer.put(&self.key, bin)?;
        Ok(updated)
    }

    pub fn delete(&self, mut writer: impl DbWriter) -> Result<(), StoreError> {
        *self.cached.write() = None;
        writer.delete(&self.key)?;
        Ok(())
    }
}
