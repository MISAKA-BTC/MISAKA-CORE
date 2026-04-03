//! Concurrent DB store access with typed caching.

use crate::cache::{Cache, CachePolicy, MemSizeEstimator};
use crate::db::DB;
use crate::errors::StoreError;
use crate::key::DbKey;
use crate::writer::DbWriter;

use rocksdb::{Direction, IteratorMode, ReadOptions};
use serde::{de::DeserializeOwned, Serialize};
use std::collections::hash_map::RandomState;
use std::error::Error;
use std::hash::BuildHasher;
use std::sync::Arc;

/// A concurrent DB store access with typed caching.
#[derive(Clone)]
pub struct CachedDbAccess<TKey, TData, S = RandomState>
where
    TKey: Clone + std::hash::Hash + Eq + Send + Sync,
    TData: Clone + Send + Sync + MemSizeEstimator,
{
    db: Arc<DB>,
    cache: Cache<TKey, TData, S>,
    prefix: Vec<u8>,
}

pub type KeyDataResult<TData> = Result<(Box<[u8]>, TData), Box<dyn Error>>;

impl<TKey, TData, S> CachedDbAccess<TKey, TData, S>
where
    TKey: Clone + std::hash::Hash + Eq + Send + Sync,
    TData: Clone + Send + Sync + MemSizeEstimator,
    S: BuildHasher + Default,
{
    pub fn new(db: Arc<DB>, cache_policy: CachePolicy, prefix: Vec<u8>) -> Self {
        Self {
            db,
            cache: Cache::new(cache_policy),
            prefix,
        }
    }

    pub fn has(&self, key: TKey) -> Result<bool, StoreError>
    where
        TKey: Clone + AsRef<[u8]>,
    {
        Ok(self.cache.contains_key(&key)
            || self.db.get_pinned(DbKey::new(&self.prefix, key))?.is_some())
    }

    pub fn read(&self, key: TKey) -> Result<TData, StoreError>
    where
        TKey: Clone + AsRef<[u8]>,
        TData: DeserializeOwned,
    {
        if let Some(data) = self.cache.get(&key) {
            Ok(data)
        } else {
            let db_key = DbKey::new(&self.prefix, key.clone());
            if let Some(slice) = self.db.get_pinned(&db_key)? {
                let data: TData = bincode::deserialize(&slice)?;
                self.cache.insert(key, data.clone());
                Ok(data)
            } else {
                Err(StoreError::KeyNotFound(db_key.to_string()))
            }
        }
    }

    pub fn write(&self, mut writer: impl DbWriter, key: TKey, data: TData) -> Result<(), StoreError>
    where
        TKey: Clone + AsRef<[u8]>,
        TData: Serialize,
    {
        let db_key = DbKey::new(&self.prefix, key.clone());
        let bin_data = bincode::serialize(&data)?;
        writer.put(&db_key, bin_data)?;
        self.cache.insert(key, data);
        Ok(())
    }

    pub fn write_no_overwrite(
        &self,
        writer: impl DbWriter,
        key: TKey,
        data: TData,
    ) -> Result<(), StoreError>
    where
        TKey: Clone + AsRef<[u8]>,
        TData: Serialize,
    {
        if self.has(key.clone())? {
            return Err(StoreError::KeyAlreadyExists(format!(
                "key already exists (prefix={})",
                hex::encode(&self.prefix)
            )));
        }
        self.write(writer, key, data)
    }

    pub fn delete(&self, mut writer: impl DbWriter, key: TKey) -> Result<(), StoreError>
    where
        TKey: Clone + AsRef<[u8]>,
    {
        let db_key = DbKey::new(&self.prefix, key.clone());
        writer.delete(&db_key)?;
        self.cache.remove(&key);
        Ok(())
    }

    pub fn iterator(&self) -> impl Iterator<Item = KeyDataResult<TData>> + '_
    where
        TKey: Clone + AsRef<[u8]>,
        TData: DeserializeOwned,
    {
        let db_key = DbKey::prefix_only(&self.prefix);
        let prefix_len = self.prefix.len();
        let mut read_opts = ReadOptions::default();
        read_opts.set_iterate_range(rocksdb::PrefixRange(db_key.as_ref()));

        self.db
            .iterator_opt(
                IteratorMode::From(db_key.as_ref(), Direction::Forward),
                read_opts,
            )
            .map(move |item| {
                let (key, value) = item.map_err(|e| Box::new(e) as Box<dyn Error>)?;
                let data: TData =
                    bincode::deserialize(&value).map_err(|e| Box::new(e) as Box<dyn Error>)?;
                Ok((key[prefix_len..].into(), data))
            })
    }
}
