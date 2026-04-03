//! Write abstraction: direct vs batch.

use crate::db::DB;
use rocksdb::WriteBatch;
use std::collections::HashMap;
use std::sync::Arc;

/// Abstraction over direct/batched DB writing.
pub trait DbWriter {
    fn put<K, V>(&mut self, key: K, value: V) -> Result<(), rocksdb::Error>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>;
    fn delete<K: AsRef<[u8]>>(&mut self, key: K) -> Result<(), rocksdb::Error>;
    fn delete_range<K>(&mut self, from: K, to: K) -> Result<(), rocksdb::Error>
    where
        K: AsRef<[u8]>;
}

/// Marker trait: not implemented for batch writer (compile-time safety).
pub trait DirectWriter: DbWriter {}

// ── Direct writer ──────────────────────────────────────────────

pub struct DirectDbWriter {
    db: Arc<DB>,
}

impl DirectDbWriter {
    pub fn new(db: Arc<DB>) -> Self {
        Self { db }
    }
}

impl DbWriter for DirectDbWriter {
    fn put<K, V>(&mut self, key: K, value: V) -> Result<(), rocksdb::Error>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.db.put(key, value)
    }

    fn delete<K: AsRef<[u8]>>(&mut self, key: K) -> Result<(), rocksdb::Error> {
        self.db.delete(key)
    }

    fn delete_range<K>(&mut self, from: K, to: K) -> Result<(), rocksdb::Error>
    where
        K: AsRef<[u8]>,
    {
        let mut batch = WriteBatch::default();
        batch.delete_range(from, to);
        self.db.write(batch)
    }
}

impl DirectWriter for DirectDbWriter {}

// ── Batch writer ───────────────────────────────────────────────

pub struct BatchDbWriter<'a> {
    batch: &'a mut WriteBatch,
}

impl<'a> BatchDbWriter<'a> {
    pub fn new(batch: &'a mut WriteBatch) -> Self {
        Self { batch }
    }
}

impl DbWriter for BatchDbWriter<'_> {
    fn put<K, V>(&mut self, key: K, value: V) -> Result<(), rocksdb::Error>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.batch.put(key, value);
        Ok(())
    }

    fn delete<K: AsRef<[u8]>>(&mut self, key: K) -> Result<(), rocksdb::Error> {
        self.batch.delete(key);
        Ok(())
    }

    fn delete_range<K>(&mut self, from: K, to: K) -> Result<(), rocksdb::Error>
    where
        K: AsRef<[u8]>,
    {
        self.batch.delete_range(from, to);
        Ok(())
    }
}

// ── Memory writer (for tests) ──────────────────────────────────

pub struct MemoryWriter {
    pub entries: HashMap<Vec<u8>, Vec<u8>>,
    pub deleted: Vec<Vec<u8>>,
}

impl Default for MemoryWriter {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            deleted: Vec::new(),
        }
    }
}

impl DbWriter for MemoryWriter {
    fn put<K, V>(&mut self, key: K, value: V) -> Result<(), rocksdb::Error>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        self.entries
            .insert(key.as_ref().to_vec(), value.as_ref().to_vec());
        Ok(())
    }

    fn delete<K: AsRef<[u8]>>(&mut self, key: K) -> Result<(), rocksdb::Error> {
        self.deleted.push(key.as_ref().to_vec());
        self.entries.remove(key.as_ref());
        Ok(())
    }

    fn delete_range<K>(&mut self, _from: K, _to: K) -> Result<(), rocksdb::Error>
    where
        K: AsRef<[u8]>,
    {
        Ok(())
    }
}

impl DirectWriter for MemoryWriter {}

// ── Blanket for &mut T ─────────────────────────────────────────

impl<T: DbWriter> DbWriter for &mut T {
    #[inline]
    fn put<K, V>(&mut self, key: K, value: V) -> Result<(), rocksdb::Error>
    where
        K: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        (**self).put(key, value)
    }

    #[inline]
    fn delete<K: AsRef<[u8]>>(&mut self, key: K) -> Result<(), rocksdb::Error> {
        (**self).delete(key)
    }

    #[inline]
    fn delete_range<K>(&mut self, from: K, to: K) -> Result<(), rocksdb::Error>
    where
        K: AsRef<[u8]>,
    {
        (**self).delete_range(from, to)
    }
}
