//! # DB Writer — Kaspa-Aligned Write Abstraction
//!
//! `DbWriter` trait enables both direct writes and batched atomic writes.
//! `DirectDbWriter` writes immediately; `BatchDbWriter` accumulates into
//! a RocksDB `WriteBatch` for atomic commit.

use std::sync::Arc;

use rocksdb::WriteBatch;

/// Abstraction over direct and batched DB writing.
pub trait DbWriter {
    fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        key: K,
        value: V,
    ) -> Result<(), rocksdb::Error>;

    fn delete<K: AsRef<[u8]>>(&mut self, key: K) -> Result<(), rocksdb::Error>;

    fn delete_range<K: AsRef<[u8]>>(&mut self, from: K, to: K) -> Result<(), rocksdb::Error>;
}

/// Marker trait for writers that commit immediately (not batch).
pub trait DirectWriter: DbWriter {}

/// Writes directly to RocksDB on each operation.
pub struct DirectDbWriter {
    db: Arc<rocksdb::DB>,
}

impl DirectDbWriter {
    pub fn new(db: Arc<rocksdb::DB>) -> Self {
        Self { db }
    }
}

impl DbWriter for DirectDbWriter {
    fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        key: K,
        value: V,
    ) -> Result<(), rocksdb::Error> {
        self.db.put(key, value)
    }

    fn delete<K: AsRef<[u8]>>(&mut self, key: K) -> Result<(), rocksdb::Error> {
        self.db.delete(key)
    }

    fn delete_range<K: AsRef<[u8]>>(&mut self, from: K, to: K) -> Result<(), rocksdb::Error> {
        let mut batch = WriteBatch::default();
        batch.delete_range(from, to);
        self.db.write(batch)
    }
}

impl DirectWriter for DirectDbWriter {}

/// Accumulates writes into a `WriteBatch` for atomic commit.
pub struct BatchDbWriter<'a> {
    batch: &'a mut WriteBatch,
}

impl<'a> BatchDbWriter<'a> {
    pub fn new(batch: &'a mut WriteBatch) -> Self {
        Self { batch }
    }
}

impl DbWriter for BatchDbWriter<'_> {
    fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        key: K,
        value: V,
    ) -> Result<(), rocksdb::Error> {
        self.batch.put(key, value);
        Ok(())
    }

    fn delete<K: AsRef<[u8]>>(&mut self, key: K) -> Result<(), rocksdb::Error> {
        self.batch.delete(key);
        Ok(())
    }

    fn delete_range<K: AsRef<[u8]>>(&mut self, from: K, to: K) -> Result<(), rocksdb::Error> {
        self.batch.delete_range(from, to);
        Ok(())
    }
}

/// Writer that discards all operations (for in-memory stores).
#[derive(Default)]
pub struct MemoryWriter;

impl DbWriter for MemoryWriter {
    fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        _key: K,
        _value: V,
    ) -> Result<(), rocksdb::Error> {
        Ok(())
    }

    fn delete<K: AsRef<[u8]>>(&mut self, _key: K) -> Result<(), rocksdb::Error> {
        Ok(())
    }

    fn delete_range<K: AsRef<[u8]>>(&mut self, _from: K, _to: K) -> Result<(), rocksdb::Error> {
        Ok(())
    }
}

impl DirectWriter for MemoryWriter {}

// Passthrough for mutable references.
impl<T: DbWriter> DbWriter for &mut T {
    fn put<K: AsRef<[u8]>, V: AsRef<[u8]>>(
        &mut self,
        key: K,
        value: V,
    ) -> Result<(), rocksdb::Error> {
        (*self).put(key, value)
    }

    fn delete<K: AsRef<[u8]>>(&mut self, key: K) -> Result<(), rocksdb::Error> {
        (*self).delete(key)
    }

    fn delete_range<K: AsRef<[u8]>>(&mut self, from: K, to: K) -> Result<(), rocksdb::Error> {
        (*self).delete_range(from, to)
    }
}

/// Atomic batch builder for multi-store ACID writes.
///
/// Accumulates writes across multiple stores and commits them
/// atomically via a single `WriteBatch`.
pub struct AtomicBatch {
    db: Arc<rocksdb::DB>,
    batch: WriteBatch,
}

impl AtomicBatch {
    pub fn new(db: Arc<rocksdb::DB>) -> Self {
        Self {
            db,
            batch: WriteBatch::default(),
        }
    }

    /// Get a writer for this batch.
    pub fn writer(&mut self) -> BatchDbWriter<'_> {
        BatchDbWriter::new(&mut self.batch)
    }

    /// Commit all accumulated writes atomically.
    pub fn commit(self) -> Result<(), rocksdb::Error> {
        self.db.write(self.batch)
    }

    /// Number of operations in this batch.
    pub fn len(&self) -> usize {
        self.batch.len()
    }

    pub fn is_empty(&self) -> bool {
        self.batch.is_empty()
    }
}
