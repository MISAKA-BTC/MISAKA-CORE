//! Core indexing types and traits.

/// Trait for index stores.
pub trait IndexStore: Send + Sync {
    fn name(&self) -> &str;
    fn is_synced(&self) -> bool;
    fn entry_count(&self) -> u64;
}

/// Index update operation.
#[derive(Debug, Clone)]
pub enum IndexOp {
    Insert { key: Vec<u8>, value: Vec<u8> },
    Delete { key: Vec<u8> },
}

/// Batch of index operations.
pub struct IndexBatch {
    pub ops: Vec<IndexOp>,
}

impl IndexBatch {
    pub fn new() -> Self { Self { ops: Vec::new() } }
    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.ops.push(IndexOp::Insert { key, value });
    }
    pub fn delete(&mut self, key: Vec<u8>) {
        self.ops.push(IndexOp::Delete { key });
    }
    pub fn len(&self) -> usize { self.ops.len() }
    pub fn is_empty(&self) -> bool { self.ops.is_empty() }
}

impl Default for IndexBatch {
    fn default() -> Self { Self::new() }
}
