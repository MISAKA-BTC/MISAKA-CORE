//! Batched updates. Returns the same root as applying inserts one by one
//! to a `SparseMerkleTree`. v1.0 will replace this with a JMT-style
//! optimized batch implementation; this module establishes the API contract.

use crate::hash::Hash;
use crate::tree::SparseMerkleTree;

/// A batch of insert/delete operations to apply atomically.
#[derive(Debug, Clone)]
pub struct UpdateBatch {
    /// Key-value pairs to insert or update.
    pub upserts: Vec<(Hash, Hash)>,
    /// Keys to delete.
    pub deletes: Vec<Hash>,
}

impl UpdateBatch {
    /// Create an empty batch.
    pub fn new() -> Self {
        Self {
            upserts: Vec::new(),
            deletes: Vec::new(),
        }
    }

    /// Apply this batch to the tree and return the new root.
    ///
    /// Semantics: upserts are applied first, then deletes.
    /// The resulting root is identical to applying each operation sequentially.
    pub fn apply(&self, tree: &mut SparseMerkleTree) -> Hash {
        for (k, v) in &self.upserts {
            tree.insert(*k, *v);
        }
        for k in &self.deletes {
            tree.remove(k);
        }
        tree.root()
    }
}

impl Default for UpdateBatch {
    fn default() -> Self {
        Self::new()
    }
}
