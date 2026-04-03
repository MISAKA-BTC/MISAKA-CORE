//! # Reachability Store — O(1) DAG Reachability Index
//!
//! Persists the reachability index data that enables O(1) ancestor
//! queries in the DAG. Each block gets an interval [start, end] in
//! a DFS ordering; block A is an ancestor of block B iff A's interval
//! contains B's interval.
//!
//! Data stored:
//! - Reachability intervals (per-block)
//! - Tree children (reachability tree structure)
//! - Future covering set (for efficient interval assignment)
//! - Relations (parent/child edges)

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::cache::{CachePolicy, MemSizeEstimate};
use crate::cached_access::CachedDbAccess;
use crate::db_writer::DbWriter;
use crate::store_errors::StoreError;
use crate::store_registry::StorePrefixes;

pub type Hash = [u8; 32];

/// Reachability interval for a block.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReachabilityInterval {
    /// Start of the interval (inclusive).
    pub start: u64,
    /// End of the interval (inclusive).
    pub end: u64,
}

impl MemSizeEstimate for ReachabilityInterval {
    fn estimate_mem_bytes(&self) -> usize {
        16
    }
}

impl ReachabilityInterval {
    pub fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    /// Check if this interval contains another.
    pub fn contains(&self, other: &Self) -> bool {
        self.start <= other.start && other.end <= self.end
    }

    /// Size of this interval.
    pub fn size(&self) -> u64 {
        self.end - self.start + 1
    }
}

/// Children list for the reachability tree.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChildrenList {
    pub children: Vec<Hash>,
}

impl MemSizeEstimate for ChildrenList {
    fn estimate_mem_bytes(&self) -> usize {
        self.children.len() * 32 + 24
    }
}

/// Future covering set — blocks that cover the future of this block.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FutureCoveringSet {
    pub blocks: Vec<Hash>,
}

impl MemSizeEstimate for FutureCoveringSet {
    fn estimate_mem_bytes(&self) -> usize {
        self.blocks.len() * 32 + 24
    }
}

/// Parent/child relations.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BlockRelations {
    pub parents: Vec<Hash>,
    pub children: Vec<Hash>,
}

impl MemSizeEstimate for BlockRelations {
    fn estimate_mem_bytes(&self) -> usize {
        (self.parents.len() + self.children.len()) * 32 + 48
    }
}

/// Reachability data store.
pub struct ReachabilityStore {
    /// Reachability intervals.
    intervals: CachedDbAccess<Hash, ReachabilityInterval>,
    /// Tree children.
    tree_children: CachedDbAccess<Hash, ChildrenList>,
    /// Future covering sets.
    future_covering: CachedDbAccess<Hash, FutureCoveringSet>,
    /// Parent relations.
    parents: CachedDbAccess<Hash, BlockRelations>,
}

impl ReachabilityStore {
    pub fn new(db: Arc<rocksdb::DB>) -> Self {
        Self {
            intervals: CachedDbAccess::new(
                db.clone(),
                CachePolicy::Tracked {
                    max_bytes: 64 * 1024 * 1024,
                    min_items: 10_000,
                },
                StorePrefixes::Reachability.prefix_bytes(),
            ),
            tree_children: CachedDbAccess::new(
                db.clone(),
                CachePolicy::Tracked {
                    max_bytes: 32 * 1024 * 1024,
                    min_items: 5_000,
                },
                StorePrefixes::ReachabilityTreeChildren.prefix_bytes(),
            ),
            future_covering: CachedDbAccess::new(
                db.clone(),
                CachePolicy::Tracked {
                    max_bytes: 32 * 1024 * 1024,
                    min_items: 5_000,
                },
                StorePrefixes::ReachabilityFutureCovering.prefix_bytes(),
            ),
            parents: CachedDbAccess::new(
                db,
                CachePolicy::Tracked {
                    max_bytes: 64 * 1024 * 1024,
                    min_items: 10_000,
                },
                StorePrefixes::RelationsParents.prefix_bytes(),
            ),
        }
    }

    // ── Intervals ──

    pub fn get_interval(&self, hash: Hash) -> Result<ReachabilityInterval, StoreError> {
        self.intervals.read(hash)
    }

    pub fn has_interval(&self, hash: Hash) -> Result<bool, StoreError> {
        self.intervals.has(hash)
    }

    pub fn set_interval(
        &self,
        writer: impl DbWriter,
        hash: Hash,
        interval: ReachabilityInterval,
    ) -> Result<(), StoreError> {
        self.intervals.write(writer, hash, interval)
    }

    /// O(1) reachability query: is `ancestor` an ancestor of `descendant`?
    pub fn is_ancestor(&self, ancestor: Hash, descendant: Hash) -> Result<bool, StoreError> {
        let a = self.intervals.read(ancestor)?;
        let d = self.intervals.read(descendant)?;
        Ok(a.contains(&d))
    }

    // ── Tree Children ──

    pub fn get_children(&self, hash: Hash) -> Result<ChildrenList, StoreError> {
        self.tree_children.read(hash)
    }

    pub fn set_children(
        &self,
        writer: impl DbWriter,
        hash: Hash,
        children: ChildrenList,
    ) -> Result<(), StoreError> {
        self.tree_children.write(writer, hash, children)
    }

    /// Append a child to the children list.
    pub fn append_child(
        &self,
        writer: impl DbWriter,
        parent: Hash,
        child: Hash,
    ) -> Result<(), StoreError> {
        let mut list = self.tree_children.read(parent).unwrap_or_default();
        list.children.push(child);
        self.tree_children.write(writer, parent, list)
    }

    // ── Future Covering Set ──

    pub fn get_future_covering(&self, hash: Hash) -> Result<FutureCoveringSet, StoreError> {
        self.future_covering.read(hash)
    }

    pub fn set_future_covering(
        &self,
        writer: impl DbWriter,
        hash: Hash,
        set: FutureCoveringSet,
    ) -> Result<(), StoreError> {
        self.future_covering.write(writer, hash, set)
    }

    // ── Relations ──

    pub fn get_relations(&self, hash: Hash) -> Result<BlockRelations, StoreError> {
        self.parents.read(hash)
    }

    pub fn set_relations(
        &self,
        writer: impl DbWriter,
        hash: Hash,
        relations: BlockRelations,
    ) -> Result<(), StoreError> {
        self.parents.write(writer, hash, relations)
    }

    pub fn get_parents(&self, hash: Hash) -> Result<Vec<Hash>, StoreError> {
        Ok(self.parents.read(hash)?.parents)
    }

    // ── Stats ──

    pub fn interval_cache_len(&self) -> usize {
        self.intervals.cache_len()
    }

    pub fn relations_cache_len(&self) -> usize {
        self.parents.cache_len()
    }
}
