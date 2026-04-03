//! # LRU Cache — Kaspa-Aligned Eviction Policies
//!
//! Thread-safe cache with three modes:
//! - `Empty`: no caching (zero overhead)
//! - `Count`: bounds by number of items
//! - `Tracked`: bounds by estimated memory size

use indexmap::IndexMap;
use parking_lot::RwLock;
use rand::Rng;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash};
use std::sync::Arc;

/// How to estimate an item's size for tracked caches.
pub trait MemSizeEstimate {
    fn estimate_mem_bytes(&self) -> usize;
}

// Blanket impl for common types.
impl MemSizeEstimate for Vec<u8> {
    fn estimate_mem_bytes(&self) -> usize {
        self.len() + 24 // Vec overhead
    }
}

impl MemSizeEstimate for [u8; 32] {
    fn estimate_mem_bytes(&self) -> usize {
        32
    }
}

impl MemSizeEstimate for u64 {
    fn estimate_mem_bytes(&self) -> usize {
        8
    }
}

/// Cache eviction policy.
#[derive(Debug, Clone, Copy)]
pub enum CachePolicy {
    /// No caching at all.
    Empty,
    /// Bounded by item count.
    Count(usize),
    /// Bounded by total estimated memory.
    Tracked { max_bytes: usize, min_items: usize },
}

#[derive(Clone)]
struct PolicyInner {
    tracked: bool,
    max_size: usize,
    min_items: usize,
}

impl From<CachePolicy> for PolicyInner {
    fn from(policy: CachePolicy) -> Self {
        match policy {
            CachePolicy::Empty => PolicyInner {
                tracked: false,
                max_size: 0,
                min_items: 0,
            },
            CachePolicy::Count(n) => PolicyInner {
                tracked: false,
                max_size: n,
                min_items: 0,
            },
            CachePolicy::Tracked {
                max_bytes,
                min_items,
            } => PolicyInner {
                tracked: true,
                max_size: max_bytes,
                min_items,
            },
        }
    }
}

struct Inner<K, V, S = RandomState>
where
    K: Clone + Hash + Eq + Send + Sync,
    V: Clone + Send + Sync + MemSizeEstimate,
{
    map: IndexMap<K, V, S>,
    tracked_size: usize,
}

impl<K, V, S> Inner<K, V, S>
where
    K: Clone + Hash + Eq + Send + Sync,
    V: Clone + Send + Sync + MemSizeEstimate,
    S: BuildHasher + Default,
{
    fn new(prealloc: usize) -> Self {
        Self {
            map: IndexMap::with_capacity_and_hasher(prealloc, S::default()),
            tracked_size: 0,
        }
    }

    fn evict_tracked(&mut self, policy: &PolicyInner) {
        while self.tracked_size > policy.max_size && self.map.len() > policy.min_items {
            let idx = rand::thread_rng().gen_range(0..self.map.len());
            if let Some((_, v)) = self.map.swap_remove_index(idx) {
                self.tracked_size = self.tracked_size.saturating_sub(v.estimate_mem_bytes());
            }
        }
    }

    fn insert(&mut self, policy: &PolicyInner, key: K, data: V) {
        if policy.tracked {
            let size = data.estimate_mem_bytes();
            self.tracked_size += size;
            if let Some(old) = self.map.insert(key, data) {
                self.tracked_size = self.tracked_size.saturating_sub(old.estimate_mem_bytes());
            }
            self.evict_tracked(policy);
        } else {
            if self.map.len() >= policy.max_size && policy.max_size > 0 {
                let idx = rand::thread_rng().gen_range(0..self.map.len());
                self.map.swap_remove_index(idx);
            }
            self.map.insert(key, data);
        }
    }

    fn remove(&mut self, policy: &PolicyInner, key: &K) -> Option<V> {
        let removed = self.map.swap_remove(key);
        if policy.tracked {
            if let Some(ref v) = removed {
                self.tracked_size = self.tracked_size.saturating_sub(v.estimate_mem_bytes());
            }
        }
        removed
    }
}

/// Thread-safe cache with configurable eviction policy.
#[derive(Clone)]
pub struct Cache<K, V, S = RandomState>
where
    K: Clone + Hash + Eq + Send + Sync,
    V: Clone + Send + Sync + MemSizeEstimate,
{
    inner: Arc<RwLock<Inner<K, V, S>>>,
    policy: PolicyInner,
}

impl<K, V, S> Cache<K, V, S>
where
    K: Clone + Hash + Eq + Send + Sync,
    V: Clone + Send + Sync + MemSizeEstimate,
    S: BuildHasher + Default,
{
    pub fn new(policy: CachePolicy) -> Self {
        let p: PolicyInner = policy.into();
        let prealloc = if p.tracked { 0 } else { p.max_size };
        Self {
            inner: Arc::new(RwLock::new(Inner::new(prealloc))),
            policy: p,
        }
    }

    pub fn get(&self, key: &K) -> Option<V> {
        self.inner.read().map.get(key).cloned()
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.inner.read().map.contains_key(key)
    }

    pub fn insert(&self, key: K, data: V) {
        if self.policy.max_size == 0 {
            return;
        }
        self.inner.write().insert(&self.policy, key, data);
    }

    pub fn insert_many(&self, iter: &mut impl Iterator<Item = (K, V)>) {
        if self.policy.max_size == 0 {
            return;
        }
        let mut inner = self.inner.write();
        for (k, v) in iter {
            inner.insert(&self.policy, k, v);
        }
    }

    pub fn remove(&self, key: &K) -> Option<V> {
        if self.policy.max_size == 0 {
            return None;
        }
        self.inner.write().remove(&self.policy, key)
    }

    pub fn remove_all(&self) {
        if self.policy.max_size == 0 {
            return;
        }
        let mut inner = self.inner.write();
        inner.map.clear();
        inner.tracked_size = 0;
    }

    pub fn len(&self) -> usize {
        self.inner.read().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().map.is_empty()
    }

    pub fn estimated_bytes(&self) -> usize {
        self.inner.read().tracked_size
    }
}
