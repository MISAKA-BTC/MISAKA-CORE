//! In-memory cache with configurable eviction policies.

use indexmap::IndexMap;
use parking_lot::RwLock;
use rand::Rng;
use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::sync::Arc;

/// Cache configuration policy.
#[derive(Debug, Clone, Copy)]
pub enum CachePolicy {
    /// No caching at all.
    Empty,
    /// Bound by number of items.
    Count(usize),
    /// Tracked by estimated byte size.
    Tracked {
        max_bytes: usize,
        min_items: usize,
    },
}

/// Trait for estimating memory size of cached items.
pub trait MemSizeEstimator {
    fn estimate_mem_bytes(&self) -> usize {
        std::mem::size_of_val(self)
    }
}

// Blanket impls for common types
impl MemSizeEstimator for u64 {}
impl MemSizeEstimator for [u8; 32] {}
impl MemSizeEstimator for Vec<u8> {
    fn estimate_mem_bytes(&self) -> usize {
        std::mem::size_of::<Vec<u8>>() + self.len()
    }
}
impl MemSizeEstimator for Vec<[u8; 32]> {
    fn estimate_mem_bytes(&self) -> usize {
        std::mem::size_of::<Vec<[u8; 32]>>() + self.len() * 32
    }
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
            CachePolicy::Count(max) => PolicyInner {
                tracked: false,
                max_size: max,
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

struct Inner<TKey, TData, S = RandomState>
where
    TKey: Clone + std::hash::Hash + Eq + Send + Sync,
    TData: Clone + Send + Sync + MemSizeEstimator,
{
    map: IndexMap<TKey, TData, S>,
    tracked_size: usize,
}

impl<TKey, TData, S> Inner<TKey, TData, S>
where
    TKey: Clone + std::hash::Hash + Eq + Send + Sync,
    TData: Clone + Send + Sync + MemSizeEstimator,
    S: BuildHasher + Default,
{
    fn tracked_evict(&mut self, policy: &PolicyInner) {
        while self.tracked_size > policy.max_size && self.map.len() > policy.min_items {
            if let Some((_, v)) = self
                .map
                .swap_remove_index(rand::thread_rng().gen_range(0..self.map.len()))
            {
                self.tracked_size -= v.estimate_mem_bytes();
            }
        }
    }

    fn insert(&mut self, policy: &PolicyInner, key: TKey, data: TData) {
        if policy.tracked {
            let new_data_size = data.estimate_mem_bytes();
            self.tracked_size += new_data_size;
            if let Some(removed) = self.map.insert(key, data) {
                self.tracked_size -= removed.estimate_mem_bytes();
            }
            self.tracked_evict(policy);
        } else {
            if self.map.len() == policy.max_size && policy.max_size > 0 {
                self.map
                    .swap_remove_index(rand::thread_rng().gen_range(0..policy.max_size));
            }
            self.map.insert(key, data);
        }
    }
}

/// Thread-safe cache with configurable eviction.
#[derive(Clone)]
pub struct Cache<TKey, TData, S = RandomState>
where
    TKey: Clone + std::hash::Hash + Eq + Send + Sync,
    TData: Clone + Send + Sync + MemSizeEstimator,
{
    inner: Arc<RwLock<Inner<TKey, TData, S>>>,
    policy: PolicyInner,
}

impl<TKey, TData, S> Cache<TKey, TData, S>
where
    TKey: Clone + std::hash::Hash + Eq + Send + Sync,
    TData: Clone + Send + Sync + MemSizeEstimator,
    S: BuildHasher + Default,
{
    pub fn new(policy: CachePolicy) -> Self {
        let policy_inner = PolicyInner::from(policy);
        let capacity = match policy {
            CachePolicy::Empty => 0,
            CachePolicy::Count(n) => n,
            CachePolicy::Tracked { min_items, .. } => min_items,
        };
        Self {
            inner: Arc::new(RwLock::new(Inner {
                map: IndexMap::with_capacity_and_hasher(capacity, S::default()),
                tracked_size: 0,
            })),
            policy: policy_inner,
        }
    }

    pub fn get(&self, key: &TKey) -> Option<TData> {
        if self.policy.max_size == 0 && !self.policy.tracked {
            return None;
        }
        self.inner.read().map.get(key).cloned()
    }

    pub fn contains_key(&self, key: &TKey) -> bool {
        if self.policy.max_size == 0 && !self.policy.tracked {
            return false;
        }
        self.inner.read().map.contains_key(key)
    }

    pub fn insert(&self, key: TKey, data: TData) {
        if self.policy.max_size == 0 && !self.policy.tracked {
            return;
        }
        self.inner.write().insert(&self.policy, key, data);
    }

    pub fn remove(&self, key: &TKey) -> Option<TData> {
        self.inner.write().map.swap_remove(key)
    }

    pub fn len(&self) -> usize {
        self.inner.read().map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().map.is_empty()
    }
}

impl MemSizeEstimator for [u8; 64] {}
impl MemSizeEstimator for bool {}
impl MemSizeEstimator for String {
    fn estimate_mem_bytes(&self) -> usize {
        std::mem::size_of::<String>() + self.len()
    }
}

impl<T: MemSizeEstimator> MemSizeEstimator for std::sync::Arc<T> {
    fn estimate_mem_bytes(&self) -> usize {
        std::mem::size_of::<std::sync::Arc<T>>() + (**self).estimate_mem_bytes()
    }
}

impl MemSizeEstimator for u32 {}
impl MemSizeEstimator for i32 {}
impl MemSizeEstimator for i64 {}
impl MemSizeEstimator for u16 {}
impl MemSizeEstimator for u128 {}
impl MemSizeEstimator for () {}
impl MemSizeEstimator for f64 {}
