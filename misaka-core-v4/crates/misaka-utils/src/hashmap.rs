//! Concurrent hash map wrappers and utilities.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::hash::Hash;

/// Simple concurrent hash map using RwLock.
pub struct ConcurrentMap<K, V> {
    inner: RwLock<HashMap<K, V>>,
}

impl<K: Hash + Eq, V> ConcurrentMap<K, V> {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            inner: RwLock::new(HashMap::with_capacity(cap)),
        }
    }

    pub fn insert(&self, key: K, value: V) -> Option<V> {
        self.inner.write().insert(key, value)
    }

    pub fn remove<Q>(&self, key: &Q) -> Option<V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.inner.write().remove(key)
    }

    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: std::borrow::Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.inner.read().contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.inner.read().len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

impl<K: Hash + Eq, V: Clone> ConcurrentMap<K, V> {
    pub fn get<Q>(&self, key: &Q) -> Option<V>
    where
        K: std::borrow::Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.inner.read().get(key).cloned()
    }
}

impl<K: Hash + Eq, V> Default for ConcurrentMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}
