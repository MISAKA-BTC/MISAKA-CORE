//! Script execution caches for signature verification.

use std::collections::HashMap;
use parking_lot::RwLock;

/// Cache key for signature verifications.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SigCacheKey {
    pub sig_hash: [u8; 32],
    pub pubkey_hash: [u8; 32],
}

/// Thread-safe signature verification cache.
pub struct SigCache {
    cache: RwLock<HashMap<SigCacheKey, bool>>,
    max_entries: usize,
}

impl SigCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            cache: RwLock::new(HashMap::with_capacity(max_entries.min(10_000))),
            max_entries,
        }
    }

    /// Check if a signature verification result is cached.
    pub fn lookup(&self, key: &SigCacheKey) -> Option<bool> {
        self.cache.read().get(key).copied()
    }

    /// Store a verification result.
    pub fn insert(&self, key: SigCacheKey, valid: bool) {
        let mut cache = self.cache.write();
        if cache.len() >= self.max_entries {
            // Simple eviction: clear half the cache
            let keys: Vec<_> = cache.keys().take(self.max_entries / 2).cloned().collect();
            for k in keys {
                cache.remove(&k);
            }
        }
        cache.insert(key, valid);
    }

    pub fn len(&self) -> usize { self.cache.read().len() }
    pub fn is_empty(&self) -> bool { self.cache.read().is_empty() }
}

/// Script hash cache for P2SH validation.
pub struct ScriptHashCache {
    cache: RwLock<HashMap<[u8; 32], Vec<u8>>>,
    max_entries: usize,
}

impl ScriptHashCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            cache: RwLock::new(HashMap::with_capacity(max_entries.min(1_000))),
            max_entries,
        }
    }

    pub fn lookup(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.cache.read().get(hash).cloned()
    }

    pub fn insert(&self, hash: [u8; 32], script: Vec<u8>) {
        let mut cache = self.cache.write();
        if cache.len() < self.max_entries {
            cache.insert(hash, script);
        }
    }
}
