//! Memory allocation tracking and budget management.

use std::sync::atomic::{AtomicUsize, Ordering};

/// Global memory budget tracker.
static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static BUDGET: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Set the global memory budget in bytes.
pub fn set_budget(bytes: usize) {
    BUDGET.store(bytes, Ordering::Release);
}

/// Get current allocated bytes.
pub fn allocated() -> usize {
    ALLOCATED.load(Ordering::Acquire)
}

/// Get remaining budget.
pub fn remaining() -> usize {
    let budget = BUDGET.load(Ordering::Acquire);
    let alloc = ALLOCATED.load(Ordering::Acquire);
    budget.saturating_sub(alloc)
}

/// Try to reserve `bytes` from the budget. Returns false if over budget.
pub fn try_reserve(bytes: usize) -> bool {
    let budget = BUDGET.load(Ordering::Acquire);
    loop {
        let current = ALLOCATED.load(Ordering::Acquire);
        if current + bytes > budget {
            return false;
        }
        if ALLOCATED.compare_exchange(current, current + bytes, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
            return true;
        }
    }
}

/// Release previously reserved bytes.
pub fn release(bytes: usize) {
    ALLOCATED.fetch_sub(bytes, Ordering::Release);
}

/// RAII guard that releases memory on drop.
pub struct MemoryGuard {
    bytes: usize,
}

impl MemoryGuard {
    pub fn try_new(bytes: usize) -> Option<Self> {
        if try_reserve(bytes) { Some(Self { bytes }) } else { None }
    }

    pub fn bytes(&self) -> usize { self.bytes }
}

impl Drop for MemoryGuard {
    fn drop(&mut self) {
        release(self.bytes);
    }
}

/// Cache with LRU eviction and memory budget awareness.
pub struct BudgetedCache<K: std::hash::Hash + Eq + Clone, V> {
    entries: parking_lot::Mutex<indexmap::IndexMap<K, (V, usize)>>,
    max_memory: usize,
    current_memory: AtomicUsize,
}

impl<K: std::hash::Hash + Eq + Clone, V> BudgetedCache<K, V> {
    pub fn new(max_memory: usize) -> Self {
        Self {
            entries: parking_lot::Mutex::new(indexmap::IndexMap::new()),
            max_memory,
            current_memory: AtomicUsize::new(0),
        }
    }

    pub fn insert(&self, key: K, value: V, size: usize) -> bool {
        let mut entries = self.entries.lock();

        // Evict until we have space
        while self.current_memory.load(Ordering::Relaxed) + size > self.max_memory {
            if let Some((_, (_, evicted_size))) = entries.shift_remove_index(0) {
                self.current_memory.fetch_sub(evicted_size, Ordering::Relaxed);
            } else {
                return false; // Single item too large
            }
        }

        if let Some((_, old_size)) = entries.insert_full(key, (value, size)).1 {
            self.current_memory.fetch_sub(old_size, Ordering::Relaxed);
        }
        self.current_memory.fetch_add(size, Ordering::Relaxed);
        true
    }

    pub fn get<Q>(&self, key: &Q) -> Option<()>
    where
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq + ?Sized,
    {
        let entries = self.entries.lock();
        entries.get(key).map(|_| ())
    }

    pub fn len(&self) -> usize { self.entries.lock().len() }
    pub fn is_empty(&self) -> bool { self.entries.lock().is_empty() }
    pub fn memory_used(&self) -> usize { self.current_memory.load(Ordering::Relaxed) }
}
