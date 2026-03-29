//! Min/max heap with removal support (used by mempool fee ordering).

use std::collections::BinaryHeap;
use std::cmp::Reverse;

/// Keyed min-heap where items can be removed by key.
pub struct KeyedMinHeap<K: Ord + Clone, V> {
    heap: BinaryHeap<Reverse<(K, usize)>>,
    values: Vec<Option<V>>,
    free_slots: Vec<usize>,
}

impl<K: Ord + Clone, V> KeyedMinHeap<K, V> {
    pub fn new() -> Self {
        Self { heap: BinaryHeap::new(), values: Vec::new(), free_slots: Vec::new() }
    }

    pub fn insert(&mut self, key: K, value: V) -> usize {
        let idx = if let Some(slot) = self.free_slots.pop() {
            self.values[slot] = Some(value);
            slot
        } else {
            self.values.push(Some(value));
            self.values.len() - 1
        };
        self.heap.push(Reverse((key, idx)));
        idx
    }

    pub fn pop_min(&mut self) -> Option<(K, V)> {
        while let Some(Reverse((key, idx))) = self.heap.pop() {
            if let Some(value) = self.values[idx].take() {
                self.free_slots.push(idx);
                return Some((key, value));
            }
        }
        None
    }

    pub fn remove(&mut self, idx: usize) -> Option<V> {
        if idx < self.values.len() {
            let v = self.values[idx].take();
            if v.is_some() { self.free_slots.push(idx); }
            v
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.values.iter().filter(|v| v.is_some()).count()
    }

    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

impl<K: Ord + Clone, V> Default for KeyedMinHeap<K, V> {
    fn default() -> Self { Self::new() }
}
