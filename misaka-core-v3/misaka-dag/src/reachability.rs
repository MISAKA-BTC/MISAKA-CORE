//! Production Reachability Index — Dynamic Interval Labeling (Phase 1).
//!
//! # Kaspa-Equivalent Design
//!
//! Intervals on the **Selected Parent Tree** (spanning tree of the DAG).
//! O(1) ancestor queries. Dynamic reallocation on interval exhaustion.
//!
//! # O(1) Ancestor Query
//!
//! A is ancestor of B iff `A.begin <= B.begin AND A.end >= B.end`.
//!
//! # Dynamic Reallocation
//!
//! When interval exhausted → walk UP to ancestor with slack →
//! redistribute all descendant intervals evenly. Amortized O(1).

use std::collections::HashMap;
use tracing::debug;

pub type Hash = [u8; 32];
const ZERO_HASH: Hash = [0u8; 32];
const GENESIS_RANGE: u64 = u64::MAX / 2;
const MIN_SLACK: u64 = 2;

// ═══════════════════════════════════════════════════════════════
//  Interval
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interval {
    pub begin: u64,
    pub end: u64,
}

impl Interval {
    #[inline] pub fn new(b: u64, e: u64) -> Self { Self { begin: b, end: e } }
    #[inline] pub fn size(&self) -> u64 { self.end.saturating_sub(self.begin) }
    #[inline] pub fn contains(&self, other: &Interval) -> bool {
        self.begin <= other.begin && self.end >= other.end
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tree Node
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
struct TreeNode {
    interval: Interval,
    parent: Hash,
    children: Vec<Hash>,
}

// ═══════════════════════════════════════════════════════════════
//  Reachability Store
// ═══════════════════════════════════════════════════════════════

pub struct ReachabilityStore {
    nodes: HashMap<Hash, TreeNode>,
    genesis: Hash,
    realloc_count: u64,
}

impl ReachabilityStore {
    pub fn new(genesis: Hash) -> Self {
        let mut nodes = HashMap::new();
        nodes.insert(genesis, TreeNode {
            interval: Interval::new(0, GENESIS_RANGE),
            parent: ZERO_HASH,
            children: vec![],
        });
        Self { nodes, genesis, realloc_count: 0 }
    }

    /// Add a block as child of its selected parent on the spanning tree.
    /// Dynamic reallocation if parent's interval is exhausted.
    pub fn add_child(&mut self, parent: Hash, child: Hash) -> Result<(), String> {
        if self.nodes.contains_key(&child) {
            return Ok(()); // Idempotent
        }
        if !self.nodes.contains_key(&parent) {
            return Err(format!("parent {} not in tree", hex::encode(&parent[..8])));
        }

        // Check if parent needs reallocation
        let parent_interval = self.nodes[&parent].interval;
        let n_existing = self.nodes[&parent].children.len() as u64;
        let needed = n_existing + 2; // existing + new + slack
        if parent_interval.size() < needed * MIN_SLACK {
            self.reallocate_from(&parent)?;
        }

        // Allocate interval for new child
        let child_interval = {
            let pnode = &self.nodes[&parent];
            let n = pnode.children.len() as u64;
            let range = pnode.interval.size();
            let slots = n + 2;
            let slot_sz = range / slots.max(1);
            let slot_sz = slot_sz.max(1);
            let cb = pnode.interval.begin + (n + 1) * slot_sz;
            let ce = cb + slot_sz.saturating_sub(1);
            Interval::new(cb.min(pnode.interval.end), ce.min(pnode.interval.end))
        };

        self.nodes.insert(child, TreeNode {
            interval: child_interval, parent, children: vec![],
        });
        self.nodes.get_mut(&parent).unwrap().children.push(child);
        Ok(())
    }

    /// Walk UP to find slack, then redistribute subtree.
    fn reallocate_from(&mut self, start: &Hash) -> Result<(), String> {
        self.realloc_count += 1;
        let mut current = *start;
        for _ in 0..50000 {
            let desc = self.count_descendants(&current);
            let node = self.nodes.get(&current).ok_or("node missing")?;
            if node.interval.size() > (desc as u64 + 10) * MIN_SLACK * 2 {
                break;
            }
            if node.parent == ZERO_HASH || current == self.genesis { break; }
            current = node.parent;
        }
        let root_interval = self.nodes[&current].interval;
        self.redistribute(&current, root_interval);
        debug!("Reachability realloc #{}: root={}", self.realloc_count, hex::encode(&current[..4]));
        Ok(())
    }

    /// Recursively redistribute intervals evenly.
    fn redistribute(&mut self, root: &Hash, range: Interval) {
        let children: Vec<Hash> = self.nodes.get(root)
            .map(|n| n.children.clone()).unwrap_or_default();
        if children.is_empty() { return; }
        let n = children.len() as u64;
        let slot = range.size() / (n + 1);
        for (i, child) in children.iter().enumerate() {
            let cb = range.begin + (i as u64 + 1) * slot;
            let ce = cb + slot.saturating_sub(1);
            let ci = Interval::new(cb, ce);
            if let Some(node) = self.nodes.get_mut(child) { node.interval = ci; }
            self.redistribute(child, ci);
        }
    }

    fn count_descendants(&self, hash: &Hash) -> usize {
        let children = match self.nodes.get(hash) { Some(n) => &n.children, None => return 0 };
        let mut c = children.len();
        for ch in children { c += self.count_descendants(ch); }
        c
    }

    // ── O(1) Queries ────────────────────────────────────

    /// O(1): Is `ancestor` on `descendant`'s selected parent chain?
    #[inline]
    pub fn is_dag_ancestor_of(&self, ancestor: &Hash, descendant: &Hash) -> bool {
        match (self.nodes.get(ancestor), self.nodes.get(descendant)) {
            (Some(a), Some(d)) => a.interval.contains(&d.interval),
            _ => false,
        }
    }

    /// O(1): Are a and b in each other's anticone?
    #[inline]
    pub fn is_anticone(&self, a: &Hash, b: &Hash) -> bool {
        !self.is_dag_ancestor_of(a, b) && !self.is_dag_ancestor_of(b, a)
    }

    pub fn get_interval(&self, hash: &Hash) -> Option<Interval> {
        self.nodes.get(hash).map(|n| n.interval)
    }
    pub fn block_count(&self) -> usize { self.nodes.len() }
    pub fn realloc_count(&self) -> u64 { self.realloc_count }
    pub fn genesis(&self) -> Hash { self.genesis }

    // ── Pruning (Phase 4) ───────────────────────────────

    /// Remove strict ancestors of the pruning point.
    pub fn prune_below(&mut self, pruning_point: &Hash) -> usize {
        let to_remove: Vec<Hash> = self.nodes.keys()
            .filter(|h| **h != self.genesis && **h != *pruning_point
                && self.is_dag_ancestor_of(h, pruning_point))
            .copied().collect();
        let count = to_remove.len();
        for hash in &to_remove {
            if let Some(node) = self.nodes.get(hash) {
                let parent = node.parent;
                if let Some(pn) = self.nodes.get_mut(&parent) {
                    pn.children.retain(|c| c != hash);
                }
            }
            self.nodes.remove(hash);
        }
        count
    }
}

// ═══════════════════════════════════════════════════════════════
//  Depth Constants
// ═══════════════════════════════════════════════════════════════

pub const MIN_DECOY_DEPTH: u64 = 100;
pub const FINALITY_DEPTH: u64 = 200;
pub const PRUNING_DEPTH: u64 = 1000;
pub const ACCUMULATOR_RETENTION_DEPTH: u64 = 2000;
const _: () = { assert!(MIN_DECOY_DEPTH <= FINALITY_DEPTH);
    assert!(FINALITY_DEPTH < PRUNING_DEPTH);
    assert!(PRUNING_DEPTH < ACCUMULATOR_RETENTION_DEPTH); };

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionLevel { Full, HeadersAndNullifiers, AccumulatorOnly, Pruned }
pub fn retention_level(d: u64) -> RetentionLevel {
    if d < FINALITY_DEPTH { RetentionLevel::Full }
    else if d < PRUNING_DEPTH { RetentionLevel::HeadersAndNullifiers }
    else if d < ACCUMULATOR_RETENTION_DEPTH { RetentionLevel::AccumulatorOnly }
    else { RetentionLevel::Pruned }
}
pub fn is_decoy_eligible(d: u64) -> bool { d >= MIN_DECOY_DEPTH && d < PRUNING_DEPTH }
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRetentionRole { Archive, Validator, Light }

// ═══════════════════════════════════════════════════════════════
//  Tests — Phase 5
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    fn h(b: u8) -> Hash { [b; 32] }
    fn hn(n: u32) -> Hash { let mut h = [0u8;32]; h[..4].copy_from_slice(&n.to_le_bytes()); h }

    #[test]
    fn test_basic_ancestry() {
        let mut s = ReachabilityStore::new(h(0));
        s.add_child(h(0), h(1)).unwrap();
        s.add_child(h(1), h(2)).unwrap();
        assert!(s.is_dag_ancestor_of(&h(0), &h(2)));
        assert!(!s.is_dag_ancestor_of(&h(2), &h(0)));
    }

    #[test]
    fn test_anticone() {
        let mut s = ReachabilityStore::new(h(0));
        s.add_child(h(0), h(1)).unwrap();
        s.add_child(h(0), h(2)).unwrap();
        assert!(s.is_anticone(&h(1), &h(2)));
        assert!(!s.is_anticone(&h(0), &h(1)));
    }

    /// Phase 5 AC1: 500-block linear chain with reallocation.
    #[test]
    fn test_interval_exhaustion_linear_500() {
        let mut s = ReachabilityStore::new(hn(0));
        let mut parent = hn(0);
        for i in 1..500u32 {
            let child = hn(i);
            s.add_child(parent, child)
                .unwrap_or_else(|e| panic!("failed at {}: {}", i, e));
            assert!(s.is_dag_ancestor_of(&hn(0), &child), "genesis→{} broken", i);
            parent = child;
        }
        assert_eq!(s.block_count(), 500);
        println!("500 linear: {} reallocs", s.realloc_count());
    }

    /// Phase 5 AC1b: Wide fanout.
    #[test]
    fn test_interval_exhaustion_wide_100() {
        let mut s = ReachabilityStore::new(hn(0));
        for i in 1..=100u32 {
            s.add_child(hn(0), hn(i))
                .unwrap_or_else(|e| panic!("failed at {}: {}", i, e));
        }
        assert!(s.is_anticone(&hn(1), &hn(50)));
        assert!(s.is_dag_ancestor_of(&hn(0), &hn(99)));
    }

    /// Phase 5 AC3 (simplified): Insertion doesn't degrade with DAG size.
    #[test]
    fn test_insertion_performance_1000() {
        let mut s = ReachabilityStore::new(hn(0));
        let mut parent = hn(0);
        let start = std::time::Instant::now();
        for i in 1..1000u32 {
            s.add_child(parent, hn(i)).unwrap();
            parent = hn(i);
        }
        let elapsed = start.elapsed();
        println!("1000 blocks: {:?} ({:?}/block)", elapsed, elapsed / 1000);
        assert!(elapsed.as_millis() < 5000, "1000 blocks should take <5s");
    }
}
