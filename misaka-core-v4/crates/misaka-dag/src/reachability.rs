//! Production Reachability Index — Hybrid Interval + Bounded BFS (Phase 1).
//!
//! # Kaspa-Equivalent Design with Side-Branch Fix
//!
//! ## The Problem (v3 Bug)
//!
//! v3 の `is_dag_ancestor_of()` は Selected Parent Tree (SPT) 上の
//! 区間包含関係のみで祖先判定を行っていた。SPT は DAG の全辺を
//! カバーしていないため、サイドブランチの祖先関係を **false と誤判定** する。
//!
//! ```text
//! Example:
//!     G
//!    / \
//!   A   B         ← B is child of G on SPT, A is child of G on SPT
//!    \ /
//!     C (SP=A)    ← C's selected parent is A. C is child of A on SPT.
//!
//! Query: is_dag_ancestor_of(B, C) ?
//!
//! SPT intervals: B ⊂ G, C ⊂ A ⊂ G
//! B.interval does NOT contain C.interval (sibling subtrees)
//! → SPT check returns false
//!
//! But B ∈ Past(C) via C.parents = [A, B] !
//! → FALSE NEGATIVE: B IS an ancestor of C in the DAG.
//! ```
//!
//! ## The Fix: Hybrid Algorithm
//!
//! 1. **O(1) Fast-Path ACCEPT**: SPT interval containment.
//!    If `A.interval ⊇ B.interval`, then A IS on B's selected parent chain,
//!    which is a subset of B's past. No false positives.
//!
//! 2. **Bounded BFS**: If interval check says NO, walk backwards from
//!    descendant through **actual DAG parents** (not just SPT) to find
//!    the ancestor. Bounded by `blue_score` difference and
//!    `MAX_ANCESTOR_SEARCH_BLOCKS`.
//!
//! ## Why This Prevents Chain Splits
//!
//! 全ノードは同一の DAG 構造と同一の GhostDagData を持つため、
//! `is_true_dag_ancestor()` の結果は入力が同一であれば常に同一。
//! BFS の探索順は blue_score による打ち切りと VecDeque の FIFO 順で決定論的。
//! 結果の true/false は探索順に依存しない (到達可能性はグラフの性質)。

use std::collections::{HashSet, VecDeque};

use crate::constants::MAX_ANCESTOR_SEARCH_BLOCKS;
use crate::dag_block::Hash;
use crate::legacy_ghostdag::DagStore;

pub type ReachabilityHash = [u8; 32];
const ZERO_HASH: ReachabilityHash = [0u8; 32];
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
    nodes: std::collections::HashMap<Hash, TreeNode>,
    genesis: Hash,
    realloc_count: u64,
}

impl ReachabilityStore {
    pub fn new(genesis: Hash) -> Self {
        let mut nodes = std::collections::HashMap::new();
        nodes.insert(genesis, TreeNode {
            interval: Interval::new(0, GENESIS_RANGE),
            parent: ZERO_HASH,
            children: vec![],
        });
        Self { nodes, genesis, realloc_count: 0 }
    }

    /// Add a block as child of its selected parent on the spanning tree.
    pub fn add_child(&mut self, parent: Hash, child: Hash) -> Result<(), String> {
        if self.nodes.contains_key(&child) {
            return Ok(());
        }
        if !self.nodes.contains_key(&parent) {
            return Err(format!("parent {} not in tree", hex::encode(&parent[..8])));
        }

        let parent_interval = self.nodes[&parent].interval;
        let n_existing = self.nodes[&parent].children.len() as u64;
        let needed = n_existing + 2;
        if parent_interval.size() < needed * MIN_SLACK {
            self.reallocate_from(&parent)?;
        }

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
        if let Some(parent_node) = self.nodes.get_mut(&parent) {
            parent_node.children.push(child);
        }
        Ok(())
    }

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
        tracing::debug!("Reachability realloc #{}: root={}", self.realloc_count, hex::encode(&current[..4]));
        Ok(())
    }

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

    // ── O(1) Selected Parent Tree Queries ──────────────────

    /// O(1): Is `ancestor` on `descendant`'s selected parent chain?
    ///
    /// **WARNING**: This checks SPT ancestry ONLY.
    /// For true DAG ancestry including side-branches, use `is_true_dag_ancestor()`.
    #[inline]
    pub fn is_sp_tree_ancestor_of(&self, ancestor: &Hash, descendant: &Hash) -> bool {
        match (self.nodes.get(ancestor), self.nodes.get(descendant)) {
            (Some(a), Some(d)) => a.interval.contains(&d.interval),
            _ => false,
        }
    }

    /// Backward-compatible alias for SPT-only contexts (e.g. pruning).
    #[inline]
    pub fn is_dag_ancestor_of(&self, ancestor: &Hash, descendant: &Hash) -> bool {
        self.is_sp_tree_ancestor_of(ancestor, descendant)
    }

    /// O(1): SPT anticone check.
    #[inline]
    pub fn is_anticone(&self, a: &Hash, b: &Hash) -> bool {
        !self.is_sp_tree_ancestor_of(a, b) && !self.is_sp_tree_ancestor_of(b, a)
    }

    pub fn get_interval(&self, hash: &Hash) -> Option<Interval> {
        self.nodes.get(hash).map(|n| n.interval)
    }
    pub fn block_count(&self) -> usize { self.nodes.len() }
    pub fn realloc_count(&self) -> u64 { self.realloc_count }
    pub fn genesis(&self) -> Hash { self.genesis }
    pub fn contains(&self, hash: &Hash) -> bool { self.nodes.contains_key(hash) }

    // ── Pruning ─────────────────────────────────────────────

    pub fn prune_below(&mut self, pruning_point: &Hash) -> usize {
        let to_remove: Vec<Hash> = self.nodes.keys()
            .filter(|h| **h != self.genesis && **h != *pruning_point
                && self.is_sp_tree_ancestor_of(h, pruning_point))
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
//  Hybrid DAG Ancestor Check (Task 1.1)
// ═══════════════════════════════════════════════════════════════

/// 真正の DAG 祖先判定 — ハイブリッドアルゴリズム。
///
/// # なぜこの関数がコンセンサス不一致を防ぐか
///
/// ## 数学的根拠
///
/// DAG 上の祖先関係 `A ∈ Past(B)` は、A から B に至る有向パスの存在と等価。
/// この関数は:
///
/// 1. SPT interval check で **十分条件** を O(1) で判定
///    (A が B の SPT 祖先 → A ∈ Past(B) は必ず成立)
///
/// 2. SPT で発見できない場合、B から A に向かって BFS で全 DAG 親を遡る。
///    A.blue_score 以下のブロックに到達したら停止。
///
/// ## 決定論性の保証
///
/// - 入力が同一 → 全ノードで同一の結果
/// - BFS の探索順は結果に影響しない (到達可能性はグラフの構造的性質)
/// - MAX_ANCESTOR_SEARCH_BLOCKS は全ノードで同一の定数
pub fn is_true_dag_ancestor<S: DagStore>(
    ancestor: &Hash,
    descendant: &Hash,
    reachability: &ReachabilityStore,
    store: &S,
) -> bool {
    if ancestor == descendant {
        return true;
    }

    // Fast-path ACCEPT: SPT interval containment (O(1), no false positives)
    if reachability.is_sp_tree_ancestor_of(ancestor, descendant) {
        return true;
    }

    // Fast-path REJECT via blue_score
    let ancestor_score = match store.get_ghostdag_data(ancestor) {
        Some(d) => d.blue_score,
        None => return false,
    };
    let descendant_score = match store.get_ghostdag_data(descendant) {
        Some(d) => d.blue_score,
        None => return false,
    };
    if ancestor_score >= descendant_score {
        return false;
    }

    // Bounded BFS through actual DAG parents
    let mut visited = HashSet::new();
    let mut queue: VecDeque<Hash> = VecDeque::new();
    visited.insert(*descendant);

    if let Some(header) = store.get_header(descendant) {
        for p in &header.parents {
            if *p == *ancestor { return true; }
            if visited.insert(*p) { queue.push_back(*p); }
        }
    }

    let mut blocks_visited: usize = 0;
    while let Some(current) = queue.pop_front() {
        blocks_visited += 1;
        if blocks_visited > MAX_ANCESTOR_SEARCH_BLOCKS {
            tracing::warn!(
                "is_true_dag_ancestor: BFS cap ({}) reached, ancestor={}, desc={}",
                MAX_ANCESTOR_SEARCH_BLOCKS,
                hex::encode(&ancestor[..4]),
                hex::encode(&descendant[..4]),
            );
            return false;
        }

        // If current is an SPT ancestor of target ancestor → too deep
        if reachability.is_sp_tree_ancestor_of(&current, ancestor) {
            continue;
        }

        let current_score = store.get_ghostdag_data(&current)
            .map(|d| d.blue_score).unwrap_or(0);
        if current_score < ancestor_score {
            continue;
        }

        if let Some(header) = store.get_header(&current) {
            for p in &header.parents {
                if *p == *ancestor { return true; }
                if visited.insert(*p) { queue.push_back(*p); }
            }
        }
    }
    false
}

/// 真正の DAG anticone 判定。
#[inline]
pub fn is_true_dag_anticone<S: DagStore>(
    a: &Hash,
    b: &Hash,
    reachability: &ReachabilityStore,
    store: &S,
) -> bool {
    !is_true_dag_ancestor(a, b, reachability, store)
        && !is_true_dag_ancestor(b, a, reachability, store)
}

// ═══════════════════════════════════════════════════════════════
//  Depth Constants — Delegated to constants.rs (SSOT)
// ═══════════════════════════════════════════════════════════════

pub use crate::constants::{
    MIN_DECOY_DEPTH, FINALITY_DEPTH, PRUNING_DEPTH, ACCUMULATOR_RETENTION_DEPTH,
    RetentionLevel, retention_level, is_decoy_eligible, NodeRetentionRole,
};

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy_ghostdag::InMemoryDagStore;
    use crate::dag_block::{DagBlockHeader, GhostDagData, DAG_VERSION, ZERO_HASH as DAG_ZERO};

    fn h(b: u8) -> Hash { [b; 32] }
    fn hn(n: u32) -> Hash { let mut h = [0u8;32]; h[..4].copy_from_slice(&n.to_le_bytes()); h }

    fn make_header(parents: Vec<Hash>) -> DagBlockHeader {
        DagBlockHeader {
            version: DAG_VERSION, parents, timestamp_ms: 0, tx_root: [0; 32],
            proposer_id: [0; 32], nonce: 0, blue_score: 0, bits: 0,
        }
    }

    #[test]
    fn test_basic_spt_ancestry() {
        let mut s = ReachabilityStore::new(h(0));
        s.add_child(h(0), h(1)).unwrap();
        s.add_child(h(1), h(2)).unwrap();
        assert!(s.is_sp_tree_ancestor_of(&h(0), &h(2)));
        assert!(!s.is_sp_tree_ancestor_of(&h(2), &h(0)));
    }

    #[test]
    fn test_spt_anticone() {
        let mut s = ReachabilityStore::new(h(0));
        s.add_child(h(0), h(1)).unwrap();
        s.add_child(h(0), h(2)).unwrap();
        assert!(s.is_anticone(&h(1), &h(2)));
        assert!(!s.is_anticone(&h(0), &h(1)));
    }

    /// **Task 1.1 Critical Test: Side-branch ancestor detection**
    ///
    /// ```text
    ///     G
    ///    / \
    ///   A   B     (parallel)
    ///    \ /
    ///     C       (parents: [A, B], SP = A)
    /// ```
    ///
    /// B ∈ Past(C) but SPT says NO. Hybrid BFS must say YES.
    #[test]
    fn test_hybrid_detects_side_branch_ancestor() {
        let g = [0x00; 32]; let a = [0x0A; 32];
        let b = [0x0B; 32]; let c = [0x0C; 32];

        let mut store = InMemoryDagStore::new();
        let mut reach = ReachabilityStore::new(g);

        store.insert_header(g, make_header(vec![]));
        store.set_ghostdag_data(g, GhostDagData {
            selected_parent: DAG_ZERO, mergeset_blues: vec![], mergeset_reds: vec![],
            blue_score: 0, blue_work: 0,
        });

        store.insert_header(a, make_header(vec![g]));
        reach.add_child(g, a).unwrap();
        store.set_ghostdag_data(a, GhostDagData {
            selected_parent: g, mergeset_blues: vec![], mergeset_reds: vec![],
            blue_score: 1, blue_work: 1,
        });

        store.insert_header(b, make_header(vec![g]));
        reach.add_child(g, b).unwrap();
        store.set_ghostdag_data(b, GhostDagData {
            selected_parent: g, mergeset_blues: vec![], mergeset_reds: vec![],
            blue_score: 1, blue_work: 1,
        });

        store.insert_header(c, make_header(vec![a, b]));
        reach.add_child(a, c).unwrap();
        store.set_ghostdag_data(c, GhostDagData {
            selected_parent: a, mergeset_blues: vec![b], mergeset_reds: vec![],
            blue_score: 3, blue_work: 3,
        });

        assert!(!reach.is_sp_tree_ancestor_of(&b, &c), "SPT must NOT detect B→C");
        assert!(is_true_dag_ancestor(&b, &c, &reach, &store), "Hybrid MUST detect B→C");
        assert!(is_true_dag_ancestor(&a, &c, &reach, &store));
        assert!(is_true_dag_ancestor(&g, &c, &reach, &store));
        assert!(!is_true_dag_ancestor(&c, &b, &reach, &store));
        assert!(is_true_dag_anticone(&a, &b, &reach, &store));
    }

    /// Deep side-branch: B reachable via D → B, two hops from E.
    #[test]
    fn test_hybrid_detects_deep_side_branch() {
        let g = [0x00; 32]; let a = [0x0A; 32]; let b = [0x0B; 32];
        let c = [0x0C; 32]; let d = [0x0D; 32]; let e = [0x0E; 32];

        let mut store = InMemoryDagStore::new();
        let mut reach = ReachabilityStore::new(g);

        store.insert_header(g, make_header(vec![]));
        store.set_ghostdag_data(g, GhostDagData { selected_parent: DAG_ZERO, mergeset_blues: vec![], mergeset_reds: vec![], blue_score: 0, blue_work: 0 });

        for (hash, parent, score) in [(a, g, 1u64), (b, g, 1), (c, a, 2), (d, b, 2)] {
            store.insert_header(hash, make_header(vec![parent]));
            reach.add_child(parent, hash).unwrap();
            store.set_ghostdag_data(hash, GhostDagData { selected_parent: parent, mergeset_blues: vec![], mergeset_reds: vec![], blue_score: score, blue_work: score as u128 });
        }

        store.insert_header(e, make_header(vec![c, d]));
        reach.add_child(c, e).unwrap();
        store.set_ghostdag_data(e, GhostDagData { selected_parent: c, mergeset_blues: vec![d], mergeset_reds: vec![], blue_score: 4, blue_work: 4 });

        assert!(is_true_dag_ancestor(&d, &e, &reach, &store));
        assert!(is_true_dag_ancestor(&b, &e, &reach, &store));
        assert!(is_true_dag_ancestor(&g, &e, &reach, &store));
    }

    #[test]
    fn test_interval_exhaustion_linear_500() {
        let mut s = ReachabilityStore::new(hn(0));
        let mut parent = hn(0);
        for i in 1..500u32 {
            let child = hn(i);
            s.add_child(parent, child).unwrap_or_else(|e| panic!("failed at {}: {}", i, e));
            assert!(s.is_sp_tree_ancestor_of(&hn(0), &child), "genesis→{} broken", i);
            parent = child;
        }
        assert_eq!(s.block_count(), 500);
    }

    #[test]
    fn test_interval_exhaustion_wide_100() {
        let mut s = ReachabilityStore::new(hn(0));
        for i in 1..=100u32 {
            s.add_child(hn(0), hn(i)).unwrap_or_else(|e| panic!("failed at {}: {}", i, e));
        }
        assert!(s.is_anticone(&hn(1), &hn(50)));
        assert!(s.is_sp_tree_ancestor_of(&hn(0), &hn(99)));
    }

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
