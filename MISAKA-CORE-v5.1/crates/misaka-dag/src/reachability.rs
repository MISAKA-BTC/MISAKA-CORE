//! Production Reachability Index — Hybrid Interval + Conclusive BFS.
//!
//! # v5 Consensus-Critical Fix: Conclusive Ancestor Queries
//!
//! ## The v4 Problem: Silent False on BFS Exhaustion
//!
//! v4 の `is_true_dag_ancestor()` は `MAX_ANCESTOR_SEARCH_BLOCKS = 4096` の
//! 探索上限に依存していた。探索上限到達時に `false` を返すため:
//!
//! - 攻撃者が wide DAG を構築 → BFS が 4096 ブロック以内に祖先を発見できない
//! - ノード A: BFS で発見 → `true`、ノード B: 別の探索順で未発見 → `false`
//! - mergeset/blue-red 分類が分岐 → **chain split**
//!
//! ## v5 Fix: Conclusive Algorithm (`is_dag_ancestor_conclusive`)
//!
//! Consensus-critical パスでは **arbitrary block count cap を排除**。
//! 代わりに DAG 構造自体が BFS の終了を保証する:
//!
//! 1. **O(1) SPT fast-path ACCEPT**: interval containment (no false positives)
//! 2. **O(1) blue_score fast-path REJECT**: ancestor_score >= descendant_score
//! 3. **Structural BFS**: 探索は以下の条件で打ち切る:
//!    - `block.blue_score < ancestor.blue_score` → 祖先より古い → 到達不可能
//!    - `is_sp_tree_ancestor_of(block, ancestor)` → 既に祖先のSPT上 → skip
//!    - queue が空 → 全パス探索済み → **確定的 false**
//!
//! 4. **Safety hard cap**: 万一 DAG が病的に巨大な場合、
//!    `CONCLUSIVE_BFS_HARD_CAP` (500K) で **Error を返す** (`false` ではない)。
//!    呼び出し元はブロックを reject する。
//!
//! ## 終了性の証明
//!
//! Active window 内のブロック数は有限 (PRUNING_WINDOW × block rate)。
//! blue_score pruning により、BFS は `ancestor_score ≤ score ≤ descendant_score` の
//! 範囲のブロックのみ訪問する。この範囲のブロック数は DAG 幅に比例するが、
//! MAX_MERGESET_SIZE による fail-closed 制約があるため実用上有界。
//!
//! ## API Summary
//!
//! | Function | Returns | Consensus-safe | Use case |
//! |----------|---------|----------------|----------|
//! | `is_dag_ancestor_conclusive()` | `Result<bool>` | ✅ | GhostDAG, mergeset |
//! | `is_dag_anticone_conclusive()` | `Result<bool>` | ✅ | Blue/red classify |
//! | `is_true_dag_ancestor()` | `bool` | ❌ (deprecated) | Non-consensus utils |

use std::collections::{HashSet, VecDeque};

use crate::dag_block::Hash;
use crate::legacy_ghostdag::DagStore;

pub type ReachabilityHash = [u8; 32];
const ZERO_HASH: ReachabilityHash = [0u8; 32];
const GENESIS_RANGE: u64 = u64::MAX / 2;
const MIN_SLACK: u64 = 2;

/// Consensus-critical BFS の安全ハードキャップ。
///
/// DAG 構造による自然な打ち切りが機能すれば、この上限に到達することはない。
/// 到達した場合は DAG が病的に巨大か、実装バグを意味する。
/// `false` ではなく `Error` を返してブロックを reject させる。
///
/// 理論上限: PRUNING_WINDOW(1000) × DAG幅 ≈ 数万ブロック。
/// 500K は十分に保守的な安全マージン。
pub const CONCLUSIVE_BFS_HARD_CAP: usize = 500_000;

// ═══════════════════════════════════════════════════════════════
//  Error Types
// ═══════════════════════════════════════════════════════════════

/// Consensus-critical reachability クエリのエラー。
///
/// silent false (chain split の原因) ではなく、明示的エラーを返す。
/// 呼び出し元はブロックを **reject** しなければならない。
#[derive(Debug)]
pub enum ReachabilityError {
    /// BFS が safety hard cap に到達。DAG が病的に巨大か、実装バグ。
    BfsExhausted {
        visited: usize,
        cap: usize,
        ancestor: Hash,
        descendant: Hash,
    },

    /// GhostDagData が見つからない (store 不整合)。
    MissingGhostDagData { hash: Hash },
}

impl std::fmt::Display for ReachabilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BfsExhausted { visited, cap, ancestor, descendant } => {
                write!(
                    f,
                    "conclusive BFS exhausted: visited {} blocks (cap={}), ancestor={}, descendant={}",
                    visited, cap,
                    hex::encode(&ancestor[..4]),
                    hex::encode(&descendant[..4]),
                )
            }
            Self::MissingGhostDagData { hash } => {
                write!(f, "missing ghostdag data for block {}", hex::encode(&hash[..4]))
            }
        }
    }
}

impl std::error::Error for ReachabilityError {}

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
    /// v9: Ancestor query cache (virtual window scoped).
    /// Caches (ancestor, descendant) → bool for O(1) repeated queries.
    /// Cleared on virtual tip change or pruning.
    ancestor_cache: std::collections::HashMap<(Hash, Hash), bool>,
    /// v9: Cache hit/miss statistics.
    cache_hits: u64,
    cache_misses: u64,
    /// v9: Maximum cache size before eviction.
    max_cache_size: usize,
}

impl ReachabilityStore {
    pub fn new(genesis: Hash) -> Self {
        let mut nodes = std::collections::HashMap::new();
        nodes.insert(genesis, TreeNode {
            interval: Interval::new(0, GENESIS_RANGE),
            parent: ZERO_HASH,
            children: vec![],
        });
        Self {
            nodes, genesis, realloc_count: 0,
            ancestor_cache: std::collections::HashMap::new(),
            cache_hits: 0, cache_misses: 0,
            max_cache_size: 100_000,
        }
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

    // ── v9: Ancestor Query Cache ────────────────────────

    /// Cache an ancestor query result (for repeated queries within a virtual window).
    ///
    /// The cache is scoped to the current virtual window — when the virtual tip
    /// changes or pruning occurs, call `invalidate_cache()`.
    pub fn cache_ancestor_result(&mut self, ancestor: Hash, descendant: Hash, result: bool) {
        if self.ancestor_cache.len() >= self.max_cache_size {
            // Simple eviction: clear entire cache (LRU would be better but adds complexity)
            self.ancestor_cache.clear();
        }
        self.ancestor_cache.insert((ancestor, descendant), result);
    }

    /// Look up a cached ancestor query result.
    pub fn get_cached_ancestor(&mut self, ancestor: &Hash, descendant: &Hash) -> Option<bool> {
        match self.ancestor_cache.get(&(*ancestor, *descendant)) {
            Some(&result) => {
                self.cache_hits += 1;
                Some(result)
            }
            None => {
                self.cache_misses += 1;
                None
            }
        }
    }

    /// Invalidate the ancestor cache.
    ///
    /// Call when:
    /// - Virtual tip changes (new block accepted)
    /// - Pruning occurs
    /// - DAG structure changes significantly
    pub fn invalidate_cache(&mut self) {
        self.ancestor_cache.clear();
    }

    /// v9: Cache statistics.
    pub fn cache_stats(&self) -> (u64, u64, usize) {
        (self.cache_hits, self.cache_misses, self.ancestor_cache.len())
    }

    // ── v9: Index Compaction After Pruning ───────────────

    /// Compact the reachability index after pruning.
    ///
    /// After `prune_below()` removes nodes, the interval space may become fragmented.
    /// This redistributes intervals from the new effective root (pruning point or genesis)
    /// to utilize the full interval space efficiently.
    ///
    /// # When to call
    ///
    /// After `prune_below()` if the pruned count is significant (e.g., > 100 nodes).
    /// Compaction is O(remaining_nodes) so should not be called on every prune.
    pub fn compact_after_pruning(&mut self, new_root: &Hash) {
        if !self.nodes.contains_key(new_root) {
            return;
        }

        // Invalidate cache since intervals change
        self.invalidate_cache();

        // Redistribute from new_root with full range
        let root_interval = self.nodes[new_root].interval;
        self.redistribute(new_root, root_interval);

        tracing::debug!(
            "Reachability compacted from root={}, remaining_nodes={}",
            hex::encode(&new_root[..4]),
            self.nodes.len(),
        );
    }

    // ── Pruning ─────────────────────────────────────────────

    pub fn prune_below(&mut self, pruning_point: &Hash) -> usize {
        // v9: Invalidate cache since DAG structure changes
        self.invalidate_cache();

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
//  Conclusive DAG Ancestor Check (v5 Consensus-Critical)
// ═══════════════════════════════════════════════════════════════

/// Consensus-critical DAG 祖先判定 — **確定的 (Conclusive)**。
///
/// # v4 → v5 の変更
///
/// v4 の `is_true_dag_ancestor()` は `MAX_ANCESTOR_SEARCH_BLOCKS(4096)` で
/// 打ち切り → `false` を返していた。これは攻撃者が wide DAG を構築した場合に
/// ノード間でコンセンサスが分岐する原因だった。
///
/// v5 では arbitrary block count cap を **排除** し、DAG 構造自体による
/// 終了条件のみに依存する。万一の safety cap 到達時は `false` ではなく
/// `Err(BfsExhausted)` を返し、呼び出し元がブロックを reject する。
///
/// # アルゴリズム
///
/// 1. `ancestor == descendant` → `Ok(true)`
/// 2. SPT interval containment → `Ok(true)` (O(1), false positive なし)
/// 3. `ancestor.blue_score >= descendant.blue_score` → `Ok(false)` (O(1))
/// 4. Structural BFS:
///    - descendant から ancestor に向かって全 DAG 親を遡る
///    - `block.blue_score < ancestor.blue_score` のブロックは skip (到達不可能)
///    - `is_sp_tree_ancestor_of(block, ancestor)` のブロックは skip
///    - ancestor を発見 → `Ok(true)`
///    - queue 空 → `Ok(false)` (全パス探索済み、確定的)
/// 5. Safety hard cap (`CONCLUSIVE_BFS_HARD_CAP`) → `Err(BfsExhausted)`
///
/// # 終了性
///
/// blue_score pruning により BFS は `ancestor_score ≤ score ≤ descendant_score`
/// の範囲のブロックのみ訪問する。Active window 内のブロック数は有限であり、
/// visited set により各ブロックは高々1回訪問される。したがって BFS は必ず終了する。
///
/// # Consensus Safety
///
/// - 全ノードは同一の DAG + GhostDagData → 同一の BFS 結果
/// - `Ok(true)` / `Ok(false)` は到達可能性というグラフの構造的性質に基づき、
///   BFS の探索順には依存しない
/// - `Err(BfsExhausted)` はブロック reject → 全ノードが同一の判断
pub fn is_dag_ancestor_conclusive<S: DagStore>(
    ancestor: &Hash,
    descendant: &Hash,
    reachability: &ReachabilityStore,
    store: &S,
) -> Result<bool, ReachabilityError> {
    // ── 1. Identity ──
    if ancestor == descendant {
        return Ok(true);
    }

    // ── 2. O(1) SPT fast-path ACCEPT ──
    if reachability.is_sp_tree_ancestor_of(ancestor, descendant) {
        return Ok(true);
    }

    // ── 3. O(1) blue_score fast-path REJECT ──
    let ancestor_score = store.get_ghostdag_data(ancestor)
        .map(|d| d.blue_score)
        .ok_or(ReachabilityError::MissingGhostDagData { hash: *ancestor })?;
    let descendant_score = store.get_ghostdag_data(descendant)
        .map(|d| d.blue_score)
        .ok_or(ReachabilityError::MissingGhostDagData { hash: *descendant })?;
    if ancestor_score >= descendant_score {
        return Ok(false);
    }

    // ── 4. Structural BFS (no arbitrary block cap) ──
    let mut visited = HashSet::new();
    let mut queue: VecDeque<Hash> = VecDeque::new();
    visited.insert(*descendant);

    // Seed: descendant の直接の親
    if let Some(header) = store.get_header(descendant) {
        for p in &header.parents {
            if *p == *ancestor { return Ok(true); }
            if visited.insert(*p) { queue.push_back(*p); }
        }
    }

    let mut blocks_visited: usize = 0;

    while let Some(current) = queue.pop_front() {
        blocks_visited += 1;

        // ── 5. Safety hard cap → Error (NOT false) ──
        if blocks_visited > CONCLUSIVE_BFS_HARD_CAP {
            return Err(ReachabilityError::BfsExhausted {
                visited: blocks_visited,
                cap: CONCLUSIVE_BFS_HARD_CAP,
                ancestor: *ancestor,
                descendant: *descendant,
            });
        }

        // SPT pruning: current が ancestor の SPT 祖先 → 探索方向が逆転 → skip
        if reachability.is_sp_tree_ancestor_of(&current, ancestor) {
            continue;
        }

        // blue_score pruning: ancestor より古い → 到達不可能
        let current_score = store.get_ghostdag_data(&current)
            .map(|d| d.blue_score)
            .unwrap_or(0);
        if current_score < ancestor_score {
            continue;
        }

        // 現在のブロックの全 DAG 親を探索
        if let Some(header) = store.get_header(&current) {
            for p in &header.parents {
                if *p == *ancestor { return Ok(true); }
                if visited.insert(*p) { queue.push_back(*p); }
            }
        }
    }

    // queue 空: 全パス探索済み → ancestor は descendant の past にない (確定的)
    Ok(false)
}

/// Consensus-critical DAG anticone 判定 — **確定的**。
///
/// `a` と `b` が互いの past にない (= anticone 関係) かを判定する。
/// どちらの方向の祖先チェックもエラーなく完了した場合のみ結果を返す。
pub fn is_dag_anticone_conclusive<S: DagStore>(
    a: &Hash,
    b: &Hash,
    reachability: &ReachabilityStore,
    store: &S,
) -> Result<bool, ReachabilityError> {
    // a が b の祖先なら anticone ではない
    if is_dag_ancestor_conclusive(a, b, reachability, store)? {
        return Ok(false);
    }
    // b が a の祖先なら anticone ではない
    if is_dag_ancestor_conclusive(b, a, reachability, store)? {
        return Ok(false);
    }
    // 両方向とも祖先ではない → anticone
    Ok(true)
}

// ═══════════════════════════════════════════════════════════════
//  Legacy Bounded BFS (Non-Consensus Only)
// ═══════════════════════════════════════════════════════════════

/// ⚠️ **DEPRECATED for consensus paths** — Use `is_dag_ancestor_conclusive()`.
///
/// BFS 上限 `MAX_ANCESTOR_SEARCH_BLOCKS` に依存しており、
/// 上限到達時に `false` を返す。コンセンサス分岐の原因になり得る。
///
/// 非コンセンサス用途 (decoy 選択、UI 表示等) でのみ使用可。
#[deprecated(note = "Consensus-critical: use is_dag_ancestor_conclusive(). \
    This function returns false on BFS exhaustion, which can cause chain splits.")]
pub fn is_true_dag_ancestor<S: DagStore>(
    ancestor: &Hash,
    descendant: &Hash,
    reachability: &ReachabilityStore,
    store: &S,
) -> bool {
    match is_dag_ancestor_conclusive(ancestor, descendant, reachability, store) {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!(
                "is_true_dag_ancestor: conclusive BFS failed ({}), returning false — \
                 THIS IS UNSAFE FOR CONSENSUS",
                e,
            );
            false
        }
    }
}

/// ⚠️ **DEPRECATED for consensus paths** — Use `is_dag_anticone_conclusive()`.
#[deprecated(note = "Consensus-critical: use is_dag_anticone_conclusive(). \
    This function delegates to is_true_dag_ancestor which is BFS-cap-unsafe.")]
pub fn is_true_dag_anticone<S: DagStore>(
    a: &Hash,
    b: &Hash,
    reachability: &ReachabilityStore,
    store: &S,
) -> bool {
    match is_dag_anticone_conclusive(a, b, reachability, store) {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!(
                "is_true_dag_anticone: conclusive BFS failed ({}), returning true — \
                 THIS IS UNSAFE FOR CONSENSUS",
                e,
            );
            true
        }
    }
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

    /// **Task 1.1 Critical Test: Side-branch ancestor detection (Conclusive)**
    ///
    /// ```text
    ///     G
    ///    / \
    ///   A   B     (parallel)
    ///    \ /
    ///     C       (parents: [A, B], SP = A)
    /// ```
    ///
    /// B ∈ Past(C) but SPT says NO. Conclusive BFS must say YES.
    #[test]
    fn test_conclusive_detects_side_branch_ancestor() {
        let g = [0x00; 32]; let a = [0x0A; 32];
        let b = [0x0B; 32]; let c = [0x0C; 32];

        let mut store = InMemoryDagStore::new();
        let mut reach = ReachabilityStore::new(g);

        store.insert_header(g, make_header(vec![]));
        store.set_ghostdag_data(g, GhostDagData {
            selected_parent: DAG_ZERO, mergeset_blues: vec![], mergeset_reds: vec![],
            blue_score: 0, blue_work: 0,
            blues_anticone_sizes: vec![],
        });

        store.insert_header(a, make_header(vec![g]));
        reach.add_child(g, a).unwrap();
        store.set_ghostdag_data(a, GhostDagData {
            selected_parent: g, mergeset_blues: vec![], mergeset_reds: vec![],
            blue_score: 1, blue_work: 1,
            blues_anticone_sizes: vec![],
        });

        store.insert_header(b, make_header(vec![g]));
        reach.add_child(g, b).unwrap();
        store.set_ghostdag_data(b, GhostDagData {
            selected_parent: g, mergeset_blues: vec![], mergeset_reds: vec![],
            blue_score: 1, blue_work: 1,
            blues_anticone_sizes: vec![],
        });

        store.insert_header(c, make_header(vec![a, b]));
        reach.add_child(a, c).unwrap();
        store.set_ghostdag_data(c, GhostDagData {
            selected_parent: a, mergeset_blues: vec![b], mergeset_reds: vec![],
            blue_score: 3, blue_work: 3,
            blues_anticone_sizes: vec![],
        });

        // SPT cannot detect B→C (sibling subtrees)
        assert!(!reach.is_sp_tree_ancestor_of(&b, &c), "SPT must NOT detect B→C");

        // Conclusive BFS MUST detect B→C
        assert_eq!(
            is_dag_ancestor_conclusive(&b, &c, &reach, &store).unwrap(),
            true,
            "Conclusive MUST detect B→C (side-branch)"
        );
        assert_eq!(is_dag_ancestor_conclusive(&a, &c, &reach, &store).unwrap(), true);
        assert_eq!(is_dag_ancestor_conclusive(&g, &c, &reach, &store).unwrap(), true);
        assert_eq!(is_dag_ancestor_conclusive(&c, &b, &reach, &store).unwrap(), false);
        assert_eq!(is_dag_anticone_conclusive(&a, &b, &reach, &store).unwrap(), true);
    }

    /// Deep side-branch: B reachable via D → B, two hops from E (Conclusive).
    #[test]
    fn test_conclusive_detects_deep_side_branch() {
        let g = [0x00; 32]; let a = [0x0A; 32]; let b = [0x0B; 32];
        let c = [0x0C; 32]; let d = [0x0D; 32]; let e = [0x0E; 32];

        let mut store = InMemoryDagStore::new();
        let mut reach = ReachabilityStore::new(g);

        store.insert_header(g, make_header(vec![]));
        store.set_ghostdag_data(g, GhostDagData { selected_parent: DAG_ZERO, mergeset_blues: vec![], mergeset_reds: vec![], blue_score: 0, blue_work: 0, blues_anticone_sizes: vec![]});

        for (hash, parent, score) in [(a, g, 1u64), (b, g, 1), (c, a, 2), (d, b, 2)] {
            store.insert_header(hash, make_header(vec![parent]));
            reach.add_child(parent, hash).unwrap();
            store.set_ghostdag_data(hash, GhostDagData { selected_parent: parent, mergeset_blues: vec![], mergeset_reds: vec![], blue_score: score, blue_work: score as u128, blues_anticone_sizes: vec![]});
        }

        store.insert_header(e, make_header(vec![c, d]));
        reach.add_child(c, e).unwrap();
        store.set_ghostdag_data(e, GhostDagData { selected_parent: c, mergeset_blues: vec![d], mergeset_reds: vec![], blue_score: 4, blue_work: 4, blues_anticone_sizes: vec![]});

        assert_eq!(is_dag_ancestor_conclusive(&d, &e, &reach, &store).unwrap(), true);
        assert_eq!(is_dag_ancestor_conclusive(&b, &e, &reach, &store).unwrap(), true);
        assert_eq!(is_dag_ancestor_conclusive(&g, &e, &reach, &store).unwrap(), true);
        // E is NOT an ancestor of B
        assert_eq!(is_dag_ancestor_conclusive(&e, &b, &reach, &store).unwrap(), false);
    }

    /// Wide DAG test: many parallel branches merging into one block.
    /// This topology would hit the old 4096 cap with enough branches.
    /// Conclusive algorithm must handle it without arbitrary limits.
    #[test]
    fn test_conclusive_wide_dag_no_false_negative() {
        let g = [0x00; 32];
        let mut store = InMemoryDagStore::new();
        let mut reach = ReachabilityStore::new(g);

        store.insert_header(g, make_header(vec![]));
        store.set_ghostdag_data(g, GhostDagData {
            selected_parent: DAG_ZERO, mergeset_blues: vec![], mergeset_reds: vec![],
            blue_score: 0, blue_work: 0,
            blues_anticone_sizes: vec![],
        });

        // Create 200 parallel branches from genesis, each 5 blocks deep
        let width = 200u32;
        let depth = 5u32;
        let mut all_tips = Vec::new();

        for branch in 0..width {
            let mut parent = g;
            for d in 0..depth {
                let id = branch * 1000 + d + 1;
                let mut hash = [0u8; 32];
                hash[..4].copy_from_slice(&id.to_le_bytes());

                store.insert_header(hash, make_header(vec![parent]));
                reach.add_child(parent, hash).unwrap();
                store.set_ghostdag_data(hash, GhostDagData {
                    selected_parent: parent,
                    mergeset_blues: vec![],
                    mergeset_reds: vec![],
                    blue_score: (d + 1) as u64,
                    blue_work: (d + 1) as u128,
                    blues_anticone_sizes: vec![],
                });
                parent = hash;
            }
            all_tips.push(parent);
        }

        // Create a merge block with 2 parents from different branches
        let merge_hash = [0xFF; 32];
        let parents = vec![all_tips[0], all_tips[100]];
        store.insert_header(merge_hash, make_header(parents.clone()));
        reach.add_child(all_tips[0], merge_hash).unwrap();
        store.set_ghostdag_data(merge_hash, GhostDagData {
            selected_parent: all_tips[0],
            mergeset_blues: vec![all_tips[100]],
            mergeset_reds: vec![],
            blue_score: (depth + 1) as u64,
            blue_work: (depth + 1) as u128,
            blues_anticone_sizes: vec![],
        });

        // Branch 100's entire chain must be detectable as ancestor of merge_hash
        let mut check = all_tips[100];
        for _ in 0..depth {
            let result = is_dag_ancestor_conclusive(&check, &merge_hash, &reach, &store);
            assert!(result.is_ok(), "conclusive must not error");
            assert_eq!(result.unwrap(), true, "branch tip must be ancestor of merge");

            // Walk back to parent
            if let Some(header) = store.get_header(&check) {
                if !header.parents.is_empty() {
                    check = header.parents[0];
                }
            }
        }

        // Genesis must also be detected
        assert_eq!(
            is_dag_ancestor_conclusive(&g, &merge_hash, &reach, &store).unwrap(),
            true,
        );

        // A tip from an unrelated branch is NOT an ancestor
        assert_eq!(
            is_dag_ancestor_conclusive(&all_tips[50], &merge_hash, &reach, &store).unwrap(),
            false,
        );
    }

    /// Missing GhostDagData returns Error (not silent false).
    #[test]
    fn test_conclusive_missing_data_returns_error() {
        let g = [0x00; 32];
        let unknown = [0xFF; 32];

        let mut store = InMemoryDagStore::new();
        let reach = ReachabilityStore::new(g);

        store.insert_header(g, make_header(vec![]));
        store.set_ghostdag_data(g, GhostDagData {
            selected_parent: DAG_ZERO, mergeset_blues: vec![], mergeset_reds: vec![],
            blue_score: 0, blue_work: 0,
            blues_anticone_sizes: vec![],
        });

        // unknown has no GhostDagData → must return Error
        let result = is_dag_ancestor_conclusive(&unknown, &g, &reach, &store);
        assert!(result.is_err(), "missing data must return Error, not silent false");

        match result.unwrap_err() {
            ReachabilityError::MissingGhostDagData { hash } => {
                assert_eq!(hash, unknown);
            }
            other => panic!("expected MissingGhostDagData, got: {:?}", other),
        }
    }

    /// Identity: a block is always its own ancestor.
    #[test]
    fn test_conclusive_identity() {
        let g = [0x00; 32];
        let store = InMemoryDagStore::new();
        let reach = ReachabilityStore::new(g);

        // No store data needed — identity check is pre-BFS
        assert_eq!(is_dag_ancestor_conclusive(&g, &g, &reach, &store).unwrap(), true);
    }

    /// Anticone: conclusive anticone is symmetric.
    #[test]
    fn test_conclusive_anticone_symmetric() {
        let g = [0x00; 32]; let a = [0x0A; 32]; let b = [0x0B; 32];

        let mut store = InMemoryDagStore::new();
        let mut reach = ReachabilityStore::new(g);

        store.insert_header(g, make_header(vec![]));
        store.set_ghostdag_data(g, GhostDagData {
            selected_parent: DAG_ZERO, mergeset_blues: vec![], mergeset_reds: vec![],
            blue_score: 0, blue_work: 0,
            blues_anticone_sizes: vec![],
        });

        for (hash, score) in [(a, 1u64), (b, 1)] {
            store.insert_header(hash, make_header(vec![g]));
            reach.add_child(g, hash).unwrap();
            store.set_ghostdag_data(hash, GhostDagData {
                selected_parent: g, mergeset_blues: vec![], mergeset_reds: vec![],
                blue_score: score, blue_work: score as u128,
                blues_anticone_sizes: vec![],
            });
        }

        // A and B are parallel (anticone)
        assert_eq!(is_dag_anticone_conclusive(&a, &b, &reach, &store).unwrap(), true);
        assert_eq!(is_dag_anticone_conclusive(&b, &a, &reach, &store).unwrap(), true);
        // Genesis is NOT in anticone with either
        assert_eq!(is_dag_anticone_conclusive(&g, &a, &reach, &store).unwrap(), false);
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
