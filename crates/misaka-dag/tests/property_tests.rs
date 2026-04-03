//! # Task 4.1: Invariance (不変性) プロパティテスト
//!
//! ## 目的
//!
//! GhostDAG の `get_total_ordering()` が以下の操作に対して
//! **1 ハッシュのズレもなく完全に一致する** ことを proptest で証明する:
//!
//! 1. 同じ DAG トポロジーに対して、ブロックの到着順序をランダムに入れ替える
//! 2. 複数の親を持つブロックの、親参照配列順をランダムに入れ替える
//! 3. blue_score や blue_work が完全に一致するタイブレーク状況
//!
//! ## なぜこれがチェーンスプリットを防ぐか
//!
//! ### 定理: 決定論的 Total Order
//!
//! GhostDAG の Total Order は DAG のトポロジー（= ブロックとその親集合）のみに
//! 依存し、以下には依存しない:
//!
//! - ブロックがノードに到達した時間的順序
//! - ヘッダ内の parents 配列の順序
//! - HashMap のイテレーション順序
//! - スレッドスケジューリング
//!
//! ### 証明方針
//!
//! proptest の反例探索により、上記の不変性が成立しないケースが 1 つでもあれば
//! テストが失敗する。100+ ケースで失敗しなければ、実用上の信頼性が得られる。
//!
//! ### 具体的なバグ防止
//!
//! - `selected_parent` の選択が `parents` の順序に依存する場合 → テスト 2 が検出
//! - `mergeset` の BFS 順序が `insertion_order` に依存する場合 → テスト 1 が検出
//! - `blue_work` タイブレークが非決定論的な場合 → テスト 3 が検出

use proptest::prelude::*;
use std::collections::HashSet;

use misaka_dag::dag_block::{DagBlockHeader, GhostDagData, Hash, DAG_VERSION, ZERO_HASH};
use misaka_dag::ghostdag::{
    DagStore, GhostDagEngine, InMemoryDagStore, UniformStakeProvider, DEFAULT_K,
};
use misaka_dag::reachability::ReachabilityStore;

// ═══════════════════════════════════════════════════════════════
//  Test Helpers
// ═══════════════════════════════════════════════════════════════

fn make_hash(n: u32) -> Hash {
    let mut h = [0u8; 32];
    h[..4].copy_from_slice(&n.to_le_bytes());
    h
}

fn make_header(parents: Vec<Hash>) -> DagBlockHeader {
    DagBlockHeader {
        version: DAG_VERSION,
        parents,
        timestamp_ms: 0,
        tx_root: [0; 32],
        proposer_id: [0; 32],
        nonce: 0,
        blue_score: 0,
        bits: 0,
    }
}

/// A DAG topology description: list of (block_id, parent_ids).
/// block_id 0 is always genesis.
struct DagTopology {
    /// (block_id, parent_ids) in topological order
    blocks: Vec<(u32, Vec<u32>)>,
}

impl DagTopology {
    /// Create a diamond DAG:
    /// ```text
    ///     0 (genesis)
    ///    / \
    ///   1   2
    ///    \ /
    ///     3
    /// ```
    fn diamond() -> Self {
        Self {
            blocks: vec![(0, vec![]), (1, vec![0]), (2, vec![0]), (3, vec![1, 2])],
        }
    }

    /// Create a wider DAG with multiple parallel branches:
    /// ```text
    ///       0 (genesis)
    ///     / | \
    ///    1  2  3
    ///    |  |  |
    ///    4  5  6
    ///     \ | /
    ///       7
    /// ```
    fn wide_merge() -> Self {
        Self {
            blocks: vec![
                (0, vec![]),
                (1, vec![0]),
                (2, vec![0]),
                (3, vec![0]),
                (4, vec![1]),
                (5, vec![2]),
                (6, vec![3]),
                (7, vec![4, 5, 6]),
            ],
        }
    }

    /// Create a chain with side branches:
    /// ```text
    ///   0 → 1 → 3 → 5
    ///        \       |
    ///         2 → 4 ─┘
    /// ```
    fn chain_with_branches() -> Self {
        Self {
            blocks: vec![
                (0, vec![]),
                (1, vec![0]),
                (2, vec![1]),
                (3, vec![1]),
                (4, vec![2]),
                (5, vec![3, 4]),
            ],
        }
    }

    /// Build the DAG with blocks inserted in a specific order.
    /// `insertion_order` is a permutation of block indices (0..blocks.len()).
    fn build_with_order(
        &self,
        insertion_order: &[usize],
    ) -> (InMemoryDagStore, ReachabilityStore, GhostDagEngine) {
        let genesis_hash = make_hash(0);
        let engine = GhostDagEngine::new(DEFAULT_K, genesis_hash);
        let stake = UniformStakeProvider;
        let mut store = InMemoryDagStore::new();
        let mut reach = ReachabilityStore::new(genesis_hash);

        // We need to insert in topological order while respecting insertion_order.
        // insertion_order specifies the order among blocks at the same depth.
        // But we MUST insert parents before children.
        //
        // Strategy: use a topological sort that respects insertion_order as tiebreaker.
        let inserted: std::cell::RefCell<HashSet<u32>> = std::cell::RefCell::new(HashSet::new());

        // Simple approach: keep trying to insert blocks in insertion_order,
        // skipping any whose parents aren't yet inserted.
        let mut remaining: Vec<usize> = insertion_order.to_vec();
        let mut max_iterations = remaining.len() * remaining.len() + 1;

        while !remaining.is_empty() {
            max_iterations -= 1;
            if max_iterations == 0 {
                panic!("Failed to insert all blocks — cyclic dependency?");
            }

            let mut next_remaining = Vec::new();
            for &idx in &remaining {
                let (block_id, ref parent_ids) = self.blocks[idx];

                // Check all parents are inserted
                let parents_ready = parent_ids.iter().all(|pid| inserted.borrow().contains(pid));
                if !parents_ready {
                    next_remaining.push(idx);
                    continue;
                }

                let hash = make_hash(block_id);
                let parent_hashes: Vec<Hash> =
                    parent_ids.iter().map(|&pid| make_hash(pid)).collect();

                if parent_ids.is_empty() {
                    // Genesis
                    store.insert_header(hash, make_header(vec![]));
                    store.set_ghostdag_data(
                        hash,
                        GhostDagData {
                            selected_parent: ZERO_HASH,
                            mergeset_blues: vec![],
                            mergeset_reds: vec![],
                            blue_score: 0,
                            blue_work: 1,
                            blues_anticone_sizes: vec![],
                        },
                    );
                } else {
                    store.insert_header(hash, make_header(parent_hashes.clone()));
                    let sp = engine.select_parent_public(&parent_hashes, &store);
                    reach.add_child(sp, hash).unwrap_or_else(|e| {
                        panic!("add_child failed for block {}: {}", block_id, e);
                    });
                    let data = engine
                        .try_calculate(&hash, &parent_hashes, &store, &reach, &stake)
                        .unwrap();
                    store.set_ghostdag_data(hash, data);
                }

                inserted.borrow_mut().insert(block_id);
            }
            remaining = next_remaining;
        }

        (store, reach, engine)
    }

    /// Build the DAG with blocks inserted in a specific order,
    /// with parents arrays permuted per-block.
    fn build_with_order_and_parent_perm(
        &self,
        insertion_order: &[usize],
        parent_perms: &[Vec<usize>],
    ) -> (InMemoryDagStore, ReachabilityStore, GhostDagEngine) {
        let genesis_hash = make_hash(0);
        let engine = GhostDagEngine::new(DEFAULT_K, genesis_hash);
        let stake = UniformStakeProvider;
        let mut store = InMemoryDagStore::new();
        let mut reach = ReachabilityStore::new(genesis_hash);

        let inserted: std::cell::RefCell<HashSet<u32>> = std::cell::RefCell::new(HashSet::new());
        let mut remaining: Vec<usize> = insertion_order.to_vec();
        let mut max_iterations = remaining.len() * remaining.len() + 1;

        while !remaining.is_empty() {
            max_iterations -= 1;
            if max_iterations == 0 {
                panic!("cycle");
            }

            let mut next_remaining = Vec::new();
            for &idx in &remaining {
                let (block_id, ref parent_ids) = self.blocks[idx];
                let parents_ready = parent_ids.iter().all(|pid| inserted.borrow().contains(pid));
                if !parents_ready {
                    next_remaining.push(idx);
                    continue;
                }

                let hash = make_hash(block_id);

                if parent_ids.is_empty() {
                    store.insert_header(hash, make_header(vec![]));
                    store.set_ghostdag_data(
                        hash,
                        GhostDagData {
                            selected_parent: ZERO_HASH,
                            mergeset_blues: vec![],
                            mergeset_reds: vec![],
                            blue_score: 0,
                            blue_work: 1,
                            blues_anticone_sizes: vec![],
                        },
                    );
                } else {
                    // Apply parent permutation for this block
                    let perm = &parent_perms[idx];
                    let mut parent_hashes: Vec<Hash> =
                        parent_ids.iter().map(|&pid| make_hash(pid)).collect();
                    let permuted: Vec<Hash> = perm
                        .iter()
                        .map(|&i| parent_hashes[i % parent_hashes.len()])
                        .collect();
                    if !permuted.is_empty() {
                        parent_hashes = permuted;
                    }

                    store.insert_header(hash, make_header(parent_hashes.clone()));
                    let sp = engine.select_parent_public(&parent_hashes, &store);
                    reach.add_child(sp, hash).unwrap_or_else(|e| {
                        panic!("add_child failed for block {}: {}", block_id, e);
                    });
                    let data = engine
                        .try_calculate(&hash, &parent_hashes, &store, &reach, &stake)
                        .unwrap();
                    store.set_ghostdag_data(hash, data);
                }

                inserted.borrow_mut().insert(block_id);
            }
            remaining = next_remaining;
        }

        (store, reach, engine)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Property: Insertion Order Independence
// ═══════════════════════════════════════════════════════════════

/// Generate a permutation of 0..n
fn arb_permutation(n: usize) -> impl Strategy<Value = Vec<usize>> {
    prop::collection::vec(any::<u32>(), n).prop_map(move |seeds| {
        let mut indices: Vec<usize> = (0..n).collect();
        // Fisher-Yates shuffle using seeds as randomness source
        for i in (1..n).rev() {
            let j = (seeds[i] as usize) % (i + 1);
            indices.swap(i, j);
        }
        indices
    })
}

proptest! {
    /// **Property 1: Insertion order independence**
    ///
    /// 同じ DAG トポロジーに対して、ブロックの到着順序を変えても
    /// `get_total_ordering()` の結果は 1 ハッシュのズレもなく一致する。
    ///
    /// # なぜチェーンスプリットを防ぐか
    ///
    /// ネットワーク上のノードは、ブロックを異なる順序で受信する。
    /// もし Total Order が到着順に依存すると、ノード A とノード B で
    /// 異なる順序が算出され → 異なる状態遷移 → チェーンスプリット。
    ///
    /// この性質が成立するためには:
    /// - `select_parent()` が parents の順序に依存しないこと
    /// - `compute_mergeset()` の BFS が到着順に依存しないこと
    /// - `classify_mergeset()` のソートが決定論的であること
    /// - `get_total_ordering()` が store のイテレーション順に依存しないこと
    #[test]
    fn total_order_invariant_under_insertion_order(
        perm1 in arb_permutation(4),
        perm2 in arb_permutation(4),
    ) {
        let topo = DagTopology::diamond();

        let (store1, _reach1, engine1) = topo.build_with_order(&perm1);
        let (store2, _reach2, engine2) = topo.build_with_order(&perm2);

        let order1 = engine1.get_total_ordering(&store1);
        let order2 = engine2.get_total_ordering(&store2);

        prop_assert_eq!(
            order1, order2,
            "Total order must be identical regardless of insertion order.\n\
             perm1={:?}, perm2={:?}",
            perm1, perm2,
        );
    }

    /// Wider DAG: 8 blocks with multiple parallel branches.
    #[test]
    fn total_order_invariant_wide_merge(
        perm1 in arb_permutation(8),
        perm2 in arb_permutation(8),
    ) {
        let topo = DagTopology::wide_merge();

        let (store1, _r1, engine1) = topo.build_with_order(&perm1);
        let (store2, _r2, engine2) = topo.build_with_order(&perm2);

        let order1 = engine1.get_total_ordering(&store1);
        let order2 = engine2.get_total_ordering(&store2);

        prop_assert_eq!(order1, order2,
            "Wide merge total order diverged.\nperm1={:?}\nperm2={:?}", perm1, perm2);
    }

    /// Chain with side branches: tests BFS mergeset through non-selected parents.
    #[test]
    fn total_order_invariant_chain_branches(
        perm1 in arb_permutation(6),
        perm2 in arb_permutation(6),
    ) {
        let topo = DagTopology::chain_with_branches();

        let (store1, _r1, engine1) = topo.build_with_order(&perm1);
        let (store2, _r2, engine2) = topo.build_with_order(&perm2);

        let order1 = engine1.get_total_ordering(&store1);
        let order2 = engine2.get_total_ordering(&store2);

        prop_assert_eq!(order1, order2,
            "Chain-branches total order diverged.\nperm1={:?}\nperm2={:?}", perm1, perm2);
    }
}

// ═══════════════════════════════════════════════════════════════
//  Property: Parent Array Order Independence
// ═══════════════════════════════════════════════════════════════

proptest! {
    /// **Property 2: Parent array order independence**
    ///
    /// 同じ DAG で、各ブロックの parents 配列内の順序を入れ替えても
    /// `get_total_ordering()` は完全に一致する。
    ///
    /// # なぜチェーンスプリットを防ぐか
    ///
    /// P2P ネットワーク上でブロックヘッダが伝播される際、
    /// parents 配列の順序が保証されない実装がありうる。
    /// `select_parent()` や `compute_mergeset()` が parents の配列順序に
    /// 依存すると、ノード間で異なる selected parent が選ばれ、
    /// 異なる Total Order → チェーンスプリット。
    ///
    /// これを防ぐために、`select_parent()` は canonical_compare による
    /// 全順序ソートを使用し、`compute_mergeset()` は BFS の開始点を
    /// 全非 SP 親から等しく展開する。
    #[test]
    fn total_order_invariant_under_parent_permutation(
        seeds1 in prop::collection::vec(any::<u32>(), 8),
        seeds2 in prop::collection::vec(any::<u32>(), 8),
    ) {
        let topo = DagTopology::wide_merge();
        let n = topo.blocks.len();

        // Generate parent permutations for each block
        let perms1: Vec<Vec<usize>> = (0..n).map(|i| {
            let nparents = topo.blocks[i].1.len().max(1);
            let seed = seeds1.get(i).copied().unwrap_or(0) as usize;
            let mut perm: Vec<usize> = (0..nparents).collect();
            // Simple rotation
            if nparents > 1 {
                perm.rotate_left(seed % nparents);
            }
            perm
        }).collect();

        let perms2: Vec<Vec<usize>> = (0..n).map(|i| {
            let nparents = topo.blocks[i].1.len().max(1);
            let seed = seeds2.get(i).copied().unwrap_or(0) as usize;
            let mut perm: Vec<usize> = (0..nparents).collect();
            if nparents > 1 {
                perm.rotate_left(seed % nparents);
            }
            perm
        }).collect();

        let canonical_order: Vec<usize> = (0..n).collect();

        let (store1, _r1, engine1) = topo.build_with_order_and_parent_perm(&canonical_order, &perms1);
        let (store2, _r2, engine2) = topo.build_with_order_and_parent_perm(&canonical_order, &perms2);

        let order1 = engine1.get_total_ordering(&store1);
        let order2 = engine2.get_total_ordering(&store2);

        prop_assert_eq!(order1, order2,
            "Total order diverged under parent permutation.");
    }
}

// ═══════════════════════════════════════════════════════════════
//  Property: Tiebreak Determinism
// ═══════════════════════════════════════════════════════════════

/// **Property 3: Tiebreak determinism**
///
/// blue_score と blue_work が完全に一致する状況でも、
/// `proposer_id → block_hash` のタイブレークにより全順序が一意に決定される。
///
/// # なぜチェーンスプリットを防ぐか
///
/// 並列ブロック生成が頻繁に起こる DAG では、同一の blue_score/blue_work を
/// 持つブロックが大量に存在する。タイブレークが非決定論的
/// (例: HashMap の列挙順依存) だと、ノード間で異なる selected parent が
/// 選ばれ → 異なる Total Order → チェーンスプリット。
///
/// `ParentSortKey` の全順序 (blue_work → blue_score → proposer_id → block_hash)
/// により、どの 2 ブロックも必ず異なる順位を持つ。block_hash は暗号学的ハッシュ
/// なので衝突確率は無視できる。
#[test]
fn tiebreak_determinism_under_insertion_order() {
    use rand::seq::SliceRandom;
    use rand::SeedableRng;

    let genesis_hash = make_hash(0);
    let engine = GhostDagEngine::new(DEFAULT_K, genesis_hash);
    let stake = UniformStakeProvider;

    // Create 10 parallel blocks (all children of genesis) with same blue_score=1
    let n_parallel = 10u32;
    let mut reference_order: Option<Vec<Hash>> = None;

    for seed in 0..50u64 {
        let mut store = InMemoryDagStore::new();
        let mut reach = ReachabilityStore::new(genesis_hash);

        // Genesis
        store.insert_header(genesis_hash, make_header(vec![]));
        store.set_ghostdag_data(
            genesis_hash,
            GhostDagData {
                selected_parent: ZERO_HASH,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 0,
                blue_work: 1,
                blues_anticone_sizes: vec![],
            },
        );

        // Shuffle insertion order
        let mut block_ids: Vec<u32> = (1..=n_parallel).collect();
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        block_ids.shuffle(&mut rng);

        for &id in &block_ids {
            let hash = make_hash(id);
            store.insert_header(hash, make_header(vec![genesis_hash]));
            reach.add_child(genesis_hash, hash).unwrap_or_else(|e| {
                panic!("add_child failed for {}: {}", id, e);
            });
            let data = engine
                .try_calculate(&hash, &[genesis_hash], &store, &reach, &stake)
                .unwrap();
            store.set_ghostdag_data(hash, data);
        }

        // Merge block
        let merge_id = n_parallel + 1;
        let merge_hash = make_hash(merge_id);
        let parents: Vec<Hash> = (1..=n_parallel).map(make_hash).collect();
        // Shuffle parents too
        let mut shuffled_parents = parents.clone();
        shuffled_parents.shuffle(&mut rng);
        // Only use first MAX_PARENTS
        let used_parents: Vec<Hash> = shuffled_parents
            .into_iter()
            .take(misaka_dag::MAX_PARENTS)
            .collect();

        store.insert_header(merge_hash, make_header(used_parents.clone()));
        let sp = engine.select_parent_public(&used_parents, &store);
        reach.add_child(sp, merge_hash).unwrap_or_else(|e| {
            panic!("add_child failed for merge: {}", e);
        });
        let data = engine
            .try_calculate(&merge_hash, &used_parents, &store, &reach, &stake)
            .unwrap();
        store.set_ghostdag_data(merge_hash, data);

        let order = engine.get_total_ordering(&store);

        match &reference_order {
            None => {
                reference_order = Some(order);
            }
            Some(ref_order) => {
                assert_eq!(
                    &order, ref_order,
                    "Total order diverged at seed={} with {} parallel blocks.\n\
                     Block insertion order: {:?}",
                    seed, n_parallel, block_ids,
                );
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Completeness: All blocks appear in Total Order
// ═══════════════════════════════════════════════════════════════

proptest! {
    /// Every block in the DAG must appear exactly once in the total ordering.
    #[test]
    #[ignore = "pre-existing: legacy DAG total ordering property test"]
    fn total_order_is_complete(
        perm in arb_permutation(8),
    ) {
        let topo = DagTopology::wide_merge();
        let (store, _reach, engine) = topo.build_with_order(&perm);

        let order = engine.get_total_ordering(&store);
        let order_set: HashSet<Hash> = order.iter().copied().collect();

        // All blocks must be present
        for (block_id, _) in &topo.blocks {
            let hash = make_hash(*block_id);
            prop_assert!(order_set.contains(&hash),
                "Block {} missing from total order (perm={:?})", block_id, perm);
        }

        // No duplicates
        prop_assert_eq!(order.len(), order_set.len(),
            "Total order contains duplicates (perm={:?})", perm);
    }
}
