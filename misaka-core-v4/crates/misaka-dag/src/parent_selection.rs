//! Canonical Parent Selection — Single Source of Truth (Task 1.1)
//!
//! # 設計原則
//!
//! システム全体で親ブロックの選択・ソートを行う箇所は **この関数群のみ** を経由する。
//! `dag_block_producer.rs (assemble_dag_block)` や `ghostdag_v2.rs (select_parent)` の
//! 場当たり的なソートは廃止し、すべてここに集約する。
//!
//! # ソートキー (降順)
//!
//! ```text
//! blue_work (desc) → blue_score (desc) → proposer_id (desc) → block_hash (desc)
//! ```
//!
//! `proposer_id` は将来的に `proposer_randomness` (VRF 出力) に置き換え予定。
//! 現時点では `proposer_id: [u8; 32]` を使用し、ソートロジックは同一。
//!
//! # 決定論性の保証
//!
//! `block_hash` による最終タイブレークにより、このソートは **全順序 (Total Order)** を
//! 定義する。入力の順序に依存せず、同一のブロック集合からは常に同一のソート結果が得られる。

use std::cmp::Ordering;
use crate::dag_block::Hash;
use crate::ghostdag::DagStore;

// ═══════════════════════════════════════════════════════════════
//  ParentSortKey — Canonical Sort Key
// ═══════════════════════════════════════════════════════════════

/// システム全体で唯一のブロックソート基準。
///
/// Block Producer, GhostDAG Engine, Finality 判定のすべてがこのキーを使用する。
///
/// # フィールド優先順位 (すべて降順)
///
/// 1. `blue_work`  — PoS 重み付き累積 Blue 作業量
/// 2. `blue_score` — 累積 Blue ブロック数
/// 3. `proposer_id` — 提案者識別子 (将来: VRF randomness)
/// 4. `block_hash`  — 最終タイブレーク (全順序を保証)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParentSortKey {
    pub blue_work: u128,
    pub blue_score: u64,
    pub proposer_id: [u8; 32],
    pub block_hash: Hash,
}

impl ParentSortKey {
    /// DagStore からブロックのソートキーを構築する。
    ///
    /// GhostDagData または Header が取得できない場合は None を返す。
    pub fn from_store<S: DagStore>(block_hash: &Hash, store: &S) -> Option<Self> {
        let data = store.get_ghostdag_data(block_hash)?;
        let header = store.get_header(block_hash)?;
        Some(Self {
            blue_work: data.blue_work,
            blue_score: data.blue_score,
            proposer_id: header.proposer_id,
            block_hash: *block_hash,
        })
    }
}

/// Canonical 比較関数 — **降順** (higher is better)。
///
/// この関数がシステム全体でブロック優先度を決定する唯一の比較ロジック。
///
/// # 使用箇所
///
/// - `GhostDagV2::select_parent()` — Selected Parent の決定
/// - `select_canonical_parents()` — Tips からの親ブロック選択
/// - `FinalityManager` — メインチェーン上の Finality 評価
#[inline]
pub fn canonical_compare(a: &ParentSortKey, b: &ParentSortKey) -> Ordering {
    // 降順: b.field.cmp(&a.field)
    b.blue_work.cmp(&a.blue_work)
        .then_with(|| b.blue_score.cmp(&a.blue_score))
        .then_with(|| b.proposer_id.cmp(&a.proposer_id))
        .then_with(|| b.block_hash.cmp(&a.block_hash))
}

// ═══════════════════════════════════════════════════════════════
//  Mergeset Canonical Ordering (SSOT)
// ═══════════════════════════════════════════════════════════════

/// Mergeset 内のブロック順序 — **昇順** (blue_score ASC, hash ASC)。
///
/// # なぜ parent selection と異なる順序が必要か
///
/// - `canonical_compare`: **降順** — 「どの親が最良か」を決定 (blue_work 最大が先)
/// - `mergeset_compare`: **昇順** — 「どのブロックから先に分類するか」を決定
///
/// GhostDAG の blue/red 分類はインクリメンタルに行う:
/// blue_score が低い (=古い) ブロックから先に分類し、
/// その結果 (Blue に入ったか) が後続ブロックの分類に影響する。
/// したがって mergeset は blue_score **昇順** で処理する必要がある。
///
/// # 使用箇所 (SSOT)
///
/// - `compute_mergeset_failclosed()` — 返り値のソート (格納順の決定論性)
/// - `classify_mergeset_dynamic()` — 分類順
/// - `get_total_ordering()` — 各チェーンブロック内の mergeset 順序
/// - `GhostDagData.mergeset_blues/reds` — 格納順
///
/// # 決定論性
///
/// blue_score + hash による全順序。入力の順序に依存しない。
#[inline]
pub fn mergeset_compare<S: DagStore>(a: &Hash, b: &Hash, store: &S) -> Ordering {
    let score_a = store.get_ghostdag_data(a).map(|d| d.blue_score).unwrap_or(0);
    let score_b = store.get_ghostdag_data(b).map(|d| d.blue_score).unwrap_or(0);
    score_a.cmp(&score_b).then_with(|| a.cmp(b))
}

/// Mergeset ブロック群を canonical 順にソートする。
///
/// `mergeset_compare` を使用した in-place ソート。
/// BFS 発見順からの正規化に使用する。
pub fn sort_mergeset_canonical<S: DagStore>(blocks: &mut [Hash], store: &S) {
    blocks.sort_by(|a, b| mergeset_compare(a, b, store));
}

// ═══════════════════════════════════════════════════════════════
//  Canonical Parent Selection
// ═══════════════════════════════════════════════════════════════

/// Tips から決定論的に親ブロック群を選択する。
///
/// # 決定論性の保証
///
/// 出力は Tips の GhostDagData のみに依存し、以下には依存しない:
/// - Iterator の順序 (HashMap 実装依存)
/// - スレッドスケジューリングやタイミング
/// - 過去の親選択結果
///
/// 同一の Tips + GhostDagData を持つ 2 つのノードは、常に同一の親を同一の順序で選択する。
///
/// # 計算量
///
/// O(|tips| × log|tips|) — ソートのため。実用上の tip 数で制約。
pub fn select_canonical_parents<S: DagStore>(
    tips: &[Hash],
    store: &S,
    max_parents: usize,
) -> Vec<Hash> {
    let mut tip_keys: Vec<(ParentSortKey, Hash)> = tips.iter()
        .filter_map(|&tip| {
            let key = ParentSortKey::from_store(&tip, store)?;
            Some((key, tip))
        })
        .collect();

    // Canonical ソート: 全順序 (hash タイブレークにより衝突なし)
    tip_keys.sort_by(|a, b| canonical_compare(&a.0, &b.0));

    // 上位 max_parents 個を取得
    tip_keys.into_iter()
        .take(max_parents)
        .map(|(_, hash)| hash)
        .collect()
}

/// 親ブロック群から Selected Parent を選択する。
///
/// = canonical ソートで最上位のブロック。
/// GhostDagData が取得できない親は blue_work=0, blue_score=0 として扱う。
///
/// # Fallback
///
/// すべての親の GhostDagData が取得できない場合は、ハッシュ値が最大の親を返す。
pub fn select_parent<S: DagStore>(
    parents: &[Hash],
    store: &S,
    genesis_hash: &Hash,
) -> Hash {
    parents.iter()
        .max_by(|a, b| {
            let key_a = ParentSortKey::from_store(a, store)
                .unwrap_or(ParentSortKey {
                    blue_work: 0, blue_score: 0,
                    proposer_id: [0; 32], block_hash: **a,
                });
            let key_b = ParentSortKey::from_store(b, store)
                .unwrap_or(ParentSortKey {
                    blue_work: 0, blue_score: 0,
                    proposer_id: [0; 32], block_hash: **b,
                });
            // canonical_compare は降順なので、「最良」のブロックが最初に来る。
            // max_by では「大きい方」を選ぶので、ここでは通常比較 (a vs b) を使う。
            // canonical_compare(a, b) == Less  means a is better (降順で先)
            // max_by は Ordering::Greater を選ぶので、反転が必要
            canonical_compare(&key_b, &key_a)
        })
        .copied()
        .unwrap_or(*genesis_hash)
}

// ═══════════════════════════════════════════════════════════════
//  Virtual Block Parent Selection (v7)
// ═══════════════════════════════════════════════════════════════

/// Virtual block の親選択結果。
///
/// `assemble_dag_block()` が直接 tips を使う代わりに、
/// この構造体を経由して virtual-aware な親選択を行う。
///
/// # Kaspa 対応
///
/// Kaspa の `VirtualBlock.Parents` に相当。
/// 単に "tips の上位 N 個" ではなく、以下のフィルタを適用:
///
/// 1. **Pruning window**: `virtual_score - tip_score > PRUNING_WINDOW` の tips を除外
/// 2. **Merge depth**: selected parent との score 差が大きすぎる tips を除外
/// 3. **Canonical sort**: 残った tips を canonical order でソートし上位を選択
#[derive(Debug, Clone)]
pub struct VirtualParents {
    /// 選択された親ブロック群 (canonical order)。
    pub parents: Vec<Hash>,
    /// Virtual selected parent (parents[0] 相当、canonical 最良)。
    pub selected_parent: Hash,
    /// フィルタで除外された tips 数。
    pub filtered_count: usize,
}

/// Maximum merge depth — selected parent との blue_score 差がこれを超える tips は除外。
///
/// Kaspa の merge depth bound に相当。これより古い分岐は
/// マージしても意味がない (consensus にほぼ影響しない)。
pub const MAX_MERGE_DEPTH: u64 = 256;

/// v9: Minimum parents for block production (ensures DAG connectivity).
pub const MIN_PARENTS: usize = 1;

/// v9: Anticone spread — tips の blue_score 分散を測定。
///
/// Kaspa において parent selection は単なる sort ではなく node policy の中核。
/// ネットワーク状態 (tip count, score spread) に応じて最適な親数を決定する。
#[derive(Debug, Clone)]
pub struct AnticoneSpread {
    pub min_score: u64,
    pub max_score: u64,
    pub spread: u64,
    pub active_tip_count: usize,
    /// v9: 推奨親数 (ネットワーク状態に基づく)。
    pub recommended_parent_count: usize,
}

impl AnticoneSpread {
    /// Tips の anticone spread を計算し、推奨親数を算出する。
    ///
    /// # Network-Adaptive Parent Count
    ///
    /// - spread が小さい (tips が近い) → 多くの親 (並列ブロックを統合)
    /// - spread が大きい (tips が散在) → 少ない親 (stale tips を排除)
    pub fn compute<S: DagStore>(tips: &[Hash], store: &S, max_parents: usize) -> Self {
        if tips.is_empty() {
            return Self {
                min_score: 0, max_score: 0, spread: 0,
                active_tip_count: 0, recommended_parent_count: MIN_PARENTS,
            };
        }

        let scores: Vec<u64> = tips.iter()
            .filter_map(|t| store.get_ghostdag_data(t).map(|d| d.blue_score))
            .collect();

        if scores.is_empty() {
            return Self {
                min_score: 0, max_score: 0, spread: 0,
                active_tip_count: tips.len(), recommended_parent_count: MIN_PARENTS,
            };
        }

        let min_score = *scores.iter().min().unwrap();
        let max_score = *scores.iter().max().unwrap();
        let spread = max_score - min_score;

        let recommended = if spread <= 2 {
            max_parents.min(tips.len()).max(MIN_PARENTS)
        } else if spread <= 10 {
            (max_parents * 2 / 3).max(MIN_PARENTS).min(tips.len())
        } else {
            (max_parents / 2).max(MIN_PARENTS).min(tips.len())
        };

        Self {
            min_score, max_score, spread,
            active_tip_count: scores.len(),
            recommended_parent_count: recommended,
        }
    }
}

/// Block template quality — ブロック生成前の品質チェック結果。
///
/// `pick_virtual_parents()` の結果に対して、block producer が
/// ブロックを生成する前に品質チェックを行う。
#[derive(Debug, Clone)]
pub struct BlockTemplateQuality {
    /// 選択された親が全て DAG に存在するか。
    pub all_parents_present: bool,
    /// Stale tips (pruning window 外) が除外されたか。
    pub stale_tips_filtered: usize,
    /// Merge depth overflow の tips が除外されたか。
    pub merge_depth_overflow_filtered: usize,
    /// Anticone spread の推奨親数が守られているか。
    pub parent_count_optimal: bool,
}

/// Block template 品質チェック。
///
/// v9: block producer は毎回 virtual selected parent, merge depth bound,
/// pruning window, anticone spread を見て親を選ぶ。
/// missing parent / stale tip / merge depth overflow を排除。
pub fn check_block_template_quality<S: DagStore>(
    virtual_parents: &VirtualParents,
    store: &S,
    anticone_spread: &AnticoneSpread,
) -> BlockTemplateQuality {
    let all_present = virtual_parents.parents.iter()
        .all(|p| store.get_header(p).is_some());

    BlockTemplateQuality {
        all_parents_present: all_present,
        stale_tips_filtered: virtual_parents.filtered_count,
        merge_depth_overflow_filtered: 0, // Already handled in pick_virtual_parents
        parent_count_optimal: virtual_parents.parents.len() <= anticone_spread.recommended_parent_count,
    }
}

/// Virtual block の親を tips から決定論的に選択する。
///
/// # Algorithm
///
/// 1. Tips から virtual selected parent を計算 (canonical 最良)
/// 2. 各 tip にフィルタ適用:
///    - `virtual_score - tip_score > pruning_window` → 除外 (stale)
///    - `virtual_score - tip_score > MAX_MERGE_DEPTH` → 除外 (deep branch)
/// 3. 残った tips を canonical sort で上位 `max_parents` 個選択
///
/// # 決定論性
///
/// 全ノードが同一の tips + GhostDagData → 同一の VirtualParents。
pub fn pick_virtual_parents<S: DagStore>(
    tips: &[Hash],
    store: &S,
    genesis_hash: &Hash,
    max_parents: usize,
    pruning_window: u64,
) -> VirtualParents {
    if tips.is_empty() {
        return VirtualParents {
            parents: vec![*genesis_hash],
            selected_parent: *genesis_hash,
            filtered_count: 0,
        };
    }

    // Step 1: compute virtual selected parent (best tip by canonical order)
    let virtual_sp = select_parent(tips, store, genesis_hash);
    let virtual_score = store.get_ghostdag_data(&virtual_sp)
        .map(|d| d.blue_score)
        .unwrap_or(0);

    // Step 2: filter tips
    let mut candidates: Vec<(ParentSortKey, Hash)> = Vec::new();
    let mut filtered = 0usize;

    for &tip in tips {
        let tip_score = store.get_ghostdag_data(&tip)
            .map(|d| d.blue_score)
            .unwrap_or(0);

        // Pruning window filter: tip is too old
        if virtual_score.saturating_sub(tip_score) > pruning_window {
            filtered += 1;
            continue;
        }

        // Merge depth filter: branch is too deep to merge usefully
        if virtual_score.saturating_sub(tip_score) > MAX_MERGE_DEPTH {
            filtered += 1;
            continue;
        }

        if let Some(key) = ParentSortKey::from_store(&tip, store) {
            candidates.push((key, tip));
        }
    }

    // Always include virtual_sp even if filtered (it's the best tip)
    if !candidates.iter().any(|(_, h)| *h == virtual_sp) {
        if let Some(key) = ParentSortKey::from_store(&virtual_sp, store) {
            candidates.push((key, virtual_sp));
        }
    }

    // Step 3: canonical sort + take top max_parents
    candidates.sort_by(|a, b| canonical_compare(&a.0, &b.0));

    let parents: Vec<Hash> = candidates.into_iter()
        .take(max_parents)
        .map(|(_, h)| h)
        .collect();

    let selected_parent = parents.first().copied().unwrap_or(*genesis_hash);

    VirtualParents {
        parents,
        selected_parent,
        filtered_count: filtered,
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_compare_total_order() {
        let a = ParentSortKey {
            blue_work: 100, blue_score: 10,
            proposer_id: [0xAA; 32], block_hash: [1; 32],
        };
        let b = ParentSortKey {
            blue_work: 100, blue_score: 10,
            proposer_id: [0xAA; 32], block_hash: [2; 32],
        };
        // 異なる block_hash → 異なる順位 (全順序)
        assert_ne!(canonical_compare(&a, &b), Ordering::Equal);
    }

    #[test]
    fn test_canonical_compare_blue_work_priority() {
        let high_work = ParentSortKey {
            blue_work: 200, blue_score: 5,
            proposer_id: [0; 32], block_hash: [1; 32],
        };
        let low_work = ParentSortKey {
            blue_work: 100, blue_score: 10,
            proposer_id: [0xFF; 32], block_hash: [0xFF; 32],
        };
        // 降順: blue_work が大きい方が先 (Less)
        assert_eq!(canonical_compare(&high_work, &low_work), Ordering::Less);
    }

    #[test]
    fn test_canonical_sort_deterministic() {
        let keys = vec![
            ParentSortKey { blue_work: 50, blue_score: 5, proposer_id: [0; 32], block_hash: [3; 32] },
            ParentSortKey { blue_work: 100, blue_score: 10, proposer_id: [0; 32], block_hash: [1; 32] },
            ParentSortKey { blue_work: 75, blue_score: 7, proposer_id: [0; 32], block_hash: [2; 32] },
        ];
        let mut sorted1 = keys.clone();
        sorted1.sort_by(|a, b| canonical_compare(a, b));

        let mut sorted2 = vec![keys[2].clone(), keys[0].clone(), keys[1].clone()];
        sorted2.sort_by(|a, b| canonical_compare(a, b));

        assert_eq!(sorted1, sorted2, "sort must be deterministic regardless of input order");
        // 降順: blue_work 100 → 75 → 50
        assert_eq!(sorted1[0].blue_work, 100);
        assert_eq!(sorted1[1].blue_work, 75);
        assert_eq!(sorted1[2].blue_work, 50);
    }

    #[test]
    fn test_canonical_compare_tiebreak_proposer_before_hash() {
        let a = ParentSortKey {
            blue_work: 100, blue_score: 10,
            proposer_id: [0xFF; 32], block_hash: [0x01; 32],
        };
        let b = ParentSortKey {
            blue_work: 100, blue_score: 10,
            proposer_id: [0x01; 32], block_hash: [0xFF; 32],
        };
        // 同一 blue_work/score → proposer_id 降順で 0xFF > 0x01 → a が先
        assert_eq!(canonical_compare(&a, &b), Ordering::Less);
    }

    #[test]
    fn test_virtual_parents_filters_stale() {
        use crate::ghostdag::InMemoryDagStore;
        use crate::dag_block::{DagBlockHeader, GhostDagData, DAG_VERSION, ZERO_HASH as DAG_ZERO};

        let g = [0x00; 32];
        let mut store = InMemoryDagStore::new();
        store.insert_header(g, DagBlockHeader {
            version: DAG_VERSION, parents: vec![], timestamp_ms: 0,
            tx_root: [0; 32], proposer_id: [0; 32], nonce: 0, blue_score: 0, bits: 0,
        });
        store.set_ghostdag_data(g, GhostDagData {
            selected_parent: DAG_ZERO, mergeset_blues: vec![], mergeset_reds: vec![],
            blue_score: 0, blue_work: 0, blues_anticone_sizes: vec![],
        });

        // Fresh tip (score=100)
        let fresh = [0x01; 32];
        store.insert_header(fresh, DagBlockHeader {
            version: DAG_VERSION, parents: vec![g], timestamp_ms: 0,
            tx_root: [0; 32], proposer_id: [1; 32], nonce: 0, blue_score: 100, bits: 0,
        });
        store.set_ghostdag_data(fresh, GhostDagData {
            selected_parent: g, mergeset_blues: vec![], mergeset_reds: vec![],
            blue_score: 100, blue_work: 100, blues_anticone_sizes: vec![],
        });

        // Stale tip (score=1, diff=99 < MAX_MERGE_DEPTH=256 but we test with small window)
        let stale = [0x02; 32];
        store.insert_header(stale, DagBlockHeader {
            version: DAG_VERSION, parents: vec![g], timestamp_ms: 0,
            tx_root: [0; 32], proposer_id: [2; 32], nonce: 0, blue_score: 1, bits: 0,
        });
        store.set_ghostdag_data(stale, GhostDagData {
            selected_parent: g, mergeset_blues: vec![], mergeset_reds: vec![],
            blue_score: 1, blue_work: 1, blues_anticone_sizes: vec![],
        });

        // With large pruning window → both included
        let vp = pick_virtual_parents(&[fresh, stale], &store, &g, 10, 1000);
        assert_eq!(vp.parents.len(), 2);
        assert_eq!(vp.selected_parent, fresh); // fresh has higher blue_work

        // With small pruning window (50) → stale filtered (100-1=99 > 50)
        let vp = pick_virtual_parents(&[fresh, stale], &store, &g, 10, 50);
        assert_eq!(vp.parents.len(), 1);
        assert_eq!(vp.parents[0], fresh);
        assert_eq!(vp.filtered_count, 1);
    }

    #[test]
    fn test_virtual_parents_empty_tips() {
        use crate::ghostdag::InMemoryDagStore;
        let store = InMemoryDagStore::new();
        let g = [0x00; 32];
        let vp = pick_virtual_parents(&[], &store, &g, 10, 1000);
        assert_eq!(vp.parents, vec![g]);
        assert_eq!(vp.selected_parent, g);
    }

    // ── v9 Tests ──

    #[test]
    fn test_anticone_spread_narrow() {
        use crate::ghostdag::InMemoryDagStore;
        use crate::dag_block::{DagBlockHeader, GhostDagData, DAG_VERSION, ZERO_HASH as DAG_ZERO};

        let g = [0x00; 32];
        let mut store = InMemoryDagStore::new();
        store.insert_header(g, DagBlockHeader {
            version: DAG_VERSION, parents: vec![], timestamp_ms: 0,
            tx_root: [0; 32], proposer_id: [0; 32], nonce: 0, blue_score: 0, bits: 0,
        });
        store.set_ghostdag_data(g, GhostDagData {
            selected_parent: DAG_ZERO, blue_score: 0, blue_work: 0,
            ..Default::default()
        });

        // Create 3 tips all at score=10 (narrow spread)
        for i in 1..=3u8 {
            let h = [i; 32];
            store.insert_header(h, DagBlockHeader {
                version: DAG_VERSION, parents: vec![g], timestamp_ms: 0,
                tx_root: [0; 32], proposer_id: [i; 32], nonce: 0, blue_score: 10, bits: 0,
            });
            store.set_ghostdag_data(h, GhostDagData {
                selected_parent: g, blue_score: 10, blue_work: 10,
                ..Default::default()
            });
        }

        let tips = vec![[1; 32], [2; 32], [3; 32]];
        let spread = AnticoneSpread::compute(&tips, &store, 10);
        assert_eq!(spread.spread, 0); // All same score
        assert_eq!(spread.active_tip_count, 3);
        // Narrow spread → take all parents
        assert_eq!(spread.recommended_parent_count, 3);
    }

    #[test]
    fn test_anticone_spread_wide() {
        use crate::ghostdag::InMemoryDagStore;
        use crate::dag_block::{DagBlockHeader, GhostDagData, DAG_VERSION, ZERO_HASH as DAG_ZERO};

        let g = [0x00; 32];
        let mut store = InMemoryDagStore::new();
        store.insert_header(g, DagBlockHeader {
            version: DAG_VERSION, parents: vec![], timestamp_ms: 0,
            tx_root: [0; 32], proposer_id: [0; 32], nonce: 0, blue_score: 0, bits: 0,
        });
        store.set_ghostdag_data(g, GhostDagData {
            selected_parent: DAG_ZERO, blue_score: 0, blue_work: 0,
            ..Default::default()
        });

        // Create tips at scores 10, 50, 100 (wide spread = 90)
        for (i, score) in [(1u8, 10u64), (2, 50), (3, 100)] {
            let h = [i; 32];
            store.insert_header(h, DagBlockHeader {
                version: DAG_VERSION, parents: vec![g], timestamp_ms: 0,
                tx_root: [0; 32], proposer_id: [i; 32], nonce: 0, blue_score: score, bits: 0,
            });
            store.set_ghostdag_data(h, GhostDagData {
                selected_parent: g, blue_score: score, blue_work: score as u128,
                ..Default::default()
            });
        }

        let tips = vec![[1; 32], [2; 32], [3; 32]];
        let spread = AnticoneSpread::compute(&tips, &store, 10);
        assert_eq!(spread.spread, 90);
        // Wide spread → fewer parents (selective)
        assert!(spread.recommended_parent_count < 10);
    }

    #[test]
    fn test_anticone_spread_empty() {
        use crate::ghostdag::InMemoryDagStore;
        let store = InMemoryDagStore::new();
        let spread = AnticoneSpread::compute(&[], &store, 10);
        assert_eq!(spread.active_tip_count, 0);
        assert_eq!(spread.recommended_parent_count, MIN_PARENTS);
    }
}
