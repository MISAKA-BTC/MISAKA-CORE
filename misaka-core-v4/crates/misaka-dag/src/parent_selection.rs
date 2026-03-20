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
/// - `GhostDagV2::classify_mergeset()` — Mergeset 内のソート
#[inline]
pub fn canonical_compare(a: &ParentSortKey, b: &ParentSortKey) -> Ordering {
    // 降順: b.field.cmp(&a.field)
    b.blue_work.cmp(&a.blue_work)
        .then_with(|| b.blue_score.cmp(&a.blue_score))
        .then_with(|| b.proposer_id.cmp(&a.proposer_id))
        .then_with(|| b.block_hash.cmp(&a.block_hash))
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
}
