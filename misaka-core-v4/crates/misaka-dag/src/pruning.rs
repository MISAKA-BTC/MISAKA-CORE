//! Pruning Point — Kaspa 準拠の安全な DAG Pruning (Task 3.2)
//!
//! # 課題
//!
//! 単純な `blue_score` 閾値による Pruning は、必要なサイドブランチや
//! 未確定のトランザクションまで消し去る危険がある。
//!
//! # Kaspa の Pruning Point 概念
//!
//! Pruning Point とは、以下の条件を満たすブロック P:
//!
//! 1. **Finality 確定**: P の `blue_score` が十分に古い
//!    (`max_score - P.blue_score >= PRUNING_DEPTH`)
//! 2. **Anticone 凍結**: P より前のブロックの Anticone がこれ以上変化しない
//!    (= 新しいブロックが P の Past に影響を与え得ない)
//! 3. **Selected Parent Chain 上**: P は現在のメインチェーン上にある
//!
//! # 安全な Pruning
//!
//! Pruning は「Pruning Point P から Reachability グラフ上で到達不可能になった
//! 過去のブロック」のみをパージする。具体的には:
//!
//! - P の Past のうち、P の Selected Parent Chain をさらに遡った
//!   旧 Pruning Point 以前のブロックのみを削除
//! - P 自体、および P から到達可能なブロックは決して削除しない
//! - Key Image データは永久保持 (二重支払い防止)
//!
//! # 実装
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  Phase 1: Pruning Point 決定                                │
//! │   → Selected Parent Chain 上で blue_score < threshold の     │
//! │     最新ブロックを Pruning Point とする                      │
//! │                                                              │
//! │  Phase 2: 安全なパージ                                      │
//! │   → Pruning Point より前で、かつ Reachability Index 上で     │
//! │     Pruning Point の strict ancestor であるブロックを削除    │
//! │   → Header と GhostDagData は保持 (Total Order 計算に必要)   │
//! │   → TX データのみ削除                                       │
//! └─────────────────────────────────────────────────────────────┘
//! ```

use crate::dag_block::Hash;
use crate::ghostdag::DagStore;
use crate::reachability::ReachabilityStore;
use tracing::info;

// ═══════════════════════════════════════════════════════════════
//  Pruning 定数 — SSOT (constants.rs) からインポート
// ═══════════════════════════════════════════════════════════════

pub use crate::constants::{PRUNING_POINT_UPDATE_INTERVAL};

/// Pruning Point の最小深度 — PRUNING_DEPTH と同義 (SSOT)。
pub use crate::constants::PRUNING_DEPTH as PRUNING_POINT_MIN_DEPTH;

// ═══════════════════════════════════════════════════════════════
//  Pruning Point
// ═══════════════════════════════════════════════════════════════

/// Pruning Point — DAG Pruning の安全な基準点。
///
/// この構造体は「これ以前のブロックの anticone が凍結されており、
/// TX データを安全に削除できる」ことが数学的に保証されたブロックを表す。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PruningPoint {
    /// Pruning Point のブロックハッシュ。
    /// Selected Parent Chain 上のブロックである必要がある。
    pub block_hash: Hash,

    /// このブロックの blue_score。
    pub blue_score: u64,
}

// ═══════════════════════════════════════════════════════════════
//  Pruning Manager
// ═══════════════════════════════════════════════════════════════

/// Kaspa 準拠の Pruning Point 管理と安全な DAG Pruning。
pub struct PruningManager {
    /// 現在の Pruning Point。
    current_pruning_point: Option<PruningPoint>,
}

impl PruningManager {
    pub fn new() -> Self {
        Self { current_pruning_point: None }
    }

    /// 既存の Pruning Point から復元する。
    pub fn with_pruning_point(mut self, pp: PruningPoint) -> Self {
        self.current_pruning_point = Some(pp);
        self
    }

    /// 現在の Pruning Point を取得する。
    pub fn pruning_point(&self) -> Option<&PruningPoint> {
        self.current_pruning_point.as_ref()
    }

    /// Pruning Point を更新すべきか判定する。
    pub fn should_update(&self, current_max_score: u64) -> bool {
        match &self.current_pruning_point {
            None => current_max_score >= PRUNING_POINT_MIN_DEPTH,
            Some(pp) => {
                current_max_score >= pp.blue_score + PRUNING_POINT_UPDATE_INTERVAL
            }
        }
    }

    /// 新しい Pruning Point を Selected Parent Chain 上で決定する。
    ///
    /// # アルゴリズム
    ///
    /// 1. 現在の DAG Tips の中から canonical sort で最上位のブロックを取得
    /// 2. そのブロックから Selected Parent Chain を遡る
    /// 3. `blue_score <= max_score - PRUNING_POINT_MIN_DEPTH` を満たす
    ///    最初のブロックを新しい Pruning Point とする
    ///
    /// # 安全性
    ///
    /// Pruning Point は必ず Selected Parent Chain 上にあるため、
    /// メインチェーンの整合性を破壊しない。
    pub fn find_new_pruning_point<S: DagStore>(
        &self,
        current_max_score: u64,
        store: &S,
    ) -> Option<PruningPoint> {
        let threshold = current_max_score.saturating_sub(PRUNING_POINT_MIN_DEPTH);

        // Tips から canonical sort で最上位のブロックを取得 (SSOT)
        let tips = store.get_tips();
        if tips.is_empty() {
            return None;
        }

        // Canonical sort (blue_work → blue_score → proposer_id → hash)
        // により全ノードで同一の virtual tip が選択される。
        // 旧コードの max_by_key(blue_score) は blue_score タイで非決定論的だった。
        let virtual_tip = crate::parent_selection::select_parent(
            &tips,
            store,
            &crate::dag_block::ZERO_HASH,
        );

        // Selected Parent Chain を遡る
        let mut current = virtual_tip;
        loop {
            let data = store.get_ghostdag_data(&current)?;

            if data.blue_score <= threshold {
                // この深さに到達 → Pruning Point
                return Some(PruningPoint {
                    block_hash: current,
                    blue_score: data.blue_score,
                });
            }

            if data.selected_parent == crate::dag_block::ZERO_HASH {
                break; // Genesis に到達
            }
            current = data.selected_parent;
        }

        None
    }

    /// Pruning Point を更新する。
    pub fn update_pruning_point<S: DagStore>(
        &mut self,
        current_max_score: u64,
        store: &S,
    ) -> Option<PruningPoint> {
        if !self.should_update(current_max_score) {
            return None;
        }

        let new_pp = self.find_new_pruning_point(current_max_score, store)?;

        info!(
            "Pruning Point updated: block={}, blue_score={}",
            hex::encode(&new_pp.block_hash[..4]),
            new_pp.blue_score,
        );

        self.current_pruning_point = Some(new_pp.clone());
        Some(new_pp)
    }

    /// Pruning Point から Reachability 上で到達不可能になったブロックを列挙する。
    ///
    /// # Kaspa 準拠の安全な Pruning
    ///
    /// 削除対象は以下の条件を **全て** 満たすブロック:
    ///
    /// 1. Pruning Point の strict ancestor である
    ///    (`reachability.is_dag_ancestor_of(block, pruning_point)` が true)
    /// 2. Genesis ブロックではない
    ///
    /// 削除内容:
    /// - TX データのみ削除 (Header と GhostDagData は保持)
    /// - Key Image データは永久保持
    pub fn collect_prunable_blocks(
        &self,
        reachability: &ReachabilityStore,
        store: &dyn DagStore,
    ) -> Vec<Hash> {
        let pp = match &self.current_pruning_point {
            Some(pp) => pp,
            None => return vec![],
        };

        let genesis = reachability.genesis();

        store.all_hashes()
            .into_iter()
            .filter(|hash| {
                // Genesis は削除しない
                if *hash == genesis || *hash == pp.block_hash {
                    return false;
                }
                // Pruning Point の strict ancestor のみ削除対象
                reachability.is_dag_ancestor_of(hash, &pp.block_hash)
            })
            .collect()
    }

    /// Reachability Store から Pruning Point 以前のノードを安全にパージする。
    ///
    /// # 戻り値
    ///
    /// パージされたブロック数。
    pub fn prune_reachability(
        &self,
        reachability: &mut ReachabilityStore,
    ) -> usize {
        match &self.current_pruning_point {
            Some(pp) => reachability.prune_below(&pp.block_hash),
            None => 0,
        }
    }
}

impl Default for PruningManager {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghostdag::InMemoryDagStore;
    use crate::dag_block::{DagBlockHeader, GhostDagData, DAG_VERSION, ZERO_HASH};
    use crate::reachability::ReachabilityStore;

    fn make_header(parents: Vec<Hash>) -> DagBlockHeader {
        DagBlockHeader {
            version: DAG_VERSION, parents, timestamp_ms: 0, tx_root: [0; 32],
            proposer_id: [0; 32], nonce: 0, blue_score: 0, bits: 0,
        }
    }

    #[test]
    fn test_pruning_point_not_set_initially() {
        let pm = PruningManager::new();
        assert!(pm.pruning_point().is_none());
    }

    #[test]
    fn test_should_update_when_deep_enough() {
        let pm = PruningManager::new();
        assert!(!pm.should_update(100));
        assert!(!pm.should_update(500));
        assert!(pm.should_update(PRUNING_POINT_MIN_DEPTH));
        assert!(pm.should_update(PRUNING_POINT_MIN_DEPTH + 100));
    }

    #[test]
    fn test_find_pruning_point_on_chain() {
        let mut store = InMemoryDagStore::new();
        let g = [0x00; 32];

        store.insert_header(g, make_header(vec![]));
        store.set_ghostdag_data(g, GhostDagData {
            selected_parent: ZERO_HASH, mergeset_blues: vec![], mergeset_reds: vec![],
            blue_score: 0, blue_work: 0,
            blues_anticone_sizes: vec![],
        });

        // Build a chain of 1200 blocks (needs > PRUNING_POINT_MIN_DEPTH=1000)
        let mut prev = g;
        for i in 1..=1200u32 {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&i.to_le_bytes());
            store.insert_header(h, make_header(vec![prev]));
            store.set_ghostdag_data(h, GhostDagData {
                selected_parent: prev, mergeset_blues: vec![], mergeset_reds: vec![],
                blue_score: i as u64, blue_work: i as u128,
                blues_anticone_sizes: vec![],
            });
            prev = h;
        }

        let pm = PruningManager::new();
        let pp = pm.find_new_pruning_point(1200, &store);
        assert!(pp.is_some());
        let pp = pp.unwrap();
        // Pruning point should be at blue_score <= 1200 - 1000 = 200
        assert!(pp.blue_score <= 200,
            "pruning point blue_score {} should be <= 200", pp.blue_score);
    }

    #[test]
    fn test_collect_prunable_blocks_respects_reachability() {
        let mut store = InMemoryDagStore::new();
        let mut reach = ReachabilityStore::new([0; 32]);

        let g = [0x00; 32];
        let a = [0x0A; 32];
        let b = [0x0B; 32];

        store.insert_header(g, make_header(vec![]));
        store.set_ghostdag_data(g, GhostDagData {
            selected_parent: ZERO_HASH, mergeset_blues: vec![], mergeset_reds: vec![],
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

        store.insert_header(b, make_header(vec![a]));
        reach.add_child(a, b).unwrap();
        store.set_ghostdag_data(b, GhostDagData {
            selected_parent: a, mergeset_blues: vec![], mergeset_reds: vec![],
            blue_score: 2, blue_work: 2,
            blues_anticone_sizes: vec![],
        });

        let pm = PruningManager::new().with_pruning_point(PruningPoint {
            block_hash: b,
            blue_score: 2,
        });

        let prunable = pm.collect_prunable_blocks(&reach, &store);
        // G and A are strict ancestors of B → prunable
        // B itself is the pruning point → not prunable
        assert!(prunable.contains(&a), "A should be prunable (strict ancestor of PP)");
        // Genesis should NOT be prunable (genesis exclusion)
        assert!(!prunable.contains(&g), "Genesis should not be prunable");
        assert!(!prunable.contains(&b), "Pruning point itself should not be prunable");
    }
}
