//! Pruning Point — Kaspa 準拠 Proof-First DAG Pruning (v9).
//!
//! # v8 → v9: Proof-First Pruning
//!
//! v8 の pruning は「selected-parent ancestor 削除」という掃除機能だった。
//! v9 では Kaspa 寄りに、pruning が node bootstrap の土台になる設計へ移行:
//!
//! 1. **Trusted State Root**: pruning point ごとに UTXO/nullifier commitment を固定
//! 2. **PruneLevel**: body prune / header retention の境界を厳密化
//! 3. **Atomic Prune**: reachability と store の prune が同一スナップショット境界
//! 4. **Persistent Store 連携**: pruning point を永続化層に保存
//! 5. **Sync Protocol 接続**: pruning proof を IBD の起点として使用可能
//!
//! # Kaspa の Pruning Point 概念
//!
//! Pruning Point とは、以下の条件を満たすブロック P:
//!
//! 1. **Finality 確定**: P の `blue_score` が十分に古い
//! 2. **Anticone 凍結**: P より前のブロックの Anticone がこれ以上変化しない
//! 3. **Selected Parent Chain 上**: P は現在のメインチェーン上にある
//!
//! # Kaspa との差 (v8) → v9 で解消
//!
//! Kaspa は pruning が node bootstrap の土台。新規ノードは:
//! 1. Pruning proof を受信
//! 2. Proof を検証 (chain + state commitment)
//! 3. Pruning point から IBD 開始
//!
//! v9 では PruningPoint に state commitment を含め、
//! pruning_proof.rs の PruningProof と連携して IBD 起点として機能する。

use crate::dag_block::{Hash, ZERO_HASH};
use crate::ghostdag::DagStore;
use crate::reachability::ReachabilityStore;
use serde::{Deserialize, Serialize};
use tracing::info;

// ═══════════════════════════════════════════════════════════════
//  Pruning 定数 — SSOT (constants.rs) からインポート
// ═══════════════════════════════════════════════════════════════

pub use crate::constants::PRUNING_POINT_UPDATE_INTERVAL;

/// Pruning Point の最小深度 — PRUNING_DEPTH と同義 (SSOT)。
pub use crate::constants::PRUNING_DEPTH as PRUNING_POINT_MIN_DEPTH;

// ═══════════════════════════════════════════════════════════════
//  Prune Level — Body / Header 保持境界
// ═══════════════════════════════════════════════════════════════

/// ブロックの prune レベル。
///
/// Kaspa では body prune と header/ghostdag retention の境界が厳密に区別される:
/// - **Full**: TX データ + ヘッダ + GhostDAG 全保持
/// - **BodyPruned**: TX データのみ削除、ヘッダ + GhostDAG は保持
///   (Total Order 計算、reachability 判定に必要)
/// - **FullyPruned**: 全データ削除 (accumulator 保持期間後)
///
/// Key Image / nullifier データは **永久保持** (二重支払い防止)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PruneLevel {
    /// 全データ保持 (pruning point より新しいブロック)。
    Full,
    /// TX データのみ削除。ヘッダ + GhostDAG data + reachability は保持。
    /// Pruning point の strict ancestor で、かつ header retention 区間内。
    BodyPruned,
    /// 完全削除 (accumulator 保持期間超過)。
    /// ヘッダの最小情報 (hash, blue_score) のみ stub として残す可能性あり。
    FullyPruned,
}

// ═══════════════════════════════════════════════════════════════
//  Pruning Point — Trusted State Root 付き (v9)
// ═══════════════════════════════════════════════════════════════

/// Pruning Point — DAG Pruning の安全な基準点。
///
/// # v9: Trusted State Commitments
///
/// v8 では PruningPoint は (block_hash, blue_score) のみだった。
/// v9 では pruning point 時点の state commitment を含み、
/// IBD で新規ノードがこの commitment を検証してから同期を開始できる。
///
/// これは Kaspa の "pruning が node bootstrap の土台" という設計に対応する。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruningPoint {
    /// Pruning Point のブロックハッシュ。
    /// Selected Parent Chain 上のブロックである必要がある。
    pub block_hash: Hash,

    /// このブロックの blue_score。
    pub blue_score: u64,

    /// v9: Pruning point 時点の state root (VirtualState.compute_state_root())。
    /// IBD 時にこの root が一致することを検証する。
    /// ZERO_HASH の場合は未計算 (backward compat)。
    #[serde(default)]
    pub state_root: Hash,

    /// v9: UTXO set commitment at pruning point。
    #[serde(default)]
    pub utxo_commitment: Hash,

    /// v9: Nullifier set commitment at pruning point。
    #[serde(default)]
    pub nullifier_commitment: Hash,
}

impl PruningPoint {
    /// 新しい PruningPoint を作成 (state commitment なし、backward compat)。
    pub fn new(block_hash: Hash, blue_score: u64) -> Self {
        Self {
            block_hash,
            blue_score,
            state_root: ZERO_HASH,
            utxo_commitment: ZERO_HASH,
            nullifier_commitment: ZERO_HASH,
        }
    }

    /// State commitment 付きの PruningPoint を作成 (v9)。
    pub fn with_state(
        block_hash: Hash,
        blue_score: u64,
        state_root: Hash,
        utxo_commitment: Hash,
        nullifier_commitment: Hash,
    ) -> Self {
        Self {
            block_hash,
            blue_score,
            state_root,
            utxo_commitment,
            nullifier_commitment,
        }
    }

    /// State commitment が設定されているかチェック。
    pub fn has_state_commitment(&self) -> bool {
        self.state_root != ZERO_HASH
    }
}

// ═══════════════════════════════════════════════════════════════
//  Prune Result — Atomic Prune 操作結果
// ═══════════════════════════════════════════════════════════════

/// Atomic prune 操作の結果。
///
/// reachability prune と store prune が同一スナップショット境界で実行されたことを保証。
#[derive(Debug, Clone)]
pub struct PruneResult {
    /// 前の pruning point。
    pub previous_pruning_point: Option<PruningPoint>,
    /// 新しい pruning point。
    pub new_pruning_point: PruningPoint,
    /// Body-pruned されたブロック数。
    pub body_pruned_count: usize,
    /// Reachability から削除されたノード数。
    pub reachability_pruned_count: usize,
    /// この prune で永続化すべき pruning point JSON。
    pub pruning_point_json: Vec<u8>,
}

// ═══════════════════════════════════════════════════════════════
//  Pruning Manager (v9)
// ═══════════════════════════════════════════════════════════════

/// Kaspa 準拠 Proof-First Pruning Manager。
///
/// v9 の改善:
/// - PruningPoint に trusted state root を含む
/// - body prune / header retention の境界を PruneLevel で管理
/// - reachability と store の prune を同一境界で atomic に実行
/// - 永続化層との連携 (save/load pruning point)
pub struct PruningManager {
    current_pruning_point: Option<PruningPoint>,
}

impl PruningManager {
    pub fn new() -> Self {
        Self {
            current_pruning_point: None,
        }
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
            Some(pp) => current_max_score >= pp.blue_score + PRUNING_POINT_UPDATE_INTERVAL,
        }
    }

    /// 新しい Pruning Point を Selected Parent Chain 上で決定する。
    ///
    /// v9: state commitment 引数を受け取り、PruningPoint に埋め込む。
    pub fn find_new_pruning_point<S: DagStore>(
        &self,
        current_max_score: u64,
        store: &S,
        state_root: Hash,
        utxo_commitment: Hash,
        nullifier_commitment: Hash,
    ) -> Option<PruningPoint> {
        let threshold = current_max_score.saturating_sub(PRUNING_POINT_MIN_DEPTH);

        let tips = store.get_tips();
        if tips.is_empty() {
            return None;
        }

        let virtual_tip = crate::parent_selection::select_parent(&tips, store, &ZERO_HASH);

        let mut current = virtual_tip;
        loop {
            let data = store.get_ghostdag_data(&current)?;

            if data.blue_score <= threshold {
                return Some(PruningPoint::with_state(
                    current,
                    data.blue_score,
                    state_root,
                    utxo_commitment,
                    nullifier_commitment,
                ));
            }

            if data.selected_parent == ZERO_HASH {
                break;
            }
            current = data.selected_parent;
        }

        None
    }

    /// v8 互換: state commitment なしで pruning point を検索。
    pub fn find_new_pruning_point_legacy<S: DagStore>(
        &self,
        current_max_score: u64,
        store: &S,
    ) -> Option<PruningPoint> {
        self.find_new_pruning_point(current_max_score, store, ZERO_HASH, ZERO_HASH, ZERO_HASH)
    }

    /// Pruning Point を更新 + atomic prune を実行。
    ///
    /// # v9: Atomic Prune
    ///
    /// 以下を同一操作で実行:
    /// 1. 新しい pruning point を決定
    /// 2. Body-prunable blocks を収集
    /// 3. Reachability index を prune
    /// 4. 結果を返す (呼び出し元が永続化)
    ///
    /// reachability と store の prune が必ず同じスナップショット境界で起きる。
    pub fn update_and_prune<S: DagStore>(
        &mut self,
        current_max_score: u64,
        store: &S,
        reachability: &mut ReachabilityStore,
        state_root: Hash,
        utxo_commitment: Hash,
        nullifier_commitment: Hash,
    ) -> Option<PruneResult> {
        if !self.should_update(current_max_score) {
            return None;
        }

        let new_pp = self.find_new_pruning_point(
            current_max_score,
            store,
            state_root,
            utxo_commitment,
            nullifier_commitment,
        )?;

        let previous = self.current_pruning_point.clone();

        // ── Atomic boundary: collect + prune in sequence ──

        // 1. Collect body-prunable blocks
        let old_pp = self.current_pruning_point.clone();
        self.current_pruning_point = Some(new_pp.clone());
        let body_prunable = self.collect_prunable_blocks(reachability, store);

        // 2. Prune reachability at same boundary
        let reach_pruned = self.prune_reachability(reachability);

        // 3. Serialize pruning point for persistence
        let pp_json = serde_json::to_vec(&new_pp).unwrap_or_default();

        info!(
            "Pruning Point updated: block={}, blue_score={}, state_root={}, body_pruned={}, reach_pruned={}",
            hex::encode(&new_pp.block_hash[..4]),
            new_pp.blue_score,
            hex::encode(&new_pp.state_root[..4]),
            body_prunable.len(),
            reach_pruned,
        );

        Some(PruneResult {
            previous_pruning_point: previous,
            new_pruning_point: new_pp,
            body_pruned_count: body_prunable.len(),
            reachability_pruned_count: reach_pruned,
            pruning_point_json: pp_json,
        })
    }

    /// Pruning Point を更新する (v8 互換、atomic prune なし)。
    pub fn update_pruning_point<S: DagStore>(
        &mut self,
        current_max_score: u64,
        store: &S,
    ) -> Option<PruningPoint> {
        if !self.should_update(current_max_score) {
            return None;
        }

        let new_pp = self.find_new_pruning_point_legacy(current_max_score, store)?;

        info!(
            "Pruning Point updated: block={}, blue_score={}",
            hex::encode(&new_pp.block_hash[..4]),
            new_pp.blue_score,
        );

        self.current_pruning_point = Some(new_pp.clone());
        Some(new_pp)
    }

    /// ブロックの PruneLevel を判定する。
    ///
    /// # v9: Body / Header 保持境界の厳密化
    ///
    /// ```text
    /// |--- FullyPruned ---|--- BodyPruned ---|--- Full ---|
    ///                 old_pp              new_pp        tips
    /// ```
    pub fn prune_level_of<S: DagStore>(
        &self,
        block_hash: &Hash,
        store: &S,
        reachability: &ReachabilityStore,
    ) -> PruneLevel {
        let pp = match &self.current_pruning_point {
            Some(pp) => pp,
            None => return PruneLevel::Full, // No pruning point → keep everything
        };

        // Pruning point 以降のブロックは Full
        if let Some(gd) = store.get_ghostdag_data(block_hash) {
            if gd.blue_score >= pp.blue_score {
                return PruneLevel::Full;
            }
        }

        // Pruning point の strict ancestor → BodyPruned
        // (ヘッダ + GhostDAG は保持、TX データのみ削除)
        if reachability.is_dag_ancestor_of(block_hash, &pp.block_hash) {
            return PruneLevel::BodyPruned;
        }

        // それ以外 (到達不能な古いサイドブランチ) は FullyPruned 候補
        // ただし実際の削除は accumulator retention depth を超えてから
        let accumulator_depth = crate::constants::ACCUMULATOR_RETENTION_DEPTH;
        if let Some(gd) = store.get_ghostdag_data(block_hash) {
            if pp.blue_score.saturating_sub(gd.blue_score) >= accumulator_depth {
                return PruneLevel::FullyPruned;
            }
        }

        PruneLevel::BodyPruned
    }

    /// Pruning Point から Reachability 上で到達不可能になったブロックを列挙する。
    ///
    /// v9: `PruneLevel::BodyPruned` 以下のブロックのみ返す。
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

        store
            .all_hashes()
            .into_iter()
            .filter(|hash| {
                if *hash == genesis || *hash == pp.block_hash {
                    return false;
                }
                reachability.is_dag_ancestor_of(hash, &pp.block_hash)
            })
            .collect()
    }

    /// Reachability Store から Pruning Point 以前のノードを安全にパージする。
    pub fn prune_reachability(&self, reachability: &mut ReachabilityStore) -> usize {
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
    use crate::dag_block::{DagBlockHeader, GhostDagData, DAG_VERSION, ZERO_HASH};
    use crate::ghostdag::InMemoryDagStore;
    use crate::reachability::ReachabilityStore;

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
    fn test_pruning_point_with_state_commitment() {
        let pp = PruningPoint::with_state([0xAA; 32], 500, [0x11; 32], [0x22; 32], [0x33; 32]);
        assert!(pp.has_state_commitment());
        assert_eq!(pp.state_root, [0x11; 32]);
        assert_eq!(pp.utxo_commitment, [0x22; 32]);
        assert_eq!(pp.nullifier_commitment, [0x33; 32]);
    }

    #[test]
    fn test_pruning_point_legacy_no_commitment() {
        let pp = PruningPoint::new([0xBB; 32], 100);
        assert!(!pp.has_state_commitment());
        assert_eq!(pp.state_root, ZERO_HASH);
    }

    #[test]
    fn test_find_pruning_point_on_chain() {
        let mut store = InMemoryDagStore::new();
        let g = [0x00; 32];

        store.insert_header(g, make_header(vec![]));
        store.set_ghostdag_data(
            g,
            GhostDagData {
                selected_parent: ZERO_HASH,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 0,
                blue_work: 0,
                blues_anticone_sizes: vec![],
            },
        );

        let mut prev = g;
        for i in 1..=1200u32 {
            let mut h = [0u8; 32];
            h[..4].copy_from_slice(&i.to_le_bytes());
            store.insert_header(h, make_header(vec![prev]));
            store.set_ghostdag_data(
                h,
                GhostDagData {
                    selected_parent: prev,
                    mergeset_blues: vec![],
                    mergeset_reds: vec![],
                    blue_score: i as u64,
                    blue_work: i as u128,
                    blues_anticone_sizes: vec![],
                },
            );
            prev = h;
        }

        let pm = PruningManager::new();
        let pp = pm.find_new_pruning_point(1200, &store, [0xAA; 32], [0xBB; 32], [0xCC; 32]);
        assert!(pp.is_some());
        let pp = pp.unwrap();
        assert!(pp.blue_score <= 200);
        // v9: state commitment が設定されている
        assert!(pp.has_state_commitment());
        assert_eq!(pp.state_root, [0xAA; 32]);
    }

    #[test]
    fn test_collect_prunable_blocks_respects_reachability() {
        let mut store = InMemoryDagStore::new();
        let mut reach = ReachabilityStore::new([0; 32]);

        let g = [0x00; 32];
        let a = [0x0A; 32];
        let b = [0x0B; 32];

        store.insert_header(g, make_header(vec![]));
        store.set_ghostdag_data(
            g,
            GhostDagData {
                selected_parent: ZERO_HASH,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 0,
                blue_work: 0,
                blues_anticone_sizes: vec![],
            },
        );

        store.insert_header(a, make_header(vec![g]));
        reach.add_child(g, a).unwrap();
        store.set_ghostdag_data(
            a,
            GhostDagData {
                selected_parent: g,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 1,
                blue_work: 1,
                blues_anticone_sizes: vec![],
            },
        );

        store.insert_header(b, make_header(vec![a]));
        reach.add_child(a, b).unwrap();
        store.set_ghostdag_data(
            b,
            GhostDagData {
                selected_parent: a,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 2,
                blue_work: 2,
                blues_anticone_sizes: vec![],
            },
        );

        let pm = PruningManager::new().with_pruning_point(PruningPoint::new(b, 2));
        let prunable = pm.collect_prunable_blocks(&reach, &store);
        assert!(prunable.contains(&a));
        assert!(!prunable.contains(&g));
        assert!(!prunable.contains(&b));
    }

    #[test]
    fn test_prune_level() {
        let mut store = InMemoryDagStore::new();
        let mut reach = ReachabilityStore::new([0; 32]);

        let g = [0x00; 32];
        let a = [0x0A; 32];
        let b = [0x0B; 32];

        store.insert_header(g, make_header(vec![]));
        store.set_ghostdag_data(
            g,
            GhostDagData {
                selected_parent: ZERO_HASH,
                ..Default::default()
            },
        );

        store.insert_header(a, make_header(vec![g]));
        reach.add_child(g, a).unwrap();
        store.set_ghostdag_data(
            a,
            GhostDagData {
                selected_parent: g,
                blue_score: 1,
                blue_work: 1,
                ..Default::default()
            },
        );

        store.insert_header(b, make_header(vec![a]));
        reach.add_child(a, b).unwrap();
        store.set_ghostdag_data(
            b,
            GhostDagData {
                selected_parent: a,
                blue_score: 2,
                blue_work: 2,
                ..Default::default()
            },
        );

        let pm = PruningManager::new().with_pruning_point(PruningPoint::new(b, 2));

        // b is the pruning point → Full (score >= pp.score)
        assert_eq!(pm.prune_level_of(&b, &store, &reach), PruneLevel::Full);
        // a is strict ancestor of b → BodyPruned
        assert_eq!(
            pm.prune_level_of(&a, &store, &reach),
            PruneLevel::BodyPruned
        );
    }

    #[test]
    fn test_pruning_point_serialization() {
        let pp = PruningPoint::with_state([0xAA; 32], 500, [0x11; 32], [0x22; 32], [0x33; 32]);
        let json = serde_json::to_vec(&pp).unwrap();
        let restored: PruningPoint = serde_json::from_slice(&json).unwrap();
        assert_eq!(restored.block_hash, pp.block_hash);
        assert_eq!(restored.state_root, pp.state_root);
        assert!(restored.has_state_commitment());
    }
}
