//! # DAG Pruning & ファイナリティ (MISAKA-CORE v2 — V2 統合)
//!
//! ## Phase 3.1: GhostDagManager 依存の完全除去
//!
//! 旧 `FinalityManager::is_finalized()` は `GhostDagManager::confirmation_depth()` に
//! 依存していたが、V2 では `GhostDagV2::confirmation_depth()` を使用する。
//!
//! Finality の決定は、GhostDagV2 の `blue_score` および
//! `parent_selection::ParentSortKey` に基づく Selected Parent Chain 上でのみ評価される。
//!
//! ## Pruning 戦略
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │  Pruned Zone      │  Finalized Zone  │  Active Zone  │
//! │  (headers only)   │  (state frozen)  │  (full data)  │
//! │                   │                  │               │
//! │  ◄── pruned ──►  ◄── checkpoint ──► ◄── live ──►   │
//! │                   │                  │               │
//! │  score < P        │  P ≤ score < F   │  F ≤ score    │
//! └──────────────────────────────────────────────────────┘
//!
//! P = max_score - PRUNING_DEPTH
//! F = max_score - FINALITY_DEPTH
//! ```

use tracing::info;

use crate::dag_block::Hash;
use crate::ghostdag::{DagStore, GhostDagEngine};
use crate::parent_selection::{canonical_compare, ParentSortKey};
use misaka_types::validator::DagCheckpointTarget;

// ═══════════════════════════════════════════════════════════════
//  定数 — SSOT (constants.rs) からインポート
// ═══════════════════════════════════════════════════════════════

pub use crate::constants::{FINALITY_DEPTH, PRUNING_DEPTH};

// ═══════════════════════════════════════════════════════════════
//  チェックポイント
// ═══════════════════════════════════════════════════════════════

/// DAG チェックポイント — ファイナライズされた時点の状態スナップショット。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DagCheckpoint {
    /// チェックポイントのブロックハッシュ (Selected Parent Chain 上のブロック)。
    pub block_hash: Hash,
    /// このチェックポイント時点の blue_score。
    pub blue_score: u64,
    /// UTXO Set の Merkle Root。
    pub utxo_root: [u8; 32],
    /// このチェックポイントまでに消費された Key Image 数。
    pub total_key_images: u64,
    /// このチェックポイントまでに適用された TX 数。
    pub total_applied_txs: u64,
    /// チェックポイント作成時のタイムスタンプ (ms)。
    pub timestamp_ms: u64,
}

impl DagCheckpoint {
    /// Deterministic validator signing target for this checkpoint.
    pub fn validator_target(&self) -> DagCheckpointTarget {
        DagCheckpointTarget {
            block_hash: self.block_hash,
            blue_score: self.blue_score,
            utxo_root: self.utxo_root,
            total_key_images: self.total_key_images,
            total_applied_txs: self.total_applied_txs,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  ファイナリティマネージャ (v4: VSPC-Based Finality)
// ═══════════════════════════════════════════════════════════════

/// DAG ファイナリティ & Pruning マネージャ。
///
/// ## v4 変更: VSPC-Based Finality
///
/// 旧コード: `confirmation_depth(block) >= FINALITY_DEPTH` のみ。
/// これは blue_score の差分だけを見ており、以下を見逃す:
///
/// - ブロックが VSPC 上にない場合 (サイドブランチ上で blue_score は深いが
///   メインチェーンではない)
/// - 競合ブランチの blue_work が接近している場合 (reorg リスクが高い)
///
/// 新コード: 以下の 3 条件をすべて満たす場合のみ Final:
///
/// 1. **VSPC Membership**: ブロックが Virtual Selected Parent Chain 上にある
/// 2. **Depth Threshold**: VSPC 上の深度が `FINALITY_DEPTH` 以上
/// 3. **Anticone Stability**: 競合ブランチの blue_work が
///    `FINALITY_DEPTH * k` 分離れている (数学的に覆る確率がゼロ)
///
/// ## Kaspa の Finality 概念との対応
///
/// Kaspa の finality は PHANTOM GHOSTDAG 論文の Theorem 3.1 に基づく:
/// 正直ノードが全体の (1 - 1/(2k+1)) 以上を占める場合、
/// VSPC 上で十分深いブロックは指数関数的確率で確定する。
/// `FINALITY_DEPTH = 200` は k=18 に対して安全マージンが十分大きい。
pub struct FinalityManager {
    latest_checkpoint: Option<DagCheckpoint>,
    checkpoint_interval: u64,
    last_checkpoint_score: u64,
}

impl FinalityManager {
    pub fn new(checkpoint_interval: u64) -> Self {
        Self {
            latest_checkpoint: None,
            checkpoint_interval,
            last_checkpoint_score: 0,
        }
    }

    pub fn with_checkpoint(mut self, checkpoint: DagCheckpoint) -> Self {
        self.last_checkpoint_score = checkpoint.blue_score;
        self.latest_checkpoint = Some(checkpoint);
        self
    }

    /// あるブロックが Final (reorg 不可) かを VSPC ベースで判定する。
    ///
    /// ## Finality 条件 (v4)
    ///
    /// 1. **VSPC Membership**: block が現在の VSPC 上にある
    /// 2. **Depth**: VSPC 上の深度が FINALITY_DEPTH 以上
    /// 3. **Anticone Stability**: 競合ブランチとの blue_work 差が十分大きい
    ///
    /// ## なぜ単純な blue_score 差では不十分か
    ///
    /// サイドブランチ上のブロックは blue_score が高くても VSPC 上にない。
    /// VSPC 上にないブロックは、メインチェーンの切り替えで無効化されうる。
    /// 例: 攻撃者が秘密裏に長いチェーンを構築し、一度に公開した場合。
    pub fn is_finalized<S: DagStore>(
        &self,
        block_hash: &Hash,
        ghostdag: &GhostDagEngine,
        store: &S,
    ) -> bool {
        // ── Condition 1: Confirmation depth (必要条件) ──
        let depth = ghostdag.confirmation_depth(block_hash, store);
        if depth < FINALITY_DEPTH {
            return false;
        }

        // ── Condition 2: VSPC membership ──
        //
        // ブロックが Virtual Selected Parent Chain 上にあるか確認。
        // VSPC は tips → genesis 方向に selected_parent を辿るチェーン。
        let tips = store.get_tips();
        if tips.is_empty() {
            return false;
        }

        // Virtual tip (canonical ソートで最上位の tip)
        let virtual_tip =
            crate::parent_selection::select_parent(&tips, store, &ghostdag.genesis_hash);

        // VSPC を遡ってブロックを探す
        let on_vspc = self.is_on_vspc(block_hash, &virtual_tip, store);
        if !on_vspc {
            return false;
        }

        // ── Condition 3: Anticone stability (blue_work gap) ──
        //
        // 競合ブランチの最大 blue_work が、VSPC の blue_work から
        // 十分離れていること。
        //
        // 具体的には: virtual_tip.blue_work - best_competing.blue_work > k * FINALITY_DEPTH
        //
        // これにより、攻撃者が秘密チェーンで追いつく確率がゼロに収束する。
        let virtual_work = store
            .get_ghostdag_data(&virtual_tip)
            .map(|d| d.blue_work)
            .unwrap_or(0);

        // 全 tips の中で VSPC 上にない最大 blue_work を探す
        let max_competing_work = tips
            .iter()
            .filter(|t| **t != virtual_tip)
            .filter_map(|t| store.get_ghostdag_data(t))
            .map(|d| d.blue_work)
            .max()
            .unwrap_or(0);

        // k × FINALITY_DEPTH 以上の gap があれば anticone は安定
        let stability_gap =
            (crate::constants::DEFAULT_K as u128).saturating_mul(FINALITY_DEPTH as u128);
        let work_gap = virtual_work.saturating_sub(max_competing_work);

        work_gap >= stability_gap
    }

    /// ブロックが VSPC (Virtual Selected Parent Chain) 上にあるか判定。
    ///
    /// virtual_tip から selected_parent を辿り、block_hash に到達するか確認。
    /// FINALITY_DEPTH + マージン分だけ遡る。
    fn is_on_vspc<S: DagStore>(&self, block_hash: &Hash, virtual_tip: &Hash, store: &S) -> bool {
        let mut current = *virtual_tip;
        // VSPC を最大 FINALITY_DEPTH + PRUNING_DEPTH 分遡る
        let max_walk = FINALITY_DEPTH + PRUNING_DEPTH;
        for _ in 0..max_walk {
            if current == *block_hash {
                return true;
            }
            if current == crate::dag_block::ZERO_HASH {
                break;
            }
            match store.get_ghostdag_data(&current) {
                Some(data) if data.selected_parent != crate::dag_block::ZERO_HASH => {
                    current = data.selected_parent;
                }
                _ => break,
            }
        }
        false
    }

    pub fn should_checkpoint(&self, current_max_score: u64) -> bool {
        current_max_score >= self.last_checkpoint_score + self.checkpoint_interval
    }

    /// Select a deterministic checkpoint candidate from the next checkpoint bucket.
    ///
    /// Earlier versions walked the selected-parent chain of the local virtual
    /// tip and chose the highest ancestor within the bucket. That still left a
    /// race in natural multi-validator networks: if two validators observed
    /// different selected-parent chains when the first bucket boundary was
    /// crossed, they could pin different pending checkpoint targets and remain
    /// blocked from rollover until finality.
    ///
    /// The current rule is:
    /// 1. derive the *next* checkpoint bucket from `last_checkpoint_score + checkpoint_interval`
    /// 2. require that the local virtual tip has reached that bucket
    /// 3. enumerate all known blocks with `blue_score <= bucket_boundary`
    /// 4. choose the canonical best block under `ParentSortKey`
    ///
    /// This prevents validators from skipping multiple buckets when their
    /// finality monitor wakes up late relative to block production. Validators
    /// may be slightly out of sync above the bucket boundary, but as long as
    /// they have converged on the block set up to the next bucket they will
    /// choose the same target.
    pub fn checkpoint_candidate<S: DagStore>(
        &self,
        ghostdag: &GhostDagEngine,
        store: &S,
    ) -> Option<(Hash, u64)> {
        if self.checkpoint_interval == 0 {
            return None;
        }

        let tips = store.get_tips();
        if tips.is_empty() {
            return None;
        }

        let virtual_tip = ghostdag.select_parent_public(&tips, store);
        let virtual_tip_score = store.get_ghostdag_data(&virtual_tip)?.blue_score;
        let target_boundary = self.last_checkpoint_score + self.checkpoint_interval;
        if virtual_tip_score < target_boundary {
            return None;
        }
        if target_boundary == 0 {
            return None;
        }

        let mut candidates: Vec<(ParentSortKey, Hash)> = store
            .all_hashes()
            .into_iter()
            .filter_map(|hash| {
                let data = store.get_ghostdag_data(&hash)?;
                if data.blue_score > target_boundary {
                    return None;
                }
                let key = ParentSortKey::from_store(&hash, store)?;
                Some((key, hash))
            })
            .collect();

        candidates.sort_by(|a, b| canonical_compare(&a.0, &b.0));
        let candidate = candidates
            .into_iter()
            .next()
            .map(|(key, hash)| (hash, key.blue_score))?;
        if let Some(existing) = self.latest_checkpoint.as_ref() {
            if existing.block_hash == candidate.0 && existing.blue_score == candidate.1 {
                return None;
            }
            if candidate.1 < existing.blue_score {
                return None;
            }
        } else if candidate.1 <= self.last_checkpoint_score {
            return None;
        }

        Some(candidate)
    }

    pub fn create_checkpoint(
        &mut self,
        block_hash: Hash,
        blue_score: u64,
        utxo_root: [u8; 32],
        total_key_images: u64,
        total_applied_txs: u64,
    ) -> DagCheckpoint {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let checkpoint = DagCheckpoint {
            block_hash,
            blue_score,
            utxo_root,
            total_key_images,
            total_applied_txs,
            timestamp_ms: now_ms,
        };

        self.latest_checkpoint = Some(checkpoint.clone());
        self.last_checkpoint_score = blue_score;

        info!(
            "DAG Checkpoint created: score={}, block={}, txs={}, kis={}",
            blue_score,
            hex::encode(&block_hash[..4]),
            total_applied_txs,
            total_key_images,
        );

        checkpoint
    }

    /// Pruning 対象のブロックハッシュを収集する。
    ///
    /// v4: blue_score 閾値ベース（PruningManager の VSPC ベースが正式版）。
    pub fn collect_prunable_blocks<S: DagStore>(
        &self,
        current_max_score: u64,
        store: &S,
    ) -> Vec<Hash> {
        let threshold = current_max_score.saturating_sub(PRUNING_DEPTH);

        store
            .all_hashes()
            .into_iter()
            .filter(|hash| {
                store
                    .get_ghostdag_data(hash)
                    .map(|d| d.blue_score < threshold)
                    .unwrap_or(false)
            })
            .collect()
    }

    pub fn latest_checkpoint(&self) -> Option<&DagCheckpoint> {
        self.latest_checkpoint.as_ref()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Virtual Block (DAG の仮想先端)
// ═══════════════════════════════════════════════════════════════

/// Virtual Block — DAG の全 Tips を親とする仮想ブロック。
pub struct VirtualBlock;

impl VirtualBlock {
    pub fn blue_score<S: DagStore>(store: &S) -> u64 {
        store
            .get_tips()
            .iter()
            .filter_map(|t| store.get_ghostdag_data(t))
            .map(|d| d.blue_score)
            .max()
            .unwrap_or(0)
            .saturating_add(1)
    }

    pub fn parents<S: DagStore>(store: &S) -> Vec<Hash> {
        store.get_tips()
    }
}

// ═══════════════════════════════════════════════════════════════
//  テスト
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag_block::ZERO_HASH;

    #[test]
    fn test_should_checkpoint() {
        let fm = FinalityManager::new(50);
        assert!(!fm.should_checkpoint(30));
        assert!(fm.should_checkpoint(50));
        assert!(fm.should_checkpoint(100));
    }

    #[test]
    fn test_create_checkpoint() {
        let mut fm = FinalityManager::new(50);
        let cp = fm.create_checkpoint([0xAA; 32], 100, [0xBB; 32], 500, 1000);
        assert_eq!(cp.blue_score, 100);
        assert_eq!(cp.total_key_images, 500);
        assert_eq!(fm.last_checkpoint_score, 100);
        assert!(!fm.should_checkpoint(130));
        assert!(fm.should_checkpoint(150));
    }

    #[test]
    fn test_checkpoint_validator_target_excludes_timestamp() {
        let mut fm = FinalityManager::new(50);
        let cp = fm.create_checkpoint([0xAB; 32], 77, [0xBC; 32], 12, 21);
        let target = cp.validator_target();
        assert_eq!(target.block_hash, cp.block_hash);
        assert_eq!(target.blue_score, cp.blue_score);
        assert_eq!(target.utxo_root, cp.utxo_root);
        assert_eq!(target.total_key_images, cp.total_key_images);
        assert_eq!(target.total_applied_txs, cp.total_applied_txs);
    }

    fn make_header(parents: Vec<Hash>, ts: u64) -> crate::dag_block::DagBlockHeader {
        crate::dag_block::DagBlockHeader {
            version: crate::dag_block::DAG_VERSION,
            parents,
            timestamp_ms: ts,
            tx_root: ZERO_HASH,
            proposer_id: [0; 32],
            nonce: 0,
            blue_score: 0,
            bits: 0,
        }
    }

    #[test]
    fn test_checkpoint_candidate_uses_next_bucket_boundary() {
        use crate::dag_block::GhostDagData;
        use crate::ghostdag::InMemoryDagStore;

        let genesis = [0x11; 32];
        let a = [0x21; 32];
        let b = [0x31; 32];
        let c = [0x41; 32];
        let d = [0x51; 32];

        let mut store = InMemoryDagStore::new();
        store.insert_header(genesis, make_header(vec![], 1));
        store.insert_header(a, make_header(vec![genesis], 2));
        store.insert_header(b, make_header(vec![a], 3));
        store.insert_header(c, make_header(vec![b], 4));
        store.insert_header(d, make_header(vec![c], 5));

        store.set_ghostdag_data(
            genesis,
            GhostDagData {
                selected_parent: ZERO_HASH,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 0,
                blue_work: 0,
                blues_anticone_sizes: vec![],
            },
        );
        store.set_ghostdag_data(
            a,
            GhostDagData {
                selected_parent: genesis,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 4,
                blue_work: 4,
                blues_anticone_sizes: vec![],
            },
        );
        store.set_ghostdag_data(
            b,
            GhostDagData {
                selected_parent: a,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 6,
                blue_work: 6,
                blues_anticone_sizes: vec![],
            },
        );
        store.set_ghostdag_data(
            c,
            GhostDagData {
                selected_parent: b,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 8,
                blue_work: 8,
                blues_anticone_sizes: vec![],
            },
        );
        store.set_ghostdag_data(
            d,
            GhostDagData {
                selected_parent: c,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 12,
                blue_work: 12,
                blues_anticone_sizes: vec![],
            },
        );

        let ghostdag = GhostDagEngine::new(crate::constants::DEFAULT_K, genesis);
        let fm = FinalityManager::new(6);
        let candidate = fm.checkpoint_candidate(&ghostdag, &store).unwrap();
        assert_eq!(candidate, (b, 6));
    }

    #[test]
    fn test_checkpoint_candidate_advances_stale_checkpoint_to_converged_target() {
        use crate::dag_block::GhostDagData;
        use crate::ghostdag::InMemoryDagStore;

        let genesis = [0x12; 32];
        let a = [0x22; 32];
        let b = [0x32; 32];
        let c = [0x42; 32];
        let d = [0x52; 32];

        let mut store = InMemoryDagStore::new();
        store.insert_header(genesis, make_header(vec![], 1));
        store.insert_header(a, make_header(vec![genesis], 2));
        store.insert_header(b, make_header(vec![a], 3));
        store.insert_header(c, make_header(vec![b], 4));
        store.insert_header(d, make_header(vec![c], 5));

        store.set_ghostdag_data(
            genesis,
            GhostDagData {
                selected_parent: ZERO_HASH,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 0,
                blue_work: 0,
                blues_anticone_sizes: vec![],
            },
        );
        store.set_ghostdag_data(
            a,
            GhostDagData {
                selected_parent: genesis,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 22,
                blue_work: 22,
                blues_anticone_sizes: vec![],
            },
        );
        store.set_ghostdag_data(
            b,
            GhostDagData {
                selected_parent: a,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 23,
                blue_work: 23,
                blues_anticone_sizes: vec![],
            },
        );
        store.set_ghostdag_data(
            c,
            GhostDagData {
                selected_parent: b,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 28,
                blue_work: 28,
                blues_anticone_sizes: vec![],
            },
        );
        store.set_ghostdag_data(
            d,
            GhostDagData {
                selected_parent: c,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 30,
                blue_work: 30,
                blues_anticone_sizes: vec![],
            },
        );

        let ghostdag = GhostDagEngine::new(crate::constants::DEFAULT_K, genesis);
        let stale_checkpoint = DagCheckpoint {
            block_hash: a,
            blue_score: 22,
            utxo_root: [0x55; 32],
            total_key_images: 0,
            total_applied_txs: 0,
            timestamp_ms: 1,
        };
        let fm = FinalityManager::new(6).with_checkpoint(stale_checkpoint);
        let candidate = fm.checkpoint_candidate(&ghostdag, &store).unwrap();
        assert_eq!(candidate, (c, 28));
    }

    #[test]
    fn test_checkpoint_candidate_uses_canonical_best_block_within_bucket() {
        use crate::dag_block::GhostDagData;
        use crate::ghostdag::InMemoryDagStore;

        let genesis = [0x13; 32];
        let a = [0x23; 32];
        let b = [0x33; 32];
        let c = [0x43; 32];

        let mut store = InMemoryDagStore::new();
        store.insert_header(genesis, make_header(vec![], 1));

        let mut header_a = make_header(vec![genesis], 2);
        header_a.proposer_id = [0x11; 32];
        store.insert_header(a, header_a);

        let mut header_b = make_header(vec![genesis], 3);
        header_b.proposer_id = [0x22; 32];
        store.insert_header(b, header_b);

        let mut header_c = make_header(vec![b], 4);
        header_c.proposer_id = [0x33; 32];
        store.insert_header(c, header_c);

        store.set_ghostdag_data(
            genesis,
            GhostDagData {
                selected_parent: ZERO_HASH,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 0,
                blue_work: 0,
                blues_anticone_sizes: vec![],
            },
        );
        store.set_ghostdag_data(
            a,
            GhostDagData {
                selected_parent: genesis,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 4,
                blue_work: 4,
                blues_anticone_sizes: vec![],
            },
        );
        store.set_ghostdag_data(
            b,
            GhostDagData {
                selected_parent: genesis,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 6,
                blue_work: 6,
                blues_anticone_sizes: vec![],
            },
        );
        store.set_ghostdag_data(
            c,
            GhostDagData {
                selected_parent: b,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blue_score: 11,
                blue_work: 11,
                blues_anticone_sizes: vec![],
            },
        );

        let ghostdag = GhostDagEngine::new(crate::constants::DEFAULT_K, genesis);
        let fm = FinalityManager::new(6);
        let candidate = fm.checkpoint_candidate(&ghostdag, &store).unwrap();

        // b wins over a at the same bucket boundary because ParentSortKey uses
        // proposer_id/hash as deterministic tie-breakers.
        assert_eq!(candidate, (b, 6));
    }
}
