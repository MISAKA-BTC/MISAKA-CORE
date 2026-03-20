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
//  ファイナリティマネージャ (V2 統合)
// ═══════════════════════════════════════════════════════════════

/// DAG ファイナリティ & Pruning マネージャ。
///
/// ## Phase 3.1 変更点
///
/// - `is_finalized()` は `GhostDagEngine` (V2) を使用
/// - Finality 判定は V2 の `blue_score` と canonical parent sort に基づく
/// - 旧 `GhostDagManager` への依存を完全に除去
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

    /// 前回のチェックポイントから復元する。
    pub fn with_checkpoint(mut self, checkpoint: DagCheckpoint) -> Self {
        self.last_checkpoint_score = checkpoint.blue_score;
        self.latest_checkpoint = Some(checkpoint);
        self
    }

    /// あるブロックが Final (reorg 不可) かを判定する。
    ///
    /// ## V2 統合
    ///
    /// `GhostDagEngine::confirmation_depth()` を使用して判定する。
    /// この関数は V2 の `blue_score` に基づき、canonical parent sort で
    /// 決定される Selected Parent Chain 上のメインチェーンでのみ評価される。
    pub fn is_finalized<S: DagStore>(
        &self,
        block_hash: &Hash,
        ghostdag: &GhostDagEngine,
        store: &S,
    ) -> bool {
        let depth = ghostdag.confirmation_depth(block_hash, store);
        depth >= FINALITY_DEPTH
    }

    pub fn should_checkpoint(&self, current_max_score: u64) -> bool {
        current_max_score >= self.last_checkpoint_score + self.checkpoint_interval
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
}
