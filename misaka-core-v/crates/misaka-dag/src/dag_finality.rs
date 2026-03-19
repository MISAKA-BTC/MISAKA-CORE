//! # DAG Pruning & ファイナリティ (MISAKA-CORE v2)
//!
//! ## 課題
//!
//! DAG は無限に成長するため、古いブロックデータを定期的に pruning する必要がある。
//! しかし、pruning は以下を破壊してはならない:
//!
//! 1. **Total Order の再計算可能性** — チェックポイントより前は固定
//! 2. **デコイの安全性** — Ring member 参照が pruning で消えない
//! 3. **Key Image の永続性** — 二重支払い防止のため永久保持
//!
//! ## Finality Window
//!
//! `blue_score > current_max_score - FINALITY_DEPTH` のブロックのみが
//! 並び替え (reorg) の対象になりうる。それ以前のブロックは **Final** とみなし、
//! チェックポイントとして確定させる。
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

use std::collections::HashSet;
use tracing::{info, debug};

use crate::dag_block::Hash;
use crate::ghostdag::{GhostDagManager, DagStore};

// ═══════════════════════════════════════════════════════════════
//  定数
// ═══════════════════════════════════════════════════════════════

/// ファイナリティ深度 — この深度以上前のブロックは reorg 不可。
///
/// GhostDAG パラメータ `k=18` に対して、`FINALITY_DEPTH = 100` は
/// 約 5.5k の blue_score 差に相当し、十分保守的。
///
/// Kaspa では `FINALITY_DEPTH = 86400` (= 1日分のブロック) を使用するが、
/// MISAKA の PoS モードではブロック間隔が長いため 100 で十分。
pub const FINALITY_DEPTH: u64 = 100;

/// Pruning 深度 — この深度以上前のブロックは TX データを削除可能。
/// ヘッダと GhostDagData は保持する (Total Order 計算に必要)。
///
/// `PRUNING_DEPTH > FINALITY_DEPTH + MIN_DECOY_DEPTH` であること。
/// デコイに使われる可能性のある UTXO のブロックデータが pruning で
/// 消えないようにする。
pub const PRUNING_DEPTH: u64 = 500;

// ═══════════════════════════════════════════════════════════════
//  チェックポイント
// ═══════════════════════════════════════════════════════════════

/// DAG チェックポイント — ファイナライズされた時点の状態スナップショット。
///
/// チェックポイント以前のブロックの Total Order は確定しており、
/// 状態遷移の結果 (UTXO Set) も不変。
/// 新しいノードはチェックポイントから同期を開始できる。
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

// ═══════════════════════════════════════════════════════════════
//  ファイナリティマネージャ
// ═══════════════════════════════════════════════════════════════

/// DAG ファイナリティ & Pruning マネージャ。
///
/// ## 責務
///
/// 1. ファイナリティ判定: あるブロック/TX が確定 (reorg 不可) かを判断
/// 2. チェックポイント生成: 定期的に確定状態をスナップショット
/// 3. Pruning: 古いブロックの TX データを削除 (ヘッダは保持)
pub struct FinalityManager {
    /// 最新のチェックポイント。
    latest_checkpoint: Option<DagCheckpoint>,

    /// チェックポイント生成間隔 (blue_score 単位)。
    checkpoint_interval: u64,

    /// 最後にチェックポイントを作成した blue_score。
    last_checkpoint_score: u64,
}

impl FinalityManager {
    /// 新しい FinalityManager を作成する。
    ///
    /// # 引数
    ///
    /// - `checkpoint_interval`: 何 blue_score ごとにチェックポイントを作成するか
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
    /// `block.blue_score <= max_blue_score - FINALITY_DEPTH` なら Final。
    pub fn is_finalized<S: DagStore>(
        &self,
        block_hash: &Hash,
        ghostdag: &GhostDagManager,
        store: &S,
    ) -> bool {
        let depth = ghostdag.confirmation_depth(block_hash, store);
        depth >= FINALITY_DEPTH
    }

    /// 新しいチェックポイントが必要か判定する。
    pub fn should_checkpoint(&self, current_max_score: u64) -> bool {
        current_max_score >= self.last_checkpoint_score + self.checkpoint_interval
    }

    /// チェックポイントを作成する。
    ///
    /// # 引数
    ///
    /// - `block_hash`: チェックポイントのブロック (Selected Parent Chain 上)
    /// - `blue_score`: そのブロックの blue_score
    /// - `utxo_root`: UTXO Set の Merkle Root
    /// - `total_key_images`: 累積 Key Image 数
    /// - `total_applied_txs`: 累積適用 TX 数
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
            .unwrap()
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
    /// `blue_score < max_score - PRUNING_DEPTH` のブロックが対象。
    /// ヘッダと GhostDagData は残し、TX データのみ削除する。
    ///
    /// # 返り値
    ///
    /// Pruning 対象のブロックハッシュ群。
    pub fn collect_prunable_blocks<S: DagStore>(
        &self,
        current_max_score: u64,
        store: &S,
    ) -> Vec<Hash> {
        let threshold = current_max_score.saturating_sub(PRUNING_DEPTH);

        store.all_hashes().into_iter()
            .filter(|hash| {
                store.get_ghostdag_data(hash)
                    .map(|d| d.blue_score < threshold)
                    .unwrap_or(false)
            })
            .collect()
    }

    /// 最新のチェックポイントを取得する。
    pub fn latest_checkpoint(&self) -> Option<&DagCheckpoint> {
        self.latest_checkpoint.as_ref()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Virtual Block (DAG の仮想先端)
// ═══════════════════════════════════════════════════════════════

/// Virtual Block — DAG の全 Tips を親とする仮想ブロック。
///
/// GhostDAG では Total Order の起点として Virtual Block を使用する。
/// 実際にはブロックとして保存されず、計算上のアンカーポイントとして機能する。
///
/// ## 用途
///
/// 1. Total Order の起点 (全 Tips を合流する視点)
/// 2. UTXO Set の「現在の状態」を定義する参照点
/// 3. ファイナリティ計算の基準点 (max blue_score)
pub struct VirtualBlock;

impl VirtualBlock {
    /// Virtual Block の blue_score を算出する。
    ///
    /// = Tips のうち最大の blue_score + 1
    pub fn blue_score<S: DagStore>(store: &S) -> u64 {
        store.get_tips().iter()
            .filter_map(|t| store.get_ghostdag_data(t))
            .map(|d| d.blue_score)
            .max()
            .unwrap_or(0)
            .saturating_add(1)
    }

    /// Virtual Block の parents (= 全 Tips) を取得する。
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
        let fm = FinalityManager::new(50); // every 50 blue_score
        assert!(!fm.should_checkpoint(30));
        assert!(fm.should_checkpoint(50));
        assert!(fm.should_checkpoint(100));
    }

    #[test]
    fn test_create_checkpoint() {
        let mut fm = FinalityManager::new(50);
        let cp = fm.create_checkpoint(
            [0xAA; 32], 100, [0xBB; 32], 500, 1000,
        );
        assert_eq!(cp.blue_score, 100);
        assert_eq!(cp.total_key_images, 500);
        assert_eq!(fm.last_checkpoint_score, 100);

        // Next checkpoint should not trigger until score 150
        assert!(!fm.should_checkpoint(130));
        assert!(fm.should_checkpoint(150));
    }
}
