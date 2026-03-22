//! # Protocol Constants — Single Source of Truth (SSOT)
//!
//! # 設計原則
//!
//! **すべての深度定数・ウィンドウ定数はこのファイルのみで定義する。**
//! 他のモジュール (`dag_finality.rs`, `pruning.rs`, `reachability.rs`,
//! `ghostdag_v2.rs`) は `use crate::constants::*` でインポートする。
//!
//! ## なぜ SSOT が必要か
//!
//! v3 までは同名の定数が 3 つのファイルに散在し、値が矛盾していた:
//!
//! | 定数名            | reachability.rs | dag_finality.rs | pruning.rs |
//! |-------------------|-----------------|-----------------|------------|
//! | `FINALITY_DEPTH`  | 200             | 100             | —          |
//! | `PRUNING_DEPTH`   | 1000            | 500             | 500        |
//!
//! この不整合は、ノード A が blue_score=150 のブロックを Final と判定し、
//! ノード B が同ブロックを未確定と判定する → reorg 不整合 → チェーンスプリット
//! を引き起こす。
//!
//! ## 定数の意味と依存関係
//!
//! ```text
//! 0 ← MIN_DECOY_DEPTH ← FINALITY_DEPTH ← PRUNING_DEPTH ← ACCUMULATOR_RETENTION_DEPTH
//!         (100)               (200)            (1000)              (2000)
//!
//! PRUNING_WINDOW ≡ PRUNING_DEPTH  (同義: 参照可能な最大 blue_score 距離)
//! ```
//!
//! # Compile-Time Assertions
//!
//! 依存関係の不変条件はコンパイル時に検証される。

// ═══════════════════════════════════════════════════════════════
//  GhostDAG Protocol Parameters
// ═══════════════════════════════════════════════════════════════

/// GhostDAG k parameter — 正直ノードの同時生成ブロック数上限推定値。
///
/// anticone サイズが k 以下のブロックを Blue と判定する。
/// Kaspa デフォルト: k=18。MISAKA v4 も k=18 から開始。
pub const DEFAULT_K: u64 = 18;

/// 最大親ブロック数 (per block)。メモリ DoS 防止。
pub const MAX_PARENTS: usize = 10;

/// 最大 Mergeset サイズ。CPU DoS 防止。
/// 超過時はブロック自体を **Invalid として拒否** する (Fail-Closed)。
pub const MAX_MERGESET_SIZE: usize = 256;

// ═══════════════════════════════════════════════════════════════
//  Depth & Window Constants (SSOT)
// ═══════════════════════════════════════════════════════════════

/// リング署名デコイ選択の最小確認深度。
///
/// この深度未満のブロックに含まれる UTXO は、DAG の並び替えにより
/// 無効化される可能性があるため、デコイとして選択してはならない。
///
/// 値は GhostDAG パラメータ `k` の数倍が目安。k=18 に対して 100 は十分保守的。
pub const MIN_DECOY_DEPTH: u64 = 100;

/// ファイナリティ深度 — この深度以上前のブロックは reorg 不可。
///
/// `confirmation_depth(block) >= FINALITY_DEPTH` のとき、
/// そのブロックの TX は安全にファイナルと見なせる。
///
/// # 安全性
///
/// k=18 に対して depth=200 は、攻撃者が全ネットワーク演算力の 49% を
/// 持っていても覆る確率が天文学的に小さい。
pub const FINALITY_DEPTH: u64 = 200;

/// Pruning 深度 — この深度以上古いブロックの TX データを削除可能。
///
/// Pruning Point の最小深度と同義。この深度以上古いチェーンブロックのみが
/// Pruning Point 候補になる。
///
/// # 不変条件
///
/// `FINALITY_DEPTH < PRUNING_DEPTH` — Finality 確定後にのみ Pruning される。
pub const PRUNING_DEPTH: u64 = 1000;

/// Pruning Window — 親ブロック参照の最大 blue_score 距離。
///
/// `header.blue_score - parent.blue_score > PRUNING_WINDOW` の場合、
/// その親参照は無効 (ParentTooOld)。
///
/// # SSOT: PRUNING_DEPTH と同値
///
/// これらは同一の概念の異なる表現:
/// - PRUNING_DEPTH: 「どこまで遡ったら Prune してよいか」
/// - PRUNING_WINDOW: 「どこまで遡った親を参照してよいか」
pub const PRUNING_WINDOW: u64 = PRUNING_DEPTH;

/// Accumulator 保持深度 — UTXO accumulator のみ保持する区間。
///
/// `PRUNING_DEPTH ≤ depth < ACCUMULATOR_RETENTION_DEPTH` の区間では
/// ヘッダと nullifier のみ保持し、TX データは削除済み。
/// `ACCUMULATOR_RETENTION_DEPTH` 以降は accumulator も削除可能。
pub const ACCUMULATOR_RETENTION_DEPTH: u64 = 2000;

/// Pruning Point 更新間隔 (blue_score 単位)。
/// この間隔ごとに Pruning Point を再評価する。
pub const PRUNING_POINT_UPDATE_INTERVAL: u64 = 100;

// ═══════════════════════════════════════════════════════════════
//  Checkpoint Attestation Quorum (BFT)
// ═══════════════════════════════════════════════════════════════

/// Quorum numerator: checkpoint finality requires `⌈ total_stake × 2/3 ⌉ + 1`.
///
/// **SSOT**: The authoritative quorum threshold is `QUORUM_THRESHOLD_BPS = 6667`
/// in `misaka_types::constants`. This re-export exists for documentation only.
/// All runtime quorum checks MUST use `ValidatorSet::quorum_threshold()`.
pub const CHECKPOINT_QUORUM_NUMERATOR: u128 = 2;
pub const CHECKPOINT_QUORUM_DENOMINATOR: u128 = 3;

// ═══════════════════════════════════════════════════════════════
//  Bounded Ancestor Search — Reachability Hybrid (Task 1.1)
// ═══════════════════════════════════════════════════════════════

/// DAG 上の真正祖先判定 BFS の最大探索ブロック数。
///
/// Interval fast-path が false を返した場合の BFS 上限。
/// これは `MAX_MERGESET_SIZE × MAX_PARENTS` 程度を想定。
/// DoS 防止のためのハードキャップ。
pub const MAX_ANCESTOR_SEARCH_BLOCKS: usize = 4096;

// ═══════════════════════════════════════════════════════════════
//  Retention Levels (Node Role 別データ保持)
// ═══════════════════════════════════════════════════════════════

/// ブロックの深度に応じたデータ保持レベル。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionLevel {
    /// 全データ保持 (depth < FINALITY_DEPTH)
    Full,
    /// ヘッダ + Nullifier のみ (FINALITY_DEPTH ≤ depth < PRUNING_DEPTH)
    HeadersAndNullifiers,
    /// Accumulator のみ (PRUNING_DEPTH ≤ depth < ACCUMULATOR_RETENTION_DEPTH)
    AccumulatorOnly,
    /// 完全削除 (depth ≥ ACCUMULATOR_RETENTION_DEPTH)
    Pruned,
}

/// 深度から保持レベルを決定する。
#[inline]
pub fn retention_level(depth: u64) -> RetentionLevel {
    if depth < FINALITY_DEPTH {
        RetentionLevel::Full
    } else if depth < PRUNING_DEPTH {
        RetentionLevel::HeadersAndNullifiers
    } else if depth < ACCUMULATOR_RETENTION_DEPTH {
        RetentionLevel::AccumulatorOnly
    } else {
        RetentionLevel::Pruned
    }
}

/// デコイ選択の適格性判定。
#[inline]
pub fn is_decoy_eligible(depth: u64) -> bool {
    depth >= MIN_DECOY_DEPTH && depth < PRUNING_DEPTH
}

/// ノードの保持ロール。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRetentionRole {
    Archive,
    Validator,
    Light,
}

// ═══════════════════════════════════════════════════════════════
//  Compile-Time Consistency Assertions
// ═══════════════════════════════════════════════════════════════

// 不変条件: MIN_DECOY_DEPTH ≤ FINALITY_DEPTH < PRUNING_DEPTH < ACCUMULATOR_RETENTION_DEPTH
const _: () = {
    assert!(MIN_DECOY_DEPTH <= FINALITY_DEPTH);
    assert!(FINALITY_DEPTH < PRUNING_DEPTH);
    assert!(PRUNING_DEPTH < ACCUMULATOR_RETENTION_DEPTH);
    assert!(PRUNING_WINDOW == PRUNING_DEPTH);
    // k に対する安全性: FINALITY_DEPTH >> k
    assert!(FINALITY_DEPTH > DEFAULT_K * 10);
    // Pruning Point 更新間隔は PRUNING_DEPTH 未満
    assert!(PRUNING_POINT_UPDATE_INTERVAL < PRUNING_DEPTH);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_retention_level_ordering() {
        assert_eq!(retention_level(0), RetentionLevel::Full);
        assert_eq!(retention_level(MIN_DECOY_DEPTH), RetentionLevel::Full);
        assert_eq!(retention_level(FINALITY_DEPTH), RetentionLevel::HeadersAndNullifiers);
        assert_eq!(retention_level(PRUNING_DEPTH), RetentionLevel::AccumulatorOnly);
        assert_eq!(retention_level(ACCUMULATOR_RETENTION_DEPTH), RetentionLevel::Pruned);
    }

    #[test]
    fn test_decoy_eligibility() {
        assert!(!is_decoy_eligible(0));
        assert!(!is_decoy_eligible(MIN_DECOY_DEPTH - 1));
        assert!(is_decoy_eligible(MIN_DECOY_DEPTH));
        assert!(is_decoy_eligible(PRUNING_DEPTH - 1));
        assert!(!is_decoy_eligible(PRUNING_DEPTH));
    }
}
