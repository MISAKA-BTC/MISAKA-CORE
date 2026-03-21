//! DAA (Difficulty Adjustment Algorithm) — DAG-Integrated Block Rate Control (B-rank).
//!
//! # 概要
//!
//! レビュー指摘: "blue_score はあるが、DAA 的な重みの世界が薄い"
//!
//! BlockDAG では線形 chain の difficulty 調整とは異なり、
//! 並列ブロック生成を前提とした block rate 制御が必要。
//!
//! # Kaspa DAA 概念
//!
//! Kaspa の DAA は:
//! 1. **DAA window**: SP chain 上の直近 N ブロックの timestamp 範囲から
//!    実効 block rate を計算
//! 2. **Target block rate**: ネットワーク設計上の目標ブロック間隔
//! 3. **Difficulty adjustment**: 実効 rate が目標より速ければ difficulty 上昇、
//!    遅ければ下降
//!
//! # MISAKA DAA
//!
//! MISAKA は PoS ベースのため、difficulty = "proposer eligibility threshold"。
//! block rate 制御は timestamp ベースで行い、DAA window から算出した
//! 実効 block rate が目標に近づくよう bits (difficulty target) を調整する。
//!
//! # Timestamp Rules (DAG-context)
//!
//! DAG では各ブロックが複数の親を持つため、timestamp 検証は
//! 単一の前ブロックではなく **past median time** で行う:
//!
//! - `block.timestamp >= past_median_time(block.parents)`
//! - `block.timestamp <= now + MAX_FUTURE_DRIFT`
//!
//! past_median_time は親ブロック群の timestamp の中央値。

use crate::dag_block::{Hash, ZERO_HASH};
use crate::ghostdag::DagStore;

// ═══════════════════════════════════════════════════════════════
//  DAA Constants
// ═══════════════════════════════════════════════════════════════

/// DAA window size (SP chain 上のブロック数)。
/// 直近 N ブロックの timestamp 範囲から block rate を推定。
pub const DAA_WINDOW_SIZE: u64 = 2641;

/// 目標ブロック間隔 (milliseconds)。
/// Kaspa は 1000ms (1 BPS)。MISAKA は初期設定 10000ms (0.1 BPS)。
pub const TARGET_BLOCK_INTERVAL_MS: u64 = 10_000;

/// 最大 future drift (milliseconds)。
/// ブロックの timestamp が現在時刻からこの値以上未来であれば reject。
pub const MAX_FUTURE_DRIFT_MS: u64 = 30_000;

/// Difficulty 調整の最大倍率 (上下)。
/// 1 回の調整で difficulty が 4 倍以上変動するのを防止。
pub const MAX_DIFFICULTY_RATIO: u64 = 4;

/// 初期 difficulty bits。
pub const INITIAL_BITS: u32 = 0x2000_0000;

/// Past median time 計算に使う親の数。
pub const MEDIAN_TIME_PAST_COUNT: usize = 11;

// ═══════════════════════════════════════════════════════════════
//  Past Median Time
// ═══════════════════════════════════════════════════════════════

/// 親ブロック群の timestamp から past median time を計算。
///
/// DAG では複数の親を持つため、bitcoin の "median of last 11 blocks" とは
/// 異なり、直接の親群の timestamp の中央値を使う。
///
/// 親が 1 つの場合はそのブロックの timestamp をそのまま返す。
pub fn compute_past_median_time<S: DagStore>(
    parents: &[Hash],
    store: &S,
) -> u64 {
    if parents.is_empty() {
        return 0;
    }

    let mut timestamps: Vec<u64> = parents.iter()
        .filter_map(|p| store.get_header(p).map(|h| h.timestamp_ms))
        .collect();

    if timestamps.is_empty() {
        return 0;
    }

    timestamps.sort_unstable();

    // Median: 中央値
    let mid = timestamps.len() / 2;
    if timestamps.len() % 2 == 0 {
        (timestamps[mid - 1] + timestamps[mid]) / 2
    } else {
        timestamps[mid]
    }
}

// ═══════════════════════════════════════════════════════════════
//  Timestamp Validation
// ═══════════════════════════════════════════════════════════════

/// DAG-context aware timestamp 検証。
///
/// # Rules
///
/// 1. `block.timestamp >= past_median_time(parents)` — 時間の逆行防止
/// 2. `block.timestamp <= now + MAX_FUTURE_DRIFT_MS` — future block 防止
///
/// # なぜ past_median_time か
///
/// DAG では並列ブロックの timestamp が交差する可能性がある。
/// 単一の前ブロックとの比較では不十分で、複数親の中央値を基準にすることで
/// timestamp manipulation への耐性を確保する。
#[derive(Debug, PartialEq, Eq)]
pub enum TimestampCheck {
    Valid,
    /// Block timestamp is before past median time.
    TooOld { block_ms: u64, past_median_ms: u64 },
    /// Block timestamp is too far in the future.
    TooFuture { block_ms: u64, max_ms: u64 },
}

pub fn validate_timestamp<S: DagStore>(
    block_timestamp_ms: u64,
    parents: &[Hash],
    store: &S,
    now_ms: u64,
) -> TimestampCheck {
    // Rule 1: >= past_median_time
    let pmt = compute_past_median_time(parents, store);
    if block_timestamp_ms < pmt {
        return TimestampCheck::TooOld {
            block_ms: block_timestamp_ms,
            past_median_ms: pmt,
        };
    }

    // Rule 2: <= now + drift
    let max_allowed = now_ms.saturating_add(MAX_FUTURE_DRIFT_MS);
    if block_timestamp_ms > max_allowed {
        return TimestampCheck::TooFuture {
            block_ms: block_timestamp_ms,
            max_ms: max_allowed,
        };
    }

    TimestampCheck::Valid
}

// ═══════════════════════════════════════════════════════════════
//  DAA Window & Block Rate
// ═══════════════════════════════════════════════════════════════

/// DAA window 内の実効 block rate を計算。
///
/// SP chain 上の直近 `window_size` ブロックの timestamp 範囲から
/// 平均ブロック間隔 (ms) を算出。
///
/// Returns: (average_interval_ms, block_count_in_window)
pub fn compute_block_rate<S: DagStore>(
    tip: &Hash,
    store: &S,
    window_size: u64,
) -> (u64, u64) {
    let mut timestamps = Vec::new();
    let mut current = *tip;
    let mut count = 0u64;

    loop {
        if count >= window_size {
            break;
        }
        if let Some(header) = store.get_header(&current) {
            timestamps.push(header.timestamp_ms);
        }
        if let Some(data) = store.get_ghostdag_data(&current) {
            if data.selected_parent == ZERO_HASH {
                break;
            }
            current = data.selected_parent;
        } else {
            break;
        }
        count += 1;
    }

    if timestamps.len() < 2 {
        return (TARGET_BLOCK_INTERVAL_MS, count);
    }

    let newest = timestamps.first().copied().unwrap_or(0);
    let oldest = timestamps.last().copied().unwrap_or(0);
    let time_span = newest.saturating_sub(oldest);
    let blocks = timestamps.len().saturating_sub(1) as u64;

    if blocks == 0 {
        return (TARGET_BLOCK_INTERVAL_MS, count);
    }

    (time_span / blocks, count)
}

// ═══════════════════════════════════════════════════════════════
//  Difficulty Adjustment
// ═══════════════════════════════════════════════════════════════

/// 新しい difficulty bits を計算。
///
/// # Algorithm
///
/// ```text
/// actual_rate = compute_block_rate(tip, window)
/// ratio = actual_rate / target_rate
/// new_bits = old_bits * ratio   (clamped by MAX_DIFFICULTY_RATIO)
/// ```
///
/// ratio > 1 → blocks are too slow → difficulty decreases (bits increases)
/// ratio < 1 → blocks are too fast → difficulty increases (bits decreases)
pub fn compute_next_bits<S: DagStore>(
    tip: &Hash,
    store: &S,
    current_bits: u32,
) -> u32 {
    let (actual_interval, block_count) = compute_block_rate(tip, store, DAA_WINDOW_SIZE);

    // Not enough data → keep current
    if block_count < 10 {
        return current_bits;
    }

    // Avoid division by zero
    if actual_interval == 0 || TARGET_BLOCK_INTERVAL_MS == 0 {
        return current_bits;
    }

    // ratio = actual / target (fixed-point × 1000 for precision)
    let ratio_x1000 = (actual_interval as u128 * 1000) / (TARGET_BLOCK_INTERVAL_MS as u128);

    // Clamp ratio to [1/MAX_DIFFICULTY_RATIO, MAX_DIFFICULTY_RATIO]
    let min_ratio = 1000 / MAX_DIFFICULTY_RATIO as u128;
    let max_ratio = MAX_DIFFICULTY_RATIO as u128 * 1000;
    let clamped = ratio_x1000.max(min_ratio).min(max_ratio);

    // new_bits = current_bits * ratio
    let new_bits = (current_bits as u128 * clamped / 1000) as u32;

    // Minimum bits floor (prevent zero difficulty)
    new_bits.max(1)
}

// ═══════════════════════════════════════════════════════════════
//  Block Quality Check
// ═══════════════════════════════════════════════════════════════

/// ブロックの品質チェック結果。
#[derive(Debug, PartialEq, Eq)]
pub enum BlockQualityCheck {
    Ok,
    /// Bits (difficulty target) が期待値と不一致。
    BitsMismatch { declared: u32, expected: u32 },
    /// Timestamp が DAG context で無効。
    BadTimestamp(TimestampCheck),
}

/// ブロックの品質を DAA + timestamp で統合チェック。
pub fn check_block_quality<S: DagStore>(
    block_timestamp_ms: u64,
    block_bits: u32,
    parents: &[Hash],
    virtual_tip: &Hash,
    store: &S,
    now_ms: u64,
) -> BlockQualityCheck {
    // Timestamp check
    let ts_check = validate_timestamp(block_timestamp_ms, parents, store, now_ms);
    if ts_check != TimestampCheck::Valid {
        return BlockQualityCheck::BadTimestamp(ts_check);
    }

    // DAA bits check
    let existing_bits = store.get_header(virtual_tip)
        .map(|h| h.bits)
        .unwrap_or(INITIAL_BITS);
    let expected_bits = compute_next_bits(virtual_tip, store, existing_bits);

    if block_bits != expected_bits {
        return BlockQualityCheck::BitsMismatch {
            declared: block_bits,
            expected: expected_bits,
        };
    }

    BlockQualityCheck::Ok
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ghostdag::InMemoryDagStore;
    use crate::dag_block::{DagBlockHeader, GhostDagData, DAG_VERSION};

    fn h(b: u8) -> Hash { [b; 32] }

    fn make_chain_with_timestamps(timestamps: &[u64]) -> (InMemoryDagStore, Hash) {
        let mut store = InMemoryDagStore::new();
        let g = h(0);
        store.insert_header(g, DagBlockHeader {
            version: DAG_VERSION, parents: vec![], timestamp_ms: timestamps.first().copied().unwrap_or(0),
            tx_root: [0; 32], proposer_id: [0; 32], nonce: 0, blue_score: 0, bits: INITIAL_BITS,
        });
        store.set_ghostdag_data(g, GhostDagData {
            selected_parent: ZERO_HASH, mergeset_blues: vec![], mergeset_reds: vec![],
            blue_score: 0, blue_work: 0, blues_anticone_sizes: vec![],
        });

        let mut parent = g;
        for (i, &ts) in timestamps.iter().enumerate().skip(1) {
            let block = {
                let mut b = [0u8; 32];
                b[..4].copy_from_slice(&(i as u32).to_le_bytes());
                b
            };
            store.insert_header(block, DagBlockHeader {
                version: DAG_VERSION, parents: vec![parent], timestamp_ms: ts,
                tx_root: [0; 32], proposer_id: [0; 32], nonce: 0, blue_score: i as u64,
                bits: INITIAL_BITS,
            });
            store.set_ghostdag_data(block, GhostDagData {
                selected_parent: parent, mergeset_blues: vec![], mergeset_reds: vec![],
                blue_score: i as u64, blue_work: i as u128, blues_anticone_sizes: vec![],
            });
            parent = block;
        }
        (store, parent)
    }

    #[test]
    fn test_past_median_time_single_parent() {
        let mut store = InMemoryDagStore::new();
        let g = h(0);
        store.insert_header(g, DagBlockHeader {
            version: DAG_VERSION, parents: vec![], timestamp_ms: 1000,
            tx_root: [0; 32], proposer_id: [0; 32], nonce: 0, blue_score: 0, bits: 0,
        });
        assert_eq!(compute_past_median_time(&[g], &store), 1000);
    }

    #[test]
    fn test_past_median_time_multiple_parents() {
        let mut store = InMemoryDagStore::new();
        for (i, ts) in [(1, 100u64), (2, 300), (3, 200)] {
            let hash = h(i);
            store.insert_header(hash, DagBlockHeader {
                version: DAG_VERSION, parents: vec![], timestamp_ms: ts,
                tx_root: [0; 32], proposer_id: [0; 32], nonce: 0, blue_score: 0, bits: 0,
            });
        }
        // sorted: [100, 200, 300], median = 200
        assert_eq!(compute_past_median_time(&[h(1), h(2), h(3)], &store), 200);
    }

    #[test]
    fn test_timestamp_valid() {
        let mut store = InMemoryDagStore::new();
        store.insert_header(h(1), DagBlockHeader {
            version: DAG_VERSION, parents: vec![], timestamp_ms: 1000,
            tx_root: [0; 32], proposer_id: [0; 32], nonce: 0, blue_score: 0, bits: 0,
        });
        assert_eq!(
            validate_timestamp(1500, &[h(1)], &store, 2000),
            TimestampCheck::Valid,
        );
    }

    #[test]
    fn test_timestamp_too_old() {
        let mut store = InMemoryDagStore::new();
        store.insert_header(h(1), DagBlockHeader {
            version: DAG_VERSION, parents: vec![], timestamp_ms: 1000,
            tx_root: [0; 32], proposer_id: [0; 32], nonce: 0, blue_score: 0, bits: 0,
        });
        assert!(matches!(
            validate_timestamp(500, &[h(1)], &store, 2000),
            TimestampCheck::TooOld { .. },
        ));
    }

    #[test]
    fn test_timestamp_too_future() {
        let store = InMemoryDagStore::new();
        assert!(matches!(
            validate_timestamp(100_000, &[], &store, 10_000),
            TimestampCheck::TooFuture { .. },
        ));
    }

    #[test]
    fn test_block_rate_steady() {
        // 20 blocks, each 10s apart = 10000ms interval
        let timestamps: Vec<u64> = (0..20).map(|i| i * 10_000).collect();
        let (store, tip) = make_chain_with_timestamps(&timestamps);

        let (avg, count) = compute_block_rate(&tip, &store, 100);
        assert!(count >= 10);
        // avg should be close to 10000ms
        assert!(avg >= 9000 && avg <= 11000, "avg={}", avg);
    }

    #[test]
    fn test_compute_next_bits_stable() {
        // Blocks at target interval → bits should stay roughly the same
        let timestamps: Vec<u64> = (0..50).map(|i| i * TARGET_BLOCK_INTERVAL_MS).collect();
        let (store, tip) = make_chain_with_timestamps(&timestamps);

        let new_bits = compute_next_bits(&tip, &store, INITIAL_BITS);
        // Should be close to INITIAL_BITS (within 10%)
        let ratio = new_bits as f64 / INITIAL_BITS as f64;
        assert!(ratio > 0.9 && ratio < 1.1, "ratio={}", ratio);
    }

    #[test]
    fn test_compute_next_bits_too_fast() {
        // Blocks 2x faster than target → difficulty should increase (bits decrease)
        let timestamps: Vec<u64> = (0..50).map(|i| i * (TARGET_BLOCK_INTERVAL_MS / 2)).collect();
        let (store, tip) = make_chain_with_timestamps(&timestamps);

        let new_bits = compute_next_bits(&tip, &store, INITIAL_BITS);
        assert!(new_bits < INITIAL_BITS, "bits should decrease: {} vs {}", new_bits, INITIAL_BITS);
    }

    #[test]
    fn test_compute_next_bits_too_slow() {
        // Blocks 2x slower → difficulty should decrease (bits increase)
        let timestamps: Vec<u64> = (0..50).map(|i| i * (TARGET_BLOCK_INTERVAL_MS * 2)).collect();
        let (store, tip) = make_chain_with_timestamps(&timestamps);

        let new_bits = compute_next_bits(&tip, &store, INITIAL_BITS);
        assert!(new_bits > INITIAL_BITS, "bits should increase: {} vs {}", new_bits, INITIAL_BITS);
    }
}
