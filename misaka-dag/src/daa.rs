//! DAA (Difficulty Adjustment Algorithm) — Consensus-Integrated Block Rate Control (v9).
//!
//! # v8 → v9: DAA を consensus の中核に統合
//!
//! v8 では DAA は補助ユーティリティだった:
//! - `past_median_time` は direct parents の中央値のみ
//! - `block_processor.rs` から DAA bits 検証が呼ばれていなかった
//! - `dag_block_producer.rs` で `epoch: 0 // TODO` が残存
//!
//! v9 では Kaspa 寄りの設計に全面移行:
//! 1. **DAA Window**: SP chain 上の直近 N ブロックを固定ウィンドウとして使用
//! 2. **Bounded Past Median Time**: direct parents ではなく SP chain 上の
//!    DAA window 内のサンプルから中央値を計算
//! 3. **DAA Score**: `blue_score` とは独立した DAA 固有のスコアリング
//! 4. **Epoch 算出**: DAA window から epoch 番号を導出
//! 5. **Proposer Cadence**: block producer が DAA ベースで生成間隔を決定
//!
//! # MISAKA DAA
//!
//! MISAKA は PoS ベースのため、difficulty = "proposer eligibility threshold"。
//! block rate 制御は timestamp ベースで行い、DAA window から算出した
//! 実効 block rate が目標に近づくよう bits (difficulty target) を調整する。

use crate::dag_block::{Hash, ZERO_HASH};
use crate::ghostdag::DagStore;

// ═══════════════════════════════════════════════════════════════
//  DAA Constants
// ═══════════════════════════════════════════════════════════════

/// DAA window size (SP chain 上のブロック数)。
pub const DAA_WINDOW_SIZE: u64 = 2641;

/// 目標ブロック間隔 (milliseconds)。
pub const TARGET_BLOCK_INTERVAL_MS: u64 = 10_000;

/// 最大 future drift (milliseconds)。
pub const MAX_FUTURE_DRIFT_MS: u64 = 30_000;

/// Difficulty 調整の最大倍率 (上下)。
pub const MAX_DIFFICULTY_RATIO: u64 = 4;

/// 初期 difficulty bits。
pub const INITIAL_BITS: u32 = 0x2000_0000;

/// Bounded past median time: SP chain 上のサンプル数。
/// Kaspa は 2*k+1。MISAKA は 2*DEFAULT_K+1 = 37。
pub const BOUNDED_MEDIAN_WINDOW: usize = 37;

/// Epoch ごとのブロック数 (DAA score ベース)。
pub const BLOCKS_PER_EPOCH: u64 = DAA_WINDOW_SIZE;

// ═══════════════════════════════════════════════════════════════
//  DAA Window — SP Chain 上の固定ウィンドウ
// ═══════════════════════════════════════════════════════════════

/// SP chain 上の DAA window を表すデータ構造。
///
/// Kaspa の DAA window は selected parent chain 上の直近 N ブロックで構成。
/// side branch の timestamp manipulation に耐性あり。
#[derive(Debug, Clone)]
pub struct DaaWindow {
    /// SP chain 上のブロック群 (newest → oldest 順)。
    pub blocks: Vec<DaaWindowBlock>,
}

#[derive(Debug, Clone, Copy)]
pub struct DaaWindowBlock {
    pub hash: Hash,
    pub timestamp_ms: u64,
    pub blue_score: u64,
}

impl DaaWindow {
    /// SP chain 上の直近 `window_size` ブロックから DAA window を構築。
    pub fn build<S: DagStore>(tip: &Hash, store: &S, window_size: u64) -> Self {
        let mut blocks = Vec::with_capacity(window_size as usize);
        let mut current = *tip;

        // tip 自身を含める
        if let Some(header) = store.get_header(&current) {
            let blue_score = store
                .get_ghostdag_data(&current)
                .map(|d| d.blue_score)
                .unwrap_or(0);
            blocks.push(DaaWindowBlock {
                hash: current,
                timestamp_ms: header.timestamp_ms,
                blue_score,
            });
        }

        // SP chain を遡る
        loop {
            if blocks.len() as u64 >= window_size {
                break;
            }
            if let Some(data) = store.get_ghostdag_data(&current) {
                if data.selected_parent == ZERO_HASH {
                    break;
                }
                let sp = data.selected_parent;
                if let Some(header) = store.get_header(&sp) {
                    let sp_score = store
                        .get_ghostdag_data(&sp)
                        .map(|d| d.blue_score)
                        .unwrap_or(0);
                    blocks.push(DaaWindowBlock {
                        hash: sp,
                        timestamp_ms: header.timestamp_ms,
                        blue_score: sp_score,
                    });
                    current = sp;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        Self { blocks }
    }

    pub fn len(&self) -> usize {
        self.blocks.len()
    }
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    pub fn newest_timestamp(&self) -> Option<u64> {
        self.blocks.first().map(|b| b.timestamp_ms)
    }

    pub fn oldest_timestamp(&self) -> Option<u64> {
        self.blocks.last().map(|b| b.timestamp_ms)
    }

    pub fn time_span(&self) -> u64 {
        match (self.newest_timestamp(), self.oldest_timestamp()) {
            (Some(newest), Some(oldest)) => newest.saturating_sub(oldest),
            _ => 0,
        }
    }

    pub fn average_interval(&self) -> u64 {
        let span = self.time_span();
        let count = self.blocks.len().saturating_sub(1) as u64;
        if count == 0 {
            return TARGET_BLOCK_INTERVAL_MS;
        }
        span / count
    }
}

// ═══════════════════════════════════════════════════════════════
//  Bounded Past Median Time — SP Chain ベース
// ═══════════════════════════════════════════════════════════════

/// SP chain ベースの bounded past median time を計算。
///
/// v8: direct parents の timestamp の中央値 (操作に弱い)
/// v9: SP chain 上の直近 BOUNDED_MEDIAN_WINDOW ブロックの timestamp の中央値
///
/// SP chain 上のブロックのみを使うことで、攻撃者が timestamp を
/// 操作するのに必要な stake 量が格段に上がる。
pub fn compute_bounded_past_median_time<S: DagStore>(parents: &[Hash], store: &S) -> u64 {
    if parents.is_empty() {
        return 0;
    }

    let selected_parent = select_best_parent(parents, store);
    let window = DaaWindow::build(&selected_parent, store, BOUNDED_MEDIAN_WINDOW as u64);

    if window.len() >= 3 {
        let mut timestamps: Vec<u64> = window.blocks.iter().map(|b| b.timestamp_ms).collect();
        timestamps.sort_unstable();
        let mid = timestamps.len() / 2;
        return timestamps[mid];
    }

    // Fallback: direct parents median (genesis 付近)
    compute_direct_parents_median(parents, store)
}

/// direct parents の timestamp の中央値 (v8 互換、fallback 用)。
pub fn compute_direct_parents_median<S: DagStore>(parents: &[Hash], store: &S) -> u64 {
    if parents.is_empty() {
        return 0;
    }

    let mut timestamps: Vec<u64> = parents
        .iter()
        .filter_map(|p| store.get_header(p).map(|h| h.timestamp_ms))
        .collect();

    if timestamps.is_empty() {
        return 0;
    }

    timestamps.sort_unstable();
    let mid = timestamps.len() / 2;
    if timestamps.len() % 2 == 0 {
        (timestamps[mid - 1] + timestamps[mid]) / 2
    } else {
        timestamps[mid]
    }
}

fn select_best_parent<S: DagStore>(parents: &[Hash], store: &S) -> Hash {
    parents
        .iter()
        .max_by_key(|p| {
            store
                .get_ghostdag_data(p)
                .map(|d| (d.blue_work, d.blue_score))
                .unwrap_or((0, 0))
        })
        .copied()
        .unwrap_or(ZERO_HASH)
}

/// v8 互換 API — bounded PMT にアップグレード。
pub fn compute_past_median_time<S: DagStore>(parents: &[Hash], store: &S) -> u64 {
    compute_bounded_past_median_time(parents, store)
}

// ═══════════════════════════════════════════════════════════════
//  Timestamp Validation
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, PartialEq, Eq)]
pub enum TimestampCheck {
    Valid,
    TooOld { block_ms: u64, past_median_ms: u64 },
    TooFuture { block_ms: u64, max_ms: u64 },
}

pub fn validate_timestamp<S: DagStore>(
    block_timestamp_ms: u64,
    parents: &[Hash],
    store: &S,
    now_ms: u64,
) -> TimestampCheck {
    let pmt = compute_bounded_past_median_time(parents, store);
    if block_timestamp_ms < pmt {
        return TimestampCheck::TooOld {
            block_ms: block_timestamp_ms,
            past_median_ms: pmt,
        };
    }

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

pub fn compute_block_rate<S: DagStore>(tip: &Hash, store: &S, window_size: u64) -> (u64, u64) {
    let window = DaaWindow::build(tip, store, window_size);
    if window.len() < 2 {
        return (TARGET_BLOCK_INTERVAL_MS, window.len() as u64);
    }
    (window.average_interval(), window.len() as u64)
}

// ═══════════════════════════════════════════════════════════════
//  Difficulty Adjustment
// ═══════════════════════════════════════════════════════════════

pub fn compute_next_bits<S: DagStore>(tip: &Hash, store: &S, current_bits: u32) -> u32 {
    let (actual_interval, block_count) = compute_block_rate(tip, store, DAA_WINDOW_SIZE);

    if block_count < 10 {
        return current_bits;
    }
    if actual_interval == 0 || TARGET_BLOCK_INTERVAL_MS == 0 {
        return current_bits;
    }

    let ratio_x1000 = (actual_interval as u128 * 1000) / (TARGET_BLOCK_INTERVAL_MS as u128);
    let min_ratio = 1000 / MAX_DIFFICULTY_RATIO as u128;
    let max_ratio = MAX_DIFFICULTY_RATIO as u128 * 1000;
    let clamped = ratio_x1000.max(min_ratio).min(max_ratio);
    let new_bits = (current_bits as u128 * clamped / 1000) as u32;
    new_bits.max(1)
}

// ═══════════════════════════════════════════════════════════════
//  DAA Score & Epoch
// ═══════════════════════════════════════════════════════════════

/// DAA Score — blue_score とは独立した DAA 固有の ordering score。
///
/// | 属性 | blue_score | daa_score |
/// |------|-----------|-----------|
/// | 定義 | mergeset blues の累積 | SP chain depth |
/// | 用途 | GhostDAG ordering | difficulty, epoch |
/// | 操作耐性 | side branch blue injection に弱い | SP chain 固定で高い |
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DaaScore(pub u64);

impl DaaScore {
    /// SP chain 上の depth から DAA score を計算。
    pub fn compute<S: DagStore>(tip: &Hash, store: &S) -> Self {
        let mut depth = 0u64;
        let mut current = *tip;
        loop {
            if let Some(data) = store.get_ghostdag_data(&current) {
                if data.selected_parent == ZERO_HASH {
                    break;
                }
                depth += 1;
                current = data.selected_parent;
            } else {
                break;
            }
        }
        Self(depth)
    }

    /// DAA score から epoch 番号を算出。
    pub fn epoch(&self) -> u64 {
        self.0 / BLOCKS_PER_EPOCH
    }

    pub fn epoch_offset(&self) -> u64 {
        self.0 % BLOCKS_PER_EPOCH
    }
}

/// tip から DAA epoch を算出。`epoch: 0 // TODO` の解消用。
pub fn compute_epoch<S: DagStore>(tip: &Hash, store: &S) -> u64 {
    DaaScore::compute(tip, store).epoch()
}

// ═══════════════════════════════════════════════════════════════
//  Proposer Cadence
// ═══════════════════════════════════════════════════════════════

/// DAA ベースの proposer cadence (ブロック生成間隔推奨値)。
pub fn compute_proposer_cadence_ms<S: DagStore>(tip: &Hash, store: &S) -> u64 {
    let (actual_interval, block_count) = compute_block_rate(tip, store, DAA_WINDOW_SIZE);
    if block_count < 10 {
        return TARGET_BLOCK_INTERVAL_MS;
    }
    let min_cadence = TARGET_BLOCK_INTERVAL_MS / MAX_DIFFICULTY_RATIO;
    let max_cadence = TARGET_BLOCK_INTERVAL_MS * MAX_DIFFICULTY_RATIO;

    let cadence = if actual_interval > 0 {
        (TARGET_BLOCK_INTERVAL_MS as u128 * TARGET_BLOCK_INTERVAL_MS as u128
            / actual_interval as u128) as u64
    } else {
        TARGET_BLOCK_INTERVAL_MS
    };

    cadence.max(min_cadence).min(max_cadence)
}

// ═══════════════════════════════════════════════════════════════
//  Block Quality Check
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, PartialEq, Eq)]
pub enum BlockQualityCheck {
    Ok,
    BitsMismatch { declared: u32, expected: u32 },
    BadTimestamp(TimestampCheck),
}

pub fn check_block_quality<S: DagStore>(
    block_timestamp_ms: u64,
    block_bits: u32,
    parents: &[Hash],
    virtual_tip: &Hash,
    store: &S,
    now_ms: u64,
) -> BlockQualityCheck {
    let ts_check = validate_timestamp(block_timestamp_ms, parents, store, now_ms);
    if ts_check != TimestampCheck::Valid {
        return BlockQualityCheck::BadTimestamp(ts_check);
    }

    let existing_bits = store
        .get_header(virtual_tip)
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
    use crate::dag_block::{DagBlockHeader, GhostDagData, DAG_VERSION};
    use crate::ghostdag::InMemoryDagStore;

    fn h(b: u8) -> Hash {
        [b; 32]
    }

    fn make_chain_with_timestamps(timestamps: &[u64]) -> (InMemoryDagStore, Hash) {
        let mut store = InMemoryDagStore::new();
        let g = h(0);
        store.insert_header(
            g,
            DagBlockHeader {
                version: DAG_VERSION,
                parents: vec![],
                timestamp_ms: timestamps.first().copied().unwrap_or(0),
                tx_root: [0; 32],
                proposer_id: [0; 32],
                nonce: 0,
                blue_score: 0,
                bits: INITIAL_BITS,
            },
        );
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

        let mut parent = g;
        for (i, &ts) in timestamps.iter().enumerate().skip(1) {
            let block = {
                let mut b = [0u8; 32];
                b[..4].copy_from_slice(&(i as u32).to_le_bytes());
                b
            };
            store.insert_header(
                block,
                DagBlockHeader {
                    version: DAG_VERSION,
                    parents: vec![parent],
                    timestamp_ms: ts,
                    tx_root: [0; 32],
                    proposer_id: [0; 32],
                    nonce: 0,
                    blue_score: i as u64,
                    bits: INITIAL_BITS,
                },
            );
            store.set_ghostdag_data(
                block,
                GhostDagData {
                    selected_parent: parent,
                    mergeset_blues: vec![],
                    mergeset_reds: vec![],
                    blue_score: i as u64,
                    blue_work: i as u128,
                    blues_anticone_sizes: vec![],
                },
            );
            parent = block;
        }
        (store, parent)
    }

    #[test]
    fn test_daa_window_build() {
        let timestamps: Vec<u64> = (0..50).map(|i| i * 10_000).collect();
        let (store, tip) = make_chain_with_timestamps(&timestamps);
        let window = DaaWindow::build(&tip, &store, 20);
        assert_eq!(window.len(), 20);
        assert!(window.blocks[0].timestamp_ms > window.blocks[19].timestamp_ms);
    }

    #[test]
    fn test_bounded_past_median_time() {
        let timestamps: Vec<u64> = (0..50).map(|i| i * 10_000).collect();
        let (store, tip) = make_chain_with_timestamps(&timestamps);
        let pmt = compute_bounded_past_median_time(&[tip], &store);
        assert!(pmt > 0);
    }

    #[test]
    fn test_direct_parents_median_single_parent() {
        let mut store = InMemoryDagStore::new();
        let g = h(0);
        store.insert_header(
            g,
            DagBlockHeader {
                version: DAG_VERSION,
                parents: vec![],
                timestamp_ms: 1000,
                tx_root: [0; 32],
                proposer_id: [0; 32],
                nonce: 0,
                blue_score: 0,
                bits: 0,
            },
        );
        assert_eq!(compute_direct_parents_median(&[g], &store), 1000);
    }

    #[test]
    fn test_timestamp_valid() {
        let mut store = InMemoryDagStore::new();
        store.insert_header(
            h(1),
            DagBlockHeader {
                version: DAG_VERSION,
                parents: vec![],
                timestamp_ms: 1000,
                tx_root: [0; 32],
                proposer_id: [0; 32],
                nonce: 0,
                blue_score: 0,
                bits: 0,
            },
        );
        store.set_ghostdag_data(
            h(1),
            GhostDagData {
                selected_parent: ZERO_HASH,
                ..Default::default()
            },
        );
        assert_eq!(
            validate_timestamp(1500, &[h(1)], &store, 2000),
            TimestampCheck::Valid,
        );
    }

    #[test]
    fn test_block_rate_steady() {
        let timestamps: Vec<u64> = (0..20).map(|i| i * 10_000).collect();
        let (store, tip) = make_chain_with_timestamps(&timestamps);
        let (avg, count) = compute_block_rate(&tip, &store, 100);
        assert!(count >= 10);
        assert!(avg >= 9000 && avg <= 11000, "avg={}", avg);
    }

    #[test]
    fn test_compute_next_bits_stable() {
        let timestamps: Vec<u64> = (0..50).map(|i| i * TARGET_BLOCK_INTERVAL_MS).collect();
        let (store, tip) = make_chain_with_timestamps(&timestamps);
        let new_bits = compute_next_bits(&tip, &store, INITIAL_BITS);
        let ratio = new_bits as f64 / INITIAL_BITS as f64;
        assert!(ratio > 0.9 && ratio < 1.1, "ratio={}", ratio);
    }

    #[test]
    fn test_daa_score_and_epoch() {
        let timestamps: Vec<u64> = (0..100).map(|i| i * 10_000).collect();
        let (store, tip) = make_chain_with_timestamps(&timestamps);
        let score = DaaScore::compute(&tip, &store);
        assert!(score.0 > 0);
        assert_eq!(score.epoch(), 0);
    }

    #[test]
    fn test_proposer_cadence_default() {
        let mut store = InMemoryDagStore::new();
        let g = h(0);
        store.insert_header(
            g,
            DagBlockHeader {
                version: DAG_VERSION,
                parents: vec![],
                timestamp_ms: 0,
                tx_root: [0; 32],
                proposer_id: [0; 32],
                nonce: 0,
                blue_score: 0,
                bits: 0,
            },
        );
        store.set_ghostdag_data(
            g,
            GhostDagData {
                selected_parent: ZERO_HASH,
                ..Default::default()
            },
        );
        let cadence = compute_proposer_cadence_ms(&g, &store);
        assert_eq!(cadence, TARGET_BLOCK_INTERVAL_MS);
    }
}
