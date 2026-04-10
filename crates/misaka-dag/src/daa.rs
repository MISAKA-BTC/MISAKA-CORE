//! DAA (Difficulty Adjustment Algorithm) — Constants only.
//!
//! With Narwhal/Bullshark, there is no PoW difficulty.
//! Block timing is controlled by the ThresholdClock (round-based).
//!
//! This module retains the timing constants used by various subsystems.

/// DAA window size (blocks).
pub const DAA_WINDOW_SIZE: u64 = 2641;

/// Target block interval (milliseconds) — SSOT from misaka-types.
pub const TARGET_BLOCK_INTERVAL_MS: u64 = misaka_types::constants::TARGET_BLOCK_INTERVAL_MS;

/// Maximum future drift (milliseconds).
pub const MAX_FUTURE_DRIFT_MS: u64 = 30_000;

/// Bounded median window size.
pub const BOUNDED_MEDIAN_WINDOW: usize = 263;

/// Blocks per epoch.
pub const BLOCKS_PER_EPOCH: u64 = 43_200;

/// Initial difficulty bits.
pub const INITIAL_BITS: u32 = 0x207f_ffff;

/// 32-byte block hash type.
pub type Hash = [u8; 32];

/// DAA score (cumulative difficulty).
pub type DaaScore = u64;

/// Timestamp validity check result.
#[derive(Debug, Clone, PartialEq)]
pub enum TimestampCheck {
    Valid,
    TooFarInFuture { block_ts: u64, max_ts: u64 },
    BeforePastMedian { block_ts: u64, median_ts: u64 },
}

/// DAA window block entry.
#[derive(Debug, Clone)]
pub struct DaaWindowBlock {
    pub hash: Hash,
    pub timestamp: u64,
    pub blue_score: u64,
}

/// DAA window.
pub type DaaWindow = Vec<DaaWindowBlock>;

/// Validate a block timestamp.
///
/// `now_ms` is the current time in milliseconds since Unix epoch.
/// In production, pass `clock.now_millis()`. In tests, pass a fixed value.
pub fn validate_timestamp(block_ts: u64, past_median: u64, max_future: u64) -> TimestampCheck {
    // Phase 0-2 completion: uses SystemClock by default.
    // Callers in deterministic contexts should use validate_timestamp_at().
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    validate_timestamp_at(block_ts, past_median, max_future, now)
}

/// Validate a block timestamp against a specific "now" (for deterministic testing).
pub fn validate_timestamp_at(
    block_ts: u64,
    past_median: u64,
    max_future: u64,
    now: u64,
) -> TimestampCheck {
    if block_ts > now + max_future {
        return TimestampCheck::TooFarInFuture {
            block_ts,
            max_ts: now + max_future,
        };
    }
    if block_ts < past_median {
        return TimestampCheck::BeforePastMedian {
            block_ts,
            median_ts: past_median,
        };
    }
    TimestampCheck::Valid
}

/// Compute past median time from timestamps.
pub fn compute_past_median_time(timestamps: &[u64]) -> u64 {
    if timestamps.is_empty() {
        return 0;
    }
    let mut sorted = timestamps.to_vec();
    sorted.sort();
    sorted[sorted.len() / 2]
}

/// Compute bounded past median time.
pub fn compute_bounded_past_median_time(timestamps: &[u64]) -> u64 {
    let window: Vec<u64> = timestamps
        .iter()
        .rev()
        .take(BOUNDED_MEDIAN_WINDOW)
        .copied()
        .collect();
    compute_past_median_time(&window)
}

/// Compute block rate (blocks per second).
pub fn compute_block_rate(window: &[DaaWindowBlock]) -> f64 {
    if window.len() < 2 {
        return 0.0;
    }
    let time_span = window
        .last()
        .unwrap()
        .timestamp
        .saturating_sub(window.first().unwrap().timestamp);
    if time_span == 0 {
        return 0.0;
    }
    (window.len() as f64 - 1.0) / (time_span as f64 / 1000.0)
}

/// Compute epoch from block height.
pub fn compute_epoch(height: u64) -> u64 {
    height / BLOCKS_PER_EPOCH
}
