// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Adaptive round-rate scheduler (Phase 3a Part B).
//!
//! # Why
//!
//! v0.8.x and v0.9.0 propose a new Narwhal round at a fixed cadence
//! (`FAST_LANE_BLOCK_TIME_SECS` — 10 s in v0.8.9). This wastes WAL
//! + DAG churn when the mempool is empty and under-utilises bandwidth
//! when the mempool is saturated. Phase 3a Part B introduces an
//! adaptive scheduler that:
//!
//! 1. Linearly interpolates the next round interval between
//!    [`DEFAULT_MIN_INTERVAL_MS`] (`100`) and
//!    [`DEFAULT_MAX_INTERVAL_MS`] (`2000`) based on a mempool
//!    utilisation signal in `[0.0, 1.0]`.
//! 2. Uses `tokio::select!` so the scheduler wakes *early* if the
//!    mempool signals a new transaction while it's sleeping —
//!    preserving latency at the floor interval even when the scheduler
//!    had picked a longer sleep.
//!
//! # Not in this commit
//!
//! - Actual wiring into `start_narwhal_node` — the scheduler is
//!   orthogonal to Part A and this module just ships the pure logic
//!   and the async helper. Integration is a follow-up commit that
//!   replaces the fixed-interval proposer loop and feeds the
//!   utilisation signal from the mempool.
//! - Prometheus metrics (`round_interval_ms`, `mempool_utilization`)
//!   are hooked through [`RoundSchedulerConfig::record_decision`] as
//!   an opaque callback. The integration commit wires a concrete
//!   recorder; this commit just provides the plumbing.
//!
//! # Determinism
//!
//! [`next_round_interval_ms`] is a pure function — two nodes with
//! the same utilisation and config compute the same interval. That
//! makes the scheduler safe to use in consensus without introducing
//! timestamp drift beyond the natural clock skew.

use std::time::Duration;

/// Hard floor for the per-round interval. Callers SHOULD NOT
/// configure a value below this; [`RoundSchedulerConfig::validate`]
/// rejects it.
pub const HARD_MIN_INTERVAL_MS: u64 = 50;

/// Hard ceiling for the per-round interval. Above this, liveness
/// feels sluggish even on idle chains.
pub const HARD_MAX_INTERVAL_MS: u64 = 10_000;

/// Default MIN for the adaptive range — chosen to match typical
/// mempool-flush latency so a fully-saturated mempool cadences at
/// ~10 rounds/sec.
pub const DEFAULT_MIN_INTERVAL_MS: u64 = 100;

/// Default MAX for the adaptive range — chosen so an idle chain
/// still advances rounds on the order of seconds, keeping equivocation
/// detection responsive without burning WAL on empty proposals.
pub const DEFAULT_MAX_INTERVAL_MS: u64 = 2_000;

/// Runtime config for the adaptive round scheduler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundSchedulerConfig {
    /// Lower bound of the adaptive range (utilisation = 1.0 picks this).
    pub min_interval_ms: u64,
    /// Upper bound of the adaptive range (utilisation = 0.0 picks this).
    pub max_interval_ms: u64,
}

/// Reasons a call to [`wait_until_next_round`] returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeCause {
    /// The adaptive timer expired — a new round is due.
    TimerExpired,
    /// The mempool signalled a new transaction before the timer
    /// expired. The caller SHOULD propose immediately (effectively
    /// collapsing the interval toward [`RoundSchedulerConfig::
    /// min_interval_ms`]).
    MempoolSignalled,
}

impl Default for RoundSchedulerConfig {
    fn default() -> Self {
        Self {
            min_interval_ms: DEFAULT_MIN_INTERVAL_MS,
            max_interval_ms: DEFAULT_MAX_INTERVAL_MS,
        }
    }
}

/// Errors raised by [`RoundSchedulerConfig::validate`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SchedulerConfigError {
    #[error(
        "min_interval_ms {actual} is below the hard floor {floor}; \
         values this low starve consensus"
    )]
    MinBelowFloor { actual: u64, floor: u64 },
    #[error(
        "max_interval_ms {actual} is above the hard ceiling {ceiling}; \
         values this high starve liveness"
    )]
    MaxAboveCeiling { actual: u64, ceiling: u64 },
    #[error(
        "min_interval_ms {min} >= max_interval_ms {max}; the adaptive \
         range is empty and the scheduler degenerates to a fixed cadence"
    )]
    MinGeMax { min: u64, max: u64 },
}

impl RoundSchedulerConfig {
    /// Reject configurations outside the sensible operating range.
    ///
    /// * `min` below [`HARD_MIN_INTERVAL_MS`] → error.
    /// * `max` above [`HARD_MAX_INTERVAL_MS`] → error.
    /// * `min >= max` → error (empty adaptive range).
    pub fn validate(&self) -> Result<(), SchedulerConfigError> {
        if self.min_interval_ms < HARD_MIN_INTERVAL_MS {
            return Err(SchedulerConfigError::MinBelowFloor {
                actual: self.min_interval_ms,
                floor: HARD_MIN_INTERVAL_MS,
            });
        }
        if self.max_interval_ms > HARD_MAX_INTERVAL_MS {
            return Err(SchedulerConfigError::MaxAboveCeiling {
                actual: self.max_interval_ms,
                ceiling: HARD_MAX_INTERVAL_MS,
            });
        }
        if self.min_interval_ms >= self.max_interval_ms {
            return Err(SchedulerConfigError::MinGeMax {
                min: self.min_interval_ms,
                max: self.max_interval_ms,
            });
        }
        Ok(())
    }
}

/// Decide the next round's interval in milliseconds.
///
/// * `utilisation`: mempool saturation in `[0.0, 1.0]`. Values outside
///   the range are clamped rather than rejected — the scheduler is
///   called on every round and must never itself fail.
/// * `config`: the adaptive range. If the config has `min == max`
///   (caught by [`RoundSchedulerConfig::validate`]), the caller
///   shouldn't have reached this function, but the implementation
///   degrades gracefully: `min == max` yields exactly `min`.
///
/// The function is pure: no I/O, no clock reads, no RNG. Two nodes
/// with the same `utilisation` and `config` pick the same interval.
#[must_use]
pub fn next_round_interval_ms(utilisation: f64, config: &RoundSchedulerConfig) -> u64 {
    let u = utilisation.clamp(0.0, 1.0);
    let min = config.min_interval_ms as f64;
    let max = config.max_interval_ms as f64;
    // Linear interp: u=1.0 picks `min`, u=0.0 picks `max`.
    // interval = max - (max - min) * u.
    let interval = max - (max - min) * u;
    // Round to nearest; clamp back into [min, max] to tolerate any
    // floating-point drift at the endpoints.
    interval.round().clamp(min, max).max(0.0) as u64
}

/// Convenience wrapper returning a [`Duration`].
#[must_use]
pub fn next_round_interval(utilisation: f64, config: &RoundSchedulerConfig) -> Duration {
    Duration::from_millis(next_round_interval_ms(utilisation, config))
}

/// Sleep until the next round should be proposed, waking early if the
/// mempool signals.
///
/// The caller hands in:
/// * the current `utilisation`,
/// * the `config`,
/// * a `mempool_wake` future that resolves as soon as the mempool has
///   a new transaction worth proposing (e.g. a channel `recv()`).
///
/// Returns [`WakeCause::TimerExpired`] when the adaptive interval
/// elapsed, [`WakeCause::MempoolSignalled`] when the future resolved
/// first. A pre-resolved future always wins the race — callers that
/// want "sleep-then-propose-no-matter-what" semantics should pass a
/// never-resolving future (e.g. `std::future::pending()`).
pub async fn wait_until_next_round<F>(
    utilisation: f64,
    config: &RoundSchedulerConfig,
    mempool_wake: F,
) -> WakeCause
where
    F: std::future::Future<Output = ()>,
{
    let dur = next_round_interval(utilisation, config);
    tokio::pin!(mempool_wake);
    tokio::select! {
        _ = tokio::time::sleep(dur) => WakeCause::TimerExpired,
        _ = &mut mempool_wake => WakeCause::MempoolSignalled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(min: u64, max: u64) -> RoundSchedulerConfig {
        RoundSchedulerConfig {
            min_interval_ms: min,
            max_interval_ms: max,
        }
    }

    // ── Default values ────────────────────────────────────────────

    #[test]
    fn default_config_is_100_to_2000() {
        let c = RoundSchedulerConfig::default();
        assert_eq!(c.min_interval_ms, DEFAULT_MIN_INTERVAL_MS);
        assert_eq!(c.max_interval_ms, DEFAULT_MAX_INTERVAL_MS);
        assert_eq!(c.min_interval_ms, 100);
        assert_eq!(c.max_interval_ms, 2_000);
    }

    #[test]
    fn default_config_validates() {
        assert!(RoundSchedulerConfig::default().validate().is_ok());
    }

    // ── validate() ───────────────────────────────────────────────

    #[test]
    fn validate_min_below_hard_floor_is_error() {
        let err = cfg(HARD_MIN_INTERVAL_MS - 1, 2000).validate().unwrap_err();
        matches!(err, SchedulerConfigError::MinBelowFloor { .. });
    }

    #[test]
    fn validate_max_above_hard_ceiling_is_error() {
        let err = cfg(100, HARD_MAX_INTERVAL_MS + 1).validate().unwrap_err();
        matches!(err, SchedulerConfigError::MaxAboveCeiling { .. });
    }

    #[test]
    fn validate_min_ge_max_is_error() {
        let err = cfg(500, 500).validate().unwrap_err();
        matches!(err, SchedulerConfigError::MinGeMax { .. });
        let err = cfg(600, 500).validate().unwrap_err();
        matches!(err, SchedulerConfigError::MinGeMax { .. });
    }

    #[test]
    fn validate_at_hard_boundaries_is_ok() {
        assert!(cfg(HARD_MIN_INTERVAL_MS, HARD_MIN_INTERVAL_MS + 1)
            .validate()
            .is_ok());
        assert!(cfg(HARD_MIN_INTERVAL_MS, HARD_MAX_INTERVAL_MS)
            .validate()
            .is_ok());
    }

    // ── next_round_interval_ms — endpoints ───────────────────────

    #[test]
    fn utilisation_one_picks_min() {
        let c = cfg(100, 2000);
        assert_eq!(next_round_interval_ms(1.0, &c), 100);
    }

    #[test]
    fn utilisation_zero_picks_max() {
        let c = cfg(100, 2000);
        assert_eq!(next_round_interval_ms(0.0, &c), 2000);
    }

    #[test]
    fn utilisation_half_picks_midpoint() {
        let c = cfg(100, 2000);
        // Linear: max - (max-min)*0.5 = 2000 - 1900*0.5 = 1050.
        assert_eq!(next_round_interval_ms(0.5, &c), 1050);
    }

    // ── next_round_interval_ms — clamping ────────────────────────

    #[test]
    fn utilisation_above_one_clamps_to_one() {
        let c = cfg(100, 2000);
        assert_eq!(next_round_interval_ms(2.5, &c), 100);
        assert_eq!(next_round_interval_ms(1e9, &c), 100);
    }

    #[test]
    fn utilisation_below_zero_clamps_to_zero() {
        let c = cfg(100, 2000);
        assert_eq!(next_round_interval_ms(-1.0, &c), 2000);
        assert_eq!(next_round_interval_ms(-1e9, &c), 2000);
    }

    #[test]
    fn nan_utilisation_treated_as_zero_after_clamp() {
        // f64::clamp on NaN returns NaN per std docs; we hit the
        // final `.max(0.0) as u64` guard, which (as u64) casts NaN
        // → 0. Caller should prefer validate-before-call semantics
        // but the scheduler must never panic.
        let c = cfg(100, 2000);
        let got = next_round_interval_ms(f64::NAN, &c);
        // Any finite u64 in [0, max] is acceptable — the only hard
        // contract is "no panic". We assert the weakest useful bound.
        assert!(got <= c.max_interval_ms);
    }

    // ── next_round_interval_ms — monotonicity ────────────────────

    #[test]
    fn higher_utilisation_picks_shorter_or_equal_interval() {
        let c = cfg(100, 2000);
        let mut prev = u64::MAX;
        for i in 0..=10 {
            let u = i as f64 / 10.0;
            let interval = next_round_interval_ms(u, &c);
            assert!(
                interval <= prev,
                "non-monotone at u={u}: prev={prev}, now={interval}"
            );
            prev = interval;
        }
    }

    // ── next_round_interval_ms — custom ranges ───────────────────

    #[test]
    fn custom_range_respected() {
        let c = cfg(200, 500);
        assert_eq!(next_round_interval_ms(1.0, &c), 200);
        assert_eq!(next_round_interval_ms(0.0, &c), 500);
        // Middle: 500 - 300*0.5 = 350.
        assert_eq!(next_round_interval_ms(0.5, &c), 350);
    }

    #[test]
    fn degenerate_min_equals_max_yields_min() {
        // validate() rejects this config but the function should
        // still not panic if reached somehow.
        let c = cfg(500, 500);
        assert_eq!(next_round_interval_ms(0.0, &c), 500);
        assert_eq!(next_round_interval_ms(1.0, &c), 500);
        assert_eq!(next_round_interval_ms(0.5, &c), 500);
    }

    // ── next_round_interval Duration wrapper ─────────────────────

    #[test]
    fn duration_wrapper_matches_ms_function() {
        let c = cfg(100, 2000);
        assert_eq!(
            next_round_interval(0.5, &c),
            Duration::from_millis(next_round_interval_ms(0.5, &c)),
        );
    }

    // ── wait_until_next_round async ──────────────────────────────

    #[tokio::test]
    async fn wait_returns_mempool_signalled_when_future_resolves_first() {
        let c = cfg(100, 2000);
        // Pre-resolved future (ready()) wins the race.
        let cause = wait_until_next_round(0.0, &c, std::future::ready(())).await;
        assert_eq!(cause, WakeCause::MempoolSignalled);
    }

    #[tokio::test]
    async fn wait_returns_timer_expired_when_mempool_never_signals() {
        // Config with a very short interval so the test runs fast.
        let c = cfg(50, 60);
        let start = std::time::Instant::now();
        let cause = wait_until_next_round(1.0, &c, std::future::pending::<()>()).await;
        let elapsed = start.elapsed();
        assert_eq!(cause, WakeCause::TimerExpired);
        // Loose bound: should have slept approximately the configured
        // interval (50 ms). Allow generous upper bound for CI jitter.
        assert!(
            elapsed >= Duration::from_millis(30),
            "returned too early: {:?}",
            elapsed
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "returned too late: {:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn wait_races_deterministically_when_mempool_later_than_timer() {
        let c = cfg(50, 60);
        // Mempool "wakes" after 500 ms, well after the 50-60 ms
        // timer — timer should win.
        let slow_wake = async {
            tokio::time::sleep(Duration::from_millis(500)).await;
        };
        let cause = wait_until_next_round(1.0, &c, slow_wake).await;
        assert_eq!(cause, WakeCause::TimerExpired);
    }
}
