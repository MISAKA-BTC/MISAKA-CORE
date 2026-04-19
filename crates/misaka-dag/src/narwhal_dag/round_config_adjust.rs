// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Epoch-boundary adjustment of the adaptive round-scheduler
//! config (Phase 3a Part C).
//!
//! # Why
//!
//! The adaptive scheduler ([`super::round_scheduler`]) picks an
//! interval in `[min, max]` based on mempool utilisation. Those
//! bounds are themselves static config today — Part C lets them
//! drift across epoch boundaries, so a network whose steady-state
//! RTT is high can widen its min, and a network that's been mostly
//! idle can widen its max.
//!
//! # Determinism
//!
//! [`adjust_round_config`] is a pure function of
//! `(previous_epoch_stats, previous_config)`. Every validator
//! computes the same next-epoch config, so applying the result at
//! the epoch boundary is consensus-safe without any extra gossip.
//!
//! # On-chain audit log
//!
//! The adjustment emits a [`RoundConfigAuditEntry`] that the caller
//! persists under [`super::columns::NarwhalCf::RoundConfigAudit`]
//! keyed by epoch number. Operators can inspect the history via
//! the store API to correlate cadence changes with observed chain
//! behaviour.
//!
//! # Clamping / safety floors
//!
//! The adjusted config is clamped through
//! [`super::round_scheduler::RoundSchedulerConfig::validate`] at
//! caller level; this module guarantees the returned config is
//! always valid (i.e. `min < max`, both inside the hard bounds)
//! by the time it's returned. The caller only needs to pass a
//! validated input.
//!
//! # Hard rules (intentionally conservative)
//!
//! * The new `min_interval_ms` MUST be at least `max_observed_rtt_ms`,
//!   otherwise the proposer can out-pace finality. We take max of
//!   `prev.min_interval_ms` and the observed RTT.
//! * The new `max_interval_ms` is a linear function of
//!   `non_empty_rounds_ratio` — busy epochs tighten, idle epochs
//!   widen. Interpolation is deterministic integer math with a
//!   final clamp into hard bounds.
//! * Adjustments are bounded: no single epoch can move either
//!   endpoint by more than [`MAX_EPOCH_SHIFT_MS`] (500 ms) to
//!   prevent runaway oscillation.

use serde::{Deserialize, Serialize};

use super::round_scheduler::{RoundSchedulerConfig, HARD_MAX_INTERVAL_MS, HARD_MIN_INTERVAL_MS};

/// Maximum amount (milliseconds) either endpoint can move in a
/// single epoch. Prevents runaway drift when one epoch's stats are
/// atypical (network partition, flash mempool spike, etc.).
pub const MAX_EPOCH_SHIFT_MS: u64 = 500;

/// Safety factor applied to observed RTT before it becomes the
/// new-min floor. RTT × 2 means the proposer gives finality room
/// for one round-trip plus one quiet tick. Tune with live data.
pub const RTT_SAFETY_FACTOR: u64 = 2;

/// Statistics observed during the *previous* epoch, fed into the
/// adjustment at the epoch boundary.
///
/// Every validator computes these the same way from the same
/// observed chain state, so two honest validators hand the same
/// `EpochStats` to [`adjust_round_config`] and reach the same
/// decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochStats {
    /// Epoch number these stats describe (not the epoch they apply
    /// to — that's `+1`).
    pub epoch: u64,
    /// Maximum round-trip time observed in milliseconds across all
    /// leader → quorum reply exchanges. Caps the *minimum* new
    /// interval so proposals never race finality.
    pub max_observed_rtt_ms: u64,
    /// Total rounds advanced during the epoch (for ratio
    /// denominator).
    pub total_rounds: u64,
    /// Rounds that produced at least one non-empty block.
    pub non_empty_rounds: u64,
    /// The leader timeout (ms) in effect during the epoch.
    /// Informational — not currently used by the derivation, kept
    /// in the struct so future tweaks can reference it without a
    /// schema change.
    pub leader_timeout_ms: u64,
}

impl EpochStats {
    /// Returns `non_empty_rounds / total_rounds` as a 0..=1000
    /// fixed-point value (avoids floating-point in the determinism
    /// path). `total_rounds == 0` → 0 (idle epoch).
    #[must_use]
    pub const fn non_empty_ratio_scaled(&self) -> u64 {
        if self.total_rounds == 0 {
            return 0;
        }
        // Integer math: (non_empty * 1000) / total, saturating.
        let num = self.non_empty_rounds.saturating_mul(1000);
        num / self.total_rounds
    }
}

/// What the adjustment decided, together with the inputs used.
/// Persisted under `NarwhalCf::RoundConfigAudit`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundConfigAuditEntry {
    /// Epoch number this config applies *from* (= prev epoch + 1).
    pub applied_from_epoch: u64,
    /// Config that was active during the previous epoch.
    pub previous_config: RoundSchedulerConfig,
    /// Config that will be active from `applied_from_epoch` onwards.
    pub new_config: RoundSchedulerConfig,
    /// Stats fed into the derivation (previous epoch).
    pub stats: EpochStats,
    /// Unix millis at which the adjustment was computed. Advisory
    /// only — determinism does not depend on this.
    pub timestamp_ms: u64,
}

/// Derive the next epoch's [`RoundSchedulerConfig`] from the
/// previous epoch's stats.
///
/// Guarantees:
///
/// * Pure. No I/O, no RNG, no clock read. Integer math only.
/// * Return value always satisfies
///   [`RoundSchedulerConfig::validate`] (`HARD_MIN ≤ min < max ≤
///   HARD_MAX`). The output is safe to install directly.
/// * Adjustment magnitude bounded by [`MAX_EPOCH_SHIFT_MS`] per
///   endpoint to damp oscillation.
/// * Two validators with the same `previous_stats` + `previous_config`
///   always compute the same new config.
#[must_use]
pub fn adjust_round_config(
    previous_stats: &EpochStats,
    previous_config: &RoundSchedulerConfig,
) -> RoundSchedulerConfig {
    let ratio = previous_stats.non_empty_ratio_scaled(); // 0..=1000

    // ── min_interval: at least RTT * safety factor, bounded drift ──
    let rtt_floor = previous_stats
        .max_observed_rtt_ms
        .saturating_mul(RTT_SAFETY_FACTOR);
    let new_min_raw = previous_config.min_interval_ms.max(rtt_floor);
    let new_min = bound_drift(previous_config.min_interval_ms, new_min_raw);

    // ── max_interval: tighter when busy, looser when idle ────────
    //
    // Target: if ratio == 1000 (100% busy), pull `max` down toward
    // `min * 2`; if ratio == 0 (idle), let `max` rise toward
    // HARD_MAX. Linear interp between the two, integer math.
    //
    //   target_max = HARD_MAX - ((HARD_MAX - min*2) * ratio) / 1000
    //
    // We compute in `u128` for the multiplication step to avoid
    // overflow on the product, then cast back.
    let floor_max = new_min.saturating_mul(2);
    let span = (HARD_MAX_INTERVAL_MS as u128).saturating_sub(floor_max as u128);
    let contribution = (span * ratio as u128) / 1000;
    let target_max_raw = (HARD_MAX_INTERVAL_MS as u128).saturating_sub(contribution);
    let target_max = target_max_raw.min(HARD_MAX_INTERVAL_MS as u128) as u64;
    let new_max_bounded = bound_drift(previous_config.max_interval_ms, target_max);

    // ── Final clamp + min < max invariant ───────────────────────
    //
    // After drift bounding, min and max might still violate the
    // hard bounds or invariant. Clamp and, if necessary, spread.
    let new_min = new_min.clamp(HARD_MIN_INTERVAL_MS, HARD_MAX_INTERVAL_MS - 1);
    let new_max = new_max_bounded.clamp(HARD_MIN_INTERVAL_MS + 1, HARD_MAX_INTERVAL_MS);
    // Ensure min < max; if drift-bounded collision happens, push
    // max up by 1 (bounded below by hard ceiling).
    let (new_min, new_max) = if new_min >= new_max {
        let lifted = new_min.saturating_add(1).min(HARD_MAX_INTERVAL_MS);
        // If that still collides (new_min was HARD_MAX), pull min
        // down instead.
        if lifted <= new_min {
            (new_min.saturating_sub(1), new_min)
        } else {
            (new_min, lifted)
        }
    } else {
        (new_min, new_max)
    };

    RoundSchedulerConfig {
        min_interval_ms: new_min,
        max_interval_ms: new_max,
    }
}

/// Clamp `target` to be within `MAX_EPOCH_SHIFT_MS` of `previous`.
#[inline]
fn bound_drift(previous: u64, target: u64) -> u64 {
    if target >= previous {
        let delta = target - previous;
        if delta > MAX_EPOCH_SHIFT_MS {
            previous.saturating_add(MAX_EPOCH_SHIFT_MS)
        } else {
            target
        }
    } else {
        let delta = previous - target;
        if delta > MAX_EPOCH_SHIFT_MS {
            previous.saturating_sub(MAX_EPOCH_SHIFT_MS)
        } else {
            target
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats(total: u64, non_empty: u64, rtt: u64) -> EpochStats {
        EpochStats {
            epoch: 1,
            max_observed_rtt_ms: rtt,
            total_rounds: total,
            non_empty_rounds: non_empty,
            leader_timeout_ms: 1000,
        }
    }

    fn cfg(min: u64, max: u64) -> RoundSchedulerConfig {
        RoundSchedulerConfig {
            min_interval_ms: min,
            max_interval_ms: max,
        }
    }

    // ── non_empty_ratio_scaled ────────────────────────────────────

    #[test]
    fn ratio_zero_when_no_rounds() {
        assert_eq!(stats(0, 0, 0).non_empty_ratio_scaled(), 0);
    }

    #[test]
    fn ratio_thousand_when_all_rounds_non_empty() {
        assert_eq!(stats(100, 100, 0).non_empty_ratio_scaled(), 1000);
    }

    #[test]
    fn ratio_half_when_half_non_empty() {
        assert_eq!(stats(100, 50, 0).non_empty_ratio_scaled(), 500);
    }

    #[test]
    fn ratio_handles_large_counts_without_panic() {
        // Very large counts saturate the numerator (non_empty * 1000
        // overflows u64 well before u64::MAX/1000). The function
        // uses `saturating_mul` so the result is bounded but loses
        // precision at extreme scale. Real epochs stay far below
        // this regime (total_rounds ≈ 10^4 in practice). The only
        // contract tested here is "doesn't panic".
        let r = stats(u64::MAX / 2, u64::MAX / 4, 0).non_empty_ratio_scaled();
        // Saturated result is whatever it is — just assert non-panic
        // and sanity-bound: ratio cannot exceed 1000 after the
        // `saturating_mul(1000) / total_rounds` path.
        assert!(r <= 1000, "ratio exceeded 1000: {r}");
    }

    #[test]
    fn ratio_bounded_at_1000_on_realistic_epoch_sizes() {
        // Typical epoch: 10_000 rounds / 5000 non-empty → 500.
        assert_eq!(stats(10_000, 5_000, 0).non_empty_ratio_scaled(), 500);
        // All non-empty: 1000.
        assert_eq!(stats(10_000, 10_000, 0).non_empty_ratio_scaled(), 1000);
    }

    // ── bound_drift ───────────────────────────────────────────────

    #[test]
    fn drift_within_bound_keeps_target() {
        assert_eq!(bound_drift(1000, 1200), 1200);
        assert_eq!(bound_drift(1000, 800), 800);
    }

    #[test]
    fn drift_exceeding_bound_clamps() {
        // previous=1000, target=2000 → clamp to 1000 + 500 = 1500.
        assert_eq!(bound_drift(1000, 2000), 1500);
        // previous=1000, target=0 → clamp to 1000 - 500 = 500.
        assert_eq!(bound_drift(1000, 0), 500);
    }

    #[test]
    fn drift_saturating_at_u64_boundary() {
        // Target near u64::MAX, previous small — saturating add
        // caps at previous + MAX_EPOCH_SHIFT_MS.
        assert_eq!(bound_drift(1000, u64::MAX), 1500);
    }

    // ── adjust_round_config: determinism ─────────────────────────

    #[test]
    fn adjust_is_deterministic_same_input_same_output() {
        let s = stats(1000, 500, 200);
        let c = cfg(100, 2000);
        let a = adjust_round_config(&s, &c);
        let b = adjust_round_config(&s, &c);
        assert_eq!(a, b);
    }

    // ── adjust_round_config: validate output ─────────────────────

    #[test]
    fn adjust_output_always_validates() {
        // Sweep a range of inputs and assert validate() holds.
        for total in [0u64, 1, 100, 10_000] {
            for non_empty in [0u64, total / 2, total] {
                for rtt in [0u64, 50, 500, 5_000, 20_000] {
                    let s = stats(total, non_empty, rtt);
                    for (min, max) in [
                        (100u64, 2000),
                        (200, 800),
                        (50, 10_000),
                        (HARD_MIN_INTERVAL_MS, HARD_MIN_INTERVAL_MS + 1),
                    ] {
                        let c = cfg(min, max);
                        let new_c = adjust_round_config(&s, &c);
                        assert!(
                            new_c.validate().is_ok(),
                            "validate failed for stats={s:?} prev={c:?} new={new_c:?}"
                        );
                    }
                }
            }
        }
    }

    // ── adjust_round_config: RTT floor ───────────────────────────

    #[test]
    fn adjust_rtt_floors_new_min() {
        // prev min=100, RTT=200 → RTT*2=400 > prev_min. But bounded
        // drift means new_min = 100 + MAX_EPOCH_SHIFT_MS = 600 if
        // target (400) is within drift. Let's check.
        let s = stats(100, 50, 200);
        let c = cfg(100, 2000);
        let new_c = adjust_round_config(&s, &c);
        // new_min should be at least 400 (target), but bounded to
        // prev + 500 = 600. Actual value can be either within.
        assert!(
            new_c.min_interval_ms >= 400.min(100 + MAX_EPOCH_SHIFT_MS),
            "expected min floored by RTT: {}",
            new_c.min_interval_ms
        );
    }

    #[test]
    fn adjust_zero_rtt_does_not_raise_min() {
        let s = stats(100, 50, 0);
        let c = cfg(100, 2000);
        let new_c = adjust_round_config(&s, &c);
        // With rtt=0 and ratio=500, min should stay at ~prev (100).
        // Drift bound allows up to prev + 500; prev being 100 and
        // target being max(100, 0) = 100 yields 100 unchanged.
        assert_eq!(new_c.min_interval_ms, 100);
    }

    // ── adjust_round_config: busy vs idle ────────────────────────

    #[test]
    fn adjust_busy_epoch_tightens_max() {
        let busy = stats(100, 100, 50); // ratio=1000
        let c = cfg(100, 2000);
        let new_c = adjust_round_config(&busy, &c);
        // Busy: max target = HARD_MAX - span*1000/1000 = min*2.
        // min stays at 100 (RTT*2=100 doesn't raise it), so target
        // max = 200. Drift: prev_max=2000, target=200, delta=1800
        // > 500 → clamp to 2000 - 500 = 1500.
        assert_eq!(new_c.max_interval_ms, 1500);
        assert!(new_c.max_interval_ms < c.max_interval_ms);
    }

    #[test]
    fn adjust_idle_epoch_widens_max() {
        let idle = stats(100, 0, 0); // ratio=0
        let c = cfg(100, 2000);
        let new_c = adjust_round_config(&idle, &c);
        // Idle: max target = HARD_MAX = 10000. Drift: prev=2000,
        // target=10000, delta=8000 > 500 → clamp to 2500.
        assert_eq!(new_c.max_interval_ms, 2500);
        assert!(new_c.max_interval_ms > c.max_interval_ms);
    }

    // ── adjust_round_config: monotonicity across ratio ──────────

    #[test]
    fn busier_epoch_never_produces_wider_max() {
        // Higher ratio → tighter or equal max.
        let c = cfg(200, 2000);
        let mut prev_max = u64::MAX;
        for ratio in [0u64, 100, 250, 500, 750, 1000] {
            let s = stats(1000, ratio, 50);
            let new_c = adjust_round_config(&s, &c);
            assert!(
                new_c.max_interval_ms <= prev_max,
                "ratio={ratio}: non-monotone (prev_max={prev_max}, new={})",
                new_c.max_interval_ms
            );
            prev_max = new_c.max_interval_ms;
        }
    }

    // ── adjust_round_config: degenerate inputs ───────────────────

    #[test]
    fn adjust_handles_extreme_rtt() {
        // rtt=1_000_000 → rtt*2 saturates, but bound_drift + clamp
        // must keep min < max and both inside hard bounds.
        let s = stats(100, 50, 1_000_000);
        let c = cfg(100, 2000);
        let new_c = adjust_round_config(&s, &c);
        assert!(new_c.validate().is_ok());
        assert!(new_c.min_interval_ms <= HARD_MAX_INTERVAL_MS - 1);
        assert!(new_c.max_interval_ms <= HARD_MAX_INTERVAL_MS);
    }

    #[test]
    fn adjust_handles_collision_between_new_min_and_new_max() {
        // Force a scenario where drift-bounded min catches up with
        // drift-bounded max. The function should still produce a
        // validating config.
        let s = stats(100, 100, 10_000);
        let c = cfg(HARD_MAX_INTERVAL_MS - 100, HARD_MAX_INTERVAL_MS);
        let new_c = adjust_round_config(&s, &c);
        assert!(new_c.validate().is_ok());
        assert!(new_c.min_interval_ms < new_c.max_interval_ms);
    }

    // ── RoundConfigAuditEntry serde ──────────────────────────────

    #[test]
    fn audit_entry_serde_roundtrips() {
        let entry = RoundConfigAuditEntry {
            applied_from_epoch: 7,
            previous_config: cfg(100, 2000),
            new_config: cfg(150, 1800),
            stats: stats(100, 50, 75),
            timestamp_ms: 1_700_000_000_000,
        };
        let j = serde_json::to_string(&entry).unwrap();
        let back: RoundConfigAuditEntry = serde_json::from_str(&j).unwrap();
        assert_eq!(back, entry);
    }
}
