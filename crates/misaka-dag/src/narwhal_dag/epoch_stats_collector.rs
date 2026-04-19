// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Live `EpochStats` collector — Phase 3a.5 Step 1.
//!
//! # Why
//!
//! [`super::round_config_adjust::adjust_round_config`] consumes an
//! [`EpochStats`] at epoch boundaries to derive the next-epoch
//! [`super::round_scheduler::RoundSchedulerConfig`]. Phase 3a Part C
//! shipped the pure derivation + audit CF but **no collector** —
//! nothing in the live propose/commit loops updated the stats that
//! the derivation would consume.
//!
//! This module provides that collector: an atomic-counter bundle
//! updated from hot paths without locks. At an epoch boundary,
//! [`EpochStatsCollector::snapshot_and_reset`] atomically freezes
//! the counters and returns a closed-form [`EpochStats`]; the same
//! call zeroes the counters so the next epoch starts fresh.
//!
//! # Threading contract
//!
//! All four record methods are lock-free — they compose only
//! `fetch_add` / `fetch_max` on shared atomics. Callers hold an
//! `Arc<EpochStatsCollector>` clone and call `record_*` from
//! whichever async task observes the event. No await points.
//!
//! `snapshot_and_reset` is lock-free too, using `fetch_and(0, ...)`-
//! style swap primitives. The result captures a consistent "what
//! had been recorded before the reset" snapshot — readers may see
//! later writes land in the new epoch, which is the correct
//! semantics for a boundary transition.
//!
//! # Determinism
//!
//! Because increments are concurrent atomic adds, two validators
//! that saw the same round events in the same order produce the
//! same snapshot. Wall-clock does not appear anywhere in the
//! collector — `max_observed_rtt_ms` is the caller's
//! responsibility to measure and feed in.
//!
//! # Not in scope
//!
//! This module ships the collector type only. Wiring it into the
//! propose loop, the commit loop, and the round-trip-timing
//! callsite is Phase 3a.5 Step 3. Reading the collector at an
//! epoch boundary and handing the snapshot to
//! `adjust_round_config` is Step 4.

use std::sync::atomic::{AtomicU64, Ordering};

use super::round_config_adjust::EpochStats;

/// Lock-free bundle of live counters that together form an
/// [`EpochStats`] at the next call to `snapshot_and_reset`.
#[derive(Debug, Default)]
pub struct EpochStatsCollector {
    /// The epoch currently being observed. Set once at construction
    /// (or via [`Self::set_epoch`] when the caller advances).
    /// Persisted in the snapshot as `EpochStats::epoch`.
    epoch: AtomicU64,

    /// Incremented once per round proposal (see
    /// `narwhal_consensus::spawn_propose_loop`).
    total_rounds: AtomicU64,

    /// Incremented on every commit whose `txs_accepted > 0` (see
    /// `start_narwhal_node` commit loop around
    /// `main.rs:4462`).
    non_empty_rounds: AtomicU64,

    /// Running maximum of observed round-trip time in
    /// milliseconds. Updated via `fetch_max` so concurrent
    /// observers don't need a lock.
    max_observed_rtt_ms: AtomicU64,

    /// Leader-timeout snapshot that was active during the epoch.
    /// Set once at epoch start via [`Self::set_leader_timeout_ms`]
    /// and carried through to the snapshot for informational
    /// purposes — `adjust_round_config` currently does not use it.
    leader_timeout_ms: AtomicU64,
}

impl EpochStatsCollector {
    /// Create a collector for the given epoch with everything
    /// zeroed. Pass the initial leader-timeout explicitly — the
    /// collector has no other way to discover it.
    #[must_use]
    pub fn new(epoch: u64, leader_timeout_ms: u64) -> Self {
        Self {
            epoch: AtomicU64::new(epoch),
            total_rounds: AtomicU64::new(0),
            non_empty_rounds: AtomicU64::new(0),
            max_observed_rtt_ms: AtomicU64::new(0),
            leader_timeout_ms: AtomicU64::new(leader_timeout_ms),
        }
    }

    // ── Hot-path record methods ───────────────────────────────────

    /// Called by the propose loop on every round proposal. Lock-free.
    pub fn record_round(&self) {
        self.total_rounds.fetch_add(1, Ordering::Relaxed);
    }

    /// Called by the commit loop on every commit that accepted at
    /// least one transaction. Lock-free.
    pub fn record_non_empty_round(&self) {
        self.non_empty_rounds.fetch_add(1, Ordering::Relaxed);
    }

    /// Called from any callsite that observes a round-trip time
    /// sample. The collector keeps the running maximum. Lock-free.
    pub fn record_rtt(&self, rtt_ms: u64) {
        self.max_observed_rtt_ms
            .fetch_max(rtt_ms, Ordering::Relaxed);
    }

    // ── Epoch transition surface ──────────────────────────────────

    /// Override the leader-timeout mid-epoch. Rare: typically set
    /// once at construction and mirrored into [`EpochStats`].
    pub fn set_leader_timeout_ms(&self, ms: u64) {
        self.leader_timeout_ms.store(ms, Ordering::Relaxed);
    }

    /// Set the epoch label. Call this from the epoch-transition
    /// handler *after* `snapshot_and_reset` to label the next
    /// epoch's counters.
    pub fn set_epoch(&self, epoch: u64) {
        self.epoch.store(epoch, Ordering::Relaxed);
    }

    /// Peek the current counts without resetting. Useful for
    /// metrics / dashboards. The return value is a transient view;
    /// if the hot path is busy, two back-to-back calls may differ.
    #[must_use]
    pub fn peek(&self) -> EpochStats {
        EpochStats {
            epoch: self.epoch.load(Ordering::Relaxed),
            max_observed_rtt_ms: self.max_observed_rtt_ms.load(Ordering::Relaxed),
            total_rounds: self.total_rounds.load(Ordering::Relaxed),
            non_empty_rounds: self.non_empty_rounds.load(Ordering::Relaxed),
            leader_timeout_ms: self.leader_timeout_ms.load(Ordering::Relaxed),
        }
    }

    /// Atomically snapshot every counter into an [`EpochStats`]
    /// and reset the four running counters (epoch label and
    /// leader_timeout are preserved).
    ///
    /// Because the four resets are individual `swap`s, a
    /// concurrent record that lands between two swaps is counted
    /// into the next epoch, not the current one — which is the
    /// correct semantics for a boundary: stragglers belong to the
    /// epoch *they* hit, not the one being closed out.
    ///
    /// Epoch label is *not* reset; the caller advances it via
    /// [`Self::set_epoch`] after reading the snapshot.
    #[must_use]
    pub fn snapshot_and_reset(&self) -> EpochStats {
        let epoch = self.epoch.load(Ordering::Relaxed);
        let leader_timeout_ms = self.leader_timeout_ms.load(Ordering::Relaxed);
        let total_rounds = self.total_rounds.swap(0, Ordering::Relaxed);
        let non_empty_rounds = self.non_empty_rounds.swap(0, Ordering::Relaxed);
        let max_observed_rtt_ms = self.max_observed_rtt_ms.swap(0, Ordering::Relaxed);
        EpochStats {
            epoch,
            max_observed_rtt_ms,
            total_rounds,
            non_empty_rounds,
            leader_timeout_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make(epoch: u64, timeout: u64) -> EpochStatsCollector {
        EpochStatsCollector::new(epoch, timeout)
    }

    // ── Construction ──────────────────────────────────────────────

    #[test]
    fn new_initialises_counters_to_zero() {
        let c = make(7, 1000);
        let p = c.peek();
        assert_eq!(p.epoch, 7);
        assert_eq!(p.leader_timeout_ms, 1000);
        assert_eq!(p.total_rounds, 0);
        assert_eq!(p.non_empty_rounds, 0);
        assert_eq!(p.max_observed_rtt_ms, 0);
    }

    // ── Record methods ────────────────────────────────────────────

    #[test]
    fn record_round_increments() {
        let c = make(0, 0);
        c.record_round();
        c.record_round();
        c.record_round();
        assert_eq!(c.peek().total_rounds, 3);
    }

    #[test]
    fn record_non_empty_round_increments_only_non_empty() {
        let c = make(0, 0);
        c.record_round();
        c.record_round();
        c.record_non_empty_round();
        let p = c.peek();
        assert_eq!(p.total_rounds, 2);
        assert_eq!(p.non_empty_rounds, 1);
    }

    #[test]
    fn record_rtt_keeps_running_max() {
        let c = make(0, 0);
        c.record_rtt(50);
        c.record_rtt(120);
        c.record_rtt(30); // should NOT lower the max
        c.record_rtt(110); // also should not lower
        assert_eq!(c.peek().max_observed_rtt_ms, 120);
    }

    #[test]
    fn record_rtt_zero_is_no_op_against_nonzero_max() {
        let c = make(0, 0);
        c.record_rtt(75);
        c.record_rtt(0);
        assert_eq!(c.peek().max_observed_rtt_ms, 75);
    }

    // ── Mutators for epoch/timeout ────────────────────────────────

    #[test]
    fn set_epoch_updates_peek() {
        let c = make(1, 0);
        c.set_epoch(5);
        assert_eq!(c.peek().epoch, 5);
    }

    #[test]
    fn set_leader_timeout_updates_peek() {
        let c = make(0, 1000);
        c.set_leader_timeout_ms(2500);
        assert_eq!(c.peek().leader_timeout_ms, 2500);
    }

    // ── snapshot_and_reset ────────────────────────────────────────

    #[test]
    fn snapshot_and_reset_returns_current_and_zeroes_counters() {
        let c = make(3, 900);
        c.record_round();
        c.record_round();
        c.record_non_empty_round();
        c.record_rtt(85);

        let snap = c.snapshot_and_reset();
        assert_eq!(snap.epoch, 3);
        assert_eq!(snap.total_rounds, 2);
        assert_eq!(snap.non_empty_rounds, 1);
        assert_eq!(snap.max_observed_rtt_ms, 85);
        assert_eq!(snap.leader_timeout_ms, 900);

        // Running counters are zero; label + timeout preserved.
        let after = c.peek();
        assert_eq!(after.total_rounds, 0);
        assert_eq!(after.non_empty_rounds, 0);
        assert_eq!(after.max_observed_rtt_ms, 0);
        assert_eq!(after.epoch, 3);
        assert_eq!(after.leader_timeout_ms, 900);
    }

    #[test]
    fn snapshot_on_fresh_collector_is_all_zero() {
        let c = make(42, 1500);
        let snap = c.snapshot_and_reset();
        assert_eq!(snap.epoch, 42);
        assert_eq!(snap.leader_timeout_ms, 1500);
        assert_eq!(snap.total_rounds, 0);
        assert_eq!(snap.non_empty_rounds, 0);
        assert_eq!(snap.max_observed_rtt_ms, 0);
    }

    #[test]
    fn back_to_back_snapshots_are_each_consistent() {
        // Stress: two consecutive snapshots with interleaved writes.
        let c = make(0, 0);
        c.record_round();
        c.record_round();
        let a = c.snapshot_and_reset();
        assert_eq!(a.total_rounds, 2);

        c.record_round();
        let b = c.snapshot_and_reset();
        assert_eq!(b.total_rounds, 1);
    }

    // ── Concurrency sanity ────────────────────────────────────────

    #[test]
    fn concurrent_record_rounds_accumulate_correctly() {
        const N_THREADS: usize = 8;
        const N_PER_THREAD: usize = 10_000;

        let c = Arc::new(make(0, 0));
        let handles: Vec<_> = (0..N_THREADS)
            .map(|_| {
                let c = c.clone();
                std::thread::spawn(move || {
                    for _ in 0..N_PER_THREAD {
                        c.record_round();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(c.peek().total_rounds, (N_THREADS * N_PER_THREAD) as u64,);
    }

    #[test]
    fn concurrent_record_rtt_converges_to_global_max() {
        const N_THREADS: usize = 4;
        let c = Arc::new(make(0, 0));
        let handles: Vec<_> = (0..N_THREADS)
            .map(|t| {
                let c = c.clone();
                std::thread::spawn(move || {
                    // Each thread pushes a different max; the
                    // overall max must be the global max.
                    for i in 0..100 {
                        c.record_rtt((t as u64) * 1000 + i);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let max = c.peek().max_observed_rtt_ms;
        // Largest observed sample is (N_THREADS-1) * 1000 + 99.
        assert_eq!(max, ((N_THREADS - 1) as u64) * 1000 + 99);
    }

    // ── Interaction with adjust_round_config ──────────────────────

    #[test]
    fn snapshot_feeds_adjust_round_config_cleanly() {
        use super::super::round_config_adjust::adjust_round_config;
        use super::super::round_scheduler::RoundSchedulerConfig;

        let c = make(1, 1000);
        for _ in 0..100 {
            c.record_round();
        }
        for _ in 0..50 {
            c.record_non_empty_round();
        }
        c.record_rtt(75);

        let snap = c.snapshot_and_reset();
        let prev_cfg = RoundSchedulerConfig::default();
        let new_cfg = adjust_round_config(&snap, &prev_cfg);

        // Sanity: the derived config validates. The specific values
        // are covered by `round_config_adjust::tests` — we just
        // confirm the wiring line.
        assert!(new_cfg.validate().is_ok());
    }
}
