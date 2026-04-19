//! Observer that records per-validator performance metrics.
//!
//! Pattern B: this tracker does not modify any existing consensus struct.
//! It is a standalone observer. Consensus code emits events into the
//! tracker via `on_*` methods; the tracker aggregates them in a
//! `BTreeMap<ValidatorId, ValidatorMetrics>`.
//!
//! Determinism: `BTreeMap` is used instead of `HashMap` so ordering is
//! stable across runs and platforms.

use parking_lot::RwLock;
use std::collections::BTreeMap;

use super::metrics::{CommissionChange, ValidatorMetrics};

/// Maximum commission-change history retained per validator.
/// Bounds unbounded memory growth; oldest entries are evicted.
pub const MAX_COMMISSION_HISTORY: usize = 100;

/// 32-byte validator id.
pub type ValidatorId = [u8; 32];

pub struct ReputationTracker {
    /// Per-validator metrics.
    per_validator: RwLock<BTreeMap<ValidatorId, ValidatorMetrics>>,

    /// Heartbeat window for uptime calculation (rounds). Informational
    /// only — `on_epoch_boundary` uses the `last_active_round` for the
    /// v0.8.0 uptime proxy.
    #[allow(dead_code)]
    heartbeat_window: u64,

    /// Expected block count per validator across the current tracking
    /// window. Fed in externally at epoch boundaries so `on_epoch_boundary`
    /// can compute `block_production_rate = produced / expected`.
    expected_blocks: RwLock<BTreeMap<ValidatorId, u64>>,

    /// Actual blocks produced per validator since the last epoch boundary
    /// (reset on `on_epoch_boundary`).
    produced_blocks: RwLock<BTreeMap<ValidatorId, u64>>,

    /// Votes cast per validator since the last epoch boundary.
    votes_cast: RwLock<BTreeMap<ValidatorId, u64>>,

    /// Votes expected per validator since the last epoch boundary.
    votes_expected: RwLock<BTreeMap<ValidatorId, u64>>,
}

impl ReputationTracker {
    pub fn new(heartbeat_window: u64) -> Self {
        Self {
            per_validator: RwLock::new(BTreeMap::new()),
            heartbeat_window: heartbeat_window.max(1),
            expected_blocks: RwLock::new(BTreeMap::new()),
            produced_blocks: RwLock::new(BTreeMap::new()),
            votes_cast: RwLock::new(BTreeMap::new()),
            votes_expected: RwLock::new(BTreeMap::new()),
        }
    }

    /// Record a block production event. Updates `last_active_round` and
    /// increments the per-epoch counter used at the next epoch boundary.
    pub fn on_block_produced(&self, validator: ValidatorId, round: u64) {
        *self.produced_blocks.write().entry(validator).or_insert(0) += 1;
        let mut m = self.per_validator.write();
        let e = m.entry(validator).or_default();
        if round > e.last_active_round {
            e.last_active_round = round;
        }
    }

    /// Record a vote cast event. Updates `last_active_round`.
    pub fn on_vote_cast(&self, validator: ValidatorId, round: u64) {
        *self.votes_cast.write().entry(validator).or_insert(0) += 1;
        let mut m = self.per_validator.write();
        let e = m.entry(validator).or_default();
        if round > e.last_active_round {
            e.last_active_round = round;
        }
    }

    /// Record that a validator was expected to vote but did not. Used so
    /// `vote_participation_rate = cast / (cast + missed)` can be computed
    /// at the next epoch boundary.
    pub fn on_vote_expected(&self, validator: ValidatorId) {
        *self.votes_expected.write().entry(validator).or_insert(0) += 1;
    }

    /// Declare how many blocks a validator was expected to produce this
    /// epoch. Called by the proposer scheduler; stored until
    /// `on_epoch_boundary` consumes it.
    pub fn set_expected_blocks(&self, validator: ValidatorId, count: u64) {
        self.expected_blocks.write().insert(validator, count);
    }

    /// Record a slash event. Increments `slash_count`.
    pub fn on_slash(&self, validator: ValidatorId) {
        let mut m = self.per_validator.write();
        let e = m.entry(validator).or_default();
        e.slash_count = e.slash_count.saturating_add(1);
    }

    /// Record a commission-rate change. Bounded to
    /// `MAX_COMMISSION_HISTORY` entries per validator; oldest is evicted.
    pub fn on_commission_change(
        &self,
        validator: ValidatorId,
        from_bps: u32,
        to_bps: u32,
        epoch: u64,
        block_height: u64,
    ) {
        let mut m = self.per_validator.write();
        let e = m.entry(validator).or_default();
        e.commission_changes.push(CommissionChange {
            epoch,
            from_bps,
            to_bps,
            block_height,
        });
        if e.commission_changes.len() > MAX_COMMISSION_HISTORY {
            let over = e.commission_changes.len() - MAX_COMMISSION_HISTORY;
            e.commission_changes.drain(..over);
        }
    }

    /// Called at each epoch boundary. For every listed validator:
    /// - finalises `block_production_rate` using the accumulated counters,
    /// - finalises `vote_participation_rate`,
    /// - sets a v0.8.0 uptime proxy from `last_active_round`,
    /// then resets the per-epoch counters. `uptime_bps_for` allows the
    /// caller to inject the authoritative uptime from
    /// `ValidatorAccount.uptime_bps` (if available); a `None` falls back
    /// to the last-seen proxy.
    pub fn on_epoch_boundary<F>(
        &self,
        _epoch: u64,
        active_validators: &[ValidatorId],
        uptime_bps_for: F,
    ) where
        F: Fn(&ValidatorId) -> Option<u64>,
    {
        let produced_snapshot: BTreeMap<ValidatorId, u64> =
            std::mem::take(&mut *self.produced_blocks.write());
        let votes_cast_snapshot: BTreeMap<ValidatorId, u64> =
            std::mem::take(&mut *self.votes_cast.write());
        let votes_expected_snapshot: BTreeMap<ValidatorId, u64> =
            std::mem::take(&mut *self.votes_expected.write());
        let expected_blocks = self.expected_blocks.read().clone();

        let mut metrics = self.per_validator.write();
        for v in active_validators {
            let e = metrics.entry(*v).or_default();

            let produced = produced_snapshot.get(v).copied().unwrap_or(0);
            let expected = expected_blocks.get(v).copied().unwrap_or(0);
            e.block_production_rate = if expected == 0 {
                0.0
            } else {
                produced as f64 / expected as f64
            };

            let cast = votes_cast_snapshot.get(v).copied().unwrap_or(0);
            let missed = votes_expected_snapshot.get(v).copied().unwrap_or(0);
            e.vote_participation_rate = if cast + missed == 0 {
                0.0
            } else {
                cast as f64 / (cast + missed) as f64
            };

            // Uptime: prefer authoritative `uptime_bps` from the staking
            // layer; otherwise fall back to a binary proxy so a brand-new
            // validator isn't penalised purely by tracker absence.
            e.uptime_pct = match uptime_bps_for(v) {
                Some(bps) => (bps.min(10_000) as f64) / 100.0,
                None if e.last_active_round > 0 => 100.0,
                None => 0.0,
            };
        }
    }

    /// Read-only snapshot for one validator. Returns `Default` when the
    /// validator has no recorded events yet.
    pub fn metrics_for(&self, validator: &ValidatorId) -> ValidatorMetrics {
        self.per_validator
            .read()
            .get(validator)
            .cloned()
            .unwrap_or_default()
    }

    /// Read-only snapshot of the whole tracker.
    pub fn all_metrics(&self) -> BTreeMap<ValidatorId, ValidatorMetrics> {
        self.per_validator.read().clone()
    }

    /// Clear a validator's entry — used when a validator deregisters.
    pub fn remove(&self, validator: &ValidatorId) {
        self.per_validator.write().remove(validator);
        self.expected_blocks.write().remove(validator);
        self.produced_blocks.write().remove(validator);
        self.votes_cast.write().remove(validator);
        self.votes_expected.write().remove(validator);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vid(n: u8) -> ValidatorId {
        [n; 32]
    }

    #[test]
    fn block_production_updates_last_active_round() {
        let t = ReputationTracker::new(100);
        t.on_block_produced(vid(1), 42);
        let m = t.metrics_for(&vid(1));
        assert_eq!(m.last_active_round, 42);
    }

    #[test]
    fn later_round_monotonic_wins() {
        let t = ReputationTracker::new(100);
        t.on_block_produced(vid(1), 50);
        t.on_block_produced(vid(1), 40); // older — must not regress
        assert_eq!(t.metrics_for(&vid(1)).last_active_round, 50);
    }

    #[test]
    fn slash_count_increments() {
        let t = ReputationTracker::new(100);
        t.on_slash(vid(1));
        t.on_slash(vid(1));
        t.on_slash(vid(1));
        assert_eq!(t.metrics_for(&vid(1)).slash_count, 3);
    }

    #[test]
    fn commission_history_is_bounded() {
        let t = ReputationTracker::new(100);
        for i in 0..(MAX_COMMISSION_HISTORY as u64 + 10) {
            t.on_commission_change(vid(1), i as u32, (i + 1) as u32, i, i * 1000);
        }
        let m = t.metrics_for(&vid(1));
        assert_eq!(m.commission_changes.len(), MAX_COMMISSION_HISTORY);
        // Oldest 10 evicted — first retained is epoch 10.
        assert_eq!(m.commission_changes.first().unwrap().epoch, 10);
    }

    #[test]
    fn epoch_boundary_computes_production_rate() {
        let t = ReputationTracker::new(100);
        t.set_expected_blocks(vid(1), 10);
        for r in 0..7 {
            t.on_block_produced(vid(1), r);
        }
        t.on_epoch_boundary(1, &[vid(1)], |_| Some(9500));
        let m = t.metrics_for(&vid(1));
        assert!((m.block_production_rate - 0.7).abs() < 1e-9);
        // uptime_bps=9500 → uptime_pct=95.0
        assert!((m.uptime_pct - 95.0).abs() < 1e-9);
    }

    #[test]
    fn epoch_boundary_resets_counters() {
        let t = ReputationTracker::new(100);
        t.set_expected_blocks(vid(1), 4);
        t.on_block_produced(vid(1), 0);
        t.on_block_produced(vid(1), 1);
        t.on_epoch_boundary(1, &[vid(1)], |_| Some(10_000));
        let first = t.metrics_for(&vid(1)).block_production_rate;
        assert!((first - 0.5).abs() < 1e-9);

        // Next epoch: no blocks produced but same expected count.
        t.on_epoch_boundary(2, &[vid(1)], |_| Some(10_000));
        let second = t.metrics_for(&vid(1)).block_production_rate;
        assert!((second - 0.0).abs() < 1e-9, "counters reset each epoch");
    }

    #[test]
    fn vote_participation_rate() {
        let t = ReputationTracker::new(100);
        for _ in 0..8 {
            t.on_vote_cast(vid(1), 0);
        }
        for _ in 0..2 {
            t.on_vote_expected(vid(1));
        }
        t.on_epoch_boundary(1, &[vid(1)], |_| Some(10_000));
        let m = t.metrics_for(&vid(1));
        assert!((m.vote_participation_rate - 0.8).abs() < 1e-9);
    }

    #[test]
    fn v08_raw_score_in_range() {
        let mut m = ValidatorMetrics::default();
        m.uptime_pct = 99.0;
        m.block_production_rate = 1.0;
        m.vote_participation_rate = 1.0;
        let s = m.v08_raw_score();
        assert!(s > 0.0 && s <= 1.5, "score {} in range", s);
    }

    #[test]
    fn remove_clears_entry() {
        let t = ReputationTracker::new(100);
        t.on_block_produced(vid(1), 10);
        t.on_slash(vid(1));
        assert_ne!(t.metrics_for(&vid(1)), ValidatorMetrics::default());
        t.remove(&vid(1));
        assert_eq!(t.metrics_for(&vid(1)), ValidatorMetrics::default());
    }
}
