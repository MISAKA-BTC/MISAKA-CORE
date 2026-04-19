//! Validator performance metrics.
//!
//! NOTE (v0.8.0): These metrics are RECORDED but NOT USED for
//! validator ranking. Ranking uses `self_stake` only.
//!
//! In a future governance-approved upgrade, a hybrid score may be
//! introduced of the form:
//!
//! ```text
//! score_i = sqrt(self_stake + delegated_stake) * reputation_i
//! ```
//!
//! where `reputation_i` is computed from these 6 metrics. The exact
//! formula will be determined by governance prior to activation.
//! See `docs/internal/REPUTATION_FORMULA.md`.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ValidatorMetrics {
    /// Uptime percentage over the last N epochs (0.0 - 100.0).
    /// Source: consensus heartbeat tracking.
    pub uptime_pct: f64,

    /// Block production rate: produced / expected (0.0 - 1.0+).
    /// Values > 1.0 possible when a validator catches up missed rounds.
    pub block_production_rate: f64,

    /// Vote participation rate: votes_cast / votes_expected (0.0 - 1.0).
    pub vote_participation_rate: f64,

    /// Total slash event count since validator activation.
    ///
    /// NOTE: the existing `ValidatorAccount.cumulative_slashed: u64` stores
    /// slashed *amount*, not event *count*. This metric adds the event
    /// count that the v0.9.0 reputation formula needs.
    pub slash_count: u64,

    /// Last round number where this validator was observed active.
    /// Used to detect dead validators.
    pub last_active_round: u64,

    /// History of commission-rate changes. Bounded (latest wins) to
    /// avoid unbounded memory growth; see `MAX_COMMISSION_HISTORY` in
    /// `tracker`.
    pub commission_changes: Vec<CommissionChange>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CommissionChange {
    pub epoch: u64,
    pub from_bps: u32,
    pub to_bps: u32,
    pub block_height: u64,
}

impl ValidatorMetrics {
    /// Placeholder reputation score for v0.8.0 RPC display only.
    ///
    /// Returns a rough composite in the `[0.0, 1.5+]` range. **Not used**
    /// for consensus ranking. The v0.9.0 activation replaces this with
    /// the governance-approved formula (see
    /// `docs/internal/REPUTATION_FORMULA.md`).
    pub fn v08_raw_score(&self) -> f64 {
        let active_penalty = (self.slash_count as f64).min(10.0) * 0.05;
        (self.uptime_pct / 100.0)
            * self.block_production_rate.min(1.5)
            * self.vote_participation_rate
            * (1.0 - active_penalty).max(0.0)
    }
}
