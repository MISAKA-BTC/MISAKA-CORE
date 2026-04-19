//! Validator reputation — performance metric recording.
//!
//! # v0.8.0 Semantics
//!
//! Six metrics (`uptime_pct`, `block_production_rate`, `vote_participation_rate`,
//! `slash_count`, `last_active_round`, `commission_change_history`) are
//! **recorded** by this module but **not used** for validator ranking.
//! Ranking in v0.8.0 is based solely on `self_stake` (see `validator_registry`).
//!
//! # Pattern B Principle
//!
//! This module is **additive**: it does not modify existing
//! `ValidatorRegistry`, `StakingRegistry`, `ValidatorSystemV2`, or
//! `RewardEpochTracker`. All interaction is through public read-only
//! methods on those existing types.
//!
//! # Future Plan
//!
//! A future governance-approved proposal may activate a hybrid DPoS
//! ranking that consumes these metrics. The exact formula is left to
//! governance; candidates are outlined in
//! `docs/internal/REPUTATION_FORMULA.md`.

pub mod metrics;
pub mod tracker;

pub use metrics::{CommissionChange, ValidatorMetrics};
pub use tracker::ReputationTracker;
