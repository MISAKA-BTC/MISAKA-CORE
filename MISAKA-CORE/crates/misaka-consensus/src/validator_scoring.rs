//! Validator Scoring — deterministic score calculation for Active/Backup selection.
//!
//! # Design Philosophy
//!
//! 「21人でネットワークを回し、元本は守りつつ、サボったノードは報酬とスコアが
//!   大きく下がって毎月最大3人まで自動で落ちる。補欠の中から、より多く預け、
//!   より安定して動き、より貢献しているノードが昇格する」
//!
//! # Score Formula
//!
//! ```text
//! Score_i = StakeFactor_i × uptime_i × contribution_i × PenaltyFactor_i × Credit_i
//! ```
//!
//! - **StakeFactor**: min(stake, MAX_EFFECTIVE_STAKE) / MIN_STAKE_ACTIVE
//! - **uptime**: online_time / observation_window (0.0 - 1.0)
//! - **contribution**: weighted combo of sync, heartbeat, readiness (0.0 - 1.0)
//! - **PenaltyFactor**: ADA-style cliff + deduction for timeouts/invalids (0.0 - 1.0)
//! - **Credit**: linear trust from stake, capped at CREDIT_CAP

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
//  Configuration
// ═══════════════════════════════════════════════════════════════

/// All scoring parameters. Fully configurable per-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoringConfig {
    /// Minimum stake to be an Active Validator (base units, 9 decimals).
    /// 10M MISAKA = 10_000_000_000_000_000
    pub min_stake_active: u64,

    /// Minimum stake to be a Backup Validator.
    /// 1M MISAKA = 1_000_000_000_000_000
    pub min_stake_backup: u64,

    /// Saturation cap: stake above this is ignored for scoring.
    /// 30M MISAKA = 30_000_000_000_000_000
    pub max_effective_stake: u64,

    /// Credit base: stake / this = Credit (before cap).
    /// 10M MISAKA = 10_000_000_000_000_000
    pub credit_base_stake: u64,

    /// Maximum Credit value (linear cap).
    pub credit_cap: f64,

    /// Uptime cliff: below this → BasePenalty = 0.5 (half score).
    pub uptime_cliff: f64,

    /// Penalty deduction per timeout event.
    pub penalty_per_timeout: f64,

    /// Penalty deduction per invalid action (bad block, bad vote, etc).
    pub penalty_per_invalid: f64,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            min_stake_active: 10_000_000_000_000_000, // 10M MISAKA (9 dec)
            min_stake_backup: 1_000_000_000_000_000,  // 1M MISAKA (9 dec)
            max_effective_stake: 30_000_000_000_000_000, // 30M MISAKA
            credit_base_stake: 10_000_000_000_000_000,   // 10M MISAKA
            credit_cap: 3.0,
            uptime_cliff: 0.90,
            penalty_per_timeout: 0.02,
            penalty_per_invalid: 0.10,
        }
    }
}

impl ScoringConfig {
    pub fn testnet() -> Self {
        Self {
            min_stake_active: 1_000_000_000_000_000,  // 1M MISAKA
            min_stake_backup: 100_000_000_000_000,     // 100K MISAKA
            max_effective_stake: 5_000_000_000_000_000, // 5M MISAKA
            credit_base_stake: 1_000_000_000_000_000,   // 1M MISAKA
            credit_cap: 3.0,
            uptime_cliff: 0.80,
            penalty_per_timeout: 0.02,
            penalty_per_invalid: 0.10,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Validator Metrics (input to scoring)
// ═══════════════════════════════════════════════════════════════

/// Raw metrics observed for a validator during an epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorMetrics {
    /// Total staked amount (base units, 9 decimals).
    pub stake: u64,
    /// Uptime ratio (0.0 - 1.0).
    pub uptime: f64,
    /// Contribution ratio (0.0 - 1.0).
    pub contribution: f64,
    /// Number of timeout events this epoch.
    pub timeouts: u32,
    /// Number of invalid actions (bad block, bad vote) this epoch.
    pub invalid_actions: u32,
}

// ═══════════════════════════════════════════════════════════════
//  Score Calculation
// ═══════════════════════════════════════════════════════════════

/// Computed score components (for transparency / debugging).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreBreakdown {
    pub stake_factor: f64,
    pub effective_stake: u64,
    pub uptime: f64,
    pub contribution: f64,
    pub penalty_factor: f64,
    pub credit: f64,
    /// Final composite score.
    pub score: f64,
}

/// Compute the full score for a validator.
///
/// ```text
/// Score_i = StakeFactor_i × uptime_i × contribution_i × PenaltyFactor_i × Credit_i
/// ```
pub fn compute_score(metrics: &ValidatorMetrics, config: &ScoringConfig) -> ScoreBreakdown {
    // ── 1. EffectiveStake (saturation cap) ──
    let effective_stake = metrics.stake.min(config.max_effective_stake);

    // ── 2. StakeFactor = EffectiveStake / MIN_STAKE_ACTIVE ──
    let stake_factor = if config.min_stake_active == 0 {
        0.0
    } else {
        effective_stake as f64 / config.min_stake_active as f64
    };
    // Cap at 3.0 to prevent extreme dominance
    let stake_factor = stake_factor.min(3.0);

    // ── 3. Credit (linear, capped) ──
    let credit = if config.credit_base_stake == 0 {
        1.0
    } else {
        (metrics.stake as f64 / config.credit_base_stake as f64).min(config.credit_cap)
    };
    // Floor at 0.1 so zero-stake doesn't zero-out everything
    let credit = credit.max(0.1);

    // ── 4. PenaltyFactor (ADA-style cliff + deductions) ──
    let base_penalty = if metrics.uptime < config.uptime_cliff {
        0.5 // Cliff: below threshold → half penalty
    } else {
        1.0
    };
    let deductions = (config.penalty_per_timeout * metrics.timeouts as f64)
        + (config.penalty_per_invalid * metrics.invalid_actions as f64);
    let penalty_factor = (base_penalty - deductions).max(0.0);

    // ── 5. Clamp inputs ──
    let uptime = metrics.uptime.clamp(0.0, 1.0);
    let contribution = metrics.contribution.clamp(0.0, 1.0);

    // ── 6. Final score ──
    let score = stake_factor * uptime * contribution * penalty_factor * credit;

    ScoreBreakdown {
        stake_factor,
        effective_stake,
        uptime,
        contribution,
        penalty_factor,
        credit,
        score,
    }
}

/// Compute contribution for a Backup validator.
///
/// ```text
/// contribution = 0.5 × sync_rate + 0.3 × heartbeat_rate + 0.2 × readiness_rate
/// ```
pub fn backup_contribution(sync_rate: f64, heartbeat_rate: f64, readiness_rate: f64) -> f64 {
    (0.5 * sync_rate.clamp(0.0, 1.0)
        + 0.3 * heartbeat_rate.clamp(0.0, 1.0)
        + 0.2 * readiness_rate.clamp(0.0, 1.0))
    .clamp(0.0, 1.0)
}

/// Compute contribution for an Active validator.
///
/// ```text
/// contribution = 0.6 × participation_rate + 0.2 × sync_rate + 0.2 × readiness_rate
/// ```
pub fn active_contribution(
    participation_rate: f64,
    sync_rate: f64,
    readiness_rate: f64,
) -> f64 {
    (0.6 * participation_rate.clamp(0.0, 1.0)
        + 0.2 * sync_rate.clamp(0.0, 1.0)
        + 0.2 * readiness_rate.clamp(0.0, 1.0))
    .clamp(0.0, 1.0)
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> ScoringConfig {
        ScoringConfig::default()
    }

    #[test]
    fn test_perfect_validator() {
        let m = ValidatorMetrics {
            stake: 10_000_000_000_000_000, // 10M exactly
            uptime: 1.0,
            contribution: 1.0,
            timeouts: 0,
            invalid_actions: 0,
        };
        let s = compute_score(&m, &default_config());
        // StakeFactor=1.0, uptime=1.0, contribution=1.0, penalty=1.0, credit=1.0
        assert!((s.score - 1.0).abs() < 0.001);
        assert_eq!(s.effective_stake, 10_000_000_000_000_000);
    }

    #[test]
    fn test_saturation_cap() {
        let m = ValidatorMetrics {
            stake: 100_000_000_000_000_000, // 100M — way above cap
            uptime: 1.0,
            contribution: 1.0,
            timeouts: 0,
            invalid_actions: 0,
        };
        let s = compute_score(&m, &default_config());
        // EffectiveStake capped at 30M → StakeFactor = 30M/10M = 3.0 (capped)
        assert_eq!(s.effective_stake, 30_000_000_000_000_000);
        assert!((s.stake_factor - 3.0).abs() < 0.001);
        // Credit: 100M / 10M = 10.0, capped at 3.0
        assert!((s.credit - 3.0).abs() < 0.001);
        // Score = 3.0 * 1.0 * 1.0 * 1.0 * 3.0 = 9.0
        assert!((s.score - 9.0).abs() < 0.001);
    }

    #[test]
    fn test_low_uptime_cliff() {
        let m = ValidatorMetrics {
            stake: 10_000_000_000_000_000,
            uptime: 0.85, // Below 0.90 cliff
            contribution: 1.0,
            timeouts: 0,
            invalid_actions: 0,
        };
        let s = compute_score(&m, &default_config());
        // BasePenalty = 0.5 (cliff triggered)
        assert!((s.penalty_factor - 0.5).abs() < 0.001);
        // Score = 1.0 * 0.85 * 1.0 * 0.5 * 1.0 = 0.425
        assert!((s.score - 0.425).abs() < 0.001);
    }

    #[test]
    fn test_timeouts_reduce_penalty() {
        let m = ValidatorMetrics {
            stake: 10_000_000_000_000_000,
            uptime: 0.95,
            contribution: 1.0,
            timeouts: 5,
            invalid_actions: 0,
        };
        let s = compute_score(&m, &default_config());
        // BasePenalty = 1.0 (above cliff), deductions = 5 * 0.02 = 0.10
        // PenaltyFactor = 1.0 - 0.10 = 0.90
        assert!((s.penalty_factor - 0.90).abs() < 0.001);
    }

    #[test]
    fn test_invalid_actions_severe() {
        let m = ValidatorMetrics {
            stake: 10_000_000_000_000_000,
            uptime: 0.95,
            contribution: 1.0,
            timeouts: 0,
            invalid_actions: 3,
        };
        let s = compute_score(&m, &default_config());
        // deductions = 3 * 0.10 = 0.30
        // PenaltyFactor = 1.0 - 0.30 = 0.70
        assert!((s.penalty_factor - 0.70).abs() < 0.001);
    }

    #[test]
    fn test_credit_linear() {
        let config = default_config();
        // 10M → Credit=1.0
        let m1 = ValidatorMetrics { stake: 10_000_000_000_000_000, uptime: 1.0, contribution: 1.0, timeouts: 0, invalid_actions: 0 };
        assert!((compute_score(&m1, &config).credit - 1.0).abs() < 0.001);

        // 20M → Credit=2.0
        let m2 = ValidatorMetrics { stake: 20_000_000_000_000_000, uptime: 1.0, contribution: 1.0, timeouts: 0, invalid_actions: 0 };
        assert!((compute_score(&m2, &config).credit - 2.0).abs() < 0.001);

        // 50M → Credit=3.0 (capped)
        let m3 = ValidatorMetrics { stake: 50_000_000_000_000_000, uptime: 1.0, contribution: 1.0, timeouts: 0, invalid_actions: 0 };
        assert!((compute_score(&m3, &config).credit - 3.0).abs() < 0.001);
    }

    #[test]
    fn test_backup_contribution() {
        assert!((backup_contribution(1.0, 1.0, 1.0) - 1.0).abs() < 0.001);
        assert!((backup_contribution(0.8, 0.6, 0.4) - 0.66).abs() < 0.01);
    }

    #[test]
    fn test_active_contribution() {
        assert!((active_contribution(1.0, 1.0, 1.0) - 1.0).abs() < 0.001);
        assert!((active_contribution(0.9, 0.8, 0.7) - 0.84).abs() < 0.01);
    }

    #[test]
    fn test_zero_stake_has_floor_credit() {
        let m = ValidatorMetrics {
            stake: 0, uptime: 1.0, contribution: 1.0, timeouts: 0, invalid_actions: 0,
        };
        let s = compute_score(&m, &default_config());
        assert!(s.credit >= 0.1); // Floor
    }
}
