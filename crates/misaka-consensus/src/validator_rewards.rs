//! Validator Rewards — epoch reward distribution with Active 80% / Backup 20% split.
//!
//! # Reward Formula
//!
//! ```text
//! EpochReward_i = BaseReward_i × uptime_i × contribution_i × PenaltyFactor_i
//! ```
//!
//! # Distribution
//!
//! - Total epoch emission is split: 80% Active pool, 20% Backup pool
//! - Within each pool, rewards are distributed proportional to each validator's
//!   reward score (uptime × contribution × penalty)
//! - Undistributed rewards (from penalized validators) carry over to next epoch
//!
//! # No Slashing
//!
//! Stake is NEVER reduced. Only rewards are affected by poor performance.

use serde::{Deserialize, Serialize};

use super::validator_scoring::{compute_score, ScoringConfig, ValidatorMetrics};

/// Reward distribution configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardConfig {
    /// Fraction of epoch emission going to Active validators (0.0 - 1.0).
    pub active_pool_share: f64,
    /// Fraction going to Backup validators.
    pub backup_pool_share: f64,
    /// Weak credit multiplier for rewards (softer than scoring credit).
    /// Prevents stake inequality from compounding too fast.
    pub reward_credit_weight: f64,
}

impl Default for RewardConfig {
    fn default() -> Self {
        Self {
            active_pool_share: 0.80,
            backup_pool_share: 0.20,
            reward_credit_weight: 0.2, // 20% influence from credit
        }
    }
}

/// Per-validator reward result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorReward {
    pub validator_id: [u8; 32],
    /// Reward amount (base units, 9 decimals).
    pub reward: u64,
    /// Reward score components for transparency.
    pub reward_score: f64,
    /// Role at time of distribution.
    pub role: ValidatorRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorRole {
    Active,
    Backup,
}

/// Input for reward distribution.
#[derive(Debug, Clone)]
pub struct RewardInput {
    pub validator_id: [u8; 32],
    pub metrics: ValidatorMetrics,
    pub role: ValidatorRole,
}

/// Epoch reward distribution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochRewardResult {
    /// Per-validator rewards.
    pub rewards: Vec<ValidatorReward>,
    /// Total distributed to Active validators.
    pub active_total_distributed: u64,
    /// Total distributed to Backup validators.
    pub backup_total_distributed: u64,
    /// Undistributed (carried over to next epoch).
    pub carry_over: u64,
    /// Epoch number.
    pub epoch: u64,
}

/// Distribute rewards for an epoch.
///
/// # Arguments
/// - `epoch`: current epoch number
/// - `total_emission`: total MISAKA to distribute this epoch (base units)
/// - `validators`: all validators with their metrics and roles
/// - `scoring_config`: scoring parameters (for penalty/credit calculation)
/// - `reward_config`: reward distribution parameters
pub fn distribute_epoch_rewards(
    epoch: u64,
    total_emission: u64,
    validators: &[RewardInput],
    scoring_config: &ScoringConfig,
    reward_config: &RewardConfig,
) -> EpochRewardResult {
    let active_pool = (total_emission as f64 * reward_config.active_pool_share) as u64;
    let backup_pool = (total_emission as f64 * reward_config.backup_pool_share) as u64;

    // ── Compute reward scores ──
    // RewardScore_i = uptime × contribution × PenaltyFactor × RewardCredit
    // RewardCredit = 1.0 + (credit - 1.0) * reward_credit_weight
    //   This softens the credit influence on rewards to prevent compounding.

    let mut active_scores: Vec<([u8; 32], f64)> = Vec::new();
    let mut backup_scores: Vec<([u8; 32], f64)> = Vec::new();

    for v in validators {
        let breakdown = compute_score(&v.metrics, scoring_config);
        let reward_credit = 1.0 + (breakdown.credit - 1.0) * reward_config.reward_credit_weight;
        let reward_credit = reward_credit.max(0.1);

        let reward_score =
            breakdown.uptime * breakdown.contribution * breakdown.penalty_factor * reward_credit;

        match v.role {
            ValidatorRole::Active => active_scores.push((v.validator_id, reward_score)),
            ValidatorRole::Backup => backup_scores.push((v.validator_id, reward_score)),
        }
    }

    // ── Distribute Active pool (80%) ──
    let active_rewards = distribute_pool(active_pool, &active_scores);

    // ── Distribute Backup pool (20%) ──
    let backup_rewards = distribute_pool(backup_pool, &backup_scores);

    // ── Merge results ──
    let active_total: u64 = active_rewards.iter().map(|r| r.1).sum();
    let backup_total: u64 = backup_rewards.iter().map(|r| r.1).sum();
    let carry_over = total_emission.saturating_sub(active_total + backup_total);

    let mut rewards: Vec<ValidatorReward> = Vec::new();

    for (id, amount) in &active_rewards {
        let score = active_scores
            .iter()
            .find(|(vid, _)| vid == id)
            .map(|(_, s)| *s)
            .unwrap_or(0.0);
        rewards.push(ValidatorReward {
            validator_id: *id,
            reward: *amount,
            reward_score: score,
            role: ValidatorRole::Active,
        });
    }

    for (id, amount) in &backup_rewards {
        let score = backup_scores
            .iter()
            .find(|(vid, _)| vid == id)
            .map(|(_, s)| *s)
            .unwrap_or(0.0);
        rewards.push(ValidatorReward {
            validator_id: *id,
            reward: *amount,
            reward_score: score,
            role: ValidatorRole::Backup,
        });
    }

    EpochRewardResult {
        rewards,
        active_total_distributed: active_total,
        backup_total_distributed: backup_total,
        carry_over,
        epoch,
    }
}

/// Distribute a pool proportionally to reward scores.
fn distribute_pool(pool: u64, scores: &[([u8; 32], f64)]) -> Vec<([u8; 32], u64)> {
    let total_score: f64 = scores.iter().map(|(_, s)| s).sum();

    if total_score <= 0.0 || pool == 0 {
        return scores.iter().map(|(id, _)| (*id, 0u64)).collect();
    }

    let mut result: Vec<([u8; 32], u64)> = Vec::new();
    let mut distributed: u64 = 0;

    for (id, score) in scores {
        let share = ((*score / total_score) * pool as f64).floor() as u64;
        result.push((*id, share));
        distributed += share;
    }

    // Give leftover dust to highest scorer (deterministic)
    if distributed < pool && !result.is_empty() {
        let dust = pool - distributed;
        // Find highest scorer
        let max_idx = scores
            .iter()
            .enumerate()
            .max_by(|(_, a), (_, b)| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, _)| i)
            .unwrap_or(0);
        result[max_idx].1 += dust;
    }

    result
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_input(id: u8, stake: u64, uptime: f64, role: ValidatorRole) -> RewardInput {
        RewardInput {
            validator_id: {
                let mut v = [0u8; 32];
                v[0] = id;
                v
            },
            metrics: ValidatorMetrics {
                stake,
                uptime,
                contribution: 1.0,
                timeouts: 0,
                invalid_actions: 0,
            },
            role,
        }
    }

    #[test]
    fn test_80_20_split() {
        let validators = vec![
            make_input(1, 10_000_000_000_000_000, 1.0, ValidatorRole::Active),
            make_input(2, 10_000_000_000_000_000, 1.0, ValidatorRole::Backup),
        ];

        let result = distribute_epoch_rewards(
            1,
            1_000_000_000, // 1 MISAKA total emission
            &validators,
            &ScoringConfig::default(),
            &RewardConfig::default(),
        );

        // Active gets 80%, Backup gets 20%
        assert_eq!(result.active_total_distributed, 800_000_000);
        assert_eq!(result.backup_total_distributed, 200_000_000);
        assert_eq!(result.carry_over, 0);
    }

    #[test]
    fn test_low_uptime_gets_less_reward() {
        let validators = vec![
            make_input(1, 10_000_000_000_000_000, 1.0, ValidatorRole::Active),
            make_input(2, 10_000_000_000_000_000, 0.5, ValidatorRole::Active),
        ];

        let result = distribute_epoch_rewards(
            1,
            1_000_000_000,
            &validators,
            &ScoringConfig::default(),
            &RewardConfig::default(),
        );

        let r1 = result
            .rewards
            .iter()
            .find(|r| r.validator_id[0] == 1)
            .unwrap();
        let r2 = result
            .rewards
            .iter()
            .find(|r| r.validator_id[0] == 2)
            .unwrap();

        // Validator 1 (uptime=1.0) should get more than validator 2 (uptime=0.5)
        assert!(
            r1.reward > r2.reward,
            "v1={} should > v2={}",
            r1.reward,
            r2.reward
        );
    }

    #[test]
    fn test_no_validators_no_crash() {
        let result = distribute_epoch_rewards(
            1,
            1_000_000_000,
            &[],
            &ScoringConfig::default(),
            &RewardConfig::default(),
        );
        assert_eq!(result.rewards.len(), 0);
        assert_eq!(result.carry_over, 1_000_000_000);
    }

    #[test]
    fn test_zero_uptime_zero_reward() {
        let validators = vec![make_input(
            1,
            10_000_000_000_000_000,
            0.0,
            ValidatorRole::Active,
        )];

        let result = distribute_epoch_rewards(
            1,
            1_000_000_000,
            &validators,
            &ScoringConfig::default(),
            &RewardConfig::default(),
        );

        let r1 = result
            .rewards
            .iter()
            .find(|r| r.validator_id[0] == 1)
            .unwrap();
        assert_eq!(r1.reward, 0); // uptime=0 → reward=0
    }

    #[test]
    fn test_backup_receives_20_percent() {
        let mut validators = Vec::new();
        for i in 0..21u8 {
            validators.push(make_input(
                i,
                10_000_000_000_000_000,
                1.0,
                ValidatorRole::Active,
            ));
        }
        for i in 100..110u8 {
            validators.push(make_input(
                i,
                1_000_000_000_000_000,
                0.95,
                ValidatorRole::Backup,
            ));
        }

        let result = distribute_epoch_rewards(
            1,
            100_000_000_000, // 100 MISAKA
            &validators,
            &ScoringConfig::default(),
            &RewardConfig::default(),
        );

        // Active pool: 80 MISAKA, Backup pool: 20 MISAKA
        let active_sum: u64 = result
            .rewards
            .iter()
            .filter(|r| r.role == ValidatorRole::Active)
            .map(|r| r.reward)
            .sum();
        let backup_sum: u64 = result
            .rewards
            .iter()
            .filter(|r| r.role == ValidatorRole::Backup)
            .map(|r| r.reward)
            .sum();

        // Allow small rounding error
        assert!((active_sum as f64 - 80_000_000_000.0).abs() < 100.0);
        assert!((backup_sum as f64 - 20_000_000_000.0).abs() < 100.0);
    }
}
