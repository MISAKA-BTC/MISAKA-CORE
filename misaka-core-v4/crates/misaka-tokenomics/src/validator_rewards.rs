//! # Validator Reward Engine — Smoothed, Anti-Concentrated, Contribution-Based
//!
//! # Reward Formula
//!
//! ```text
//! weekly_reward = weekly_fee_income_on_L1 + weekly_subsidy_from_Solana_reserve
//!
//! weekly_subsidy = min(
//!     max(0, weekly_target_reward - weekly_fee_income),
//!     weekly_reserve_cap,
//!     remaining_validator_reward_reserve
//! )
//! ```
//!
//! # Anti-Concentration: Sub-Linear Stake Weighting
//!
//! ```text
//! effective_stake_i = stake_i ^ α     where α = 0.5 (square-root)
//! weight_i = effective_stake_i × contribution_i
//! reward_i = validator_pool × (weight_i / Σ weight_j)
//! ```
//!
//! # Reward Pool Split
//!
//! ```text
//! 70% → active validators (weight-based)
//! 20% → block proposers (per-proposal bonus)
//! 10% → burned or reserved
//! ```

use serde::{Deserialize, Serialize};

use crate::canonical_supply::{CanonicalSupplyTracker, SupplyError, ONE_MISAKA};

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

/// Default stake damping exponent (square-root weighting).
/// α = 0.5 means effective_stake = sqrt(stake).
pub const DEFAULT_ALPHA: f64 = 0.5;

/// Validator pool share (70%).
pub const VALIDATOR_POOL_BPS: u64 = 7_000;

/// Proposer pool share (20%).
pub const PROPOSER_POOL_BPS: u64 = 2_000;

/// Burn/reserve share (10%).
pub const BURN_RESERVE_BPS: u64 = 1_000;

/// Maximum share of proposer rewards one validator can receive per window.
pub const PROPOSER_CAP_BPS: u64 = 2_500; // 25% of proposer pool

/// Default weekly target reward in base units (configurable).
pub const DEFAULT_WEEKLY_TARGET: u128 = 500_000 * ONE_MISAKA; // 500K MISAKA/week

/// Default weekly reserve cap (max subsidy per week).
pub const DEFAULT_WEEKLY_RESERVE_CAP: u128 = 200_000 * ONE_MISAKA; // 200K MISAKA/week

// ═══════════════════════════════════════════════════════════════
//  Reward Configuration
// ═══════════════════════════════════════════════════════════════

/// Weekly reward configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardConfig {
    /// Target weekly reward (base units).
    pub weekly_target_reward: u128,
    /// Maximum subsidy from reserve per week (base units).
    pub weekly_reserve_cap: u128,
    /// Stake damping exponent (0.5 = square-root).
    pub alpha: f64,
    /// Proposer reward cap per validator per window (basis points of proposer pool).
    pub proposer_cap_bps: u64,
}

impl Default for RewardConfig {
    fn default() -> Self {
        Self {
            weekly_target_reward: DEFAULT_WEEKLY_TARGET,
            weekly_reserve_cap: DEFAULT_WEEKLY_RESERVE_CAP,
            alpha: DEFAULT_ALPHA,
            proposer_cap_bps: PROPOSER_CAP_BPS,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Contribution Score
// ═══════════════════════════════════════════════════════════════

/// Validator contribution metrics for one epoch/week.
///
/// Each metric is normalized to [0.0, 1.0].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContributionMetrics {
    /// Block proposal success rate.
    pub proposal_rate: f64,
    /// Vote participation rate.
    pub vote_rate: f64,
    /// Uptime fraction.
    pub uptime: f64,
    /// Latency performance score (1.0 = best, 0.0 = worst).
    pub latency_score: f64,
}

impl ContributionMetrics {
    /// Compute the composite contribution score ∈ [0, 1].
    ///
    /// Weighted average:
    /// - 30% proposal success
    /// - 30% vote participation
    /// - 25% uptime
    /// - 15% latency
    pub fn contribution_score(&self) -> f64 {
        let raw = self.proposal_rate * 0.30
            + self.vote_rate * 0.30
            + self.uptime * 0.25
            + self.latency_score * 0.15;
        raw.clamp(0.0, 1.0)
    }

    /// Perfect contribution (for testing / genesis).
    pub fn perfect() -> Self {
        Self { proposal_rate: 1.0, vote_rate: 1.0, uptime: 1.0, latency_score: 1.0 }
    }

    /// Zero contribution (inactive validator).
    pub fn zero() -> Self {
        Self { proposal_rate: 0.0, vote_rate: 0.0, uptime: 0.0, latency_score: 0.0 }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Validator Entry
// ═══════════════════════════════════════════════════════════════

/// A single validator's data for reward calculation.
#[derive(Debug, Clone)]
pub struct ValidatorRewardEntry {
    /// Validator identifier.
    pub validator_id: [u8; 20],
    /// Raw stake (base units).
    pub stake: u128,
    /// Contribution metrics for this period.
    pub contribution: ContributionMetrics,
    /// Number of successful block proposals in this period.
    pub proposals_in_period: u32,
}

// ═══════════════════════════════════════════════════════════════
//  Weekly Reward Calculation
// ═══════════════════════════════════════════════════════════════

/// Result of computing weekly rewards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeeklyRewardResult {
    /// Total reward distributed this week.
    pub total_reward: u128,
    /// Fee income component.
    pub fee_income: u128,
    /// Subsidy component (from Solana reserve).
    pub subsidy: u128,
    /// Amount allocated to validator pool (70%).
    pub validator_pool: u128,
    /// Amount allocated to proposer pool (20%).
    pub proposer_pool: u128,
    /// Amount burned/reserved (10%).
    pub burned_reserved: u128,
    /// Per-validator reward breakdown.
    pub validator_rewards: Vec<ValidatorReward>,
}

/// Individual validator reward.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorReward {
    pub validator_id: [u8; 20],
    /// Raw stake.
    pub stake: u128,
    /// Effective stake after damping (stake^α).
    pub effective_stake: f64,
    /// Contribution score [0, 1].
    pub contribution_score: f64,
    /// Combined weight = effective_stake × contribution_score.
    pub weight: f64,
    /// Reward from validator pool (weight-based).
    pub validator_pool_reward: u128,
    /// Reward from proposer pool (per-proposal).
    pub proposer_reward: u128,
    /// Total reward = validator_pool_reward + proposer_reward.
    pub total_reward: u128,
}

/// Compute weekly rewards for all validators.
///
/// # Steps
///
/// 1. Compute subsidy backstop
/// 2. Split total reward into pools (70/20/10)
/// 3. Compute effective stake (stake^α) for each validator
/// 4. Compute contribution-weighted shares
/// 5. Distribute validator pool proportionally
/// 6. Distribute proposer pool with per-validator cap
/// 7. Burn/reserve the remainder
pub fn compute_weekly_rewards(
    fee_income: u128,
    validators: &[ValidatorRewardEntry],
    supply_tracker: &CanonicalSupplyTracker,
    config: &RewardConfig,
) -> WeeklyRewardResult {
    // ── Step 1: Subsidy backstop ──
    let deficit = if fee_income >= config.weekly_target_reward {
        0u128
    } else {
        config.weekly_target_reward - fee_income
    };

    let subsidy = deficit
        .min(config.weekly_reserve_cap)
        .min(supply_tracker.remaining_reward_reserve);

    let total_reward = fee_income + subsidy;

    // ── Step 2: Pool split ──
    let validator_pool = total_reward * VALIDATOR_POOL_BPS as u128 / 10_000;
    let proposer_pool = total_reward * PROPOSER_POOL_BPS as u128 / 10_000;
    let burned_reserved = total_reward - validator_pool - proposer_pool;

    // ── Step 3-4: Effective stake + contribution weighting ──
    let alpha = config.alpha.clamp(0.5, 0.8);

    let weighted: Vec<(usize, f64)> = validators.iter().enumerate().map(|(i, v)| {
        let effective_stake = (v.stake as f64).powf(alpha);
        let contribution = v.contribution.contribution_score();
        let weight = effective_stake * contribution;
        (i, weight)
    }).collect();

    let total_weight: f64 = weighted.iter().map(|(_, w)| w).sum();

    // ── Step 5: Validator pool distribution ──
    let mut validator_rewards: Vec<ValidatorReward> = validators.iter().enumerate().map(|(i, v)| {
        let effective_stake = (v.stake as f64).powf(alpha);
        let contribution_score = v.contribution.contribution_score();
        let weight = effective_stake * contribution_score;

        let pool_reward = if total_weight > 0.0 {
            ((validator_pool as f64) * (weight / total_weight)) as u128
        } else {
            0
        };

        ValidatorReward {
            validator_id: v.validator_id,
            stake: v.stake,
            effective_stake,
            contribution_score,
            weight,
            validator_pool_reward: pool_reward,
            proposer_reward: 0, // Filled in step 6
            total_reward: pool_reward,
        }
    }).collect();

    // ── Step 6: Proposer pool distribution with per-validator cap ──
    let total_proposals: u32 = validators.iter().map(|v| v.proposals_in_period).sum();
    let proposer_cap = proposer_pool * config.proposer_cap_bps as u128 / 10_000;

    if total_proposals > 0 {
        let reward_per_proposal = proposer_pool / total_proposals as u128;

        for (i, v) in validators.iter().enumerate() {
            let raw_proposer_reward = reward_per_proposal * v.proposals_in_period as u128;
            let capped = raw_proposer_reward.min(proposer_cap);
            validator_rewards[i].proposer_reward = capped;
            validator_rewards[i].total_reward += capped;
        }
    }

    WeeklyRewardResult {
        total_reward,
        fee_income,
        subsidy,
        validator_pool,
        proposer_pool,
        burned_reserved,
        validator_rewards,
    }
}

/// Execute the weekly reward: lock subsidy from reserve + mint wMISAKA for rewards.
///
/// This is the transactional entry point — it modifies the supply tracker.
pub fn execute_weekly_rewards(
    fee_income: u128,
    validators: &[ValidatorRewardEntry],
    supply_tracker: &mut CanonicalSupplyTracker,
    config: &RewardConfig,
) -> Result<WeeklyRewardResult, SupplyError> {
    let result = compute_weekly_rewards(fee_income, validators, supply_tracker, config);

    // Lock subsidy from Solana reserve if needed
    if result.subsidy > 0 {
        let subsidy_proof = supply_tracker.lock_subsidy_from_reserve(result.subsidy)?;
        supply_tracker.mint_wmisaka(&subsidy_proof)?;
    }

    Ok(result)
}

// ═══════════════════════════════════════════════════════════════
//  Anti-Concentration Analysis
// ═══════════════════════════════════════════════════════════════

/// Analyze the anti-concentration effect of stake damping.
///
/// Returns the Gini coefficient of rewards vs raw stake.
/// Lower = more equal. 0.0 = perfect equality, 1.0 = maximum inequality.
pub fn compute_reward_gini(rewards: &[ValidatorReward]) -> f64 {
    if rewards.is_empty() { return 0.0; }
    let n = rewards.len() as f64;
    let mut sorted_rewards: Vec<f64> = rewards.iter()
        .map(|r| r.total_reward as f64)
        .collect();
    sorted_rewards.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let total: f64 = sorted_rewards.iter().sum();
    if total == 0.0 { return 0.0; }

    let mut sum = 0.0;
    for (i, reward) in sorted_rewards.iter().enumerate() {
        sum += (2.0 * (i as f64 + 1.0) - n - 1.0) * reward;
    }

    sum / (n * total)
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_supply::CanonicalSupplyTracker;

    fn make_validator(id: u8, stake_misaka: u128, proposals: u32) -> ValidatorRewardEntry {
        ValidatorRewardEntry {
            validator_id: {
                let mut v = [0u8; 20];
                v[0] = id;
                v
            },
            stake: stake_misaka * ONE_MISAKA,
            contribution: ContributionMetrics::perfect(),
            proposals_in_period: proposals,
        }
    }

    #[test]
    fn test_weekly_reward_no_subsidy_when_fees_sufficient() {
        let tracker = CanonicalSupplyTracker::new();
        let config = RewardConfig::default();
        let validators = vec![make_validator(1, 10_000, 10)];

        let result = compute_weekly_rewards(
            config.weekly_target_reward + 1000, // fees exceed target
            &validators,
            &tracker,
            &config,
        );

        assert_eq!(result.subsidy, 0);
        assert_eq!(result.fee_income, config.weekly_target_reward + 1000);
    }

    #[test]
    fn test_weekly_reward_subsidy_backstop() {
        let tracker = CanonicalSupplyTracker::new();
        let config = RewardConfig::default();
        let validators = vec![make_validator(1, 10_000, 10)];

        let fee_income = 100_000 * ONE_MISAKA; // below target
        let result = compute_weekly_rewards(fee_income, &validators, &tracker, &config);

        let expected_subsidy = (config.weekly_target_reward - fee_income)
            .min(config.weekly_reserve_cap);
        assert_eq!(result.subsidy, expected_subsidy);
        assert_eq!(result.total_reward, fee_income + expected_subsidy);
    }

    #[test]
    fn test_pool_split_70_20_10() {
        let tracker = CanonicalSupplyTracker::new();
        let config = RewardConfig::default();
        let validators = vec![make_validator(1, 10_000, 10)];

        let total = 1_000_000 * ONE_MISAKA;
        let result = compute_weekly_rewards(total, &validators, &tracker, &config);

        assert_eq!(result.validator_pool, total * 7000 / 10_000);
        assert_eq!(result.proposer_pool, total * 2000 / 10_000);
        assert_eq!(result.burned_reserved, total - result.validator_pool - result.proposer_pool);
    }

    #[test]
    fn test_sqrt_weighting_favors_small_validators() {
        let tracker = CanonicalSupplyTracker::new();
        let config = RewardConfig { alpha: 0.5, ..Default::default() };

        // Small validator: 1,000 MISAKA stake
        // Large validator: 1,000,000 MISAKA stake (1000x more)
        let validators = vec![
            make_validator(1, 1_000, 5),
            make_validator(2, 1_000_000, 5),
        ];

        let result = compute_weekly_rewards(
            config.weekly_target_reward,
            &validators,
            &tracker,
            &config,
        );

        let small = &result.validator_rewards[0];
        let large = &result.validator_rewards[1];

        // With sqrt: effective_stake ratio = sqrt(1000) / sqrt(1000000) = ~31.6 / ~1000 = ~1:31.6
        // Without damping: ratio would be 1:1000
        // So small validator gets ~31x more reward per token staked
        let small_per_token = small.validator_pool_reward as f64 / small.stake as f64;
        let large_per_token = large.validator_pool_reward as f64 / large.stake as f64;

        assert!(
            small_per_token > large_per_token * 10.0,
            "small validator should get >10x more reward per token with sqrt weighting"
        );

        // Large still earns more in absolute terms
        assert!(large.validator_pool_reward > small.validator_pool_reward);
    }

    #[test]
    fn test_zero_contribution_gets_zero_reward() {
        let tracker = CanonicalSupplyTracker::new();
        let config = RewardConfig::default();

        let validators = vec![
            ValidatorRewardEntry {
                validator_id: [1; 20],
                stake: 10_000 * ONE_MISAKA,
                contribution: ContributionMetrics::zero(), // inactive
                proposals_in_period: 0,
            },
            make_validator(2, 10_000, 10), // active
        ];

        let result = compute_weekly_rewards(
            config.weekly_target_reward,
            &validators,
            &tracker,
            &config,
        );

        assert_eq!(result.validator_rewards[0].validator_pool_reward, 0);
        assert!(result.validator_rewards[1].validator_pool_reward > 0);
    }

    #[test]
    fn test_proposer_cap_enforced() {
        let tracker = CanonicalSupplyTracker::new();
        let config = RewardConfig {
            proposer_cap_bps: 2500, // 25%
            ..Default::default()
        };

        // One validator did ALL proposals
        let validators = vec![
            make_validator(1, 10_000, 100), // all proposals
            make_validator(2, 10_000, 0),   // no proposals
        ];

        let result = compute_weekly_rewards(
            config.weekly_target_reward,
            &validators,
            &tracker,
            &config,
        );

        let proposer_cap = result.proposer_pool * config.proposer_cap_bps as u128 / 10_000;
        assert!(
            result.validator_rewards[0].proposer_reward <= proposer_cap,
            "proposer reward must be capped at {}% of pool",
            config.proposer_cap_bps / 100
        );
    }

    #[test]
    fn test_execute_weekly_rewards_locks_subsidy() {
        let mut tracker = CanonicalSupplyTracker::new();
        let config = RewardConfig::default();
        let validators = vec![make_validator(1, 10_000, 10)];

        let fee_income = 100_000 * ONE_MISAKA; // below target → subsidy needed
        let result = execute_weekly_rewards(
            fee_income, &validators, &mut tracker, &config,
        ).expect("execute");

        assert!(result.subsidy > 0);
        assert_eq!(tracker.outstanding_wmisaka, result.subsidy);
        assert!(tracker.remaining_reward_reserve < crate::canonical_supply::VALIDATOR_REWARD_RESERVE);
        tracker.verify_invariant().expect("bridge invariant must hold");
    }

    #[test]
    fn test_contribution_score_computation() {
        let m = ContributionMetrics {
            proposal_rate: 0.9,
            vote_rate: 0.95,
            uptime: 1.0,
            latency_score: 0.8,
        };
        let score = m.contribution_score();
        // 0.9*0.3 + 0.95*0.3 + 1.0*0.25 + 0.8*0.15 = 0.27 + 0.285 + 0.25 + 0.12 = 0.925
        assert!((score - 0.925).abs() < 0.001);
    }

    #[test]
    fn test_gini_equal_distribution() {
        let rewards = vec![
            ValidatorReward {
                validator_id: [1; 20], stake: 100, effective_stake: 10.0,
                contribution_score: 1.0, weight: 10.0,
                validator_pool_reward: 100, proposer_reward: 0, total_reward: 100,
            },
            ValidatorReward {
                validator_id: [2; 20], stake: 100, effective_stake: 10.0,
                contribution_score: 1.0, weight: 10.0,
                validator_pool_reward: 100, proposer_reward: 0, total_reward: 100,
            },
        ];
        let gini = compute_reward_gini(&rewards);
        assert!(gini.abs() < 0.01, "equal distribution should have ~0 Gini");
    }
}
