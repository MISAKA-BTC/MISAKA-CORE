//! # Reward Distribution — Fee-Only Model with Linear Stake Weighting
//!
//! # Core Formula
//!
//! ```text
//! reward_weight_i = active_stake_i * smoothed_score_i
//!
//! validator_reward_i =
//!     validator_pool_total
//!     * reward_weight_i
//!     / total_reward_weight
//! ```
//!
//! # Design Goals
//!
//! 1. **Fee-only**: No inflation; reward pool comes from transaction fees
//! 2. **Linear stake**: Reward scales proportionally with staked amount
//! 3. **Work-weighted**: `smoothed_score` reflects actual validator contributions
//! 4. **Integer-only**: No floats; deterministic across all architectures
//! 5. **Remainder-safe**: Rounding dust goes to `next_epoch_carry`
//!
//! # Tie-Breaking
//!
//! When two validators have identical `reward_weight`, the tie is broken
//! by lexicographic ordering of `validator_id` (deterministic, auditable).

use serde::{Deserialize, Serialize};

use crate::workload::serde_u128_string;

// ═══════════════════════════════════════════════════════════════
//  Reward Configuration
// ═══════════════════════════════════════════════════════════════

/// Reward weight model configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardWeightConfig {
    /// Enable stake component in weight calculation.
    /// If false, stake is ignored (pure score mode — weight = score).
    pub stake_enabled: bool,
}

impl Default for RewardWeightConfig {
    fn default() -> Self {
        Self {
            stake_enabled: true,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Reward Breakdown Snapshot (per-validator, per-epoch)
// ═══════════════════════════════════════════════════════════════

/// Complete reward breakdown for one validator in one epoch.
///
/// This is the "explain your reward" response — it shows every step
/// from stake → weight → share → payout.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RewardBreakdownSnapshot {
    pub validator_id: String,
    pub epoch: u64,
    /// Active (bonded) stake in the smallest token unit.
    #[serde(with = "serde_u128_string")]
    pub active_stake: u128,
    /// Stake component used in weight calculation (= active_stake, clamped to u64).
    pub stake_weight: u64,
    /// Smoothed performance score (EMA or epoch score).
    pub smoothed_score: u64,
    /// `stake_weight * smoothed_score` — the full reward weight.
    #[serde(with = "serde_u128_string")]
    pub reward_weight: u128,
    /// This validator's share in parts per million (ppm).
    /// `reward_weight * 1_000_000 / total_reward_weight`
    pub reward_share_ppm: u64,
    /// Actual reward received in the smallest token unit.
    #[serde(with = "serde_u128_string")]
    pub epoch_reward: u128,
}

// ═══════════════════════════════════════════════════════════════
//  Epoch Reward Input
// ═══════════════════════════════════════════════════════════════

/// Input data for one validator's reward calculation.
#[derive(Debug, Clone)]
pub struct ValidatorRewardInput {
    pub validator_id: String,
    pub active_stake: u128,
    pub smoothed_score: u64,
}

// ═══════════════════════════════════════════════════════════════
//  Epoch Reward Output
// ═══════════════════════════════════════════════════════════════

/// Result of epoch reward distribution.
#[derive(Debug, Clone)]
pub struct EpochRewardResult {
    /// Per-validator breakdowns (sorted by validator_id for determinism).
    pub breakdowns: Vec<RewardBreakdownSnapshot>,
    /// Undistributed dust carried to the next epoch.
    pub next_epoch_carry: u128,
    /// Total reward weight across all validators.
    pub total_reward_weight: u128,
}

// ═══════════════════════════════════════════════════════════════
//  Stake Weight — linear (power = 1)
// ═══════════════════════════════════════════════════════════════

/// Compute the stake weight component (linear).
///
/// Returns `active_stake` clamped to u64.
/// The full reward weight is `stake_weight * smoothed_score`.
///
/// # Linear Scaling Effect
///
/// ```text
/// stake = 100          → stake_weight = 100
/// stake = 10,000       → stake_weight = 10,000
/// stake = 1,000,000    → stake_weight = 1,000,000
/// ```
///
/// 100x stake → 100x reward weight (proportional).
fn linear_stake_weight(active_stake: u128) -> u64 {
    if active_stake > u64::MAX as u128 {
        u64::MAX
    } else {
        active_stake as u64
    }
}

// ═══════════════════════════════════════════════════════════════
//  Distribution Logic
// ═══════════════════════════════════════════════════════════════

/// Distribute epoch rewards across validators.
///
/// # Formula
///
/// ```text
/// reward_weight_i = active_stake_i * smoothed_score_i
/// validator_reward_i = pool * reward_weight_i / total_reward_weight
/// ```
///
/// # Determinism
///
/// This function is 100% deterministic:
/// - Integer-only math
/// - Sorted by validator_id (lexicographic)
/// - Tie-break on validator_id ordering
/// - Remainder accumulated in `next_epoch_carry`
pub fn distribute_epoch_rewards(
    epoch: u64,
    validator_pool_total: u128,
    validators: &[ValidatorRewardInput],
    config: &RewardWeightConfig,
) -> EpochRewardResult {
    if validators.is_empty() || validator_pool_total == 0 {
        return EpochRewardResult {
            breakdowns: Vec::new(),
            next_epoch_carry: validator_pool_total,
            total_reward_weight: 0,
        };
    }

    // Step 1: Compute reward weights (linear stake × score)
    let mut entries: Vec<(String, u128, u64, u64, u128)> = validators
        .iter()
        .map(|v| {
            let sw = if config.stake_enabled {
                linear_stake_weight(v.active_stake)
            } else {
                // If stake disabled, stake component is 1 (pure score mode)
                1u64
            };
            let weight = sw as u128 * v.smoothed_score as u128;
            (
                v.validator_id.clone(),
                v.active_stake,
                sw,
                v.smoothed_score,
                weight,
            )
        })
        .collect();

    // Step 2: Sort by validator_id (deterministic tie-break)
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    // Step 3: Compute total weight
    let total_reward_weight: u128 = entries.iter().map(|e| e.4).sum();

    if total_reward_weight == 0 {
        let breakdowns = entries
            .iter()
            .map(|(id, stake, sw, score, _w)| RewardBreakdownSnapshot {
                validator_id: id.clone(),
                epoch,
                active_stake: *stake,
                stake_weight: *sw,
                smoothed_score: *score,
                reward_weight: 0,
                reward_share_ppm: 0,
                epoch_reward: 0,
            })
            .collect();

        return EpochRewardResult {
            breakdowns,
            next_epoch_carry: validator_pool_total,
            total_reward_weight: 0,
        };
    }

    // Step 4: Distribute rewards
    let mut distributed: u128 = 0;
    let breakdowns: Vec<RewardBreakdownSnapshot> = entries
        .iter()
        .map(|(id, stake, sw, score, weight)| {
            let epoch_reward = if *weight == 0 {
                0u128
            } else {
                validator_pool_total * *weight / total_reward_weight
            };
            distributed += epoch_reward;

            let share_ppm = (*weight * 1_000_000 / total_reward_weight) as u64;

            RewardBreakdownSnapshot {
                validator_id: id.clone(),
                epoch,
                active_stake: *stake,
                stake_weight: *sw,
                smoothed_score: *score,
                reward_weight: *weight,
                reward_share_ppm: share_ppm,
                epoch_reward,
            }
        })
        .collect();

    // Step 5: Remainder → carry
    let next_epoch_carry = validator_pool_total - distributed;

    EpochRewardResult {
        breakdowns,
        next_epoch_carry,
        total_reward_weight,
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> RewardWeightConfig {
        RewardWeightConfig::default()
    }

    #[test]
    fn test_empty_validators() {
        let result = distribute_epoch_rewards(1, 1_000_000, &[], &default_config());
        assert!(result.breakdowns.is_empty());
        assert_eq!(result.next_epoch_carry, 1_000_000);
    }

    #[test]
    fn test_zero_pool() {
        let vals = vec![ValidatorRewardInput {
            validator_id: "v1".into(),
            active_stake: 10000,
            smoothed_score: 100,
        }];
        let result = distribute_epoch_rewards(1, 0, &vals, &default_config());
        // Zero pool → no rewards distributed, carry remains 0
        assert!(result.breakdowns.is_empty() || result.breakdowns[0].epoch_reward == 0);
        assert_eq!(result.next_epoch_carry, 0);
    }

    #[test]
    fn test_single_validator_gets_all() {
        let vals = vec![ValidatorRewardInput {
            validator_id: "v1".into(),
            active_stake: 10000,
            smoothed_score: 500,
        }];
        let pool = 1_000_000u128;
        let result = distribute_epoch_rewards(1, pool, &vals, &default_config());

        assert_eq!(result.breakdowns.len(), 1);
        assert_eq!(result.breakdowns[0].epoch_reward, pool);
        assert_eq!(result.next_epoch_carry, 0);
        assert_eq!(result.breakdowns[0].reward_share_ppm, 1_000_000);
    }

    #[test]
    fn test_equal_validators_equal_reward() {
        let vals = vec![
            ValidatorRewardInput {
                validator_id: "v1".into(),
                active_stake: 10000,
                smoothed_score: 500,
            },
            ValidatorRewardInput {
                validator_id: "v2".into(),
                active_stake: 10000,
                smoothed_score: 500,
            },
        ];
        let pool = 1_000_000u128;
        let result = distribute_epoch_rewards(1, pool, &vals, &default_config());

        assert_eq!(result.breakdowns[0].epoch_reward, 500_000);
        assert_eq!(result.breakdowns[1].epoch_reward, 500_000);
        assert_eq!(result.next_epoch_carry, 0);
    }

    #[test]
    fn test_reward_weight_formula_consistency() {
        let vals = vec![ValidatorRewardInput {
            validator_id: "v1".into(),
            active_stake: 250_000_000_000, // 250B
            smoothed_score: 831_500,
        }];
        let result = distribute_epoch_rewards(128, 100_000_000, &vals, &default_config());

        let bd = &result.breakdowns[0];
        // Verify: reward_weight = stake_weight * smoothed_score
        assert_eq!(
            bd.reward_weight,
            bd.stake_weight as u128 * bd.smoothed_score as u128,
            "reward_weight must equal stake_weight * smoothed_score"
        );
    }

    #[test]
    fn test_linear_stake_proportional() {
        // V1: 100 stake, same score
        // V2: 10000 stake (100x), same score
        // With linear weighting: 100x stake → 100x reward
        let vals = vec![
            ValidatorRewardInput {
                validator_id: "v1".into(),
                active_stake: 100,
                smoothed_score: 1000,
            },
            ValidatorRewardInput {
                validator_id: "v2".into(),
                active_stake: 10000,
                smoothed_score: 1000,
            },
        ];
        let pool = 1_010_000u128; // divisible nicely
        let result = distribute_epoch_rewards(1, pool, &vals, &default_config());

        let r1 = result.breakdowns[0].epoch_reward;
        let r2 = result.breakdowns[1].epoch_reward;

        // V2 has 100x stake → should get 100x reward (linear)
        // weight_v1 = 100 * 1000 = 100_000
        // weight_v2 = 10000 * 1000 = 10_000_000
        // total = 10_100_000
        // r1 = 1_010_000 * 100_000 / 10_100_000 = 10_000
        // r2 = 1_010_000 * 10_000_000 / 10_100_000 = 1_000_000
        let ratio = r2 / r1.max(1);
        assert_eq!(
            ratio, 100,
            "100x stake should yield exactly 100x reward with linear weighting"
        );
    }

    #[test]
    fn test_score_matters_with_linear_stake() {
        // V1: low stake, very high score
        // V2: high stake, low score
        let vals = vec![
            ValidatorRewardInput {
                validator_id: "v1".into(),
                active_stake: 100,
                smoothed_score: 10_000,
            },
            ValidatorRewardInput {
                validator_id: "v2".into(),
                active_stake: 1_000_000,
                smoothed_score: 1,
            },
        ];
        let pool = 2_000_000u128;
        let result = distribute_epoch_rewards(1, pool, &vals, &default_config());

        let r1 = result.breakdowns[0].epoch_reward;
        let r2 = result.breakdowns[1].epoch_reward;

        // V1 weight: 100 * 10000 = 1_000_000
        // V2 weight: 1_000_000 * 1 = 1_000_000
        // Equal weights → equal rewards
        assert_eq!(r1, r2, "equal weight should yield equal reward");
    }

    #[test]
    fn test_zero_weight_gets_zero_reward() {
        let vals = vec![
            ValidatorRewardInput {
                validator_id: "active".into(),
                active_stake: 10000,
                smoothed_score: 500,
            },
            ValidatorRewardInput {
                validator_id: "idle".into(),
                active_stake: 10000,
                smoothed_score: 0, // zero score → zero weight
            },
        ];
        let pool = 1_000_000u128;
        let result = distribute_epoch_rewards(1, pool, &vals, &default_config());

        let idle = result
            .breakdowns
            .iter()
            .find(|b| b.validator_id == "idle")
            .expect("idle");
        assert_eq!(
            idle.epoch_reward, 0,
            "zero-score validator must get zero reward"
        );
        assert_eq!(idle.reward_weight, 0);
    }

    #[test]
    fn test_remainder_goes_to_carry() {
        // 3 equal validators, pool = 100 → 33 each, 1 remainder
        let vals = vec![
            ValidatorRewardInput {
                validator_id: "a".into(),
                active_stake: 100,
                smoothed_score: 100,
            },
            ValidatorRewardInput {
                validator_id: "b".into(),
                active_stake: 100,
                smoothed_score: 100,
            },
            ValidatorRewardInput {
                validator_id: "c".into(),
                active_stake: 100,
                smoothed_score: 100,
            },
        ];
        let pool = 100u128;
        let result = distribute_epoch_rewards(1, pool, &vals, &default_config());

        let total_distributed: u128 = result.breakdowns.iter().map(|b| b.epoch_reward).sum();
        assert_eq!(
            total_distributed + result.next_epoch_carry,
            pool,
            "distributed + carry must equal pool"
        );
        assert!(
            result.next_epoch_carry > 0,
            "3-way split of 100 should have remainder"
        );
    }

    #[test]
    fn test_deterministic_ordering() {
        let vals = vec![
            ValidatorRewardInput {
                validator_id: "z_last".into(),
                active_stake: 10000,
                smoothed_score: 500,
            },
            ValidatorRewardInput {
                validator_id: "a_first".into(),
                active_stake: 10000,
                smoothed_score: 500,
            },
        ];
        let result = distribute_epoch_rewards(1, 100, &vals, &default_config());

        assert_eq!(result.breakdowns[0].validator_id, "a_first");
        assert_eq!(result.breakdowns[1].validator_id, "z_last");
    }

    #[test]
    fn test_no_distribution_exceeds_pool() {
        let vals: Vec<ValidatorRewardInput> = (0..50)
            .map(|i| ValidatorRewardInput {
                validator_id: format!("v{i:03}"),
                active_stake: (i as u128 + 1) * 1000,
                smoothed_score: (i as u64 + 1) * 100,
            })
            .collect();

        let pool = 999_999_999u128;
        let result = distribute_epoch_rewards(1, pool, &vals, &default_config());

        let total: u128 = result.breakdowns.iter().map(|b| b.epoch_reward).sum();
        assert!(
            total <= pool,
            "distributed ({total}) must not exceed pool ({pool})"
        );
        assert_eq!(total + result.next_epoch_carry, pool);
    }

    #[test]
    fn test_breakdown_serde_roundtrip() {
        let bd = RewardBreakdownSnapshot {
            validator_id: "val_001".into(),
            epoch: 128,
            active_stake: 250_000_000_000,
            stake_weight: 250_000_000_000u64,
            smoothed_score: 831_500,
            reward_weight: 250_000_000_000u128 * 831_500,
            reward_share_ppm: 8421,
            epoch_reward: 12_000_444,
        };

        let json = serde_json::to_string(&bd).expect("serialize");
        let deser: RewardBreakdownSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(bd, deser);
    }

    #[test]
    fn test_disabled_stake_pure_score_mode() {
        let config = RewardWeightConfig {
            stake_enabled: false,
        };
        let vals = vec![
            ValidatorRewardInput {
                validator_id: "rich".into(),
                active_stake: 1_000_000_000,
                smoothed_score: 100,
            },
            ValidatorRewardInput {
                validator_id: "poor".into(),
                active_stake: 1,
                smoothed_score: 100,
            },
        ];
        let result = distribute_epoch_rewards(1, 1_000_000, &vals, &config);

        // With stake disabled, stake is ignored → equal scores = equal reward
        assert_eq!(
            result.breakdowns[0].epoch_reward, result.breakdowns[1].epoch_reward,
            "with stake disabled, equal scores must yield equal rewards"
        );
    }

    #[test]
    fn test_linear_stake_weight_clamping() {
        // u128 value larger than u64::MAX should be clamped
        assert_eq!(linear_stake_weight(u64::MAX as u128), u64::MAX);
        assert_eq!(linear_stake_weight(u64::MAX as u128 + 1), u64::MAX);
        assert_eq!(linear_stake_weight(100), 100);
        assert_eq!(linear_stake_weight(0), 0);
    }
}
