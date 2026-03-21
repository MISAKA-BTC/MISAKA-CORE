//! # MISAKA 2-Role Reward Engine — Weekly Distribution
//!
//! # Architecture
//!
//! ```text
//!                     Weekly Revenue
//!                          │
//!              ┌───────────┼───────────┐
//!              │           │           │
//!         Fee Income    Subsidy     (if deficit)
//!         (L1 txs)   (Solana reserve)
//!              │           │
//!              └─────┬─────┘
//!                    ▼
//!              R_week (total)
//!              ┌─────┼─────────────┐
//!              │     │             │
//!           75%    20%           5%
//!         Validator Service      Burn
//!           Pool    Pool
//!           │
//!      ┌────┼────┐
//!      │         │
//!    75%       25%
//!   Base    Proposer
//! ```
//!
//! # Roles (exactly 2)
//!
//! | Role | Responsibility |
//! |------|---------------|
//! | **Validator** | Block production, voting/finality, state progression, bridge validation |
//! | **Service** | Peer discovery, relay, RPC, validator protection relay |
//!
//! Hidden Node は存在しない。Seed/Public/Sentry は Service に統合。

use serde::{Deserialize, Serialize};

use crate::canonical_supply::{CanonicalSupplyTracker, SupplyError, ONE_MISAKA};

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

/// Total supply (10 billion, 9 decimals).
pub const TOTAL_SUPPLY: u128 = 10_000_000_000 * ONE_MISAKA;

/// Reward reserve on Solana (2 billion).
pub const REWARD_RESERVE: u128 = 2_000_000_000 * ONE_MISAKA;

/// Reserve depletion period (3 years = 156 weeks).
pub const RESERVE_DEPLETION_WEEKS: u128 = 156;

/// Weekly reserve cap = 2B / 156.
pub const WEEKLY_RESERVE_CAP: u128 = REWARD_RESERVE / RESERVE_DEPLETION_WEEKS;

/// Stake damping exponent. α = 0.5 (square-root). Fixed.
pub const ALPHA: f64 = 0.5;

/// Pool split: Validator 75%.
pub const VALIDATOR_POOL_BPS: u64 = 7_500;
/// Pool split: Service 20%.
pub const SERVICE_POOL_BPS: u64 = 2_000;
/// Pool split: Burn 5%.
pub const BURN_POOL_BPS: u64 = 500;

/// Proposer sub-pool within validator pool: 25%.
pub const PROPOSER_SUB_BPS: u64 = 2_500;
/// Validator base sub-pool: 75%.
pub const VALIDATOR_BASE_SUB_BPS: u64 = 7_500;

/// Max proposer reward share per validator per week: 20%.
pub const PROPOSER_CAP_BPS: u64 = 2_000;

/// Service node minimum uptime threshold (below this → no reward).
pub const SERVICE_MIN_UPTIME: f64 = 0.80;

// ═══════════════════════════════════════════════════════════════
//  Weekly Target
// ═══════════════════════════════════════════════════════════════

/// Default weekly target reward.
/// When fee income < target, subsidy fills the gap up to WEEKLY_RESERVE_CAP.
pub const DEFAULT_WEEKLY_TARGET: u128 = WEEKLY_RESERVE_CAP;

// ═══════════════════════════════════════════════════════════════
//  Reward Config
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardConfig {
    pub weekly_target: u128,
}

impl Default for RewardConfig {
    fn default() -> Self {
        Self { weekly_target: DEFAULT_WEEKLY_TARGET }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Validator Input
// ═══════════════════════════════════════════════════════════════

/// Per-validator metrics for one week.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInput {
    pub id: [u8; 20],
    /// Raw stake in base units.
    pub stake: u128,
    /// Uptime fraction ∈ [0, 1].
    pub uptime: f64,
    /// Vote participation rate ∈ [0, 1].
    pub vote_participation: f64,
    /// Correctness (no equivocation, no invalid proposals) ∈ [0, 1].
    pub correctness: f64,
    /// Bridge attestation factor ∈ [0, 1]. 1.0 if full participation.
    pub bridge_factor: f64,
    /// Successful block proposals this week.
    pub proposal_points: u32,
}

impl ValidatorInput {
    /// Compute multiplicative contribution score.
    ///
    /// contribution = uptime × vote_participation × correctness × bridge_factor
    ///
    /// This is MULTIPLICATIVE, not additive. A validator with 0 uptime
    /// gets 0 contribution regardless of other metrics.
    pub fn contribution(&self) -> f64 {
        let raw = self.uptime * self.vote_participation * self.correctness * self.bridge_factor;
        raw.clamp(0.0, 1.0)
    }

    /// Effective stake = stake^α (α = 0.5, square-root).
    pub fn effective_stake(&self) -> f64 {
        (self.stake as f64).powf(ALPHA)
    }

    /// Combined weight = effective_stake × contribution.
    pub fn weight(&self) -> f64 {
        self.effective_stake() * self.contribution()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Service Node Input
// ═══════════════════════════════════════════════════════════════

/// Per-service-node metrics for one week.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceNodeInput {
    pub id: [u8; 20],
    /// Uptime fraction ∈ [0, 1].
    pub uptime: f64,
    /// Relay success rate ∈ [0, 1].
    pub relay_success_rate: f64,
    /// RPC availability ∈ [0, 1].
    pub rpc_availability: f64,
    /// Peer diversity score ∈ [0, 1].
    pub peer_diversity: f64,
}

impl ServiceNodeInput {
    /// Service score = uptime × relay × rpc × peer_diversity.
    ///
    /// Returns 0 if uptime < SERVICE_MIN_UPTIME (minimum threshold).
    pub fn service_score(&self) -> f64 {
        if self.uptime < SERVICE_MIN_UPTIME {
            return 0.0; // Below minimum — no reward
        }
        let raw = self.uptime * self.relay_success_rate * self.rpc_availability * self.peer_diversity;
        raw.clamp(0.0, 1.0)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Weekly Reward Output
// ═══════════════════════════════════════════════════════════════

/// Complete weekly distribution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeeklyDistribution {
    // ── Totals ──
    pub fee_income: u128,
    pub subsidy: u128,
    pub total_reward: u128,

    // ── Pool allocation ──
    pub validator_pool: u128,
    pub service_pool: u128,
    pub burn_amount: u128,

    // ── Validator sub-pools ──
    pub validator_base_pool: u128,
    pub proposer_pool: u128,

    // ── Per-participant rewards ──
    pub validator_rewards: Vec<ValidatorRewardOutput>,
    pub service_rewards: Vec<ServiceRewardOutput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorRewardOutput {
    pub id: [u8; 20],
    pub stake: u128,
    pub effective_stake: f64,
    pub contribution: f64,
    pub weight: f64,
    pub base_reward: u128,
    pub proposer_reward: u128,
    pub total_reward: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRewardOutput {
    pub id: [u8; 20],
    pub service_score: f64,
    pub reward: u128,
}

// ═══════════════════════════════════════════════════════════════
//  Errors
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum RewardError {
    #[error("supply error: {0}")]
    Supply(#[from] SupplyError),

    #[error("no validators — cannot distribute validator pool")]
    NoValidators,

    #[error("accounting error: {field} mismatch (expected={expected}, got={got})")]
    AccountingMismatch { field: String, expected: u128, got: u128 },
}

// ═══════════════════════════════════════════════════════════════
//  Core: compute_weekly_distribution
// ═══════════════════════════════════════════════════════════════

/// Compute the full weekly reward distribution.
///
/// Pure function — does NOT modify supply tracker. Use `execute_weekly`
/// to apply the subsidy lock + mint.
pub fn compute_weekly_distribution(
    fee_income: u128,
    validators: &[ValidatorInput],
    service_nodes: &[ServiceNodeInput],
    remaining_reserve: u128,
    config: &RewardConfig,
) -> WeeklyDistribution {
    // ── Step 1: Subsidy backstop ──
    let deficit = config.weekly_target.saturating_sub(fee_income);
    let subsidy = deficit
        .min(WEEKLY_RESERVE_CAP)
        .min(remaining_reserve);
    let total_reward = fee_income + subsidy;

    // ── Step 2: Pool split (75 / 20 / 5) ──
    let validator_pool = total_reward * VALIDATOR_POOL_BPS as u128 / 10_000;
    let service_pool = total_reward * SERVICE_POOL_BPS as u128 / 10_000;
    let burn_amount = total_reward - validator_pool - service_pool;

    // ── Step 3: Validator sub-pools (base 75% + proposer 25%) ──
    let proposer_pool = validator_pool * PROPOSER_SUB_BPS as u128 / 10_000;
    let validator_base_pool = validator_pool - proposer_pool;

    // ── Step 4: Validator base rewards (weight-based) ──
    let total_weight: f64 = validators.iter().map(|v| v.weight()).sum();

    let mut validator_rewards: Vec<ValidatorRewardOutput> = validators.iter().map(|v| {
        let w = v.weight();
        let base = if total_weight > 0.0 {
            ((validator_base_pool as f64) * (w / total_weight)) as u128
        } else { 0 };

        ValidatorRewardOutput {
            id: v.id,
            stake: v.stake,
            effective_stake: v.effective_stake(),
            contribution: v.contribution(),
            weight: w,
            base_reward: base,
            proposer_reward: 0,
            total_reward: base,
        }
    }).collect();

    // ── Step 5: Proposer rewards (per proposal_points, capped 20%) ──
    let total_proposals: u64 = validators.iter().map(|v| v.proposal_points as u64).sum();
    let proposer_cap = proposer_pool * PROPOSER_CAP_BPS as u128 / 10_000;

    if total_proposals > 0 {
        let per_point = proposer_pool / total_proposals as u128;
        for (i, v) in validators.iter().enumerate() {
            let raw = per_point * v.proposal_points as u128;
            let capped = raw.min(proposer_cap);
            validator_rewards[i].proposer_reward = capped;
            validator_rewards[i].total_reward += capped;
        }
    }

    // ── Step 6: Service node rewards (score-based) ──
    let total_service_score: f64 = service_nodes.iter().map(|s| s.service_score()).sum();

    let service_rewards: Vec<ServiceRewardOutput> = service_nodes.iter().map(|s| {
        let score = s.service_score();
        let reward = if total_service_score > 0.0 {
            ((service_pool as f64) * (score / total_service_score)) as u128
        } else { 0 };

        ServiceRewardOutput { id: s.id, service_score: score, reward }
    }).collect();

    WeeklyDistribution {
        fee_income, subsidy, total_reward,
        validator_pool, service_pool, burn_amount,
        validator_base_pool, proposer_pool,
        validator_rewards, service_rewards,
    }
}

/// Execute weekly distribution — locks subsidy from reserve, mints wMISAKA.
///
/// This is the transactional entry point.
pub fn execute_weekly(
    fee_income: u128,
    validators: &[ValidatorInput],
    service_nodes: &[ServiceNodeInput],
    supply: &mut CanonicalSupplyTracker,
    config: &RewardConfig,
) -> Result<WeeklyDistribution, RewardError> {
    let dist = compute_weekly_distribution(
        fee_income, validators, service_nodes,
        supply.remaining_reward_reserve, config,
    );

    if dist.subsidy > 0 {
        let proof = supply.lock_subsidy_from_reserve(dist.subsidy)?;
        supply.mint_wmisaka(&proof)?;
    }

    Ok(dist)
}

// ═══════════════════════════════════════════════════════════════
//  Global State
// ═══════════════════════════════════════════════════════════════

/// Complete protocol economic state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolEconomicState {
    /// Current week number (0-indexed from genesis).
    pub week: u64,
    /// Canonical supply tracker (bridge + reserve).
    pub supply: CanonicalSupplyTracker,
    /// Cumulative fees collected.
    pub cumulative_fees: u128,
    /// Cumulative subsidy used.
    pub cumulative_subsidy: u128,
    /// Cumulative burned.
    pub cumulative_burned: u128,
    /// Last weekly distribution (for RPC queries).
    pub last_distribution: Option<WeeklyDistribution>,
}

impl ProtocolEconomicState {
    pub fn genesis() -> Self {
        Self {
            week: 0,
            supply: CanonicalSupplyTracker::new(),
            cumulative_fees: 0,
            cumulative_subsidy: 0,
            cumulative_burned: 0,
            last_distribution: None,
        }
    }

    /// Process a full week.
    pub fn process_week(
        &mut self,
        fee_income: u128,
        validators: &[ValidatorInput],
        service_nodes: &[ServiceNodeInput],
        config: &RewardConfig,
    ) -> Result<WeeklyDistribution, RewardError> {
        let dist = execute_weekly(
            fee_income, validators, service_nodes,
            &mut self.supply, config,
        )?;

        self.week += 1;
        self.cumulative_fees += dist.fee_income;
        self.cumulative_subsidy += dist.subsidy;
        self.cumulative_burned += dist.burn_amount;
        self.last_distribution = Some(dist.clone());

        Ok(dist)
    }

    /// Verify all invariants.
    pub fn verify_invariants(&self) -> Result<(), RewardError> {
        self.supply.verify_invariant()?;

        // subsidy_used <= initial reserve
        if self.cumulative_subsidy > REWARD_RESERVE {
            return Err(RewardError::AccountingMismatch {
                field: "cumulative_subsidy".into(),
                expected: REWARD_RESERVE,
                got: self.cumulative_subsidy,
            });
        }

        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
//  Gini Coefficient (fairness metric)
// ═══════════════════════════════════════════════════════════════

pub fn gini(values: &[u128]) -> f64 {
    if values.is_empty() { return 0.0; }
    let n = values.len() as f64;
    let mut sorted: Vec<f64> = values.iter().map(|v| *v as f64).collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let total: f64 = sorted.iter().sum();
    if total == 0.0 { return 0.0; }
    let mut sum = 0.0;
    for (i, v) in sorted.iter().enumerate() {
        sum += (2.0 * (i as f64 + 1.0) - n - 1.0) * v;
    }
    sum / (n * total)
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn val(id: u8, stake_m: u128, proposals: u32) -> ValidatorInput {
        ValidatorInput {
            id: { let mut v = [0u8;20]; v[0] = id; v },
            stake: stake_m * ONE_MISAKA,
            uptime: 1.0, vote_participation: 1.0, correctness: 1.0,
            bridge_factor: 1.0, proposal_points: proposals,
        }
    }

    fn svc(id: u8, uptime: f64, relay: f64, rpc: f64, diversity: f64) -> ServiceNodeInput {
        ServiceNodeInput {
            id: { let mut v = [0u8;20]; v[0] = id; v },
            uptime, relay_success_rate: relay,
            rpc_availability: rpc, peer_diversity: diversity,
        }
    }

    // ── Pool Split ──

    #[test]
    fn test_pool_split_75_20_5() {
        let dist = compute_weekly_distribution(
            1_000_000 * ONE_MISAKA,
            &[val(1, 10_000, 10)],
            &[svc(1, 1.0, 1.0, 1.0, 1.0)],
            REWARD_RESERVE, &RewardConfig::default(),
        );
        let total = dist.total_reward;
        assert_eq!(dist.validator_pool, total * 7500 / 10_000);
        assert_eq!(dist.service_pool, total * 2000 / 10_000);
        assert_eq!(dist.burn_amount, total - dist.validator_pool - dist.service_pool);
    }

    // ── Subsidy Backstop ──

    #[test]
    fn test_subsidy_when_fees_low() {
        let fee = 1_000 * ONE_MISAKA;
        let dist = compute_weekly_distribution(
            fee, &[val(1, 10_000, 10)], &[], REWARD_RESERVE,
            &RewardConfig::default(),
        );
        assert!(dist.subsidy > 0, "subsidy should kick in");
        assert_eq!(dist.total_reward, fee + dist.subsidy);
    }

    #[test]
    fn test_no_subsidy_when_fees_sufficient() {
        let target = DEFAULT_WEEKLY_TARGET;
        let dist = compute_weekly_distribution(
            target + 1, &[val(1, 10_000, 10)], &[], REWARD_RESERVE,
            &RewardConfig::default(),
        );
        assert_eq!(dist.subsidy, 0);
    }

    #[test]
    fn test_subsidy_capped_at_weekly_cap() {
        let dist = compute_weekly_distribution(
            0, &[val(1, 10_000, 10)], &[], REWARD_RESERVE,
            &RewardConfig { weekly_target: REWARD_RESERVE }, // huge target
        );
        assert_eq!(dist.subsidy, WEEKLY_RESERVE_CAP);
    }

    #[test]
    fn test_subsidy_capped_by_remaining_reserve() {
        let tiny_reserve = 100 * ONE_MISAKA;
        let dist = compute_weekly_distribution(
            0, &[val(1, 10_000, 10)], &[], tiny_reserve,
            &RewardConfig::default(),
        );
        assert_eq!(dist.subsidy, tiny_reserve);
    }

    // ── Validator Base Reward (sqrt weighting) ──

    #[test]
    fn test_sqrt_anti_concentration() {
        let dist = compute_weekly_distribution(
            1_000_000 * ONE_MISAKA,
            &[val(1, 1_000, 5), val(2, 1_000_000, 5)],
            &[], REWARD_RESERVE, &RewardConfig::default(),
        );
        let small = &dist.validator_rewards[0];
        let large = &dist.validator_rewards[1];

        // Per-token reward: small should be > 10x larger
        let small_per = small.base_reward as f64 / small.stake as f64;
        let large_per = large.base_reward as f64 / large.stake as f64;
        assert!(small_per > large_per * 10.0,
            "sqrt weighting: small gets {}x more per token (expected >10x)", small_per / large_per);

        // Absolute: large still earns more
        assert!(large.base_reward > small.base_reward);
    }

    // ── Contribution = multiplicative ──

    #[test]
    fn test_zero_uptime_zero_reward() {
        let mut v = val(1, 10_000, 10);
        v.uptime = 0.0;
        let dist = compute_weekly_distribution(
            1_000_000 * ONE_MISAKA,
            &[v, val(2, 10_000, 10)],
            &[], REWARD_RESERVE, &RewardConfig::default(),
        );
        assert_eq!(dist.validator_rewards[0].base_reward, 0);
        assert!(dist.validator_rewards[1].base_reward > 0);
    }

    #[test]
    fn test_zero_bridge_factor_zero_contribution() {
        let mut v = val(1, 10_000, 10);
        v.bridge_factor = 0.0; // Not participating in bridge
        assert_eq!(v.contribution(), 0.0);
    }

    #[test]
    fn test_contribution_multiplicative() {
        let v = ValidatorInput {
            id: [0;20], stake: 10_000 * ONE_MISAKA,
            uptime: 0.9, vote_participation: 0.95,
            correctness: 1.0, bridge_factor: 0.8,
            proposal_points: 0,
        };
        let expected = 0.9 * 0.95 * 1.0 * 0.8;
        assert!((v.contribution() - expected).abs() < 1e-9);
    }

    // ── Proposer Rewards ──

    #[test]
    fn test_proposer_cap_20_percent() {
        let dist = compute_weekly_distribution(
            1_000_000 * ONE_MISAKA,
            &[val(1, 10_000, 100), val(2, 10_000, 0)],
            &[], REWARD_RESERVE, &RewardConfig::default(),
        );
        let cap = dist.proposer_pool * PROPOSER_CAP_BPS as u128 / 10_000;
        assert!(dist.validator_rewards[0].proposer_reward <= cap,
            "proposer reward {} exceeds cap {}", dist.validator_rewards[0].proposer_reward, cap);
    }

    #[test]
    fn test_proposer_sub_pool_25_percent_of_validator() {
        let dist = compute_weekly_distribution(
            1_000_000 * ONE_MISAKA,
            &[val(1, 10_000, 10)],
            &[], REWARD_RESERVE, &RewardConfig::default(),
        );
        assert_eq!(dist.proposer_pool, dist.validator_pool * 2500 / 10_000);
        assert_eq!(dist.validator_base_pool, dist.validator_pool - dist.proposer_pool);
    }

    // ── Service Node Rewards ──

    #[test]
    fn test_service_node_reward_distribution() {
        let dist = compute_weekly_distribution(
            1_000_000 * ONE_MISAKA,
            &[val(1, 10_000, 10)],
            &[svc(1, 1.0, 0.9, 0.95, 0.85), svc(2, 1.0, 0.8, 0.9, 0.7)],
            REWARD_RESERVE, &RewardConfig::default(),
        );
        assert!(dist.service_rewards[0].reward > dist.service_rewards[1].reward,
            "higher-scoring service node should earn more");
        let total_svc: u128 = dist.service_rewards.iter().map(|s| s.reward).sum();
        assert!(total_svc <= dist.service_pool);
    }

    #[test]
    fn test_service_below_uptime_threshold_no_reward() {
        let dist = compute_weekly_distribution(
            1_000_000 * ONE_MISAKA,
            &[val(1, 10_000, 10)],
            &[svc(1, 0.79, 1.0, 1.0, 1.0), svc(2, 0.90, 1.0, 1.0, 1.0)],
            REWARD_RESERVE, &RewardConfig::default(),
        );
        assert_eq!(dist.service_rewards[0].reward, 0, "below 80% uptime → 0 reward");
        assert!(dist.service_rewards[1].reward > 0);
    }

    // ── Execute + State ──

    #[test]
    fn test_execute_weekly_locks_subsidy() {
        let mut supply = CanonicalSupplyTracker::new();
        let config = RewardConfig::default();
        let dist = execute_weekly(
            1_000 * ONE_MISAKA, &[val(1, 10_000, 10)], &[],
            &mut supply, &config,
        ).expect("execute");

        assert!(dist.subsidy > 0);
        supply.verify_invariant().expect("bridge invariant");
    }

    #[test]
    fn test_protocol_state_multi_week() {
        let mut state = ProtocolEconomicState::genesis();
        let config = RewardConfig::default();

        for week in 0..10u64 {
            let fee = (week as u128 + 1) * 100_000 * ONE_MISAKA;
            state.process_week(
                fee, &[val(1, 10_000, 10)], &[svc(1, 0.95, 0.9, 0.9, 0.8)],
                &config,
            ).expect("process week");
        }

        assert_eq!(state.week, 10);
        assert!(state.cumulative_fees > 0);
        state.verify_invariants().expect("invariants");
    }

    // ── Gini ──

    #[test]
    fn test_gini_equal() {
        assert!(gini(&[100, 100, 100]).abs() < 0.01);
    }

    #[test]
    fn test_gini_unequal() {
        assert!(gini(&[0, 0, 0, 1000]) > 0.5);
    }

    // ── Weekly Reserve Cap ──

    #[test]
    fn test_weekly_cap_computation() {
        // 2B / 156 ≈ 12,820,512.82 MISAKA
        let cap_misaka = WEEKLY_RESERVE_CAP / ONE_MISAKA;
        assert_eq!(cap_misaka, 12_820_512);
    }
}
