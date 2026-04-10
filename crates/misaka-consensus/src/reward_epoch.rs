//! # Epoch Reward Distribution — Workload Tracking + Linear Stake Rewards
//!
//! Integrates `misaka-tokenomics` into the consensus epoch lifecycle:
//!
//! 1. During an epoch: accumulate validator workload events
//! 2. At epoch boundary: freeze snapshots, compute scores, distribute rewards
//!
//! ```text
//! ┌─────────────┐    ┌──────────────────┐    ┌─────────────────┐
//! │  Consensus   │───▶│  WorkloadTracker  │───▶│ distribute_epoch │
//! │  (votes,     │    │  (per-validator   │    │ _rewards()       │
//! │   blocks)    │    │   accumulators)   │    │ (tokenomics)     │
//! └─────────────┘    └──────────────────┘    └─────────────────┘
//! ```

use misaka_tokenomics::{
    compute_network_summary, distribute_epoch_rewards, NetworkWorkloadSummary,
    RewardBreakdownSnapshot, RewardWeightConfig, ValidatorRewardInput, ValidatorWorkloadSnapshot,
    WorkloadAccumulator, WorkloadConfig,
};
use misaka_types::validator::ValidatorId;
use std::collections::HashMap;

/// Tracks per-validator workload during an epoch and distributes rewards at epoch end.
pub struct RewardEpochTracker {
    config: WorkloadConfig,
    reward_config: RewardWeightConfig,
    /// Per-validator workload accumulators (reset each epoch).
    accumulators: HashMap<ValidatorId, (WorkloadAccumulator, u128, u64)>, // (acc, stake, smoothed_score)
    /// Fee pool accumulated during this epoch.
    epoch_fee_pool: u128,
    /// Current epoch number.
    epoch: u64,
    /// Carry-over dust from previous epoch.
    carry_forward: u128,
}

impl RewardEpochTracker {
    pub fn new(epoch: u64, config: WorkloadConfig, reward_config: RewardWeightConfig) -> Self {
        Self {
            config,
            reward_config,
            accumulators: HashMap::new(),
            epoch_fee_pool: 0,
            epoch,
            carry_forward: 0,
        }
    }

    /// Register a validator (call at epoch start or on new validator registration).
    /// SEC-FIX TM-10: Always update stake to the latest value, even for existing validators.
    /// Previously `or_insert_with` would ignore stake changes after initial registration.
    pub fn register_validator(
        &mut self,
        id: ValidatorId,
        stake: u128,
        initial_smoothed_score: u64,
    ) {
        self.accumulators
            .entry(id)
            .and_modify(|(_, existing_stake, _)| {
                *existing_stake = stake;
            })
            .or_insert_with(|| {
                (
                    WorkloadAccumulator::default(),
                    stake,
                    initial_smoothed_score,
                )
            });
    }

    /// Record a block proposal.
    pub fn on_block_proposed(&mut self, validator: &ValidatorId, accepted: bool, fee: u128) {
        if let Some((acc, _, _)) = self.accumulators.get_mut(validator) {
            acc.proposed_blocks += 1;
            if accepted {
                acc.accepted_blocks += 1;
                // SEC-FIX NM-1: checked_add to prevent u128 overflow
                self.epoch_fee_pool = self.epoch_fee_pool.saturating_add(fee);
            } else {
                acc.rejected_blocks += 1;
            }
        }
    }

    /// Record a consensus vote.
    pub fn on_vote(&mut self, validator: &ValidatorId, signed: bool) {
        if let Some((acc, _, _)) = self.accumulators.get_mut(validator) {
            if signed {
                acc.signed_votes += 1;
            } else {
                acc.missed_votes += 1;
            }
        }
    }

    /// Record block validation.
    pub fn on_validated(&mut self, validator: &ValidatorId) {
        if let Some((acc, _, _)) = self.accumulators.get_mut(validator) {
            acc.validated_blocks += 1;
        }
    }

    /// Record finality contribution.
    pub fn on_finality(&mut self, validator: &ValidatorId) {
        if let Some((acc, _, _)) = self.accumulators.get_mut(validator) {
            acc.finalized_contribution_count += 1;
        }
    }

    /// Record message relay.
    pub fn on_relay(&mut self, validator: &ValidatorId, count: u64) {
        if let Some((acc, _, _)) = self.accumulators.get_mut(validator) {
            acc.relayed_messages += count;
        }
    }

    /// Record uptime check.
    pub fn on_uptime_check(&mut self, validator: &ValidatorId, passed: bool) {
        if let Some((acc, _, _)) = self.accumulators.get_mut(validator) {
            if passed {
                acc.uptime_checks_passed += 1;
                acc.active_time_slots += 1;
            } else {
                acc.uptime_checks_failed += 1;
            }
        }
    }

    /// Process epoch transition — freeze snapshots & distribute rewards.
    ///
    /// Returns the results and resets accumulators for the next epoch.
    pub fn transition_epoch(&mut self) -> EpochRewardOutput {
        let epoch = self.epoch;
        let pool = self.epoch_fee_pool + self.carry_forward;

        // Freeze workload snapshots
        let mut snapshots = Vec::new();
        let mut reward_inputs = Vec::new();

        for (vid, (acc, stake, _smoothed)) in &self.accumulators {
            let validator_id = hex::encode(vid);
            let snap = acc
                .clone()
                .into_snapshot(validator_id.clone(), epoch, &self.config);

            reward_inputs.push(ValidatorRewardInput {
                validator_id,
                active_stake: *stake,
                smoothed_score: snap.workload_score, // use current epoch score
            });

            snapshots.push(snap);
        }

        // Network summary
        let network_summary = compute_network_summary(epoch, &snapshots);

        // Distribute rewards
        let result = distribute_epoch_rewards(epoch, pool, &reward_inputs, &self.reward_config);

        // Update smoothed scores for next epoch (EMA: 70/30)
        for (vid, (_, _, smoothed)) in self.accumulators.iter_mut() {
            let validator_id = hex::encode(vid);
            let current = snapshots
                .iter()
                .find(|s| s.validator_id == validator_id)
                .map(|s| s.workload_score)
                .unwrap_or(0);
            *smoothed = (*smoothed * 7 + current * 3) / 10;
        }

        let output = EpochRewardOutput {
            epoch,
            fee_pool: pool,
            snapshots,
            breakdowns: result.breakdowns,
            network_summary,
            carry_forward: result.next_epoch_carry,
        };

        // Reset for next epoch
        self.epoch += 1;
        self.epoch_fee_pool = 0;
        self.carry_forward = output.carry_forward;
        for (_, (acc, _, _)) in self.accumulators.iter_mut() {
            *acc = WorkloadAccumulator::default();
        }

        output
    }

    pub fn current_epoch(&self) -> u64 {
        self.epoch
    }
    pub fn epoch_fee_pool(&self) -> u128 {
        self.epoch_fee_pool
    }
    pub fn validator_count(&self) -> usize {
        self.accumulators.len()
    }
}

/// Output of an epoch reward transition.
#[derive(Debug)]
pub struct EpochRewardOutput {
    pub epoch: u64,
    pub fee_pool: u128,
    pub snapshots: Vec<ValidatorWorkloadSnapshot>,
    pub breakdowns: Vec<RewardBreakdownSnapshot>,
    pub network_summary: NetworkWorkloadSummary,
    pub carry_forward: u128,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vid(n: u8) -> ValidatorId {
        [n; 32]
    }

    #[test]
    fn test_tracker_basic_flow() {
        let mut tracker =
            RewardEpochTracker::new(0, WorkloadConfig::default(), RewardWeightConfig::default());

        tracker.register_validator(vid(1), 100_000, 0);
        tracker.register_validator(vid(2), 400_000, 0);

        // Simulate work
        tracker.on_block_proposed(&vid(1), true, 500);
        tracker.on_block_proposed(&vid(2), true, 300);
        tracker.on_vote(&vid(1), true);
        tracker.on_vote(&vid(2), true);
        tracker.on_validated(&vid(1));
        tracker.on_validated(&vid(2));
        tracker.on_uptime_check(&vid(1), true);
        tracker.on_uptime_check(&vid(2), true);

        let output = tracker.transition_epoch();

        assert_eq!(output.epoch, 0);
        assert_eq!(output.snapshots.len(), 2);
        assert_eq!(output.breakdowns.len(), 2);
        assert_eq!(output.fee_pool, 800);

        let total_rewarded: u128 = output.breakdowns.iter().map(|b| b.epoch_reward).sum();
        assert_eq!(total_rewarded + output.carry_forward, 800);

        // Next epoch should be reset
        assert_eq!(tracker.current_epoch(), 1);
        assert_eq!(tracker.epoch_fee_pool(), 0);
    }

    #[test]
    fn test_linear_stake_in_rewards() {
        let mut tracker =
            RewardEpochTracker::new(0, WorkloadConfig::default(), RewardWeightConfig::default());

        // V2 has 100x stake → linear weight is 100x, but the per-validator
        // 33% reward cap (introduced in H3) limits maximum individual reward.
        // With only 2 validators, V2's uncapped share (~99%) is capped at 33%.
        tracker.register_validator(vid(1), 100, 0);
        tracker.register_validator(vid(2), 10_000, 0);

        for v in [vid(1), vid(2)] {
            tracker.on_block_proposed(&v, true, 500);
            tracker.on_vote(&v, true);
            tracker.on_validated(&v);
            tracker.on_uptime_check(&v, true);
        }

        let output = tracker.transition_epoch();
        let r1 = output
            .breakdowns
            .iter()
            .find(|b| b.validator_id == hex::encode(vid(1)))
            .map(|b| b.epoch_reward)
            .unwrap_or(0);
        let r2 = output
            .breakdowns
            .iter()
            .find(|b| b.validator_id == hex::encode(vid(2)))
            .map(|b| b.epoch_reward)
            .unwrap_or(0);

        // V2 has higher stake so it should receive more reward.
        // The exact ratio is limited by the 33% per-validator cap.
        assert!(
            r2 > r1,
            "higher stake should yield higher reward: r1={r1}, r2={r2}"
        );
    }

    #[test]
    fn test_carry_forward_preserved() {
        let mut tracker =
            RewardEpochTracker::new(0, WorkloadConfig::default(), RewardWeightConfig::default());
        tracker.register_validator(vid(1), 100, 0);
        tracker.register_validator(vid(2), 100, 0);
        tracker.register_validator(vid(3), 100, 0);

        for v in [vid(1), vid(2), vid(3)] {
            tracker.on_block_proposed(&v, true, 33);
            tracker.on_vote(&v, true);
        }

        let out = tracker.transition_epoch();
        // 99 total pool, 3 equal validators → some dust
        assert_eq!(
            out.breakdowns.iter().map(|b| b.epoch_reward).sum::<u128>() + out.carry_forward,
            99
        );
    }
}
