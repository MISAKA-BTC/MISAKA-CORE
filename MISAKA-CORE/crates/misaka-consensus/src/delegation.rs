//! Delegated Staking — users delegate MISAKA to validators for rewards.
//!
//! # Design
//!
//! ```text
//! Delegator (user)          Validator
//! ┌──────────┐              ┌──────────┐
//! │ delegate │──TxDelegate──►│ pool     │ stake += amount
//! │          │              │          │ weight recalculated
//! │ undelegate│◄─unbonding───│          │ stake -= amount (after cooldown)
//! │          │              │          │
//! │ claim    │◄─rewards──────│ proposer │ (1 - commission) × share
//! └──────────┘              │ reward   │
//!                           └──────────┘
//! ```
//!
//! # UTXO Integration
//!
//! - Delegation = special UTXO (TxType::Delegate) locked to validator
//! - Undelegation = TxType::Undelegate → enters unbonding queue
//! - Rewards = distributed proportionally at epoch boundary
//!
//! # Slashing Propagation
//!
//! When a validator is slashed, ALL delegators lose proportional stake.
//! This creates economic alignment: delegators must choose validators carefully.
//!
//! # Comparison
//!
//! | Feature | Cosmos | Ethereum | MISAKA |
//! |---------|--------|----------|--------|
//! | Redelegation | Yes | No | Phase 2 |
//! | Unbonding Period | 21 days | ~7 days | 7 days (10080 epochs) |
//! | Commission | Validator-set | N/A | Per-validator BPS |
//! | Reward Model | Block + fee | Block + tip | Block + fee (proportional) |

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::staking::{StakingConfig, StakingRegistry, ValidatorState};
use misaka_types::validator::ValidatorId;

// ═══════════════════════════════════════════════════════════════
//  Delegation Types
// ═══════════════════════════════════════════════════════════════

/// Unique identifier for a delegation (delegator address + validator ID).
pub type DelegationId = [u8; 32];

/// A delegation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    /// Delegation ID (SHA3-256 of delegator_address || validator_id || nonce).
    pub id: DelegationId,
    /// Delegator's one-time stealth address (privacy-preserving).
    pub delegator_address: [u8; 32],
    /// Target validator.
    pub validator_id: [u8; 32],
    /// Delegated amount (base units).
    pub amount: u64,
    /// Epoch when delegation was created.
    pub start_epoch: u64,
    /// Unbonding state (None = active, Some = unbonding).
    pub unbonding: Option<UnbondingEntry>,
    /// Accumulated unclaimed rewards (base units).
    pub pending_rewards: u64,
    /// Last epoch when rewards were computed.
    pub last_reward_epoch: u64,
}

/// Unbonding entry — delegation is exiting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnbondingEntry {
    /// Amount being unbonded.
    pub amount: u64,
    /// Epoch when unbonding completes.
    pub complete_epoch: u64,
}

impl Delegation {
    /// Whether this delegation is active (not unbonding).
    pub fn is_active(&self) -> bool {
        self.unbonding.is_none() && self.amount > 0
    }

    /// Whether unbonding is complete and can be withdrawn.
    pub fn can_withdraw(&self, current_epoch: u64) -> bool {
        match &self.unbonding {
            Some(entry) => current_epoch >= entry.complete_epoch,
            None => false,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Validator Delegation Pool
// ═══════════════════════════════════════════════════════════════

/// Per-validator aggregation of all delegations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorPool {
    pub validator_id: [u8; 32],
    /// Total actively delegated stake.
    pub total_delegated: u64,
    /// Total unbonding stake.
    pub total_unbonding: u64,
    /// Number of active delegations.
    pub delegation_count: u32,
    /// Validator's commission rate (BPS, e.g., 1000 = 10%).
    pub commission_bps: u32,
}

impl ValidatorPool {
    pub fn new(validator_id: [u8; 32], commission_bps: u32) -> Self {
        Self {
            validator_id,
            total_delegated: 0,
            total_unbonding: 0,
            delegation_count: 0,
            commission_bps,
        }
    }

    /// Effective voting power = self-stake + delegated stake.
    pub fn effective_stake(&self, self_stake: u64) -> u128 {
        self_stake as u128 + self.total_delegated as u128
    }
}

// ═══════════════════════════════════════════════════════════════
//  Delegation Registry
// ═══════════════════════════════════════════════════════════════

/// Global delegation registry.
///
/// Manages all delegations across all validators.
/// Integrated with `StakingRegistry` for effective stake calculation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRegistry {
    /// All delegations by ID.
    delegations: HashMap<DelegationId, Delegation>,
    /// Per-validator pools.
    pools: HashMap<[u8; 32], ValidatorPool>,
    /// Minimum delegation amount.
    pub min_delegation: u64,
    /// Maximum delegations per validator (DoS protection).
    pub max_delegations_per_validator: u32,
    /// Unbonding period (same as validator unbonding for consistency).
    pub unbonding_epochs: u64,
}

impl DelegationRegistry {
    pub fn new(min_delegation: u64, unbonding_epochs: u64) -> Self {
        Self {
            delegations: HashMap::new(),
            pools: HashMap::new(),
            min_delegation,
            max_delegations_per_validator: 10_000,
            unbonding_epochs,
        }
    }

    pub fn testnet() -> Self {
        Self::new(1_000_000, 100) // 1 MISAKA min, 100 epoch unbonding
    }

    pub fn mainnet() -> Self {
        Self::new(1_000_000_000, 10_080) // 1000 MISAKA min, ~7 day unbonding
    }

    // ─── Queries ────────────────────────────────────────────

    pub fn get(&self, id: &DelegationId) -> Option<&Delegation> {
        self.delegations.get(id)
    }

    pub fn pool(&self, validator_id: &[u8; 32]) -> Option<&ValidatorPool> {
        self.pools.get(validator_id)
    }

    /// Total delegated stake for a validator.
    pub fn total_delegated_to(&self, validator_id: &[u8; 32]) -> u64 {
        self.pools
            .get(validator_id)
            .map(|p| p.total_delegated)
            .unwrap_or(0)
    }

    /// Effective voting power: self-stake + delegations.
    pub fn effective_stake(
        &self,
        validator_id: &[u8; 32],
        self_stake: u64,
    ) -> u128 {
        match self.pools.get(validator_id) {
            Some(pool) => pool.effective_stake(self_stake),
            None => self_stake as u128,
        }
    }

    /// All active delegations for a validator.
    pub fn delegations_for_validator(
        &self,
        validator_id: &[u8; 32],
    ) -> Vec<&Delegation> {
        self.delegations
            .values()
            .filter(|d| d.validator_id == *validator_id && d.is_active())
            .collect()
    }

    // ─── State Transitions ──────────────────────────────────

    /// Create a new delegation.
    pub fn delegate(
        &mut self,
        id: DelegationId,
        delegator_address: [u8; 32],
        validator_id: [u8; 32],
        amount: u64,
        current_epoch: u64,
    ) -> Result<(), DelegationError> {
        if amount < self.min_delegation {
            return Err(DelegationError::BelowMinimum {
                amount,
                minimum: self.min_delegation,
            });
        }

        if self.delegations.contains_key(&id) {
            return Err(DelegationError::AlreadyExists);
        }

        let pool = self
            .pools
            .entry(validator_id)
            .or_insert_with(|| ValidatorPool::new(validator_id, 0));

        if pool.delegation_count >= self.max_delegations_per_validator {
            return Err(DelegationError::ValidatorPoolFull);
        }

        self.delegations.insert(
            id,
            Delegation {
                id,
                delegator_address,
                validator_id,
                amount,
                start_epoch: current_epoch,
                unbonding: None,
                pending_rewards: 0,
                last_reward_epoch: current_epoch,
            },
        );

        pool.total_delegated += amount;
        pool.delegation_count += 1;

        Ok(())
    }

    /// Initiate undelegation (enter unbonding queue).
    pub fn undelegate(
        &mut self,
        delegation_id: &DelegationId,
        current_epoch: u64,
    ) -> Result<(), DelegationError> {
        let d = self
            .delegations
            .get_mut(delegation_id)
            .ok_or(DelegationError::NotFound)?;

        if d.unbonding.is_some() {
            return Err(DelegationError::AlreadyUnbonding);
        }

        let amount = d.amount;
        d.unbonding = Some(UnbondingEntry {
            amount,
            complete_epoch: current_epoch + self.unbonding_epochs,
        });

        // Move from active to unbonding in pool
        if let Some(pool) = self.pools.get_mut(&d.validator_id) {
            pool.total_delegated = pool.total_delegated.saturating_sub(amount);
            pool.total_unbonding += amount;
        }

        Ok(())
    }

    /// Withdraw after unbonding period. Returns the withdrawn amount.
    pub fn withdraw(
        &mut self,
        delegation_id: &DelegationId,
        current_epoch: u64,
    ) -> Result<u64, DelegationError> {
        let d = self
            .delegations
            .get(delegation_id)
            .ok_or(DelegationError::NotFound)?;

        if !d.can_withdraw(current_epoch) {
            return Err(DelegationError::UnbondingNotComplete);
        }

        let amount = d.amount;
        let validator_id = d.validator_id;

        // Remove delegation
        self.delegations.remove(delegation_id);

        // Update pool
        if let Some(pool) = self.pools.get_mut(&validator_id) {
            pool.total_unbonding = pool.total_unbonding.saturating_sub(amount);
            pool.delegation_count = pool.delegation_count.saturating_sub(1);
        }

        Ok(amount)
    }

    // ─── Reward Distribution ────────────────────────────────

    /// Distribute epoch rewards to all delegators of a validator.
    ///
    /// `total_validator_reward` = the validator's total reward for this epoch.
    /// Commission is deducted, remainder split proportionally by delegation amount.
    ///
    /// Returns: (validator_commission, total_distributed_to_delegators)
    pub fn distribute_rewards(
        &mut self,
        validator_id: &[u8; 32],
        total_validator_reward: u64,
        commission_bps: u32,
        current_epoch: u64,
    ) -> (u64, u64) {
        // Commission
        let commission = (total_validator_reward as u128 * commission_bps as u128 / 10_000) as u64;
        let delegator_pool = total_validator_reward.saturating_sub(commission);

        if delegator_pool == 0 {
            return (commission, 0);
        }

        // Get total active delegation for this validator
        let total_delegated = self.total_delegated_to(validator_id);
        if total_delegated == 0 {
            return (total_validator_reward, 0); // All to validator if no delegators
        }

        let mut distributed: u64 = 0;

        // Distribute proportionally
        let delegation_ids: Vec<DelegationId> = self
            .delegations
            .values()
            .filter(|d| d.validator_id == *validator_id && d.is_active())
            .map(|d| d.id)
            .collect();

        for did in delegation_ids {
            if let Some(d) = self.delegations.get_mut(&did) {
                let share =
                    (delegator_pool as u128 * d.amount as u128 / total_delegated as u128) as u64;
                d.pending_rewards += share;
                d.last_reward_epoch = current_epoch;
                distributed += share;
            }
        }

        (commission, distributed)
    }

    /// Claim pending rewards for a delegation. Returns rewards claimed.
    pub fn claim_rewards(
        &mut self,
        delegation_id: &DelegationId,
    ) -> Result<u64, DelegationError> {
        let d = self
            .delegations
            .get_mut(delegation_id)
            .ok_or(DelegationError::NotFound)?;

        let rewards = d.pending_rewards;
        d.pending_rewards = 0;
        Ok(rewards)
    }

    // ─── Slashing Propagation ───────────────────────────────

    /// Propagate a validator slash to all its delegators.
    ///
    /// Each delegator loses `slash_bps` of their delegation.
    /// Returns total slashed from delegators.
    pub fn propagate_slash(
        &mut self,
        validator_id: &[u8; 32],
        slash_bps: u64,
    ) -> u64 {
        let mut total_slashed: u64 = 0;

        let delegation_ids: Vec<DelegationId> = self
            .delegations
            .values()
            .filter(|d| d.validator_id == *validator_id && d.is_active())
            .map(|d| d.id)
            .collect();

        for did in delegation_ids {
            if let Some(d) = self.delegations.get_mut(&did) {
                let slash_amount = d.amount * slash_bps / 10_000;
                d.amount = d.amount.saturating_sub(slash_amount);
                total_slashed += slash_amount;
            }
        }

        // Update pool total
        if let Some(pool) = self.pools.get_mut(validator_id) {
            pool.total_delegated = pool.total_delegated.saturating_sub(total_slashed);
        }

        total_slashed
    }

    // ─── Pool Management ────────────────────────────────────

    /// Initialize or update a validator's commission rate.
    pub fn set_commission(
        &mut self,
        validator_id: [u8; 32],
        commission_bps: u32,
        max_commission_bps: u32,
    ) -> Result<(), DelegationError> {
        if commission_bps > max_commission_bps {
            return Err(DelegationError::CommissionTooHigh {
                requested: commission_bps,
                maximum: max_commission_bps,
            });
        }
        let pool = self
            .pools
            .entry(validator_id)
            .or_insert_with(|| ValidatorPool::new(validator_id, commission_bps));
        pool.commission_bps = commission_bps;
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
//  Errors
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum DelegationError {
    #[error("delegation amount {amount} below minimum {minimum}")]
    BelowMinimum { amount: u64, minimum: u64 },
    #[error("delegation already exists")]
    AlreadyExists,
    #[error("delegation not found")]
    NotFound,
    #[error("already unbonding")]
    AlreadyUnbonding,
    #[error("unbonding period not complete")]
    UnbondingNotComplete,
    #[error("validator pool full")]
    ValidatorPoolFull,
    #[error("commission {requested} > max {maximum}")]
    CommissionTooHigh { requested: u32, maximum: u32 },
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_id(n: u8) -> DelegationId {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    fn make_vid(n: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    #[test]
    fn test_delegate_and_withdraw() {
        let mut reg = DelegationRegistry::testnet();
        let did = make_id(1);
        let vid = make_vid(1);

        reg.delegate(did, [0xAA; 32], vid, 5_000_000, 0).unwrap();
        assert_eq!(reg.total_delegated_to(&vid), 5_000_000);
        assert!(reg.get(&did).unwrap().is_active());

        // Undelegate
        reg.undelegate(&did, 10).unwrap();
        assert_eq!(reg.total_delegated_to(&vid), 0);
        assert!(!reg.get(&did).unwrap().is_active());

        // Too early to withdraw
        assert!(reg.withdraw(&did, 50).is_err());

        // After unbonding
        let amount = reg.withdraw(&did, 110).unwrap();
        assert_eq!(amount, 5_000_000);
        assert!(reg.get(&did).is_none());
    }

    #[test]
    fn test_below_minimum() {
        let mut reg = DelegationRegistry::testnet();
        assert!(reg.delegate(make_id(1), [0; 32], make_vid(1), 100, 0).is_err());
    }

    #[test]
    fn test_reward_distribution() {
        let mut reg = DelegationRegistry::testnet();
        let vid = make_vid(1);
        reg.set_commission(vid, 1000, 5000).unwrap(); // 10% commission

        // Two delegators: 3M and 7M
        reg.delegate(make_id(1), [0xAA; 32], vid, 3_000_000, 0).unwrap();
        reg.delegate(make_id(2), [0xBB; 32], vid, 7_000_000, 0).unwrap();

        // Distribute 100_000 reward
        let (commission, distributed) = reg.distribute_rewards(&vid, 100_000, 1000, 10);
        assert_eq!(commission, 10_000); // 10%
        assert_eq!(distributed, 90_000); // 90% to delegators

        // Check proportional split
        let d1 = reg.get(&make_id(1)).unwrap();
        let d2 = reg.get(&make_id(2)).unwrap();
        assert_eq!(d1.pending_rewards, 27_000); // 30% of 90_000
        assert_eq!(d2.pending_rewards, 63_000); // 70% of 90_000
    }

    #[test]
    fn test_claim_rewards() {
        let mut reg = DelegationRegistry::testnet();
        let vid = make_vid(1);
        reg.delegate(make_id(1), [0; 32], vid, 5_000_000, 0).unwrap();
        reg.distribute_rewards(&vid, 100_000, 0, 10); // 0% commission

        let rewards = reg.claim_rewards(&make_id(1)).unwrap();
        assert_eq!(rewards, 100_000);

        // Second claim = 0
        let rewards2 = reg.claim_rewards(&make_id(1)).unwrap();
        assert_eq!(rewards2, 0);
    }

    #[test]
    fn test_slash_propagation() {
        let mut reg = DelegationRegistry::testnet();
        let vid = make_vid(1);
        reg.delegate(make_id(1), [0; 32], vid, 10_000_000, 0).unwrap();
        reg.delegate(make_id(2), [1; 32], vid, 5_000_000, 0).unwrap();

        // 20% slash (2000 BPS)
        let total_slashed = reg.propagate_slash(&vid, 2000);
        assert_eq!(total_slashed, 3_000_000); // 20% of 15M

        let d1 = reg.get(&make_id(1)).unwrap();
        let d2 = reg.get(&make_id(2)).unwrap();
        assert_eq!(d1.amount, 8_000_000); // 10M - 2M
        assert_eq!(d2.amount, 4_000_000); // 5M - 1M
    }

    #[test]
    fn test_effective_stake() {
        let mut reg = DelegationRegistry::testnet();
        let vid = make_vid(1);
        reg.delegate(make_id(1), [0; 32], vid, 5_000_000, 0).unwrap();

        let eff = reg.effective_stake(&vid, 10_000_000);
        assert_eq!(eff, 15_000_000); // self 10M + delegated 5M
    }

    #[test]
    fn test_double_undelegate_fails() {
        let mut reg = DelegationRegistry::testnet();
        let vid = make_vid(1);
        reg.delegate(make_id(1), [0; 32], vid, 5_000_000, 0).unwrap();
        reg.undelegate(&make_id(1), 10).unwrap();
        assert!(reg.undelegate(&make_id(1), 20).is_err());
    }
}
