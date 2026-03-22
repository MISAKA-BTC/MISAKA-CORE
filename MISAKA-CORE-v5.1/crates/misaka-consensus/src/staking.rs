//! Validator Lock / Admission System — 10M MISAKA Required.
//!
//! # Design Philosophy
//!
//! 「金をロックしたやつだけが参加できる」＋「ちゃんと働いたやつだけが稼げる」
//!
//! - Sybil 耐性: 10M MISAKA ロックでコスト大
//! - sqrt(stake) で分割優位を減殺
//! - score + uptime フィルタで怠惰な validator を排除
//!
//! # State Machine
//!
//! ```text
//! UNLOCKED ──register()──► LOCKED ──activate()──► ACTIVE
//!                                                   │
//!                             ┌────── slash() ──────┤
//!                             ▼                     │
//!                          ACTIVE                exit()
//!                       (stake reduced)             │
//!                             │                     │
//!                             ▼ if stake < 10M      ▼
//!                          auto-eject ──────────► EXITING
//!                                                   │
//!                               unbonding period    │
//!                                                   ▼
//!                         unlock() ─────────────► UNLOCKED
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
//  Configuration
// ═══════════════════════════════════════════════════════════════

/// Staking configuration — consensus-critical parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingConfig {
    /// Minimum stake to become a validator (base units).
    /// 10,000,000 MISAKA = 10_000_000_000_000 base units (6 decimals).
    pub min_validator_stake: u64,
    /// Unbonding period in epochs (blocks).
    pub unbonding_epochs: u64,
    /// Maximum active validators.
    pub max_active_validators: usize,
    /// Minimum uptime (BPS) to remain eligible. 9000 = 90%.
    pub min_uptime_bps: u64,
    /// Minimum workload score to remain eligible.
    pub min_score: u64,
    /// Slash: minor (BPS). 100 = 1%.
    pub slash_minor_bps: u64,
    /// Slash: medium (BPS). 500 = 5%.
    pub slash_medium_bps: u64,
    /// Slash: severe (BPS). 2000 = 20%.
    pub slash_severe_bps: u64,
    /// Reporter reward (BPS of slashed amount). 1000 = 10%.
    pub slash_reporter_reward_bps: u64,
    /// Cooldown between slash events for same validator (epochs).
    pub slash_cooldown_epochs: u64,
    /// Maximum commission rate (BPS). 5000 = 50%.
    pub max_commission_bps: u32,
}

impl Default for StakingConfig {
    fn default() -> Self {
        Self {
            min_validator_stake: 10_000_000_000_000, // 10M MISAKA
            unbonding_epochs: 10_080,
            max_active_validators: 150,
            min_uptime_bps: 9000,
            min_score: 100_000,
            slash_minor_bps: 100,
            slash_medium_bps: 500,
            slash_severe_bps: 2000,
            slash_reporter_reward_bps: 1000,
            slash_cooldown_epochs: 1000,
            max_commission_bps: 5000,
        }
    }
}

impl StakingConfig {
    pub fn testnet() -> Self {
        Self {
            min_validator_stake: 10_000_000,
            unbonding_epochs: 100,
            max_active_validators: 50,
            min_uptime_bps: 5000,
            min_score: 10_000,
            ..Self::default()
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Validator State Machine
// ═══════════════════════════════════════════════════════════════

/// Validator lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorState {
    /// No stake locked.
    Unlocked,
    /// Stake locked, candidate — not yet producing blocks.
    Locked,
    /// Active in validator set.
    Active,
    /// Exit initiated, stake still locked (subject to slashing).
    Exiting { exit_epoch: u64 },
}

impl ValidatorState {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Unlocked => "UNLOCKED",
            Self::Locked => "LOCKED",
            Self::Active => "ACTIVE",
            Self::Exiting { .. } => "EXITING",
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Validator Account
// ═══════════════════════════════════════════════════════════════

/// Full validator account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorAccount {
    pub validator_id: [u8; 20],
    pub pubkey: Vec<u8>,
    pub stake_amount: u64,
    pub state: ValidatorState,
    pub registered_epoch: u64,
    pub activation_epoch: Option<u64>,
    pub exit_epoch: Option<u64>,
    pub unlock_epoch: Option<u64>,
    pub commission_bps: u32,
    pub reward_address: [u8; 20],
    pub cumulative_slashed: u64,
    pub last_slash_epoch: Option<u64>,
    /// Uptime (BPS, 0-10000). Updated by consensus.
    pub uptime_bps: u64,
    /// Workload score. Updated by reward_epoch.
    pub score: u64,
    pub stake_tx_hash: [u8; 32],
    pub stake_output_index: u32,
}

impl ValidatorAccount {
    /// Whether eligible for the active set.
    pub fn is_eligible(&self, config: &StakingConfig) -> bool {
        self.state == ValidatorState::Active
            && self.stake_amount >= config.min_validator_stake
            && self.uptime_bps >= config.min_uptime_bps
            && self.score >= config.min_score
    }

    /// reward_weight = sqrt(stake) × score. 0 if ineligible.
    pub fn reward_weight(&self, config: &StakingConfig) -> u128 {
        if self.stake_amount < config.min_validator_stake
            || self.state != ValidatorState::Active
        {
            return 0;
        }
        let sqrt_stake = misaka_tokenomics::isqrt_u128(self.stake_amount as u128);
        sqrt_stake * self.score as u128
    }

    pub fn can_unlock(&self, current_epoch: u64, config: &StakingConfig) -> bool {
        match self.state {
            ValidatorState::Exiting { exit_epoch } => {
                current_epoch >= exit_epoch + config.unbonding_epochs
            }
            _ => false,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Staking Registry
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingRegistry {
    validators: HashMap<[u8; 20], ValidatorAccount>,
    total_locked: u64,
    config: StakingConfig,
}

impl StakingRegistry {
    pub fn new(config: StakingConfig) -> Self {
        Self { validators: HashMap::new(), total_locked: 0, config }
    }

    pub fn config(&self) -> &StakingConfig { &self.config }
    pub fn get(&self, id: &[u8; 20]) -> Option<&ValidatorAccount> { self.validators.get(id) }
    pub fn all_validators(&self) -> impl Iterator<Item = &ValidatorAccount> { self.validators.values() }
    pub fn total_locked_stake(&self) -> u64 { self.total_locked }

    pub fn active_count(&self) -> usize {
        self.validators.values().filter(|v| v.state == ValidatorState::Active).count()
    }

    pub fn eligible_count(&self) -> usize {
        self.validators.values().filter(|v| v.is_eligible(&self.config)).count()
    }

    /// Top N eligible validators by reward_weight.
    pub fn compute_active_set(&self) -> Vec<&ValidatorAccount> {
        let mut eligible: Vec<&ValidatorAccount> = self.validators.values()
            .filter(|v| v.is_eligible(&self.config))
            .collect();
        eligible.sort_by(|a, b| b.reward_weight(&self.config).cmp(&a.reward_weight(&self.config)));
        eligible.truncate(self.config.max_active_validators);
        eligible
    }

    pub fn total_reward_weight(&self) -> u128 {
        self.compute_active_set().iter().map(|v| v.reward_weight(&self.config)).sum()
    }

    // ─── State Transitions ──────────────────────────────────

    /// UNLOCKED → LOCKED
    pub fn register(
        &mut self,
        validator_id: [u8; 20],
        pubkey: Vec<u8>,
        stake_amount: u64,
        commission_bps: u32,
        reward_address: [u8; 20],
        current_epoch: u64,
        stake_tx_hash: [u8; 32],
        stake_output_index: u32,
    ) -> Result<(), StakingError> {
        if stake_amount < self.config.min_validator_stake {
            return Err(StakingError::BelowMinStake {
                deposited: stake_amount, minimum: self.config.min_validator_stake,
            });
        }
        if commission_bps > self.config.max_commission_bps {
            return Err(StakingError::CommissionTooHigh {
                requested: commission_bps, maximum: self.config.max_commission_bps,
            });
        }
        if let Some(existing) = self.validators.get(&validator_id) {
            if existing.state != ValidatorState::Unlocked {
                return Err(StakingError::AlreadyRegistered);
            }
        }

        self.validators.insert(validator_id, ValidatorAccount {
            validator_id, pubkey, stake_amount,
            state: ValidatorState::Locked,
            registered_epoch: current_epoch,
            activation_epoch: None, exit_epoch: None, unlock_epoch: None,
            commission_bps, reward_address,
            cumulative_slashed: 0, last_slash_epoch: None,
            uptime_bps: 10_000, score: 0,
            stake_tx_hash, stake_output_index,
        });
        self.recompute_total();
        Ok(())
    }

    /// LOCKED → ACTIVE
    pub fn activate(&mut self, validator_id: &[u8; 20], current_epoch: u64) -> Result<(), StakingError> {
        // Check capacity before mutable borrow (SEC-AUDIT-V5: borrow checker fix)
        let at_capacity = self.active_count() >= self.config.max_active_validators;
        let a = self.validators.get_mut(validator_id).ok_or(StakingError::ValidatorNotFound)?;
        if a.state != ValidatorState::Locked {
            return Err(StakingError::InvalidTransition { from: a.state.label().into(), to: "ACTIVE".into() });
        }
        if a.stake_amount < self.config.min_validator_stake {
            return Err(StakingError::BelowMinStake { deposited: a.stake_amount, minimum: self.config.min_validator_stake });
        }
        if at_capacity {
            return Err(StakingError::ValidatorSetFull);
        }
        a.state = ValidatorState::Active;
        a.activation_epoch = Some(current_epoch);
        Ok(())
    }

    /// ACTIVE → EXITING
    pub fn exit(&mut self, validator_id: &[u8; 20], current_epoch: u64) -> Result<(), StakingError> {
        let a = self.validators.get_mut(validator_id).ok_or(StakingError::ValidatorNotFound)?;
        if a.state != ValidatorState::Active {
            return Err(StakingError::InvalidTransition { from: a.state.label().into(), to: "EXITING".into() });
        }
        a.state = ValidatorState::Exiting { exit_epoch: current_epoch };
        a.exit_epoch = Some(current_epoch);
        a.unlock_epoch = Some(current_epoch + self.config.unbonding_epochs);
        Ok(())
    }

    /// EXITING → UNLOCKED (after unbonding). Returns unlocked amount.
    pub fn unlock(&mut self, validator_id: &[u8; 20], current_epoch: u64) -> Result<u64, StakingError> {
        let a = self.validators.get_mut(validator_id).ok_or(StakingError::ValidatorNotFound)?;
        if !a.can_unlock(current_epoch, &self.config) {
            return Err(StakingError::UnbondingNotComplete);
        }
        let amount = a.stake_amount;
        a.stake_amount = 0;
        a.state = ValidatorState::Unlocked;
        a.activation_epoch = None;
        a.exit_epoch = None;
        a.unlock_epoch = None;
        self.recompute_total();
        Ok(amount)
    }

    // ─── Slashing ───────────────────────────────────────────

    /// Slash. Auto-ejects if stake < min. Returns (slashed, reporter_reward).
    pub fn slash(
        &mut self,
        validator_id: &[u8; 20],
        severity: SlashSeverity,
        current_epoch: u64,
    ) -> Result<(u64, u64), StakingError> {
        let a = self.validators.get_mut(validator_id).ok_or(StakingError::ValidatorNotFound)?;
        match a.state {
            ValidatorState::Active | ValidatorState::Exiting { .. } => {}
            _ => return Err(StakingError::InvalidTransition { from: a.state.label().into(), to: "Slashed".into() }),
        }
        if let Some(last) = a.last_slash_epoch {
            if current_epoch < last + self.config.slash_cooldown_epochs {
                return Err(StakingError::SlashCooldown { next_allowed: last + self.config.slash_cooldown_epochs });
            }
        }
        let slash_bps = severity.penalty_bps(&self.config);
        let slash_amount = a.stake_amount * slash_bps / 10_000;
        let reporter_reward = slash_amount * self.config.slash_reporter_reward_bps / 10_000;
        a.stake_amount = a.stake_amount.saturating_sub(slash_amount);
        a.cumulative_slashed += slash_amount;
        a.last_slash_epoch = Some(current_epoch);

        // Auto-eject if below minimum
        if a.stake_amount < self.config.min_validator_stake && a.state == ValidatorState::Active {
            a.state = ValidatorState::Exiting { exit_epoch: current_epoch };
            a.exit_epoch = Some(current_epoch);
            a.unlock_epoch = Some(current_epoch + self.config.unbonding_epochs);
        }
        self.recompute_total();
        Ok((slash_amount, reporter_reward))
    }

    // ─── Score / Uptime ─────────────────────────────────────

    pub fn update_score(&mut self, validator_id: &[u8; 20], new_score: u64) {
        if let Some(a) = self.validators.get_mut(validator_id) { a.score = new_score; }
    }

    pub fn update_uptime(&mut self, validator_id: &[u8; 20], uptime_bps: u64) {
        if let Some(a) = self.validators.get_mut(validator_id) { a.uptime_bps = uptime_bps.min(10_000); }
    }

    fn recompute_total(&mut self) {
        self.total_locked = self.validators.values()
            .filter(|v| !matches!(v.state, ValidatorState::Unlocked))
            .map(|v| v.stake_amount)
            .sum();
    }
}

// ═══════════════════════════════════════════════════════════════
//  Slash Types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SlashSeverity {
    Minor,   // 1%
    Medium,  // 5%
    Severe,  // 20%
    Custom(u64),
}

impl SlashSeverity {
    pub fn penalty_bps(&self, config: &StakingConfig) -> u64 {
        match self {
            Self::Minor => config.slash_minor_bps,
            Self::Medium => config.slash_medium_bps,
            Self::Severe => config.slash_severe_bps,
            Self::Custom(bps) => *bps,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashEvidence {
    DoubleSign {
        validator_id: [u8; 20],
        message_a: Vec<u8>, signature_a: Vec<u8>,
        message_b: Vec<u8>, signature_b: Vec<u8>,
    },
    InvalidBlock {
        validator_id: [u8; 20],
        block_hash: [u8; 32],
        reason: String,
    },
    LongOffline {
        validator_id: [u8; 20],
        missed_from_epoch: u64,
        missed_to_epoch: u64,
    },
    ProtocolViolation {
        validator_id: [u8; 20],
        description: String,
    },
}

impl SlashEvidence {
    pub fn validator_id(&self) -> &[u8; 20] {
        match self {
            Self::DoubleSign { validator_id, .. } => validator_id,
            Self::InvalidBlock { validator_id, .. } => validator_id,
            Self::LongOffline { validator_id, .. } => validator_id,
            Self::ProtocolViolation { validator_id, .. } => validator_id,
        }
    }

    pub fn severity(&self) -> SlashSeverity {
        match self {
            Self::DoubleSign { .. } => SlashSeverity::Severe,
            Self::InvalidBlock { .. } => SlashSeverity::Medium,
            Self::LongOffline { .. } => SlashSeverity::Minor,
            Self::ProtocolViolation { .. } => SlashSeverity::Medium,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Errors
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum StakingError {
    #[error("stake {deposited} below minimum {minimum}")]
    BelowMinStake { deposited: u64, minimum: u64 },
    #[error("validator set full")]
    ValidatorSetFull,
    #[error("validator not found")]
    ValidatorNotFound,
    #[error("validator already registered")]
    AlreadyRegistered,
    #[error("invalid transition: {from} → {to}")]
    InvalidTransition { from: String, to: String },
    #[error("unbonding period not complete")]
    UnbondingNotComplete,
    #[error("commission {requested} > max {maximum}")]
    CommissionTooHigh { requested: u32, maximum: u32 },
    #[error("slash cooldown: next at epoch {next_allowed}")]
    SlashCooldown { next_allowed: u64 },
    #[error("overflow")]
    Overflow,
    #[error("invalid evidence: {0}")]
    InvalidEvidence(String),
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> StakingConfig {
        StakingConfig {
            min_validator_stake: 10_000_000,
            unbonding_epochs: 100,
            max_active_validators: 5,
            min_uptime_bps: 5000,
            min_score: 1000,
            slash_minor_bps: 100,
            slash_medium_bps: 500,
            slash_severe_bps: 2000,
            slash_reporter_reward_bps: 1000,
            slash_cooldown_epochs: 10,
            max_commission_bps: 5000,
        }
    }

    fn make_id(n: u8) -> [u8; 20] { let mut id = [0u8; 20]; id[0] = n; id }

    fn register_and_activate(reg: &mut StakingRegistry, id: [u8; 20], stake: u64, epoch: u64) {
        reg.register(id, vec![1; 1952], stake, 500, id, epoch, [id[0]; 32], 0).unwrap();
        reg.update_score(&id, 5000);
        reg.activate(&id, epoch + 1).unwrap();
    }

    #[test]
    fn test_full_lifecycle() {
        let mut reg = StakingRegistry::new(test_config());
        let id = make_id(1);

        // UNLOCKED → LOCKED
        reg.register(id, vec![1; 1952], 10_000_000, 500, id, 0, [1; 32], 0).unwrap();
        assert_eq!(reg.get(&id).unwrap().state, ValidatorState::Locked);

        // LOCKED → ACTIVE
        reg.update_score(&id, 5000);
        reg.activate(&id, 1).unwrap();
        assert_eq!(reg.get(&id).unwrap().state, ValidatorState::Active);

        // ACTIVE → EXITING
        reg.exit(&id, 100).unwrap();
        assert!(matches!(reg.get(&id).unwrap().state, ValidatorState::Exiting { .. }));

        // Cannot unlock before unbonding
        assert!(reg.unlock(&id, 150).is_err());

        // EXITING → UNLOCKED
        let amount = reg.unlock(&id, 200).unwrap();
        assert_eq!(amount, 10_000_000);
        assert_eq!(reg.get(&id).unwrap().state, ValidatorState::Unlocked);
    }

    #[test]
    fn test_below_min_stake() {
        let mut reg = StakingRegistry::new(test_config());
        assert!(reg.register(make_id(1), vec![], 9_999_999, 500, make_id(1), 0, [1; 32], 0).is_err());
    }

    #[test]
    fn test_exit_from_locked_fails() {
        let mut reg = StakingRegistry::new(test_config());
        let id = make_id(1);
        reg.register(id, vec![], 10_000_000, 500, id, 0, [1; 32], 0).unwrap();
        assert!(reg.exit(&id, 10).is_err());
    }

    #[test]
    fn test_slash_auto_eject() {
        let mut reg = StakingRegistry::new(test_config());
        let id = make_id(1);
        register_and_activate(&mut reg, id, 10_000_000, 0);

        // 20% slash → 8M < 10M → auto-eject
        reg.slash(&id, SlashSeverity::Severe, 50).unwrap();
        assert!(matches!(reg.get(&id).unwrap().state, ValidatorState::Exiting { .. }));
        assert_eq!(reg.get(&id).unwrap().stake_amount, 8_000_000);
    }

    #[test]
    fn test_slash_cooldown() {
        let mut reg = StakingRegistry::new(test_config());
        let id = make_id(1);
        register_and_activate(&mut reg, id, 20_000_000, 0);
        reg.slash(&id, SlashSeverity::Minor, 50).unwrap();
        assert!(reg.slash(&id, SlashSeverity::Minor, 55).is_err());
        reg.slash(&id, SlashSeverity::Minor, 61).unwrap();
    }

    #[test]
    fn test_active_set_filters() {
        let mut reg = StakingRegistry::new(test_config());
        register_and_activate(&mut reg, make_id(1), 10_000_000, 0);
        register_and_activate(&mut reg, make_id(2), 10_000_000, 0);

        // Low score → not eligible
        reg.update_score(&make_id(2), 500);
        assert_eq!(reg.compute_active_set().len(), 1);

        // Restore score, low uptime → not eligible
        reg.update_score(&make_id(2), 5000);
        reg.update_uptime(&make_id(2), 3000);
        assert_eq!(reg.compute_active_set().len(), 1);
    }

    #[test]
    fn test_active_set_max_size() {
        let mut reg = StakingRegistry::new(test_config()); // max=5
        for i in 0..8u8 {
            register_and_activate(&mut reg, make_id(i), 10_000_000 + i as u64 * 1000, 0);
        }
        assert_eq!(reg.compute_active_set().len(), 5);
        assert_eq!(reg.compute_active_set()[0].validator_id, make_id(7));
    }

    #[test]
    fn test_reward_weight_zero_below_min() {
        let config = test_config();
        let a = ValidatorAccount {
            validator_id: make_id(1), pubkey: vec![], stake_amount: 5_000_000,
            state: ValidatorState::Active, registered_epoch: 0,
            activation_epoch: Some(0), exit_epoch: None, unlock_epoch: None,
            commission_bps: 500, reward_address: make_id(1),
            cumulative_slashed: 0, last_slash_epoch: None,
            uptime_bps: 10_000, score: 10_000,
            stake_tx_hash: [0; 32], stake_output_index: 0,
        };
        assert_eq!(a.reward_weight(&config), 0);
    }

    #[test]
    fn test_reward_weight_sqrt_proportional() {
        let config = test_config();
        let make = |stake: u64, score: u64| ValidatorAccount {
            validator_id: make_id(1), pubkey: vec![], stake_amount: stake,
            state: ValidatorState::Active, registered_epoch: 0,
            activation_epoch: Some(0), exit_epoch: None, unlock_epoch: None,
            commission_bps: 500, reward_address: make_id(1),
            cumulative_slashed: 0, last_slash_epoch: None,
            uptime_bps: 10_000, score,
            stake_tx_hash: [0; 32], stake_output_index: 0,
        };
        let w1 = make(10_000_000, 1000).reward_weight(&config);
        let w2 = make(40_000_000, 1000).reward_weight(&config);
        // 4× stake → 2× sqrt → ~2× weight
        let ratio = w2 as f64 / w1 as f64;
        assert!((ratio - 2.0).abs() < 0.1);
    }

    #[test]
    fn test_commission_too_high() {
        let mut reg = StakingRegistry::new(test_config());
        assert!(reg.register(make_id(1), vec![], 10_000_000, 9000, make_id(1), 0, [1; 32], 0).is_err());
    }

    #[test]
    fn test_reregister_after_unlock() {
        let mut reg = StakingRegistry::new(test_config());
        let id = make_id(1);
        register_and_activate(&mut reg, id, 10_000_000, 0);
        reg.exit(&id, 50).unwrap();
        reg.unlock(&id, 200).unwrap();
        reg.register(id, vec![1; 1952], 10_000_000, 500, id, 300, [2; 32], 0).unwrap();
        assert_eq!(reg.get(&id).unwrap().state, ValidatorState::Locked);
    }
}
