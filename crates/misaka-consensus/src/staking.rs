//! Validator Lock / Admission System — Mainnet 10M / Testnet 1M MISAKA Required.
//!
//! # Design Philosophy
//!
//! 「金をロックしたやつだけが参加できる」＋「ちゃんと働いたやつだけが稼げる」
//!
//! - Sybil 耐性: 10M MISAKA (mainnet) / 1M MISAKA (testnet) ロックでコスト大
//! - linear stake weighting (proportional to deposited amount)
//! - score + uptime フィルタで怠惰な validator を排除
//! - misakastake.com でのステーキング TX 検証が ACTIVE 遷移の必須条件
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

mod validator_map_serde {
    use super::ValidatorAccount;
    use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;

    pub fn serialize<S>(
        map: &HashMap<[u8; 32], ValidatorAccount>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let as_hex: HashMap<String, &ValidatorAccount> = map
            .iter()
            .map(|(validator_id, account)| (hex::encode(validator_id), account))
            .collect();
        as_hex.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<HashMap<[u8; 32], ValidatorAccount>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let as_hex = HashMap::<String, ValidatorAccount>::deserialize(deserializer)?;
        let mut validators = HashMap::with_capacity(as_hex.len());
        for (validator_id_hex, account) in as_hex {
            let bytes = hex::decode(&validator_id_hex)
                .map_err(|err| D::Error::custom(format!("invalid validator id hex: {err}")))?;
            if bytes.len() != 32 {
                return Err(D::Error::custom(format!(
                    "validator id must be 32 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut validator_id = [0u8; 32];
            validator_id.copy_from_slice(&bytes);
            validators.insert(validator_id, account);
        }
        Ok(validators)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Configuration
// ═══════════════════════════════════════════════════════════════

/// Staking configuration — consensus-critical parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingConfig {
    /// Minimum stake to become a validator (base units).
    /// MISAKA has 9 decimals: 1 MISAKA = 1_000_000_000 base units.
    /// Mainnet: 10,000,000 MISAKA = 10_000_000_000_000_000 base units.
    /// Testnet:  1,000,000 MISAKA =  1_000_000_000_000_000 base units.
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
            min_validator_stake: 10_000_000_000_000_000, // 10M MISAKA (9 decimals)
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
    /// Testnet config — lower thresholds for testing.
    /// Minimum stake: 1M MISAKA = 1_000_000 × 10^9 base units.
    pub fn testnet() -> Self {
        Self {
            min_validator_stake: 1_000_000_000_000_000, // 1M MISAKA (9 decimals)
            unbonding_epochs: 100,
            max_active_validators: 50,
            min_uptime_bps: 5000,
            min_score: 10_000,
            ..Self::default()
        }
    }

    /// Mainnet config — production thresholds.
    /// Minimum stake: 10M MISAKA = 10_000_000 × 10^9 base units.
    pub fn mainnet() -> Self {
        Self::default() // Default IS mainnet
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
    pub validator_id: [u8; 32],
    pub pubkey: Vec<u8>,
    pub stake_amount: u64,
    pub state: ValidatorState,
    pub registered_epoch: u64,
    pub activation_epoch: Option<u64>,
    pub exit_epoch: Option<u64>,
    pub unlock_epoch: Option<u64>,
    pub commission_bps: u32,
    pub reward_address: [u8; 32],
    pub cumulative_slashed: u64,
    pub last_slash_epoch: Option<u64>,
    /// Uptime (BPS, 0-10000). Updated by consensus.
    pub uptime_bps: u64,
    /// Workload score. Updated by reward_epoch.
    pub score: u64,
    pub stake_tx_hash: [u8; 32],
    pub stake_output_index: u32,

    /// SEC-STAKE: Whether this validator's stake has been verified on Solana
    /// via the misakastake.com staking program. REQUIRED for LOCKED → ACTIVE.
    /// Set to `true` only after the node confirms the staking TX on-chain.
    #[serde(default)]
    pub solana_stake_verified: bool,

    /// SEC-STAKE: Solana TX signature proving the staking deposit (base58).
    /// Stored for audit trail and re-verification.
    #[serde(default)]
    pub solana_stake_signature: Option<String>,

    /// Bridge: Separate Solana public key for bridge signing.
    /// This is NOT the SR consensus key — key separation is mandatory.
    /// Registered by the SR operator via register_bridge_key().
    #[serde(default)]
    pub bridge_solana_pubkey: Option<[u8; 32]>,
}

impl ValidatorAccount {
    /// Whether eligible for the active set.
    pub fn is_eligible(&self, config: &StakingConfig) -> bool {
        self.state == ValidatorState::Active
            && self.stake_amount >= config.min_validator_stake
            && self.uptime_bps >= config.min_uptime_bps
            && self.score >= config.min_score
    }

    /// reward_weight = stake × score (linear). 0 if ineligible.
    pub fn reward_weight(&self, config: &StakingConfig) -> u128 {
        if self.stake_amount < config.min_validator_stake || self.state != ValidatorState::Active {
            return 0;
        }
        self.stake_amount as u128 * self.score as u128
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
    #[serde(with = "validator_map_serde")]
    validators: HashMap<[u8; 32], ValidatorAccount>,
    total_locked: u64,
    config: StakingConfig,
    /// SEC-STAKE: Set of Solana TX signatures already used for validator registration.
    /// Prevents the same staking TX from being used to register multiple validators
    /// (i.e., 1 stake = 1 validator, not 1 stake = N validators).
    #[serde(default)]
    used_stake_signatures: std::collections::HashSet<String>,
}

impl StakingRegistry {
    pub fn new(config: StakingConfig) -> Self {
        Self {
            validators: HashMap::new(),
            total_locked: 0,
            config,
            used_stake_signatures: std::collections::HashSet::new(),
        }
    }

    pub fn config(&self) -> &StakingConfig {
        &self.config
    }
    pub fn get(&self, id: &[u8; 32]) -> Option<&ValidatorAccount> {
        self.validators.get(id)
    }
    pub fn all_validators(&self) -> impl Iterator<Item = &ValidatorAccount> {
        self.validators.values()
    }
    pub fn total_locked_stake(&self) -> u64 {
        self.total_locked
    }

    pub fn active_count(&self) -> usize {
        self.validators
            .values()
            .filter(|v| v.state == ValidatorState::Active)
            .count()
    }

    pub fn eligible_count(&self) -> usize {
        self.validators
            .values()
            .filter(|v| v.is_eligible(&self.config))
            .count()
    }

    /// Top N eligible validators by reward_weight.
    pub fn compute_active_set(&self) -> Vec<&ValidatorAccount> {
        let mut eligible: Vec<&ValidatorAccount> = self
            .validators
            .values()
            .filter(|v| v.is_eligible(&self.config))
            .collect();
        eligible.sort_by(|a, b| {
            b.reward_weight(&self.config)
                .cmp(&a.reward_weight(&self.config))
        });
        eligible.truncate(self.config.max_active_validators);
        eligible
    }

    // ─── Bridge Key Management ──────────────────────────────

    /// Register a separate Solana bridge public key for an SR.
    /// Key separation is mandatory: bridge_solana_pubkey != consensus pubkey.
    pub fn register_bridge_key(
        &mut self,
        validator_id: &[u8; 32],
        bridge_solana_pubkey: [u8; 32],
    ) -> Result<(), String> {
        let v = self.validators.get_mut(validator_id)
            .ok_or_else(|| "validator not found".to_string())?;

        if v.state != ValidatorState::Active {
            return Err("only active validators can register bridge keys".into());
        }

        // Key separation: bridge key must differ from consensus pubkey
        if bridge_solana_pubkey == v.validator_id {
            return Err("bridge key must be different from consensus key".into());
        }

        v.bridge_solana_pubkey = Some(bridge_solana_pubkey);
        Ok(())
    }

    /// Derive the bridge committee from the current active SR set.
    /// Returns (bridge_solana_pubkeys, count_with_bridge_key).
    /// Only SRs with registered bridge_solana_pubkey are included.
    pub fn derive_bridge_committee(&self) -> Vec<[u8; 32]> {
        self.compute_active_set()
            .iter()
            .filter_map(|v| v.bridge_solana_pubkey)
            .collect()
    }

    /// Check if enough active SRs have bridge keys for 15/21 threshold.
    pub fn bridge_committee_ready(&self) -> bool {
        self.derive_bridge_committee().len() >= 15
    }

    pub fn total_reward_weight(&self) -> u128 {
        self.compute_active_set()
            .iter()
            .map(|v| v.reward_weight(&self.config))
            .sum()
    }

    // ─── State Transitions ──────────────────────────────────

    /// UNLOCKED → LOCKED
    ///
    /// Registers a validator candidate with stake locked via misakastake.com.
    ///
    /// # SEC-STAKE: misakastake.com Verification Flow
    ///
    /// ```text
    /// 1. Validator stakes tokens at misakastake.com (Solana TX)
    /// 2. Validator calls /api/v1/validators/register with the Solana TX signature
    /// 3. Node verifies the TX on-chain (finalized, correct program, correct amount)
    /// 4. If verified: solana_stake_verified = true → can proceed to activate()
    /// 5. If not verified: solana_stake_verified = false → activate() will reject
    /// ```
    ///
    /// The `solana_stake_verified` flag is the ONLY gate between LOCKED and ACTIVE.
    /// Even if registration succeeds, the validator cannot produce blocks without
    /// on-chain verification of their stake deposit.
    pub fn register(
        &mut self,
        validator_id: [u8; 32],
        pubkey: Vec<u8>,
        stake_amount: u64,
        commission_bps: u32,
        reward_address: [u8; 32],
        current_epoch: u64,
        stake_tx_hash: [u8; 32],
        stake_output_index: u32,
        solana_stake_verified: bool,
        solana_stake_signature: Option<String>,
    ) -> Result<(), StakingError> {
        if stake_amount < self.config.min_validator_stake {
            return Err(StakingError::BelowMinStake {
                deposited: stake_amount,
                minimum: self.config.min_validator_stake,
            });
        }
        if commission_bps > self.config.max_commission_bps {
            return Err(StakingError::CommissionTooHigh {
                requested: commission_bps,
                maximum: self.config.max_commission_bps,
            });
        }
        if let Some(existing) = self.validators.get(&validator_id) {
            if existing.state != ValidatorState::Unlocked {
                return Err(StakingError::AlreadyRegistered);
            }
        }

        // SEC-STAKE: Prevent the same Solana TX signature from being used
        // to register multiple validators. 1 stake deposit = 1 validator only.
        if let Some(ref sig) = solana_stake_signature {
            if self.used_stake_signatures.contains(sig) {
                return Err(StakingError::StakeSignatureAlreadyUsed {
                    signature: sig.clone(),
                });
            }
        }

        // Record the signature BEFORE inserting (atomic with the check above)
        if let Some(ref sig) = solana_stake_signature {
            self.used_stake_signatures.insert(sig.clone());
        }

        self.validators.insert(
            validator_id,
            ValidatorAccount {
                validator_id,
                pubkey,
                stake_amount,
                state: ValidatorState::Locked,
                registered_epoch: current_epoch,
                activation_epoch: None,
                exit_epoch: None,
                unlock_epoch: None,
                commission_bps,
                reward_address,
                cumulative_slashed: 0,
                last_slash_epoch: None,
                uptime_bps: 10_000,
                score: 0,
                stake_tx_hash,
                stake_output_index,
                solana_stake_verified,
                solana_stake_signature,
                bridge_solana_pubkey: None,
            },
        );
        self.recompute_total();
        Ok(())
    }

    /// Mark a validator's Solana stake as verified after on-chain confirmation.
    ///
    /// Called by the node after verifying the staking TX via Solana RPC.
    /// This is the prerequisite for `activate()`.
    pub fn mark_stake_verified(
        &mut self,
        validator_id: &[u8; 32],
        signature: String,
    ) -> Result<(), StakingError> {
        // SEC-STAKE: Check signature not already used by another validator
        if self.used_stake_signatures.contains(&signature) {
            // Allow if the same validator is re-verifying with the same sig
            let account = self
                .validators
                .get(validator_id)
                .ok_or(StakingError::ValidatorNotFound)?;
            if account.solana_stake_signature.as_deref() != Some(&signature) {
                return Err(StakingError::StakeSignatureAlreadyUsed { signature });
            }
        }

        let account = self
            .validators
            .get_mut(validator_id)
            .ok_or(StakingError::ValidatorNotFound)?;
        account.solana_stake_verified = true;
        account.solana_stake_signature = Some(signature.clone());
        self.used_stake_signatures.insert(signature);
        Ok(())
    }

    /// LOCKED → ACTIVE
    pub fn activate(
        &mut self,
        validator_id: &[u8; 32],
        current_epoch: u64,
    ) -> Result<(), StakingError> {
        let active_count = self.active_count();
        let a = self
            .validators
            .get_mut(validator_id)
            .ok_or(StakingError::ValidatorNotFound)?;
        if a.state != ValidatorState::Locked {
            return Err(StakingError::InvalidTransition {
                from: a.state.label().into(),
                to: "ACTIVE".into(),
            });
        }
        if a.stake_amount < self.config.min_validator_stake {
            return Err(StakingError::BelowMinStake {
                deposited: a.stake_amount,
                minimum: self.config.min_validator_stake,
            });
        }
        if active_count >= self.config.max_active_validators {
            return Err(StakingError::ValidatorSetFull);
        }

        // SEC-STAKE: Require on-chain staking verification from misakastake.com.
        // Without this, a validator can register with a fake stake_amount and
        // join the active set without actually locking any tokens on Solana.
        if !a.solana_stake_verified {
            return Err(StakingError::StakeNotVerified);
        }

        a.state = ValidatorState::Active;
        a.activation_epoch = Some(current_epoch);
        Ok(())
    }

    /// ACTIVE → EXITING
    pub fn exit(
        &mut self,
        validator_id: &[u8; 32],
        current_epoch: u64,
    ) -> Result<(), StakingError> {
        let a = self
            .validators
            .get_mut(validator_id)
            .ok_or(StakingError::ValidatorNotFound)?;
        if a.state != ValidatorState::Active {
            return Err(StakingError::InvalidTransition {
                from: a.state.label().into(),
                to: "EXITING".into(),
            });
        }
        a.state = ValidatorState::Exiting {
            exit_epoch: current_epoch,
        };
        a.exit_epoch = Some(current_epoch);
        a.unlock_epoch = Some(current_epoch + self.config.unbonding_epochs);
        Ok(())
    }

    /// EXITING → UNLOCKED (after unbonding). Returns unlocked amount.
    pub fn unlock(
        &mut self,
        validator_id: &[u8; 32],
        current_epoch: u64,
    ) -> Result<u64, StakingError> {
        let a = self
            .validators
            .get_mut(validator_id)
            .ok_or(StakingError::ValidatorNotFound)?;
        if !a.can_unlock(current_epoch, &self.config) {
            return Err(StakingError::UnbondingNotComplete);
        }
        let amount = a.stake_amount;
        a.stake_amount = 0;
        a.state = ValidatorState::Unlocked;
        a.activation_epoch = None;
        a.exit_epoch = None;
        a.unlock_epoch = None;

        // SEC-STAKE: Release the Solana TX signature so it can be reused
        // if the validator re-stakes at misakastake.com. Also clear the
        // verification flag — they must re-verify on re-registration.
        if let Some(ref sig) = a.solana_stake_signature {
            self.used_stake_signatures.remove(sig);
        }
        a.solana_stake_verified = false;
        a.solana_stake_signature = None;

        self.recompute_total();
        Ok(amount)
    }

    // ─── Slashing ───────────────────────────────────────────

    /// Slash. Auto-ejects if stake < min. Returns (slashed, reporter_reward).
    pub fn slash(
        &mut self,
        validator_id: &[u8; 32],
        severity: SlashSeverity,
        current_epoch: u64,
    ) -> Result<(u64, u64), StakingError> {
        let a = self
            .validators
            .get_mut(validator_id)
            .ok_or(StakingError::ValidatorNotFound)?;
        match a.state {
            ValidatorState::Active | ValidatorState::Exiting { .. } => {}
            _ => {
                return Err(StakingError::InvalidTransition {
                    from: a.state.label().into(),
                    to: "Slashed".into(),
                });
            }
        }
        if let Some(last) = a.last_slash_epoch {
            if current_epoch < last + self.config.slash_cooldown_epochs {
                return Err(StakingError::SlashCooldown {
                    next_allowed: last + self.config.slash_cooldown_epochs,
                });
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
            a.state = ValidatorState::Exiting {
                exit_epoch: current_epoch,
            };
            a.exit_epoch = Some(current_epoch);
            a.unlock_epoch = Some(current_epoch + self.config.unbonding_epochs);
        }
        self.recompute_total();
        Ok((slash_amount, reporter_reward))
    }

    // ─── Score / Uptime ─────────────────────────────────────

    // ─── L1-Native Registration & Additional Stake ──────────────────

    /// L1 ネイティブでバリデーターを登録する (Solana 不要)。
    ///
    /// `ValidatorStakeTx::Register` が finalized されたときにノードが呼ぶ。
    /// Solana 検証の代わりに L1 UTXO で stake_amount を証明済みとみなす。
    ///
    /// # Security
    /// - `stake_tx_hash` は `ValidatorStakeTx` 自体の tx_hash (replay 防止)
    /// - `net_stake_amount` は tx.net_stake_amount() — UTXO 合計 - fee
    /// - 同一 `stake_tx_hash` の二重使用は `used_stake_signatures` で防ぐ
    pub fn register_l1_native(
        &mut self,
        validator_id: [u8; 32],
        pubkey: Vec<u8>,
        net_stake_amount: u64,
        commission_bps: u32,
        reward_address: [u8; 32],
        current_epoch: u64,
        stake_tx_hash: [u8; 32],
        stake_output_index: u32,
    ) -> Result<(), StakingError> {
        // stake_tx_hash を signature として再利用防止セットに保存
        let tx_hash_hex = hex::encode(stake_tx_hash);

        if self.used_stake_signatures.contains(&tx_hash_hex) {
            return Err(StakingError::StakeSignatureAlreadyUsed {
                signature: tx_hash_hex,
            });
        }
        if net_stake_amount < self.config.min_validator_stake {
            return Err(StakingError::BelowMinStake {
                deposited: net_stake_amount,
                minimum: self.config.min_validator_stake,
            });
        }
        if commission_bps > self.config.max_commission_bps {
            return Err(StakingError::CommissionTooHigh {
                requested: commission_bps,
                maximum: self.config.max_commission_bps,
            });
        }
        if let Some(existing) = self.validators.get(&validator_id) {
            if existing.state != ValidatorState::Unlocked {
                return Err(StakingError::AlreadyRegistered);
            }
        }

        self.used_stake_signatures.insert(tx_hash_hex.clone());

        self.validators.insert(
            validator_id,
            ValidatorAccount {
                validator_id,
                pubkey,
                stake_amount: net_stake_amount,
                state: ValidatorState::Locked,
                registered_epoch: current_epoch,
                activation_epoch: None,
                exit_epoch: None,
                unlock_epoch: None,
                commission_bps,
                reward_address,
                cumulative_slashed: 0,
                last_slash_epoch: None,
                uptime_bps: 10_000,
                score: 0,
                stake_tx_hash,
                stake_output_index,
                // L1 ネイティブ登録は L1 UTXO で stake 証明済み
                solana_stake_verified: true,
                solana_stake_signature: Some(tx_hash_hex),
                bridge_solana_pubkey: None,
            },
        );
        self.recompute_total();

        tracing::info!(
            "StakingRegistry::register_l1_native: validator={} stake={} epoch={}",
            hex::encode(validator_id),
            net_stake_amount,
            current_epoch
        );
        Ok(())
    }

    /// 既存バリデーターに追加ステークを積む。
    ///
    /// `ValidatorStakeTx::StakeMore` が finalized されたときにノードが呼ぶ。
    ///
    /// # 状態制約
    /// - Locked / Active 状態のバリデーターのみ対象
    /// - Exiting / Unlocked は拒否（まず exit を完了させてから再登録）
    ///
    /// # Security
    /// - `additional_amount` は `ValidatorStakeTx::net_stake_amount()` を使うこと
    /// - `stake_tx_hash` の再利用は防ぐ（replay 防止）
    /// - overflow は checked_add で検査
    pub fn stake_more(
        &mut self,
        validator_id: &[u8; 32],
        additional_amount: u64,
        stake_tx_hash: [u8; 32],
    ) -> Result<u64, StakingError> {
        // replay 防止
        let tx_hash_hex = hex::encode(stake_tx_hash);
        if self.used_stake_signatures.contains(&tx_hash_hex) {
            return Err(StakingError::StakeSignatureAlreadyUsed {
                signature: tx_hash_hex,
            });
        }
        if additional_amount == 0 {
            return Err(StakingError::BelowMinStake {
                deposited: 0,
                minimum: 1,
            });
        }

        let a = self
            .validators
            .get_mut(validator_id)
            .ok_or(StakingError::ValidatorNotFound)?;

        // Exiting / Unlocked には追加ステーク不可
        match a.state {
            ValidatorState::Locked | ValidatorState::Active => {}
            ValidatorState::Exiting { .. } => {
                return Err(StakingError::InvalidTransition {
                    from: "EXITING".into(),
                    to: "stake_more".into(),
                });
            }
            ValidatorState::Unlocked => {
                return Err(StakingError::InvalidTransition {
                    from: "UNLOCKED".into(),
                    to: "stake_more".into(),
                });
            }
        }

        // overflow 検査
        let new_stake = a
            .stake_amount
            .checked_add(additional_amount)
            .ok_or(StakingError::Overflow)?;

        a.stake_amount = new_stake;
        self.used_stake_signatures.insert(tx_hash_hex);
        self.recompute_total();

        tracing::info!(
            "StakingRegistry::stake_more: validator={} additional={} new_total={}",
            hex::encode(validator_id),
            additional_amount,
            new_stake
        );
        Ok(new_stake)
    }

    pub fn update_score(&mut self, validator_id: &[u8; 32], new_score: u64) {
        if let Some(a) = self.validators.get_mut(validator_id) {
            a.score = new_score;
        }
    }

    pub fn update_uptime(&mut self, validator_id: &[u8; 32], uptime_bps: u64) {
        if let Some(a) = self.validators.get_mut(validator_id) {
            a.uptime_bps = uptime_bps.min(10_000);
        }
    }

    fn recompute_total(&mut self) {
        self.total_locked = self
            .validators
            .values()
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
    Minor,  // 1%
    Medium, // 5%
    Severe, // 20%
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
        validator_id: [u8; 32],
        message_a: Vec<u8>,
        signature_a: Vec<u8>,
        message_b: Vec<u8>,
        signature_b: Vec<u8>,
    },
    InvalidBlock {
        validator_id: [u8; 32],
        block_hash: [u8; 32],
        reason: String,
    },
    LongOffline {
        validator_id: [u8; 32],
        missed_from_epoch: u64,
        missed_to_epoch: u64,
    },
    ProtocolViolation {
        validator_id: [u8; 32],
        description: String,
    },
}

impl SlashEvidence {
    pub fn validator_id(&self) -> &[u8; 32] {
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
    /// SEC-STAKE: Solana staking TX has not been verified.
    /// The validator registered locally but their stake deposit on
    /// misakastake.com has not been confirmed on-chain.
    /// They cannot join the active set until verification passes.
    #[error("solana stake not verified — register at misakastake.com first")]
    StakeNotVerified,
    /// SEC-STAKE: This Solana TX signature has already been used to register
    /// another validator. One stake deposit = one validator only.
    #[error("solana stake signature already used by another validator: {signature}")]
    StakeSignatureAlreadyUsed { signature: String },
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

    fn make_id(n: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    fn register_and_activate(reg: &mut StakingRegistry, id: [u8; 32], stake: u64, epoch: u64) {
        reg.register(
            id,
            vec![1; 1952],
            stake,
            500,
            id,
            epoch,
            [id[0]; 32],
            0,
            true, // solana_stake_verified — pre-verified for test convenience
            Some(format!("test_sig_{}", id[0])),
        )
        .unwrap();
        reg.update_score(&id, 5000);
        reg.activate(&id, epoch + 1).unwrap();
    }

    fn insert_active_validator(reg: &mut StakingRegistry, id: [u8; 32], stake: u64, score: u64) {
        reg.validators.insert(
            id,
            ValidatorAccount {
                validator_id: id,
                pubkey: vec![1; 1952],
                stake_amount: stake,
                state: ValidatorState::Active,
                registered_epoch: 0,
                activation_epoch: Some(0),
                exit_epoch: None,
                unlock_epoch: None,
                commission_bps: 500,
                reward_address: id,
                cumulative_slashed: 0,
                last_slash_epoch: None,
                uptime_bps: 10_000,
                score,
                stake_tx_hash: [id[0]; 32],
                stake_output_index: 0,
                solana_stake_verified: true,
                solana_stake_signature: Some(format!("test_sig_{}", id[0])),
                bridge_solana_pubkey: None,
            },
        );
        reg.recompute_total();
    }

    #[test]
    fn test_full_lifecycle() {
        let mut reg = StakingRegistry::new(test_config());
        let id = make_id(1);

        // UNLOCKED → LOCKED (with Solana stake verified)
        reg.register(
            id,
            vec![1; 1952],
            10_000_000,
            500,
            id,
            0,
            [1; 32],
            0,
            true,
            Some("solana_sig_abc".into()),
        )
        .unwrap();
        assert_eq!(reg.get(&id).unwrap().state, ValidatorState::Locked);

        // LOCKED → ACTIVE
        reg.update_score(&id, 5000);
        reg.activate(&id, 1).unwrap();
        assert_eq!(reg.get(&id).unwrap().state, ValidatorState::Active);

        // ACTIVE → EXITING
        reg.exit(&id, 100).unwrap();
        assert!(matches!(
            reg.get(&id).unwrap().state,
            ValidatorState::Exiting { .. }
        ));

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
        assert!(reg
            .register(
                make_id(1),
                vec![],
                9_999_999,
                500,
                make_id(1),
                0,
                [1; 32],
                0,
                true,
                None,
            )
            .is_err());
    }

    #[test]
    fn test_exit_from_locked_fails() {
        let mut reg = StakingRegistry::new(test_config());
        let id = make_id(1);
        reg.register(id, vec![], 10_000_000, 500, id, 0, [1; 32], 0, true, None)
            .unwrap();
        assert!(reg.exit(&id, 10).is_err());
    }

    #[test]
    fn test_slash_auto_eject() {
        let mut reg = StakingRegistry::new(test_config());
        let id = make_id(1);
        register_and_activate(&mut reg, id, 10_000_000, 0);

        // 20% slash → 8M < 10M → auto-eject
        reg.slash(&id, SlashSeverity::Severe, 50).unwrap();
        assert!(matches!(
            reg.get(&id).unwrap().state,
            ValidatorState::Exiting { .. }
        ));
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
            insert_active_validator(&mut reg, make_id(i), 10_000_000 + i as u64 * 1000, 5_000);
        }
        assert_eq!(reg.compute_active_set().len(), 5);
        assert_eq!(reg.compute_active_set()[0].validator_id, make_id(7));
    }

    #[test]
    fn test_reward_weight_zero_below_min() {
        let config = test_config();
        let a = ValidatorAccount {
            validator_id: make_id(1),
            pubkey: vec![],
            stake_amount: 5_000_000,
            state: ValidatorState::Active,
            registered_epoch: 0,
            activation_epoch: Some(0),
            exit_epoch: None,
            unlock_epoch: None,
            commission_bps: 500,
            reward_address: make_id(1),
            cumulative_slashed: 0,
            last_slash_epoch: None,
            uptime_bps: 10_000,
            score: 10_000,
            stake_tx_hash: [0; 32],
            stake_output_index: 0,
            solana_stake_verified: true,
            solana_stake_signature: None,
            bridge_solana_pubkey: None,
        };
        assert_eq!(a.reward_weight(&config), 0);
    }

    #[test]
    fn test_reward_weight_linear_proportional() {
        let config = test_config();
        let make = |stake: u64, score: u64| ValidatorAccount {
            validator_id: make_id(1),
            pubkey: vec![],
            stake_amount: stake,
            state: ValidatorState::Active,
            registered_epoch: 0,
            activation_epoch: Some(0),
            exit_epoch: None,
            unlock_epoch: None,
            commission_bps: 500,
            reward_address: make_id(1),
            cumulative_slashed: 0,
            last_slash_epoch: None,
            uptime_bps: 10_000,
            score,
            stake_tx_hash: [0; 32],
            stake_output_index: 0,
            solana_stake_verified: true,
            solana_stake_signature: None,
            bridge_solana_pubkey: None,
        };
        let w1 = make(10_000_000, 1000).reward_weight(&config);
        let w2 = make(40_000_000, 1000).reward_weight(&config);
        // 4× stake → 4× weight (linear)
        let ratio = w2 as f64 / w1 as f64;
        assert!(
            (ratio - 4.0).abs() < 0.01,
            "4x stake should yield 4x weight, got {ratio}x"
        );
    }

    #[test]
    fn test_commission_too_high() {
        let mut reg = StakingRegistry::new(test_config());
        assert!(reg
            .register(
                make_id(1),
                vec![],
                10_000_000,
                9000,
                make_id(1),
                0,
                [1; 32],
                0,
                true,
                None,
            )
            .is_err());
    }

    #[test]
    fn test_reregister_after_unlock() {
        let mut reg = StakingRegistry::new(test_config());
        let id = make_id(1);
        register_and_activate(&mut reg, id, 10_000_000, 0);
        reg.exit(&id, 50).unwrap();
        reg.unlock(&id, 200).unwrap();
        reg.register(
            id,
            vec![1; 1952],
            10_000_000,
            500,
            id,
            300,
            [2; 32],
            0,
            true,
            Some("new_sig".into()),
        )
        .unwrap();
        assert_eq!(reg.get(&id).unwrap().state, ValidatorState::Locked);
    }

    // ── SEC-STAKE: misakastake.com Verification Tests ──

    #[test]
    fn test_activate_rejected_without_stake_verification() {
        let mut reg = StakingRegistry::new(test_config());
        let id = make_id(1);

        // Register WITHOUT Solana stake verification
        reg.register(
            id,
            vec![1; 1952],
            10_000_000,
            500,
            id,
            0,
            [1; 32],
            0,
            false, // NOT verified via misakastake.com
            None,
        )
        .unwrap();
        assert_eq!(reg.get(&id).unwrap().state, ValidatorState::Locked);
        assert!(!reg.get(&id).unwrap().solana_stake_verified);

        // Try to activate — MUST fail
        reg.update_score(&id, 5000);
        let result = reg.activate(&id, 1);
        assert!(result.is_err());
        match result.unwrap_err() {
            StakingError::StakeNotVerified => {} // expected
            other => panic!("expected StakeNotVerified, got: {}", other),
        }

        // Validator stays in LOCKED state
        assert_eq!(reg.get(&id).unwrap().state, ValidatorState::Locked);
    }

    #[test]
    fn test_activate_succeeds_after_mark_stake_verified() {
        let mut reg = StakingRegistry::new(test_config());
        let id = make_id(1);

        // Register without verification
        reg.register(
            id,
            vec![1; 1952],
            10_000_000,
            500,
            id,
            0,
            [1; 32],
            0,
            false,
            None,
        )
        .unwrap();

        // Activation blocked
        reg.update_score(&id, 5000);
        assert!(reg.activate(&id, 1).is_err());

        // Now verify the stake (simulating Solana RPC confirmation)
        reg.mark_stake_verified(&id, "5nXuqx...verified_sig".to_string())
            .unwrap();
        assert!(reg.get(&id).unwrap().solana_stake_verified);
        assert_eq!(
            reg.get(&id).unwrap().solana_stake_signature.as_deref(),
            Some("5nXuqx...verified_sig")
        );

        // Activation now succeeds
        assert!(reg.activate(&id, 1).is_ok());
        assert_eq!(reg.get(&id).unwrap().state, ValidatorState::Active);
    }

    #[test]
    fn test_register_with_verified_stake_can_activate_immediately() {
        let mut reg = StakingRegistry::new(test_config());
        let id = make_id(1);

        // Register WITH pre-verified stake (e.g., node verified during register)
        reg.register(
            id,
            vec![1; 1952],
            10_000_000,
            500,
            id,
            0,
            [1; 32],
            0,
            true,
            Some("pre_verified_sig".into()),
        )
        .unwrap();

        reg.update_score(&id, 5000);
        assert!(reg.activate(&id, 1).is_ok());
        assert_eq!(reg.get(&id).unwrap().state, ValidatorState::Active);
    }

    #[test]
    fn test_testnet_1m_stake_accepted() {
        // Testnet: 1M MISAKA = 1_000_000_000_000_000 base units (9 decimals)
        let config = StakingConfig::testnet();
        let mut reg = StakingRegistry::new(config.clone());
        let id = make_id(1);

        // Exactly 1M MISAKA — should succeed
        reg.register(
            id,
            vec![1; 1952],
            1_000_000_000_000_000,
            500,
            id,
            0,
            [1; 32],
            0,
            true,
            Some("testnet_sig".into()),
        )
        .unwrap();

        // Below 1M — should fail
        let id2 = make_id(2);
        let result = reg.register(
            id2,
            vec![1; 1952],
            999_999_999_999_999,
            500,
            id2,
            0,
            [2; 32],
            0,
            true,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_mainnet_10m_stake_required() {
        // Mainnet: 10M MISAKA = 10_000_000_000_000_000 base units (9 decimals)
        let config = StakingConfig::mainnet();
        let mut reg = StakingRegistry::new(config);
        let id = make_id(1);

        // Below 10M — should fail
        let result = reg.register(
            id,
            vec![1; 1952],
            9_999_999_999_999_999,
            500,
            id,
            0,
            [1; 32],
            0,
            true,
            None,
        );
        assert!(result.is_err());

        // Exactly 10M — should succeed
        reg.register(
            id,
            vec![1; 1952],
            10_000_000_000_000_000,
            500,
            id,
            0,
            [1; 32],
            0,
            true,
            Some("mainnet_sig".into()),
        )
        .unwrap();
    }

    #[test]
    fn test_same_stake_signature_rejected_for_second_validator() {
        let mut reg = StakingRegistry::new(test_config());
        let id1 = make_id(1);
        let id2 = make_id(2);
        let shared_sig = "same_solana_tx_sig_12345".to_string();

        // First validator registers with a Solana stake signature — OK
        reg.register(
            id1,
            vec![1; 1952],
            10_000_000,
            500,
            id1,
            0,
            [1; 32],
            0,
            true,
            Some(shared_sig.clone()),
        )
        .unwrap();

        // Second validator tries to use the SAME signature — MUST fail
        let result = reg.register(
            id2,
            vec![2; 1952],
            10_000_000,
            500,
            id2,
            0,
            [2; 32],
            0,
            true,
            Some(shared_sig.clone()),
        );
        assert!(result.is_err());
        match result.unwrap_err() {
            StakingError::StakeSignatureAlreadyUsed { signature } => {
                assert_eq!(signature, shared_sig);
            }
            other => panic!("expected StakeSignatureAlreadyUsed, got: {}", other),
        }
    }

    #[test]
    fn test_stake_signature_released_after_unlock() {
        let mut reg = StakingRegistry::new(test_config());
        let id1 = make_id(1);
        let id2 = make_id(2);
        let sig = "reusable_sig".to_string();

        // Register, activate, exit, unlock
        register_and_activate(&mut reg, id1, 10_000_000, 0);
        // Overwrite signature (register_and_activate uses "test_sig")
        reg.mark_stake_verified(&id1, sig.clone()).unwrap();

        reg.exit(&id1, 50).unwrap();
        reg.unlock(&id1, 200).unwrap();

        // After unlock, the signature should be released
        // A new validator can use it
        reg.register(
            id2,
            vec![2; 1952],
            10_000_000,
            500,
            id2,
            300,
            [2; 32],
            0,
            true,
            Some(sig.clone()),
        )
        .unwrap();
        assert_eq!(reg.get(&id2).unwrap().state, ValidatorState::Locked);
    }

    #[test]
    fn test_staking_registry_json_roundtrip_preserves_32_byte_validator_ids() {
        let mut reg = StakingRegistry::new(test_config());
        let validator_id = make_id(7);
        reg.register(
            validator_id,
            vec![0x11; 1952],
            10_000_000,
            500,
            [0x22; 32],
            1,
            [0x33; 32],
            0,
            false,
            None,
        )
        .unwrap();

        let json = serde_json::to_string(&reg).expect("serialize staking registry");
        let decoded: StakingRegistry =
            serde_json::from_str(&json).expect("deserialize staking registry");

        assert!(decoded.get(&validator_id).is_some());
    }
}
