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
    /// via the misakastake.com staking program. One of the two gates for
    /// LOCKED → ACTIVE (the other is `l1_stake_verified`).
    /// Set to `true` only after the node confirms the staking TX on-chain.
    #[serde(default)]
    pub solana_stake_verified: bool,

    /// SEC-STAKE: Solana TX signature proving the staking deposit (base58).
    /// Stored for audit trail and re-verification.
    #[serde(default)]
    pub solana_stake_signature: Option<String>,

    /// v0.9.0: Whether this validator's stake has been locked via an L1 native
    /// `ValidatorStakeTx::Register` / `StakeMore` UTXO transaction. One of the
    /// two gates for LOCKED → ACTIVE (the other is `solana_stake_verified`).
    ///
    /// The flag is set by `utxo_executor` after a `StakeDeposit` tx is finalized
    /// (wired in v0.9.0 γ-3). In β-1 the field is defined and read by
    /// `active_authorities()` but not yet written by any caller — existing
    /// snapshots deserialize with `false` via `#[serde(default)]`.
    #[serde(default)]
    pub l1_stake_verified: bool,

    /// v0.9.0: Peer-to-peer network address (`ip:port`) announced by the
    /// validator. Populated by the REST registration path and by the
    /// L1 `Register` tx via `params.p2p_endpoint`. `None` for validators
    /// migrated from pre-0.9.0 snapshots that never announced an address.
    #[serde(default)]
    pub network_address: Option<String>,
}

impl ValidatorAccount {
    /// Whether eligible for the active set.
    ///
    /// γ-3: stake verification is now satisfied by EITHER the Solana bridge
    /// (`solana_stake_verified`) OR the L1 native `ValidatorStakeTx` path
    /// (`l1_stake_verified`). Both paths produce the same on-chain
    /// attestation for consensus purposes; callers can choose either.
    pub fn is_eligible(&self, config: &StakingConfig) -> bool {
        self.state == ValidatorState::Active
            && self.stake_amount >= config.min_validator_stake
            && self.uptime_bps >= config.min_uptime_bps
            && self.score >= config.min_score
            && (self.solana_stake_verified || self.l1_stake_verified)
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

    /// γ-3: non-serialized handle to the caller-owned `Arc<StakingConfig>`.
    ///
    /// Serialized snapshots still carry the raw `config` field (above) so the
    /// wire format is unchanged. On `load()` this starts out `None`; the
    /// lifecycle bootstrap calls [`Self::rewire_config_arc`] to bind it to
    /// the process-wide canonical `Arc<StakingConfig>`.
    ///
    /// Callers obtain the shared Arc via [`Self::config_arc`] and can assert
    /// singleton wiring with `Arc::ptr_eq` at startup.
    #[serde(skip, default)]
    config_arc: Option<std::sync::Arc<StakingConfig>>,
}

impl StakingRegistry {
    /// γ-3: deprecated in favour of [`Self::new_with_config_arc`] so that
    /// `StakingConfig` exists as a single Arc'd instance shared across
    /// registry / executor / API state. Kept working for tests and legacy
    /// callers — internally wraps the value in a fresh Arc.
    #[deprecated(
        since = "0.9.0",
        note = "use new_with_config_arc to share one StakingConfig instance \
                across registry / executor / api state"
    )]
    pub fn new(config: StakingConfig) -> Self {
        Self::new_with_config_arc(std::sync::Arc::new(config))
    }

    /// γ-3: canonical constructor. Stores the caller-owned Arc so that
    /// `config_arc()` returns the *same* Arc handle downstream.
    pub fn new_with_config_arc(config: std::sync::Arc<StakingConfig>) -> Self {
        let cloned = (*config).clone();
        Self {
            validators: HashMap::new(),
            total_locked: 0,
            config: cloned,
            used_stake_signatures: std::collections::HashSet::new(),
            config_arc: Some(config),
        }
    }

    /// γ-3: rewire the internal Arc after snapshot deserialization so the
    /// registry shares the process-wide canonical `Arc<StakingConfig>`.
    ///
    /// The serialized `config` value is kept as-is — by γ-3 design it must
    /// match the caller's Arc (same values). `Arc::ptr_eq(&self.config_arc,
    /// &caller_arc)` is what subsequent singleton asserts check.
    pub fn rewire_config_arc(&mut self, config: std::sync::Arc<StakingConfig>) {
        self.config_arc = Some(config);
    }

    pub fn config(&self) -> &StakingConfig {
        &self.config
    }

    /// γ-3: handle to the canonical `Arc<StakingConfig>`.
    ///
    /// If the registry was deserialized from a snapshot and [`Self::rewire_config_arc`]
    /// has not yet been called, this falls back to wrapping the inner value in a
    /// fresh Arc. In that degraded mode `Arc::ptr_eq` with the caller's Arc
    /// will return false — the lifecycle bootstrap is expected to always
    /// rewire on the production path.
    pub fn config_arc(&self) -> std::sync::Arc<StakingConfig> {
        self.config_arc
            .clone()
            .unwrap_or_else(|| std::sync::Arc::new(self.config.clone()))
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

    pub fn total_reward_weight(&self) -> u128 {
        self.compute_active_set()
            .iter()
            .map(|v| v.reward_weight(&self.config))
            .sum()
    }

    /// v0.9.0: Return validators that should appear in the DAG committee.
    ///
    /// The filter is:
    /// - `state == Active`
    /// - `(solana_stake_verified || l1_stake_verified)` — at least one of the
    ///   two verification paths has succeeded
    /// - `network_address` is `Some` — otherwise the node cannot be contacted
    ///
    /// Output is sorted by `validator_id` (canonical id = the 32-byte hash
    /// of the ML-DSA-65 pubkey) in ascending order, so the caller can assign
    /// `authority_index` deterministically without depending on `HashMap`
    /// iteration order.
    pub fn active_authorities(&self) -> Vec<&ValidatorAccount> {
        let mut out: Vec<&ValidatorAccount> = self
            .validators
            .values()
            .filter(|v| {
                v.state == ValidatorState::Active
                    && (v.solana_stake_verified || v.l1_stake_verified)
                    && v.network_address.is_some()
            })
            .collect();
        out.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));
        out
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
    /// Either `solana_stake_verified` OR `l1_stake_verified` must become true
    /// before `activate()` will succeed. They are set by distinct paths:
    /// Solana bridge (`mark_stake_verified`) and L1 UTXO executor (v0.9.0 γ-3).
    ///
    /// # 0.9.0 signature change
    /// The `l1_stake_verified` parameter was added to allow the L1 native
    /// path to mark its verification flag at registration time. REST callers
    /// (Solana path) should pass `false`; the L1 `utxo_executor` passes `true`.
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
        l1_stake_verified: bool,
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
                l1_stake_verified,
                network_address: None,
            },
        );
        self.recompute_total();
        Ok(())
    }

    /// Mark a validator's Solana stake as verified after on-chain confirmation.
    ///
    /// Called by the node after verifying the staking TX via Solana RPC.
    /// This is the prerequisite for `activate()`.
    /// SEC-FIX: `on_chain_amount` parameter added. Previously the self-reported
    /// `stake_amount` from the registration request was never corrected to match
    /// the actual on-chain stake. A validator could claim stake_amount=1B while
    /// only staking min_stake, gaining disproportionate BFT weight and rewards.
    pub fn mark_stake_verified(
        &mut self,
        validator_id: &[u8; 32],
        signature: String,
        on_chain_amount: Option<u64>,
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

        // SEC-FIX: Clamp stake_amount to the actual on-chain amount.
        // Prevents validators from inflating their BFT weight by self-reporting
        // a higher stake_amount than they actually staked on-chain.
        if let Some(actual) = on_chain_amount {
            if actual < account.stake_amount {
                tracing::warn!(
                    "Validator {:?}: claimed stake {} but on-chain is {}; clamping",
                    hex::encode(&validator_id[..8]),
                    account.stake_amount,
                    actual
                );
                account.stake_amount = actual;
            }
        }

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

        // SEC-STAKE / γ-3: Require on-chain stake attestation from EITHER
        // the Solana bridge (`solana_stake_verified`, set via `mark_stake_verified`)
        // OR the L1 native `ValidatorStakeTx::Register` path
        // (`l1_stake_verified`, set by `utxo_executor` when the deposit tx
        // is finalized). Without one of these, a validator could register
        // with a fake stake_amount and join the active set without actually
        // locking tokens on any side.
        if !a.solana_stake_verified && !a.l1_stake_verified {
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

        // Audit R7: Do NOT remove used_stake_signatures on unlock.
        // The set must be monotonically growing to prevent signature replay.
        // Re-registration uses a new stake_tx_hash (from a new UTXO), so the
        // old signature doesn't need to be released.
        a.solana_stake_verified = false;
        a.solana_stake_signature = None;

        self.recompute_total();
        Ok(amount)
    }

    // ─── γ-5: Epoch-boundary unbonding settlement ───────────

    /// γ-5: At an epoch boundary, unlock every `Exiting` validator whose
    /// unbonding period has completed at `current_epoch` and return the
    /// `(validator_id, unlocked_amount, reward_address)` tuples needed by
    /// the caller (typically `UtxoExecutor::apply_settled_unlocks`) to
    /// materialize the unlocked stake into the UTXO set.
    ///
    /// This method performs the registry-side mutation (`state = Unlocked`,
    /// `stake_amount = 0`, etc.) synchronously. The caller is responsible for
    /// the UTXO-side effects; these two sides are not bundled into a single
    /// transaction — if the node crashes between them, the registry is
    /// persisted separately and replay reconciliation is expected to repair
    /// the gap on the next boot. γ-4 (transactional rollback) tightens this.
    ///
    /// Idempotency: after the first call unlocks a validator, subsequent
    /// calls in the same or later epoch skip it because `state` is no longer
    /// `Exiting` and `can_unlock()` returns `false`.
    pub fn settle_unlocks(&mut self, current_epoch: u64) -> Vec<([u8; 32], u64, [u8; 32])> {
        // Collect candidate ids up front so we release the borrow on
        // `self.validators` before mutating via `self.unlock(..)`.
        let candidates: Vec<[u8; 32]> = self
            .validators
            .iter()
            .filter(|(_, v)| v.can_unlock(current_epoch, &self.config))
            .map(|(id, _)| *id)
            .collect();

        let mut settled = Vec::with_capacity(candidates.len());
        for vid in candidates {
            // Capture reward_address BEFORE unlock (unlock() preserves it,
            // but reading before the mutation keeps the contract simple).
            let reward_address = match self.validators.get(&vid) {
                Some(a) => a.reward_address,
                None => continue,
            };
            match self.unlock(&vid, current_epoch) {
                Ok(amount) => {
                    tracing::info!(
                        "γ-5 settle_unlocks: validator={} amount={} reward={}",
                        hex::encode(&vid[..8]),
                        amount,
                        hex::encode(&reward_address[..8]),
                    );
                    settled.push((vid, amount, reward_address));
                }
                Err(e) => {
                    // Should not happen — candidates all pass can_unlock().
                    // Log and skip rather than panic so a single bad entry
                    // doesn't freeze the epoch boundary.
                    tracing::warn!(
                        "γ-5 settle_unlocks: unexpected unlock failure for {}: {:?}",
                        hex::encode(&vid[..8]),
                        e
                    );
                }
            }
        }
        settled
    }

    /// Group 2: At an epoch boundary, promote every `Locked` validator that
    /// has passed the stake-verification gate (OR of `solana_stake_verified`
    /// / `l1_stake_verified`) and meets the minimum stake threshold, up to
    /// the `max_active_validators` cap.
    ///
    /// This is the automatic counterpart to the manual `activate(..)` REST
    /// route. Returns the list of `validator_id`s that transitioned LOCKED
    /// → ACTIVE in this call. A validator that fails any `activate(..)`
    /// precondition is logged (warn!) and skipped — a single bad entry
    /// must not freeze the epoch boundary.
    ///
    /// Ordering: callers should run `settle_unlocks` FIRST so unbonded
    /// stake is retired, opening headroom under `max_active_validators`
    /// for new promotions in this same epoch.
    ///
    /// Idempotency: calling again in the same or a later epoch with no new
    /// LOCKED validators is a no-op. Validators already ACTIVE are ignored
    /// (filtered by `state == Locked`).
    pub fn auto_activate_locked(&mut self, current_epoch: u64) -> Vec<[u8; 32]> {
        // Collect candidate ids up front so we release the borrow on
        // `self.validators` before mutating via `self.activate(..)`.
        // Pre-filter here to avoid work inside activate() that will fail
        // for obvious reasons (wrong state, unverified, below min stake).
        let candidates: Vec<[u8; 32]> = self
            .validators
            .iter()
            .filter(|(_, v)| {
                v.state == ValidatorState::Locked
                    && (v.solana_stake_verified || v.l1_stake_verified)
                    && v.stake_amount >= self.config.min_validator_stake
            })
            .map(|(id, _)| *id)
            .collect();

        // Deterministic order: ascending validator_id. Without a stable
        // order, the `max_active_validators` cap would apply non-
        // deterministically across nodes when more candidates exist than
        // slots.
        let mut candidates = candidates;
        candidates.sort();

        let mut activated = Vec::new();
        for vid in candidates {
            // `activate(..)` re-checks every precondition including the
            // `active_count < max_active_validators` cap, so as we promote
            // validators one-by-one the cap is enforced automatically
            // (later candidates see an incremented `active_count`).
            match self.activate(&vid, current_epoch) {
                Ok(()) => {
                    tracing::info!(
                        "Group 2 auto_activate_locked: promoted validator={} at epoch={}",
                        hex::encode(&vid[..8]),
                        current_epoch,
                    );
                    activated.push(vid);
                }
                Err(StakingError::ValidatorSetFull) => {
                    // Cap reached — no point trying further candidates.
                    tracing::info!(
                        "Group 2 auto_activate_locked: active set full at epoch={}, skipping remaining candidates",
                        current_epoch,
                    );
                    break;
                }
                Err(e) => {
                    // Pre-filter should have caught these, but racing callers
                    // (REST activate running concurrently) could invalidate
                    // a candidate. Log and continue with the rest.
                    tracing::warn!(
                        "Group 2 auto_activate_locked: activate({}) failed: {:?}",
                        hex::encode(&vid[..8]),
                        e
                    );
                }
            }
        }
        activated
    }

    // ─── γ-4: Pre-flight dry-run checks ─────────────────────
    //
    // These helpers mirror the mutation path of `register_l1_native`,
    // `stake_more`, and `exit` but perform NO state changes. They return
    // the same `StakingError` variants the mutating call would, so
    // callers (`utxo_executor::apply_stake_*`) can reject a stake tx
    // *before* touching the UTXO set — closing the "donate to the void"
    // window where UTXO inputs were consumed only to have the registry
    // reject the mutation afterwards.
    //
    // The check is best-effort: the mutating call still re-validates
    // everything (defense in depth + race resilience). If the registry
    // is mutated concurrently between dry-run and commit, the real call
    // will still reject and the UTXO rollback path kicks in.

    /// γ-4: Dry-run equivalent of `register_l1_native`. Returns `Ok(())`
    /// iff a subsequent `register_l1_native` call with the same inputs
    /// would succeed against the current registry state.
    pub fn can_register_l1_native(
        &self,
        validator_id: &[u8; 32],
        net_stake_amount: u64,
        commission_bps: u32,
        stake_tx_hash: &[u8; 32],
    ) -> Result<(), StakingError> {
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
        if let Some(existing) = self.validators.get(validator_id) {
            if existing.state != ValidatorState::Unlocked {
                return Err(StakingError::AlreadyRegistered);
            }
        }
        Ok(())
    }

    /// γ-4: Dry-run equivalent of `stake_more`.
    pub fn can_stake_more(
        &self,
        validator_id: &[u8; 32],
        additional_amount: u64,
        stake_tx_hash: &[u8; 32],
    ) -> Result<(), StakingError> {
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
            .get(validator_id)
            .ok_or(StakingError::ValidatorNotFound)?;
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
        // Overflow check — mirrors the mutating path's `checked_add`.
        a.stake_amount
            .checked_add(additional_amount)
            .ok_or(StakingError::Overflow)?;
        Ok(())
    }

    /// γ-4: Dry-run equivalent of `exit`.
    pub fn can_exit(&self, validator_id: &[u8; 32]) -> Result<(), StakingError> {
        let a = self
            .validators
            .get(validator_id)
            .ok_or(StakingError::ValidatorNotFound)?;
        if a.state != ValidatorState::Active {
            return Err(StakingError::InvalidTransition {
                from: a.state.label().into(),
                to: "EXITING".into(),
            });
        }
        Ok(())
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
        // Audit fix: u128 arithmetic to prevent overflow on large stakes
        let slash_amount = ((a.stake_amount as u128) * (slash_bps as u128) / 10_000) as u64;
        let reporter_reward = ((slash_amount as u128)
            * (self.config.slash_reporter_reward_bps as u128)
            / 10_000) as u64;
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
        // Audit #22: Preserve slash history on re-registration.
        // When an Unlocked validator re-registers, their cumulative_slashed
        // and last_slash_epoch MUST be carried over to prevent slash evasion.
        let (prev_cumulative_slashed, prev_last_slash_epoch) =
            if let Some(existing) = self.validators.get(&validator_id) {
                if existing.state != ValidatorState::Unlocked {
                    return Err(StakingError::AlreadyRegistered);
                }
                (existing.cumulative_slashed, existing.last_slash_epoch)
            } else {
                (0, None)
            };

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
                cumulative_slashed: prev_cumulative_slashed,
                last_slash_epoch: prev_last_slash_epoch,
                uptime_bps: 10_000,
                score: 0,
                stake_tx_hash,
                stake_output_index,
                // 0.9.0 γ-3: L1 ネイティブパスは `l1_stake_verified` のみで
                // `activate()` の OR gate を満たす。`solana_stake_verified` を
                // `true` に併記していた β-1 のワークアラウンドは解除した
                // (activate() は `solana_stake_verified || l1_stake_verified`
                // を見るので、どちらか片方が true なら ACTIVE に移行できる)。
                solana_stake_verified: false,
                solana_stake_signature: Some(tx_hash_hex),
                l1_stake_verified: true,
                network_address: None,
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

    /// v0.9.0: Set the validator's announced P2P endpoint.
    ///
    /// `register()` inserts with `network_address: None` to keep the parameter
    /// list finite. Callers that know the address (REST registration,
    /// `utxo_executor` when processing `ValidatorStakeTx::Register`, the β-1
    /// `registered_validators.json` migrator) populate it via this method.
    pub fn set_network_address(
        &mut self,
        validator_id: &[u8; 32],
        addr: Option<String>,
    ) -> Result<(), StakingError> {
        let a = self
            .validators
            .get_mut(validator_id)
            .ok_or(StakingError::ValidatorNotFound)?;
        a.network_address = addr;
        Ok(())
    }

    /// v0.9.0: Operator-level hard removal for a validator that is still in
    /// `LOCKED` (i.e. never activated). Used by the β-2 `/api/deregister_validator`
    /// REST route so an operator can undo an accidental REST registration
    /// without waiting for the unbonding period.
    ///
    /// `used_stake_signatures` is NOT rolled back — signatures must remain
    /// monotonically growing for replay protection (audit R7), identical to
    /// the invariant maintained by `unlock()`.
    ///
    /// Returns `Err(StakingError::InvalidTransition)` if the validator is
    /// `Active`, `Exiting`, or `Unlocked` — those paths must go through
    /// `exit()` / `unlock()` respectively.
    pub fn force_remove_locked(&mut self, validator_id: &[u8; 32]) -> Result<(), StakingError> {
        let state = self
            .validators
            .get(validator_id)
            .map(|a| a.state)
            .ok_or(StakingError::ValidatorNotFound)?;
        if state != ValidatorState::Locked {
            return Err(StakingError::InvalidTransition {
                from: state.label().into(),
                to: "force_remove_locked".into(),
            });
        }
        self.validators.remove(validator_id);
        self.recompute_total();
        Ok(())
    }

    fn recompute_total(&mut self) {
        // Audit fix: use fold with saturating_add to prevent overflow
        self.total_locked = self
            .validators
            .values()
            .filter(|v| !matches!(v.state, ValidatorState::Unlocked))
            .fold(0u64, |acc, v| acc.saturating_add(v.stake_amount));
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
            // Audit fix: clamp Custom to 10000 bps (100%) maximum
            Self::Custom(bps) => (*bps).min(10_000),
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
#[allow(deprecated)] // γ-3: existing tests still call `StakingRegistry::new`
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
            false, // l1_stake_verified — not the L1 path in these tests
        )
        .unwrap();
        reg.update_score(&id, 5000);
        reg.activate(&id, epoch + 1).unwrap();
    }

    /// γ-3: register a validator via the L1 native path (l1_stake_verified = true,
    /// solana_stake_verified = false). Complementary to the Solana-only
    /// `register_and_activate` fixture above — mirrors what `utxo_executor`
    /// does when a `StakeDeposit::Register` tx is finalized.
    fn preregister_l1(reg: &mut StakingRegistry, id: [u8; 32], pubkey: Vec<u8>, stake_amount: u64) {
        reg.register(
            id,
            pubkey,
            stake_amount,
            500,
            id,
            0,
            [id[0]; 32],
            0,
            false, // solana_stake_verified
            None,  // solana_stake_signature (L1 path has none)
            true,  // l1_stake_verified — γ-3 gate
        )
        .expect("preregister_l1");
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
                l1_stake_verified: false,
                network_address: None,
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
            false,
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
                false,
            )
            .is_err());
    }

    #[test]
    fn test_exit_from_locked_fails() {
        let mut reg = StakingRegistry::new(test_config());
        let id = make_id(1);
        reg.register(
            id,
            vec![],
            10_000_000,
            500,
            id,
            0,
            [1; 32],
            0,
            true,
            None,
            false,
        )
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
            l1_stake_verified: false,
            network_address: None,
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
            l1_stake_verified: false,
            network_address: None,
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
                false,
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
            false,
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
            false, // l1_stake_verified — testing the "no verification" path
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
            false,
        )
        .unwrap();

        // Activation blocked
        reg.update_score(&id, 5000);
        assert!(reg.activate(&id, 1).is_err());

        // Now verify the stake (simulating Solana RPC confirmation)
        reg.mark_stake_verified(&id, "5nXuqx...verified_sig".to_string(), None)
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
            false,
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
            false,
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
            false,
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
            false,
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
            false,
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
            false,
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
            false,
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
    fn test_stake_signature_not_released_after_unlock() {
        // Audit R7: used_stake_signatures is now monotonically growing.
        // After unlock, the old signature remains in the set to prevent replay.
        // A new validator must use a DIFFERENT signature.
        let mut reg = StakingRegistry::new(test_config());
        let id1 = make_id(1);
        let id2 = make_id(2);
        let sig = "reusable_sig".to_string();

        // Register, activate, exit, unlock
        register_and_activate(&mut reg, id1, 10_000_000, 0);
        reg.mark_stake_verified(&id1, sig.clone(), None).unwrap();

        reg.exit(&id1, 50).unwrap();
        reg.unlock(&id1, 200).unwrap();

        // After unlock, the old signature is NOT released — replay prevented
        let result = reg.register(
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
            false,
        );
        assert!(result.is_err(), "old signature must not be reusable");

        // But a new, different signature works fine
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
            Some("new_different_sig".to_string()),
            false,
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
            false,
        )
        .unwrap();

        let json = serde_json::to_string(&reg).expect("serialize staking registry");
        let decoded: StakingRegistry =
            serde_json::from_str(&json).expect("deserialize staking registry");

        assert!(decoded.get(&validator_id).is_some());
    }

    // ─── γ-3: activate() / is_eligible() OR gate tests ────────────────────

    #[test]
    fn test_activate_with_only_l1_verified_ok() {
        let mut reg = StakingRegistry::new(test_config());
        let id = make_id(1);
        preregister_l1(&mut reg, id, vec![1; 1952], 10_000_000);
        // activation should pass even though solana_stake_verified=false
        reg.activate(&id, 1)
            .expect("activate with only l1_stake_verified");
        let acc = reg.get(&id).expect("validator present");
        assert_eq!(acc.state, ValidatorState::Active);
        assert!(acc.l1_stake_verified);
        assert!(!acc.solana_stake_verified);
    }

    #[test]
    fn test_activate_with_neither_rejected() {
        let mut reg = StakingRegistry::new(test_config());
        let id = make_id(2);
        reg.register(
            id,
            vec![1; 1952],
            10_000_000,
            500,
            id,
            0,
            [id[0]; 32],
            0,
            false, // solana_stake_verified
            None,  // solana_stake_signature
            false, // l1_stake_verified
        )
        .expect("register");
        // both gates false — activate must reject
        match reg.activate(&id, 1) {
            Err(StakingError::StakeNotVerified) => {}
            other => panic!("expected StakeNotVerified, got {:?}", other),
        }
    }

    #[test]
    fn test_is_eligible_l1_only_passes() {
        let mut reg = StakingRegistry::new(test_config());
        let id = make_id(3);
        preregister_l1(&mut reg, id, vec![1; 1952], 10_000_000);
        reg.activate(&id, 1).expect("activate");
        reg.update_score(&id, 5000);
        let cfg = reg.config().clone();
        let acc = reg.get(&id).expect("validator present");
        assert!(acc.is_eligible(&cfg), "l1-only validator must be eligible");
        // sanity: solana-only version is still eligible under the same config
        let mut reg2 = StakingRegistry::new(test_config());
        register_and_activate(&mut reg2, make_id(4), 10_000_000, 0);
        reg2.update_score(&make_id(4), 5000);
        let acc2 = reg2.get(&make_id(4)).expect("solana validator");
        assert!(acc2.is_eligible(&cfg));
    }

    // ─── γ-3: StakingConfig Arc singleton property ────────────────────────

    #[test]
    fn test_new_with_config_arc_preserves_arc_identity() {
        let arc = std::sync::Arc::new(test_config());
        let reg = StakingRegistry::new_with_config_arc(arc.clone());
        assert!(
            std::sync::Arc::ptr_eq(&arc, &reg.config_arc()),
            "new_with_config_arc must return an Arc bit-equal to the caller's",
        );
    }

    #[test]
    fn test_rewire_config_arc_after_deserialize() {
        let original = StakingRegistry::new(test_config());
        let json = serde_json::to_string(&original).expect("serialize");
        let mut decoded: StakingRegistry = serde_json::from_str(&json).expect("deserialize");
        // config_arc after deserialize is an orphan Arc; rewire to canonical
        let canonical = std::sync::Arc::new(test_config());
        decoded.rewire_config_arc(canonical.clone());
        assert!(
            std::sync::Arc::ptr_eq(&canonical, &decoded.config_arc()),
            "rewire must bind to caller-owned Arc",
        );
    }

    // ─── γ-5: settle_unlocks tests ────────────────────────────────

    #[test]
    fn settle_unlocks_returns_completed_validators() {
        // test_config: unbonding_epochs = 100
        let mut reg = StakingRegistry::new(test_config());
        let id = make_id(1);
        register_and_activate(&mut reg, id, 20_000_000, 0);
        reg.exit(&id, 10).expect("exit ok");

        // Before unbonding completes (epoch 10 + 100 = 110).
        assert_eq!(
            reg.settle_unlocks(109),
            Vec::<([u8; 32], u64, [u8; 32])>::new(),
            "must not settle before unbonding completes"
        );

        // At/after unbonding completion — exactly one settlement.
        let settled = reg.settle_unlocks(110);
        assert_eq!(settled.len(), 1);
        assert_eq!(settled[0].0, id);
        assert_eq!(
            settled[0].1, 20_000_000,
            "returned amount == original stake"
        );
        assert_eq!(settled[0].2, id, "reward_address matches register()");
        assert_eq!(
            reg.get(&id).unwrap().state,
            ValidatorState::Unlocked,
            "state transitions to Unlocked"
        );
        assert_eq!(reg.get(&id).unwrap().stake_amount, 0, "stake zeroed");
    }

    #[test]
    fn settle_unlocks_skips_still_bonding() {
        let mut reg = StakingRegistry::new(test_config());
        let id = make_id(2);
        register_and_activate(&mut reg, id, 15_000_000, 0);
        reg.exit(&id, 50).expect("exit ok");

        // 100 epochs not yet elapsed (50 + 49 = 99, needs >= 150).
        assert!(reg.settle_unlocks(99).is_empty());
        assert!(reg.settle_unlocks(149).is_empty());
        assert_eq!(
            reg.get(&id).unwrap().state,
            ValidatorState::Exiting { exit_epoch: 50 },
            "still EXITING while under unbonding period"
        );
    }

    #[test]
    fn settle_unlocks_idempotent_within_same_epoch() {
        let mut reg = StakingRegistry::new(test_config());
        let id = make_id(3);
        register_and_activate(&mut reg, id, 12_000_000, 0);
        reg.exit(&id, 5).expect("exit ok");

        // First call settles; second call must return empty (already Unlocked).
        let first = reg.settle_unlocks(105);
        assert_eq!(first.len(), 1);

        let second = reg.settle_unlocks(105);
        assert!(
            second.is_empty(),
            "second call in same epoch must be no-op (idempotent)"
        );

        // Also idempotent at a later epoch — validator stays Unlocked.
        let third = reg.settle_unlocks(200);
        assert!(third.is_empty(), "idempotent at later epoch too");
    }

    #[test]
    fn settle_unlocks_multiple_validators_partial_batch() {
        // 3 validators with staggered exit epochs. At epoch 120:
        //   - v1 exited at 5  → unlocks at 105   ✓ settled
        //   - v2 exited at 15 → unlocks at 115   ✓ settled
        //   - v3 exited at 25 → unlocks at 125   ✗ still bonding
        let mut reg = StakingRegistry::new(test_config());
        let v1 = make_id(10);
        let v2 = make_id(11);
        let v3 = make_id(12);
        register_and_activate(&mut reg, v1, 11_000_000, 0);
        register_and_activate(&mut reg, v2, 11_000_000, 0);
        register_and_activate(&mut reg, v3, 11_000_000, 0);
        reg.exit(&v1, 5).unwrap();
        reg.exit(&v2, 15).unwrap();
        reg.exit(&v3, 25).unwrap();

        let settled = reg.settle_unlocks(120);
        assert_eq!(
            settled.len(),
            2,
            "only the two fully-unbonded validators settle"
        );
        let settled_ids: std::collections::HashSet<[u8; 32]> =
            settled.iter().map(|(id, _, _)| *id).collect();
        assert!(settled_ids.contains(&v1));
        assert!(settled_ids.contains(&v2));
        assert!(!settled_ids.contains(&v3));

        assert_eq!(reg.get(&v1).unwrap().state, ValidatorState::Unlocked);
        assert_eq!(reg.get(&v2).unwrap().state, ValidatorState::Unlocked);
        assert_eq!(
            reg.get(&v3).unwrap().state,
            ValidatorState::Exiting { exit_epoch: 25 },
            "v3 remains EXITING"
        );

        // Advance to epoch 125 — v3 now settles, v1/v2 stay Unlocked.
        let later = reg.settle_unlocks(125);
        assert_eq!(later.len(), 1);
        assert_eq!(later[0].0, v3);
    }

    // ─── Group 2: auto_activate_locked tests ──────────────────────

    /// Register a LOCKED validator (not yet activated) with arbitrary
    /// verification flags. Mirrors the REST register path without the
    /// activate step.
    fn register_locked(
        reg: &mut StakingRegistry,
        id: [u8; 32],
        stake: u64,
        solana_verified: bool,
        l1_verified: bool,
    ) {
        reg.register(
            id,
            vec![1; 1952],
            stake,
            500,
            id,
            0,
            [id[0]; 32],
            0,
            solana_verified,
            if solana_verified {
                Some(format!("sig_{}", id[0]))
            } else {
                None
            },
            l1_verified,
        )
        .expect("register_locked");
    }

    #[test]
    fn auto_activate_locked_promotes_verified_validator() {
        let mut reg = StakingRegistry::new(test_config());
        let id = make_id(50);
        // Above min stake (10_000_000) + solana verified.
        register_locked(&mut reg, id, 20_000_000, true, false);
        assert_eq!(reg.get(&id).unwrap().state, ValidatorState::Locked);

        let activated = reg.auto_activate_locked(5);
        assert_eq!(activated, vec![id]);
        assert_eq!(reg.get(&id).unwrap().state, ValidatorState::Active);
        assert_eq!(reg.get(&id).unwrap().activation_epoch, Some(5));
    }

    #[test]
    fn auto_activate_locked_skips_unverified() {
        let mut reg = StakingRegistry::new(test_config());
        let id = make_id(51);
        // Above min stake but NEITHER verification flag set.
        register_locked(&mut reg, id, 20_000_000, false, false);

        let activated = reg.auto_activate_locked(7);
        assert!(
            activated.is_empty(),
            "unverified validators must not be auto-activated"
        );
        assert_eq!(
            reg.get(&id).unwrap().state,
            ValidatorState::Locked,
            "unverified stays LOCKED",
        );
    }

    #[test]
    fn auto_activate_locked_respects_max_validators_cap() {
        // test_config has max_active_validators = 5. Fill 5 ACTIVE slots,
        // then register 3 LOCKED candidates. auto_activate must promote
        // zero of them because the set is already full.
        let mut reg = StakingRegistry::new(test_config());
        for i in 0..5u8 {
            insert_active_validator(&mut reg, make_id(60 + i), 50_000_000, 5000);
        }
        assert_eq!(reg.active_count(), 5);

        for i in 0..3u8 {
            register_locked(&mut reg, make_id(70 + i), 20_000_000, true, false);
        }

        let activated = reg.auto_activate_locked(9);
        assert!(
            activated.is_empty(),
            "set is full → no promotions; got {:?}",
            activated
        );
        for i in 0..3u8 {
            assert_eq!(
                reg.get(&make_id(70 + i)).unwrap().state,
                ValidatorState::Locked,
                "candidate {} must remain LOCKED",
                70 + i
            );
        }
    }

    // ─── γ-4: dry-run check tests ─────────────────────────────────

    #[test]
    fn gamma4_can_register_l1_native_mirrors_register_gates() {
        let mut reg = StakingRegistry::new(test_config());
        let vid = make_id(91);
        let tx_hash = [0x91u8; 32];

        // Happy path.
        assert!(reg
            .can_register_l1_native(&vid, 20_000_000, 500, &tx_hash)
            .is_ok());

        // Below min stake.
        match reg.can_register_l1_native(&vid, 1, 500, &tx_hash) {
            Err(StakingError::BelowMinStake { .. }) => {}
            other => panic!("expected BelowMinStake, got {:?}", other),
        }

        // Commission too high.
        match reg.can_register_l1_native(&vid, 20_000_000, 9999, &tx_hash) {
            Err(StakingError::CommissionTooHigh { .. }) => {}
            other => panic!("expected CommissionTooHigh, got {:?}", other),
        }

        // After a real register_l1_native, the same tx_hash must be
        // rejected as replay AND the validator_id must be rejected as
        // already-registered. Use register_l1_native so the replay check
        // hits the tx_hash-hex entry that can_register_l1_native inspects.
        reg.register_l1_native(vid, vec![1; 1952], 20_000_000, 500, vid, 0, tx_hash, 0)
            .expect("register_l1_native");

        // Replay of same tx_hash.
        match reg.can_register_l1_native(&make_id(92), 20_000_000, 500, &tx_hash) {
            Err(StakingError::StakeSignatureAlreadyUsed { .. }) => {}
            other => panic!("expected StakeSignatureAlreadyUsed, got {:?}", other),
        }

        // Different tx_hash but same validator_id (Locked — not Unlocked).
        let other_hash = [0x92u8; 32];
        match reg.can_register_l1_native(&vid, 20_000_000, 500, &other_hash) {
            Err(StakingError::AlreadyRegistered) => {}
            other => panic!("expected AlreadyRegistered, got {:?}", other),
        }
    }

    #[test]
    fn gamma4_can_stake_more_mirrors_stake_more_gates() {
        let mut reg = StakingRegistry::new(test_config());
        let vid = make_id(93);
        let initial_hash = [0x93u8; 32];

        // Register first so StakeMore has a target. Use register_l1_native
        // so the stake_tx_hash-hex lands in used_stake_signatures — the
        // same replay namespace can_stake_more inspects.
        reg.register_l1_native(vid, vec![1; 1952], 20_000_000, 500, vid, 0, initial_hash, 0)
            .expect("register_l1_native");

        // Happy path on a LOCKED validator.
        let more_hash = [0x94u8; 32];
        assert!(reg.can_stake_more(&vid, 1_000, &more_hash).is_ok());

        // Zero additional amount → rejected.
        match reg.can_stake_more(&vid, 0, &[0xFFu8; 32]) {
            Err(StakingError::BelowMinStake { .. }) => {}
            other => panic!("expected BelowMinStake, got {:?}", other),
        }

        // Replay of register's tx_hash → rejected.
        match reg.can_stake_more(&vid, 1_000, &initial_hash) {
            Err(StakingError::StakeSignatureAlreadyUsed { .. }) => {}
            other => panic!("expected StakeSignatureAlreadyUsed, got {:?}", other),
        }

        // Non-existent validator.
        match reg.can_stake_more(&make_id(99), 1_000, &more_hash) {
            Err(StakingError::ValidatorNotFound) => {}
            other => panic!("expected ValidatorNotFound, got {:?}", other),
        }

        // Dry-run must not mutate: used_stake_signatures should still
        // reject the initial_hash (from register), and the new
        // `more_hash` should still be eligible (not consumed by dry-run).
        assert!(reg.can_stake_more(&vid, 1_000, &more_hash).is_ok());
    }

    #[test]
    fn gamma4_can_exit_mirrors_exit_gates() {
        let mut reg = StakingRegistry::new(test_config());
        let vid = make_id(95);

        // Non-existent → ValidatorNotFound.
        match reg.can_exit(&vid) {
            Err(StakingError::ValidatorNotFound) => {}
            other => panic!("expected ValidatorNotFound, got {:?}", other),
        }

        // Register but don't activate → LOCKED → InvalidTransition.
        reg.register(
            vid,
            vec![1; 1952],
            20_000_000,
            500,
            vid,
            0,
            [vid[0]; 32],
            0,
            true,
            Some("s".into()),
            false,
        )
        .expect("register");
        match reg.can_exit(&vid) {
            Err(StakingError::InvalidTransition { from, .. }) => {
                assert_eq!(from, "LOCKED");
            }
            other => panic!("expected InvalidTransition from LOCKED, got {:?}", other),
        }

        // Activate → Active → can_exit OK.
        reg.update_score(&vid, 5000);
        reg.activate(&vid, 1).expect("activate");
        assert!(reg.can_exit(&vid).is_ok(), "ACTIVE can exit");

        // After real exit, validator is EXITING → can_exit rejects again.
        reg.exit(&vid, 2).expect("exit");
        match reg.can_exit(&vid) {
            Err(StakingError::InvalidTransition { from, .. }) => {
                assert_eq!(from, "EXITING");
            }
            other => panic!("expected InvalidTransition from EXITING, got {:?}", other),
        }
    }

    #[test]
    fn auto_activate_locked_below_min_stake_is_skipped() {
        // Pre-filter drops candidates below min_validator_stake before
        // activate() is called, so they survive as LOCKED.
        let mut reg = StakingRegistry::new(test_config());
        // Register succeeds only if stake >= min. To test the pre-filter
        // we need a validator that registered above min then had stake
        // reduced (e.g. via slash). Use insert + manual state for this.
        reg.validators.insert(
            make_id(80),
            ValidatorAccount {
                validator_id: make_id(80),
                pubkey: vec![1; 1952],
                stake_amount: 1, // well below min
                state: ValidatorState::Locked,
                registered_epoch: 0,
                activation_epoch: None,
                exit_epoch: None,
                unlock_epoch: None,
                commission_bps: 500,
                reward_address: make_id(80),
                cumulative_slashed: 0,
                last_slash_epoch: None,
                uptime_bps: 10_000,
                score: 5000,
                stake_tx_hash: [0x80; 32],
                stake_output_index: 0,
                solana_stake_verified: true,
                solana_stake_signature: Some("sig_80".into()),
                l1_stake_verified: false,
                network_address: None,
            },
        );
        reg.recompute_total();

        let activated = reg.auto_activate_locked(11);
        assert!(activated.is_empty(), "below-min candidates stay LOCKED");
        assert_eq!(reg.get(&make_id(80)).unwrap().state, ValidatorState::Locked);
    }
}
