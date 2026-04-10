//! MISAKA Validator System V2 — ADA-Style No-Slash Design
//!
//! # 5段階の制御フロー
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────┐
//! │  Level 1: 不正（DoubleSign / InvalidBlock / FraudProof）     │
//! │  → 即座に Active から除外                                     │
//! │  → Backup 上位を即昇格                                       │
//! │  → Jail + Cooldown                                           │
//! ├───────────────────────────────────────────────────────────────┤
//! │  Level 2: 極端な低稼働（uptime < 80%）                       │
//! │  → 即座に Active から除外                                     │
//! │  → Backup 上位を即昇格                                       │
//! │  → Cooldown（Jail ではない）                                  │
//! ├───────────────────────────────────────────────────────────────┤
//! │  Level 3: 通常の低稼働（uptime < 95%）                       │
//! │  → 月次評価で降格候補                                        │
//! │  → Score 低い順に最大3人入れ替え                              │
//! ├───────────────────────────────────────────────────────────────┤
//! │  Level 4: 月次更新                                            │
//! │  → 維持条件を満たさない Active を最大3人降格                  │
//! │  → Backup 上位を昇格し Active 21人を維持                     │
//! ├───────────────────────────────────────────────────────────────┤
//! │  Level 5: 元本保護                                            │
//! │  → stake は一切没収しない（ADA 方式）                        │
//! │  → 罰則は報酬減額 + スコア低下のみ                           │
//! └───────────────────────────────────────────────────────────────┘
//! ```
//!
//! # 基本思想
//!
//! 「元本を守るが、サボると得しない」チェーン。
//!
//! # バリデータ構造
//!
//! - **Active (21人固定)**: BFTコンセンサス参加。公開到達可能ノード必須。
//! - **Backup (自由参加)**: ローカルPC可。NAT配下可。outbound-only可。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

pub const ACTIVE_SET_SIZE: usize = 21;
pub const MAX_DEMOTION_PER_EPOCH: usize = 3;
pub const COOLDOWN_EPOCHS: u64 = 1;
pub const EPOCH_DURATION_SECS: u64 = 30 * 24 * 3600; // 30 days
pub const DECIMALS: u64 = 1_000_000_000;

// ── Stake Thresholds ──
pub const MIN_STAKE_ACTIVE: u64 = 10_000_000 * DECIMALS;
pub const MIN_STAKE_BACKUP: u64 = 1_000_000 * DECIMALS;
pub const MAX_EFFECTIVE_STAKE: u64 = 30_000_000 * DECIMALS;
pub const CREDIT_BASE_STAKE: u64 = 10_000_000 * DECIMALS;
pub const CREDIT_CAP: f64 = 3.0;

// ── Uptime Thresholds ──

/// Level 2: これ未満は即座に Active 除外。
pub const CRITICAL_UPTIME_THRESHOLD: f64 = 0.80;
/// Level 3: これ未満は月次で降格候補。
pub const MIN_UPTIME_ACTIVE: f64 = 0.95;
pub const MIN_UPTIME_BACKUP: f64 = 0.90;

// ── Other Active Requirements ──
pub const MIN_CONTRIBUTION_ACTIVE: f64 = 0.95;
pub const MIN_PENALTY_ACTIVE: f64 = 0.90;
pub const MIN_ACTIVE_SCORE: f64 = 0.95;
pub const MIN_CONTRIBUTION_BACKUP: f64 = 0.90;

// ── Penalty Parameters ──
pub const PENALTY_PER_TIMEOUT: f64 = 0.02;
pub const PENALTY_PER_INVALID_ACTION: f64 = 0.10;
pub const BASE_PENALTY_LOW_UPTIME: f64 = 0.5;
pub const BASE_PENALTY_NORMAL: f64 = 1.0;
pub const STAKE_FACTOR_CAP: f64 = 3.0;

// ═══════════════════════════════════════════════════════════════
//  Config
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSystemConfig {
    pub active_set_size: usize,
    pub max_demotion_per_epoch: usize,
    pub cooldown_epochs: u64,
    pub epoch_duration_secs: u64,
    pub min_stake_active: u64,
    pub min_stake_backup: u64,
    pub max_effective_stake: u64,
    pub credit_base_stake: u64,
    pub credit_cap: f64,
    pub critical_uptime_threshold: f64,
    pub min_uptime_active: f64,
    pub min_contribution_active: f64,
    pub min_penalty_active: f64,
    pub min_active_score: f64,
    pub min_uptime_backup: f64,
    pub min_contribution_backup: f64,
    pub penalty_per_timeout: f64,
    pub penalty_per_invalid_action: f64,
    pub base_penalty_low_uptime: f64,
    pub base_penalty_normal: f64,
    pub stake_factor_cap: f64,
    pub base_reward_per_epoch: u64,
}

impl Default for ValidatorSystemConfig {
    fn default() -> Self {
        Self {
            active_set_size: ACTIVE_SET_SIZE,
            max_demotion_per_epoch: MAX_DEMOTION_PER_EPOCH,
            cooldown_epochs: COOLDOWN_EPOCHS,
            epoch_duration_secs: EPOCH_DURATION_SECS,
            min_stake_active: MIN_STAKE_ACTIVE,
            min_stake_backup: MIN_STAKE_BACKUP,
            max_effective_stake: MAX_EFFECTIVE_STAKE,
            credit_base_stake: CREDIT_BASE_STAKE,
            credit_cap: CREDIT_CAP,
            critical_uptime_threshold: CRITICAL_UPTIME_THRESHOLD,
            min_uptime_active: MIN_UPTIME_ACTIVE,
            min_contribution_active: MIN_CONTRIBUTION_ACTIVE,
            min_penalty_active: MIN_PENALTY_ACTIVE,
            min_active_score: MIN_ACTIVE_SCORE,
            min_uptime_backup: MIN_UPTIME_BACKUP,
            min_contribution_backup: MIN_CONTRIBUTION_BACKUP,
            penalty_per_timeout: PENALTY_PER_TIMEOUT,
            penalty_per_invalid_action: PENALTY_PER_INVALID_ACTION,
            base_penalty_low_uptime: BASE_PENALTY_LOW_UPTIME,
            base_penalty_normal: BASE_PENALTY_NORMAL,
            stake_factor_cap: STAKE_FACTOR_CAP,
            base_reward_per_epoch: 500_000_000 * DECIMALS,
        }
    }
}

impl ValidatorSystemConfig {
    pub fn testnet() -> Self {
        Self {
            min_stake_active: 1_000_000 * DECIMALS,
            min_stake_backup: 100_000 * DECIMALS,
            epoch_duration_secs: 3600,
            critical_uptime_threshold: 0.50,
            min_uptime_active: 0.80,
            min_contribution_active: 0.80,
            min_penalty_active: 0.50,
            min_active_score: 0.50,
            min_uptime_backup: 0.70,
            min_contribution_backup: 0.70,
            base_reward_per_epoch: 1_000_000 * DECIMALS,
            ..Default::default()
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorRole {
    Active,
    Backup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionMode {
    Public,
    OutboundOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    Normal,
    Cooldown {
        until_epoch: u64,
    },
    Jailed {
        until_epoch: u64,
        reason: JailReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JailReason {
    DoubleSign,
    InvalidBlock,
    InvalidQC,
    FraudProof,
}

/// 不正行為の種類。**いずれも stake は没収しない。**
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Infraction {
    /// Level 1: 即除外 + Jail
    DoubleSign,
    InvalidBlock,
    InvalidQC,
    FraudProof,
    /// Level 3: PenaltyFactor 減少のみ
    Timeout,
    ProtocolViolation,
}

/// 即時除外の理由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImmediateRemovalReason {
    /// Level 1: 不正行為。
    Infraction(Infraction),
    /// Level 2: 極端な低稼働 (uptime < 80%)。
    CriticalUptime { uptime: u64 }, // uptime × 10000 (BPS)
}

// ═══════════════════════════════════════════════════════════════
//  Validator Account
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorAccountV2 {
    pub validator_id: [u8; 32],
    pub pubkey: Vec<u8>,
    /// **元本没収なし — この値は決して減らない。**
    pub stake_amount: u64,
    pub role: ValidatorRole,
    pub connection_mode: ConnectionMode,
    pub status: ValidatorStatus,

    // ── メトリクス ──
    pub uptime: f64,
    pub contribution: f64,
    pub timeouts: u32,
    pub invalid_actions: u32,

    // ── 計算済みスコア ──
    pub penalty_factor: f64,
    pub score: f64,

    // ── 履歴 ──
    pub registered_epoch: u64,
    pub active_since_epoch: Option<u64>,
    pub demoted_epoch: Option<u64>,
    pub cumulative_rewards: u64,
    pub reward_address: [u8; 32],

    // ── ネットワーク状態 ──
    pub public_reachable: bool,
    pub port_open: bool,
    pub inbound_consensus: bool,
    pub stable_endpoint: bool,

    pub solana_stake_verified: bool,
    pub solana_stake_signature: Option<String>,
}

impl ValidatorAccountV2 {
    /// EffectiveStake = min(stake, MAX_EFFECTIVE_STAKE)
    pub fn effective_stake(&self, config: &ValidatorSystemConfig) -> u64 {
        self.stake_amount.min(config.max_effective_stake)
    }

    /// StakeFactor = min(EffectiveStake / MIN_STAKE_ACTIVE, cap)
    pub fn stake_factor(&self, config: &ValidatorSystemConfig) -> f64 {
        if config.min_stake_active == 0 {
            return 1.0;
        }
        (self.effective_stake(config) as f64 / config.min_stake_active as f64)
            .min(config.stake_factor_cap)
    }

    /// Credit = min(stake / CREDIT_BASE_STAKE, CREDIT_CAP)
    pub fn credit(&self, config: &ValidatorSystemConfig) -> f64 {
        if config.credit_base_stake == 0 {
            return 1.0;
        }
        (self.stake_amount as f64 / config.credit_base_stake as f64).min(config.credit_cap)
    }

    /// PenaltyFactor 計算。
    pub fn compute_penalty_factor(&self, config: &ValidatorSystemConfig) -> f64 {
        let base = if self.uptime < 0.90 {
            config.base_penalty_low_uptime
        } else {
            config.base_penalty_normal
        };
        (base
            - config.penalty_per_timeout * self.timeouts as f64
            - config.penalty_per_invalid_action * self.invalid_actions as f64)
            .max(0.0)
    }

    /// Score = StakeFactor × uptime × contribution × PenaltyFactor × Credit
    pub fn compute_score(&self, config: &ValidatorSystemConfig) -> f64 {
        self.stake_factor(config)
            * self.uptime
            * self.contribution
            * self.penalty_factor
            * self.credit(config)
    }

    /// EpochReward = BaseReward × uptime × contribution × PenaltyFactor
    pub fn compute_epoch_reward(&self, base_reward: u64) -> u64 {
        (base_reward as f64 * self.uptime * self.contribution * self.penalty_factor) as u64
    }

    /// Active 維持条件（月次評価用）。
    pub fn meets_active_requirements(&self, config: &ValidatorSystemConfig) -> bool {
        self.stake_amount >= config.min_stake_active
            && self.uptime >= config.min_uptime_active
            && self.contribution >= config.min_contribution_active
            && self.penalty_factor >= config.min_penalty_active
            && self.score >= config.min_active_score
            && self.public_reachable
            && self.port_open
            && self.inbound_consensus
            && self.status == ValidatorStatus::Normal
            && self.solana_stake_verified
    }

    /// Backup として eligible か。
    pub fn is_eligible_backup(&self, config: &ValidatorSystemConfig, epoch: u64) -> bool {
        self.stake_amount >= config.min_stake_backup
            && self.uptime >= config.min_uptime_backup
            && self.contribution >= config.min_contribution_backup
            && self.solana_stake_verified
            && match self.status {
                ValidatorStatus::Normal => true,
                ValidatorStatus::Cooldown { until_epoch } => epoch >= until_epoch,
                ValidatorStatus::Jailed { until_epoch, .. } => epoch >= until_epoch,
            }
    }

    /// Backup → Active 昇格条件。
    pub fn can_promote_to_active(&self, config: &ValidatorSystemConfig, epoch: u64) -> bool {
        self.is_eligible_backup(config, epoch)
            && self.stake_amount >= config.min_stake_active
            && self.public_reachable
            && self.port_open
            && self.inbound_consensus
    }

    pub fn reset_epoch_metrics(&mut self) {
        self.timeouts = 0;
        self.invalid_actions = 0;
    }
}

// ═══════════════════════════════════════════════════════════════
//  Result Types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct InfractionResult {
    pub validator_id: [u8; 32],
    pub infraction: Infraction,
    pub reward_zeroed: bool,
    pub immediately_removed: bool,
    pub jailed: bool,
    pub new_penalty_factor: f64,
    /// 即昇格した Backup（あれば）。
    pub promoted_replacement: Option<[u8; 32]>,
}

/// Level 2 即時除外の結果。
#[derive(Debug, Clone)]
pub struct ImmediateRemovalResult {
    pub validator_id: [u8; 32],
    pub reason: ImmediateRemovalReason,
    /// 即昇格した Backup（あれば）。
    pub promoted_replacement: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct EpochUpdateResult {
    pub epoch: u64,
    pub demoted: Vec<DemotionRecord>,
    pub promoted: Vec<PromotionRecord>,
    pub rewards: Vec<RewardRecord>,
    pub active_count: usize,
    pub backup_count: usize,
}

#[derive(Debug, Clone)]
pub struct DemotionRecord {
    pub validator_id: [u8; 32],
    pub reason: DemotionReason,
    pub score: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemotionReason {
    LowUptime,
    LowContribution,
    LowPenaltyFactor,
    LowScore,
    NotReachable,
    StakeBelowMinimum,
    Jailed,
}

#[derive(Debug, Clone)]
pub struct PromotionRecord {
    pub validator_id: [u8; 32],
    pub score: f64,
}

#[derive(Debug, Clone)]
pub struct RewardRecord {
    pub validator_id: [u8; 32],
    pub amount: u64,
    pub score: f64,
}

// ═══════════════════════════════════════════════════════════════
//  Validator System V2
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSystemV2 {
    pub config: ValidatorSystemConfig,
    pub validators: HashMap<[u8; 32], ValidatorAccountV2>,
    pub current_epoch: u64,
    used_stake_signatures: std::collections::HashSet<String>,
}

impl ValidatorSystemV2 {
    pub fn new(config: ValidatorSystemConfig) -> Self {
        Self {
            config,
            validators: HashMap::new(),
            current_epoch: 0,
            used_stake_signatures: std::collections::HashSet::new(),
        }
    }

    // ── 登録 ──────────────────────────────────────────────────

    pub fn register(
        &mut self,
        validator_id: [u8; 32],
        pubkey: Vec<u8>,
        stake_amount: u64,
        reward_address: [u8; 32],
        connection_mode: ConnectionMode,
        solana_stake_verified: bool,
        solana_stake_signature: Option<String>,
    ) -> Result<(), ValidatorSystemError> {
        if self.validators.contains_key(&validator_id) {
            return Err(ValidatorSystemError::AlreadyRegistered);
        }
        if stake_amount < self.config.min_stake_backup {
            return Err(ValidatorSystemError::StakeBelowMinimum {
                deposited: stake_amount,
                minimum: self.config.min_stake_backup,
            });
        }
        if let Some(ref sig) = solana_stake_signature {
            if self.used_stake_signatures.contains(sig) {
                return Err(ValidatorSystemError::StakeSignatureAlreadyUsed {
                    signature: sig.clone(),
                });
            }
            self.used_stake_signatures.insert(sig.clone());
        }

        let is_public = connection_mode == ConnectionMode::Public;
        self.validators.insert(
            validator_id,
            ValidatorAccountV2 {
                validator_id,
                pubkey,
                stake_amount,
                role: ValidatorRole::Backup,
                connection_mode,
                status: ValidatorStatus::Normal,
                uptime: 1.0,
                contribution: 1.0,
                timeouts: 0,
                invalid_actions: 0,
                penalty_factor: 1.0,
                score: 0.0,
                registered_epoch: self.current_epoch,
                active_since_epoch: None,
                demoted_epoch: None,
                cumulative_rewards: 0,
                reward_address,
                public_reachable: is_public,
                port_open: is_public,
                inbound_consensus: is_public,
                stable_endpoint: is_public,
                solana_stake_verified,
                solana_stake_signature,
            },
        );
        Ok(())
    }

    // ── メトリクス更新 ────────────────────────────────────────

    pub fn update_uptime(&mut self, validator_id: &[u8; 32], uptime: f64) {
        if let Some(v) = self.validators.get_mut(validator_id) {
            v.uptime = uptime.clamp(0.0, 1.0);
        }
    }

    pub fn update_contribution(&mut self, validator_id: &[u8; 32], contribution: f64) {
        if let Some(v) = self.validators.get_mut(validator_id) {
            v.contribution = contribution.clamp(0.0, 1.0);
        }
    }

    pub fn update_connectivity(
        &mut self,
        validator_id: &[u8; 32],
        public_reachable: bool,
        port_open: bool,
        inbound_consensus: bool,
    ) {
        if let Some(v) = self.validators.get_mut(validator_id) {
            v.public_reachable = public_reachable;
            v.port_open = port_open;
            v.inbound_consensus = inbound_consensus;
        }
    }

    pub fn update_stake_from_solana(&mut self, validator_id: &[u8; 32], stake_amount: u64) {
        if let Some(v) = self.validators.get_mut(validator_id) {
            v.stake_amount = stake_amount;
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  Level 1: 不正 → 即除外 + Jail
    // ═══════════════════════════════════════════════════════════

    /// Level 1: 不正行為を記録し、即座に Active から除外する。
    ///
    /// **元本は一切没収しない。** 報酬ゼロ化 + Jail + Backup昇格。
    pub fn report_infraction(
        &mut self,
        validator_id: &[u8; 32],
        infraction: Infraction,
    ) -> Result<InfractionResult, ValidatorSystemError> {
        let v = self
            .validators
            .get_mut(validator_id)
            .ok_or(ValidatorSystemError::ValidatorNotFound)?;

        let mut reward_zeroed = false;
        let mut immediately_removed = false;
        let mut jailed = false;

        match infraction {
            // Level 1: 重大不正 → 即除外 + Jail
            Infraction::DoubleSign | Infraction::InvalidQC | Infraction::FraudProof => {
                v.penalty_factor = 0.0;
                v.score = 0.0;
                reward_zeroed = true;
                let reason = match infraction {
                    Infraction::DoubleSign => JailReason::DoubleSign,
                    Infraction::InvalidQC => JailReason::InvalidQC,
                    Infraction::FraudProof => JailReason::FraudProof,
                    _ => JailReason::FraudProof,
                };
                v.status = ValidatorStatus::Jailed {
                    until_epoch: self.current_epoch + self.config.cooldown_epochs + 1,
                    reason,
                };
                jailed = true;
                if v.role == ValidatorRole::Active {
                    v.role = ValidatorRole::Backup;
                    v.active_since_epoch = None;
                    v.demoted_epoch = Some(self.current_epoch);
                    immediately_removed = true;
                }
            }
            Infraction::InvalidBlock => {
                v.invalid_actions = v.invalid_actions.saturating_add(1);
                v.penalty_factor = 0.0;
                v.score = 0.0;
                reward_zeroed = true;
                v.status = ValidatorStatus::Jailed {
                    until_epoch: self.current_epoch + self.config.cooldown_epochs,
                    reason: JailReason::InvalidBlock,
                };
                jailed = true;
                if v.role == ValidatorRole::Active {
                    v.role = ValidatorRole::Backup;
                    v.active_since_epoch = None;
                    v.demoted_epoch = Some(self.current_epoch);
                    immediately_removed = true;
                }
            }
            // Level 3: 軽微 → PenaltyFactor 減少のみ（月次で降格判定）
            Infraction::Timeout => {
                v.timeouts = v.timeouts.saturating_add(1);
                v.penalty_factor = v.compute_penalty_factor(&self.config);
                v.score = v.compute_score(&self.config);
            }
            Infraction::ProtocolViolation => {
                v.invalid_actions = v.invalid_actions.saturating_add(1);
                v.penalty_factor = v.compute_penalty_factor(&self.config);
                v.score = v.compute_score(&self.config);
            }
        }

        // 即除外の場合 → Backup 上位を即昇格
        let promoted = if immediately_removed {
            self.promote_top_backup()
        } else {
            None
        };

        // 即時除外された validator のゼロ報酬は、昇格処理の再計算で戻さない。
        if immediately_removed {
            if let Some(v) = self.validators.get_mut(validator_id) {
                v.penalty_factor = 0.0;
                v.score = 0.0;
            }
        }

        Ok(InfractionResult {
            validator_id: *validator_id,
            infraction,
            reward_zeroed,
            immediately_removed,
            jailed,
            new_penalty_factor: self
                .validators
                .get(validator_id)
                .map(|v| v.penalty_factor)
                .unwrap_or(0.0),
            promoted_replacement: promoted,
        })
    }

    // ═══════════════════════════════════════════════════════════
    //  Level 2: 極端な低稼働 → 即除外
    // ═══════════════════════════════════════════════════════════

    /// Level 2: uptime < CRITICAL_UPTIME_THRESHOLD の Active を即座に除外する。
    ///
    /// ブロック生成ループまたは定期チェックから呼ばれる。
    /// 月次更新を待たず即座に除外し、Backup 上位を昇格させる。
    ///
    /// **元本は没収しない。Cooldown に移行。**
    pub fn enforce_critical_uptime(&mut self) -> Vec<ImmediateRemovalResult> {
        let threshold = self.config.critical_uptime_threshold;
        let epoch = self.current_epoch;

        // 除外対象を特定
        let to_remove: Vec<[u8; 32]> = self
            .validators
            .values()
            .filter(|v| v.role == ValidatorRole::Active && v.uptime < threshold)
            .map(|v| v.validator_id)
            .collect();

        let mut results = Vec::new();
        for id in to_remove {
            let uptime_bps = self
                .validators
                .get(&id)
                .map(|v| (v.uptime * 10000.0) as u64)
                .unwrap_or(0);

            // Active → Backup + Cooldown
            if let Some(v) = self.validators.get_mut(&id) {
                v.role = ValidatorRole::Backup;
                v.active_since_epoch = None;
                v.demoted_epoch = Some(epoch);
                v.status = ValidatorStatus::Cooldown {
                    until_epoch: epoch + self.config.cooldown_epochs,
                };
            }

            // Backup 上位を即昇格
            let promoted = self.promote_top_backup();

            results.push(ImmediateRemovalResult {
                validator_id: id,
                reason: ImmediateRemovalReason::CriticalUptime { uptime: uptime_bps },
                promoted_replacement: promoted,
            });
        }
        results
    }

    // ═══════════════════════════════════════════════════════════
    //  Level 4: 月次エポック更新
    // ═══════════════════════════════════════════════════════════

    /// 月次エポック更新。
    ///
    /// 1. 全バリデータの Score 再計算
    /// 2. Active 維持条件チェック → 降格候補抽出
    /// 3. Score 低い順に最大3人降格 → Cooldown
    /// 4. Backup 上位を昇格 → Active 21人維持
    /// 5. Active に報酬配分（uptime × contribution × PenaltyFactor に比例）
    /// 6. メトリクスリセット
    /// 7. エポック進行
    pub fn process_epoch_update(&mut self) -> EpochUpdateResult {
        let epoch = self.current_epoch;

        // ── Step 1: Score 再計算 ──
        let ids: Vec<[u8; 32]> = self.validators.keys().copied().collect();
        for id in &ids {
            if let Some(v) = self.validators.get_mut(id) {
                v.penalty_factor = v.compute_penalty_factor(&self.config);
                v.score = v.compute_score(&self.config);
            }
        }

        // ── Step 2: 降格候補抽出 ──
        let mut demotion_candidates: Vec<([u8; 32], f64, DemotionReason)> = Vec::new();
        for v in self.validators.values() {
            if v.role != ValidatorRole::Active {
                continue;
            }
            let reason = if v.stake_amount < self.config.min_stake_active {
                Some(DemotionReason::StakeBelowMinimum)
            } else if matches!(v.status, ValidatorStatus::Jailed { .. }) {
                Some(DemotionReason::Jailed)
            } else if !v.public_reachable || !v.port_open || !v.inbound_consensus {
                Some(DemotionReason::NotReachable)
            } else if v.uptime < self.config.min_uptime_active {
                Some(DemotionReason::LowUptime)
            } else if v.contribution < self.config.min_contribution_active {
                Some(DemotionReason::LowContribution)
            } else if v.penalty_factor < self.config.min_penalty_active {
                Some(DemotionReason::LowPenaltyFactor)
            } else if v.score < self.config.min_active_score {
                Some(DemotionReason::LowScore)
            } else {
                None
            };
            if let Some(r) = reason {
                demotion_candidates.push((v.validator_id, v.score, r));
            }
        }

        // ── Step 3: Score 低い順に最大3人降格 ──
        demotion_candidates.sort_by(|a, b| {
            a.1.partial_cmp(&b.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
        demotion_candidates.truncate(self.config.max_demotion_per_epoch);

        let mut demoted = Vec::new();
        for (id, score, reason) in &demotion_candidates {
            if let Some(v) = self.validators.get_mut(id) {
                v.role = ValidatorRole::Backup;
                v.active_since_epoch = None;
                v.demoted_epoch = Some(epoch);
                v.status = ValidatorStatus::Cooldown {
                    until_epoch: epoch + self.config.cooldown_epochs,
                };
                demoted.push(DemotionRecord {
                    validator_id: *id,
                    reason: *reason,
                    score: *score,
                });
            }
        }

        // ── Step 4: Backup → Active 昇格 ──
        let mut promoted = Vec::new();
        let vacancies = self
            .config
            .active_set_size
            .saturating_sub(self.active_count());
        if vacancies > 0 {
            let mut eligible: Vec<([u8; 32], f64)> = self
                .validators
                .values()
                .filter(|v| {
                    v.role == ValidatorRole::Backup && v.can_promote_to_active(&self.config, epoch)
                })
                .map(|v| (v.validator_id, v.score))
                .collect();
            eligible.sort_by(|a, b| {
                b.1.partial_cmp(&a.1)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| a.0.cmp(&b.0))
            });
            for (id, score) in eligible.into_iter().take(vacancies) {
                if let Some(v) = self.validators.get_mut(&id) {
                    v.role = ValidatorRole::Active;
                    v.active_since_epoch = Some(epoch);
                    v.connection_mode = ConnectionMode::Public;
                    v.status = ValidatorStatus::Normal;
                    promoted.push(PromotionRecord {
                        validator_id: id,
                        score,
                    });
                }
            }
        }

        // ── Step 5: 報酬配分 ──
        let active_ids: Vec<[u8; 32]> = self
            .validators
            .values()
            .filter(|v| v.role == ValidatorRole::Active)
            .map(|v| v.validator_id)
            .collect();
        let per_base = if active_ids.is_empty() {
            0
        } else {
            self.config.base_reward_per_epoch / active_ids.len() as u64
        };

        let mut rewards = Vec::new();
        for id in &active_ids {
            if let Some(v) = self.validators.get_mut(id) {
                let reward = v.compute_epoch_reward(per_base);
                v.cumulative_rewards = v.cumulative_rewards.saturating_add(reward);
                rewards.push(RewardRecord {
                    validator_id: *id,
                    amount: reward,
                    score: v.score,
                });
            }
        }

        // ── Step 6: メトリクスリセット ──
        for v in self.validators.values_mut() {
            v.reset_epoch_metrics();
        }

        // ── Step 7: エポック進行 ──
        self.current_epoch += 1;

        EpochUpdateResult {
            epoch,
            demoted,
            promoted,
            rewards,
            active_count: self.active_count(),
            backup_count: self.backup_count(),
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  Internal: Backup 上位を即昇格
    // ═══════════════════════════════════════════════════════════

    /// Backup の中から最も Score が高い eligible ノードを Active に昇格する。
    ///
    /// Level 1 (不正) / Level 2 (低稼働) での即時除外後に呼ばれる。
    /// 月次更新ではなく、リアルタイムで Active 21人を維持する。
    fn promote_top_backup(&mut self) -> Option<[u8; 32]> {
        let epoch = self.current_epoch;
        let config = self.config.clone();

        // Level 1/2 の即時除外直後でも、既に確定した penalty_factor を上書きしない。
        // 不正で 0 に落とした validator をここで再計算すると reward zeroing が壊れるため、
        // 昇格候補の比較には現在の penalty_factor を使って score だけ更新する。
        for v in self.validators.values_mut() {
            v.score = v.compute_score(&config);
        }

        let mut eligible: Vec<([u8; 32], f64)> = self
            .validators
            .values()
            .filter(|v| v.role == ValidatorRole::Backup && v.can_promote_to_active(&config, epoch))
            .map(|v| (v.validator_id, v.score))
            .collect();

        eligible.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });

        if let Some((id, _)) = eligible.first() {
            if let Some(v) = self.validators.get_mut(id) {
                v.role = ValidatorRole::Active;
                v.active_since_epoch = Some(epoch);
                v.connection_mode = ConnectionMode::Public;
                v.status = ValidatorStatus::Normal;
                return Some(*id);
            }
        }
        None
    }

    // ── クエリ ────────────────────────────────────────────────

    pub fn active_validators(&self) -> Vec<&ValidatorAccountV2> {
        let mut v: Vec<_> = self
            .validators
            .values()
            .filter(|v| v.role == ValidatorRole::Active)
            .collect();
        v.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.validator_id.cmp(&b.validator_id))
        });
        v
    }

    pub fn backup_validators(&self) -> Vec<&ValidatorAccountV2> {
        let mut v: Vec<_> = self
            .validators
            .values()
            .filter(|v| v.role == ValidatorRole::Backup)
            .collect();
        v.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.validator_id.cmp(&b.validator_id))
        });
        v
    }

    pub fn get(&self, id: &[u8; 32]) -> Option<&ValidatorAccountV2> {
        self.validators.get(id)
    }
    pub fn active_count(&self) -> usize {
        self.validators
            .values()
            .filter(|v| v.role == ValidatorRole::Active)
            .count()
    }
    pub fn backup_count(&self) -> usize {
        self.validators
            .values()
            .filter(|v| v.role == ValidatorRole::Backup)
            .count()
    }
    pub fn total_active_stake(&self) -> u64 {
        self.validators
            .values()
            .filter(|v| v.role == ValidatorRole::Active)
            .map(|v| v.effective_stake(&self.config))
            .sum()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Errors
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum ValidatorSystemError {
    #[error("validator already registered")]
    AlreadyRegistered,
    #[error("stake below minimum: deposited {deposited}, minimum {minimum}")]
    StakeBelowMinimum { deposited: u64, minimum: u64 },
    #[error("validator not found")]
    ValidatorNotFound,
    #[error("stake signature already used: {signature}")]
    StakeSignatureAlreadyUsed { signature: String },
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn id(n: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = n;
        a
    }

    fn sys() -> ValidatorSystemV2 {
        ValidatorSystemV2::new(ValidatorSystemConfig::testnet())
    }

    fn add_active(s: &mut ValidatorSystemV2, n: u8, stake: u64) {
        s.register(
            id(n),
            vec![n; 32],
            stake,
            id(n),
            ConnectionMode::Public,
            true,
            None,
        )
        .unwrap();
        let v = s.validators.get_mut(&id(n)).unwrap();
        v.role = ValidatorRole::Active;
        v.active_since_epoch = Some(0);
    }

    fn add_backup(s: &mut ValidatorSystemV2, n: u8, stake: u64) {
        s.register(
            id(n),
            vec![n; 32],
            stake,
            id(n),
            ConnectionMode::OutboundOnly,
            true,
            None,
        )
        .unwrap();
    }

    // ── Level 5: 元本保護 ──

    #[test]
    fn stake_never_reduced_on_double_sign() {
        let mut s = sys();
        add_active(&mut s, 1, 10_000_000 * DECIMALS);
        let before = s.get(&id(1)).unwrap().stake_amount;
        s.report_infraction(&id(1), Infraction::DoubleSign).unwrap();
        assert_eq!(s.get(&id(1)).unwrap().stake_amount, before); // NEVER reduced
    }

    #[test]
    fn stake_never_reduced_on_invalid_block() {
        let mut s = sys();
        add_active(&mut s, 1, 10_000_000 * DECIMALS);
        let before = s.get(&id(1)).unwrap().stake_amount;
        s.report_infraction(&id(1), Infraction::InvalidBlock)
            .unwrap();
        assert_eq!(s.get(&id(1)).unwrap().stake_amount, before);
    }

    // ── Level 1: 不正 → 即除外 ──

    #[test]
    fn double_sign_immediately_removes_and_jails() {
        let mut s = sys();
        add_active(&mut s, 1, 10_000_000 * DECIMALS);
        add_backup(&mut s, 100, 10_000_000 * DECIMALS);
        let b = s.validators.get_mut(&id(100)).unwrap();
        b.public_reachable = true;
        b.port_open = true;
        b.inbound_consensus = true;

        let r = s.report_infraction(&id(1), Infraction::DoubleSign).unwrap();
        assert!(r.immediately_removed);
        assert!(r.jailed);
        assert!(r.reward_zeroed);
        assert_eq!(r.new_penalty_factor, 0.0);
        assert_eq!(s.get(&id(1)).unwrap().role, ValidatorRole::Backup);
        // Backup promoted
        assert!(r.promoted_replacement.is_some());
    }

    // ── Level 2: 極端な低稼働 → 即除外 ──

    #[test]
    fn critical_uptime_immediately_removes() {
        let mut s = sys();
        add_active(&mut s, 1, 10_000_000 * DECIMALS);
        add_active(&mut s, 2, 10_000_000 * DECIMALS);
        s.validators.get_mut(&id(1)).unwrap().uptime = 0.30; // << 80%

        add_backup(&mut s, 100, 10_000_000 * DECIMALS);
        let b = s.validators.get_mut(&id(100)).unwrap();
        b.public_reachable = true;
        b.port_open = true;
        b.inbound_consensus = true;

        let results = s.enforce_critical_uptime();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].validator_id, id(1));
        assert_eq!(s.get(&id(1)).unwrap().role, ValidatorRole::Backup);
        assert!(matches!(
            s.get(&id(1)).unwrap().status,
            ValidatorStatus::Cooldown { .. }
        ));
        // Stake untouched
        assert_eq!(s.get(&id(1)).unwrap().stake_amount, 10_000_000 * DECIMALS);
    }

    // ── Level 3: 通常の低稼働 → 月次降格 ──

    #[test]
    fn low_uptime_demoted_at_monthly_update() {
        let mut s = sys();
        for i in 1..=21u8 {
            add_active(&mut s, i, 10_000_000 * DECIMALS);
        }
        s.validators.get_mut(&id(1)).unwrap().uptime = 0.70; // < 80% (testnet threshold)

        let r = s.process_epoch_update();
        assert!(r.demoted.iter().any(|d| d.validator_id == id(1)));
    }

    // ── Level 4: 月次更新 max 3 ──

    #[test]
    fn max_3_demotions_per_epoch() {
        let mut s = sys();
        for i in 1..=21u8 {
            add_active(&mut s, i, 10_000_000 * DECIMALS);
            s.validators.get_mut(&id(i)).unwrap().uptime = 0.30;
        }
        let r = s.process_epoch_update();
        assert!(r.demoted.len() <= 3);
    }

    #[test]
    fn backup_promoted_to_fill_vacancies() {
        let mut s = sys();
        for i in 1..=21u8 {
            add_active(&mut s, i, 10_000_000 * DECIMALS);
        }
        s.validators.get_mut(&id(1)).unwrap().uptime = 0.30;

        let bid = id(100);
        s.register(
            bid,
            vec![100; 32],
            10_000_000 * DECIMALS,
            bid,
            ConnectionMode::Public,
            true,
            None,
        )
        .unwrap();
        let b = s.validators.get_mut(&bid).unwrap();
        b.public_reachable = true;
        b.port_open = true;
        b.inbound_consensus = true;
        b.uptime = 0.99;
        b.contribution = 0.99;

        let r = s.process_epoch_update();
        assert!(r.promoted.iter().any(|p| p.validator_id == bid));
        assert_eq!(r.active_count, 21);
    }

    // ── Cooldown ──

    #[test]
    fn cooldown_blocks_immediate_repromotion() {
        let mut s = sys();
        add_active(&mut s, 1, 10_000_000 * DECIMALS);
        s.validators.get_mut(&id(1)).unwrap().uptime = 0.30;
        s.process_epoch_update();
        assert_eq!(s.get(&id(1)).unwrap().role, ValidatorRole::Backup);
        assert!(!s
            .get(&id(1))
            .unwrap()
            .can_promote_to_active(&s.config, s.current_epoch));
    }

    // ── Rewards ──

    #[test]
    fn reward_proportional_to_performance() {
        let mut s = sys();
        add_active(&mut s, 1, 10_000_000 * DECIMALS);
        add_active(&mut s, 2, 10_000_000 * DECIMALS);
        s.validators.get_mut(&id(1)).unwrap().uptime = 1.0;
        s.validators.get_mut(&id(1)).unwrap().contribution = 1.0;
        s.validators.get_mut(&id(2)).unwrap().uptime = 0.90;
        s.validators.get_mut(&id(2)).unwrap().contribution = 0.90;

        let r = s.process_epoch_update();
        let r1 = r.rewards.iter().find(|r| r.validator_id == id(1)).unwrap();
        let r2 = r.rewards.iter().find(|r| r.validator_id == id(2)).unwrap();
        assert!(r1.amount > r2.amount);
    }

    #[test]
    fn infraction_zeroes_reward() {
        let mut s = sys();
        add_active(&mut s, 1, 10_000_000 * DECIMALS);
        s.report_infraction(&id(1), Infraction::DoubleSign).unwrap();
        let reward = s.get(&id(1)).unwrap().compute_epoch_reward(1_000_000);
        assert_eq!(reward, 0);
    }

    // ── Saturation ──

    #[test]
    fn effective_stake_capped_at_saturation() {
        let mut s = sys();
        add_backup(&mut s, 1, 50_000_000 * DECIMALS);
        assert_eq!(
            s.get(&id(1)).unwrap().effective_stake(&s.config),
            s.config.max_effective_stake
        );
    }

    #[test]
    fn credit_capped() {
        let mut s = sys();
        add_backup(&mut s, 1, 100_000_000 * DECIMALS);
        assert_eq!(s.get(&id(1)).unwrap().credit(&s.config), CREDIT_CAP);
    }

    // ── Backup outbound-only ──

    #[test]
    fn backup_allows_outbound_only() {
        let mut s = sys();
        add_backup(&mut s, 1, 2_000_000 * DECIMALS);
        assert_eq!(
            s.get(&id(1)).unwrap().connection_mode,
            ConnectionMode::OutboundOnly
        );
    }
}
