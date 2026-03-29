//! Validator Registry — Active/Backup 状態管理の中枢
//!
//! # 状態機械
//!
//! ```text
//! [未登録]
//!     │ register(stake >= MIN_BACKUP, endpoint_info)
//!     ▼
//! [Backup]  ←─────────────────────────────────────────┐
//!     │ promote() — score条件 + public mode 可能        │
//!     │             cooldown なし + fraud なし           │
//!     ▼                                                │
//! [Active] ─── demote(score低 or 維持条件未達) ────────┤ (cooldown後)
//!     │        or severe_offense()                     │
//!     ▼                                                │
//! [Cooldown/Jail] ─── cooldown満了 ─────────────────────┘
//!     │ deregister()
//!     ▼
//! [退出]
//! ```
//!
//! # Active セット制約
//! - 固定 21 人
//! - 月次更新で最大 3 人降格
//! - Active はポート開放済みの公開ノードのみ
//! - 元本没収なし

use crate::p2p_mode::{NodeConnectionMode, ValidatorNetworkProfile};
use crate::validator_cooldown::{CooldownConfig, CooldownReason, CooldownRegistry};
use crate::validator_scoring::{ScoreBreakdown, ScoringConfig, ValidatorMetrics};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ─── 定数 ────────────────────────────────────────────────────────────────────

/// Active バリデータ固定人数
pub const ACTIVE_SET_SIZE: usize = 21;
/// 1エポックで降格できる最大人数
pub const MAX_DEMOTION_PER_EPOCH: usize = 3;

// ─── ValidatorRole ─────────────────────────────────────────────────────────────

/// バリデータのロール
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorRole {
    /// コンセンサス参加中 (公開ノード必須)
    Active,
    /// 昇格待機中 (ローカルPC可)
    Backup,
    /// 降格後のクールダウン/ジェイル中
    Cooldown,
}

impl ValidatorRole {
    pub fn is_active(&self) -> bool {
        matches!(self, ValidatorRole::Active)
    }
    pub fn is_backup(&self) -> bool {
        matches!(self, ValidatorRole::Backup)
    }
    pub fn is_cooldown(&self) -> bool {
        matches!(self, ValidatorRole::Cooldown)
    }
}

impl std::fmt::Display for ValidatorRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Backup => write!(f, "backup"),
            Self::Cooldown => write!(f, "cooldown"),
        }
    }
}

// ─── ValidatorRecord ──────────────────────────────────────────────────────────

/// レジストリ内の単一バリデータの全状態
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorRecord {
    /// バリデータ ID (32 bytes, canonical SHA3-256)
    pub validator_id: [u8; 32],
    /// 現在のロール
    pub role: ValidatorRole,
    /// ステーク量 (base units, 9 decimals)
    pub stake: u64,
    /// 現在エポックの稼働指標
    pub metrics: ValidatorMetrics,
    /// 最後に計算されたスコア内訳
    pub last_score: Option<ScoreBreakdown>,
    /// ネットワークプロファイル (接続モード・エンドポイント)
    pub network: ValidatorNetworkProfile,
    /// 登録エポック
    pub registered_epoch: u64,
    /// Active に昇格した回数
    pub promotion_count: u64,
    /// 降格された回数
    pub demotion_count: u64,
    /// 重大不正フラグ (double sign, fraud proof)
    pub fraud_flag: bool,
}

impl ValidatorRecord {
    pub fn new_backup(
        validator_id: [u8; 32],
        stake: u64,
        current_epoch: u64,
        network: ValidatorNetworkProfile,
    ) -> Self {
        let metrics = ValidatorMetrics {
            stake,
            uptime: 0.0,
            contribution: 0.0,
            timeouts: 0,
            invalid_actions: 0,
        };
        Self {
            validator_id,
            role: ValidatorRole::Backup,
            stake,
            metrics,
            last_score: None,
            network,
            registered_epoch: current_epoch,
            promotion_count: 0,
            demotion_count: 0,
            fraud_flag: false,
        }
    }

    /// Active 維持条件を満たしているか
    pub fn satisfies_active_requirements(
        &self,
        config: &RotationConfig,
    ) -> bool {
        self.stake >= config.scoring.min_stake_active
            && self.metrics.uptime >= config.min_uptime_active
            && self.metrics.contribution >= config.min_contribution_active
            && !self.fraud_flag
            && self.network.eligible_for_active()
            && self.last_score
                .as_ref()
                .map(|s| s.penalty_factor >= config.min_penalty_active)
                .unwrap_or(false)
    }

    /// Backup 参加条件を満たしているか
    pub fn satisfies_backup_requirements(&self, config: &RotationConfig) -> bool {
        self.stake >= config.scoring.min_stake_backup
            && self.metrics.uptime >= config.min_uptime_backup
            && self.metrics.contribution >= config.min_contribution_backup
            && !self.fraud_flag
    }
}

// ─── RotationConfig ────────────────────────────────────────────────────────────

/// 月次ローテーションのパラメータ
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationConfig {
    pub scoring: ScoringConfig,
    pub cooldown: CooldownConfig,

    // Active 維持条件
    pub min_uptime_active: f64,
    pub min_contribution_active: f64,
    pub min_penalty_active: f64,
    pub min_active_score: f64,

    // Backup 参加条件
    pub min_uptime_backup: f64,
    pub min_contribution_backup: f64,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            scoring: ScoringConfig::default(),
            cooldown: CooldownConfig::default(),
            min_uptime_active: 0.95,
            min_contribution_active: 0.95,
            min_penalty_active: 0.90,
            min_active_score: 0.95,
            min_uptime_backup: 0.90,
            min_contribution_backup: 0.90,
        }
    }
}

impl RotationConfig {
    pub fn testnet() -> Self {
        Self {
            scoring: ScoringConfig::testnet(),
            cooldown: CooldownConfig::default(),
            min_uptime_active: 0.80,
            min_contribution_active: 0.80,
            min_penalty_active: 0.70,
            min_active_score: 0.50,
            min_uptime_backup: 0.70,
            min_contribution_backup: 0.70,
        }
    }
}

// ─── ValidatorRegistry ────────────────────────────────────────────────────────

/// バリデータレジストリ — Active/Backup の全状態を管理する
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorRegistry {
    pub(crate) validators: HashMap<[u8; 32], ValidatorRecord>,
    pub(crate) cooldown: CooldownRegistry,
    /// 現在の Active セット (順序付き: index = 0 が最高スコア)
    pub(crate) active_set: Vec<[u8; 32]>,
    /// 現在のエポック番号
    pub current_epoch: u64,
    pub config: RotationConfig,
}

impl ValidatorRegistry {
    pub fn new(config: RotationConfig, initial_epoch: u64) -> Self {
        Self {
            validators: HashMap::new(),
            cooldown: CooldownRegistry::new(),
            active_set: Vec::new(),
            current_epoch: initial_epoch,
            config,
        }
    }

    // ─── 登録 / 退出 ──────────────────────────────────────────────────────

    /// Backup として新規登録する
    ///
    /// # Errors
    /// - stake が MIN_STAKE_BACKUP 未満
    /// - 既に登録済み
    pub fn register(
        &mut self,
        validator_id: [u8; 32],
        stake: u64,
        network: ValidatorNetworkProfile,
    ) -> Result<(), RegistryError> {
        if self.validators.contains_key(&validator_id) {
            return Err(RegistryError::AlreadyRegistered(validator_id));
        }
        if stake < self.config.scoring.min_stake_backup {
            return Err(RegistryError::StakeTooLow {
                provided: stake,
                required: self.config.scoring.min_stake_backup,
            });
        }

        let record = ValidatorRecord::new_backup(
            validator_id,
            stake,
            self.current_epoch,
            network,
        );
        self.validators.insert(validator_id, record);
        tracing::info!(
            "ValidatorRegistry: registered {} as Backup (stake={})",
            hex::encode(validator_id),
            stake
        );
        Ok(())
    }

    /// バリデータを退出させる (stake は返還)
    pub fn deregister(&mut self, validator_id: &[u8; 32]) -> Result<u64, RegistryError> {
        let record = self
            .validators
            .remove(validator_id)
            .ok_or(RegistryError::NotFound(*validator_id))?;

        // Active だった場合、Active セットから除外
        self.active_set.retain(|id| id != validator_id);

        tracing::info!(
            "ValidatorRegistry: deregistered {} (role={} stake={})",
            hex::encode(validator_id),
            record.role,
            record.stake
        );
        Ok(record.stake)
    }

    /// バリデーターに追加ステークを積む。
    ///
    /// `ValidatorStakeTx::StakeMore` が finalized されたときに呼ぶ。
    /// stake が増えることでスコアが上がり、Active セット入りが近くなる。
    ///
    /// # 制約
    /// - Cooldown 状態でも受け付ける（ステーク増はいつでも可）
    /// - `additional_amount` は ValidatorStakeTx::net_stake_amount() を使うこと
    pub fn add_stake(
        &mut self,
        validator_id: &[u8; 32],
        additional_amount: u64,
    ) -> Result<u64, RegistryError> {
        if additional_amount == 0 {
            return Err(RegistryError::StakeTooLow { provided: 0, required: 1 });
        }
        let record = self
            .validators
            .get_mut(validator_id)
            .ok_or(RegistryError::NotFound(*validator_id))?;

        let new_stake = record
            .stake
            .checked_add(additional_amount)
            .ok_or(RegistryError::StakeOverflow)?;

        record.stake = new_stake;
        // metrics も更新（スコア再計算のため）
        record.metrics.stake = new_stake;

        tracing::info!(
            "ValidatorRegistry: add_stake {} additional={} new_total={}",
            hex::encode(validator_id),
            additional_amount,
            new_stake
        );
        Ok(new_stake)
    }

    // ─── 指標更新 ──────────────────────────────────────────────────────────

    /// 各バリデータの指標を更新し、スコアを再計算する
    pub fn update_metrics(
        &mut self,
        validator_id: &[u8; 32],
        metrics: ValidatorMetrics,
    ) -> Result<ScoreBreakdown, RegistryError> {
        let record = self
            .validators
            .get_mut(validator_id)
            .ok_or(RegistryError::NotFound(*validator_id))?;

        record.stake = metrics.stake;
        record.metrics = metrics.clone();

        let breakdown =
            crate::validator_scoring::compute_score(&metrics, &self.config.scoring);
        record.last_score = Some(breakdown.clone());
        Ok(breakdown)
    }

    // ─── 重大不正 ──────────────────────────────────────────────────────────

    /// 重大不正 (double sign / fraud) を処理する
    ///
    /// - stake 没収なし
    /// - 即時 Active から除外
    /// - 報酬ゼロ
    /// - jail 状態へ移行
    pub fn handle_severe_offense(
        &mut self,
        validator_id: [u8; 32],
        reason: CooldownReason,
    ) -> Result<(), RegistryError> {
        let record = self
            .validators
            .get_mut(&validator_id)
            .ok_or(RegistryError::NotFound(validator_id))?;

        record.fraud_flag = true;
        record.role = ValidatorRole::Cooldown;
        self.active_set.retain(|id| *id != validator_id);
        self.cooldown
            .enter_cooldown(validator_id, self.current_epoch, reason, &self.config.cooldown);

        tracing::warn!(
            "ValidatorRegistry: SEVERE OFFENSE — {} jailed for {:?}",
            hex::encode(validator_id),
            reason
        );
        Ok(())
    }

    // ─── クエリ ────────────────────────────────────────────────────────────

    pub fn get(&self, validator_id: &[u8; 32]) -> Option<&ValidatorRecord> {
        self.validators.get(validator_id)
    }

    pub fn active_set(&self) -> &[[u8; 32]] {
        &self.active_set
    }

    pub fn active_count(&self) -> usize {
        self.active_set.len()
    }

    pub fn is_active(&self, validator_id: &[u8; 32]) -> bool {
        self.active_set.contains(validator_id)
    }

    pub fn is_in_cooldown(&self, validator_id: &[u8; 32]) -> bool {
        self.cooldown.is_in_cooldown(validator_id, self.current_epoch)
    }

    /// Backup バリデータを Score 降順で返す (昇格候補リスト)
    pub fn ranked_backup_candidates(&self) -> Vec<(&ValidatorRecord, f64)> {
        let mut candidates: Vec<_> = self
            .validators
            .values()
            .filter(|r| r.role.is_backup())
            .filter(|r| !self.cooldown.is_in_cooldown(&r.validator_id, self.current_epoch))
            .filter(|r| r.satisfies_backup_requirements(&self.config))
            .map(|r| {
                let score = r.last_score.as_ref().map(|s| s.score).unwrap_or(0.0);
                (r, score)
            })
            .collect();

        // score 降順でソート (同スコアは validator_id の辞書順で決定論的に)
        candidates.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.validator_id.cmp(&b.0.validator_id))
        });
        candidates
    }

    /// 現在の Active バリデータの (record, score) リストを Score 昇順で返す
    /// (降格時にスコアが低い順に最大 3 人を選ぶため昇順)
    pub fn active_by_score_ascending(&self) -> Vec<(&ValidatorRecord, f64)> {
        let mut actives: Vec<_> = self
            .active_set
            .iter()
            .filter_map(|id| self.validators.get(id))
            .map(|r| {
                let score = r.last_score.as_ref().map(|s| s.score).unwrap_or(0.0);
                (r, score)
            })
            .collect();

        actives.sort_by(|a, b| {
            a.1.partial_cmp(&b.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.validator_id.cmp(&b.0.validator_id))
        });
        actives
    }

    /// Active セットを直接設定する (genesis / snapshot 復元用)
    pub fn set_active_set(&mut self, active_ids: Vec<[u8; 32]>) {
        for id in &active_ids {
            if let Some(record) = self.validators.get_mut(id) {
                record.role = ValidatorRole::Active;
            }
        }
        self.active_set = active_ids;
    }
}

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("validator not found: {}", hex::encode(.0))]
    NotFound([u8; 32]),
    #[error("validator already registered: {}", hex::encode(.0))]
    AlreadyRegistered([u8; 32]),
    #[error("stake too low: provided={provided}, required={required}")]
    StakeTooLow { provided: u64, required: u64 },
    #[error("active set already full ({ACTIVE_SET_SIZE})")]
    ActiveSetFull,
    #[error("validator is in cooldown")]
    InCooldown,
    #[error("validator cannot switch to public mode")]
    CannotGoPublic,
    #[error("stake amount overflow (u64)")]
    StakeOverflow,
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::p2p_mode::*;

    fn make_id(n: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    fn make_registry() -> ValidatorRegistry {
        ValidatorRegistry::new(RotationConfig::testnet(), 0)
    }

    fn backup_profile(id: u8) -> ValidatorNetworkProfile {
        ValidatorNetworkProfile::new_backup(make_id(id))
    }

    fn public_profile(id: u8) -> ValidatorNetworkProfile {
        let ep = ActiveEndpointInfo {
            endpoint: format!("10.0.0.{}", id),
            port: 6690,
            reachability_verified: true,
            last_verified_ms: 1_700_000_000_000,
        };
        let mut p = ValidatorNetworkProfile::new_public(make_id(id), ep);
        p.requirements.public_reachable = true;
        p
    }

    fn good_metrics(stake: u64) -> ValidatorMetrics {
        ValidatorMetrics {
            stake,
            uptime: 0.99,
            contribution: 0.99,
            timeouts: 0,
            invalid_actions: 0,
        }
    }

    #[test]
    fn register_backup_ok() {
        let mut reg = make_registry();
        let stake = reg.config.scoring.min_stake_backup;
        reg.register(make_id(1), stake, backup_profile(1)).expect("ok");
        assert!(reg.get(&make_id(1)).is_some());
    }

    #[test]
    fn register_below_min_stake_rejected() {
        let mut reg = make_registry();
        let result = reg.register(make_id(1), 0, backup_profile(1));
        assert!(matches!(result, Err(RegistryError::StakeTooLow { .. })));
    }

    #[test]
    fn duplicate_registration_rejected() {
        let mut reg = make_registry();
        let stake = reg.config.scoring.min_stake_backup;
        reg.register(make_id(1), stake, backup_profile(1)).expect("ok");
        let result = reg.register(make_id(1), stake, backup_profile(1));
        assert!(matches!(result, Err(RegistryError::AlreadyRegistered(_))));
    }

    #[test]
    fn metrics_update_computes_score() {
        let mut reg = make_registry();
        let stake = reg.config.scoring.min_stake_active;
        reg.register(make_id(1), stake, public_profile(1)).expect("ok");
        let breakdown = reg
            .update_metrics(&make_id(1), good_metrics(stake))
            .expect("ok");
        assert!(breakdown.score > 0.0);
    }

    #[test]
    fn severe_offense_removes_from_active() {
        let mut reg = make_registry();
        let stake = reg.config.scoring.min_stake_active;
        reg.register(make_id(1), stake, public_profile(1)).expect("ok");
        reg.active_set.push(make_id(1));
        reg.validators.get_mut(&make_id(1)).unwrap().role = ValidatorRole::Active;

        reg.handle_severe_offense(make_id(1), CooldownReason::DoubleSign)
            .expect("ok");

        assert!(!reg.is_active(&make_id(1)));
        assert!(reg.is_in_cooldown(&make_id(1)));
        assert!(reg.get(&make_id(1)).unwrap().fraud_flag);
    }

    #[test]
    fn backup_candidates_sorted_by_score() {
        let mut reg = make_registry();
        let stake = reg.config.scoring.min_stake_backup;

        // 3人登録して異なる uptime を設定
        for i in 1u8..=3 {
            reg.register(make_id(i), stake, backup_profile(i)).expect("ok");
            let m = ValidatorMetrics {
                stake,
                uptime: 0.7 + i as f64 * 0.05,
                contribution: 0.90,
                timeouts: 0,
                invalid_actions: 0,
            };
            reg.update_metrics(&make_id(i), m).expect("ok");
        }

        let ranked = reg.ranked_backup_candidates();
        // スコア降順であることを確認
        for w in ranked.windows(2) {
            assert!(w[0].1 >= w[1].1);
        }
    }

    #[test]
    fn active_count_matches_set() {
        let mut reg = make_registry();
        let stake = reg.config.scoring.min_stake_active;
        reg.register(make_id(1), stake, public_profile(1)).expect("ok");
        reg.register(make_id(2), stake, public_profile(2)).expect("ok");
        reg.set_active_set(vec![make_id(1), make_id(2)]);
        assert_eq!(reg.active_count(), 2);
    }

    #[test]
    fn deregister_removes_from_active() {
        let mut reg = make_registry();
        let stake = reg.config.scoring.min_stake_active;
        reg.register(make_id(1), stake, public_profile(1)).expect("ok");
        reg.set_active_set(vec![make_id(1)]);
        assert_eq!(reg.active_count(), 1);

        reg.deregister(&make_id(1)).expect("ok");
        assert_eq!(reg.active_count(), 0);
        assert!(reg.get(&make_id(1)).is_none());
    }

    #[test]
    fn backup_profile_not_eligible_for_active() {
        let profile = ValidatorNetworkProfile::new_backup(make_id(9));
        assert!(!profile.eligible_for_active());
    }
}
