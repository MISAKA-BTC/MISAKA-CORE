//! Epoch Rotation — 月次バリデータ入れ替えアルゴリズム
//!
//! # アルゴリズム概要
//!
//! 毎月1回、以下の順序で Active セットを更新する：
//!
//! ```text
//! Step 1: 全 Active の Score_i を計算
//! Step 2: 維持条件未達の Active を抽出
//! Step 3: Score 昇順で最大3人を降格対象に選定
//! Step 4: 降格対象を Active から除外し cooldown へ
//! Step 5: Backup から eligible なノードを抽出
//! Step 6: eligible Backup を Score 降順でランク付け
//! Step 7: 上位から Active 接続条件を満たすものを昇格
//! Step 8: Active を常に21人に保つ
//! ```
//!
//! # 決定論性の保証
//!
//! スコアが同値のバリデータが複数いる場合、`validator_id` の辞書順で
//! タイブレークを行い、全ノードが同一の結果を得る。
//!
//! # 元本没収なし
//!
//! 降格・cooldown 中もステーク量は変わらない。
//! 制裁は「報酬減額」「スコア低下」「Active 資格喪失」のみ。

use crate::validator_cooldown::CooldownReason;
use crate::validator_registry::{
    RotationConfig, ValidatorRecord, ValidatorRegistry, ValidatorRole, ACTIVE_SET_SIZE,
    MAX_DEMOTION_PER_EPOCH,
};
use serde::{Deserialize, Serialize};

// ─── RotationResult ────────────────────────────────────────────────────────────

/// 月次ローテーションの実行結果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationResult {
    /// エポック番号
    pub epoch: u64,
    /// 降格されたバリデータの一覧 (id + スコア)
    pub demoted: Vec<DemotionRecord>,
    /// 昇格されたバリデータの一覧 (id + スコア)
    pub promoted: Vec<PromotionRecord>,
    /// ローテーション後の Active セット
    pub new_active_set: Vec<[u8; 32]>,
    /// Active セットの人数 (常に ACTIVE_SET_SIZE を目標とする)
    pub active_count: usize,
    /// スキップされた昇格候補の数 (接続条件未達など)
    pub skipped_candidates: usize,
}

/// 降格記録
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemotionRecord {
    pub validator_id: [u8; 32],
    pub score: f64,
    pub reason: DemotionReason,
}

/// 昇格記録
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionRecord {
    pub validator_id: [u8; 32],
    pub score: f64,
    pub previous_role: String,
}

/// 降格の理由
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DemotionReason {
    /// スコアが最低基準未満
    ScoreTooLow,
    /// Uptime が基準未満
    UptimeTooLow,
    /// Contribution が基準未満
    ContributionTooLow,
    /// ペナルティ係数が基準未満
    PenaltyTooHigh,
    /// ステーク不足
    StakeTooLow,
    /// 公開接続要件未達
    NetworkRequirementFailed,
    /// 重大不正による即時除外
    SevereOffense,
}

// ─── EpochRotationEngine ──────────────────────────────────────────────────────

/// 月次ローテーションのエンジン。
/// `ValidatorRegistry` への参照を受け取り、入れ替えを実行する。
pub struct EpochRotationEngine<'a> {
    registry: &'a mut ValidatorRegistry,
}

impl<'a> EpochRotationEngine<'a> {
    pub fn new(registry: &'a mut ValidatorRegistry) -> Self {
        Self { registry }
    }

    /// エポック開始時に呼ぶ。クールダウンの GC を行う。
    pub fn begin_epoch(&mut self, epoch: u64) {
        self.registry.current_epoch = epoch;
        self.registry.cooldown.gc_expired(epoch);
    }

    /// 月次ローテーションを実行する。
    ///
    /// # Returns
    /// `RotationResult` — 降格・昇格・新 Active セットの詳細
    pub fn run_rotation(&mut self) -> RotationResult {
        let epoch = self.registry.current_epoch;
        let config = self.registry.config.clone();

        // ── Step 1-2: 維持条件未達の Active を抽出 ──────────────────────
        let demotion_candidates: Vec<([u8; 32], f64, DemotionReason)> = {
            let actives = self.registry.active_by_score_ascending();
            actives
                .iter()
                .filter_map(|(record, score)| {
                    self.demotion_reason(record, &config)
                        .map(|reason| (record.validator_id, *score, reason))
                })
                .collect()
        };

        // ── Step 3: Score 昇順で最大 MAX_DEMOTION_PER_EPOCH 人を選定 ──
        let to_demote: Vec<([u8; 32], f64, DemotionReason)> = demotion_candidates
            .into_iter()
            .take(MAX_DEMOTION_PER_EPOCH)
            .collect();

        // ── Step 4: 降格実行 ─────────────────────────────────────────────
        let mut demoted_records = Vec::new();
        for (id, score, reason) in &to_demote {
            if let Some(record) = self.registry.validators.get_mut(id) {
                record.role = ValidatorRole::Backup;
                record.demotion_count += 1;
            }
            self.registry.active_set.retain(|active_id| active_id != id);
            self.registry.cooldown.enter_cooldown(
                *id,
                epoch,
                CooldownReason::Demotion,
                &config.cooldown,
            );
            demoted_records.push(DemotionRecord {
                validator_id: *id,
                score: *score,
                reason: reason.clone(),
            });
            tracing::info!(
                "EpochRotation[{}]: demoted {} (score={:.3}, reason={:?})",
                epoch,
                hex::encode(id),
                score,
                reason
            );
        }

        // ── Step 5-7: Backup からの昇格 ──────────────────────────────────
        let slots_available = ACTIVE_SET_SIZE.saturating_sub(self.registry.active_set.len());
        let mut promoted_records = Vec::new();
        let mut skipped = 0usize;

        if slots_available > 0 {
            let candidates: Vec<([u8; 32], f64)> = self
                .registry
                .ranked_backup_candidates()
                .iter()
                .map(|(r, s)| (r.validator_id, *s))
                .collect();

            for (id, score) in candidates {
                if promoted_records.len() >= slots_available {
                    break;
                }

                // Active 接続条件チェック
                let network_ok = self
                    .registry
                    .validators
                    .get(&id)
                    .map(|r| r.network.can_promote_to_active())
                    .unwrap_or(false);

                if !network_ok {
                    skipped += 1;
                    tracing::debug!(
                        "EpochRotation[{}]: skipped {} — cannot switch to public mode",
                        epoch,
                        hex::encode(id)
                    );
                    continue;
                }

                // 昇格実行
                if let Some(record) = self.registry.validators.get_mut(&id) {
                    record.role = ValidatorRole::Active;
                    record.promotion_count += 1;
                }
                self.registry.active_set.push(id);
                promoted_records.push(PromotionRecord {
                    validator_id: id,
                    score,
                    previous_role: "backup".to_string(),
                });
                tracing::info!(
                    "EpochRotation[{}]: promoted {} (score={:.3})",
                    epoch,
                    hex::encode(id),
                    score
                );
            }
        }

        // ── Step 8: Active セットの整合性確認 ───────────────────────────
        let active_count = self.registry.active_set.len();
        if active_count < ACTIVE_SET_SIZE {
            tracing::warn!(
                "EpochRotation[{}]: Active set has only {} / {} validators",
                epoch,
                active_count,
                ACTIVE_SET_SIZE
            );
        }

        RotationResult {
            epoch,
            demoted: demoted_records,
            promoted: promoted_records,
            new_active_set: self.registry.active_set.clone(),
            active_count,
            skipped_candidates: skipped,
        }
    }

    // ─── Helpers ──────────────────────────────────────────────────────────

    /// Active が維持条件を満たしていない場合、降格理由を返す。
    /// 満たしている場合は `None`。
    fn demotion_reason(
        &self,
        record: &ValidatorRecord,
        config: &RotationConfig,
    ) -> Option<DemotionReason> {
        // 重大不正フラグ（severe_offense は別途 handle_severe_offense で処理済みだが念のため）
        if record.fraud_flag {
            return Some(DemotionReason::SevereOffense);
        }

        // ステーク不足
        if record.stake < config.scoring.min_stake_active {
            return Some(DemotionReason::StakeTooLow);
        }

        // Uptime 不足
        if record.metrics.uptime < config.min_uptime_active {
            return Some(DemotionReason::UptimeTooLow);
        }

        // Contribution 不足
        if record.metrics.contribution < config.min_contribution_active {
            return Some(DemotionReason::ContributionTooLow);
        }

        // ペナルティ係数不足
        let penalty_ok = record
            .last_score
            .as_ref()
            .map(|s| s.penalty_factor >= config.min_penalty_active)
            .unwrap_or(false);
        if !penalty_ok {
            return Some(DemotionReason::PenaltyTooHigh);
        }

        // スコア不足
        let score_ok = record
            .last_score
            .as_ref()
            .map(|s| s.score >= config.min_active_score)
            .unwrap_or(false);
        if !score_ok {
            return Some(DemotionReason::ScoreTooLow);
        }

        // 公開接続要件未達
        if !record.network.eligible_for_active() {
            return Some(DemotionReason::NetworkRequirementFailed);
        }

        None // 維持条件を満たしている
    }
}

// ─── RewardDistributor ────────────────────────────────────────────────────────

/// エポック報酬の計算と分配。
///
/// ```text
/// EpochReward_i = BaseReward_i × uptime_i × contribution_i × PenaltyFactor_i
/// ```
///
/// - 降格中・cooldown 中は報酬ゼロ
/// - Backup は Active の報酬の一定割合を受け取る
#[derive(Debug, Clone)]
pub struct RewardDistributor {
    /// 1エポック全体のベース報酬 (base units)
    pub epoch_base_reward: u64,
    /// Backup が Active に対して受け取る報酬比率 (0.0 - 1.0)
    pub backup_reward_ratio: f64,
}

impl Default for RewardDistributor {
    fn default() -> Self {
        Self {
            epoch_base_reward: 1_000_000_000_000_000, // 1M MISAKA per epoch total
            backup_reward_ratio: 0.3,                 // Backup は Active の 30%
        }
    }
}

impl RewardDistributor {
    /// バリデータの報酬を計算する
    ///
    /// # Arguments
    /// - `record`:     バリデータレコード
    /// - `scoring`:    スコア設定
    /// - `is_active`:  Active か Backup か
    pub fn compute_reward(
        &self,
        record: &ValidatorRecord,
        _scoring: &crate::validator_scoring::ScoringConfig,
        is_active: bool,
    ) -> u64 {
        // cooldown 中・重大不正は報酬ゼロ
        if record.role.is_cooldown() || record.fraud_flag {
            return 0;
        }

        let base = if is_active {
            // Active 1人あたりのベース報酬 (equal share)
            self.epoch_base_reward / ACTIVE_SET_SIZE as u64
        } else {
            // Backup はより少ない
            (self.epoch_base_reward / ACTIVE_SET_SIZE as u64)
                * (self.backup_reward_ratio * 1000.0) as u64
                / 1000
        };

        // penalty_factor を取得
        let penalty_factor = record
            .last_score
            .as_ref()
            .map(|s| s.penalty_factor)
            .unwrap_or(0.0);

        // EpochReward = base × uptime × contribution × penalty
        let reward_f = base as f64
            * record.metrics.uptime.clamp(0.0, 1.0)
            * record.metrics.contribution.clamp(0.0, 1.0)
            * penalty_factor.clamp(0.0, 1.0);

        reward_f as u64
    }

    /// 全バリデータの報酬を一括計算する
    pub fn compute_all_rewards(&self, registry: &ValidatorRegistry) -> Vec<([u8; 32], u64)> {
        registry
            .validators
            .values()
            .map(|record| {
                let is_active = registry.is_active(&record.validator_id);
                let reward = self.compute_reward(record, &registry.config.scoring, is_active);
                (record.validator_id, reward)
            })
            .collect()
    }
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::p2p_mode::*;
    use crate::validator_registry::RotationConfig;
    use crate::validator_scoring::ValidatorMetrics;

    fn make_id(n: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = n;
        id
    }

    fn public_profile(id: u8) -> ValidatorNetworkProfile {
        let ep = ActiveEndpointInfo {
            endpoint: format!("10.0.0.{}", id),
            port: 6690,
            reachability_verified: true,
            last_verified_ms: 0,
        };
        let mut p = ValidatorNetworkProfile::new_public(make_id(id), ep);
        p.requirements.public_reachable = true;
        p
    }

    fn backup_profile(id: u8) -> ValidatorNetworkProfile {
        ValidatorNetworkProfile::new_backup(make_id(id))
    }

    fn good_active_metrics(stake: u64) -> ValidatorMetrics {
        ValidatorMetrics {
            stake,
            uptime: 0.99,
            contribution: 0.99,
            timeouts: 0,
            invalid_actions: 0,
        }
    }

    fn bad_metrics(stake: u64) -> ValidatorMetrics {
        ValidatorMetrics {
            stake,
            uptime: 0.50,
            contribution: 0.50,
            timeouts: 10,
            invalid_actions: 2,
        }
    }

    /// 21人の Active + N人の Backup を持つレジストリを作成
    fn make_full_registry(n_backup: u8) -> ValidatorRegistry {
        let config = RotationConfig::testnet();
        let min_active = config.scoring.min_stake_active;
        let min_backup = config.scoring.min_stake_backup;
        let mut reg = ValidatorRegistry::new(config, 0);

        // Active 21人
        let mut active_ids = Vec::new();
        for i in 1u8..=21 {
            reg.register(make_id(i), min_active, public_profile(i))
                .expect("ok");
            reg.update_metrics(&make_id(i), good_active_metrics(min_active))
                .expect("ok");
            active_ids.push(make_id(i));
        }
        reg.set_active_set(active_ids);

        // Backup N人 (全員 outbound-only)
        for i in 22u8..22 + n_backup {
            reg.register(make_id(i), min_backup, backup_profile(i))
                .expect("ok");
            reg.update_metrics(&make_id(i), good_active_metrics(min_backup))
                .expect("ok");
        }

        reg
    }

    #[test]
    fn rotation_no_demotion_when_all_healthy() {
        let mut reg = make_full_registry(3);
        let mut engine = EpochRotationEngine::new(&mut reg);
        engine.begin_epoch(1);
        let result = engine.run_rotation();

        assert_eq!(result.demoted.len(), 0);
        assert_eq!(result.active_count, ACTIVE_SET_SIZE);
    }

    #[test]
    fn rotation_demotes_low_scorers_max_3() {
        let config = RotationConfig::testnet();
        let min_active = config.scoring.min_stake_active;
        let mut reg = ValidatorRegistry::new(config, 0);

        // 21人 Active 登録、うち5人は悪い指標
        let mut active_ids = Vec::new();
        for i in 1u8..=21 {
            reg.register(make_id(i), min_active, public_profile(i))
                .expect("ok");
            let metrics = if i <= 5 {
                bad_metrics(min_active)
            } else {
                good_active_metrics(min_active)
            };
            reg.update_metrics(&make_id(i), metrics).expect("ok");
            active_ids.push(make_id(i));
        }
        reg.set_active_set(active_ids);

        let mut engine = EpochRotationEngine::new(&mut reg);
        engine.begin_epoch(1);
        let result = engine.run_rotation();

        // 悪い指標は5人いるが、最大3人しか降格されない
        assert!(result.demoted.len() <= MAX_DEMOTION_PER_EPOCH);
        assert_eq!(result.demoted.len(), 3);
    }

    #[test]
    fn rotation_promotes_public_backup_over_local() {
        let config = RotationConfig::testnet();
        let min_active = config.scoring.min_stake_active;
        let min_backup = config.scoring.min_stake_backup;
        let mut reg = ValidatorRegistry::new(config, 0);

        // 20人 Active (1人欠員)
        let mut active_ids = Vec::new();
        for i in 1u8..=20 {
            reg.register(make_id(i), min_active, public_profile(i))
                .expect("ok");
            reg.update_metrics(&make_id(i), good_active_metrics(min_active))
                .expect("ok");
            active_ids.push(make_id(i));
        }
        reg.set_active_set(active_ids);

        // Backup 2人: 1人は public (昇格可能)、1人は outbound-only
        reg.register(make_id(30), min_backup * 2, public_profile(30))
            .expect("ok");
        reg.update_metrics(&make_id(30), good_active_metrics(min_backup * 2))
            .expect("ok");

        reg.register(make_id(31), min_backup * 3, backup_profile(31))
            .expect("ok"); // より高スコア
        reg.update_metrics(&make_id(31), good_active_metrics(min_backup * 3))
            .expect("ok");

        let mut engine = EpochRotationEngine::new(&mut reg);
        engine.begin_epoch(1);
        let result = engine.run_rotation();

        // id 31 はスコアが高いが public mode 不可なので昇格できない
        // id 30 が昇格するはず
        assert_eq!(result.promoted.len(), 1);
        assert_eq!(result.promoted[0].validator_id, make_id(30));
        assert_eq!(result.skipped_candidates, 1); // id 31 はスキップ
    }

    #[test]
    fn active_set_always_21_when_enough_backups() {
        let config = RotationConfig::testnet();
        let min_active = config.scoring.min_stake_active;
        let min_backup = config.scoring.min_stake_backup;
        let mut reg = ValidatorRegistry::new(config, 0);

        // 21人 Active (うち3人が降格対象)
        let mut active_ids = Vec::new();
        for i in 1u8..=21 {
            reg.register(make_id(i), min_active, public_profile(i))
                .expect("ok");
            let m = if i <= 3 {
                bad_metrics(min_active)
            } else {
                good_active_metrics(min_active)
            };
            reg.update_metrics(&make_id(i), m).expect("ok");
            active_ids.push(make_id(i));
        }
        reg.set_active_set(active_ids);

        // 公開接続の Backup 3人
        for i in 22u8..=24 {
            reg.register(make_id(i), min_backup, public_profile(i))
                .expect("ok");
            reg.update_metrics(&make_id(i), good_active_metrics(min_backup))
                .expect("ok");
        }

        let mut engine = EpochRotationEngine::new(&mut reg);
        engine.begin_epoch(1);
        let result = engine.run_rotation();

        assert_eq!(result.active_count, ACTIVE_SET_SIZE);
    }

    #[test]
    fn demoted_enters_cooldown() {
        let config = RotationConfig::testnet();
        let min_active = config.scoring.min_stake_active;
        let mut reg = ValidatorRegistry::new(config, 0);

        reg.register(make_id(1), min_active, public_profile(1))
            .expect("ok");
        reg.update_metrics(&make_id(1), bad_metrics(min_active))
            .expect("ok");
        reg.set_active_set(vec![make_id(1)]);

        let mut engine = EpochRotationEngine::new(&mut reg);
        engine.begin_epoch(5);
        engine.run_rotation();

        assert!(reg.is_in_cooldown(&make_id(1)));
    }

    #[test]
    fn reward_zero_during_cooldown() {
        let config = RotationConfig::testnet();
        let min_active = config.scoring.min_stake_active;
        let mut reg = ValidatorRegistry::new(config.clone(), 0);

        reg.register(make_id(1), min_active, backup_profile(1))
            .expect("ok");
        reg.update_metrics(&make_id(1), good_active_metrics(min_active))
            .expect("ok");
        // クールダウンに入れる
        reg.validators.get_mut(&make_id(1)).unwrap().role = ValidatorRole::Cooldown;

        let distributor = RewardDistributor::default();
        let record = reg.get(&make_id(1)).unwrap().clone();
        let reward = distributor.compute_reward(&record, &config.scoring, false);
        assert_eq!(reward, 0);
    }

    #[test]
    fn reward_nonzero_for_good_active() {
        let config = RotationConfig::testnet();
        let min_active = config.scoring.min_stake_active;
        let mut reg = ValidatorRegistry::new(config.clone(), 0);

        reg.register(make_id(1), min_active, public_profile(1))
            .expect("ok");
        reg.update_metrics(&make_id(1), good_active_metrics(min_active))
            .expect("ok");
        reg.validators.get_mut(&make_id(1)).unwrap().role = ValidatorRole::Active;

        let distributor = RewardDistributor::default();
        let record = reg.get(&make_id(1)).unwrap().clone();
        let reward = distributor.compute_reward(&record, &config.scoring, true);
        assert!(reward > 0);
    }
}
