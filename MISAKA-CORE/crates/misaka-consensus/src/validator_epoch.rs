//! Validator Epoch Rotation — monthly Active set update.
//!
//! # Monthly Update Process (every 30 days)
//!
//! 1. Compute Score_i for all 21 Active validators
//! 2. Identify Active validators failing maintenance criteria
//! 3. Demote at most 3 (worst scores first)
//! 4. Place demoted validators in cooldown
//! 5. From eligible Backup validators (not in cooldown), select top scorers
//! 6. Promote them to Active to fill vacancies
//! 7. Active set always stays at 21 (or fewer if not enough Backup)

use serde::{Deserialize, Serialize};

use super::validator_cooldown::{CooldownConfig, CooldownReason, CooldownRegistry};
use super::validator_scoring::{ScoringConfig, ValidatorMetrics, ScoreBreakdown, compute_score};

// ═══════════════════════════════════════════════════════════════
//  Configuration
// ═══════════════════════════════════════════════════════════════

/// Epoch rotation parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochConfig {
    /// Fixed number of Active validators.
    pub active_set_size: usize,
    /// Maximum validators to demote per epoch.
    pub max_demotion_per_epoch: usize,
    /// Epoch duration in seconds (30 days = 2_592_000).
    pub epoch_duration_secs: u64,

    // ── Active maintenance thresholds ──
    pub min_uptime_active: f64,
    pub min_contribution_active: f64,
    pub min_penalty_active: f64,
    pub min_active_score: f64,

    // ── Backup eligibility thresholds ──
    pub min_uptime_backup: f64,
    pub min_contribution_backup: f64,
}

impl Default for EpochConfig {
    fn default() -> Self {
        Self {
            active_set_size: 21,
            max_demotion_per_epoch: 3,
            epoch_duration_secs: 30 * 24 * 60 * 60, // 30 days

            min_uptime_active: 0.95,
            min_contribution_active: 0.95,
            min_penalty_active: 0.90,
            min_active_score: 0.95,

            min_uptime_backup: 0.90,
            min_contribution_backup: 0.90,
        }
    }
}

impl EpochConfig {
    pub fn testnet() -> Self {
        Self {
            active_set_size: 5, // Smaller for testing
            max_demotion_per_epoch: 2,
            epoch_duration_secs: 60 * 60, // 1 hour for testing

            min_uptime_active: 0.80,
            min_contribution_active: 0.80,
            min_penalty_active: 0.70,
            min_active_score: 0.50,

            min_uptime_backup: 0.70,
            min_contribution_backup: 0.70,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Validator State (Active / Backup)
// ═══════════════════════════════════════════════════════════════

/// Tracked state for each validator in the rotation system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationValidator {
    pub validator_id: [u8; 32],
    pub role: RotationRole,
    pub metrics: ValidatorMetrics,
    /// Last computed score (updated each epoch).
    pub last_score: Option<ScoreBreakdown>,
    /// Epoch when this validator joined their current role.
    pub role_since_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RotationRole {
    Active,
    Backup,
}

// ═══════════════════════════════════════════════════════════════
//  Epoch Rotation Result
// ═══════════════════════════════════════════════════════════════

/// Result of running an epoch rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochRotationResult {
    pub epoch: u64,
    /// Validators demoted from Active → Backup.
    pub demoted: Vec<DemotionRecord>,
    /// Validators promoted from Backup → Active.
    pub promoted: Vec<PromotionRecord>,
    /// Validators immediately ejected (severe offenses).
    pub ejected: Vec<EjectionRecord>,
    /// Final Active set after rotation.
    pub active_set: Vec<[u8; 32]>,
    /// Active count (may be < 21 if not enough Backup).
    pub active_count: usize,
    pub backup_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemotionRecord {
    pub validator_id: [u8; 32],
    pub score: f64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionRecord {
    pub validator_id: [u8; 32],
    pub score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EjectionRecord {
    pub validator_id: [u8; 32],
    pub reason: CooldownReason,
}

// ═══════════════════════════════════════════════════════════════
//  Rotation Logic
// ═══════════════════════════════════════════════════════════════

/// Run the monthly epoch rotation.
///
/// This is the core selection algorithm. It is:
/// - **Deterministic**: same inputs → same outputs
/// - **No voting**: purely formula-based
/// - **Gradual**: max 3 demotions per epoch
pub fn run_epoch_rotation(
    epoch: u64,
    validators: &mut [RotationValidator],
    cooldowns: &mut CooldownRegistry,
    scoring_config: &ScoringConfig,
    epoch_config: &EpochConfig,
    cooldown_config: &CooldownConfig,
) -> EpochRotationResult {
    // Clean up expired cooldowns
    cooldowns.gc_expired(epoch);

    // ── Step 1: Compute scores for all validators ──
    for v in validators.iter_mut() {
        let breakdown = compute_score(&v.metrics, scoring_config);
        v.last_score = Some(breakdown);
    }

    // ── Step 2: Identify Active validators failing maintenance ──
    let mut failing_active: Vec<(usize, f64)> = Vec::new();

    for (i, v) in validators.iter().enumerate() {
        if v.role != RotationRole::Active {
            continue;
        }
        let score = v.last_score.as_ref().map(|s| s.score).unwrap_or(0.0);
        let breakdown = v.last_score.as_ref();

        let fails_uptime = breakdown.map(|b| b.uptime < epoch_config.min_uptime_active).unwrap_or(true);
        let fails_contribution = breakdown.map(|b| b.contribution < epoch_config.min_contribution_active).unwrap_or(true);
        let fails_penalty = breakdown.map(|b| b.penalty_factor < epoch_config.min_penalty_active).unwrap_or(true);
        let fails_score = score < epoch_config.min_active_score;
        let fails_stake = v.metrics.stake < scoring_config.min_stake_active;

        if fails_uptime || fails_contribution || fails_penalty || fails_score || fails_stake {
            failing_active.push((i, score));
        }
    }

    // ── Step 3: Sort failures by score (worst first), limit to max_demotion ──
    failing_active.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    let demotion_count = failing_active
        .len()
        .min(epoch_config.max_demotion_per_epoch);

    // ── Step 4: Demote ──
    let mut demoted: Vec<DemotionRecord> = Vec::new();
    let to_demote: Vec<usize> = failing_active[..demotion_count]
        .iter()
        .map(|(i, _)| *i)
        .collect();

    for &idx in &to_demote {
        let v = &mut validators[idx];
        let score = v.last_score.as_ref().map(|s| s.score).unwrap_or(0.0);

        demoted.push(DemotionRecord {
            validator_id: v.validator_id,
            score,
            reason: format!(
                "Below maintenance: uptime={:.2} contribution={:.2} penalty={:.2} score={:.2}",
                v.last_score.as_ref().map(|s| s.uptime).unwrap_or(0.0),
                v.last_score.as_ref().map(|s| s.contribution).unwrap_or(0.0),
                v.last_score.as_ref().map(|s| s.penalty_factor).unwrap_or(0.0),
                score,
            ),
        });

        // Enter cooldown
        cooldowns.enter_cooldown(
            v.validator_id,
            epoch,
            CooldownReason::Demotion,
            cooldown_config,
        );

        // Role change
        v.role = RotationRole::Backup;
        v.role_since_epoch = epoch;
    }

    // ── Step 5: Find eligible Backup validators ──
    let vacancies = demoted.len();
    let mut eligible_backup: Vec<(usize, f64)> = Vec::new();

    for (i, v) in validators.iter().enumerate() {
        if v.role != RotationRole::Backup {
            continue;
        }
        if cooldowns.is_in_cooldown(&v.validator_id, epoch) {
            continue;
        }
        if v.metrics.stake < scoring_config.min_stake_backup {
            continue;
        }

        let breakdown = v.last_score.as_ref();
        let uptime_ok = breakdown
            .map(|b| b.uptime >= epoch_config.min_uptime_backup)
            .unwrap_or(false);
        let contribution_ok = breakdown
            .map(|b| b.contribution >= epoch_config.min_contribution_backup)
            .unwrap_or(false);

        if uptime_ok && contribution_ok {
            let score = breakdown.map(|b| b.score).unwrap_or(0.0);
            eligible_backup.push((i, score));
        }
    }

    // ── Step 6: Sort eligible Backup by score (highest first) ──
    eligible_backup.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

    // ── Step 7: Promote top Backup to fill vacancies ──
    let promotion_count = vacancies.min(eligible_backup.len());
    let mut promoted: Vec<PromotionRecord> = Vec::new();

    for &(idx, score) in eligible_backup.iter().take(promotion_count) {
        let v = &mut validators[idx];
        promoted.push(PromotionRecord {
            validator_id: v.validator_id,
            score,
        });
        v.role = RotationRole::Active;
        v.role_since_epoch = epoch;
    }

    // ── Build final Active set ──
    let active_set: Vec<[u8; 32]> = validators
        .iter()
        .filter(|v| v.role == RotationRole::Active)
        .map(|v| v.validator_id)
        .collect();

    let backup_count = validators
        .iter()
        .filter(|v| v.role == RotationRole::Backup)
        .count();

    EpochRotationResult {
        epoch,
        demoted,
        promoted,
        ejected: Vec::new(), // Ejections are handled separately via eject_validator()
        active_count: active_set.len(),
        active_set,
        backup_count,
    }
}

/// Immediately eject a validator for severe offense (no monthly wait).
///
/// - stake は没収しない
/// - 即時 Active から除外
/// - 報酬ゼロ
/// - Extended jail 期間
/// - Backup 上位を補充（次回 rotation で自動）
pub fn eject_validator(
    validators: &mut [RotationValidator],
    cooldowns: &mut CooldownRegistry,
    validator_id: &[u8; 32],
    reason: CooldownReason,
    current_epoch: u64,
    cooldown_config: &CooldownConfig,
) -> Option<EjectionRecord> {
    if let Some(v) = validators.iter_mut().find(|v| &v.validator_id == validator_id) {
        if v.role == RotationRole::Active {
            v.role = RotationRole::Backup;
            v.role_since_epoch = current_epoch;

            cooldowns.enter_cooldown(*validator_id, current_epoch, reason, cooldown_config);

            return Some(EjectionRecord {
                validator_id: *validator_id,
                reason,
            });
        }
    }
    None
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_validator(id: u8, role: RotationRole, stake: u64, uptime: f64, contribution: f64) -> RotationValidator {
        RotationValidator {
            validator_id: { let mut v = [0u8; 32]; v[0] = id; v },
            role,
            metrics: ValidatorMetrics {
                stake,
                uptime,
                contribution,
                timeouts: 0,
                invalid_actions: 0,
            },
            last_score: None,
            role_since_epoch: 0,
        }
    }

    fn default_configs() -> (ScoringConfig, EpochConfig, CooldownConfig) {
        let mut ec = EpochConfig::testnet();
        ec.active_set_size = 3;
        ec.max_demotion_per_epoch = 2;
        ec.min_active_score = 0.3;
        (ScoringConfig::testnet(), ec, CooldownConfig::default())
    }

    #[test]
    fn test_no_demotion_if_all_healthy() {
        let (sc, ec, cc) = default_configs();
        let mut validators = vec![
            make_validator(1, RotationRole::Active, 1_000_000_000_000_000, 0.99, 0.99),
            make_validator(2, RotationRole::Active, 1_000_000_000_000_000, 0.98, 0.98),
            make_validator(3, RotationRole::Active, 1_000_000_000_000_000, 0.97, 0.97),
        ];
        let mut cooldowns = CooldownRegistry::new();

        let result = run_epoch_rotation(1, &mut validators, &mut cooldowns, &sc, &ec, &cc);

        assert_eq!(result.demoted.len(), 0);
        assert_eq!(result.promoted.len(), 0);
        assert_eq!(result.active_count, 3);
    }

    #[test]
    fn test_demotion_and_promotion() {
        let (sc, ec, cc) = default_configs();
        let mut validators = vec![
            make_validator(1, RotationRole::Active, 1_000_000_000_000_000, 0.99, 0.99),
            make_validator(2, RotationRole::Active, 1_000_000_000_000_000, 0.50, 0.50), // Bad
            make_validator(3, RotationRole::Active, 1_000_000_000_000_000, 0.99, 0.99),
            // Backup ready to promote
            make_validator(10, RotationRole::Backup, 1_000_000_000_000_000, 0.95, 0.95),
            make_validator(11, RotationRole::Backup, 1_000_000_000_000_000, 0.90, 0.90),
        ];
        let mut cooldowns = CooldownRegistry::new();

        let result = run_epoch_rotation(1, &mut validators, &mut cooldowns, &sc, &ec, &cc);

        assert_eq!(result.demoted.len(), 1); // Validator 2 demoted
        assert_eq!(result.demoted[0].validator_id[0], 2);
        assert_eq!(result.promoted.len(), 1); // Validator 10 promoted (higher score)
        assert_eq!(result.promoted[0].validator_id[0], 10);
        assert_eq!(result.active_count, 3); // Still 3
    }

    #[test]
    fn test_max_demotion_limit() {
        let (sc, mut ec, cc) = default_configs();
        ec.max_demotion_per_epoch = 1; // Only 1 allowed

        let mut validators = vec![
            make_validator(1, RotationRole::Active, 1_000_000_000_000_000, 0.50, 0.50), // Bad
            make_validator(2, RotationRole::Active, 1_000_000_000_000_000, 0.40, 0.40), // Worse
            make_validator(3, RotationRole::Active, 1_000_000_000_000_000, 0.99, 0.99),
            make_validator(10, RotationRole::Backup, 1_000_000_000_000_000, 0.95, 0.95),
        ];
        let mut cooldowns = CooldownRegistry::new();

        let result = run_epoch_rotation(1, &mut validators, &mut cooldowns, &sc, &ec, &cc);

        // Only 1 demoted (the worst: validator 2)
        assert_eq!(result.demoted.len(), 1);
        assert_eq!(result.demoted[0].validator_id[0], 2);
    }

    #[test]
    fn test_cooldown_prevents_immediate_repromotion() {
        let (sc, ec, cc) = default_configs();

        let mut validators = vec![
            make_validator(1, RotationRole::Active, 1_000_000_000_000_000, 0.99, 0.99),
            make_validator(2, RotationRole::Active, 1_000_000_000_000_000, 0.50, 0.50),
            make_validator(3, RotationRole::Active, 1_000_000_000_000_000, 0.99, 0.99),
            make_validator(10, RotationRole::Backup, 1_000_000_000_000_000, 0.95, 0.95),
        ];
        let mut cooldowns = CooldownRegistry::new();

        // Epoch 1: demote validator 2
        let r1 = run_epoch_rotation(1, &mut validators, &mut cooldowns, &sc, &ec, &cc);
        assert_eq!(r1.demoted.len(), 1);
        assert_eq!(r1.demoted[0].validator_id[0], 2);

        // Fix validator 2's metrics
        validators[1].metrics.uptime = 0.99;
        validators[1].metrics.contribution = 0.99;

        // Epoch 1 (same epoch): validator 2 is in cooldown, can't be promoted
        let r2 = run_epoch_rotation(1, &mut validators, &mut cooldowns, &sc, &ec, &cc);
        // Validator 2 should NOT be promoted (in cooldown)
        assert!(!r2.promoted.iter().any(|p| p.validator_id[0] == 2));

        // Epoch 2: cooldown expired, can be promoted
        let r3 = run_epoch_rotation(2, &mut validators, &mut cooldowns, &sc, &ec, &cc);
        // Now validator 2 could be a candidate if there are vacancies
        // (depends on whether anyone else got demoted)
        assert!(cooldowns.is_in_cooldown(&validators[1].validator_id, 1));
        assert!(!cooldowns.is_in_cooldown(&validators[1].validator_id, 2));
    }

    #[test]
    fn test_severe_offense_ejection() {
        let (_, _, cc) = default_configs();
        let mut validators = vec![
            make_validator(1, RotationRole::Active, 1_000_000_000_000_000, 0.99, 0.99),
        ];
        let mut cooldowns = CooldownRegistry::new();

        let result = eject_validator(
            &mut validators,
            &mut cooldowns,
            &validators[0].validator_id,
            CooldownReason::DoubleSign,
            5,
            &cc,
        );

        assert!(result.is_some());
        assert_eq!(validators[0].role, RotationRole::Backup);
        assert!(cooldowns.is_in_cooldown(&validators[0].validator_id, 5));
        assert!(cooldowns.is_in_cooldown(&validators[0].validator_id, 6));
        assert!(cooldowns.is_in_cooldown(&validators[0].validator_id, 7));
        assert!(!cooldowns.is_in_cooldown(&validators[0].validator_id, 8)); // 5+3=8
    }
}
