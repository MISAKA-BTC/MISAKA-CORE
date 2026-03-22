//! # Validator Workload Tracking — Epoch-Snapshotted Metrics
//!
//! Tracks per-validator work contributions for:
//! 1. **Reward fairness**: Score reflects actual work, not just stake
//! 2. **Transparency**: Explorer / Dashboard can show "who did what"
//! 3. **Anti-gaming**: Raw metrics are validator-observed, not self-reported
//!
//! # Workload Score Formula
//!
//! ```text
//! workload_score =
//!     W_blocks   * normalized_accepted_blocks
//!   + W_votes    * normalized_signed_votes
//!   + W_validate * normalized_validated_blocks
//!   + W_finality * normalized_finalized_contribution
//!   + W_relay    * normalized_relayed_messages
//!   + W_uptime   * normalized_active_time
//! ```
//!
//! # Anti-Gaming
//!
//! - Rejected blocks / missed votes reduce the score (penalty path)
//! - "Lots of junk work" ≠ high score: only accepted work counts
//! - Workload data is consensus-observed, NOT self-reported

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
//  Workload Configuration
// ═══════════════════════════════════════════════════════════════

/// Weights for each workload component.
///
/// All weights are u32; the sum determines the relative importance.
/// Default: blocks=25, votes=20, validate=20, finality=15, relay=10, uptime=10
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadWeights {
    pub blocks: u32,
    pub votes: u32,
    pub validate: u32,
    pub finality: u32,
    pub relay: u32,
    pub uptime: u32,
}

impl Default for WorkloadWeights {
    fn default() -> Self {
        Self {
            blocks: 25,
            votes: 20,
            validate: 20,
            finality: 15,
            relay: 10,
            uptime: 10,
        }
    }
}

impl WorkloadWeights {
    /// Total weight sum (used for normalization sanity checks).
    pub fn total(&self) -> u32 {
        self.blocks + self.votes + self.validate + self.finality + self.relay + self.uptime
    }
}

/// Workload tracking configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadConfig {
    pub enabled: bool,
    pub track_mempool_stats: bool,
    pub track_relay_stats: bool,
    pub track_finality_contribution: bool,
    pub weights: WorkloadWeights,
}

impl Default for WorkloadConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            track_mempool_stats: true,
            track_relay_stats: true,
            track_finality_contribution: true,
            weights: WorkloadWeights::default(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Validator Workload Snapshot (per-epoch)
// ═══════════════════════════════════════════════════════════════

/// Immutable snapshot of a validator's work in one epoch.
///
/// Created at epoch boundary, never modified afterward.
/// This is the data stored for historical queries and the
/// raw input to `compute_workload_score()`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ValidatorWorkloadSnapshot {
    /// Validator identifier (32-byte hex or compact form).
    pub validator_id: String,
    /// Epoch number.
    pub epoch: u64,

    // ── Block Production ──
    /// Blocks proposed by this validator in the epoch.
    pub proposed_blocks: u64,
    /// Blocks accepted into the canonical chain.
    pub accepted_blocks: u64,
    /// Blocks rejected (invalid / orphaned).
    pub rejected_blocks: u64,
    /// Total data bytes produced in accepted blocks.
    #[serde(with = "serde_u128_string")]
    pub produced_data_bytes: u128,

    // ── Validation / Voting ──
    /// Blocks validated (verified + voted on).
    pub validated_blocks: u64,
    /// Consensus votes successfully signed and delivered.
    pub signed_votes: u64,
    /// Consensus votes missed (absent, timed out).
    pub missed_votes: u64,

    // ── Attestation / Finality ──
    /// Attestations issued.
    pub attestation_count: u64,
    /// Contributions to finality (finalized-chain votes).
    pub finalized_contribution_count: u64,

    // ── Mempool / Relay ──
    /// Transactions observed in the mempool.
    pub mempool_tx_seen: u64,
    /// Transactions included in proposed blocks.
    pub mempool_tx_included: u64,
    /// P2P messages relayed to other nodes.
    pub relayed_messages: u64,

    // ── Uptime ──
    /// Uptime health checks passed.
    pub uptime_checks_passed: u64,
    /// Uptime health checks failed.
    pub uptime_checks_failed: u64,
    /// Active time slots in the epoch.
    pub active_time_slots: u64,

    // ── Height Reference ──
    /// Last block height this validator was active at.
    pub last_active_height: u64,

    // ── Computed ──
    /// Workload score computed from the raw metrics.
    pub workload_score: u64,
}

/// Mutable accumulator used during an epoch to collect workload events.
///
/// At epoch boundary, this is frozen into a `ValidatorWorkloadSnapshot`.
#[derive(Debug, Default, Clone)]
pub struct WorkloadAccumulator {
    pub proposed_blocks: u64,
    pub accepted_blocks: u64,
    pub rejected_blocks: u64,
    pub produced_data_bytes: u128,
    pub validated_blocks: u64,
    pub signed_votes: u64,
    pub missed_votes: u64,
    pub attestation_count: u64,
    pub finalized_contribution_count: u64,
    pub mempool_tx_seen: u64,
    pub mempool_tx_included: u64,
    pub relayed_messages: u64,
    pub uptime_checks_passed: u64,
    pub uptime_checks_failed: u64,
    pub active_time_slots: u64,
    pub last_active_height: u64,
}

impl WorkloadAccumulator {
    /// Freeze this accumulator into an immutable snapshot.
    pub fn into_snapshot(
        self,
        validator_id: String,
        epoch: u64,
        config: &WorkloadConfig,
    ) -> ValidatorWorkloadSnapshot {
        let workload_score = compute_workload_score_from_raw(
            &config.weights,
            self.accepted_blocks,
            self.rejected_blocks,
            self.signed_votes,
            self.missed_votes,
            self.validated_blocks,
            self.finalized_contribution_count,
            self.relayed_messages,
            self.active_time_slots,
            self.uptime_checks_passed,
            self.uptime_checks_failed,
        );

        ValidatorWorkloadSnapshot {
            validator_id,
            epoch,
            proposed_blocks: self.proposed_blocks,
            accepted_blocks: self.accepted_blocks,
            rejected_blocks: self.rejected_blocks,
            produced_data_bytes: self.produced_data_bytes,
            validated_blocks: self.validated_blocks,
            signed_votes: self.signed_votes,
            missed_votes: self.missed_votes,
            attestation_count: self.attestation_count,
            finalized_contribution_count: self.finalized_contribution_count,
            mempool_tx_seen: self.mempool_tx_seen,
            mempool_tx_included: self.mempool_tx_included,
            relayed_messages: self.relayed_messages,
            uptime_checks_passed: self.uptime_checks_passed,
            uptime_checks_failed: self.uptime_checks_failed,
            active_time_slots: self.active_time_slots,
            last_active_height: self.last_active_height,
            workload_score,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Network Workload Summary
// ═══════════════════════════════════════════════════════════════

/// Aggregate workload statistics for the entire network in one epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkWorkloadSummary {
    pub epoch: u64,
    pub active_validators: u32,
    pub total_accepted_blocks: u64,
    pub total_signed_votes: u64,
    pub total_validated_blocks: u64,
    pub total_relayed_messages: u64,
    pub avg_workload_score: u64,
    pub median_workload_score: u64,
}

/// Compute a `NetworkWorkloadSummary` from a slice of snapshots.
pub fn compute_network_summary(epoch: u64, snapshots: &[ValidatorWorkloadSnapshot]) -> NetworkWorkloadSummary {
    if snapshots.is_empty() {
        return NetworkWorkloadSummary {
            epoch,
            active_validators: 0,
            total_accepted_blocks: 0,
            total_signed_votes: 0,
            total_validated_blocks: 0,
            total_relayed_messages: 0,
            avg_workload_score: 0,
            median_workload_score: 0,
        };
    }

    let total_accepted_blocks: u64 = snapshots.iter().map(|s| s.accepted_blocks).sum();
    let total_signed_votes: u64 = snapshots.iter().map(|s| s.signed_votes).sum();
    let total_validated_blocks: u64 = snapshots.iter().map(|s| s.validated_blocks).sum();
    let total_relayed_messages: u64 = snapshots.iter().map(|s| s.relayed_messages).sum();

    let mut scores: Vec<u64> = snapshots.iter().map(|s| s.workload_score).collect();
    let count = scores.len() as u64;
    let avg = scores.iter().sum::<u64>() / count;

    scores.sort_unstable();
    let median = if scores.len() % 2 == 0 {
        let mid = scores.len() / 2;
        (scores[mid - 1] + scores[mid]) / 2
    } else {
        scores[scores.len() / 2]
    };

    NetworkWorkloadSummary {
        epoch,
        active_validators: snapshots.len() as u32,
        total_accepted_blocks,
        total_signed_votes,
        total_validated_blocks,
        total_relayed_messages,
        avg_workload_score: avg,
        median_workload_score: median,
    }
}

// ═══════════════════════════════════════════════════════════════
//  Workload Score Computation
// ═══════════════════════════════════════════════════════════════

/// Scale factor for normalized score components (fixed-point, 6 decimal digits).
const NORM_SCALE: u64 = 1_000_000;

/// Compute workload score from raw metrics.
///
/// # Normalization
///
/// Each component is normalized to [0, NORM_SCALE] using a ratio of
/// "good work" to "total work" (accepted / (accepted + rejected)).
/// This means a validator doing lots of low-quality work scores poorly.
///
/// # Penalty Integration
///
/// - `rejected_blocks` reduce the block component
/// - `missed_votes` reduce the vote component
/// - `uptime_checks_failed` reduce the uptime component
///
/// # Integer Only
///
/// All math uses u64/u128 — no floats.
pub fn compute_workload_score_from_raw(
    weights: &WorkloadWeights,
    accepted_blocks: u64,
    rejected_blocks: u64,
    signed_votes: u64,
    missed_votes: u64,
    validated_blocks: u64,
    finalized_contribution: u64,
    relayed_messages: u64,
    active_time_slots: u64,
    uptime_passed: u64,
    uptime_failed: u64,
) -> u64 {
    let total_weight = weights.total() as u128;
    if total_weight == 0 {
        return 0;
    }

    // Normalized components: ratio * NORM_SCALE
    let norm_blocks = safe_ratio(accepted_blocks, accepted_blocks + rejected_blocks);
    let norm_votes = safe_ratio(signed_votes, signed_votes + missed_votes);
    let norm_validate = if validated_blocks > 0 { NORM_SCALE } else { 0 };
    let norm_finality = if finalized_contribution > 0 { NORM_SCALE } else { 0 };
    let norm_relay = if relayed_messages > 0 { NORM_SCALE } else { 0 };
    let norm_uptime = safe_ratio(uptime_passed, uptime_passed + uptime_failed);

    // Scale by absolute volume (reward more work, not just accuracy)
    // Use log2-ish volume scaling: min(volume, cap) / cap * NORM_SCALE
    // This prevents a validator with 1 perfect block from outscoring one with 100 good + 2 bad
    let vol_blocks = volume_scale(accepted_blocks, 100);
    let vol_votes = volume_scale(signed_votes, 1000);
    let vol_validate = volume_scale(validated_blocks, 1000);
    let vol_finality = volume_scale(finalized_contribution, 1000);
    let vol_relay = volume_scale(relayed_messages, 100_000);
    let vol_uptime = volume_scale(active_time_slots, 1440); // ~1 day at 1 slot/min

    // Combined: quality * volume * weight
    let score = (weights.blocks as u128 * combine(norm_blocks, vol_blocks))
        + (weights.votes as u128 * combine(norm_votes, vol_votes))
        + (weights.validate as u128 * combine(norm_validate, vol_validate))
        + (weights.finality as u128 * combine(norm_finality, vol_finality))
        + (weights.relay as u128 * combine(norm_relay, vol_relay))
        + (weights.uptime as u128 * combine(norm_uptime, vol_uptime));

    // Divide by total weight to normalize the overall score
    (score / total_weight) as u64
}

/// Compute `numerator / denominator * NORM_SCALE` without overflow.
/// Returns 0 if denominator is 0.
fn safe_ratio(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    ((numerator as u128 * NORM_SCALE as u128) / denominator as u128) as u64
}

/// Volume scaling: `min(actual, cap) / cap * NORM_SCALE`.
///
/// A validator must have done at least `cap` units of work to reach
/// full volume credit. Below that, credit scales linearly.
fn volume_scale(actual: u64, cap: u64) -> u64 {
    if cap == 0 {
        return if actual > 0 { NORM_SCALE } else { 0 };
    }
    let clamped = actual.min(cap);
    ((clamped as u128 * NORM_SCALE as u128) / cap as u128) as u64
}

/// Combine quality ratio and volume ratio → single component value.
///
/// `quality * volume / NORM_SCALE` — integer-safe.
fn combine(quality: u64, volume: u64) -> u128 {
    (quality as u128 * volume as u128) / NORM_SCALE as u128
}

// ═══════════════════════════════════════════════════════════════
//  Serde Helper: u128 as String
// ═══════════════════════════════════════════════════════════════

pub mod serde_u128_string {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u128, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u128, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse::<u128>().map_err(serde::de::Error::custom)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_safe_ratio_normal() {
        assert_eq!(safe_ratio(50, 100), 500_000); // 50%
        assert_eq!(safe_ratio(100, 100), NORM_SCALE); // 100%
        assert_eq!(safe_ratio(0, 100), 0); // 0%
    }

    #[test]
    fn test_safe_ratio_zero_denominator() {
        assert_eq!(safe_ratio(42, 0), 0);
    }

    #[test]
    fn test_volume_scale() {
        assert_eq!(volume_scale(50, 100), 500_000);
        assert_eq!(volume_scale(100, 100), NORM_SCALE);
        assert_eq!(volume_scale(200, 100), NORM_SCALE); // capped
        assert_eq!(volume_scale(0, 100), 0);
    }

    #[test]
    fn test_workload_score_all_zeros() {
        let w = WorkloadWeights::default();
        let score = compute_workload_score_from_raw(&w, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        assert_eq!(score, 0);
    }

    #[test]
    fn test_workload_score_perfect_validator() {
        let w = WorkloadWeights::default();
        let score = compute_workload_score_from_raw(
            &w,
            100,  // accepted_blocks
            0,    // rejected_blocks
            1000, // signed_votes
            0,    // missed_votes
            1000, // validated_blocks
            1000, // finalized_contribution
            100_000, // relayed_messages
            1440, // active_time_slots
            1440, // uptime_passed
            0,    // uptime_failed
        );
        assert!(score > 0, "perfect validator must have positive score: {score}");
        // Perfect validator should achieve NORM_SCALE
        assert_eq!(score, NORM_SCALE, "perfect validator should get max score");
    }

    #[test]
    fn test_workload_penalty_rejected_blocks() {
        let w = WorkloadWeights::default();
        let good = compute_workload_score_from_raw(
            &w, 100, 0, 1000, 0, 1000, 1000, 100_000, 1440, 1440, 0,
        );
        let with_rejects = compute_workload_score_from_raw(
            &w, 100, 50, 1000, 0, 1000, 1000, 100_000, 1440, 1440, 0,
        );
        assert!(
            with_rejects < good,
            "rejected blocks must reduce score: good={good}, with_rejects={with_rejects}"
        );
    }

    #[test]
    fn test_workload_penalty_missed_votes() {
        let w = WorkloadWeights::default();
        let good = compute_workload_score_from_raw(
            &w, 100, 0, 1000, 0, 1000, 1000, 100_000, 1440, 1440, 0,
        );
        let with_missed = compute_workload_score_from_raw(
            &w, 100, 0, 1000, 500, 1000, 1000, 100_000, 1440, 1440, 0,
        );
        assert!(
            with_missed < good,
            "missed votes must reduce score: good={good}, with_missed={with_missed}"
        );
    }

    #[test]
    fn test_junk_work_no_advantage() {
        let w = WorkloadWeights::default();
        // Validator A: 20 good blocks, 0 bad
        let quality = compute_workload_score_from_raw(
            &w, 20, 0, 500, 0, 500, 500, 50_000, 1000, 1000, 0,
        );
        // Validator B: 100 blocks but 80 rejected (gaming attempt)
        let junk = compute_workload_score_from_raw(
            &w, 20, 80, 500, 0, 500, 500, 50_000, 1000, 1000, 0,
        );
        assert!(
            junk < quality,
            "junk work must not be rewarded: quality={quality}, junk={junk}"
        );
    }

    #[test]
    fn test_accumulator_into_snapshot() {
        let config = WorkloadConfig::default();
        let mut acc = WorkloadAccumulator::default();
        acc.accepted_blocks = 10;
        acc.signed_votes = 100;
        acc.validated_blocks = 100;
        acc.active_time_slots = 720;
        acc.uptime_checks_passed = 720;

        let snap = acc.into_snapshot("val_001".into(), 42, &config);
        assert_eq!(snap.validator_id, "val_001");
        assert_eq!(snap.epoch, 42);
        assert_eq!(snap.accepted_blocks, 10);
        assert!(snap.workload_score > 0, "snapshot should have computed score");
    }

    #[test]
    fn test_network_summary_empty() {
        let summary = compute_network_summary(1, &[]);
        assert_eq!(summary.active_validators, 0);
        assert_eq!(summary.avg_workload_score, 0);
    }

    #[test]
    fn test_network_summary_basic() {
        let snaps = vec![
            ValidatorWorkloadSnapshot {
                validator_id: "a".into(),
                epoch: 1,
                proposed_blocks: 10,
                accepted_blocks: 10,
                rejected_blocks: 0,
                produced_data_bytes: 1000,
                validated_blocks: 100,
                signed_votes: 100,
                missed_votes: 0,
                attestation_count: 100,
                finalized_contribution_count: 100,
                mempool_tx_seen: 5000,
                mempool_tx_included: 4000,
                relayed_messages: 50000,
                uptime_checks_passed: 1440,
                uptime_checks_failed: 0,
                active_time_slots: 1440,
                last_active_height: 100,
                workload_score: 800_000,
            },
            ValidatorWorkloadSnapshot {
                validator_id: "b".into(),
                epoch: 1,
                proposed_blocks: 8,
                accepted_blocks: 8,
                rejected_blocks: 0,
                produced_data_bytes: 800,
                validated_blocks: 90,
                signed_votes: 90,
                missed_votes: 10,
                attestation_count: 80,
                finalized_contribution_count: 80,
                mempool_tx_seen: 4500,
                mempool_tx_included: 3500,
                relayed_messages: 45000,
                uptime_checks_passed: 1400,
                uptime_checks_failed: 40,
                active_time_slots: 1400,
                last_active_height: 100,
                workload_score: 600_000,
            },
        ];

        let summary = compute_network_summary(1, &snaps);
        assert_eq!(summary.active_validators, 2);
        assert_eq!(summary.total_accepted_blocks, 18);
        assert_eq!(summary.total_signed_votes, 190);
        assert_eq!(summary.avg_workload_score, 700_000);
        assert_eq!(summary.median_workload_score, 700_000);
    }

    #[test]
    fn test_workload_snapshot_serde_roundtrip() {
        let snap = ValidatorWorkloadSnapshot {
            validator_id: "val_001".into(),
            epoch: 128,
            proposed_blocks: 21,
            accepted_blocks: 19,
            rejected_blocks: 2,
            produced_data_bytes: 88_473_600,
            validated_blocks: 610,
            signed_votes: 602,
            missed_votes: 8,
            attestation_count: 599,
            finalized_contribution_count: 588,
            mempool_tx_seen: 220_000,
            mempool_tx_included: 185_000,
            relayed_messages: 92_000,
            uptime_checks_passed: 1438,
            uptime_checks_failed: 2,
            active_time_slots: 1435,
            last_active_height: 99999,
            workload_score: 812_300,
        };

        let json = serde_json::to_string(&snap).expect("serialize");
        let deser: ValidatorWorkloadSnapshot = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(snap, deser);
    }
}
