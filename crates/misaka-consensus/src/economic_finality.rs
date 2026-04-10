//! BFT Economic Finality — separated from DAG ordering.
//!
//! # Architecture: Ordering vs. Finality
//!
//! ```text
//! DAG Layer (GhostDAG)          Finality Layer (this module)
//! ─────────────────────         ──────────────────────────────
//! • Relative ordering           • Absolute confirmation
//! • Blue/Red classification     • Cannot be reversed
//! • Reorg-capable               • 2/3 validator attestation
//! • Probabilistic               • Deterministic
//! ```
//!
//! # Why Separate?
//!
//! DAG ordering (GhostDAG) determines the SEQUENCE of transactions.
//! But it does NOT guarantee they won't be reordered by a deeper reorg.
//!
//! Economic Finality guarantees that once 2/3+ of validator stake has
//! attested to a checkpoint, reversing it requires >1/3 stake to be
//! slashed — making attacks economically irrational.
//!
//! # Finality Protocol
//!
//! 1. Every `EPOCH_LENGTH` blue_scores, validators vote on a checkpoint
//! 2. A checkpoint includes: block_hash, state_root, epoch_number
//! 3. When >2/3 of total stake has attested, the checkpoint is FINALIZED
//! 4. Finalized checkpoints are irreversible (stored permanently)
//! 5. DAG reorgs CANNOT cross finalized checkpoints
//!
//! # Security (BFT Threshold)
//!
//! With N validators and total stake S:
//! - Safety: requires >1/3 S to be byzantine to violate finality
//! - Liveness: requires >2/3 S online to produce new finalized checkpoints
//! - This matches the standard BFT safety/liveness tradeoff

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

pub type Hash = [u8; 32];

/// Epoch length in blue_score units.
pub const EPOCH_LENGTH: u64 = 100;

/// BFT threshold: fraction of stake required for finality (2/3).
/// Represented as (numerator, denominator) for integer arithmetic.
pub const FINALITY_THRESHOLD: (u64, u64) = (2, 3);

// ═══════════════════════════════════════════════════════════════
//  Finality Checkpoint (what validators attest to)
// ═══════════════════════════════════════════════════════════════

/// A checkpoint that validators attest to for economic finality.
///
/// This is the ONLY type that achieves irreversibility.
/// DAG blue_score, blue_work, and reachability are all reorg-capable.
/// Only this checkpoint, once finalized, is permanent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityCheckpoint {
    /// Epoch number (monotonically increasing).
    pub epoch: u64,
    /// Block hash at epoch boundary (on Selected Parent Chain).
    pub block_hash: Hash,
    /// Blue score at this checkpoint.
    pub blue_score: u64,
    /// Cryptographic state root (UTXO + SpendTag commitment).
    pub state_root: Hash,
    /// Number of finalized transactions up to this point.
    pub cumulative_txs: u64,
}

impl FinalityCheckpoint {
    /// Canonical signing message for validator attestation.
    ///
    /// Validators sign this message with ML-DSA-65.
    /// The signing message is deterministic and includes ALL checkpoint fields.
    pub fn signing_message(&self) -> Hash {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:finality:attest:v1:");
        h.update(self.epoch.to_le_bytes());
        h.update(&self.block_hash);
        h.update(self.blue_score.to_le_bytes());
        h.update(&self.state_root);
        h.update(self.cumulative_txs.to_le_bytes());
        h.finalize().into()
    }

    /// Epoch from blue_score.
    pub fn epoch_for_score(blue_score: u64) -> u64 {
        blue_score / EPOCH_LENGTH
    }
}

// ═══════════════════════════════════════════════════════════════
//  Validator Attestation
// ═══════════════════════════════════════════════════════════════

/// A validator's attestation to a finality checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorAttestation {
    /// Validator's 32-byte canonical ID (SHA3-256 of ML-DSA public key).
    pub validator_id: [u8; 32],
    /// Epoch being attested.
    pub epoch: u64,
    /// Checkpoint being attested (must match the validator's local state).
    pub checkpoint_hash: Hash,
    /// ML-DSA-65 signature over FinalityCheckpoint::signing_message().
    pub signature: Vec<u8>,
    /// Validator's stake weight at this epoch.
    pub stake_weight: u128,
}

impl ValidatorAttestation {
    /// Hash of this attestation (for dedup).
    pub fn attestation_hash(&self) -> Hash {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:attest:hash:v1:");
        h.update(&self.validator_id);
        h.update(self.epoch.to_le_bytes());
        h.update(&self.checkpoint_hash);
        h.finalize().into()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Finalized Epoch Record
// ═══════════════════════════════════════════════════════════════

/// A checkpoint that has achieved economic finality.
///
/// Once created, this record is PERMANENT and IRREVERSIBLE.
/// DAG reorgs CANNOT cross this boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizedEpoch {
    pub checkpoint: FinalityCheckpoint,
    /// Total stake that attested.
    pub attested_stake: u128,
    /// Total active stake at this epoch.
    pub total_stake: u128,
    /// Number of distinct validators that attested.
    pub attestation_count: usize,
    /// Timestamp of finalization (local clock, not consensus-binding).
    pub finalized_at_ms: u64,
}

impl FinalizedEpoch {
    /// Is the BFT threshold met?
    pub fn is_threshold_met(&self) -> bool {
        // CRITICAL FIX: strict > 2/3 (not >=).
        // BFT safety requires STRICTLY MORE than 2/3. With >=, exactly 2/3
        // allows two conflicting checkpoints to both finalize (safety violation).
        // Example: total=99, attested=66 → 66*3=198, 99*2=198 → 198>=198 was TRUE (BUG)
        // Now: 198 > 198 is FALSE (correct — need 67+ to finalize)
        self.attested_stake
            .saturating_mul(FINALITY_THRESHOLD.1 as u128)
            > self
                .total_stake
                .saturating_mul(FINALITY_THRESHOLD.0 as u128)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Economic Finality Manager
// ═══════════════════════════════════════════════════════════════

/// Check if attested stake exceeds the 2/3 BFT finality threshold.
///
/// Strict > 2/3 (not >=). BFT safety requires STRICTLY MORE than 2/3.
/// With >=, exactly 2/3 allows two conflicting checkpoints to both
/// finalize (safety violation).
fn check_finality_threshold(attested: u128, total: u128) -> bool {
    attested.saturating_mul(3) > total.saturating_mul(2)
}

/// Manages the economic finality protocol.
///
/// # Responsibilities
///
/// 1. Collect validator attestations for each epoch
/// 2. Track stake weight per attestation
/// 3. Determine when 2/3 threshold is reached → FINALIZED
/// 4. Store finalized epochs (permanent, cannot reorg past them)
/// 5. Prevent DAG reorgs from crossing finalized boundaries
///
/// # Type Safety: Reorg Boundary
///
/// ```ignore
/// fn can_reorg_to(&self, target_score: u64) -> bool {
///     target_score > self.last_finalized_score()
/// }
/// ```
///
/// If a reorg target is BELOW the last finalized checkpoint,
/// the reorg is REJECTED. This is the core safety property.
pub struct EconomicFinalityManager {
    /// Pending attestations per epoch (not yet finalized).
    pending: HashMap<u64, EpochAttestations>,
    /// Finalized epochs (permanent, ordered by epoch number).
    finalized: Vec<FinalizedEpoch>,
    /// Total active stake (updated at epoch boundaries).
    total_stake: u128,
}

/// Attestations collected for a single epoch (pre-finalization).
struct EpochAttestations {
    checkpoint: FinalityCheckpoint,
    attestations: Vec<ValidatorAttestation>,
    /// Unique validator IDs that have attested (dedup).
    seen_validators: HashMap<[u8; 32], u128>, // validator_id → stake
    total_attested_stake: u128,
}

#[derive(Debug, thiserror::Error)]
pub enum FinalityError {
    #[error("duplicate attestation from validator {}", hex::encode(&validator[..4]))]
    DuplicateAttestation { validator: [u8; 32] },
    #[error("attestation epoch {got} does not match expected {expected}")]
    EpochMismatch { got: u64, expected: u64 },
    #[error("checkpoint hash mismatch")]
    CheckpointMismatch,
    #[error("reorg target score {target} is below finalized score {finalized}")]
    ReorgBelowFinality { target: u64, finalized: u64 },
    #[error("epoch {epoch} already finalized")]
    AlreadyFinalized { epoch: u64 },
    #[error("unknown validator: {}", hex::encode(&id[..4]))]
    UnknownValidator { id: [u8; 32] },
    #[error("invalid ML-DSA-65 signature from validator {}", hex::encode(&validator[..4]))]
    InvalidSignature { validator: [u8; 32] },
}

impl EconomicFinalityManager {
    pub fn new(total_stake: u128) -> Self {
        Self {
            pending: HashMap::new(),
            finalized: Vec::new(),
            total_stake,
        }
    }

    /// Update total active stake (called at epoch boundaries).
    pub fn set_total_stake(&mut self, stake: u128) {
        self.total_stake = stake;
    }

    /// Start collecting attestations for a new epoch.
    pub fn begin_epoch(&mut self, checkpoint: FinalityCheckpoint) {
        let epoch = checkpoint.epoch;
        self.pending.insert(
            epoch,
            EpochAttestations {
                checkpoint,
                attestations: Vec::new(),
                seen_validators: HashMap::new(),
                total_attested_stake: 0,
            },
        );
    }

    /// Add a validator attestation. Returns `true` if finality is newly achieved.
    /// Add an attestation with MANDATORY signature verification.
    ///
    /// CRITICAL-01 fix: Previously accepted attestations without verifying
    /// the ML-DSA-65 signature, allowing forged finality. Now requires
    /// a ValidatorSet to:
    /// 1. Verify the validator is a known committee member
    /// 2. Look up the validator's real stake (not self-reported)
    /// 3. Verify the ML-DSA-65 signature over the checkpoint message
    pub fn add_attestation(
        &mut self,
        attestation: ValidatorAttestation,
        validator_set: &crate::ValidatorSet,
    ) -> Result<bool, FinalityError> {
        let epoch = attestation.epoch;

        // Check not already finalized
        if self.finalized.iter().any(|f| f.checkpoint.epoch == epoch) {
            return Err(FinalityError::AlreadyFinalized { epoch });
        }

        let pending = self
            .pending
            .get_mut(&epoch)
            .ok_or(FinalityError::EpochMismatch {
                got: epoch,
                expected: 0,
            })?;

        // Dedup check
        if pending
            .seen_validators
            .contains_key(&attestation.validator_id)
        {
            return Err(FinalityError::DuplicateAttestation {
                validator: attestation.validator_id,
            });
        }

        // Checkpoint consistency
        if attestation.checkpoint_hash != pending.checkpoint.signing_message() {
            return Err(FinalityError::CheckpointMismatch);
        }

        // CRITICAL-01: Verify validator is in the validator set
        let validator = validator_set.get(&attestation.validator_id).ok_or(
            FinalityError::UnknownValidator {
                id: attestation.validator_id,
            },
        )?;

        // CRITICAL-01: Use stake from ValidatorSet, NOT from attestation
        let stake = validator.stake_weight;

        // CRITICAL-01: Verify ML-DSA-65 signature (raw, no domain prefix).
        // Phase 2c-B D5c: domain separation handled upstream.
        let pk = misaka_pqc::pq_sign::MlDsaPublicKey::from_bytes(&validator.public_key.bytes)
            .map_err(|_| FinalityError::InvalidSignature {
                validator: attestation.validator_id,
            })?;
        let sig = misaka_pqc::pq_sign::MlDsaSignature::from_bytes(&attestation.signature).map_err(
            |_| FinalityError::InvalidSignature {
                validator: attestation.validator_id,
            },
        )?;
        misaka_pqc::pq_sign::ml_dsa_verify_raw(
            &pk,
            &attestation.checkpoint_hash,
            &sig,
        )
        .map_err(|_| FinalityError::InvalidSignature {
            validator: attestation.validator_id,
        })?;

        // Record attestation (with verified stake)
        pending
            .seen_validators
            .insert(attestation.validator_id, stake);
        pending.total_attested_stake = pending.total_attested_stake.saturating_add(stake);
        pending.attestations.push(attestation);

        if check_finality_threshold(pending.total_attested_stake, self.total_stake) {
            self.finalize_epoch(epoch);
            return Ok(true);
        }

        Ok(false)
    }

    /// Test-only: add attestation with validator set check but skip ML-DSA-65
    /// signature verification. Uses verified stake from ValidatorSet.
    #[cfg(test)]
    pub fn add_attestation_unchecked(
        &mut self,
        attestation: ValidatorAttestation,
        validator_set: &crate::ValidatorSet,
    ) -> Result<bool, FinalityError> {
        let epoch = attestation.epoch;

        if self.finalized.iter().any(|f| f.checkpoint.epoch == epoch) {
            return Err(FinalityError::AlreadyFinalized { epoch });
        }

        let pending = self
            .pending
            .get_mut(&epoch)
            .ok_or(FinalityError::EpochMismatch {
                got: epoch,
                expected: 0,
            })?;

        if pending
            .seen_validators
            .contains_key(&attestation.validator_id)
        {
            return Err(FinalityError::DuplicateAttestation {
                validator: attestation.validator_id,
            });
        }

        if attestation.checkpoint_hash != pending.checkpoint.signing_message() {
            return Err(FinalityError::CheckpointMismatch);
        }

        // Verify validator is in the set (but skip sig verification for tests)
        let validator = validator_set.get(&attestation.validator_id).ok_or(
            FinalityError::UnknownValidator {
                id: attestation.validator_id,
            },
        )?;
        let stake = validator.stake_weight;

        pending
            .seen_validators
            .insert(attestation.validator_id, stake);
        pending.total_attested_stake = pending.total_attested_stake.saturating_add(stake);
        pending.attestations.push(attestation);

        if check_finality_threshold(pending.total_attested_stake, self.total_stake) {
            self.finalize_epoch(epoch);
            return Ok(true);
        }

        Ok(false)
    }

    /// Finalize an epoch (move from pending to permanent).
    fn finalize_epoch(&mut self, epoch: u64) {
        if let Some(pending) = self.pending.remove(&epoch) {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;

            self.finalized.push(FinalizedEpoch {
                checkpoint: pending.checkpoint,
                attested_stake: pending.total_attested_stake,
                total_stake: self.total_stake,
                attestation_count: pending.attestations.len(),
                finalized_at_ms: now_ms,
            });
        }
    }

    /// Check if a reorg target is safe (above finalized boundary).
    ///
    /// # Core Safety Property
    ///
    /// A reorg that would undo a finalized checkpoint is REJECTED.
    /// This is the fundamental guarantee of economic finality:
    /// once 2/3+ stake has attested, the state is permanent.
    pub fn can_reorg_to(&self, target_blue_score: u64) -> Result<(), FinalityError> {
        if let Some(last) = self.finalized.last() {
            if target_blue_score <= last.checkpoint.blue_score {
                return Err(FinalityError::ReorgBelowFinality {
                    target: target_blue_score,
                    finalized: last.checkpoint.blue_score,
                });
            }
        }
        Ok(())
    }

    /// Last finalized epoch (if any).
    pub fn last_finalized(&self) -> Option<&FinalizedEpoch> {
        self.finalized.last()
    }

    /// Last finalized blue_score.
    pub fn last_finalized_score(&self) -> u64 {
        self.finalized
            .last()
            .map(|f| f.checkpoint.blue_score)
            .unwrap_or(0)
    }

    /// Total finalized epochs.
    pub fn finalized_count(&self) -> usize {
        self.finalized.len()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ValidatorSet;
    use misaka_types::validator::{ValidatorIdentity, ValidatorPublicKey};

    fn make_checkpoint(epoch: u64, score: u64) -> FinalityCheckpoint {
        FinalityCheckpoint {
            epoch,
            block_hash: [epoch as u8; 32],
            blue_score: score,
            state_root: [0xAA; 32],
            cumulative_txs: epoch * 100,
        }
    }

    /// Build a test ValidatorSet with N validators whose validator_id = [id_byte; 32].
    /// Each validator's public_key.bytes is a dummy (not real ML-DSA-65).
    /// Tests bypass real signature verification by using the inner
    /// `add_attestation_unchecked` helper.
    fn make_test_validator_set(entries: &[(u8, u128)]) -> ValidatorSet {
        let validators = entries
            .iter()
            .map(|(id_byte, stake)| {
                ValidatorIdentity {
                    validator_id: [*id_byte; 32],
                    stake_weight: *stake,
                    public_key: ValidatorPublicKey {
                        bytes: vec![0u8; 1952],
                    },
                    is_active: true,
                }
            })
            .collect();
        ValidatorSet::new(validators)
    }

    fn make_attestation(
        validator_id: u8,
        epoch: u64,
        cp: &FinalityCheckpoint,
        stake: u128,
    ) -> ValidatorAttestation {
        ValidatorAttestation {
            validator_id: [validator_id; 32],
            epoch,
            checkpoint_hash: cp.signing_message(),
            signature: vec![0u8; 64], // Placeholder — tests use unchecked path
            stake_weight: stake,
        }
    }

    #[test]
    fn test_finality_threshold_calculation() {
        // 2/3 threshold: 67 out of 100 = finalized
        let epoch = FinalizedEpoch {
            checkpoint: make_checkpoint(1, 100),
            attested_stake: 67,
            total_stake: 100,
            attestation_count: 3,
            finalized_at_ms: 0,
        };
        assert!(epoch.is_threshold_met());

        // 66 out of 100 = NOT finalized
        let epoch2 = FinalizedEpoch {
            attested_stake: 66,
            ..epoch.clone()
        };
        assert!(!epoch2.is_threshold_met());
    }

    #[test]
    fn test_finality_with_attestations() {
        let vs = make_test_validator_set(&[(1, 30), (2, 30), (3, 10)]);
        let mut fm = EconomicFinalityManager::new(100); // 100 total stake
        let cp = make_checkpoint(1, 100);
        fm.begin_epoch(cp.clone());

        // Validator A: 30 stake → not yet
        let result = fm
            .add_attestation_unchecked(make_attestation(1, 1, &cp, 30), &vs)
            .unwrap();
        assert!(!result, "30/100 < 2/3");

        // Validator B: 30 stake → still not
        let result = fm
            .add_attestation_unchecked(make_attestation(2, 1, &cp, 30), &vs)
            .unwrap();
        assert!(!result, "60/100 < 2/3");

        // Validator C: 10 stake → 70/100 ≥ 2/3 → FINALIZED
        let result = fm
            .add_attestation_unchecked(make_attestation(3, 1, &cp, 10), &vs)
            .unwrap();
        assert!(result, "70/100 >= 2/3 → finalized");

        assert_eq!(fm.finalized_count(), 1);
        assert_eq!(fm.last_finalized_score(), 100);
    }

    #[test]
    fn test_duplicate_attestation_rejected() {
        let vs = make_test_validator_set(&[(1, 50)]);
        let mut fm = EconomicFinalityManager::new(100);
        let cp = make_checkpoint(1, 100);
        fm.begin_epoch(cp.clone());

        fm.add_attestation_unchecked(make_attestation(1, 1, &cp, 50), &vs)
            .unwrap();
        let err = fm.add_attestation_unchecked(make_attestation(1, 1, &cp, 50), &vs);
        assert!(matches!(
            err,
            Err(FinalityError::DuplicateAttestation { .. })
        ));
    }

    #[test]
    fn test_reorg_below_finality_rejected() {
        let vs = make_test_validator_set(&[(1, 70)]);
        let mut fm = EconomicFinalityManager::new(100);
        let cp = make_checkpoint(1, 100);
        fm.begin_epoch(cp.clone());
        fm.add_attestation_unchecked(make_attestation(1, 1, &cp, 70), &vs)
            .unwrap();

        // Try to reorg to score 50 (below finalized 100) → REJECTED
        let err = fm.can_reorg_to(50);
        assert!(matches!(err, Err(FinalityError::ReorgBelowFinality { .. })));

        // Reorg to score 150 (above finalized 100) → OK
        fm.can_reorg_to(150).unwrap();
    }

    #[test]
    fn test_signing_message_deterministic() {
        let cp = make_checkpoint(5, 500);
        assert_eq!(cp.signing_message(), cp.signing_message());
    }

    #[test]
    fn test_unknown_validator_rejected() {
        let vs = make_test_validator_set(&[(1, 50)]); // only validator 1
        let mut fm = EconomicFinalityManager::new(100);
        let cp = make_checkpoint(1, 100);
        fm.begin_epoch(cp.clone());

        // Validator 99 is NOT in the set
        let err = fm.add_attestation_unchecked(make_attestation(99, 1, &cp, 50), &vs);
        assert!(matches!(err, Err(FinalityError::UnknownValidator { .. })));
    }
}
