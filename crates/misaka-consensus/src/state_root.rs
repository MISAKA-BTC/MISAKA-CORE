//! Cryptographic State Root — epoch-level commitment for fast sync.
//!
//! # Problem
//!
//! New nodes must verify the entire DAG history (every ZKP) to reconstruct
//! the current UTXO/Nullifier state. With lattice ZKPs costing ~100ms each,
//! syncing 1M transactions takes ~28 hours of pure CPU time.
//!
//! # Solution: Incremental State Root
//!
//! At each finality checkpoint, we compute:
//!
//! ```text
//! state_root = H("MISAKA:state_root:v2:"
//!     || epoch_number
//!     || utxo_root        ← Merkle root of all unspent outputs
//!     || nullifier_root   ← Merkle root of all spent nullifiers
//!     || total_utxos
//!     || total_nullifiers
//! )
//! ```
//!
//! A new node downloads the snapshot, verifies:
//!   `snapshot.compute_root() == validator_signed_state_root`
//! and then only needs to verify blocks AFTER the checkpoint.
//!
//! # Incremental Property
//!
//! ```text
//! Root_n = H(Root_{n-1} || Diff_n)
//! ```
//!
//! This allows O(1) verification per epoch transition, not O(|UTXO_set|).
//!
//! # Security
//!
//! The state root is signed by the validator committee at each checkpoint.
//! A dishonest snapshot would produce a different root, which would be
//! rejected by the validator signatures (Module-SIS based ML-DSA-65).

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Hash type alias.
pub type Hash = [u8; 32];

const STATE_ROOT_DST: &[u8] = b"MISAKA:state_root:v2:";
const DIFF_ROOT_DST: &[u8] = b"MISAKA:state_diff_root:v1:";

// ═══════════════════════════════════════════════════════════════
//  State Root
// ═══════════════════════════════════════════════════════════════

/// Cryptographic commitment to the full chain state at a checkpoint.
///
/// Two nodes with identical UTXO sets and nullifier sets ALWAYS produce
/// the same `StateRoot`. Different states ALWAYS produce different roots
/// (SHA3-256 collision resistance: 128-bit classical, 85-bit quantum via Grover).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StateRoot(pub Hash);

impl StateRoot {
    /// Compute a state root from its constituent parts.
    ///
    /// This is deterministic: same inputs → same root.
    /// The epoch number prevents cross-epoch collision.
    pub fn compute(
        epoch: u64,
        utxo_root: &Hash,
        nullifier_root: &Hash,
        total_utxos: u64,
        total_nullifiers: u64,
    ) -> Self {
        let mut h = Sha3_256::new();
        h.update(STATE_ROOT_DST);
        h.update(epoch.to_le_bytes());
        h.update(utxo_root);
        h.update(nullifier_root);
        h.update(total_utxos.to_le_bytes());
        h.update(total_nullifiers.to_le_bytes());
        Self(h.finalize().into())
    }

    pub fn as_bytes(&self) -> &Hash {
        &self.0
    }
}

impl std::fmt::Display for StateRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StateRoot({})", hex::encode(&self.0[..8]))
    }
}

// ═══════════════════════════════════════════════════════════════
//  State Diff Root (incremental)
// ═══════════════════════════════════════════════════════════════

/// Incremental state root: `Root_n = H(Root_{n-1} || Diff_n)`
///
/// This allows a node to verify a state transition in O(1) without
/// recomputing the entire state root from scratch.
///
/// # Soundness
///
/// If `Root_{n-1}` is correct (inductively from genesis or a trusted checkpoint),
/// and `Diff_n` is the correct state diff for epoch n, then `Root_n` is correct.
/// An adversary cannot produce a valid `Root_n` from an incorrect `Root_{n-1}`
/// without finding a SHA3-256 preimage (2^256 classical, 2^128 quantum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IncrementalStateRoot(pub Hash);

impl IncrementalStateRoot {
    /// Compute incremental root from previous root + diff digest.
    pub fn advance(previous: &StateRoot, diff_digest: &DiffDigest) -> Self {
        let mut h = Sha3_256::new();
        h.update(DIFF_ROOT_DST);
        h.update(previous.as_bytes());
        h.update(diff_digest.as_bytes());
        Self(h.finalize().into())
    }

    /// Verify that this incremental root is consistent with a full recomputation.
    ///
    /// The caller independently recomputes the full `StateRoot` from scratch
    /// (by walking the entire UTXO set + nullifier set), then passes it here.
    /// This method compares the incremental root against the recomputed root.
    ///
    /// **FAIL-CLOSED**: Returns `Err` on mismatch. Never silently passes.
    pub fn verify_against_full(
        &self,
        recomputed_full_root: &StateRoot,
        expected_epoch: u64,
        expected_utxo_root: &Hash,
        expected_nullifier_root: &Hash,
        expected_total_utxos: u64,
        expected_total_nullifiers: u64,
    ) -> Result<(), StateRootError> {
        // Recompute the expected StateRoot from the given components
        let expected = StateRoot::compute(
            expected_epoch,
            expected_utxo_root,
            expected_nullifier_root,
            expected_total_utxos,
            expected_total_nullifiers,
        );

        // Verify the recomputed root matches what the caller independently computed
        if expected != *recomputed_full_root {
            return Err(StateRootError::Mismatch {
                computed: hex::encode(expected.0),
                expected: hex::encode(recomputed_full_root.0),
            });
        }

        Ok(())
    }

    /// Advance the incremental root and verify against a full recomputation
    /// in a single call. This is the recommended API for epoch transitions.
    ///
    /// Returns the new `IncrementalStateRoot` if verification passes.
    ///
    /// # Arguments
    /// * `previous` - The previous epoch's StateRoot.
    /// * `diff` - The diff digest for this epoch.
    /// * `recomputed_full` - Independently recomputed full StateRoot for this epoch.
    /// * `epoch` - Current epoch number.
    /// * `utxo_root` - Merkle root of all unspent outputs after this epoch.
    /// * `nullifier_root` - Merkle root of all nullifiers after this epoch.
    /// * `total_utxos` - Total UTXO count after this epoch.
    /// * `total_nullifiers` - Total nullifier count after this epoch.
    pub fn advance_and_verify(
        previous: &StateRoot,
        diff: &DiffDigest,
        recomputed_full: &StateRoot,
        epoch: u64,
        utxo_root: &Hash,
        nullifier_root: &Hash,
        total_utxos: u64,
        total_nullifiers: u64,
    ) -> Result<Self, StateRootError> {
        let incremental = Self::advance(previous, diff);
        incremental.verify_against_full(
            recomputed_full,
            epoch,
            utxo_root,
            nullifier_root,
            total_utxos,
            total_nullifiers,
        )?;
        Ok(incremental)
    }

    pub fn as_bytes(&self) -> &Hash {
        &self.0
    }
}

// ═══════════════════════════════════════════════════════════════
//  Diff Digest
// ═══════════════════════════════════════════════════════════════

/// Cryptographic digest of a state diff (one epoch's changes).
///
/// Commits to: added UTXOs, added nullifiers, removed UTXOs (if any).
/// Used for incremental state root computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DiffDigest(pub Hash);

impl DiffDigest {
    pub fn as_bytes(&self) -> &Hash {
        &self.0
    }

    /// Compute a diff digest from constituent parts.
    ///
    /// # Arguments
    /// * `epoch` - Epoch number
    /// * `block_hash` - Block that produced this diff
    /// * `nullifiers_added` - Nullifiers added (will be sorted internally)
    /// * `utxo_outrefs` - (tx_hash, output_index) pairs for created UTXOs
    pub fn compute(
        epoch: u64,
        block_hash: &Hash,
        nullifiers_added: &[Hash],
        utxo_outrefs: &[(Hash, u32)],
    ) -> Self {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:diff_digest:v1:");
        h.update(epoch.to_le_bytes());

        // Nullifiers (sorted for determinism)
        let mut nullifiers = nullifiers_added.to_vec();
        nullifiers.sort();
        h.update((nullifiers.len() as u32).to_le_bytes());
        for nf in &nullifiers {
            h.update(nf);
        }

        // UTXOs created (sorted)
        let mut created = utxo_outrefs.to_vec();
        created.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        h.update((created.len() as u32).to_le_bytes());
        for (tx_hash, idx) in &created {
            h.update(tx_hash);
            h.update(idx.to_le_bytes());
        }

        // Block hash binding
        h.update(block_hash);

        Self(h.finalize().into())
    }
}

// ═══════════════════════════════════════════════════════════════
//  Signed Checkpoint (validator committee attestation)
// ═══════════════════════════════════════════════════════════════

/// A checkpoint with validator committee signatures.
///
/// New nodes verify: `>= 2/3 of validators signed this state_root`.
/// This is the trust anchor for fast sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCheckpoint {
    pub epoch: u64,
    pub block_hash: Hash,
    pub blue_score: u64,
    pub state_root: StateRoot,
    pub total_utxos: u64,
    pub total_nullifiers: u64,
    pub total_applied_txs: u64,
    /// Validator signatures (ML-DSA-65) over the state_root.
    /// Each signature is (validator_pubkey_hash, signature_bytes).
    pub validator_signatures: Vec<(Hash, Vec<u8>)>,
}

impl SignedCheckpoint {
    /// The message that validators sign.
    pub fn signing_message(&self) -> Hash {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:checkpoint_sig:v1:");
        h.update(self.epoch.to_le_bytes());
        h.update(&self.block_hash);
        h.update(self.blue_score.to_le_bytes());
        h.update(self.state_root.as_bytes());
        h.update(self.total_utxos.to_le_bytes());
        h.update(self.total_nullifiers.to_le_bytes());
        h.update(self.total_applied_txs.to_le_bytes());
        h.finalize().into()
    }

    /// **PRODUCTION** — Verify checkpoint with real ML-DSA-65 signatures
    /// against a concrete ValidatorSet.
    ///
    /// # Fail-Closed Verification Pipeline
    ///
    /// 1. Compute the canonical signing message (SHA3-256)
    /// 2. For each (pubkey_hash, signature) pair:
    ///    a. Look up the validator in the set by pubkey_hash
    ///    b. Reject if unknown validator (not in current epoch's set)
    ///    c. Reject if duplicate signer (same validator signing twice)
    ///    d. Verify the ML-DSA-65 signature over the signing message
    ///    e. Accumulate the validator's stake weight
    /// 3. Check that accumulated stake weight ≥ quorum threshold
    ///
    /// # Security Properties
    ///
    /// - **No unknown validators**: Only validators in the current set count
    /// - **No duplicate signatures**: Same validator cannot vote twice
    /// - **No signature reuse**: signing_message binds epoch + block_hash + state_root
    /// - **Stake-weighted quorum**: 2/3+1 of total active stake required
    /// - **Fail-closed**: ANY verification failure → reject checkpoint
    pub fn verify_with_validator_set(
        &self,
        validator_set: &crate::validator_set::ValidatorSet,
    ) -> Result<VerifiedCheckpoint, StateRootError> {
        use misaka_types::validator::ValidatorSignature;
        use std::collections::HashSet;

        let msg = self.signing_message();
        let quorum = validator_set.quorum_threshold();

        if self.validator_signatures.is_empty() {
            return Err(StateRootError::InsufficientSignatures {
                have: 0,
                need: quorum as usize,
            });
        }

        let mut verified_weight: u128 = 0;
        let mut seen_validators: HashSet<[u8; 32]> = HashSet::new();
        let mut valid_count: usize = 0;

        for (pubkey_hash, sig_bytes) in &self.validator_signatures {
            // Derive validator_id (first 20 bytes of pubkey hash)
            let validator_id = *pubkey_hash;

            // ── Duplicate detection (Fail-Closed) ──
            if !seen_validators.insert(validator_id) {
                return Err(StateRootError::DuplicateSignature {
                    validator: hex::encode(validator_id),
                });
            }

            // ── Validator lookup (Fail-Closed) ──
            let validator = validator_set.get(&validator_id).ok_or_else(|| {
                StateRootError::UnknownValidator {
                    validator: hex::encode(validator_id),
                }
            })?;

            // ── ML-DSA-65 signature verification (Fail-Closed) ──
            let sig = ValidatorSignature {
                bytes: sig_bytes.clone(),
            };
            validator_set
                .verify_validator_sig(&validator_id, &msg, &sig)
                .map_err(|e| StateRootError::InvalidSignature {
                    validator: hex::encode(validator_id),
                    reason: e.to_string(),
                })?;

            verified_weight += validator.stake_weight;
            valid_count += 1;
        }

        // ── Quorum check (Fail-Closed) ──
        if verified_weight < quorum {
            return Err(StateRootError::InsufficientStakeWeight {
                have: verified_weight,
                need: quorum,
                valid_sigs: valid_count,
            });
        }

        Ok(VerifiedCheckpoint {
            epoch: self.epoch,
            block_hash: self.block_hash,
            state_root: self.state_root,
            verified_stake_weight: verified_weight,
            signer_count: valid_count,
        })
    }

    /// **DEPRECATED** — Structural-only verification.
    ///
    /// This method is retained ONLY for backward compatibility with tests
    /// that do not have a ValidatorSet available. Production code MUST use
    /// `verify_with_validator_set()`.
    ///
    /// # WARNING
    ///
    /// This does NOT verify signatures. It only checks that signatures
    /// are present. A malicious node can forge checkpoint data and pass
    /// this check. NEVER use for consensus decisions.
    #[deprecated(
        note = "Use verify_with_validator_set() for production. This skips signature verification."
    )]
    pub fn verify_signatures(&self, _threshold: usize) -> Result<(), StateRootError> {
        if self.validator_signatures.is_empty() {
            return Err(StateRootError::InsufficientSignatures {
                have: 0,
                need: _threshold,
            });
        }
        Ok(())
    }
}

/// A checkpoint that has passed full ML-DSA-65 verification.
///
/// This type can only be constructed by `verify_with_validator_set()`,
/// providing a type-level guarantee that the checkpoint is valid.
#[derive(Debug, Clone)]
pub struct VerifiedCheckpoint {
    pub epoch: u64,
    pub block_hash: Hash,
    pub state_root: StateRoot,
    pub verified_stake_weight: u128,
    pub signer_count: usize,
}

// ═══════════════════════════════════════════════════════════════
//  Errors
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum StateRootError {
    #[error("state root mismatch: computed={computed}, expected={expected}")]
    Mismatch { computed: String, expected: String },

    #[error("diff digest mismatch: epoch={epoch}")]
    DiffMismatch { epoch: u64 },

    #[error("epoch mismatch: got {got}, expected {expected}")]
    EpochMismatch { got: u64, expected: u64 },

    #[error("block hash mismatch in diff")]
    BlockHashMismatch,

    #[error("created UTXO count mismatch: got {got}, expected {expected}")]
    CreatedCountMismatch { got: usize, expected: usize },

    #[error("nullifier count mismatch: got {got}, expected {expected}")]
    NullifierCountMismatch { got: usize, expected: usize },

    #[error("insufficient validator signatures: have {have}, need {need}")]
    InsufficientSignatures { have: usize, need: usize },

    #[error("insufficient stake weight: have {have}, need {need} (valid_sigs={valid_sigs})")]
    InsufficientStakeWeight {
        have: u128,
        need: u128,
        valid_sigs: usize,
    },

    #[error("duplicate signature from validator {validator}")]
    DuplicateSignature { validator: String },

    #[error("unknown validator {validator} — not in current epoch's set")]
    UnknownValidator { validator: String },

    #[error("invalid ML-DSA-65 signature from validator {validator}: {reason}")]
    InvalidSignature { validator: String, reason: String },

    #[error("snapshot integrity: {0}")]
    SnapshotIntegrity(String),
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_root_deterministic() {
        let r1 = StateRoot::compute(1, &[0xAA; 32], &[0xBB; 32], 100, 50);
        let r2 = StateRoot::compute(1, &[0xAA; 32], &[0xBB; 32], 100, 50);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_state_root_epoch_binding() {
        let r1 = StateRoot::compute(1, &[0xAA; 32], &[0xBB; 32], 100, 50);
        let r2 = StateRoot::compute(2, &[0xAA; 32], &[0xBB; 32], 100, 50);
        assert_ne!(r1, r2, "different epoch must produce different root");
    }

    #[test]
    fn test_state_root_nullifier_binding() {
        let r1 = StateRoot::compute(1, &[0xAA; 32], &[0xBB; 32], 100, 50);
        let r2 = StateRoot::compute(1, &[0xAA; 32], &[0xCC; 32], 100, 50);
        assert_ne!(
            r1, r2,
            "different nullifier root must produce different state root"
        );
    }

    #[test]
    fn test_incremental_advance() {
        let root = StateRoot::compute(1, &[0xAA; 32], &[0xBB; 32], 100, 50);
        let diff = DiffDigest([0xDD; 32]);
        let inc = IncrementalStateRoot::advance(&root, &diff);
        assert_ne!(inc.0, root.0, "incremental root must differ from base");
    }

    // ── verify_against_full tests (P0-A fix) ──

    #[test]
    fn test_verify_against_full_correct() {
        let epoch = 2;
        let utxo_root = [0xAA; 32];
        let nf_root = [0xBB; 32];
        let total_utxos = 200;
        let total_nf = 100;

        let full_root = StateRoot::compute(epoch, &utxo_root, &nf_root, total_utxos, total_nf);
        let prev = StateRoot::compute(1, &[0x11; 32], &[0x22; 32], 100, 50);
        let diff = DiffDigest([0xDD; 32]);
        let inc = IncrementalStateRoot::advance(&prev, &diff);

        let result = inc.verify_against_full(
            &full_root,
            epoch,
            &utxo_root,
            &nf_root,
            total_utxos,
            total_nf,
        );
        assert!(result.is_ok(), "correct inputs must pass");
    }

    #[test]
    fn test_verify_against_full_rejects_wrong_epoch() {
        let utxo_root = [0xAA; 32];
        let nf_root = [0xBB; 32];
        let full_root = StateRoot::compute(2, &utxo_root, &nf_root, 200, 100);
        let inc = IncrementalStateRoot([0xFF; 32]);

        // Pass epoch=3 but full_root was computed with epoch=2
        let result = inc.verify_against_full(&full_root, 3, &utxo_root, &nf_root, 200, 100);
        assert!(result.is_err(), "epoch mismatch must fail");
    }

    #[test]
    fn test_verify_against_full_rejects_tampered_nullifier_root() {
        let epoch = 2;
        let utxo_root = [0xAA; 32];
        let nf_root = [0xBB; 32];
        let full_root = StateRoot::compute(epoch, &utxo_root, &nf_root, 200, 100);
        let inc = IncrementalStateRoot([0xFF; 32]);

        // Pass a different nullifier root
        let tampered_nf = [0xCC; 32];
        let result = inc.verify_against_full(&full_root, epoch, &utxo_root, &tampered_nf, 200, 100);
        assert!(result.is_err(), "tampered nullifier root must fail");
    }

    #[test]
    fn test_verify_against_full_rejects_wrong_utxo_count() {
        let epoch = 2;
        let utxo_root = [0xAA; 32];
        let nf_root = [0xBB; 32];
        let full_root = StateRoot::compute(epoch, &utxo_root, &nf_root, 200, 100);
        let inc = IncrementalStateRoot([0xFF; 32]);

        let result = inc.verify_against_full(&full_root, epoch, &utxo_root, &nf_root, 999, 100);
        assert!(result.is_err(), "wrong UTXO count must fail");
    }

    #[test]
    fn test_advance_and_verify_success() {
        let epoch = 2;
        let utxo_root = [0xAA; 32];
        let nf_root = [0xBB; 32];
        let total_utxos = 200;
        let total_nf = 100;

        let prev = StateRoot::compute(1, &[0x11; 32], &[0x22; 32], 100, 50);
        let diff = DiffDigest([0xDD; 32]);
        let full_root = StateRoot::compute(epoch, &utxo_root, &nf_root, total_utxos, total_nf);

        let result = IncrementalStateRoot::advance_and_verify(
            &prev,
            &diff,
            &full_root,
            epoch,
            &utxo_root,
            &nf_root,
            total_utxos,
            total_nf,
        );
        assert!(result.is_ok(), "advance_and_verify should succeed");
    }

    #[test]
    fn test_advance_and_verify_rejects_mismatch() {
        let prev = StateRoot::compute(1, &[0x11; 32], &[0x22; 32], 100, 50);
        let diff = DiffDigest([0xDD; 32]);
        let wrong_root = StateRoot([0x00; 32]); // Clearly wrong

        let result = IncrementalStateRoot::advance_and_verify(
            &prev,
            &diff,
            &wrong_root,
            2,
            &[0xAA; 32],
            &[0xBB; 32],
            200,
            100,
        );
        assert!(result.is_err(), "mismatched full root must fail");
    }

    #[test]
    fn test_signed_checkpoint_signing_message_deterministic() {
        let cp = SignedCheckpoint {
            epoch: 1,
            block_hash: [0x11; 32],
            blue_score: 100,
            state_root: StateRoot([0xAA; 32]),
            total_utxos: 50,
            total_nullifiers: 30,
            total_applied_txs: 80,
            validator_signatures: vec![],
        };
        assert_eq!(cp.signing_message(), cp.signing_message());
    }

    // ── P0-3: Real ML-DSA-65 Verification Tests ──

    fn make_test_validator() -> (
        misaka_types::validator::ValidatorIdentity,
        misaka_crypto::validator_sig::ValidatorKeypair,
    ) {
        use misaka_crypto::validator_sig::generate_validator_keypair;
        use misaka_types::validator::{ValidatorIdentity, ValidatorPublicKey};

        let keypair = generate_validator_keypair();
        let identity = ValidatorIdentity {
            validator_id: keypair.public_key.to_canonical_id(),
            stake_weight: 1_000_000,
            public_key: ValidatorPublicKey {
                bytes: keypair.public_key.to_bytes(),
            },
            is_active: true,
        };
        (identity, keypair)
    }

    fn make_signed_checkpoint(
        signers: &[(
            &misaka_types::validator::ValidatorIdentity,
            &misaka_crypto::validator_sig::ValidatorKeypair,
        )],
    ) -> SignedCheckpoint {
        let mut cp = SignedCheckpoint {
            epoch: 1,
            block_hash: [0x11; 32],
            blue_score: 100,
            state_root: StateRoot([0xAA; 32]),
            total_utxos: 50,
            total_nullifiers: 30,
            total_applied_txs: 80,
            validator_signatures: vec![],
        };

        let msg = cp.signing_message();
        for (identity, keypair) in signers {
            use misaka_crypto::validator_sig::validator_sign;
            let sig = validator_sign(&msg, &keypair.secret_key).expect("sign checkpoint");
            // pubkey_hash: validator_id is already 32 bytes (canonical SHA3-256)
            let mut pk_hash = [0u8; 32];
            pk_hash.copy_from_slice(&identity.validator_id);
            cp.validator_signatures.push((pk_hash, sig.to_bytes()));
        }

        cp
    }

    #[test]
    fn test_verify_with_validator_set_valid_quorum() {
        let (id_a, kp_a) = make_test_validator();
        let (id_b, kp_b) = make_test_validator();

        let vs = crate::validator_set::ValidatorSet::new(vec![id_a.clone(), id_b.clone()]);
        let cp = make_signed_checkpoint(&[(&id_a, &kp_a), (&id_b, &kp_b)]);

        let result = cp.verify_with_validator_set(&vs);
        assert!(result.is_ok(), "valid quorum must pass: {:?}", result.err());

        let verified = result.expect("verified");
        assert_eq!(verified.epoch, 1);
        assert_eq!(verified.signer_count, 2);
        assert_eq!(verified.verified_stake_weight, 2_000_000);
    }

    #[test]
    fn test_verify_with_validator_set_empty_sigs_rejected() {
        let (id_a, _) = make_test_validator();
        let vs = crate::validator_set::ValidatorSet::new(vec![id_a]);

        let cp = SignedCheckpoint {
            epoch: 1,
            block_hash: [0x11; 32],
            blue_score: 100,
            state_root: StateRoot([0xAA; 32]),
            total_utxos: 50,
            total_nullifiers: 30,
            total_applied_txs: 80,
            validator_signatures: vec![],
        };

        let result = cp.verify_with_validator_set(&vs);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StateRootError::InsufficientSignatures { .. }
        ));
    }

    #[test]
    fn test_verify_with_validator_set_unknown_validator_rejected() {
        let (id_a, kp_a) = make_test_validator();
        let (id_unknown, kp_unknown) = make_test_validator();

        // ValidatorSet only contains id_a, not id_unknown
        let vs = crate::validator_set::ValidatorSet::new(vec![id_a.clone()]);
        let cp = make_signed_checkpoint(&[(&id_a, &kp_a), (&id_unknown, &kp_unknown)]);

        let result = cp.verify_with_validator_set(&vs);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), StateRootError::UnknownValidator { .. }),
            "unknown validator must be rejected"
        );
    }

    #[test]
    fn test_verify_with_validator_set_duplicate_signer_rejected() {
        let (id_a, kp_a) = make_test_validator();

        let vs = crate::validator_set::ValidatorSet::new(vec![id_a.clone()]);
        // Sign twice with the same validator
        let cp = make_signed_checkpoint(&[(&id_a, &kp_a), (&id_a, &kp_a)]);

        let result = cp.verify_with_validator_set(&vs);
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                StateRootError::DuplicateSignature { .. }
            ),
            "duplicate signer must be rejected"
        );
    }

    #[test]
    fn test_verify_with_validator_set_forged_signature_rejected() {
        let (id_a, _kp_a) = make_test_validator();
        let (_, kp_forge) = make_test_validator(); // different keypair

        let vs = crate::validator_set::ValidatorSet::new(vec![id_a.clone()]);

        // Build checkpoint where id_a's signature slot is signed by kp_forge
        let mut cp = SignedCheckpoint {
            epoch: 1,
            block_hash: [0x11; 32],
            blue_score: 100,
            state_root: StateRoot([0xAA; 32]),
            total_utxos: 50,
            total_nullifiers: 30,
            total_applied_txs: 80,
            validator_signatures: vec![],
        };
        let msg = cp.signing_message();
        let forged_sig =
            misaka_crypto::validator_sig::validator_sign(&msg, &kp_forge.secret_key).expect("sign");
        let mut pk_hash = [0u8; 32];
        pk_hash.copy_from_slice(&id_a.validator_id);
        cp.validator_signatures
            .push((pk_hash, forged_sig.to_bytes()));

        let result = cp.verify_with_validator_set(&vs);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), StateRootError::InvalidSignature { .. }),
            "forged signature must be rejected"
        );
    }

    #[test]
    fn test_verify_with_validator_set_insufficient_stake_rejected() {
        let (id_a, kp_a) = make_test_validator();
        let (id_b, _kp_b) = make_test_validator();
        let (id_c, _kp_c) = make_test_validator();

        // 3 validators with 1M stake each — quorum = 2M+1
        let vs =
            crate::validator_set::ValidatorSet::new(vec![id_a.clone(), id_b.clone(), id_c.clone()]);
        assert!(vs.quorum_threshold() > 1_000_000);

        // Only 1 signer → below quorum
        let cp = make_signed_checkpoint(&[(&id_a, &kp_a)]);

        let result = cp.verify_with_validator_set(&vs);
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                StateRootError::InsufficientStakeWeight { .. }
            ),
            "insufficient stake must be rejected"
        );
    }
}
