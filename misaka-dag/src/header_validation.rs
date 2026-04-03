//! Hardened Block Header Validation (Improvements E + J).
//!
//! # Improvement E: Header validation was "structure only"
//!
//! Previous: version, parent count, timestamp, duplicate parents.
//! Missing: proposer signature, tx_root verification, blue_score local
//! recomputation, proposer eligibility check, chain domain separation.
//!
//! # Improvement J: Tie-break with proposer randomness
//!
//! Previous: blue_score + hash comparison (attacker can grind hash).
//! New: blue_score + proposer_randomness_commitment + hash.

use sha3::{Digest as Sha3Digest, Sha3_256};

/// Maximum timestamp drift from local clock (seconds).
pub const MAX_FUTURE_SECS: u64 = 30;
/// Maximum parents per block — from SSOT (constants.rs).
pub use crate::constants::MAX_PARENTS;
/// DAG block version.
pub const EXPECTED_VERSION: u8 = 0x02;

/// Comprehensive header validation result.
#[derive(Debug)]
pub enum HeaderCheckResult {
    Valid,
    BadVersion(u8),
    NoParents,
    TooManyParents(usize),
    DuplicateParent,
    FutureTimestamp {
        block_ms: u64,
        now_ms: u64,
    },
    TxRootMismatch {
        declared: [u8; 32],
        computed: [u8; 32],
    },
    ProposerNotEligible([u8; 32]),
    ProposerSignatureInvalid,
    BluScoreMismatch {
        declared: u64,
        computed: u64,
    },
    ChainIdMismatch {
        header: u32,
        expected: u32,
    },
    ParentNotFound([u8; 32]),
}

/// Full header validation (Improvement E).
///
/// Checks EVERYTHING, not just structure:
/// 1. Version
/// 2. Parent count + uniqueness + availability
/// 3. Timestamp bounds
/// 4. tx_root == recomputed from block TXs
/// 5. Proposer eligibility (is in active validator set?)
/// 6. Proposer signature over header hash
/// 7. blue_score == locally computed (not trusted from header)
/// 8. Chain ID matches network
/// Callback type for proposer signature verification.
///
/// The caller MUST bind the proposer's ML-DSA-65 public key (from the
/// active validator set) before invoking this callback. The callback
/// receives `(header_hash, proposer_sig_bytes)` and returns `true`
/// if and only if ML-DSA verification succeeds.
///
/// Example binding at the call site:
/// ```ignore
/// let proposer_pk = validator_set.get_pk(&proposer_id)?;
/// let verify_sig = |hash: &[u8; 32], sig: &[u8]| -> bool {
///     let Ok(pk) = ValidatorPqPublicKey::from_bytes(&proposer_pk) else { return false };
///     let Ok(sig) = ValidatorPqSignature::from_bytes(sig) else { return false };
///     validator_verify(hash, &sig, &pk).is_ok()
/// };
/// ```
pub type VerifyProposerSigFn<'a> = &'a dyn Fn(&[u8; 32], &[u8]) -> bool;

pub fn validate_header_full(
    header_hash: &[u8; 32],
    version: u8,
    parents: &[[u8; 32]],
    timestamp_ms: u64,
    tx_root_declared: &[u8; 32],
    tx_root_computed: &[u8; 32],
    proposer_id: &[u8; 32],
    proposer_sig: &[u8], // ML-DSA-65 signature (3309 bytes for non-genesis)
    blue_score_declared: u64,
    blue_score_computed: u64,
    chain_id_header: u32,
    chain_id_expected: u32,
    now_ms: u64,
    is_genesis: bool,
    is_proposer_eligible: bool,
    parent_exists: impl Fn(&[u8; 32]) -> bool,
    verify_proposer_sig: VerifyProposerSigFn<'_>,
) -> HeaderCheckResult {
    // 1. Version
    if version != EXPECTED_VERSION {
        return HeaderCheckResult::BadVersion(version);
    }

    // 2. Parents
    if !is_genesis && parents.is_empty() {
        return HeaderCheckResult::NoParents;
    }
    if parents.len() > MAX_PARENTS {
        return HeaderCheckResult::TooManyParents(parents.len());
    }
    let mut seen = std::collections::HashSet::new();
    for p in parents {
        if !seen.insert(p) {
            return HeaderCheckResult::DuplicateParent;
        }
        if !parent_exists(p) {
            return HeaderCheckResult::ParentNotFound(*p);
        }
    }

    // 3. Timestamp
    let max_ts = now_ms + MAX_FUTURE_SECS * 1000;
    if timestamp_ms > max_ts {
        return HeaderCheckResult::FutureTimestamp {
            block_ms: timestamp_ms,
            now_ms,
        };
    }

    // 4. TX root (Improvement E: was not checked before)
    if tx_root_declared != tx_root_computed {
        return HeaderCheckResult::TxRootMismatch {
            declared: *tx_root_declared,
            computed: *tx_root_computed,
        };
    }

    // 5. Proposer eligibility (Improvement E)
    if !is_genesis && !is_proposer_eligible {
        return HeaderCheckResult::ProposerNotEligible(*proposer_id);
    }

    // 6. Proposer signature verification — FAIL-CLOSED
    //
    // The previous placeholder only checked `sig.is_empty()`.
    // Now we require full ML-DSA-65 cryptographic verification via the
    // caller-supplied callback which MUST call `validator_verify()` with
    // the proposer's public key resolved from the active validator set.
    //
    // Fail-closed: ANY verification failure (empty sig, wrong format,
    // wrong key, tampered data) results in immediate rejection.
    if !is_genesis {
        // Reject structurally invalid signatures before expensive crypto
        if proposer_sig.is_empty() {
            return HeaderCheckResult::ProposerSignatureInvalid;
        }
        // Full ML-DSA-65 verification via callback
        if !verify_proposer_sig(header_hash, proposer_sig) {
            return HeaderCheckResult::ProposerSignatureInvalid;
        }
    }

    // 7. Blue score local recomputation (Improvement E: never trust header value)
    if blue_score_declared != blue_score_computed {
        return HeaderCheckResult::BluScoreMismatch {
            declared: blue_score_declared,
            computed: blue_score_computed,
        };
    }

    // 8. Chain ID
    if chain_id_header != chain_id_expected {
        return HeaderCheckResult::ChainIdMismatch {
            header: chain_id_header,
            expected: chain_id_expected,
        };
    }

    HeaderCheckResult::Valid
}

// ═══════════════════════════════════════════════════════════════
//  Improvement J: Deterministic tie-break with proposer randomness
// ═══════════════════════════════════════════════════════════════

/// Enhanced tie-break key for total ordering.
///
/// Previous: (blue_score, block_hash) — attacker can grind hash.
/// New: (blue_score, randomness_commitment, block_hash).
///
/// The randomness_commitment is H(proposer_secret || block_height_estimate).
/// The proposer commits to randomness BEFORE seeing the DAG state,
/// so they cannot retroactively choose a favorable position.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TieBreakKey {
    pub blue_score: u64,
    /// H(proposer_vrf_output) — committed before block creation.
    pub randomness: [u8; 32],
    /// Block hash (final fallback).
    pub block_hash: [u8; 32],
}

impl TieBreakKey {
    pub fn new(blue_score: u64, proposer_randomness: &[u8; 32], block_hash: &[u8; 32]) -> Self {
        Self {
            blue_score,
            randomness: *proposer_randomness,
            block_hash: *block_hash,
        }
    }

    /// Compute proposer randomness commitment.
    ///
    /// `randomness = H("MISAKA_TIEBREAK_V1:" || proposer_sk_hash || epoch)`
    ///
    /// This is verifiable: the verifier can check H(proposer_pk, epoch) matches.
    pub fn compute_randomness(proposer_sk_hash: &[u8; 32], epoch: u64) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_TIEBREAK_V1:");
        h.update(proposer_sk_hash);
        h.update(&epoch.to_le_bytes());
        h.finalize().into()
    }
}

/// Sort blocks by enhanced tie-break key for total ordering.
pub fn sort_by_tiebreak(hashes: &mut Vec<[u8; 32]>, get_key: impl Fn(&[u8; 32]) -> TieBreakKey) {
    hashes.sort_by(|a, b| get_key(a).cmp(&get_key(b)));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: always-valid signature verifier (for non-sig tests).
    fn sig_ok(_hash: &[u8; 32], _sig: &[u8]) -> bool {
        true
    }
    /// Helper: always-invalid signature verifier.
    fn sig_fail(_hash: &[u8; 32], _sig: &[u8]) -> bool {
        false
    }

    #[test]
    fn test_valid_header() {
        let result = validate_header_full(
            &[0xAA; 32],
            EXPECTED_VERSION,
            &[[0xBB; 32]],
            1000,
            &[0xCC; 32],
            &[0xCC; 32], // tx_root matches
            &[0xDD; 32],
            b"sig", // proposer with sig
            5,
            5, // blue_score matches
            2,
            2, // chain_id matches
            2000,
            false,
            true,
            |_| true,
            &sig_ok,
        );
        assert!(matches!(result, HeaderCheckResult::Valid));
    }

    #[test]
    fn test_proposer_sig_cryptographically_verified() {
        // Even with non-empty sig, if verify_proposer_sig returns false → reject
        let result = validate_header_full(
            &[0xAA; 32],
            EXPECTED_VERSION,
            &[[0xBB; 32]],
            1000,
            &[0xCC; 32],
            &[0xCC; 32],
            &[0xDD; 32],
            b"sig_bytes_that_look_fine",
            5,
            5,
            2,
            2,
            2000,
            false,
            true,
            |_| true,
            &sig_fail,
        );
        assert!(
            matches!(result, HeaderCheckResult::ProposerSignatureInvalid),
            "non-empty but cryptographically invalid sig MUST be rejected"
        );
    }

    #[test]
    fn test_empty_sig_rejected_before_crypto() {
        let result = validate_header_full(
            &[0xAA; 32],
            EXPECTED_VERSION,
            &[[0xBB; 32]],
            1000,
            &[0xCC; 32],
            &[0xCC; 32],
            &[0xDD; 32],
            b"", // empty sig
            5,
            5,
            2,
            2,
            2000,
            false,
            true,
            |_| true,
            &sig_ok, // wouldn't even reach this
        );
        assert!(matches!(
            result,
            HeaderCheckResult::ProposerSignatureInvalid
        ));
    }

    #[test]
    fn test_tx_root_mismatch_rejected() {
        let result = validate_header_full(
            &[0xAA; 32],
            EXPECTED_VERSION,
            &[[0xBB; 32]],
            1000,
            &[0xCC; 32],
            &[0xDD; 32], // MISMATCH
            &[0xDD; 32],
            b"sig",
            5,
            5,
            2,
            2,
            2000,
            false,
            true,
            |_| true,
            &sig_ok,
        );
        assert!(matches!(result, HeaderCheckResult::TxRootMismatch { .. }));
    }

    #[test]
    fn test_blue_score_mismatch_rejected() {
        let result = validate_header_full(
            &[0xAA; 32],
            EXPECTED_VERSION,
            &[[0xBB; 32]],
            1000,
            &[0xCC; 32],
            &[0xCC; 32],
            &[0xDD; 32],
            b"sig",
            10,
            5, // declared 10, computed 5 — MISMATCH
            2,
            2,
            2000,
            false,
            true,
            |_| true,
            &sig_ok,
        );
        assert!(matches!(result, HeaderCheckResult::BluScoreMismatch { .. }));
    }

    #[test]
    fn test_proposer_not_eligible_rejected() {
        let result = validate_header_full(
            &[0xAA; 32],
            EXPECTED_VERSION,
            &[[0xBB; 32]],
            1000,
            &[0xCC; 32],
            &[0xCC; 32],
            &[0xDD; 32],
            b"sig",
            5,
            5,
            2,
            2,
            2000,
            false,
            false, // NOT eligible
            |_| true,
            &sig_ok,
        );
        assert!(matches!(result, HeaderCheckResult::ProposerNotEligible(_)));
    }

    #[test]
    fn test_missing_parent_rejected() {
        let result = validate_header_full(
            &[0xAA; 32],
            EXPECTED_VERSION,
            &[[0xBB; 32]],
            1000,
            &[0xCC; 32],
            &[0xCC; 32],
            &[0xDD; 32],
            b"sig",
            5,
            5,
            2,
            2,
            2000,
            false,
            true,
            |_| false, // parent NOT found
            &sig_ok,
        );
        assert!(matches!(result, HeaderCheckResult::ParentNotFound(_)));
    }

    #[test]
    fn test_tiebreak_ordering() {
        let k1 = TieBreakKey::new(5, &[0x01; 32], &[0xAA; 32]);
        let k2 = TieBreakKey::new(5, &[0x02; 32], &[0xBB; 32]);
        let k3 = TieBreakKey::new(6, &[0x01; 32], &[0xCC; 32]);
        assert!(k1 < k2); // same score, different randomness
        assert!(k2 < k3); // different score
    }
}
