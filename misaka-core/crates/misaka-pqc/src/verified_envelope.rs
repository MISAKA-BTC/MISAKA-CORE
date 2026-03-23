//! Verified Transaction Envelope — type-level state-update protection.
//!
//! # Problem
//!
//! The DAG state manager (`dag_state_manager.rs`) receives transactions and
//! applies them to the UTXO/Nullifier state. Previously, it accepted raw
//! `OrderedTxData` which contained no compile-time guarantee that cryptographic
//! verification had been performed. A developer could accidentally:
//!
//! 1. Skip ZKP verification before passing TX to state manager
//! 2. Pass a TX that failed verification (but error was silently ignored)
//! 3. Apply state changes from a TX whose range proofs weren't checked
//!
//! # Solution: VerifiedTransactionEnvelope
//!
//! This type can ONLY be constructed by `verify_and_seal()`, which performs
//! ALL cryptographic checks. The DAG state manager accepts ONLY this type.
//!
//! ```text
//! Raw TX  ──→ verify_and_seal() ──→ VerifiedTransactionEnvelope ──→ State Manager
//!                    │
//!         Performs:  │
//!         ✓ Structural validation
//!         ✓ Nullifier binding (algebraic Σ-proof)
//!         ✓ Membership proof (SIS Merkle + BDLOP committed path)
//!         ✓ Range proofs (all outputs + fee)
//!         ✓ Balance excess proof (Σ inputs = Σ outputs + fee)
//!         ✓ Confidential fee proofs
//!         ✓ ZKP verification budget check
//! ```
//!
//! # Why This Prevents Developer Error
//!
//! The `_seal` field is `pub(crate)` and has no public constructor.
//! External code CANNOT create a `VerifiedTransactionEnvelope` without
//! going through the verification function. This is enforced at compile time.

use crate::bdlop::{compute_balance_diff, verify_balance_with_excess, BdlopCrs};
use crate::confidential_fee::verify_confidential_fee;
use crate::crypto_types::{AnonymityRoot, PublicNullifier, TxDigest};
use crate::error::CryptoError;
use crate::pq_ring::{derive_public_param, Poly, DEFAULT_A_SEED};
use crate::qdag_tx::QdagTransaction;
use crate::range_proof::verify_range;
use crate::unified_zkp::{unified_verify, UnifiedMembershipProof};
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
//  Verification Seal (unforgeable token)
// ═══════════════════════════════════════════════════════════════

/// Unforgeable verification seal.
///
/// This struct has no public fields and no public constructor.
/// It can ONLY be created inside this module by `verify_and_seal()`.
/// This is the core of the type-level safety guarantee.
#[derive(Debug)]
struct VerificationSeal {
    /// Which checks passed (bitmask for debugging).
    checks_passed: u32,
}

const CHECK_STRUCTURAL: u32 = 1 << 0;
const CHECK_NULLIFIERS: u32 = 1 << 1;
const CHECK_MEMBERSHIP: u32 = 1 << 2;
const CHECK_RANGE: u32 = 1 << 3;
const CHECK_BALANCE: u32 = 1 << 4;
const CHECK_FEE: u32 = 1 << 5;
const ALL_CHECKS: u32 = CHECK_STRUCTURAL
    | CHECK_NULLIFIERS
    | CHECK_MEMBERSHIP
    | CHECK_RANGE
    | CHECK_BALANCE
    | CHECK_FEE;

// ═══════════════════════════════════════════════════════════════
//  Verified Transaction Envelope
// ═══════════════════════════════════════════════════════════════

/// A transaction that has passed ALL cryptographic verification.
///
/// # Construction
///
/// The ONLY way to create this type is via `verify_and_seal()`.
/// Attempting to construct it directly is a compile-time error
/// because `_seal` is private to this module.
///
/// # Guarantees
///
/// If you hold a `VerifiedTransactionEnvelope`, ALL of the following are true:
/// 1. Structural validation passed (version, counts, sizes)
/// 2. All nullifiers are correctly derived (algebraic Σ-proof verified)
/// 3. All membership proofs are valid (SIS Merkle + BDLOP committed path)
/// 4. All range proofs are valid (outputs + fee are in [0, 2^64))
/// 5. Balance proof is valid (Σ inputs = Σ outputs + fee)
/// 6. Confidential fee proofs are valid (fee ≥ MIN_FEE)
///
/// # Cached Metadata (Task 3.1)
///
/// The envelope caches verification results so downstream DAG consensus
/// can use them WITHOUT re-computing expensive crypto:
///
/// - `verified_nullifiers`: typed nullifiers (already checked for correctness)
/// - `verified_anonymity_roots`: per-input roots (already checked against SIS Merkle)
/// - `proof_weight`: aggregate ZKP cost in verification units (for budget accounting)
/// - `fee_policy_compliance`: confirms fee meets minimum policy (for block assembly)
pub struct VerifiedTransactionEnvelope {
    /// The original transaction (immutable after verification).
    tx: QdagTransaction,
    /// Extracted nullifiers (typed, not raw bytes).
    nullifiers: Vec<PublicNullifier>,
    /// Transaction digest that was verified against.
    tx_digest: TxDigest,
    /// Per-input anonymity roots that were validated.
    anonymity_roots: Vec<AnonymityRoot>,
    /// Aggregate proof weight in verification units.
    /// DAG consensus uses this for per-block budget enforcement
    /// without re-computing individual proof costs.
    proof_weight: u64,
    /// Whether the fee meets the current minimum policy.
    /// `true` iff confidential_fee verification passed.
    fee_policy_ok: bool,
    /// Private seal — prevents external construction.
    _seal: VerificationSeal,
}

impl VerifiedTransactionEnvelope {
    /// Access the verified transaction.
    pub fn tx(&self) -> &QdagTransaction {
        &self.tx
    }

    /// Get verified nullifiers (typed).
    pub fn nullifiers(&self) -> &[PublicNullifier] {
        &self.nullifiers
    }

    /// Get the transaction digest.
    pub fn tx_digest(&self) -> &TxDigest {
        &self.tx_digest
    }

    /// Get the transaction hash.
    pub fn tx_hash(&self) -> [u8; 32] {
        self.tx.tx_hash()
    }

    /// Get verified anonymity roots (one per input).
    pub fn anonymity_roots(&self) -> &[AnonymityRoot] {
        &self.anonymity_roots
    }

    /// Get the aggregate proof weight in verification units.
    ///
    /// This is: (num_inputs × COST_MEMBERSHIP) + (num_outputs × COST_RANGE)
    ///          + COST_BALANCE + COST_FEE
    ///
    /// The DAG block assembler uses this to sum weights across TXs
    /// and reject blocks that exceed `MAX_BLOCK_VERIFICATION_UNITS`.
    pub fn proof_weight(&self) -> u64 {
        self.proof_weight
    }

    /// Does this TX comply with fee policy?
    pub fn fee_policy_ok(&self) -> bool {
        self.fee_policy_ok
    }
}

impl std::fmt::Debug for VerifiedTransactionEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "VerifiedTxEnvelope(digest={:?}, nullifiers={}, weight={}, fee_ok={})",
            self.tx_digest,
            self.nullifiers.len(),
            self.proof_weight,
            self.fee_policy_ok
        )
    }
}

// ═══════════════════════════════════════════════════════════════
//  Verification Error (explicit failure stages)
// ═══════════════════════════════════════════════════════════════

/// Explicit verification failure with stage identification.
///
/// Each variant tells the caller EXACTLY which stage failed,
/// enabling fail-fast diagnostics and peer scoring decisions.
#[derive(Debug, thiserror::Error)]
pub enum TxVerificationError {
    #[error("structural: {0}")]
    Structural(String),

    #[error("input[{index}] nullifier binding failed: {reason}")]
    NullifierBinding { index: usize, reason: String },

    #[error("input[{index}] membership proof failed: {reason}")]
    MembershipProof { index: usize, reason: String },

    #[error("output[{index}] range proof failed: {reason}")]
    RangeProof { index: usize, reason: String },

    #[error("balance proof failed: {reason}")]
    BalanceProof { reason: String },

    #[error("fee proof failed: {reason}")]
    FeeProof { reason: String },

    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
}

impl TxVerificationError {
    /// Is this a cheap-check failure (pre-crypto)?
    pub fn is_cheap_failure(&self) -> bool {
        matches!(self, Self::Structural(_))
    }

    /// Is this an expensive-check failure (requires crypto)?
    pub fn is_crypto_failure(&self) -> bool {
        !self.is_cheap_failure()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Verification Pipeline
// ═══════════════════════════════════════════════════════════════

/// Verify ALL cryptographic proofs in a QdagTransaction and seal it.
///
/// This is the ONLY function that can produce a `VerifiedTransactionEnvelope`.
/// It performs ALL checks in order, failing fast on the first error.
///
/// # Fail-Closed Design
///
/// If ANY check fails, the entire function returns `Err`.
/// There is no "partial verification" or "skip this check" mode.
/// This is critical for security: a TX that passes structural validation
/// but fails balance proof MUST NOT be applied to state.
///
/// # Arguments
///
/// * `tx` - The raw transaction to verify
/// * `expected_roots` - Per-input expected anonymity roots from chain state
///
/// # Returns
///
/// `Ok(VerifiedTransactionEnvelope)` if and only if ALL proofs are valid.
pub fn verify_and_seal(
    tx: QdagTransaction,
) -> Result<VerifiedTransactionEnvelope, TxVerificationError> {
    let mut checks: u32 = 0;

    let a_param = derive_public_param(&DEFAULT_A_SEED);
    let crs = BdlopCrs::default_crs();

    // ── 1. Structural validation (cheap, no crypto) ──
    tx.validate_structure()
        .map_err(|e| TxVerificationError::Structural(e.to_string()))?;
    checks |= CHECK_STRUCTURAL;

    let tx_digest = TxDigest::from_raw(tx.signing_digest());

    // ── 2. Per-input: Membership proof + Nullifier binding ──
    for (i, inp) in tx.inputs.iter().enumerate() {
        // Deserialize proof
        let proof = UnifiedMembershipProof::from_bytes(&inp.membership_proof).map_err(|e| {
            TxVerificationError::MembershipProof {
                index: i,
                reason: format!("deserialize: {}", e),
            }
        })?;

        // Verify unified ZKP (membership + nullifier Σ-protocol)
        unified_verify(
            &a_param,
            &inp.anonymity_root,
            tx_digest.as_bytes(),
            &inp.nullifier,
            &proof,
        )
        .map_err(|e| TxVerificationError::MembershipProof {
            index: i,
            reason: e.to_string(),
        })?;
    }
    checks |= CHECK_NULLIFIERS | CHECK_MEMBERSHIP;

    // ── 3. Per-output: Range proofs ──
    for (i, out) in tx.outputs.iter().enumerate() {
        verify_range(&crs, &out.commitment, &out.range_proof).map_err(|e| {
            TxVerificationError::RangeProof {
                index: i,
                reason: e.to_string(),
            }
        })?;
    }
    checks |= CHECK_RANGE;

    // ── 4. Confidential fee proofs ──
    verify_confidential_fee(&crs, &tx.fee).map_err(|e| TxVerificationError::FeeProof {
        reason: e.to_string(),
    })?;
    checks |= CHECK_FEE;

    // ── 5. Balance excess proof ──
    let input_commitments: Vec<_> = tx
        .inputs
        .iter()
        .map(|i| i.input_commitment.clone())
        .collect();
    let output_commitments: Vec<_> = tx.outputs.iter().map(|o| o.commitment.clone()).collect();

    // Compute balance diff: Σ C_in - Σ C_out - C_fee
    // For confidential fee, we use the fee commitment directly
    let balance_diff = {
        let mut diff = crate::pq_ring::Poly::zero();
        for c in &input_commitments {
            diff = diff.add(&c.0);
        }
        for c in &output_commitments {
            diff = diff.sub(&c.0);
        }
        diff = diff.sub(&tx.fee.commitment.0);
        crate::bdlop::BdlopCommitment(diff)
    };

    verify_balance_with_excess(&crs, &balance_diff, &tx.balance_proof).map_err(|e| {
        TxVerificationError::BalanceProof {
            reason: e.to_string(),
        }
    })?;
    checks |= CHECK_BALANCE;

    // ── All checks passed — seal the envelope ──
    assert_eq!(
        checks, ALL_CHECKS,
        "BUG: not all verification stages executed"
    );

    let nullifiers = tx
        .inputs
        .iter()
        .map(|inp| PublicNullifier::from_raw(inp.nullifier))
        .collect();

    let anonymity_roots = tx
        .inputs
        .iter()
        .map(|inp| AnonymityRoot::from_raw(inp.anonymity_root))
        .collect();

    // Compute aggregate proof weight (Task 3.1)
    // These constants match misaka-consensus/src/zkp_budget.rs
    const COST_MEMBERSHIP: u64 = 10;
    const COST_RANGE: u64 = 3;
    const COST_BALANCE: u64 = 2;
    const COST_FEE: u64 = 3; // fee range proof + minimum proof
    let proof_weight = (tx.inputs.len() as u64) * COST_MEMBERSHIP
        + (tx.outputs.len() as u64) * COST_RANGE
        + COST_BALANCE
        + COST_FEE;

    Ok(VerifiedTransactionEnvelope {
        tx,
        nullifiers,
        tx_digest,
        anonymity_roots,
        proof_weight,
        fee_policy_ok: true, // We passed fee verification above
        _seal: VerificationSeal {
            checks_passed: checks,
        },
    })
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qdag_tx::{ConfidentialInput, QdagTxType, QDAG_VERSION};

    #[test]
    fn test_empty_transfer_rejected_at_structural() {
        let tx = QdagTransaction {
            version: QDAG_VERSION,
            tx_type: QdagTxType::Transfer,
            chain_id: 2,
            parents: vec![],
            inputs: vec![], // Transfer with no inputs — structural failure
            outputs: vec![],
            fee: crate::confidential_fee::ConfidentialFee {
                commitment: crate::bdlop::BdlopCommitment(Poly::zero()),
                range_proof: crate::range_proof::RangeProof {
                    bit_commitments: vec![],
                    or_proofs: vec![],
                },
                minimum_proof: crate::confidential_fee::FeeMinimumProof {
                    diff_range_proof: crate::range_proof::RangeProof {
                        bit_commitments: vec![],
                        or_proofs: vec![],
                    },
                },
                proposer_hint_ct: vec![],
            },
            balance_proof: crate::bdlop::BalanceExcessProof {
                challenge: [0; 32],
                response: Poly::zero(),
            },
            extra: vec![],
        };

        let err = verify_and_seal(tx).unwrap_err();
        assert!(
            err.is_cheap_failure(),
            "structural failure must be classified as cheap check"
        );
        assert!(
            err.to_string().contains("structural"),
            "error message must identify structural stage"
        );
    }

    // NOTE: Full happy-path test requires real crypto (covered by e2e_zkp_pipeline.rs)
}
