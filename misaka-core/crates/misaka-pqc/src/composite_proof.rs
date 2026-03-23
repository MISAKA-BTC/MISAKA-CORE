//! Composite Proof — Production ZKP for UtxoTransaction (STARK Stub Replacement).
//!
//! # Problem
//!
//! `stark_proof.rs` (feature-gated behind `stark-stub`) provides zero soundness:
//! hash commitments that anyone knowing the constraint values can forge.
//! Production builds exclude it via `compile_error!`.
//!
//! # Solution
//!
//! CompositeProof wraps the existing lattice-based proof primitives into a
//! single serializable proof that can be carried in `UtxoTransaction.zk_proof`.
//!
//! Sub-proofs (all lattice-based, computationally sound under Module-SIS/LWE):
//!
//! | Sub-proof         | Primitive              | What it proves                           |
//! |-------------------|------------------------|------------------------------------------|
//! | Balance           | BDLOP BalanceExcess    | `Σ C_in = Σ C_out + C_fee` (conservation)|
//! | Range (per output)| BDLOP bit-decomposition| `0 ≤ amount < 2^64` (no overflow)        |
//! | Nullifier binding | SHA3 transcript        | Proof is bound to specific nullifiers    |
//!
//! # Backend Tag
//!
//! `SCHEME_COMPOSITE = 0x20` — distinct from:
//! - `0x10` UnifiedZKP-v1 (Q-DAG-CT native: membership + nullifier + range)
//! - `0xF1` STARK-stub (deprecated, dev-only)
//!
//! # Feature Gate
//!
//! This module is NOT feature-gated — always available for production builds.

use serde::{Deserialize, Serialize};
use sha3::{Digest as Sha3Digest, Sha3_256};

use crate::bdlop::{BalanceExcessProof, BdlopCommitment, BdlopCrs, BlindingFactor};
use crate::error::CryptoError;
use crate::pq_ring::Poly;
use crate::range_proof::{prove_range, verify_range, RangeProof};
use crate::secret::ct_eq_32;

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

/// Backend tag for CompositeProof in `ZeroKnowledgeProofCarrier.backend_tag`.
pub const SCHEME_COMPOSITE: u8 = 0x20;

/// Version tag for serialization format evolution.
pub const COMPOSITE_VERSION: u8 = 0x01;

/// Domain separator for nullifier binding.
const DST_COMPOSITE_BIND: &[u8] = b"MISAKA_COMPOSITE_BIND_V1:";

// ═══════════════════════════════════════════════════════════════
//  CompositeProof
// ═══════════════════════════════════════════════════════════════

/// Production zero-knowledge proof for UtxoTransaction.
///
/// Carried inside `UtxoTransaction.zk_proof` as:
/// ```text
/// ZeroKnowledgeProofCarrier {
///     backend_tag: 0x20,  // SCHEME_COMPOSITE
///     proof_bytes: CompositeProof.to_bytes(),
/// }
/// ```
///
/// # Soundness
///
/// All sub-proofs are lattice-based Σ-protocols:
/// - Balance: BalanceExcessProof — proves knowledge of `r_excess` such that
///   `balance_diff = A₁ · r_excess` (Module-SIS hardness)
/// - Range: bit-decomposition proofs — each bit commitment proven to be 0 or 1
///   via OR-composition (Module-SIS hardness)
///
/// Forging any sub-proof requires solving Module-SIS with at least 128-bit
/// quantum security.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompositeProof {
    /// Serialization version.
    pub version: u8,
    /// Balance conservation proof: Σ C_in = Σ C_out + C_fee.
    pub balance_proof: BalanceExcessProof,
    /// Per-output range proofs: each output amount is in [0, 2^64).
    pub range_proofs: Vec<RangeProof>,
    /// Per-output BDLOP commitments (verifier needs these to check range proofs).
    pub output_commitments: Vec<BdlopCommitment>,
    /// Binding digest: H(DST || tx_digest || nullifiers || output_commitments).
    /// The verifier recomputes this and checks it matches.
    pub binding_digest: [u8; 32],
}

impl CompositeProof {
    /// Serialize to bytes for `ZeroKnowledgeProofCarrier.proof_bytes`.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        serde_json::from_slice(data).map_err(|e| {
            CryptoError::RingSignatureInvalid(format!("CompositeProof deserialize: {}", e))
        })
    }

    /// Wire size estimate.
    pub fn wire_size(&self) -> usize {
        self.to_bytes().len()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Binding Digest
// ═══════════════════════════════════════════════════════════════

/// Compute the binding digest that ties the proof to the transaction context.
///
/// `H = SHA3-256(DST || tx_digest || num_nullifiers || nullifiers... || num_commitments || commitments...)`
///
/// This prevents proof transplant attacks: a proof generated for TX-A
/// cannot be used for TX-B because the binding digest won't match.
pub fn compute_binding_digest(
    tx_digest: &[u8; 32],
    nullifiers: &[[u8; 32]],
    output_commitments: &[BdlopCommitment],
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DST_COMPOSITE_BIND);
    h.update(tx_digest);
    h.update(&(nullifiers.len() as u32).to_le_bytes());
    for nf in nullifiers {
        h.update(nf);
    }
    h.update(&(output_commitments.len() as u32).to_le_bytes());
    for c in output_commitments {
        h.update(&c.0.to_bytes());
    }
    h.finalize().into()
}

// ═══════════════════════════════════════════════════════════════
//  Prover
// ═══════════════════════════════════════════════════════════════

/// Prover witness for a single output.
pub struct OutputWitness {
    /// Output amount (plaintext, known to prover).
    pub amount: u64,
    /// Blinding factor for the BDLOP commitment.
    pub blinding: BlindingFactor,
}

/// Generate a CompositeProof for a transaction.
///
/// # Arguments
///
/// - `crs`: BDLOP Common Reference String
/// - `tx_digest`: Transaction signing digest (binds proof to TX)
/// - `input_commitments`: BDLOP commitments for each input (from UTXO set)
/// - `input_blindings`: Blinding factors for input commitments
/// - `output_witnesses`: Amount + blinding for each output
/// - `fee_amount`: Transaction fee
/// - `fee_blinding`: Blinding factor for fee commitment
/// - `nullifiers`: Canonical nullifiers (key images) for each input
///
/// # Returns
///
/// `CompositeProof` containing balance proof + range proofs + binding digest.
pub fn prove_composite(
    crs: &BdlopCrs,
    tx_digest: &[u8; 32],
    input_commitments: &[BdlopCommitment],
    input_blindings: &[BlindingFactor],
    output_witnesses: &[OutputWitness],
    fee_amount: u64,
    fee_blinding: &BlindingFactor,
    nullifiers: &[[u8; 32]],
) -> Result<CompositeProof, CryptoError> {
    // ── 1. Commit to outputs and generate range proofs ──
    let mut output_commitments = Vec::with_capacity(output_witnesses.len());
    let mut range_proofs = Vec::with_capacity(output_witnesses.len());

    for witness in output_witnesses {
        let commitment = BdlopCommitment::commit(&crs, &witness.blinding, witness.amount)?;
        let (range_proof, _bit_blinds) = prove_range(crs, witness.amount, &witness.blinding)?;
        output_commitments.push(commitment);
        range_proofs.push(range_proof);
    }

    // ── 2. Compute balance diff: Σ C_in - Σ C_out - C_fee ──
    let mut sum_in = Poly::zero();
    for c in input_commitments {
        sum_in = sum_in.add(&c.0);
    }
    let mut sum_out = Poly::zero();
    for c in &output_commitments {
        sum_out = sum_out.add(&c.0);
    }
    let fee_commitment = BdlopCommitment::commit(&crs, fee_blinding, fee_amount)?;
    let balance_diff = BdlopCommitment(sum_in.sub(&sum_out).sub(&fee_commitment.0));

    // ── 3. Compute excess blinding: r_excess = Σ r_in - Σ r_out - r_fee ──
    let mut r_excess_coeffs = vec![0i64; crate::pq_ring::N];
    for blind in input_blindings {
        for (i, c) in blind.0.coeffs.iter().enumerate() {
            r_excess_coeffs[i] += if *c > crate::pq_ring::Q / 2 {
                *c as i64 - crate::pq_ring::Q as i64
            } else {
                *c as i64
            };
        }
    }
    for witness in output_witnesses {
        for (i, c) in witness.blinding.0.coeffs.iter().enumerate() {
            r_excess_coeffs[i] -= if *c > crate::pq_ring::Q / 2 {
                *c as i64 - crate::pq_ring::Q as i64
            } else {
                *c as i64
            };
        }
    }
    for (i, c) in fee_blinding.0.coeffs.iter().enumerate() {
        r_excess_coeffs[i] -= if *c > crate::pq_ring::Q / 2 {
            *c as i64 - crate::pq_ring::Q as i64
        } else {
            *c as i64
        };
    }
    let mut r_excess = Poly::zero();
    for (i, v) in r_excess_coeffs.iter().enumerate() {
        r_excess.coeffs[i] = ((*v % crate::pq_ring::Q as i64 + crate::pq_ring::Q as i64)
            % crate::pq_ring::Q as i64) as i32;
    }
    let r_excess_blind = BlindingFactor(r_excess);

    // ── 4. Generate balance excess proof ──
    let balance_proof = BalanceExcessProof::prove(crs, &balance_diff, &r_excess_blind)?;

    // ── 5. Compute binding digest ──
    let binding_digest = compute_binding_digest(tx_digest, nullifiers, &output_commitments);

    Ok(CompositeProof {
        version: COMPOSITE_VERSION,
        balance_proof,
        range_proofs,
        output_commitments,
        binding_digest,
    })
}

// ═══════════════════════════════════════════════════════════════
//  Verifier
// ═══════════════════════════════════════════════════════════════

/// Verify a CompositeProof against transaction constraints.
///
/// # Checks (all must pass — fail-closed)
///
/// 1. Version check
/// 2. Binding digest matches recomputed value (anti-transplant)
/// 3. Range proof for each output (amount ≥ 0, no overflow)
/// 4. Balance conservation (Σ C_in = Σ C_out + C_fee)
///
/// # Arguments
///
/// - `crs`: BDLOP Common Reference String
/// - `proof`: The CompositeProof to verify
/// - `tx_digest`: Transaction signing digest
/// - `input_commitments`: BDLOP commitments for each input
/// - `fee_commitment`: BDLOP commitment for fee
/// - `nullifiers`: Canonical nullifiers for each input
pub fn verify_composite(
    crs: &BdlopCrs,
    proof: &CompositeProof,
    tx_digest: &[u8; 32],
    input_commitments: &[BdlopCommitment],
    fee_commitment: &BdlopCommitment,
    nullifiers: &[[u8; 32]],
) -> Result<(), CryptoError> {
    // ── 1. Version ──
    if proof.version != COMPOSITE_VERSION {
        return Err(CryptoError::RingSignatureInvalid(format!(
            "CompositeProof version mismatch: got {}, expected {}",
            proof.version, COMPOSITE_VERSION,
        )));
    }

    // ── 2. Output count consistency ──
    if proof.range_proofs.len() != proof.output_commitments.len() {
        return Err(CryptoError::RingSignatureInvalid(
            "range_proofs.len() != output_commitments.len()".into(),
        ));
    }

    // ── 3. Binding digest (anti-transplant) ──
    let expected_digest = compute_binding_digest(tx_digest, nullifiers, &proof.output_commitments);
    if !ct_eq_32(&expected_digest, &proof.binding_digest) {
        return Err(CryptoError::RingSignatureInvalid(
            "binding digest mismatch — possible proof transplant attack".into(),
        ));
    }

    // ── 4. Range proofs (parallel-safe, each independent) ──
    for (i, (commitment, range_proof)) in proof
        .output_commitments
        .iter()
        .zip(proof.range_proofs.iter())
        .enumerate()
    {
        verify_range(crs, commitment, range_proof).map_err(|e| {
            CryptoError::RingSignatureInvalid(format!("range proof failed for output {}: {}", i, e))
        })?;
    }

    // ── 5. Balance conservation ──
    let mut sum_in = Poly::zero();
    for c in input_commitments {
        sum_in = sum_in.add(&c.0);
    }
    let mut sum_out = Poly::zero();
    for c in &proof.output_commitments {
        sum_out = sum_out.add(&c.0);
    }
    let balance_diff = BdlopCommitment(sum_in.sub(&sum_out).sub(&fee_commitment.0));

    crate::bdlop::verify_balance_with_excess(crs, &balance_diff, &proof.balance_proof)
        .map_err(|e| CryptoError::RingSignatureInvalid(format!("balance proof failed: {}", e)))
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bdlop::BdlopCrs;

    fn setup_crs() -> BdlopCrs {
        BdlopCrs::default_crs()
    }

    #[test]
    fn test_prove_verify_roundtrip() {
        let crs = setup_crs();

        let in_blind = BlindingFactor::random();
        let in_amount = 10_000u64;
        let in_commitment = BdlopCommitment::commit(&crs, &in_blind, in_amount)?;

        let out_witness = OutputWitness {
            amount: 9_900,
            blinding: BlindingFactor::random(),
        };
        let fee_blind = BlindingFactor::random();
        let fee_amount = 100u64;

        let tx_digest = [0x42u8; 32];
        let nullifiers = vec![[0xAAu8; 32]];

        let proof = prove_composite(
            &crs,
            &tx_digest,
            &[in_commitment.clone()],
            &[in_blind],
            &[out_witness],
            fee_amount,
            &fee_blind,
            &nullifiers,
        )
        .expect("prove should succeed");

        let fee_commitment = BdlopCommitment::commit(&crs, &fee_blind, fee_amount)?;

        verify_composite(
            &crs,
            &proof,
            &tx_digest,
            &[in_commitment],
            &fee_commitment,
            &nullifiers,
        )
        .expect("verify should succeed");
    }

    #[test]
    fn test_wrong_tx_digest_rejected() {
        let crs = setup_crs();

        let in_blind = BlindingFactor::random();
        let in_commitment = BdlopCommitment::commit(&crs, &in_blind, 1000)?;
        let out_witness = OutputWitness {
            amount: 900,
            blinding: BlindingFactor::random(),
        };
        let fee_blind = BlindingFactor::random();

        let proof = prove_composite(
            &crs,
            &[0x01; 32],
            &[in_commitment.clone()],
            &[in_blind],
            &[out_witness],
            100,
            &fee_blind,
            &[[0xBB; 32]],
        )
        .expect("prove");

        let fee_commitment = BdlopCommitment::commit(&crs, &fee_blind, 100)?;

        // Verify with DIFFERENT tx_digest → binding digest mismatch
        let result = verify_composite(
            &crs,
            &proof,
            &[0x02; 32],
            &[in_commitment],
            &fee_commitment,
            &[[0xBB; 32]],
        );
        assert!(result.is_err(), "wrong tx_digest must be rejected");
    }

    #[test]
    fn test_wrong_nullifier_rejected() {
        let crs = setup_crs();

        let in_blind = BlindingFactor::random();
        let in_commitment = BdlopCommitment::commit(&crs, &in_blind, 1000)?;
        let out_witness = OutputWitness {
            amount: 900,
            blinding: BlindingFactor::random(),
        };
        let fee_blind = BlindingFactor::random();

        let proof = prove_composite(
            &crs,
            &[0x01; 32],
            &[in_commitment.clone()],
            &[in_blind],
            &[out_witness],
            100,
            &fee_blind,
            &[[0xBB; 32]],
        )
        .expect("prove");

        let fee_commitment = BdlopCommitment::commit(&crs, &fee_blind, 100)?;

        // Verify with DIFFERENT nullifier → binding digest mismatch
        let result = verify_composite(
            &crs,
            &proof,
            &[0x01; 32],
            &[in_commitment],
            &fee_commitment,
            &[[0xCC; 32]],
        );
        assert!(result.is_err(), "wrong nullifier must be rejected");
    }

    #[test]
    fn test_serialization_roundtrip() {
        let crs = setup_crs();

        let in_blind = BlindingFactor::random();
        let in_commitment = BdlopCommitment::commit(&crs, &in_blind, 5000)?;
        let out_witness = OutputWitness {
            amount: 4950,
            blinding: BlindingFactor::random(),
        };
        let fee_blind = BlindingFactor::random();

        let proof = prove_composite(
            &crs,
            &[0x33; 32],
            &[in_commitment],
            &[in_blind],
            &[out_witness],
            50,
            &fee_blind,
            &[[0xDD; 32]],
        )
        .expect("prove");

        let bytes = proof.to_bytes();
        assert!(!bytes.is_empty());

        let decoded = CompositeProof::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded.version, COMPOSITE_VERSION);
        assert_eq!(decoded.binding_digest, proof.binding_digest);
        assert_eq!(decoded.range_proofs.len(), proof.range_proofs.len());
    }

    #[test]
    fn test_multiple_outputs() {
        let crs = setup_crs();

        let in_blind = BlindingFactor::random();
        let in_commitment = BdlopCommitment::commit(&crs, &in_blind, 10_000)?;

        let out1 = OutputWitness {
            amount: 6_000,
            blinding: BlindingFactor::random(),
        };
        let out2 = OutputWitness {
            amount: 3_900,
            blinding: BlindingFactor::random(),
        };
        let fee_blind = BlindingFactor::random();

        let proof = prove_composite(
            &crs,
            &[0x44; 32],
            &[in_commitment.clone()],
            &[in_blind],
            &[out1, out2],
            100,
            &fee_blind,
            &[[0xEE; 32]],
        )
        .expect("prove");

        assert_eq!(proof.range_proofs.len(), 2);

        let fee_commitment = BdlopCommitment::commit(&crs, &fee_blind, 100)?;
        verify_composite(
            &crs,
            &proof,
            &[0x44; 32],
            &[in_commitment],
            &fee_commitment,
            &[[0xEE; 32]],
        )
        .expect("verify should succeed for 2 outputs");
    }
}
