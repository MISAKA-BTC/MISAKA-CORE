//! Lattice Range Proof — Prove v ≥ 0 for BDLOP commitment (Q-DAG-CT §2).
//!
//! # Construction
//!
//! Bit decomposition approach: decompose `v = Σ vᵢ · 2^i` where each vᵢ ∈ {0,1},
//! commit to each bit, and prove:
//!
//! 1. Each bit commitment `Cᵢ` commits to 0 or 1 (via Σ-protocol: `Cᵢ·(Cᵢ - A₂) = 0`)
//! 2. The original commitment equals the weighted sum: `C = Σ 2^i · Cᵢ`
//!
//! # Size
//!
//! For 64-bit values: 64 bit commitments + 64 Σ-protocol proofs.
//! Total ≈ 64 × (512 + 544) ≈ 67 KB — acceptable for DAG where bandwidth > linear chain.
//!
//! # Future Optimization
//!
//! Replace with MatRiCT+ aggregate range proof for O(log(bits)) size.
//! Current implementation prioritizes correctness over compactness.

use sha3::{Sha3_256, Digest as Sha3Digest};
use serde::{Serialize, Deserialize};

use crate::pq_ring::{Poly, Q, N, BETA, MAX_SIGN_ATTEMPTS, hash_to_challenge, sample_masking_poly};
use crate::bdlop::{BdlopCrs, BdlopCommitment, BlindingFactor};
use crate::error::CryptoError;

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

/// Maximum bit width for range proofs (64-bit amounts).
pub const RANGE_BITS: usize = 64;

const DST_RANGE_CHAL: &[u8] = b"MISAKA_RANGE_CHAL_V1:";

// ═══════════════════════════════════════════════════════════════
//  Bit Commitment
// ═══════════════════════════════════════════════════════════════

/// Proof that a single BDLOP commitment opens to 0 or 1.
///
/// Uses a Σ-protocol: prover shows knowledge of `r` such that
/// `C = A₁·r + A₂·b` where `b ∈ {0,1}`.
///
/// The verifier checks both branches (b=0 and b=1) in parallel
/// and the prover can only complete one honestly — a standard
/// OR-proof composition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitProof {
    /// Challenge for the b=0 branch.
    pub c0: [u8; 32],
    /// Challenge for the b=1 branch.
    pub c1: [u8; 32],
    /// Response for the b=0 branch.
    pub z0: Poly,
    /// Response for the b=1 branch.
    pub z1: Poly,
}

/// Full range proof: proves the committed value is in [0, 2^RANGE_BITS).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeProof {
    /// Per-bit commitments (RANGE_BITS entries).
    pub bit_commitments: Vec<BdlopCommitment>,
    /// Per-bit proofs (RANGE_BITS entries).
    pub bit_proofs: Vec<BitProof>,
}

impl RangeProof {
    /// Approximate wire size.
    pub fn wire_size(&self) -> usize {
        self.bit_commitments.len() * N * 2   // commitments
        + self.bit_proofs.len() * (32 + 32 + N * 2 + N * 2) // proofs
    }
}

// ═══════════════════════════════════════════════════════════════
//  Prove
// ═══════════════════════════════════════════════════════════════

/// Generate a range proof that `amount ∈ [0, 2^64)`.
///
/// Returns the proof + per-bit blinding factors (needed for balance proof).
pub fn prove_range(
    crs: &BdlopCrs,
    amount: u64,
    blind: &BlindingFactor,
) -> Result<(RangeProof, Vec<BlindingFactor>), CryptoError> {
    let mut bit_commitments = Vec::with_capacity(RANGE_BITS);
    let mut bit_proofs = Vec::with_capacity(RANGE_BITS);
    let mut bit_blinds = Vec::with_capacity(RANGE_BITS);

    for i in 0..RANGE_BITS {
        let bit = ((amount >> i) & 1) as u64;
        let r_i = BlindingFactor::random();
        let c_i = BdlopCommitment::commit(crs, &r_i, bit);

        let proof = prove_bit(crs, &c_i, &r_i, bit as u8)?;

        bit_commitments.push(c_i);
        bit_proofs.push(proof);
        bit_blinds.push(r_i);
    }

    Ok((RangeProof { bit_commitments, bit_proofs }, bit_blinds))
}

/// Prove a single bit commitment opens to 0 or 1.
///
/// OR-proof: simulate the branch we're NOT using, honestly prove the branch we ARE.
fn prove_bit(
    crs: &BdlopCrs,
    commitment: &BdlopCommitment,
    blind: &BlindingFactor,
    bit: u8,
) -> Result<BitProof, CryptoError> {
    assert!(bit <= 1);

    for _ in 0..MAX_SIGN_ATTEMPTS {
        // Simulated branch (the bit we're NOT)
        let sim_z = sample_masking_poly();
        let mut sim_c_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut sim_c_bytes);
        let sim_c_poly = hash_to_challenge(&sim_c_bytes);

        // For the simulated branch, compute w_sim = A₁·z_sim - c_sim·(C - A₂·b_sim)
        let b_sim = 1 - bit;
        let mut b_sim_poly = Poly::zero();
        b_sim_poly.coeffs[0] = b_sim as i32;
        let a2b = crs.a2.mul(&b_sim_poly);
        let target_sim = commitment.0.sub(&a2b); // C - A₂·b_sim
        let a1z = crs.a1.mul(&sim_z);
        let ct = sim_c_poly.mul(&target_sim);
        let w_sim = a1z.sub(&ct);

        // Honest branch
        let y = sample_masking_poly();
        let w_honest = crs.a1.mul(&y);

        // Overall challenge = H(commitment || w0 || w1)
        let (w0, w1) = if bit == 0 {
            (&w_honest, &w_sim)
        } else {
            (&w_sim, &w_honest)
        };

        let mut h = Sha3_256::new();
        h.update(DST_RANGE_CHAL);
        h.update(&commitment.to_bytes());
        h.update(&w0.to_bytes());
        h.update(&w1.to_bytes());
        let overall_c: [u8; 32] = h.finalize().into();

        // Split challenge: c_honest = overall_c XOR c_sim (simplified)
        let mut honest_c_bytes = [0u8; 32];
        for j in 0..32 {
            honest_c_bytes[j] = overall_c[j] ^ sim_c_bytes[j];
        }
        let honest_c_poly = hash_to_challenge(&honest_c_bytes);

        // Response for honest branch: z = y + c_honest · r
        let cs = honest_c_poly.mul(blind.as_poly());
        let mut z_honest = Poly::zero();
        for i in 0..N {
            let y_c = if y.coeffs[i] > Q / 2 { y.coeffs[i] - Q } else { y.coeffs[i] };
            let cs_c = if cs.coeffs[i] > Q / 2 { cs.coeffs[i] - Q } else { cs.coeffs[i] };
            z_honest.coeffs[i] = ((y_c + cs_c) % Q + Q) % Q;
        }

        if z_honest.norm_inf() >= BETA {
            crate::secret::zeroize_i32s(&mut z_honest.coeffs);
            continue;
        }

        let (c0, c1, z0, z1) = if bit == 0 {
            (honest_c_bytes, sim_c_bytes, z_honest, sim_z)
        } else {
            (sim_c_bytes, honest_c_bytes, sim_z, z_honest)
        };

        return Ok(BitProof { c0, c1, z0, z1 });
    }

    Err(CryptoError::RingSignatureInvalid("range bit proof: max attempts".into()))
}

// ═══════════════════════════════════════════════════════════════
//  Verify
// ═══════════════════════════════════════════════════════════════

/// Verify a range proof.
///
/// 1. Each bit proof is valid (commitment opens to 0 or 1).
/// 2. The weighted sum of bit commitments reconstructs to C.
/// 3. Response norms are bounded.
pub fn verify_range(
    crs: &BdlopCrs,
    commitment: &BdlopCommitment,
    proof: &RangeProof,
) -> Result<(), CryptoError> {
    if proof.bit_commitments.len() != RANGE_BITS || proof.bit_proofs.len() != RANGE_BITS {
        return Err(CryptoError::RingSignatureInvalid(
            format!("range proof: expected {} bits, got {}", RANGE_BITS, proof.bit_commitments.len())));
    }

    // Step 1: Verify each bit proof
    for (i, (c_i, bp)) in proof.bit_commitments.iter().zip(proof.bit_proofs.iter()).enumerate() {
        verify_bit_proof(crs, c_i, bp)
            .map_err(|e| CryptoError::RingSignatureInvalid(
                format!("range proof bit[{}]: {}", i, e)))?;
    }

    // Step 2: Verify weighted sum: Σ 2^i · C_i == C
    let mut weighted_sum = Poly::zero();
    for (i, c_i) in proof.bit_commitments.iter().enumerate() {
        // Multiply commitment by 2^i (mod q)
        let power = pow2_mod_q(i);
        let mut scaled = Poly::zero();
        for j in 0..N {
            scaled.coeffs[j] = ((c_i.0.coeffs[j] as i64 * power as i64) % Q as i64) as i32;
        }
        weighted_sum = weighted_sum.add(&scaled);
    }

    // Compare
    let mut match_ok = true;
    for j in 0..N {
        let a = ((weighted_sum.coeffs[j] % Q) + Q) % Q;
        let b = ((commitment.0.coeffs[j] % Q) + Q) % Q;
        if a != b {
            match_ok = false;
            break;
        }
    }

    if !match_ok {
        return Err(CryptoError::RingSignatureInvalid(
            "range proof: weighted bit sum does not match commitment".into()));
    }

    Ok(())
}

/// Verify a single bit proof (OR-proof that C opens to 0 or 1).
fn verify_bit_proof(
    crs: &BdlopCrs,
    commitment: &BdlopCommitment,
    proof: &BitProof,
) -> Result<(), CryptoError> {
    // Norm checks
    if proof.z0.norm_inf() >= BETA || proof.z1.norm_inf() >= BETA {
        return Err(CryptoError::RingSignatureInvalid("bit proof: response norm".into()));
    }

    let c0_poly = hash_to_challenge(&proof.c0);
    let c1_poly = hash_to_challenge(&proof.c1);

    // Branch 0: verify w0 = A₁·z0 - c0·C (C commits to 0 → target = C)
    let a1z0 = crs.a1.mul(&proof.z0);
    let c0c = c0_poly.mul(&commitment.0);
    let w0 = a1z0.sub(&c0c);

    // Branch 1: verify w1 = A₁·z1 - c1·(C - A₂) (C commits to 1 → target = C - A₂)
    let mut one = Poly::zero();
    one.coeffs[0] = 1;
    let a2_one = crs.a2.mul(&one);
    let target1 = commitment.0.sub(&a2_one);
    let a1z1 = crs.a1.mul(&proof.z1);
    let c1t = c1_poly.mul(&target1);
    let w1 = a1z1.sub(&c1t);

    // Recompute overall challenge
    let mut h = Sha3_256::new();
    h.update(DST_RANGE_CHAL);
    h.update(&commitment.to_bytes());
    h.update(&w0.to_bytes());
    h.update(&w1.to_bytes());
    let expected_c: [u8; 32] = h.finalize().into();

    // Check: c0 XOR c1 == expected_c
    let mut xor = [0u8; 32];
    for j in 0..32 {
        xor[j] = proof.c0[j] ^ proof.c1[j];
    }
    if xor != expected_c {
        return Err(CryptoError::RingSignatureInvalid("bit proof: challenge mismatch".into()));
    }

    Ok(())
}

/// Compute 2^i mod q.
fn pow2_mod_q(i: usize) -> i32 {
    let mut val = 1i64;
    for _ in 0..i {
        val = (val * 2) % Q as i64;
    }
    val as i32
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bdlop::BdlopCrs;

    fn crs() -> BdlopCrs { BdlopCrs::default_crs() }

    #[test]
    fn test_range_proof_small_amount() {
        let crs = crs();
        let r = BlindingFactor::random();
        let amount = 42u64;
        let c = BdlopCommitment::commit(&crs, &r, amount);

        let (proof, _blinds) = prove_range(&crs, amount, &r).unwrap();
        verify_range(&crs, &c, &proof).unwrap();
    }

    #[test]
    fn test_range_proof_zero() {
        let crs = crs();
        let r = BlindingFactor::random();
        let c = BdlopCommitment::commit(&crs, &r, 0);

        let (proof, _) = prove_range(&crs, 0, &r).unwrap();
        verify_range(&crs, &c, &proof).unwrap();
    }

    #[test]
    fn test_range_proof_max_u64() {
        let crs = crs();
        let r = BlindingFactor::random();
        let amount = u64::MAX;
        let c = BdlopCommitment::commit(&crs, &r, amount);

        let (proof, _) = prove_range(&crs, amount, &r).unwrap();
        verify_range(&crs, &c, &proof).unwrap();
    }

    #[test]
    fn test_range_proof_wrong_commitment_fails() {
        let crs = crs();
        let r = BlindingFactor::random();
        let (proof, _) = prove_range(&crs, 100, &r).unwrap();

        // Verify against wrong commitment
        let r2 = BlindingFactor::random();
        let c_wrong = BdlopCommitment::commit(&crs, &r2, 200);
        assert!(verify_range(&crs, &c_wrong, &proof).is_err());
    }
}
