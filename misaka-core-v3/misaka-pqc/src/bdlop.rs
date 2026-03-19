//! BDLOP Commitment — Lattice-based Pedersen Equivalent (Q-DAG-CT §1).
//!
//! # Construction
//!
//! Based on Baum-Damgård-Lyubashevsky-Oechslin-Peikert commitment over
//! $R_q = \mathbb{Z}_q[X]/(X^{256}+1)$, hardness from Module-SIS.
//!
//! ```text
//! C = A₁ · r + A₂ · v  (mod q)
//! ```
//!
//! where:
//! - `A₁, A₂ ∈ R_q` — public commitment keys (CRS, deterministic from seed)
//! - `r ∈ R_q` — blinding factor (short, secret)
//! - `v ∈ R_q` — value polynomial (amount encoded in constant term)
//! - `C ∈ R_q` — commitment (512 bytes)
//!
//! # Security Properties
//!
//! - **Computationally Hiding**: Under Module-LWE assumption (128-bit PQ)
//! - **Computationally Binding**: Under Module-SIS assumption
//! - **Additively Homomorphic**: `C(v₁) + C(v₂) = C(v₁+v₂)` (with combined blinds)
//!   This enables balance verification without revealing amounts.
//!
//! # Parameters
//!
//! Reuses LRS-v1 ring: q=12289, n=256. Blinding factor norm bound η_r = 1.

use sha3::{Sha3_256, Sha3_512, Digest as Sha3Digest};
use rand::RngCore;
use serde::{Serialize, Deserialize};

use crate::pq_ring::{Poly, Q, N};
use crate::ntt::ntt_mul;
use crate::error::CryptoError;

// ═══════════════════════════════════════════════════════════════
//  Constants & CRS
// ═══════════════════════════════════════════════════════════════

const DST_CRS_A1: &[u8] = b"MISAKA_BDLOP_CRS_A1_V1:";
const DST_CRS_A2: &[u8] = b"MISAKA_BDLOP_CRS_A2_V1:";
const DST_BLIND: &[u8]  = b"MISAKA_BDLOP_BLIND_V1:";

/// Blinding factor coefficient bound: {-1, 0, 1}.
const ETA_BLIND: i32 = 1;

/// BDLOP Common Reference String — two public polynomials.
///
/// Generated deterministically from a seed so all nodes agree.
/// The seed MUST be committed to in the genesis block.
#[derive(Debug, Clone)]
pub struct BdlopCrs {
    /// Commitment key for the blinding factor.
    pub a1: Poly,
    /// Commitment key for the value.
    pub a2: Poly,
}

/// Default CRS seed (embedded in genesis).
pub const BDLOP_CRS_SEED: [u8; 32] = [
    0x51, 0x44, 0x41, 0x47, 0x2D, 0x43, 0x54, 0x2D, // QDAG-CT-
    0x42, 0x44, 0x4C, 0x4F, 0x50, 0x2D, 0x73, 0x65, // BDLOP-se
    0x65, 0x64, 0x2D, 0x76, 0x31, 0x00, 0x00, 0x00, // ed-v1...
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // .......1
];

impl BdlopCrs {
    /// Derive CRS deterministically from a seed.
    ///
    /// Uses rejection sampling (SEC-AUDIT-V4 HIGH-001 compliant)
    /// to produce uniform polynomials over [0, q).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            a1: derive_crs_poly(seed, DST_CRS_A1),
            a2: derive_crs_poly(seed, DST_CRS_A2),
        }
    }

    /// Default CRS from genesis seed.
    pub fn default_crs() -> Self {
        Self::from_seed(&BDLOP_CRS_SEED)
    }
}

/// Derive a CRS polynomial with rejection sampling.
fn derive_crs_poly(seed: &[u8; 32], dst: &[u8]) -> Poly {
    let threshold = u32::MAX - (u32::MAX % Q as u32);
    let mut poly = Poly::zero();

    for i in 0..N {
        let mut counter = 0u32;
        loop {
            let mut h = Sha3_256::new();
            h.update(dst);
            h.update(seed);
            h.update(&(i as u32).to_le_bytes());
            h.update(&counter.to_le_bytes());
            let hout: [u8; 32] = h.finalize().into();
            let raw = u32::from_le_bytes([hout[0], hout[1], hout[2], hout[3]]);
            if raw < threshold {
                poly.coeffs[i] = (raw % Q as u32) as i32;
                break;
            }
            counter += 1;
        }
    }
    poly
}

// ═══════════════════════════════════════════════════════════════
//  Blinding Factor
// ═══════════════════════════════════════════════════════════════

/// Blinding factor polynomial with short coefficients in {-1, 0, 1}.
///
/// Zeroized on drop (SEC-AUDIT-V4 HIGH-002 compliant).
#[derive(Clone)]
pub struct BlindingFactor(pub Poly);

impl BlindingFactor {
    /// Sample a random blinding factor.
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let mut p = Poly::zero();
        for i in 0..N {
            let mut buf = [0u8; 1];
            rng.fill_bytes(&mut buf);
            p.coeffs[i] = match buf[0] % 3 {
                0 => Q - 1, // -1 mod q
                1 => 0,
                _ => 1,
            };
        }
        Self(p)
    }

    /// Derive deterministically from a secret + index.
    pub fn derive(secret: &[u8], index: u32) -> Result<Self, CryptoError> {
        use hkdf::Hkdf;
        let hk = Hkdf::<Sha3_256>::new(None, secret);
        let mut expanded = [0u8; N];
        let info = [DST_BLIND, &index.to_le_bytes()].concat();
        hk.expand(&info, &mut expanded)
            .map_err(|_| CryptoError::RingSignatureInvalid("BDLOP blind HKDF failed".into()))?;

        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = match expanded[i] % 3 {
                0 => Q - 1,
                1 => 0,
                _ => 1,
            };
        }
        Ok(Self(p))
    }

    pub fn as_poly(&self) -> &Poly {
        &self.0
    }
}

impl Drop for BlindingFactor {
    fn drop(&mut self) {
        crate::secret::zeroize_i32s(&mut self.0.coeffs);
    }
}

// ═══════════════════════════════════════════════════════════════
//  BDLOP Commitment
// ═══════════════════════════════════════════════════════════════

/// BDLOP commitment: `C = A₁·r + A₂·v mod q`
///
/// 512 bytes (256 coefficients × 2 bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BdlopCommitment(pub Poly);

impl BdlopCommitment {
    /// Commit to a value with a blinding factor.
    ///
    /// `C = A₁ · r + A₂ · v(amount)`
    ///
    /// The amount is encoded as the constant term of a value polynomial:
    /// `v = [amount mod q, 0, 0, ..., 0]`
    pub fn commit(crs: &BdlopCrs, blind: &BlindingFactor, amount: u64) -> Self {
        let mut v = Poly::zero();
        v.coeffs[0] = (amount % Q as u64) as i32;

        let a1r = crs.a1.mul(blind.as_poly());
        let a2v = crs.a2.mul(&v);
        let c = a1r.add(&a2v);
        Self(c)
    }

    /// Commit to zero (for balance proof construction).
    ///
    /// `C_zero = A₁ · r_diff` where `r_diff = Σr_in - Σr_out`
    pub fn commit_zero(crs: &BdlopCrs, blind_diff: &BlindingFactor) -> Self {
        let c = crs.a1.mul(blind_diff.as_poly());
        Self(c)
    }

    /// Additive homomorphism: `C₁ + C₂ = Commit(v₁+v₂, r₁+r₂)`
    pub fn add(&self, other: &BdlopCommitment) -> BdlopCommitment {
        BdlopCommitment(self.0.add(&other.0))
    }

    /// Subtraction: `C₁ - C₂ = Commit(v₁-v₂, r₁-r₂)`
    pub fn sub(&self, other: &BdlopCommitment) -> BdlopCommitment {
        BdlopCommitment(self.0.sub(&other.0))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        Ok(Self(Poly::from_bytes(data)?))
    }
}

// ═══════════════════════════════════════════════════════════════
//  Balance Verification (Homomorphic)
// ═══════════════════════════════════════════════════════════════

/// Verify that commitments balance: Σ C_in = Σ C_out + C_fee
///
/// Due to additive homomorphism, this is equivalent to checking:
///   `Σ C_in - Σ C_out - Commit(fee, 0) == A₁ · r_excess`
///
/// where r_excess is the difference of blinding factors.
/// The prover must supply a proof that r_excess is short (norm bound).
///
/// Returns the balance difference commitment for proof verification.
pub fn compute_balance_diff(
    crs: &BdlopCrs,
    input_commitments: &[BdlopCommitment],
    output_commitments: &[BdlopCommitment],
    fee: u64,
) -> BdlopCommitment {
    let mut sum_in = Poly::zero();
    for c in input_commitments {
        sum_in = sum_in.add(&c.0);
    }

    let mut sum_out = Poly::zero();
    for c in output_commitments {
        sum_out = sum_out.add(&c.0);
    }

    // Fee commitment with zero blinding: A₂ · fee
    let mut fee_poly = Poly::zero();
    fee_poly.coeffs[0] = (fee % Q as u64) as i32;
    let fee_commit = crs.a2.mul(&fee_poly);

    // Diff = Σ C_in - Σ C_out - C_fee
    // If balance is correct: diff = A₁ · (Σ r_in - Σ r_out)
    let diff = sum_in.sub(&sum_out).sub(&fee_commit);
    BdlopCommitment(diff)
}

/// Verify balance: check that the difference commitment is of the form A₁·r_excess.
///
/// This requires the prover to supply `r_excess` and a proof that ||r_excess|| is small.
/// For now, we verify by recomputing A₁·r_excess and comparing.
///
/// In production, this would be replaced by a Lattice Σ-protocol proof
/// of knowledge of short r_excess (without revealing it).
pub fn verify_balance_with_excess(
    crs: &BdlopCrs,
    balance_diff: &BdlopCommitment,
    r_excess_proof: &BalanceExcessProof,
) -> Result<(), CryptoError> {
    // Recompute: expected = A₁ · z - c · balance_diff
    let c_poly = crate::pq_ring::hash_to_challenge(&r_excess_proof.challenge);
    let a1z = crs.a1.mul(&r_excess_proof.response);
    let c_diff = c_poly.mul(&balance_diff.0);
    let w_prime = a1z.sub(&c_diff);

    // Recompute challenge
    let mut h = Sha3_256::new();
    h.update(b"MISAKA_BALANCE_CHAL_V1:");
    h.update(&crs.a1.to_bytes());
    h.update(&balance_diff.to_bytes());
    h.update(&w_prime.to_bytes());
    let expected_challenge: [u8; 32] = h.finalize().into();

    if expected_challenge != r_excess_proof.challenge {
        return Err(CryptoError::RingSignatureInvalid(
            "balance proof: challenge mismatch".into()));
    }

    // Response norm check
    if r_excess_proof.response.norm_inf() >= crate::pq_ring::BETA {
        return Err(CryptoError::RingSignatureInvalid(
            "balance proof: response norm too large".into()));
    }

    Ok(())
}

/// Balance excess proof: Σ-protocol proof of knowledge of short r_excess
/// such that balance_diff = A₁ · r_excess.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceExcessProof {
    /// Fiat-Shamir challenge.
    pub challenge: [u8; 32],
    /// Response polynomial z = y + c · r_excess.
    pub response: Poly,
}

impl BalanceExcessProof {
    /// Generate a balance excess proof.
    pub fn prove(
        crs: &BdlopCrs,
        balance_diff: &BdlopCommitment,
        r_excess: &BlindingFactor,
    ) -> Result<Self, CryptoError> {
        use crate::pq_ring::{sample_masking_poly, hash_to_challenge, BETA, MAX_SIGN_ATTEMPTS};

        for _ in 0..MAX_SIGN_ATTEMPTS {
            let y = sample_masking_poly();
            let w = crs.a1.mul(&y);

            let mut h = Sha3_256::new();
            h.update(b"MISAKA_BALANCE_CHAL_V1:");
            h.update(&crs.a1.to_bytes());
            h.update(&balance_diff.to_bytes());
            h.update(&w.to_bytes());
            let challenge: [u8; 32] = h.finalize().into();

            let c_poly = hash_to_challenge(&challenge);
            let cs = c_poly.mul(r_excess.as_poly());
            let mut z = Poly::zero();
            for i in 0..N {
                let y_c = if y.coeffs[i] > Q / 2 { y.coeffs[i] - Q } else { y.coeffs[i] };
                let cs_c = if cs.coeffs[i] > Q / 2 { cs.coeffs[i] - Q } else { cs.coeffs[i] };
                z.coeffs[i] = ((y_c + cs_c) % Q + Q) % Q;
            }

            if z.norm_inf() >= BETA {
                // Zeroize rejected response (HIGH-002)
                crate::secret::zeroize_i32s(&mut z.coeffs);
                continue;
            }

            return Ok(Self { challenge, response: z });
        }
        Err(CryptoError::RingSignatureInvalid("balance proof: max attempts".into()))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + N * 2);
        buf.extend_from_slice(&self.challenge);
        buf.extend_from_slice(&self.response.to_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() != 32 + N * 2 {
            return Err(CryptoError::RingSignatureInvalid("balance proof size".into()));
        }
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&data[..32]);
        let response = Poly::from_bytes(&data[32..])?;
        Ok(Self { challenge, response })
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn crs() -> BdlopCrs { BdlopCrs::default_crs() }

    #[test]
    fn test_crs_deterministic() {
        let c1 = BdlopCrs::from_seed(&BDLOP_CRS_SEED);
        let c2 = BdlopCrs::from_seed(&BDLOP_CRS_SEED);
        assert_eq!(c1.a1.to_bytes(), c2.a1.to_bytes());
        assert_eq!(c1.a2.to_bytes(), c2.a2.to_bytes());
    }

    #[test]
    fn test_crs_a1_a2_differ() {
        let c = crs();
        assert_ne!(c.a1.to_bytes(), c.a2.to_bytes());
    }

    #[test]
    fn test_commit_different_amounts_differ() {
        let c = crs();
        let r = BlindingFactor::random();
        let c1 = BdlopCommitment::commit(&c, &r, 100);
        let c2 = BdlopCommitment::commit(&c, &r, 200);
        assert_ne!(c1.to_bytes(), c2.to_bytes());
    }

    #[test]
    fn test_commit_different_blinds_differ() {
        let c = crs();
        let r1 = BlindingFactor::random();
        let r2 = BlindingFactor::random();
        let c1 = BdlopCommitment::commit(&c, &r1, 100);
        let c2 = BdlopCommitment::commit(&c, &r2, 100);
        assert_ne!(c1.to_bytes(), c2.to_bytes());
    }

    #[test]
    fn test_homomorphic_addition() {
        let crs = crs();
        let r1 = BlindingFactor::random();
        let r2 = BlindingFactor::random();

        let c1 = BdlopCommitment::commit(&crs, &r1, 100);
        let c2 = BdlopCommitment::commit(&crs, &r2, 200);
        let c_sum = c1.add(&c2);

        // Combined blinding: r1 + r2
        let mut r_combined = Poly::zero();
        for i in 0..N {
            r_combined.coeffs[i] = (r1.0.coeffs[i] + r2.0.coeffs[i]) % Q;
            if r_combined.coeffs[i] < 0 { r_combined.coeffs[i] += Q; }
        }
        let c_direct = BdlopCommitment::commit(&crs, &BlindingFactor(r_combined), 300);

        assert_eq!(c_sum.to_bytes(), c_direct.to_bytes(),
            "C(100,r1) + C(200,r2) must equal C(300,r1+r2)");
    }

    #[test]
    fn test_balance_diff_zero_when_balanced() {
        let crs = crs();
        let r_in = BlindingFactor::random();
        let r_out = BlindingFactor::random();

        let c_in = BdlopCommitment::commit(&crs, &r_in, 1000);
        let c_out = BdlopCommitment::commit(&crs, &r_out, 900);
        let fee = 100u64;

        let diff = compute_balance_diff(&crs, &[c_in], &[c_out], fee);

        // diff should equal A₁ · (r_in - r_out)
        let mut r_excess_poly = Poly::zero();
        for i in 0..N {
            r_excess_poly.coeffs[i] = (r_in.0.coeffs[i] - r_out.0.coeffs[i]) % Q;
            if r_excess_poly.coeffs[i] < 0 { r_excess_poly.coeffs[i] += Q; }
        }
        let expected = crs.a1.mul(&r_excess_poly);
        assert_eq!(diff.to_bytes(), BdlopCommitment(expected).to_bytes());
    }

    #[test]
    fn test_balance_proof_roundtrip() {
        let crs = crs();
        let r_in = BlindingFactor::random();
        let r_out = BlindingFactor::random();

        let c_in = BdlopCommitment::commit(&crs, &r_in, 500);
        let c_out = BdlopCommitment::commit(&crs, &r_out, 400);
        let fee = 100u64;

        let diff = compute_balance_diff(&crs, &[c_in], &[c_out], fee);

        // Compute r_excess = r_in - r_out
        let mut r_excess_poly = Poly::zero();
        for i in 0..N {
            r_excess_poly.coeffs[i] = (r_in.0.coeffs[i] - r_out.0.coeffs[i]) % Q;
            if r_excess_poly.coeffs[i] < 0 { r_excess_poly.coeffs[i] += Q; }
        }
        let r_excess = BlindingFactor(r_excess_poly);

        let proof = BalanceExcessProof::prove(&crs, &diff, &r_excess).unwrap();
        verify_balance_with_excess(&crs, &diff, &proof).unwrap();
    }

    #[test]
    fn test_balance_proof_wrong_excess_fails() {
        let crs = crs();
        let r_in = BlindingFactor::random();
        let r_out = BlindingFactor::random();

        let c_in = BdlopCommitment::commit(&crs, &r_in, 500);
        let c_out = BdlopCommitment::commit(&crs, &r_out, 400);
        let diff = compute_balance_diff(&crs, &[c_in], &[c_out], 100);

        // Use wrong excess
        let r_wrong = BlindingFactor::random();
        let proof = BalanceExcessProof::prove(&crs, &diff, &r_wrong).unwrap();
        assert!(verify_balance_with_excess(&crs, &diff, &proof).is_err());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let crs = crs();
        let r = BlindingFactor::random();
        let c = BdlopCommitment::commit(&crs, &r, 42);
        let bytes = c.to_bytes();
        let c2 = BdlopCommitment::from_bytes(&bytes).unwrap();
        assert_eq!(c, c2);
    }
}
