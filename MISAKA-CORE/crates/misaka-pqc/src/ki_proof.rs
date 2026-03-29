//! Key Image Correctness Proof — Strong Binding (Algebraic Dual-Statement).
//!
//! # Strong Binding Design
//!
//! This proves knowledge of secret `s` satisfying TWO algebraic relations
//! simultaneously using a single response polynomial `z`:
//!
//! ```text
//! Statement 1: pk     = a    · s   (public key relation)
//! Statement 2: ki_poly = h_pk · s   (key image relation)
//! ```
//!
//! Where `h_pk = HashToPoly(pk)` is a deterministic polynomial base derived
//! from the public key.
//!
//! # Why This Is "Strong Binding"
//!
//! The Verifier reconstructs BOTH commitments from z:
//!
//! ```text
//! w_pk'  = a    · z - c · pk       (standard Σ-protocol)
//! w_ki'  = h_pk · z - c · ki_poly  (NEW: algebraic KI check)
//! ```
//!
//! Then verifies: `c == H(a || pk || ki_poly || w_pk' || w_ki')`
//!
//! If the prover uses a fake `ki_poly' ≠ h_pk · s`, then `w_ki'` will be
//! wrong, and the recomputed challenge will not match. The prover CANNOT
//! cheat because:
//! - `z = y + c · s` is fixed (same `s` for both statements)
//! - `w_ki' = h_pk · (y + c·s) - c · ki_poly'`
//!          = `h_pk · y + c · (h_pk·s - ki_poly')`
//!          ≠ `h_pk · y` unless `ki_poly' = h_pk · s`
//!
//! # Canonical Key Image
//!
//! ```text
//! ki_poly   = h_pk · s          (R_q polynomial, 512 bytes)
//! key_image = SHA3-256("MISAKA_KI_STRONG_V1:" || ki_poly.to_bytes())  (32-byte nullifier)
//! ```

use crate::error::CryptoError;
use crate::pq_ring::{hash_to_challenge, sample_masking_poly, Poly, BETA, MAX_SIGN_ATTEMPTS, N, Q};
use crate::secret::ct_eq_32;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Domain separation tags.
const DST_KI_PROOF: &[u8] = b"MISAKA_KI_STRONG_V1:";
const DST_KI_HASH: &[u8] = b"MISAKA_KI_HASH_V1:";
const DST_H_PK: &[u8] = b"MISAKA_KI_BASEPOLY_V1:";

/// Proof size: challenge(32) + response(N*2=512) + ki_poly(N*2=512) = 1056 bytes.
pub const KI_PROOF_SIZE: usize = 32 + N * 2 + N * 2;

// ═══ HashToPoly: Deterministic Base for KI ══════════════════

/// Derive the KI base polynomial `h_pk` from a public key.
///
/// `h_pk = HashToPoly(pk)` — deterministic, public, collision-resistant.
///
/// Uses SHAKE-like expansion from SHA3-256 to fill N coefficients in [0, q).
pub fn hash_to_poly(pk: &Poly) -> Poly {
    let pk_bytes = pk.to_bytes();
    let mut result = Poly::zero();

    // Generate N coefficients by hashing with counter
    for chunk_start in (0..N).step_by(8) {
        let mut h = Sha3_256::new();
        h.update(DST_H_PK);
        h.update(&pk_bytes);
        h.update(&(chunk_start as u32).to_le_bytes());
        let hash: [u8; 32] = h.finalize().into();

        // Extract up to 8 coefficients from 32-byte hash (4 bytes each)
        for j in 0..8 {
            let idx = chunk_start + j;
            if idx >= N {
                break;
            }
            let offset = j * 4;
            let raw = u32::from_le_bytes([
                hash[offset],
                hash[offset + 1],
                hash[offset + 2],
                hash[offset + 3],
            ]);
            result.coeffs[idx] = (raw % Q as u32) as i32;
        }
    }
    result.reduce();
    result
}

// ═══ Canonical Key Image ════════════════════════════════════

/// Compute the algebraic key image polynomial: `ki_poly = h_pk · s`.
pub fn compute_ki_poly(pk: &Poly, secret: &Poly) -> Poly {
    let h_pk = hash_to_poly(pk);
    h_pk.mul(secret)
}

/// Compute the 32-byte nullifier from the KI polynomial.
///
/// `key_image = SHA3-256(DST_KI_HASH || ki_poly.to_bytes())`
pub fn ki_poly_to_nullifier(ki_poly: &Poly) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DST_KI_HASH);
    h.update(&ki_poly.to_bytes());
    h.finalize().into()
}

/// Compute the full canonical key image (polynomial + 32-byte nullifier).
pub fn canonical_strong_ki(pk: &Poly, secret: &Poly) -> (Poly, [u8; 32]) {
    let ki_poly = compute_ki_poly(pk, secret);
    let nullifier = ki_poly_to_nullifier(&ki_poly);
    (ki_poly, nullifier)
}

// ═══ Proof Structure ════════════════════════════════════════

/// Strong-binding KI proof.
///
/// Contains the algebraic KI polynomial (for verifier reconstruction)
/// plus the Σ-protocol challenge and response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KiProof {
    /// Fiat-Shamir challenge.
    pub challenge: [u8; 32],
    /// Response polynomial z = y + c · s.
    pub response: Poly,
    /// Algebraic key image: ki_poly = h_pk · s.
    /// Included so verifier can reconstruct w_ki' = h_pk·z - c·ki_poly.
    pub ki_poly: Poly,
}

impl KiProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(KI_PROOF_SIZE);
        buf.extend_from_slice(&self.challenge);
        buf.extend_from_slice(&self.response.to_bytes());
        buf.extend_from_slice(&self.ki_poly.to_bytes());
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() != KI_PROOF_SIZE {
            return Err(CryptoError::ProofInvalid(format!(
                "ki_proof bytes: expected {}, got {}",
                KI_PROOF_SIZE,
                data.len()
            )));
        }
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&data[..32]);
        let response = Poly::from_bytes(&data[32..32 + N * 2])?;
        let ki_poly = Poly::from_bytes(&data[32 + N * 2..])?;
        Ok(Self {
            challenge,
            response,
            ki_poly,
        })
    }
}

// ═══ Challenge Computation ══════════════════════════════════

/// Compute the Fiat-Shamir challenge for the dual-statement proof.
///
/// `c = H(DST || a || pk || ki_poly || w_pk || w_ki)`
///
/// Both `w_pk` and `w_ki` are included, binding both algebraic relations.
fn dual_challenge(a: &Poly, pk: &Poly, ki_poly: &Poly, w_pk: &Poly, w_ki: &Poly) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DST_KI_PROOF);
    h.update(&a.to_bytes());
    h.update(&pk.to_bytes());
    h.update(&ki_poly.to_bytes());
    h.update(&w_pk.to_bytes());
    h.update(&w_ki.to_bytes());
    h.finalize().into()
}

// ═══ Prove ══════════════════════════════════════════════════

/// Generate a Strong Binding KI proof.
///
/// Proves knowledge of `secret` such that:
///   `pk = a · secret`  AND  `ki_poly = h_pk · secret`
///
/// Both statements use the SAME `z = y + c · s`, making it impossible
/// to satisfy one without satisfying the other.
pub fn prove_key_image(
    a: &Poly,
    secret: &Poly,
    pubkey: &Poly,
    key_image: &[u8; 32],
) -> Result<KiProof, CryptoError> {
    // Compute the algebraic KI
    let h_pk = hash_to_poly(pubkey);
    let ki_poly = h_pk.mul(secret);

    // Verify the nullifier matches what the caller claims
    let expected_nullifier = ki_poly_to_nullifier(&ki_poly);
    if !ct_eq_32(key_image, &expected_nullifier) {
        return Err(CryptoError::ProofInvalid(
            "ki_proof: key_image does not match algebraic ki_poly = h_pk * s".into(),
        ));
    }

    for _ in 0..MAX_SIGN_ATTEMPTS {
        // 1. Sample masking polynomial y
        let y = sample_masking_poly();

        // 2. Dual commitment (BOTH from same y):
        let w_pk = a.mul(&y); // Statement 1: pk = a·s
        let w_ki = h_pk.mul(&y); // Statement 2: ki = h_pk·s

        // 3. Fiat-Shamir challenge (includes BOTH commitments)
        let challenge = dual_challenge(a, pubkey, &ki_poly, &w_pk, &w_ki);
        let c_poly = hash_to_challenge(&challenge);

        // 4. Response: z = y + c · s (shared for both statements)
        let cs = c_poly.mul(secret);
        let mut z = Poly::zero();
        for i in 0..N {
            let y_c = if y.coeffs[i] > Q / 2 {
                y.coeffs[i] - Q
            } else {
                y.coeffs[i]
            };
            let cs_c = if cs.coeffs[i] > Q / 2 {
                cs.coeffs[i] - Q
            } else {
                cs.coeffs[i]
            };
            let val = y_c + cs_c;
            z.coeffs[i] = ((val % Q) + Q) % Q;
        }

        // 5. Rejection sampling
        if z.norm_inf() >= BETA {
            continue;
        }

        return Ok(KiProof {
            challenge,
            response: z,
            ki_poly,
        });
    }

    Err(CryptoError::ProofInvalid(
        "ki_proof: max attempts".into(),
    ))
}

// ═══ Verify ═════════════════════════════════════════════════

/// Verify a Strong Binding KI proof.
///
/// The verifier RECONSTRUCTS both commitments from z:
///
/// ```text
/// w_pk' = a    · z - c · pk       ← checks pk = a·s
/// w_ki' = h_pk · z - c · ki_poly  ← checks ki_poly = h_pk·s
/// ```
///
/// Then verifies: `c == H(DST || a || pk || ki_poly || w_pk' || w_ki')`
///
/// If `ki_poly ≠ h_pk · s`, then `w_ki'` will be wrong, and the
/// recomputed challenge will NOT match. This is the Strong Binding property.
pub fn verify_key_image_proof(
    a: &Poly,
    public_key: &Poly,
    key_image: &[u8; 32],
    proof: &KiProof,
) -> Result<(), CryptoError> {
    // SECURITY: all verification failures return the same generic error
    // to prevent error-oracle attacks.
    let reject = || CryptoError::ProofInvalid("invalid proof".into());
    let z = &proof.response;

    // Accumulate failures — run all checks even if one fails
    let mut valid = true;

    // 1. Response bound check (constant-time norm_inf)
    if z.norm_inf() >= BETA {
        valid = false;
    }

    // 2. Verify key_image matches ki_poly hash (constant-time)
    let expected_nullifier = ki_poly_to_nullifier(&proof.ki_poly);
    if !ct_eq_32(key_image, &expected_nullifier) {
        valid = false;
    }

    // 3. Recompute h_pk deterministically
    let h_pk = hash_to_poly(public_key);

    // 4. Expand challenge → polynomial
    let c_poly = hash_to_challenge(&proof.challenge);

    // 5. RECONSTRUCT both commitments (the Strong Binding step):
    //    w_pk' = a · z - c · pk
    let az = a.mul(z);
    let c_pk = c_poly.mul(public_key);
    let w_pk_prime = az.sub(&c_pk);

    //    w_ki' = h_pk · z - c · ki_poly
    let hz = h_pk.mul(z);
    let c_ki = c_poly.mul(&proof.ki_poly);
    let w_ki_prime = hz.sub(&c_ki);

    // 6. Recompute challenge from BOTH reconstructed commitments
    let expected_c = dual_challenge(a, public_key, &proof.ki_poly, &w_pk_prime, &w_ki_prime);

    // 7. Challenge must match (constant-time)
    if !ct_eq_32(&expected_c, &proof.challenge) {
        valid = false;
    }

    if valid { Ok(()) } else { Err(reject()) }
}

/// Legacy alias.
pub fn verify_key_image(
    a: &Poly,
    public_key: &Poly,
    key_image: &[u8; 32],
    proof: &KiProof,
) -> Result<(), CryptoError> {
    verify_key_image_proof(a, public_key, key_image, proof)
}

// ═══ Tests ══════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_ring::{
        compute_pubkey, derive_public_param, derive_secret_poly, SpendingKeypair, DEFAULT_A_SEED,
    };
    use crate::pq_sign::MlDsaKeypair;

    fn setup() -> (Poly, Poly, Poly) {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let kp = MlDsaKeypair::generate();
        let s = derive_secret_poly(&kp.secret_key).unwrap();
        let pk = compute_pubkey(&a, &s);
        (a, s, pk)
    }

    // ─── 1. Valid Proof ─────────────────────────────────

    #[test]
    fn test_valid_proof_accepted() {
        let (a, s, pk) = setup();
        let (ki_poly, nullifier) = canonical_strong_ki(&pk, &s);
        let proof = prove_key_image(&a, &s, &pk, &nullifier).unwrap();
        verify_key_image_proof(&a, &pk, &nullifier, &proof).unwrap();
    }

    #[test]
    fn test_serialization_roundtrip() {
        let (a, s, pk) = setup();
        let (_, nullifier) = canonical_strong_ki(&pk, &s);
        let proof = prove_key_image(&a, &s, &pk, &nullifier).unwrap();
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), KI_PROOF_SIZE);
        let proof2 = KiProof::from_bytes(&bytes).unwrap();
        verify_key_image_proof(&a, &pk, &nullifier, &proof2).unwrap();
    }

    // ─── 2. Forged KI (MUST Reject) ─────────────────────

    #[test]
    fn test_forged_ki_rejected_at_prove() {
        let (a, s, pk) = setup();
        let forged_nullifier = [0xDE; 32];
        assert!(
            prove_key_image(&a, &s, &pk, &forged_nullifier).is_err(),
            "prove must reject non-canonical key_image"
        );
    }

    #[test]
    fn test_forged_ki_rejected_at_verify() {
        let (a, s, pk) = setup();
        let (_, real_nullifier) = canonical_strong_ki(&pk, &s);
        let proof = prove_key_image(&a, &s, &pk, &real_nullifier).unwrap();

        // Verify with a forged nullifier
        let forged = [0xAB; 32];
        assert!(
            verify_key_image_proof(&a, &pk, &forged, &proof).is_err(),
            "forged key_image must be rejected"
        );
    }

    #[test]
    fn test_forged_ki_poly_rejected() {
        let (a, s, pk) = setup();
        let (_, real_nullifier) = canonical_strong_ki(&pk, &s);
        let mut proof = prove_key_image(&a, &s, &pk, &real_nullifier).unwrap();

        // Tamper with ki_poly (algebraic KI)
        proof.ki_poly.coeffs[0] = (proof.ki_poly.coeffs[0] + 1) % Q;
        // This changes the nullifier too, so it will fail at step 2
        assert!(
            verify_key_image_proof(&a, &pk, &real_nullifier, &proof).is_err(),
            "tampered ki_poly must be rejected"
        );
    }

    #[test]
    fn test_1bit_ki_alteration_rejected() {
        let (a, s, pk) = setup();
        let (_, real_nullifier) = canonical_strong_ki(&pk, &s);
        let proof = prove_key_image(&a, &s, &pk, &real_nullifier).unwrap();

        let mut altered = real_nullifier;
        altered[0] ^= 0x01;
        assert!(
            verify_key_image_proof(&a, &pk, &altered, &proof).is_err(),
            "1-bit alteration must be rejected"
        );
    }

    // ─── 3. Mismatched Secret (MUST Reject) ─────────────

    #[test]
    fn test_wrong_secret_ki_rejected() {
        let (a, s1, pk1) = setup();
        let (_, _, pk2) = setup(); // Different pk
        let (_, s2, _) = setup(); // Different secret

        // Generate KI from s2 but prove against pk1
        let (_, nullifier_s2) = canonical_strong_ki(&pk1, &s2);
        // This should fail at prove time because pk1 = a*s1, not a*s2
        // The proof will be algebraically incorrect
        let result = prove_key_image(&a, &s2, &pk1, &nullifier_s2);
        if let Ok(proof) = result {
            // Even if the prover cheats (rejection sampling might pass),
            // verification must fail because pk1 ≠ a*s2
            assert!(
                verify_key_image_proof(&a, &pk1, &nullifier_s2, &proof).is_err(),
                "proof with wrong secret must fail verification"
            );
        }
    }

    #[test]
    fn test_wrong_pk_same_ki_rejected() {
        let (a, s1, pk1) = setup();
        let (_, _, pk2) = setup();
        let (_, nullifier) = canonical_strong_ki(&pk1, &s1);
        let proof = prove_key_image(&a, &s1, &pk1, &nullifier).unwrap();

        // Verify against pk2 — must fail
        assert!(
            verify_key_image_proof(&a, &pk2, &nullifier, &proof).is_err(),
            "wrong pk must be rejected"
        );
    }

    // ─── 4. Altered Challenge / Transcript ──────────────

    #[test]
    fn test_altered_challenge_rejected() {
        let (a, s, pk) = setup();
        let (_, nullifier) = canonical_strong_ki(&pk, &s);
        let mut proof = prove_key_image(&a, &s, &pk, &nullifier).unwrap();
        proof.challenge[0] ^= 0xFF;
        assert!(
            verify_key_image_proof(&a, &pk, &nullifier, &proof).is_err(),
            "altered challenge must be rejected"
        );
    }

    #[test]
    fn test_corrupted_response_rejected() {
        let (a, s, pk) = setup();
        let (_, nullifier) = canonical_strong_ki(&pk, &s);
        let mut proof = prove_key_image(&a, &s, &pk, &nullifier).unwrap();
        proof.response.coeffs[0] = (proof.response.coeffs[0] + 1) % Q;
        assert!(
            verify_key_image_proof(&a, &pk, &nullifier, &proof).is_err(),
            "corrupted response must be rejected"
        );
    }

    #[test]
    fn test_transcript_swap_rejected() {
        let (a, s1, pk1) = setup();
        let (_, s2, pk2) = setup();
        let (_, n1) = canonical_strong_ki(&pk1, &s1);
        let (_, n2) = canonical_strong_ki(&pk2, &s2);
        let proof1 = prove_key_image(&a, &s1, &pk1, &n1).unwrap();
        // Try proof1 with pk1 but n2 — transcript malleability
        assert!(
            verify_key_image_proof(&a, &pk1, &n2, &proof1).is_err(),
            "swapped ki must be rejected"
        );
    }

    // ─── Utilities ──────────────────────────────────────

    #[test]
    fn test_ki_deterministic() {
        let (_, s, pk) = setup();
        let (_, n1) = canonical_strong_ki(&pk, &s);
        let (_, n2) = canonical_strong_ki(&pk, &s);
        assert_eq!(n1, n2, "canonical KI must be deterministic");
    }

    #[test]
    fn test_ki_unique_per_secret() {
        let (_, s1, pk1) = setup();
        let (_, s2, pk2) = setup();
        let (_, n1) = canonical_strong_ki(&pk1, &s1);
        let (_, n2) = canonical_strong_ki(&pk2, &s2);
        assert_ne!(n1, n2, "different keys → different KI");
    }

    #[test]
    fn test_hash_to_poly_deterministic() {
        let (_, _, pk) = setup();
        let h1 = hash_to_poly(&pk);
        let h2 = hash_to_poly(&pk);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_to_poly_different_for_different_pk() {
        let (_, _, pk1) = setup();
        let (_, _, pk2) = setup();
        assert_ne!(hash_to_poly(&pk1), hash_to_poly(&pk2));
    }

    #[test]
    fn test_malformed_bytes_rejected() {
        assert!(KiProof::from_bytes(&[]).is_err());
        assert!(KiProof::from_bytes(&[0u8; 10]).is_err());
        assert!(KiProof::from_bytes(&[0u8; KI_PROOF_SIZE + 1]).is_err());
    }
}
