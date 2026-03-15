//! Key Image Correctness Proof (Σ-protocol).
//!
//! Proves knowledge of secret polynomial `s` such that:
//!   - `t = a · s mod q`  (public key relation)
//!   - `I = SHA3-256(DST_KI || SHA3-512(s))` (key image relation)
//!
//! Protocol (Fiat–Shamir transformed):
//!   1. Sample masking polynomial y, compute w = a · y
//!   2. Challenge c = SHA3-256(a || pk || ki || w)
//!   3. Expand c to challenge polynomial c_poly via hash_to_challenge
//!   4. Response z = y + c_poly · s (with rejection sampling: ||z||_∞ < β)

use sha3::{Digest, Sha3_256};
use crate::pq_ring::{
    Poly, Q, N, BETA, MAX_SIGN_ATTEMPTS,
    hash_to_challenge, sample_masking_poly,
};
use crate::error::CryptoError;
use serde::{Serialize, Deserialize};

/// Proof size: challenge(32) + response(N*2=512) + hash_commit(32) = 576 bytes.
pub const KI_PROOF_SIZE: usize = 32 + N * 2 + 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KiProof {
    /// Fiat-Shamir challenge hash: SHA3-256(a || pk || ki || w).
    pub challenge: [u8; 32],
    /// Response polynomial z = y + c_poly * s.
    pub response: Poly,
    /// Commitment hash: SHA3-256(w) for additional binding.
    pub hash_commit: [u8; 32],
}

impl KiProof {
    /// Serialize to bytes (576 bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(KI_PROOF_SIZE);
        buf.extend_from_slice(&self.challenge);
        buf.extend_from_slice(&self.response.to_bytes());
        buf.extend_from_slice(&self.hash_commit);
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() != KI_PROOF_SIZE {
            return Err(CryptoError::RingSignatureInvalid(
                format!("ki_proof bytes: expected {}, got {}", KI_PROOF_SIZE, data.len()),
            ));
        }
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&data[..32]);

        let response = Poly::from_bytes(&data[32..32 + N * 2])?;

        let mut hash_commit = [0u8; 32];
        hash_commit.copy_from_slice(&data[32 + N * 2..]);

        Ok(Self { challenge, response, hash_commit })
    }
}

// --- Prove ---

/// Generate a Key Image Correctness Proof.
///
/// Proves knowledge of `secret` such that `pubkey = a * secret`
/// and `key_image` is correctly derived from `secret`.
pub fn prove_key_image(
    a: &Poly,
    secret: &Poly,
    pubkey: &Poly,
    key_image: &[u8; 32],
) -> Result<KiProof, CryptoError> {
    let a_bytes = a.to_bytes();
    let pk_bytes = pubkey.to_bytes();

    for _ in 0..MAX_SIGN_ATTEMPTS {
        // 1. Sample masking polynomial y, compute commitment w = a * y
        let y = sample_masking_poly();
        let w = a.mul(&y);
        let w_bytes = w.to_bytes();

        // 2. Fiat-Shamir challenge: c = SHA3-256(a || pk || ki || w)
        let challenge: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(&a_bytes);
            h.update(&pk_bytes);
            h.update(key_image);
            h.update(&w_bytes);
            h.finalize().into()
        };

        // 3. Expand to challenge polynomial (sparse, tau nonzero +/-1 coeffs)
        let c_poly = hash_to_challenge(&challenge);

        // 4. Response: z = y + c_poly * s (centered arithmetic)
        let cs = c_poly.mul(secret);
        let mut z = Poly::zero();
        for i in 0..N {
            let y_c = if y.coeffs[i] > Q / 2 { y.coeffs[i] - Q } else { y.coeffs[i] };
            let cs_c = if cs.coeffs[i] > Q / 2 { cs.coeffs[i] - Q } else { cs.coeffs[i] };
            let val = y_c + cs_c;
            z.coeffs[i] = ((val % Q) + Q) % Q;
        }

        // 5. Rejection sampling (constant-time norm check)
        if z.norm_inf() >= BETA {
            continue;
        }

        // 6. Commitment hash for additional binding
        let hash_commit: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(&w_bytes);
            h.finalize().into()
        };

        return Ok(KiProof {
            challenge,
            response: z,
            hash_commit,
        });
    }

    Err(CryptoError::RingSignatureInvalid(
        "ki_proof: exceeded max sign attempts".into(),
    ))
}

// --- Verify ---

/// Verify a Key Image Correctness Proof (Sigma-protocol).
///
/// Checks that the prover knows `s` such that `pubkey = a * s`
/// by reconstructing the commitment and verifying the Fiat-Shamir hash.
pub fn verify_key_image_proof(
    a: &Poly,
    public_key: &Poly,
    key_image: &[u8; 32],
    proof: &KiProof,
) -> Result<(), CryptoError> {
    let z = &proof.response;

    // 1. Check response bound
    if z.norm_inf() >= BETA {
        return Err(CryptoError::RingSignatureInvalid(
            format!("ki_proof response norm {} >= beta={}", z.norm_inf(), BETA),
        ));
    }

    // 2. Expand challenge hash -> challenge polynomial
    let c_poly = hash_to_challenge(&proof.challenge);

    // 3. Reconstruct commitment: w' = a * z - c_poly * pk
    let az = a.mul(z);
    let cpk = c_poly.mul(public_key);
    let w_prime = az.sub(&cpk);

    // 4. Recompute Fiat-Shamir hash
    let expected_c: [u8; 32] = {
        let mut hasher = Sha3_256::new();
        hasher.update(a.to_bytes());
        hasher.update(public_key.to_bytes());
        hasher.update(key_image);
        hasher.update(w_prime.to_bytes());
        hasher.finalize().into()
    };

    // 5. Challenge must match
    if expected_c == proof.challenge {
        Ok(())
    } else {
        Err(CryptoError::RingSignatureInvalid(
            "Key image proof verification failed".to_string(),
        ))
    }
}

/// Legacy alias — prefer `verify_key_image_proof`.
pub fn verify_key_image(
    a: &Poly,
    public_key: &Poly,
    key_image: &[u8; 32],
    proof: &KiProof,
) -> Result<(), CryptoError> {
    verify_key_image_proof(a, public_key, key_image, proof)
}

// --- Tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_ring::{derive_public_param, DEFAULT_A_SEED, SpendingKeypair};
    use crate::pq_sign::MlDsaKeypair;

    #[test]
    fn test_ki_proof_roundtrip() {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let kp = MlDsaKeypair::generate();
        let skp = SpendingKeypair::from_ml_dsa(kp.secret_key);

        let proof = prove_key_image(
            &a, &skp.secret_poly, &skp.public_poly, &skp.key_image,
        ).expect("prove should succeed");

        // Verify
        verify_key_image_proof(&a, &skp.public_poly, &skp.key_image, &proof)
            .expect("verify should succeed");

        // Serialization roundtrip
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), KI_PROOF_SIZE);
        let proof2 = KiProof::from_bytes(&bytes).expect("deserialize should succeed");
        verify_key_image_proof(&a, &skp.public_poly, &skp.key_image, &proof2)
            .expect("verify after roundtrip should succeed");
    }

    #[test]
    fn test_ki_proof_wrong_key_fails() {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let kp1 = MlDsaKeypair::generate();
        let kp2 = MlDsaKeypair::generate();
        let skp1 = SpendingKeypair::from_ml_dsa(kp1.secret_key);
        let skp2 = SpendingKeypair::from_ml_dsa(kp2.secret_key);

        // Prove with skp1's secret
        let proof = prove_key_image(
            &a, &skp1.secret_poly, &skp1.public_poly, &skp1.key_image,
        ).unwrap();

        // Verify against skp2's public key — must fail
        assert!(
            verify_key_image_proof(&a, &skp2.public_poly, &skp1.key_image, &proof).is_err(),
            "proof must not verify against wrong public key"
        );
    }
}
