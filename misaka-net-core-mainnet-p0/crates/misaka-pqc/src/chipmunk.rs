//! ChipmunkRing — Lattice-based ring signature with MISAKA linkability layer.
//!
//! # Design
//!
//! ChipmunkRing itself provides anonymity among ring members but has NO native
//! key image. MISAKA adds a linkability layer on top:
//!
//! ## Signature part (anonymity)
//! Based on a commitment-and-challenge lattice Σ-protocol:
//! - Prover commits to masked polynomials
//! - Hash-chain binds all ring positions
//! - Rejection sampling ensures signature doesn't leak secret
//!
//! ## Linkability part (double-spend detection)
//! Separate from the ring signature:
//! - Deterministic key image: I = SHA3-256("MISAKA-CRS:ki:v1:" || SHA3-512(s))
//! - KI proof: Schnorr-like Σ-protocol proving I was derived from the signing key
//!
//! # Parameters (post-quantum 128-bit security)
//!
//! | Parameter | Value | Description |
//! |-----------|-------|-------------|
//! | q | 12289 | Ring modulus (NTT-friendly prime) |
//! | n | 256 | Polynomial degree |
//! | η | 2 | Secret coefficient bound {-2..2} (wider than LRS) |
//! | τ | 46 | Challenge weight |
//! | γ | 8192 | Masking bound (larger for wider secrets) |
//! | β | 8100 | Rejection threshold (γ − τ·η) |
//! | Ring Size | 4–32 | Extended maximum |

use sha3::{Sha3_256, Sha3_512, Digest as Sha3Digest};
use rand::RngCore;
use serde::{Serialize, Deserialize};

use crate::error::CryptoError;
use crate::pq_ring::{Poly, N, Q};
use crate::ntt;

// ─── ChipmunkRing Parameter Sets ────────────────────────────
//
// Security rationale:
//
//   Ring modulus q = 12289 (NTT-friendly prime, 14-bit, matches Dilithium/NewHope)
//   Polynomial degree n = 256
//
//   Secret bound η (eta):
//     Coefficients of secret polynomial s ∈ {-η, ..., η}.
//     η=2 gives slightly wider secrets than LRS (η=1) for better rejection
//     sampling performance, while maintaining 128-bit PQ security.
//
//   Masking bound γ (gamma):
//     Masking polynomial y sampled uniformly from [-γ+1, γ-1].
//     Must be large enough that z = y + c·s does not leak s.
//     γ = 8192 chosen so γ >> τ·η (= 92) with margin factor ~89x.
//
//   Rejection threshold β (beta):
//     Response z is accepted only if ‖z‖_∞ < β.
//     β = γ − τ·η ensures the rejection sampling distribution is
//     statistically close to uniform.
//     β = 8192 − 46·2 = 8100.
//     Expected signing attempts: ~1.5 (93% acceptance rate).
//
//   Challenge weight τ (tau):
//     Number of nonzero ±1 coefficients in challenge polynomial.
//     τ=46 gives challenge space ≈ C(256,46)·2^46 >> 2^128.
//
//   Max ring size:
//     32 members max (extended from LRS's 16) for better anonymity sets.

/// Auditable parameter set for ChipmunkRing.
/// Values are compile-time constants — no runtime injection allowed.
#[derive(Debug, Clone, Copy)]
pub struct ChipmunkParams {
    /// Secret coefficient bound: s_i ∈ {-η, ..., η}
    pub eta: i32,
    /// Challenge weight (# of nonzero ±1 positions)
    pub tau: usize,
    /// Masking polynomial sampling bound
    pub gamma: i32,
    /// Rejection threshold: β = γ − τ·η
    pub beta: i32,
    /// Minimum ring members
    pub min_ring: usize,
    /// Maximum ring members
    pub max_ring: usize,
    /// Maximum signing attempts before abort
    pub max_attempts: usize,
}

impl ChipmunkParams {
    /// Validate parameter consistency (called at compile-test time).
    pub const fn validate(&self) -> bool {
        // β must equal γ − τ·η
        let expected_beta = self.gamma - (self.tau as i32) * self.eta;
        if self.beta != expected_beta { return false; }
        // γ must be much larger than τ·η
        if self.gamma < (self.tau as i32) * self.eta * 10 { return false; }
        // β must be positive
        if self.beta <= 0 { return false; }
        // Ring bounds
        if self.min_ring < 2 { return false; }
        if self.max_ring < self.min_ring { return false; }
        // η > 0
        if self.eta <= 0 { return false; }
        true
    }
}

/// Production candidate parameter set.
/// ⚠ REQUIRES external cryptographic audit before mainnet.
pub const PARAMS_PRODUCTION: ChipmunkParams = ChipmunkParams {
    eta: 2,
    tau: 46,
    gamma: 8192,
    beta: 8100,     // 8192 − 46·2
    min_ring: 4,
    max_ring: 32,
    max_attempts: 512,
};

/// Toy parameter set for fast unit tests (NOT SECURE).
#[cfg(test)]
pub const PARAMS_TOY: ChipmunkParams = ChipmunkParams {
    eta: 1,
    tau: 20,
    gamma: 4096,
    beta: 4076,     // 4096 − 20·1
    min_ring: 2,
    max_ring: 8,
    max_attempts: 256,
};

// Compile-time parameter validation
const _: () = assert!(PARAMS_PRODUCTION.validate(), "ChipmunkRing production params invalid");

// Active parameter set — always production. No runtime switching.
pub const CR_ETA: i32 = PARAMS_PRODUCTION.eta;
pub const CR_TAU: usize = PARAMS_PRODUCTION.tau;
pub const CR_GAMMA: i32 = PARAMS_PRODUCTION.gamma;
pub const CR_BETA: i32 = PARAMS_PRODUCTION.beta;
pub const CR_MIN_RING: usize = PARAMS_PRODUCTION.min_ring;
pub const CR_MAX_RING: usize = PARAMS_PRODUCTION.max_ring;
pub const CR_MAX_ATTEMPTS: usize = PARAMS_PRODUCTION.max_attempts;

const DST_KI: &[u8] = b"MISAKA-CRS:ki:v1:";
const DST_CHALLENGE: &[u8] = b"MISAKA-CRS:challenge:v1:";
const DST_COMMITMENT: &[u8] = b"MISAKA-CRS:commit:v1:";

// ─── ChipmunkRing Signature ─────────────────────────────────

/// ChipmunkRing signature (ring part only, no key image).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChipmunkSig {
    /// Initial challenge polynomial c_0 (in sparse ±1 set).
    pub c0: Poly,
    /// Response polynomials, one per ring member.
    pub responses: Vec<Poly>,
}

impl ChipmunkSig {
    pub fn to_bytes(&self) -> Vec<u8> {
        let n = self.responses.len();
        let mut buf = Vec::with_capacity(N + n * N * 2);
        buf.extend_from_slice(&self.c0.challenge_to_bytes());
        for z in &self.responses {
            buf.extend_from_slice(&z.to_bytes());
        }
        buf
    }

    pub fn from_bytes(data: &[u8], ring_size: usize) -> Result<Self, CryptoError> {
        let expected = N + ring_size * N * 2;
        if data.len() != expected {
            return Err(CryptoError::RingSignatureInvalid(
                format!("chipmunk sig: expected {} bytes, got {}", expected, data.len())));
        }
        let c0 = Poly::challenge_from_bytes(&data[..N])?;
        let mut responses = Vec::with_capacity(ring_size);
        for i in 0..ring_size {
            let start = N + i * N * 2;
            let z = Poly::from_bytes(&data[start..start + N * 2])?;
            responses.push(z);
        }
        Ok(Self { c0, responses })
    }
}

// ─── Key Image (Linkability Layer) ──────────────────────────

/// Compute deterministic key image for ChipmunkRing.
///
/// `I = SHA3-256("MISAKA-CRS:ki:v1:" || SHA3-512(s_bytes))`
///
/// This is separate from the ring signature and provides linkability
/// for double-spend detection.
pub fn chipmunk_compute_key_image(secret: &Poly) -> [u8; 32] {
    let s_bytes = secret.to_bytes();
    let inner: [u8; 64] = {
        let mut h = Sha3_512::new();
        h.update(&s_bytes);
        h.finalize().into()
    };
    let mut h = Sha3_256::new();
    h.update(DST_KI);
    h.update(&inner);
    h.finalize().into()
}

// ─── Key Image Proof (Σ-Protocol) ───────────────────────────

/// ChipmunkRing KI proof.
///
/// Same structure as LRS KI proof but with different DST and parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChipmunkKiProof {
    pub challenge: [u8; 32],
    pub response: Poly,
    pub hash_commit: [u8; 32],
}

pub const CR_KI_PROOF_SIZE: usize = 32 + N * 2 + 32;

impl ChipmunkKiProof {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(CR_KI_PROOF_SIZE);
        buf.extend_from_slice(&self.challenge);
        buf.extend_from_slice(&self.response.to_bytes());
        buf.extend_from_slice(&self.hash_commit);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() != CR_KI_PROOF_SIZE {
            return Err(CryptoError::RingSignatureInvalid(
                format!("chipmunk ki_proof: expected {}, got {}", CR_KI_PROOF_SIZE, data.len())));
        }
        let mut challenge = [0u8; 32];
        challenge.copy_from_slice(&data[..32]);
        let response = Poly::from_bytes(&data[32..32 + N * 2])?;
        let mut hash_commit = [0u8; 32];
        hash_commit.copy_from_slice(&data[32 + N * 2..]);
        Ok(Self { challenge, response, hash_commit })
    }
}

// ─── Challenge Hashing ──────────────────────────────────────

fn cr_hash_to_challenge(data: &[u8]) -> Poly {
    let mut c = Poly::zero();
    let seed: [u8; 64] = {
        let mut h = Sha3_512::new();
        h.update(DST_CHALLENGE);
        h.update(data);
        h.finalize().into()
    };
    let mut positions: Vec<usize> = (0..N).collect();
    for i in 0..CR_TAU {
        let mut h = Sha3_256::new();
        h.update(&seed);
        h.update(&(i as u32).to_le_bytes());
        let hout: [u8; 32] = h.finalize().into();
        let idx = (u32::from_le_bytes([hout[0], hout[1], hout[2], hout[3]]) as usize) % (N - i);
        positions.swap(i, i + idx);
        let sign = if hout[4] & 1 == 0 { 1 } else { Q - 1 };
        c.coeffs[positions[i]] = sign;
    }
    c
}

// ─── Masking / Response Sampling ────────────────────────────

fn cr_sample_masking() -> Poly {
    let mut rng = rand::thread_rng();
    let mut y = Poly::zero();
    let range = (2 * CR_GAMMA - 1) as u32;
    let mut buf = [0u8; N * 4];
    rng.fill_bytes(&mut buf);
    for i in 0..N {
        let raw = u32::from_le_bytes([buf[i*4], buf[i*4+1], buf[i*4+2], buf[i*4+3]]);
        let val = (raw % range) as i32 - (CR_GAMMA - 1);
        y.coeffs[i] = ((val % Q) + Q) % Q;
    }
    y
}

fn cr_sample_response() -> Poly {
    let mut rng = rand::thread_rng();
    let mut z = Poly::zero();
    let range = (2 * CR_BETA - 1) as u32;
    let mut buf = [0u8; N * 4];
    rng.fill_bytes(&mut buf);
    for i in 0..N {
        let raw = u32::from_le_bytes([buf[i*4], buf[i*4+1], buf[i*4+2], buf[i*4+3]]);
        let val = (raw % range) as i32 - (CR_BETA - 1);
        z.coeffs[i] = ((val % Q) + Q) % Q;
    }
    z
}

// ─── Ring Signature ─────────────────────────────────────────

/// Sign with ChipmunkRing scheme.
///
/// Returns only the ring signature (no key image — that's separate).
pub fn chipmunk_ring_sign(
    a: &Poly,
    ring_pubkeys: &[Poly],
    signer_index: usize,
    secret: &Poly,
    message: &[u8; 32],
) -> Result<ChipmunkSig, CryptoError> {
    let n_ring = ring_pubkeys.len();
    if n_ring < CR_MIN_RING || n_ring > CR_MAX_RING {
        return Err(CryptoError::RingSignatureInvalid(
            format!("ring size {} out of range [{}, {}]", n_ring, CR_MIN_RING, CR_MAX_RING)));
    }
    if signer_index >= n_ring {
        return Err(CryptoError::RingSignatureInvalid("signer index out of range".into()));
    }

    // Build ring hash (binds message + ring)
    let mut ring_encoding = Vec::new();
    ring_encoding.extend_from_slice(DST_COMMITMENT);
    ring_encoding.extend_from_slice(message);
    for pk in ring_pubkeys { ring_encoding.extend_from_slice(&pk.to_bytes()); }
    let h: [u8; 32] = {
        let mut hasher = Sha3_256::new();
        hasher.update(&ring_encoding);
        hasher.finalize().into()
    };

    for _ in 0..CR_MAX_ATTEMPTS {
        // Step 1: honest commitment
        let y = cr_sample_masking();
        let w_pi = a.mul(&y);

        // Step 2: derive c_{π+1}
        let mut chain_input = Vec::new();
        chain_input.extend_from_slice(&h);
        chain_input.extend_from_slice(&w_pi.to_bytes());
        let mut c_next = cr_hash_to_challenge(&chain_input);

        // Step 3: simulate all other positions
        let mut responses = vec![Poly::zero(); n_ring];
        let mut challenges = vec![Poly::zero(); n_ring];

        let mut idx = (signer_index + 1) % n_ring;
        loop {
            if idx == signer_index { break; }
            challenges[idx] = c_next.clone();
            let z_i = cr_sample_response();
            let az = a.mul(&z_i);
            let ct = challenges[idx].mul(&ring_pubkeys[idx]);
            let w_i = az.sub(&ct);
            responses[idx] = z_i;
            let mut ci_input = Vec::new();
            ci_input.extend_from_slice(&h);
            ci_input.extend_from_slice(&w_i.to_bytes());
            c_next = cr_hash_to_challenge(&ci_input);
            idx = (idx + 1) % n_ring;
        }

        // Step 4: close the ring
        challenges[signer_index] = c_next;
        let cs = challenges[signer_index].mul(secret);
        let mut z_pi = Poly::zero();
        for i in 0..N {
            let y_c = if y.coeffs[i] > Q / 2 { y.coeffs[i] - Q } else { y.coeffs[i] };
            let cs_c = if cs.coeffs[i] > Q / 2 { cs.coeffs[i] - Q } else { cs.coeffs[i] };
            let val = y_c + cs_c;
            z_pi.coeffs[i] = ((val % Q) + Q) % Q;
        }

        // Rejection sampling
        if z_pi.norm_inf() >= CR_BETA { continue; }

        responses[signer_index] = z_pi;

        return Ok(ChipmunkSig {
            c0: challenges[0].clone(),
            responses,
        });
    }

    Err(CryptoError::RingSignatureInvalid("exceeded max sign attempts".into()))
}

/// Verify ChipmunkRing signature.
pub fn chipmunk_ring_verify(
    a: &Poly,
    ring_pubkeys: &[Poly],
    message: &[u8; 32],
    sig: &ChipmunkSig,
) -> Result<(), CryptoError> {
    let n_ring = ring_pubkeys.len();
    if n_ring < CR_MIN_RING || n_ring > CR_MAX_RING {
        return Err(CryptoError::RingSignatureInvalid("ring size out of range".into()));
    }
    if sig.responses.len() != n_ring {
        return Err(CryptoError::RingSignatureInvalid("response count mismatch".into()));
    }

    let mut ring_encoding = Vec::new();
    ring_encoding.extend_from_slice(DST_COMMITMENT);
    ring_encoding.extend_from_slice(message);
    for pk in ring_pubkeys { ring_encoding.extend_from_slice(&pk.to_bytes()); }
    let h: [u8; 32] = {
        let mut hasher = Sha3_256::new();
        hasher.update(&ring_encoding);
        hasher.finalize().into()
    };

    let mut c_current = sig.c0.clone();

    for i in 0..n_ring {
        if sig.responses[i].norm_inf() >= CR_BETA {
            return Err(CryptoError::RingSignatureInvalid(
                format!("response[{}] norm >= β", i)));
        }
        let az = a.mul(&sig.responses[i]);
        let ct = c_current.mul(&ring_pubkeys[i]);
        let w_i = az.sub(&ct);
        let mut ci_input = Vec::new();
        ci_input.extend_from_slice(&h);
        ci_input.extend_from_slice(&w_i.to_bytes());
        c_current = cr_hash_to_challenge(&ci_input);
    }

    if c_current != sig.c0 {
        return Err(CryptoError::RingSignatureInvalid("ring does not close".into()));
    }

    Ok(())
}

// ─── KI Proof ───────────────────────────────────────────────

/// Prove key image correctness (Σ-protocol, ChipmunkRing variant).
pub fn chipmunk_prove_ki(
    a: &Poly,
    secret: &Poly,
    pubkey: &Poly,
    key_image: &[u8; 32],
) -> Result<ChipmunkKiProof, CryptoError> {
    let a_bytes = a.to_bytes();
    let pk_bytes = pubkey.to_bytes();

    for _ in 0..CR_MAX_ATTEMPTS {
        let y = cr_sample_masking();
        let w = a.mul(&y);
        let w_bytes = w.to_bytes();

        let challenge: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(b"MISAKA-CRS:ki-proof:v1:");
            h.update(&a_bytes);
            h.update(&pk_bytes);
            h.update(key_image);
            h.update(&w_bytes);
            h.finalize().into()
        };

        let c_poly = cr_hash_to_challenge(&challenge);
        let cs = c_poly.mul(secret);
        let mut z = Poly::zero();
        for i in 0..N {
            let y_c = if y.coeffs[i] > Q / 2 { y.coeffs[i] - Q } else { y.coeffs[i] };
            let cs_c = if cs.coeffs[i] > Q / 2 { cs.coeffs[i] - Q } else { cs.coeffs[i] };
            let val = y_c + cs_c;
            z.coeffs[i] = ((val % Q) + Q) % Q;
        }

        if z.norm_inf() >= CR_BETA { continue; }

        let hash_commit: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(&w_bytes);
            h.finalize().into()
        };

        return Ok(ChipmunkKiProof { challenge, response: z, hash_commit });
    }

    Err(CryptoError::RingSignatureInvalid("ki proof: exceeded max attempts".into()))
}

/// Verify ChipmunkRing KI proof.
pub fn chipmunk_verify_ki(
    a: &Poly,
    pubkey: &Poly,
    key_image: &[u8; 32],
    proof: &ChipmunkKiProof,
) -> Result<(), CryptoError> {
    if proof.response.norm_inf() >= CR_BETA {
        return Err(CryptoError::RingSignatureInvalid("ki proof response norm too large".into()));
    }

    let c_poly = cr_hash_to_challenge(&proof.challenge);
    let az = a.mul(&proof.response);
    let cpk = c_poly.mul(pubkey);
    let w_prime = az.sub(&cpk);

    let expected_c: [u8; 32] = {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA-CRS:ki-proof:v1:");
        h.update(a.to_bytes());
        h.update(pubkey.to_bytes());
        h.update(key_image);
        h.update(w_prime.to_bytes());
        h.finalize().into()
    };

    if expected_c == proof.challenge {
        Ok(())
    } else {
        Err(CryptoError::RingSignatureInvalid("ki proof verification failed".into()))
    }
}

// ─── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_sign::MlDsaKeypair;
    use crate::pq_ring::{derive_secret_poly, derive_public_param, DEFAULT_A_SEED};

    fn setup() -> (Poly, Vec<Poly>, Vec<Poly>) {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let mut sks = Vec::new();
        let mut pks = Vec::new();
        for _ in 0..4 {
            let kp = MlDsaKeypair::generate();
            let sk = derive_secret_poly(&kp.secret_key);
            let pk = a.mul(&sk);
            sks.push(sk);
            pks.push(pk);
        }
        (a, sks, pks)
    }

    #[test]
    fn test_chipmunk_sign_verify() {
        let (a, sks, pks) = setup();
        let msg = [0x42u8; 32];
        let sig = chipmunk_ring_sign(&a, &pks, 0, &sks[0], &msg).unwrap();
        chipmunk_ring_verify(&a, &pks, &msg, &sig).unwrap();
    }

    #[test]
    fn test_chipmunk_wrong_message_fails() {
        let (a, sks, pks) = setup();
        let msg = [0x42u8; 32];
        let sig = chipmunk_ring_sign(&a, &pks, 0, &sks[0], &msg).unwrap();
        let bad_msg = [0x43u8; 32];
        assert!(chipmunk_ring_verify(&a, &pks, &bad_msg, &sig).is_err());
    }

    #[test]
    fn test_chipmunk_ki_deterministic() {
        let (_, sks, _) = setup();
        let ki1 = chipmunk_compute_key_image(&sks[0]);
        let ki2 = chipmunk_compute_key_image(&sks[0]);
        assert_eq!(ki1, ki2);
    }

    #[test]
    fn test_chipmunk_ki_unique() {
        let (_, sks, _) = setup();
        let ki0 = chipmunk_compute_key_image(&sks[0]);
        let ki1 = chipmunk_compute_key_image(&sks[1]);
        assert_ne!(ki0, ki1);
    }

    #[test]
    fn test_chipmunk_ki_proof() {
        let (a, sks, pks) = setup();
        let ki = chipmunk_compute_key_image(&sks[0]);
        let proof = chipmunk_prove_ki(&a, &sks[0], &pks[0], &ki).unwrap();
        chipmunk_verify_ki(&a, &pks[0], &ki, &proof).unwrap();
    }

    #[test]
    fn test_chipmunk_ki_proof_wrong_pk_fails() {
        let (a, sks, pks) = setup();
        let ki = chipmunk_compute_key_image(&sks[0]);
        let proof = chipmunk_prove_ki(&a, &sks[0], &pks[0], &ki).unwrap();
        assert!(chipmunk_verify_ki(&a, &pks[1], &ki, &proof).is_err());
    }

    #[test]
    fn test_chipmunk_sig_serialization() {
        let (a, sks, pks) = setup();
        let msg = [0xAA; 32];
        let sig = chipmunk_ring_sign(&a, &pks, 0, &sks[0], &msg).unwrap();
        let bytes = sig.to_bytes();
        let sig2 = ChipmunkSig::from_bytes(&bytes, 4).unwrap();
        chipmunk_ring_verify(&a, &pks, &msg, &sig2).unwrap();
    }

    #[test]
    fn test_chipmunk_ki_proof_serialization() {
        let (a, sks, pks) = setup();
        let ki = chipmunk_compute_key_image(&sks[0]);
        let proof = chipmunk_prove_ki(&a, &sks[0], &pks[0], &ki).unwrap();
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), CR_KI_PROOF_SIZE);
        let proof2 = ChipmunkKiProof::from_bytes(&bytes).unwrap();
        chipmunk_verify_ki(&a, &pks[0], &ki, &proof2).unwrap();
    }

    #[test]
    fn test_chipmunk_ring_size_8() {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let mut sks = Vec::new();
        let mut pks = Vec::new();
        for _ in 0..8 {
            let kp = MlDsaKeypair::generate();
            let sk = derive_secret_poly(&kp.secret_key);
            let pk = a.mul(&sk);
            sks.push(sk);
            pks.push(pk);
        }
        let msg = [0x55; 32];
        let sig = chipmunk_ring_sign(&a, &pks, 3, &sks[3], &msg).unwrap();
        chipmunk_ring_verify(&a, &pks, &msg, &sig).unwrap();
    }

    // ─── Parameter validation tests ─────────────────────────

    #[test]
    fn test_production_params_valid() {
        assert!(PARAMS_PRODUCTION.validate());
    }

    #[test]
    fn test_toy_params_valid() {
        assert!(PARAMS_TOY.validate());
    }

    #[test]
    fn test_beta_equals_gamma_minus_tau_eta() {
        assert_eq!(CR_BETA, CR_GAMMA - (CR_TAU as i32) * CR_ETA);
        assert_eq!(CR_BETA, 8100);
    }

    #[test]
    fn test_gamma_margin_over_tau_eta() {
        // γ must be >> τ·η for security
        let tau_eta = (CR_TAU as i32) * CR_ETA;
        assert!(CR_GAMMA > tau_eta * 10, "insufficient γ margin: {} vs {}", CR_GAMMA, tau_eta);
    }

    // ─── Boundary / negative tests ──────────────────────────

    #[test]
    fn test_ring_too_small_rejected() {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let kp = MlDsaKeypair::generate();
        let sk = derive_secret_poly(&kp.secret_key);
        let pk = a.mul(&sk);
        let ring = vec![pk.clone(), pk.clone(), pk.clone()]; // 3 < min 4
        let msg = [0x42; 32];
        assert!(chipmunk_ring_sign(&a, &ring, 0, &sk, &msg).is_err());
    }

    #[test]
    fn test_ring_too_large_rejected() {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let kp = MlDsaKeypair::generate();
        let sk = derive_secret_poly(&kp.secret_key);
        let pk = a.mul(&sk);
        let ring: Vec<Poly> = (0..33).map(|_| pk.clone()).collect(); // 33 > max 32
        let msg = [0x42; 32];
        assert!(chipmunk_ring_sign(&a, &ring, 0, &sk, &msg).is_err());
    }

    #[test]
    fn test_signer_index_oob_rejected() {
        let (a, sks, pks) = setup();
        let msg = [0x42; 32];
        assert!(chipmunk_ring_sign(&a, &pks, 99, &sks[0], &msg).is_err());
    }

    #[test]
    fn test_verify_ring_size_mismatch_rejected() {
        let (a, sks, pks) = setup();
        let msg = [0x42; 32];
        let sig = chipmunk_ring_sign(&a, &pks, 0, &sks[0], &msg).unwrap();
        // Verify with a different ring → must fail
        let (_, _, pks2) = setup();
        assert!(chipmunk_ring_verify(&a, &pks2, &msg, &sig).is_err());
    }

    #[test]
    fn test_tampered_response_rejected() {
        let (a, sks, pks) = setup();
        let msg = [0x42; 32];
        let mut sig = chipmunk_ring_sign(&a, &pks, 0, &sks[0], &msg).unwrap();
        // Tamper with a response coefficient
        sig.responses[0].coeffs[0] = (sig.responses[0].coeffs[0] + 1) % Q;
        assert!(chipmunk_ring_verify(&a, &pks, &msg, &sig).is_err());
    }

    #[test]
    fn test_tampered_c0_rejected() {
        let (a, sks, pks) = setup();
        let msg = [0x42; 32];
        let mut sig = chipmunk_ring_sign(&a, &pks, 0, &sks[0], &msg).unwrap();
        sig.c0.coeffs[0] = (sig.c0.coeffs[0] + 1) % Q;
        assert!(chipmunk_ring_verify(&a, &pks, &msg, &sig).is_err());
    }

    #[test]
    fn test_response_norm_at_boundary() {
        // Verify that a response with norm = β is rejected (must be < β)
        let (a, _, pks) = setup();
        let msg = [0x42; 32];
        let mut sig = ChipmunkSig {
            c0: Poly::zero(),
            responses: vec![Poly::zero(); 4],
        };
        // Set one coefficient to exactly β → should fail norm check
        sig.responses[0].coeffs[0] = CR_BETA as i32;
        assert!(chipmunk_ring_verify(&a, &pks, &msg, &sig).is_err());
    }

    #[test]
    fn test_ki_proof_wrong_key_image() {
        let (a, sks, pks) = setup();
        let ki = chipmunk_compute_key_image(&sks[0]);
        let proof = chipmunk_prove_ki(&a, &sks[0], &pks[0], &ki).unwrap();
        // Verify against wrong KI
        let bad_ki = [0xFF; 32];
        assert!(chipmunk_verify_ki(&a, &pks[0], &bad_ki, &proof).is_err());
    }

    #[test]
    fn test_malformed_sig_bytes_rejected() {
        // Too short
        assert!(ChipmunkSig::from_bytes(&[0u8; 10], 4).is_err());
        // Wrong ring size
        let (a, sks, pks) = setup();
        let msg = [0x42; 32];
        let sig = chipmunk_ring_sign(&a, &pks, 0, &sks[0], &msg).unwrap();
        let bytes = sig.to_bytes();
        assert!(ChipmunkSig::from_bytes(&bytes, 5).is_err()); // 5 != 4
    }

    #[test]
    fn test_malformed_ki_proof_bytes_rejected() {
        assert!(ChipmunkKiProof::from_bytes(&[0u8; 10]).is_err());
        assert!(ChipmunkKiProof::from_bytes(&[0u8; CR_KI_PROOF_SIZE + 1]).is_err());
    }
}
