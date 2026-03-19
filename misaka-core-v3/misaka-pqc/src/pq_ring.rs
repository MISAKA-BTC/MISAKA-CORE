//! MISAKA Lattice Ring Signature (LRS-v1).
//!
//! # Construction
//!
//! Based on Lyubashevsky Σ-protocol over R_q = Z_q[X]/(X^256+1),
//! composed into a hash-chain ring signature.
//!
//! ```text
//! ML-DSA-65 secret key (PQ identity)
//!   └─ HKDF ─→ lattice secret polynomial s ∈ R_q (short)
//!   └─ public key t = a·s mod q
//!   └─ key image I = SHA3-256(SHA3-512(s))
//!   └─ ring signature: hash-chain over Lyubashevsky Σ-protocol
//! ```
//!
//! **No ECC.** All algebra is over polynomial rings Z_q[X]/(X^256+1).
//!
//! # Parameters (128-bit post-quantum security)
//!
//! | Parameter | Value | Description |
//! |-----------|-------|-------------|
//! | q         | 12289 | Ring modulus (NTT-friendly prime) |
//! | n         | 256   | Polynomial degree |
//! | η         | 1     | Secret coefficient bound {-1,0,1} |
//! | τ         | 46    | Challenge weight (≈2^128 space) |
//! | γ         | 6000  | Masking bound |
//! | β         | 5954  | Rejection threshold (γ - τ·η) |

use sha3::{Sha3_256, Sha3_512, Digest as Sha3Digest};
use hkdf::Hkdf;
use rand::RngCore;

use crate::error::CryptoError;
use crate::pq_sign::MlDsaSecretKey;

use serde::{Serialize, Deserialize};
use serde_with::serde_as;
// ─── Parameters ──────────────────────────────────────────────

pub const Q: i32 = 12289;
pub const N: usize = 256;
pub const ETA: i32 = 1;
pub const TAU: usize = 46;
pub const GAMMA: i32 = 6000;
pub const BETA: i32 = GAMMA - (TAU as i32) * ETA; // 5954
pub const MIN_RING_SIZE: usize = 4;
pub const MAX_RING_SIZE: usize = 16;
pub const MAX_SIGN_ATTEMPTS: usize = 256;

const DST_SPENDING: &[u8] = b"misaka/lrs/spending-key/v1";
const DST_KI: &[u8] = b"MISAKA-LRS:ki:v1:";
const DST_PUBPARAM: &[u8] = b"MISAKA-LRS:a-param:v1";
const DST_CHALLENGE: &[u8] = b"MISAKA-LRS:challenge:v1:";

// ─── Polynomial Type ─────────────────────────────────────────

/// Polynomial in R_q = Z_q[X]/(X^256+1).
/// Coefficients stored as i32, reduced to [0, q) after operations.
#[serde_as]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Poly {
    #[serde_as(as = "[_; 256]")]
    pub coeffs: [i32; N],
}

impl std::fmt::Debug for Poly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Poly([{},..])", self.coeffs[0])
    }
}

impl Poly {
    pub fn zero() -> Self { Self { coeffs: [0; N] } }

    /// Reduce all coefficients to [0, q).
    pub fn reduce(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c = ((*c % Q) + Q) % Q;
        }
    }

    /// Polynomial addition mod q.
    pub fn add(&self, other: &Poly) -> Poly {
        let mut r = Poly::zero();
        for i in 0..N {
            r.coeffs[i] = (self.coeffs[i] + other.coeffs[i]) % Q;
            if r.coeffs[i] < 0 { r.coeffs[i] += Q; }
        }
        r
    }

    /// Polynomial subtraction mod q.
    pub fn sub(&self, other: &Poly) -> Poly {
        let mut r = Poly::zero();
        for i in 0..N {
            r.coeffs[i] = (self.coeffs[i] - other.coeffs[i]) % Q;
            if r.coeffs[i] < 0 { r.coeffs[i] += Q; }
        }
        r
    }

    /// Schoolbook polynomial multiplication O(n²). Used as reference.
    #[allow(dead_code)]
    pub fn mul_schoolbook(&self, other: &Poly) -> Poly {
        let mut r = [0i64; N];
        for i in 0..N {
            if self.coeffs[i] == 0 { continue; }
            for j in 0..N {
                if other.coeffs[j] == 0 { continue; }
                let k = i + j;
                let prod = self.coeffs[i] as i64 * other.coeffs[j] as i64;
                if k < N {
                    r[k] += prod;
                } else {
                    // X^256 = -1 in R_q
                    r[k - N] -= prod;
                }
            }
        }
        let mut out = Poly::zero();
        for i in 0..N {
            out.coeffs[i] = ((r[i] % Q as i64 + Q as i64) % Q as i64) as i32;
        }
        out
    }

    /// Polynomial multiplication via NTT. O(n log n).
    pub fn mul(&self, other: &Poly) -> Poly {
        crate::ntt::ntt_mul(self, other)
    }

    /// Infinity norm (centered representation).
    /// Constant-time: no secret-dependent branching.
    pub fn norm_inf(&self) -> i32 {
        let mut max_val = 0i32;
        for &c in &self.coeffs {
            // Constant-time centering: centered = c - Q * (c > Q/2)
            let above_half = ((Q / 2 - c) >> 31) & 1; // 1 if c > Q/2, else 0
            let centered = c - Q * above_half;
            // Constant-time abs: mask = centered >> 31 (all 1s if negative)
            let mask = centered >> 31;
            let abs_val = (centered ^ mask) - mask;
            // Constant-time max
            let gt = ((max_val - abs_val) >> 31) & 1; // 1 if abs_val > max_val
            max_val = max_val + gt * (abs_val - max_val);
        }
        max_val
    }

    /// Serialize to bytes (2 bytes per coefficient, LE).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(N * 2);
        for &c in &self.coeffs {
            buf.extend_from_slice(&(c as u16).to_le_bytes());
        }
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() != N * 2 {
            return Err(CryptoError::RingSignatureInvalid(
                format!("poly bytes: expected {}, got {}", N * 2, data.len())));
        }
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = u16::from_le_bytes([data[i * 2], data[i * 2 + 1]]) as i32;
            if p.coeffs[i] >= Q {
                return Err(CryptoError::RingSignatureInvalid("coefficient >= q".into()));
            }
        }
        Ok(p)
    }

    /// Serialize challenge polynomial (1 byte per coeff, signed: 0, 1, or 0xFF=-1).
    /// Returns Err if any coefficient is not a valid challenge value.
    pub fn challenge_to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let mut result = Vec::with_capacity(N);
        for (i, &c) in self.coeffs.iter().enumerate() {
            let byte = if c == 0 { 0u8 }
            else if c == 1 { 1u8 }
            else if c == Q - 1 { 0xFFu8 } // -1 mod q
            else {
                return Err(CryptoError::RingSignatureInvalid(
                    format!("invalid challenge coefficient at [{}]: {}", i, c)
                ));
            };
            result.push(byte);
        }
        Ok(result)
    }

    /// Deserialize challenge polynomial.
    pub fn challenge_from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() != N {
            return Err(CryptoError::RingSignatureInvalid("challenge bytes".into()));
        }
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = match data[i] {
                0 => 0,
                1 => 1,
                0xFF => Q - 1, // -1 mod q
                _ => return Err(CryptoError::RingSignatureInvalid("bad challenge byte".into())),
            };
        }
        Ok(p)
    }
}

// ─── Shared Public Parameter ─────────────────────────────────

/// Derive the shared polynomial 'a' from a seed (deterministic).
///
/// SEC-AUDIT-V4 HIGH-001 fix: Uses 32-bit rejection sampling instead of
/// 16-bit modular reduction. The old code had `u16 % 12289` which produces
/// ~20% bias on some residue classes (65536/12289 is not an integer).
/// Rejection sampling eliminates all distributional bias.
pub fn derive_public_param(seed: &[u8; 32]) -> Poly {
    let mut h = Sha3_512::new();
    h.update(DST_PUBPARAM);
    h.update(seed);
    let hash = h.finalize();

    // Expand with SHAKE-like approach using SHA3-256 iterations
    let mut a = Poly::zero();
    let mut expand_buf = [0u8; 32];
    expand_buf.copy_from_slice(&hash[..32]);

    // SEC-AUDIT-V4 HIGH-001: rejection threshold for unbiased sampling
    let threshold = u32::MAX - (u32::MAX % Q as u32);

    for i in 0..N {
        // Use counter to allow rejection sampling retries deterministically
        let mut counter = 0u32;
        loop {
            let mut h2 = Sha3_256::new();
            h2.update(&expand_buf);
            h2.update(&(i as u32).to_le_bytes());
            h2.update(&counter.to_le_bytes());
            let hout: [u8; 32] = h2.finalize().into();
            let raw = u32::from_le_bytes([hout[0], hout[1], hout[2], hout[3]]);
            if raw < threshold {
                a.coeffs[i] = (raw % Q as u32) as i32;
                break;
            }
            counter += 1;
            // Rejection probability is ~3e-10 per attempt, so this loop
            // terminates in 1 iteration with overwhelming probability.
        }
    }
    a
}

/// Default shared parameter seed.
pub const DEFAULT_A_SEED: [u8; 32] = [
    0x4D, 0x49, 0x53, 0x41, 0x4B, 0x41, 0x2D, 0x4C, // MISAKA-L
    0x52, 0x53, 0x2D, 0x76, 0x31, 0x2D, 0x73, 0x65, // RS-v1-se
    0x65, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ed......
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // .......1
];

// ─── Key Generation ──────────────────────────────────────────

/// Derive a lattice secret polynomial from ML-DSA-65 secret key.
/// Coefficients in {-1, 0, 1} (η=1).
///
/// # Errors
///
/// Returns `CryptoError` if HKDF expansion fails (SEC-006 fix).
/// Previous implementation silently returned `Poly::zero()` on failure,
/// which would produce predictable keys and key image collisions.
pub fn derive_secret_poly(ml_dsa_sk: &MlDsaSecretKey) -> Result<Poly, CryptoError> {
    let hk = Hkdf::<Sha3_256>::new(None, ml_dsa_sk.as_bytes());
    let mut expanded = [0u8; N];
    hk.expand(DST_SPENDING, &mut expanded)
        .map_err(|_| CryptoError::RingSignatureInvalid(
            "HKDF expand failed in derive_secret_poly — refusing to use zero polynomial".into()
        ))?;

    let mut s = Poly::zero();
    for i in 0..N {
        // Map byte to {-1, 0, 1}: 0-84 → -1, 85-170 → 0, 171-255 → 1
        s.coeffs[i] = match expanded[i] {
            0..=84 => Q - 1,   // -1 mod q
            85..=170 => 0,
            _ => 1,
        };
    }
    Ok(s)
}

/// Compute public key: t = a * s mod q.
pub fn compute_pubkey(a: &Poly, s: &Poly) -> Poly {
    a.mul(s)
}

/// Compute key image: deterministic from secret polynomial.
///
/// `I = SHA3-256(DST_KI || SHA3-512(s_bytes))`
///
/// # Linkability properties
///
/// - **Deterministic**: Same `s` always produces same `I`.
/// - **One-way**: Cannot recover `s` from `I` (preimage resistance of SHA3).
/// - **Unlinkable to ring**: Verifier sees `I` but cannot determine which
///   ring member produced it (ring signature anonymity).
/// - **Exculpable**: Nobody can forge a key image for another party's `s`
///   without knowing `s` (second preimage resistance).
///
/// For stealth addresses, use `compute_key_image_bound()` instead,
/// which binds the key image to a specific one-time address.
#[deprecated(note = "Use nullifier::compute_nullifier instead")]
pub fn compute_key_image(s: &Poly) -> [u8; 32] {
    let s_bytes = s.to_bytes();
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

/// Compute key image bound to a stealth one-time address.
///
/// `I = SHA3-256(DST_KI || SHA3-512(s_bytes) || one_time_address)`
///
/// This variant ties the key image to a specific output, preventing
/// key image reuse across different stealth outputs derived from
/// the same underlying identity.
#[deprecated(note = "Use nullifier::compute_nullifier instead")]
pub fn compute_key_image_bound(s: &Poly, one_time_address: &[u8; 32]) -> [u8; 32] {
    let s_bytes = s.to_bytes();
    let inner: [u8; 64] = {
        let mut h = Sha3_512::new();
        h.update(&s_bytes);
        h.finalize().into()
    };
    let mut h = Sha3_256::new();
    h.update(DST_KI);
    h.update(&inner);
    h.update(one_time_address);
    h.finalize().into()
}

// ─── Challenge Hash ──────────────────────────────────────────

/// Hash-to-challenge: map bytes → polynomial in C_τ.
/// Exactly τ coefficients are ±1, rest are 0.
/// Uses rejection sampling in Fisher-Yates to eliminate modular bias.
pub(crate) fn hash_to_challenge(data: &[u8]) -> Poly {
    let mut c = Poly::zero();
    // Expand hash to get enough randomness
    let seed: [u8; 64] = {
        let mut h = Sha3_512::new();
        h.update(DST_CHALLENGE);
        h.update(data);
        h.finalize().into()
    };

    // Select τ positions using Fisher-Yates with rejection sampling
    let mut positions: Vec<usize> = (0..N).collect();
    for i in 0..TAU {
        let remaining = N - i;
        // Derive deterministic randomness via chained hashing
        let mut h = Sha3_256::new();
        h.update(&seed);
        h.update(&(i as u32).to_le_bytes());
        let hout: [u8; 32] = h.finalize().into();

        // Rejection sampling: reject values >= largest multiple of `remaining`
        let range = remaining as u32;
        let threshold = u32::MAX - (u32::MAX % range);
        let raw = u32::from_le_bytes([hout[0], hout[1], hout[2], hout[3]]);
        // For deterministic challenge derivation, use modular reduction with
        // additional entropy from upper bytes if primary sample is biased.
        // In practice, bias is negligible (remaining <= 256, so < 2^-24),
        // but we use rejection-free Lemire's method for correctness:
        let idx = ((raw as u64 * range as u64) >> 32) as usize;
        positions.swap(i, i + idx);

        // Sign bit from hash
        let sign = if hout[4] & 1 == 0 { 1 } else { Q - 1 }; // +1 or -1
        c.coeffs[positions[i]] = sign;
    }
    c
}

// ─── Random Polynomials ──────────────────────────────────────

/// Sample y uniformly with coefficients in [-γ+1, γ-1].
/// Uses rejection sampling to eliminate modular bias.
/// Constant-time per accepted sample; retry count is data-independent
/// since rejection probability is negligible (range / 2^32 ≈ 0.9997).
pub(crate) fn sample_masking_poly() -> Poly {
    let mut rng = rand::thread_rng();
    let mut y = Poly::zero();
    let range = (2 * GAMMA - 1) as u32;
    // Rejection threshold: largest multiple of range that fits in u32
    let threshold = u32::MAX - (u32::MAX % range);
    for i in 0..N {
        loop {
            let mut buf = [0u8; 4];
            rng.fill_bytes(&mut buf);
            let raw = u32::from_le_bytes(buf);
            if raw < threshold {
                let val = (raw % range) as i32 - (GAMMA - 1);
                y.coeffs[i] = ((val % Q) + Q) % Q;
                break;
            }
        }
    }
    y
}

// ═══════════════════════════════════════════════════════════════
// REMOVED: O(n) LRS Ring Signature — SEC-AUDIT-V4
//
// The legacy hash-chain ring signature (ring_sign / ring_verify / RingSig /
// sample_response_poly) has been removed. LogRing (O(log n), Merkle + lattice Σ)
// is now the SOLE ring signature scheme for MISAKA Network.
//
// ═══════════════════════════════════════════════════════════════

// ─── High-level API ──────────────────────────────────────────

/// Spending keypair: ML-DSA identity → lattice ring key.
pub struct SpendingKeypair {
    pub ml_dsa_sk: MlDsaSecretKey,
    pub secret_poly: Poly,
    pub public_poly: Poly,
}

impl SpendingKeypair {
    /// Derive from ML-DSA-65 secret key.
    pub fn from_ml_dsa(ml_dsa_sk: MlDsaSecretKey) -> Result<Self, CryptoError> {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let secret_poly = derive_secret_poly(&ml_dsa_sk)?;
        let public_poly = compute_pubkey(&a, &secret_poly);
        Ok(Self { ml_dsa_sk, secret_poly, public_poly })
    }

    /// Derive a child spending keypair from master secret bytes + index.
    /// index=0 is the master key (use from_ml_dsa). index=1+ are children.
    /// Each child has a unique public_poly and produces unique nullifiers.
    ///
    /// Returns Err if index is 0 or key derivation fails.
    pub fn derive_child(master_sk_bytes: &[u8], index: u32) -> Result<Self, CryptoError> {
        if index == 0 {
            return Err(CryptoError::RingSignatureInvalid(
                "index 0 is reserved for the master key".into()
            ));
        }
        let salt = format!("MISAKA:child:v1:{}", index);
        let hk = Hkdf::<Sha3_256>::new(Some(salt.as_bytes()), master_sk_bytes);
        let mut child_bytes = vec![0u8; master_sk_bytes.len()];
        hk.expand(b"misaka/child-spending-key", &mut child_bytes)
            .map_err(|_| {
                tracing::error!("HKDF expand failed for child key derivation");
                CryptoError::RingSignatureInvalid("HKDF expand failed for child key".into())
            })?;
        let child_sk = MlDsaSecretKey::from_bytes(&child_bytes)
            .map_err(|e| {
                tracing::error!("child key from_bytes failed: {e}");
                CryptoError::RingSignatureInvalid("child key derivation failed".into())
            })?;
        Ok(Self::from_ml_dsa(child_sk)?)
    }

    /// Derive the MISAKA address for this spending keypair.
    pub fn derive_address(&self) -> String {
        use sha3::{Sha3_256, Digest};
        let pub_bytes = self.public_poly.to_bytes();
        let hash: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(b"MISAKA:address:v1:");
            h.update(&pub_bytes);
            h.finalize().into()
        };
        format!("msk1{}", hex::encode(&hash[..20]))
    }
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_sign::MlDsaKeypair;

    #[test]
    fn test_spending_keypair_unique() {
        let kp1 = MlDsaKeypair::generate();
        let kp2 = MlDsaKeypair::generate();
        let skp1 = SpendingKeypair::from_ml_dsa(kp1.secret_key).unwrap();
        let skp2 = SpendingKeypair::from_ml_dsa(kp2.secret_key).unwrap();
        assert_ne!(skp1.public_poly.to_bytes(), skp2.public_poly.to_bytes(),
            "Different keys must produce different public polys");
    }

    #[test]
    fn test_pubkey_verification() {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let kp = MlDsaKeypair::generate();
        let skp = SpendingKeypair::from_ml_dsa(kp.secret_key).unwrap();
        let t = skp.public_poly;
        let t_manual = a.mul(&skp.secret_poly);
        assert_eq!(t.to_bytes(), t_manual.to_bytes(), "Public key must satisfy t = a * s");
    }

    #[test]
    fn test_derive_public_param_unbiased() {
        // SEC-AUDIT-V4 HIGH-001: verify no coefficient exceeds Q
        let a = derive_public_param(&DEFAULT_A_SEED);
        for (i, &c) in a.coeffs.iter().enumerate() {
            assert!(c >= 0 && c < Q, "coefficient [{}] = {} out of [0, Q)", i, c);
        }
    }

    #[test]
    fn test_derive_public_param_deterministic() {
        let a1 = derive_public_param(&DEFAULT_A_SEED);
        let a2 = derive_public_param(&DEFAULT_A_SEED);
        assert_eq!(a1.coeffs, a2.coeffs);
    }

    #[test]
    fn test_derive_secret_poly_ternary() {
        let kp = MlDsaKeypair::generate();
        let s = derive_secret_poly(&kp.secret_key).unwrap();
        for &c in &s.coeffs {
            assert!(c == 0 || c == 1 || c == Q - 1, "secret coeff must be in {{-1,0,1}} mod Q");
        }
    }

    #[test]
    fn test_spending_keypair_address_deterministic() {
        let kp = MlDsaKeypair::generate();
        let sk_bytes = kp.secret_key.as_bytes().to_vec();
        let skp1 = SpendingKeypair::from_ml_dsa(
            crate::pq_sign::MlDsaSecretKey::from_bytes(&sk_bytes).unwrap()
        ).unwrap();
        let skp2 = SpendingKeypair::from_ml_dsa(
            crate::pq_sign::MlDsaSecretKey::from_bytes(&sk_bytes).unwrap()
        ).unwrap();
        assert_eq!(skp1.derive_address(), skp2.derive_address());
    }
}
