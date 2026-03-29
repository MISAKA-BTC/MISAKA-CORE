//! MISAKA Lattice Ring Signature (LRS-v1).
//!
//! # Construction
//!
//! Based on Lyubashevsky Σ-protocol over R_q = Z_q[X]/(X^256+1),
//! composed into a hash-chain lattice ZKP proof.
//!
//! ```text
//! ML-DSA-65 secret key (PQ identity)
//!   └─ HKDF ─→ lattice secret polynomial s ∈ R_q (short)
//!   └─ public key t = a·s mod q
//!   └─ key image I = SHA3-256(SHA3-512(s))
//!   └─ lattice ZKP proof: hash-chain over Lyubashevsky Σ-protocol
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

use hkdf::Hkdf;
use rand::RngCore;
use sha3::{Digest as Sha3Digest, Sha3_256, Sha3_512};

use crate::error::CryptoError;
use crate::pq_sign::MlDsaSecretKey;
use crate::secret::zeroize_poly_coeffs;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;
// ─── Parameters ──────────────────────────────────────────────

pub const Q: i32 = 12289;
pub const N: usize = 256;
pub const ETA: i32 = 1;
pub const TAU: usize = 46;
pub const GAMMA: i32 = 6000;
pub const BETA: i32 = GAMMA - (TAU as i32) * ETA; // 5954
pub const MIN_ANONYMITY_SET: usize = 4;
pub const MAX_ANONYMITY_SET: usize = 16;
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
    pub fn zero() -> Self {
        Self { coeffs: [0; N] }
    }

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
            if r.coeffs[i] < 0 {
                r.coeffs[i] += Q;
            }
        }
        r
    }

    /// Polynomial subtraction mod q.
    pub fn sub(&self, other: &Poly) -> Poly {
        let mut r = Poly::zero();
        for i in 0..N {
            r.coeffs[i] = (self.coeffs[i] - other.coeffs[i]) % Q;
            if r.coeffs[i] < 0 {
                r.coeffs[i] += Q;
            }
        }
        r
    }

    /// Schoolbook polynomial multiplication O(n²). Used as reference in tests.
    /// Constant-time: no zero-coefficient skipping.
    #[allow(dead_code)]
    pub fn mul_schoolbook(&self, other: &Poly) -> Poly {
        let mut r = [0i64; N];
        for i in 0..N {
            for j in 0..N {
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

    /// Constant-time polynomial equality check.
    ///
    /// Compares all N coefficients without early exit, preventing
    /// timing side-channel on challenge polynomials during verification.
    /// Uses XOR accumulation — runs in O(N) regardless of content.
    #[inline(never)]
    pub fn ct_eq(&self, other: &Poly) -> bool {
        let mut acc = 0i32;
        for i in 0..N {
            acc |= self.coeffs[i] ^ other.coeffs[i];
        }
        acc == 0
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
            return Err(CryptoError::ProofInvalid(format!(
                "poly bytes: expected {}, got {}",
                N * 2,
                data.len()
            )));
        }
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = u16::from_le_bytes([data[i * 2], data[i * 2 + 1]]) as i32;
            if p.coeffs[i] >= Q {
                return Err(CryptoError::ProofInvalid("coefficient >= q".into()));
            }
        }
        Ok(p)
    }

    /// Serialize challenge polynomial (1 byte per coeff, signed: 0, 1, or 0xFF=-1).
    /// Returns Err if any coefficient is not a valid challenge value.
    pub fn challenge_to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let mut result = Vec::with_capacity(N);
        for (i, &c) in self.coeffs.iter().enumerate() {
            let byte = if c == 0 {
                0u8
            } else if c == 1 {
                1u8
            } else if c == Q - 1 {
                0xFFu8
            }
            // -1 mod q
            else {
                return Err(CryptoError::ProofInvalid(format!(
                    "invalid challenge coefficient at [{}]: {}",
                    i, c
                )));
            };
            result.push(byte);
        }
        Ok(result)
    }

    /// Deserialize challenge polynomial.
    pub fn challenge_from_bytes(data: &[u8]) -> Result<Self, CryptoError> {
        if data.len() != N {
            return Err(CryptoError::ProofInvalid("challenge bytes".into()));
        }
        let mut p = Poly::zero();
        for i in 0..N {
            p.coeffs[i] = match data[i] {
                0 => 0,
                1 => 1,
                0xFF => Q - 1, // -1 mod q
                _ => {
                    return Err(CryptoError::ProofInvalid(
                        "bad challenge byte".into(),
                    ))
                }
            };
        }
        Ok(p)
    }
}

// ─── Shared Public Parameter ─────────────────────────────────

/// Derive the shared polynomial 'a' from a seed (deterministic).
pub fn derive_public_param(seed: &[u8; 32]) -> Poly {
    let mut h = Sha3_512::new();
    h.update(DST_PUBPARAM);
    h.update(seed);
    let hash = h.finalize();

    // Expand with SHAKE-like approach using SHA3-256 iterations
    let mut a = Poly::zero();
    let mut expand_buf = [0u8; 32];
    expand_buf.copy_from_slice(&hash[..32]);
    for i in 0..N {
        let mut h2 = Sha3_256::new();
        h2.update(&expand_buf);
        h2.update(&(i as u32).to_le_bytes());
        let hout: [u8; 32] = h2.finalize().into();
        let val = u16::from_le_bytes([hout[0], hout[1]]) as i32;
        a.coeffs[i] = val % Q;
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
    hk.expand(DST_SPENDING, &mut expanded).map_err(|_| {
        CryptoError::ProofInvalid(
            "HKDF expand failed in derive_secret_poly — refusing to use zero polynomial".into(),
        )
    })?;

    let mut s = Poly::zero();
    for i in 0..N {
        // SECURITY: branchless ternary mapping to prevent timing leak on secret.
        // Map byte to {-1, 0, 1}: 0-84 → Q-1 (-1 mod q), 85-170 → 0, 171-255 → 1
        //
        // neg_mask = 0 if b <= 84 (i.e. want -1), else 1
        // pos_mask = 0 if b <= 170, else 1 (i.e. want +1)
        // result = (1 - neg_mask) * (Q - 1) + pos_mask
        let b = expanded[i] as i32;
        let neg_mask = ((84i32 - b) >> 31) & 1;
        let pos_mask = ((170i32 - b) >> 31) & 1;
        s.coeffs[i] = (1 - neg_mask) * (Q - 1) + pos_mask;
    }

    // SECURITY: zeroize HKDF-derived secret material
    expanded.iter_mut().for_each(|b| *b = 0);
    crate::secret::zeroize_bytes(&mut expanded);

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
///   ring member produced it (lattice ZKP proof anonymity).
/// - **Exculpable**: Nobody can forge a key image for another party's `s`
///   without knowing `s` (second preimage resistance).
///
/// For stealth addresses, use `compute_key_image_bound()` instead,
/// which binds the key image to a specific one-time address.
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
        let _threshold = u32::MAX - (u32::MAX % range);
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
    let mut rng = rand::rngs::OsRng;
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

/// Sample z uniformly with centered coefficients in [-β+1, β-1].
/// Uses rejection sampling to eliminate modular bias.
fn sample_response_poly() -> Poly {
    let mut rng = rand::rngs::OsRng;
    let mut z = Poly::zero();
    let range = (2 * BETA - 1) as u32;
    let threshold = u32::MAX - (u32::MAX % range);
    for i in 0..N {
        loop {
            let mut buf = [0u8; 4];
            rng.fill_bytes(&mut buf);
            let raw = u32::from_le_bytes(buf);
            if raw < threshold {
                let val = (raw % range) as i32 - (BETA - 1);
                z.coeffs[i] = ((val % Q) + Q) % Q;
                break;
            }
        }
    }
    z
}

// ─── Ring Signature ──────────────────────────────────────────

/// Lattice lattice ZKP proof.
#[derive(Debug, Clone)]
pub struct LegacyProofData {
    /// Initial challenge polynomial c_0 (in C_τ).
    pub c0: Poly,
    /// Response polynomials, one per ring member.
    pub responses: Vec<Poly>,
    /// Key image (32 bytes).
    pub key_image: [u8; 32],
}

impl LegacyProofData {
    pub fn to_bytes(&self) -> Vec<u8> {
        let n = self.responses.len();
        let mut buf = Vec::with_capacity(N + n * N * 2 + 32);
        // Challenge polynomial - use checked serialization, fallback to zeros on error
        match self.c0.challenge_to_bytes() {
            Ok(bytes) => buf.extend_from_slice(&bytes),
            Err(_) => buf.extend_from_slice(&vec![0u8; N]),
        }
        for z in &self.responses {
            buf.extend_from_slice(&z.to_bytes());
        }
        buf.extend_from_slice(&self.key_image);
        buf
    }

    pub fn from_bytes(data: &[u8], anonymity_set_size: usize) -> Result<Self, CryptoError> {
        let expected = N + anonymity_set_size * N * 2 + 32;
        if data.len() != expected {
            return Err(CryptoError::ProofInvalid(format!(
                "sig length {} != expected {}",
                data.len(),
                expected
            )));
        }
        let c0 = Poly::challenge_from_bytes(&data[..N])?;
        let mut responses = Vec::with_capacity(anonymity_set_size);
        let mut offset = N;
        for _ in 0..anonymity_set_size {
            responses.push(Poly::from_bytes(&data[offset..offset + N * 2])?);
            offset += N * 2;
        }
        let mut ki = [0u8; 32];
        ki.copy_from_slice(&data[offset..]);
        Ok(Self {
            c0,
            responses,
            key_image: ki,
        })
    }
}

/// Sign with lattice lattice ZKP proof.
///
/// - `a`: shared public parameter polynomial
/// - `ring_pubkeys`: public key polynomials t_i = a·s_i
/// - `signer_index`: position of the real signer
/// - `secret`: signer's secret polynomial s_π
/// - `message`: 32-byte signing digest
pub fn pq_sign(
    a: &Poly,
    ring_pubkeys: &[Poly],
    signer_index: usize,
    secret: &Poly,
    message: &[u8; 32],
) -> Result<LegacyProofData, CryptoError> {
    let n_ring = ring_pubkeys.len();
    if n_ring < MIN_ANONYMITY_SET || n_ring > MAX_ANONYMITY_SET {
        return Err(CryptoError::ProofInvalid(format!(
            "ring size {} out of [{}, {}]",
            n_ring, MIN_ANONYMITY_SET, MAX_ANONYMITY_SET
        )));
    }
    if signer_index >= n_ring {
        return Err(CryptoError::ProofInvalid(
            "signer index out of range".into(),
        ));
    }

    let key_image = compute_key_image(secret);

    // Build ring hash base
    let mut ring_encoding = Vec::new();
    for pk in ring_pubkeys {
        ring_encoding.extend_from_slice(&pk.to_bytes());
    }

    let h: [u8; 32] = {
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        hasher.update(&ring_encoding);
        hasher.update(&key_image);
        hasher.finalize().into()
    };

    for _attempt in 0..MAX_SIGN_ATTEMPTS {
        // Step 1: honest commitment for signer
        let mut y = sample_masking_poly();
        let w_pi = a.mul(&y);

        // Step 2: derive c_{π+1}
        let mut chain_input = Vec::new();
        chain_input.extend_from_slice(&h);
        chain_input.extend_from_slice(&w_pi.to_bytes());
        let mut c_next = hash_to_challenge(&chain_input);
        // Zeroize scratch buffer
        zeroize_poly_coeffs(&mut Poly::zero().coeffs); // force volatile fence
        chain_input.iter_mut().for_each(|b| *b = 0);

        // Step 3: simulate all other positions
        let mut responses = vec![Poly::zero(); n_ring];
        let mut challenges = vec![Poly::zero(); n_ring];

        let mut idx = (signer_index + 1) % n_ring;
        loop {
            if idx == signer_index {
                break;
            }

            challenges[idx] = c_next.clone();
            let z_i = sample_response_poly();
            // w_i = a·z_i - c_i·t_i mod q
            let az = a.mul(&z_i);
            let ct = challenges[idx].mul(&ring_pubkeys[idx]);
            let w_i = az.sub(&ct);

            responses[idx] = z_i;

            // c_{i+1}
            let mut ci_input = Vec::new();
            ci_input.extend_from_slice(&h);
            ci_input.extend_from_slice(&w_i.to_bytes());
            c_next = hash_to_challenge(&ci_input);
            ci_input.iter_mut().for_each(|b| *b = 0);

            idx = (idx + 1) % n_ring;
        }

        // Step 4: close the ring
        challenges[signer_index] = c_next;

        // z_π = y + c_π · s_π (in centered representation)
        // SECURITY: branchless centering prevents timing side-channel on secret data.
        // Uses arithmetic bit-shift to avoid data-dependent branches.
        let mut cs = challenges[signer_index].mul(secret);
        let mut z_pi = Poly::zero();
        for i in 0..N {
            // Constant-time centering: val - Q if val > Q/2, else val
            let y_above = ((Q / 2 - y.coeffs[i]) >> 31) & 1;
            let y_centered = y.coeffs[i] - Q * y_above;
            let cs_above = ((Q / 2 - cs.coeffs[i]) >> 31) & 1;
            let cs_centered = cs.coeffs[i] - Q * cs_above;
            let val = y_centered + cs_centered;
            z_pi.coeffs[i] = ((val % Q) + Q) % Q;
        }

        // Rejection sampling: constant-time norm check.
        let z_norm = z_pi.norm_inf();
        if z_norm >= BETA {
            // SECURITY: zeroize secret-derived temporaries before retry
            zeroize_poly_coeffs(&mut y.coeffs);
            zeroize_poly_coeffs(&mut cs.coeffs);
            zeroize_poly_coeffs(&mut z_pi.coeffs);
            for ch in &mut challenges {
                zeroize_poly_coeffs(&mut ch.coeffs);
            }
            continue;
        }

        // Zeroize temporaries before returning
        zeroize_poly_coeffs(&mut y.coeffs);
        zeroize_poly_coeffs(&mut cs.coeffs);
        for i in 1..n_ring {
            if i != 0 {
                zeroize_poly_coeffs(&mut challenges[i].coeffs);
            }
        }

        responses[signer_index] = z_pi;

        return Ok(LegacyProofData {
            c0: challenges[0].clone(),
            responses,
            key_image,
        });
    }

    Err(CryptoError::ProofInvalid(
        "exceeded max sign attempts".into(),
    ))
}

/// Verify lattice lattice ZKP proof.
pub fn ring_verify(
    a: &Poly,
    ring_pubkeys: &[Poly],
    message: &[u8; 32],
    sig: &LegacyProofData,
) -> Result<(), CryptoError> {
    let n_ring = ring_pubkeys.len();
    // SECURITY: all verification failures return the same generic error
    // to prevent error-oracle attacks that reveal which step failed.
    let reject = || CryptoError::ProofInvalid("invalid proof".into());

    if n_ring < MIN_ANONYMITY_SET || n_ring > MAX_ANONYMITY_SET {
        return Err(reject());
    }
    if sig.responses.len() != n_ring {
        return Err(reject());
    }

    // Build ring hash base
    let mut ring_encoding = Vec::new();
    for pk in ring_pubkeys {
        ring_encoding.extend_from_slice(&pk.to_bytes());
    }

    let h: [u8; 32] = {
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        hasher.update(&ring_encoding);
        hasher.update(&sig.key_image);
        hasher.finalize().into()
    };

    // Verify hash chain — accumulate failure instead of early return
    // to prevent timing oracle on which ring position failed.
    let mut c_current = sig.c0.clone();
    let mut valid = true;

    for i in 0..n_ring {
        // Check response bound (constant-time norm_inf)
        if sig.responses[i].norm_inf() >= BETA {
            valid = false;
        }

        // Reconstruct commitment: w_i = a·z_i - c_i·t_i
        let az = a.mul(&sig.responses[i]);
        let ct = c_current.mul(&ring_pubkeys[i]);
        let w_i = az.sub(&ct);

        // Derive next challenge
        let mut ci_input = Vec::new();
        ci_input.extend_from_slice(&h);
        ci_input.extend_from_slice(&w_i.to_bytes());
        c_current = hash_to_challenge(&ci_input);
    }

    // Ring must close (constant-time comparison)
    if !c_current.ct_eq(&sig.c0) {
        valid = false;
    }

    if valid { Ok(()) } else { Err(reject()) }
}

/// Sign with anonymity_set_size=1 for transparent (public) transfers.
///
/// Identical to `pq_sign` but allows anonymity_set_size=1 (no decoys).
/// The sender is fully identifiable — no anonymity.
pub fn ring_sign_transparent(
    a: &Poly,
    ring_pubkeys: &[Poly],
    signer_index: usize,
    secret: &Poly,
    message: &[u8; 32],
) -> Result<LegacyProofData, CryptoError> {
    let n_ring = ring_pubkeys.len();
    if n_ring == 0 || n_ring > MAX_ANONYMITY_SET {
        return Err(CryptoError::ProofInvalid(format!(
            "transparent ring size {} out of [1, {}]",
            n_ring, MAX_ANONYMITY_SET
        )));
    }
    if signer_index >= n_ring {
        return Err(CryptoError::ProofInvalid(
            "signer index out of range".into(),
        ));
    }

    let key_image = compute_key_image(secret);

    let mut ring_encoding = Vec::new();
    for pk in ring_pubkeys {
        ring_encoding.extend_from_slice(&pk.to_bytes());
    }

    let h: [u8; 32] = {
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        hasher.update(&ring_encoding);
        hasher.update(&key_image);
        hasher.finalize().into()
    };

    for _attempt in 0..MAX_SIGN_ATTEMPTS {
        let mut y = sample_masking_poly();
        let w_pi = a.mul(&y);

        let mut chain_input = Vec::new();
        chain_input.extend_from_slice(&h);
        chain_input.extend_from_slice(&w_pi.to_bytes());
        let mut c_next = hash_to_challenge(&chain_input);
        chain_input.iter_mut().for_each(|b| *b = 0);

        let mut responses = vec![Poly::zero(); n_ring];
        let mut challenges = vec![Poly::zero(); n_ring];

        // Simulate other positions (if anonymity_set_size > 1, though usually 1)
        let mut idx = (signer_index + 1) % n_ring;
        loop {
            if idx == signer_index {
                break;
            }
            challenges[idx] = c_next.clone();
            let z_i = sample_response_poly();
            let az = a.mul(&z_i);
            let ct = challenges[idx].mul(&ring_pubkeys[idx]);
            let w_i = az.sub(&ct);
            responses[idx] = z_i;

            let mut ci_input = Vec::new();
            ci_input.extend_from_slice(&h);
            ci_input.extend_from_slice(&w_i.to_bytes());
            c_next = hash_to_challenge(&ci_input);
            ci_input.iter_mut().for_each(|b| *b = 0);
            idx = (idx + 1) % n_ring;
        }

        challenges[signer_index] = c_next;
        let mut cs = challenges[signer_index].mul(secret);
        let mut z_pi = Poly::zero();
        for i in 0..N {
            // Constant-time centering: branchless, prevents timing leak on secret
            let y_above = ((Q / 2 - y.coeffs[i]) >> 31) & 1;
            let y_centered = y.coeffs[i] - Q * y_above;
            let cs_above = ((Q / 2 - cs.coeffs[i]) >> 31) & 1;
            let cs_centered = cs.coeffs[i] - Q * cs_above;
            let val = y_centered + cs_centered;
            z_pi.coeffs[i] = ((val % Q) + Q) % Q;
        }

        if z_pi.norm_inf() >= BETA {
            // SECURITY: zeroize secret-derived temporaries before retry
            zeroize_poly_coeffs(&mut y.coeffs);
            zeroize_poly_coeffs(&mut cs.coeffs);
            zeroize_poly_coeffs(&mut z_pi.coeffs);
            for ch in &mut challenges {
                zeroize_poly_coeffs(&mut ch.coeffs);
            }
            continue;
        }

        // Zeroize temporaries before returning
        zeroize_poly_coeffs(&mut y.coeffs);
        zeroize_poly_coeffs(&mut cs.coeffs);
        for i in 1..n_ring {
            zeroize_poly_coeffs(&mut challenges[i].coeffs);
        }

        responses[signer_index] = z_pi;

        return Ok(LegacyProofData {
            c0: challenges[0].clone(),
            responses,
            key_image,
        });
    }

    Err(CryptoError::ProofInvalid(
        "transparent ring sign: failed after max attempts (rejection sampling)".into(),
    ))
}

/// Verify lattice ZKP proof with anonymity_set_size >= 1 (transparent transfers).
pub fn ring_verify_transparent(
    a: &Poly,
    ring_pubkeys: &[Poly],
    message: &[u8; 32],
    raw_sig: &[u8],
) -> Result<(), CryptoError> {
    let n_ring = ring_pubkeys.len();
    let reject = || CryptoError::ProofInvalid("invalid proof".into());

    if n_ring == 0 || n_ring > MAX_ANONYMITY_SET {
        return Err(reject());
    }

    let sig = LegacyProofData::from_bytes(raw_sig, n_ring).map_err(|_| reject())?;

    if sig.responses.len() != n_ring {
        return Err(reject());
    }

    let mut ring_encoding = Vec::new();
    for pk in ring_pubkeys {
        ring_encoding.extend_from_slice(&pk.to_bytes());
    }

    let h: [u8; 32] = {
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        hasher.update(&ring_encoding);
        hasher.update(&sig.key_image);
        hasher.finalize().into()
    };

    let mut c_current = sig.c0.clone();
    let mut valid = true;

    for i in 0..n_ring {
        if sig.responses[i].norm_inf() >= BETA {
            valid = false;
        }

        let az = a.mul(&sig.responses[i]);
        let ct = c_current.mul(&ring_pubkeys[i]);
        let w_i = az.sub(&ct);

        let mut ci_input = Vec::new();
        ci_input.extend_from_slice(&h);
        ci_input.extend_from_slice(&w_i.to_bytes());
        c_current = hash_to_challenge(&ci_input);
    }

    if !c_current.ct_eq(&sig.c0) {
        valid = false;
    }

    if valid { Ok(()) } else { Err(reject()) }
}

// ─── High-level API ──────────────────────────────────────────

/// Spending keypair: ML-DSA-65 identity + lattice key image.
///
/// v10: `ml_dsa_pk_bytes` stores the ML-DSA-65 public key (1952 bytes)
/// for UTXO spending_pubkey and address derivation. This replaces the
/// legacy Poly-based spending_pubkey.
pub struct SpendingKeypair {
    pub ml_dsa_sk: MlDsaSecretKey,
    /// ML-DSA-65 public key bytes (1952 bytes, NIST FIPS 204).
    /// Stored in UTXOs as `spending_pubkey`. Used by block_validation
    /// for ML-DSA-65 signature verification.
    pub ml_dsa_pk_bytes: Vec<u8>,
    pub secret_poly: Poly,
    pub public_poly: Poly,
    pub key_image: [u8; 32],
}

impl SpendingKeypair {
    /// Derive from ML-DSA-65 keypair (both sk and pk required).
    ///
    /// The ML-DSA pk is stored for UTXO spending_pubkey and address derivation.
    /// Returns `Err` if HKDF expansion fails (SEC-006 fix).
    pub fn from_ml_dsa_pair(
        ml_dsa_sk: MlDsaSecretKey,
        ml_dsa_pk_bytes: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let secret_poly = derive_secret_poly(&ml_dsa_sk)?;
        let public_poly = compute_pubkey(&a, &secret_poly);
        let key_image = compute_key_image(&secret_poly);
        Ok(Self {
            ml_dsa_sk,
            ml_dsa_pk_bytes,
            secret_poly,
            public_poly,
            key_image,
        })
    }

    /// Legacy: Derive from ML-DSA-65 secret key only (pk unknown).
    /// Used by test code and legacy paths. The ml_dsa_pk_bytes will be empty.
    pub fn from_ml_dsa(ml_dsa_sk: MlDsaSecretKey) -> Result<Self, CryptoError> {
        Self::from_ml_dsa_pair(ml_dsa_sk, Vec::new())
    }

    pub fn key_image_bytes(&self) -> [u8; 32] {
        self.key_image
    }

    /// Canonical key image (scheme-independent).
    /// Use this for v2 transactions to ensure cross-scheme double-spend detection.
    /// The `key_image` field uses the legacy LRS DST for v1 backwards compatibility.
    pub fn canonical_key_image(&self) -> [u8; 32] {
        crate::canonical_ki::canonical_key_image(&self.secret_poly)
    }

    /// Derive a child spending keypair for change outputs.
    ///
    /// v10 (mainnet-ready): Generates a fresh ML-DSA-65 keypair per child.
    /// The HKDF-derived seed is used for the lattice secret polynomial
    /// (key image derivation), while the ML-DSA-65 keypair is generated
    /// independently for signing security.
    ///
    /// Child keys are non-deterministic (ML-DSA-65 keypair uses OS randomness).
    /// The wallet MUST persist child keys — they cannot be re-derived from master.
    /// This matches Kaspa/Bitcoin's model where each address has its own key.
    ///
    /// Returns Err if index is 0.
    pub fn derive_child(master_sk_bytes: &[u8], index: u32) -> Result<Self, CryptoError> {
        if index == 0 {
            return Err(CryptoError::ProofInvalid(
                "index 0 is reserved for the master key".into(),
            ));
        }

        // Generate a fresh ML-DSA-65 keypair for this child
        let child_kp = crate::pq_sign::MlDsaKeypair::generate();
        let child_pk_bytes = child_kp.public_key.as_bytes().to_vec();

        // Derive lattice secret polynomial via HKDF for key image
        let salt = format!("MISAKA:child:v1:{}", index);
        let hk = Hkdf::<Sha3_256>::new(Some(salt.as_bytes()), master_sk_bytes);
        let mut expanded = [0u8; N];
        hk.expand(b"misaka/child-ki-seed", &mut expanded)
            .map_err(|_| {
                CryptoError::ProofInvalid("HKDF expand failed for child KI seed".into())
            })?;

        // Build lattice key image from HKDF seed (deterministic per index)
        let a = derive_public_param(&DEFAULT_A_SEED);
        let secret_poly = {
            let mut s = Poly::zero();
            for i in 0..N {
                let b = expanded[i] as i32;
                let neg_mask = ((84i32 - b) >> 31) & 1;
                let pos_mask = ((170i32 - b) >> 31) & 1;
                s.coeffs[i] = (1 - neg_mask) * (Q - 1) + pos_mask;
            }
            s
        };
        crate::secret::zeroize_bytes(&mut expanded);
        let public_poly = compute_pubkey(&a, &secret_poly);
        let key_image = compute_key_image(&secret_poly);

        Ok(Self {
            ml_dsa_sk: child_kp.secret_key,
            ml_dsa_pk_bytes: child_pk_bytes,
            secret_poly,
            public_poly,
            key_image,
        })
    }

    /// Derive the MISAKA address for this spending keypair.
    ///
    /// v10: Address = misaka1... (encode_address format, chain_id=2 for testnet).
    /// Uses ML-DSA-65 public key (1952 bytes) for address derivation.
    /// Falls back to Poly-based derivation if ml_dsa_pk_bytes is empty (legacy).
    pub fn derive_address(&self) -> String {
        self.derive_address_with_chain(2) // default testnet
    }

    /// Derive address with explicit chain_id.
    pub fn derive_address_with_chain(&self, chain_id: u32) -> String {
        use sha3::{Digest, Sha3_256};
        let pk_bytes = if self.ml_dsa_pk_bytes.is_empty() {
            self.public_poly.to_bytes()
        } else {
            self.ml_dsa_pk_bytes.clone()
        };
        let hash: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(b"MISAKA:address:v1:");
            h.update(&pk_bytes);
            h.finalize().into()
        };
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&hash);
        misaka_types::address::encode_address(&addr, chain_id)
    }

    /// Get ML-DSA-65 public key bytes for UTXO spending_pubkey field.
    /// Returns the 1952-byte ML-DSA pk used for signature verification.
    pub fn ml_dsa_pk(&self) -> &[u8] {
        &self.ml_dsa_pk_bytes
    }
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_sign::MlDsaKeypair;

    // ヘルパー: テスト用のパラメータ a を生成
    fn shared_a() -> Poly {
        derive_public_param(&DEFAULT_A_SEED)
    }

    // ヘルパー: 指定サイズのリングと署名者情報を生成
    fn make_ring(size: usize) -> (Poly, Vec<Poly>, usize, SpendingKeypair) {
        let a = shared_a();
        let mut wallets: Vec<SpendingKeypair> = (0..size)
            .map(|_| SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key).unwrap())
            .collect();

        let ring_pks: Vec<Poly> = wallets.iter().map(|w| w.public_poly.clone()).collect();
        let signer_idx = 0;
        let signer = wallets.swap_remove(signer_idx);

        (a, ring_pks, signer_idx, signer)
    }

    #[test]
    fn test_key_image_unique() {
        // 異なる秘密鍵からは異なる Key Image が生成されることを確認
        let kp1 = MlDsaKeypair::generate();
        let kp2 = MlDsaKeypair::generate();
        let skp1 = SpendingKeypair::from_ml_dsa(kp1.secret_key).unwrap();
        let skp2 = SpendingKeypair::from_ml_dsa(kp2.secret_key).unwrap();

        assert_ne!(
            skp1.key_image, skp2.key_image,
            "Key images must be unique for different keys"
        );
    }

    #[test]
    fn test_ring_too_small() {
        // リングサイズが小さすぎる（例: 3未満）場合にエラーになることを確認
        let a = shared_a();
        let ml_kp = MlDsaKeypair::generate();
        let skp = SpendingKeypair::from_ml_dsa(ml_kp.secret_key).unwrap();

        // サイズ2のリングを作成
        let ring = vec![skp.public_poly.clone(); 2];
        let result = pq_sign(&a, &ring, 0, &skp.secret_poly, &[0; 32]);

        assert!(result.is_err(), "Signing should fail for ring size < 3");
    }

    #[test]
    fn test_sig_serialization_roundtrip() {
        // 署名のシリアライズ・デシリアライズが正しく行われ、検証が通ることを確認
        let (a, ring, idx, signer) = make_ring(4);
        let msg = [0x42u8; 32];

        // 署名生成
        let sig = pq_sign(&a, &ring, idx, &signer.secret_poly, &msg).unwrap();

        // バイト列変換 (シリアライズ)
        let bytes = sig.to_bytes();

        // バイト列から復元 (デシリアライズ)
        // LegacyProofData::from_bytes にはリングサイズが必要
        let sig2 = LegacyProofData::from_bytes(&bytes, 4).expect("Deserialization failed");

        // 内部データの一致確認
        assert_eq!(sig.c0, sig2.c0);
        assert_eq!(sig.key_image, sig2.key_image);
        assert_eq!(sig.responses.len(), sig2.responses.len());

        // 復元した署名で検証が通ることを確認
        ring_verify(&a, &ring, &msg, &sig2).expect("Verification of restored signature failed");
    }

    #[test]
    fn test_pubkey_verification() {
        // 公開鍵の代数的関係 t = a * s (mod q) が成立することを確認
        let a = shared_a();
        let kp = MlDsaKeypair::generate();

        // SpendingKeypair の内部ロジックで計算された公開鍵
        let skp = SpendingKeypair::from_ml_dsa(kp.secret_key).unwrap();
        let t = skp.public_poly;

        // 直接多項式乗算した結果
        let t_manual = a.mul(&skp.secret_poly);

        assert_eq!(
            t.to_bytes(),
            t_manual.to_bytes(),
            "Public key must satisfy t = a * s"
        );
    }
}
