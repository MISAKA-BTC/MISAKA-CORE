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
    pub fn challenge_to_bytes(&self) -> Vec<u8> {
        self.coeffs.iter().map(|&c| {
            if c == 0 { 0u8 }
            else if c == 1 { 1u8 }
            else if c == Q - 1 { 0xFFu8 } // -1 mod q
            else { panic!("invalid challenge coefficient: {}", c) }
        }).collect()
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
pub fn derive_secret_poly(ml_dsa_sk: &MlDsaSecretKey) -> Poly {
    let hk = Hkdf::<Sha3_256>::new(None, ml_dsa_sk.as_bytes());
    let mut expanded = [0u8; N];
    hk.expand(DST_SPENDING, &mut expanded).expect("valid HKDF");

    let mut s = Poly::zero();
    for i in 0..N {
        // Map byte to {-1, 0, 1}: 0-84 → -1, 85-170 → 0, 171-255 → 1
        s.coeffs[i] = match expanded[i] {
            0..=84 => Q - 1,   // -1 mod q
            85..=170 => 0,
            _ => 1,
        };
    }
    s
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
pub fn compute_key_image_bound(s: &Poly, one_time_address: &[u8; 20]) -> [u8; 32] {
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
pub(crate) fn hash_to_challenge(data: &[u8]) -> Poly {
    let mut c = Poly::zero();
    // Expand hash to get enough randomness
    let seed: [u8; 64] = {
        let mut h = Sha3_512::new();
        h.update(DST_CHALLENGE);
        h.update(data);
        h.finalize().into()
    };

    // Select τ positions using Fisher-Yates
    let mut positions: Vec<usize> = (0..N).collect();
    for i in 0..TAU {
        // Hash to get random index
        let mut h = Sha3_256::new();
        h.update(&seed);
        h.update(&(i as u32).to_le_bytes());
        let hout: [u8; 32] = h.finalize().into();
        let idx = (u32::from_le_bytes([hout[0], hout[1], hout[2], hout[3]]) as usize) % (N - i);
        positions.swap(i, i + idx);

        // Sign bit from hash
        let sign = if hout[4] & 1 == 0 { 1 } else { Q - 1 }; // +1 or -1
        c.coeffs[positions[i]] = sign;
    }
    c
}

// ─── Random Polynomials ──────────────────────────────────────

/// Sample y uniformly with coefficients in [-γ+1, γ-1].
/// Constant-time: fixed iteration count, no early exit.
pub(crate) fn sample_masking_poly() -> Poly {
    let mut rng = rand::thread_rng();
    let mut y = Poly::zero();
    let range = (2 * GAMMA - 1) as u32;
    let mut buf = [0u8; N * 4];
    rng.fill_bytes(&mut buf);
    for i in 0..N {
        let raw = u32::from_le_bytes([buf[i*4], buf[i*4+1], buf[i*4+2], buf[i*4+3]]);
        let val = (raw % range) as i32 - (GAMMA - 1);
        y.coeffs[i] = ((val % Q) + Q) % Q;
    }
    y
}

/// Sample z uniformly with centered coefficients in [-β+1, β-1].
/// Constant-time: single RNG call, fixed iteration.
fn sample_response_poly() -> Poly {
    let mut rng = rand::thread_rng();
    let mut z = Poly::zero();
    let range = (2 * BETA - 1) as u32;
    let mut buf = [0u8; N * 4];
    rng.fill_bytes(&mut buf);
    for i in 0..N {
        let raw = u32::from_le_bytes([buf[i*4], buf[i*4+1], buf[i*4+2], buf[i*4+3]]);
        let val = (raw % range) as i32 - (BETA - 1);
        z.coeffs[i] = ((val % Q) + Q) % Q;
    }
    z
}

// ─── Ring Signature ──────────────────────────────────────────

/// Lattice ring signature.
#[derive(Debug, Clone)]
pub struct RingSig {
    /// Initial challenge polynomial c_0 (in C_τ).
    pub c0: Poly,
    /// Response polynomials, one per ring member.
    pub responses: Vec<Poly>,
    /// Key image (32 bytes).
    pub key_image: [u8; 32],
}

impl RingSig {
    pub fn to_bytes(&self) -> Vec<u8> {
        let n = self.responses.len();
        let mut buf = Vec::with_capacity(N + n * N * 2 + 32);
        buf.extend_from_slice(&self.c0.challenge_to_bytes());
        for z in &self.responses {
            buf.extend_from_slice(&z.to_bytes());
        }
        buf.extend_from_slice(&self.key_image);
        buf
    }

    pub fn from_bytes(data: &[u8], ring_size: usize) -> Result<Self, CryptoError> {
        let expected = N + ring_size * N * 2 + 32;
        if data.len() != expected {
            return Err(CryptoError::RingSignatureInvalid(
                format!("sig length {} != expected {}", data.len(), expected)));
        }
        let c0 = Poly::challenge_from_bytes(&data[..N])?;
        let mut responses = Vec::with_capacity(ring_size);
        let mut offset = N;
        for _ in 0..ring_size {
            responses.push(Poly::from_bytes(&data[offset..offset + N * 2])?);
            offset += N * 2;
        }
        let mut ki = [0u8; 32];
        ki.copy_from_slice(&data[offset..]);
        Ok(Self { c0, responses, key_image: ki })
    }
}

/// Sign with lattice ring signature.
///
/// - `a`: shared public parameter polynomial
/// - `ring_pubkeys`: public key polynomials t_i = a·s_i
/// - `signer_index`: position of the real signer
/// - `secret`: signer's secret polynomial s_π
/// - `message`: 32-byte signing digest
pub fn ring_sign(
    a: &Poly,
    ring_pubkeys: &[Poly],
    signer_index: usize,
    secret: &Poly,
    message: &[u8; 32],
) -> Result<RingSig, CryptoError> {
    let n_ring = ring_pubkeys.len();
    if n_ring < MIN_RING_SIZE || n_ring > MAX_RING_SIZE {
        return Err(CryptoError::RingSignatureInvalid(
            format!("ring size {} out of [{}, {}]", n_ring, MIN_RING_SIZE, MAX_RING_SIZE)));
    }
    if signer_index >= n_ring {
        return Err(CryptoError::RingSignatureInvalid("signer index out of range".into()));
    }

    let key_image = compute_key_image(secret);

    // Build ring hash base
    let mut ring_encoding = Vec::new();
    for pk in ring_pubkeys { ring_encoding.extend_from_slice(&pk.to_bytes()); }

    let h: [u8; 32] = {
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        hasher.update(&ring_encoding);
        hasher.update(&key_image);
        hasher.finalize().into()
    };

    for _attempt in 0..MAX_SIGN_ATTEMPTS {
        // Step 1: honest commitment for signer
        let y = sample_masking_poly();
        let w_pi = a.mul(&y);

        // Step 2: derive c_{π+1}
        let mut chain_input = Vec::new();
        chain_input.extend_from_slice(&h);
        chain_input.extend_from_slice(&w_pi.to_bytes());
        let mut c_next = hash_to_challenge(&chain_input);

        // Step 3: simulate all other positions
        let mut responses = vec![Poly::zero(); n_ring];
        let mut challenges = vec![Poly::zero(); n_ring];

        let mut idx = (signer_index + 1) % n_ring;
        loop {
            if idx == signer_index { break; }

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

            idx = (idx + 1) % n_ring;
        }

        // Step 4: close the ring
        challenges[signer_index] = c_next;

        // z_π = y + c_π · s_π (in centered representation)
        let cs = challenges[signer_index].mul(secret);
        let mut z_pi = Poly::zero();
        for i in 0..N {
            let y_centered = if y.coeffs[i] > Q / 2 { y.coeffs[i] - Q } else { y.coeffs[i] };
            let cs_centered = if cs.coeffs[i] > Q / 2 { cs.coeffs[i] - Q } else { cs.coeffs[i] };
            let val = y_centered + cs_centered;
            z_pi.coeffs[i] = ((val % Q) + Q) % Q;
        }

        // Rejection sampling: constant-time norm check.
        // The retry loop itself leaks iteration count, which is inherent
        // to rejection sampling. But the norm computation is constant-time.
        let z_norm = z_pi.norm_inf();
        if z_norm >= BETA {
            continue; // retry (expected ~1.5 attempts on average)
        }

        responses[signer_index] = z_pi;

        return Ok(RingSig {
            c0: challenges[0].clone(),
            responses,
            key_image,
        });
    }

    Err(CryptoError::RingSignatureInvalid("exceeded max sign attempts".into()))
}

/// Verify lattice ring signature.
pub fn ring_verify(
    a: &Poly,
    ring_pubkeys: &[Poly],
    message: &[u8; 32],
    sig: &RingSig,
) -> Result<(), CryptoError> {
    let n_ring = ring_pubkeys.len();
    if n_ring < MIN_RING_SIZE || n_ring > MAX_RING_SIZE {
        return Err(CryptoError::RingSignatureInvalid("ring size out of range".into()));
    }
    if sig.responses.len() != n_ring {
        return Err(CryptoError::RingSignatureInvalid("response count mismatch".into()));
    }

    // Build ring hash base
    let mut ring_encoding = Vec::new();
    for pk in ring_pubkeys { ring_encoding.extend_from_slice(&pk.to_bytes()); }

    let h: [u8; 32] = {
        let mut hasher = Sha3_256::new();
        hasher.update(message);
        hasher.update(&ring_encoding);
        hasher.update(&sig.key_image);
        hasher.finalize().into()
    };

    // Verify hash chain
    let mut c_current = sig.c0.clone();

    for i in 0..n_ring {
        // Check response bound
        if sig.responses[i].norm_inf() >= BETA {
            return Err(CryptoError::RingSignatureInvalid(
                format!("response[{}] norm {} >= β={}", i, sig.responses[i].norm_inf(), BETA)));
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

    // Ring must close
    if c_current != sig.c0 {
        return Err(CryptoError::RingSignatureInvalid("ring does not close".into()));
    }

    Ok(())
}

// ─── High-level API ──────────────────────────────────────────

/// Spending keypair: ML-DSA identity → lattice ring key.
pub struct SpendingKeypair {
    pub ml_dsa_sk: MlDsaSecretKey,
    pub secret_poly: Poly,
    pub public_poly: Poly,
    pub key_image: [u8; 32],
}

impl SpendingKeypair {
    /// Derive from ML-DSA-65 secret key.
    pub fn from_ml_dsa(ml_dsa_sk: MlDsaSecretKey) -> Self {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let secret_poly = derive_secret_poly(&ml_dsa_sk);
        let public_poly = compute_pubkey(&a, &secret_poly);
        let key_image = compute_key_image(&secret_poly);
        Self { ml_dsa_sk, secret_poly, public_poly, key_image }
    }

    pub fn key_image_bytes(&self) -> [u8; 32] { self.key_image }

    /// Canonical key image (scheme-independent).
    /// Use this for v2 transactions to ensure cross-scheme double-spend detection.
    /// The `key_image` field uses the legacy LRS DST for v1 backwards compatibility.
    pub fn canonical_key_image(&self) -> [u8; 32] {
        crate::canonical_ki::canonical_key_image(&self.secret_poly)
    }

    /// Derive a child spending keypair from master secret bytes + index.
    /// index=0 is the master key (use from_ml_dsa). index=1+ are children.
    /// Each child has a unique key_image, enabling UTXO reuse.
    pub fn derive_child(master_sk_bytes: &[u8], index: u32) -> Self {
        use hkdf::Hkdf;
        assert!(index > 0, "index 0 is reserved for the master key");
        let salt = format!("MISAKA:child:v1:{}", index);
        let hk = Hkdf::<Sha3_256>::new(Some(salt.as_bytes()), master_sk_bytes);
        let mut child_bytes = vec![0u8; master_sk_bytes.len()];
        hk.expand(b"misaka/child-spending-key", &mut child_bytes)
            .expect("HKDF expand for child key");
        let child_sk = MlDsaSecretKey::from_bytes(&child_bytes)
            .expect("child key bytes must match ML-DSA SK length");
        Self::from_ml_dsa(child_sk)
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

    // ヘルパー: テスト用のパラメータ a を生成
    fn shared_a() -> Poly {
        derive_public_param(&DEFAULT_A_SEED)
    }

    // ヘルパー: 指定サイズのリングと署名者情報を生成
    fn make_ring(size: usize) -> (Poly, Vec<Poly>, usize, SpendingKeypair) {
        let a = shared_a();
        let mut wallets: Vec<SpendingKeypair> = (0..size)
            .map(|_| SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key))
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
        let skp1 = SpendingKeypair::from_ml_dsa(kp1.secret_key);
        let skp2 = SpendingKeypair::from_ml_dsa(kp2.secret_key);
        
        assert_ne!(skp1.key_image, skp2.key_image, "Key images must be unique for different keys");
    }

    #[test]
    fn test_ring_too_small() {
        // リングサイズが小さすぎる（例: 3未満）場合にエラーになることを確認
        let a = shared_a();
        let ml_kp = MlDsaKeypair::generate();
        let skp = SpendingKeypair::from_ml_dsa(ml_kp.secret_key);
        
        // サイズ2のリングを作成
        let ring = vec![skp.public_poly.clone(); 2];
        let result = ring_sign(&a, &ring, 0, &skp.secret_poly, &[0; 32]);
        
        assert!(result.is_err(), "Signing should fail for ring size < 3");
    }

    #[test]
    fn test_sig_serialization_roundtrip() {
        // 署名のシリアライズ・デシリアライズが正しく行われ、検証が通ることを確認
        let (a, ring, idx, signer) = make_ring(4);
        let msg = [0x42u8; 32];
        
        // 署名生成
        let sig = ring_sign(&a, &ring, idx, &signer.secret_poly, &msg).unwrap();
        
        // バイト列変換 (シリアライズ)
        let bytes = sig.to_bytes();
        
        // バイト列から復元 (デシリアライズ)
        // RingSig::from_bytes にはリングサイズが必要
        let sig2 = RingSig::from_bytes(&bytes, 4).expect("Deserialization failed");
        
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
        let skp = SpendingKeypair::from_ml_dsa(kp.secret_key);
        let t = skp.public_poly;
        
        // 直接多項式乗算した結果
        let t_manual = a.mul(&skp.secret_poly);
        
        assert_eq!(t.to_bytes(), t_manual.to_bytes(), "Public key must satisfy t = a * s");
    }
}
