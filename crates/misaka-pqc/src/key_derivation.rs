//! Key derivation and polynomial arithmetic for MISAKA spending keys.
//!
//! Contains:
//! - `Poly`: polynomial in R_q = Z_q[X]/(X^256+1)
//! - `SpendingKeypair`: ML-DSA-65 identity + canonical spend ID
//! - `derive_public_param`, `derive_secret_poly`
//!
//! SEC-FIX: Legacy LRS (Linkable Ring Signature) code has been removed.
//! All transactions use TransparentTransfer (ML-DSA-65 direct signatures)
//! as of Phase 2c-B. Functions removed: pq_sign, legacy_verify,
//! legacy_verify_transparent, legacy_sign_transparent, LegacyProofData.

use hkdf::Hkdf;
use rand::RngCore;
use sha3::{Digest as Sha3Digest, Sha3_256, Sha3_512};

use crate::error::CryptoError;
use crate::pq_sign::MlDsaSecretKey;

use serde::{Deserialize, Serialize};
use serde_with::serde_as;

// 笏笏笏 Parameters 笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏

pub const Q: i32 = 12289;
pub const N: usize = 256;

// SEC-FIX: LRS ring signature constants removed (ETA, TAU, GAMMA, BETA,
// MIN_RING_SIZE, MAX_RING_SIZE, MAX_SIGN_ATTEMPTS, DST_KI, DST_CHALLENGE).
// Only Q and N are retained 窶・used by Poly arithmetic.

const DST_SPENDING: &[u8] = b"misaka/lrs/spending-key/v1";
const DST_PUBPARAM: &[u8] = b"MISAKA-LRS:a-param:v1";

// 笏笏笏 Zeroize helpers (inlined from deleted `secret` module) 笏笏

/// Zeroize polynomial coefficients in-place (volatile write).
fn zeroize_poly_coeffs(coeffs: &mut [i32; N]) {
    for c in coeffs.iter_mut() {
        unsafe { std::ptr::write_volatile(c, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Zeroize byte slice in-place (volatile write).
fn zeroize_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

// 笏笏笏 Polynomial Type 笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏

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
        // SEC-FIX H-9: Redact coefficients to prevent secret key material
        // from leaking into logs, panic messages, or debug output.
        write!(f, "Poly([REDACTED; 256])")
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

    /// Schoolbook polynomial multiplication O(n^2) in R_q = Z_q[X]/(X^N+1).
    /// Constant-time: no zero-coefficient skipping.
    pub fn mul(&self, other: &Poly) -> Poly {
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

    /// Infinity norm (centered representation).
    /// Constant-time: no secret-dependent branching.
    pub fn norm_inf(&self) -> i32 {
        let mut max_val = 0i32;
        for &c in &self.coeffs {
            let above_half = ((Q / 2 - c) >> 31) & 1;
            let centered = c - Q * above_half;
            let mask = centered >> 31;
            let abs_val = (centered ^ mask) - mask;
            let gt = ((max_val - abs_val) >> 31) & 1;
            max_val = max_val + gt * (abs_val - max_val);
        }
        max_val
    }

    /// Constant-time polynomial equality check.
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
    pub fn challenge_to_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let mut result = Vec::with_capacity(N);
        for (i, &c) in self.coeffs.iter().enumerate() {
            let byte = if c == 0 {
                0u8
            } else if c == 1 {
                1u8
            } else if c == Q - 1 {
                0xFFu8
            } else {
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
                _ => return Err(CryptoError::ProofInvalid("bad challenge byte".into())),
            };
        }
        Ok(p)
    }
}

// 笏笏笏 Shared Public Parameter 笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏

/// Derive the shared polynomial 'a' from a seed (deterministic).
pub fn derive_public_param(seed: &[u8; 32]) -> Poly {
    let mut h = Sha3_512::new();
    h.update(DST_PUBPARAM);
    h.update(seed);
    let hash = h.finalize();

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

// 笏笏笏 Key Generation 笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏

/// Derive a lattice secret polynomial from ML-DSA-65 secret key.
/// Coefficients in {-1, 0, 1} (eta=1).
pub fn derive_secret_poly(ml_dsa_sk: &MlDsaSecretKey) -> Result<Poly, CryptoError> {
    let hk = ml_dsa_sk.with_bytes(|sk_bytes| Hkdf::<Sha3_256>::new(None, sk_bytes));
    let mut expanded = [0u8; N];
    hk.expand(DST_SPENDING, &mut expanded).map_err(|_| {
        CryptoError::ProofInvalid(
            "HKDF expand failed in derive_secret_poly 窶・refusing to use zero polynomial".into(),
        )
    })?;

    let mut s = Poly::zero();
    for i in 0..N {
        let b = expanded[i] as i32;
        let neg_mask = ((84i32 - b) >> 31) & 1;
        let pos_mask = ((170i32 - b) >> 31) & 1;
        s.coeffs[i] = (1 - neg_mask) * (Q - 1) + pos_mask;
    }

    zeroize_bytes(&mut expanded);

    Ok(s)
}

/// Compute public key: t = a * s mod q.
pub fn compute_pubkey(a: &Poly, s: &Poly) -> Poly {
    a.mul(s)
}

// SEC-FIX: compute_legacy_spend_id() removed (LRS-only, used DST "MISAKA-LRS:ki:v1:").
// Canonical spend ID uses canonical_ki::canonical_spend_id() instead.

// SEC-FIX: hash_to_challenge(), sample_masking_poly(), sample_response_poly()
// removed - all were LRS-only internal functions using removed constants.

// 笏笏笏 Ring Signature (REMOVED) 笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏
//
// SEC-FIX: The following legacy LRS code has been completely removed:
// - LegacyProofData struct (ring signature proof container)
// - pq_sign() (ring signature generation)
// - legacy_verify() (ring signature verification)
// - legacy_sign_transparent() (transparent ring signature generation)
// - legacy_verify_transparent() (transparent ring signature verification)
//
// All transactions now use TransparentTransfer with ML-DSA-65 direct
// signatures. The LRS code contained a key image (canonical_spend_id)
// forgery vulnerability where attackers could provide arbitrary spend IDs
// since the mathematical verification did not bind the key image.
//
// See: Phase 2c-B migration, security audit CRITICAL #2.

// (LRS code removed 窶・see comment above)
// 笏笏笏 High-level API 笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏

/// Spending keypair: ML-DSA-65 identity + lattice key image.
///
/// SEC-FIX M-11: Drop impl zeroizes secret_poly to prevent secret material
/// from lingering in freed heap memory.
pub struct SpendingKeypair {
    pub ml_dsa_sk: MlDsaSecretKey,
    pub ml_dsa_pk_bytes: Vec<u8>,
    pub secret_poly: Poly,
    pub public_poly: Poly,
}

impl Drop for SpendingKeypair {
    fn drop(&mut self) {
        zeroize_poly_coeffs(&mut self.secret_poly.coeffs);
    }
}

impl SpendingKeypair {
    /// Derive from ML-DSA-65 keypair (both sk and pk required).
    pub fn from_ml_dsa_pair(
        ml_dsa_sk: MlDsaSecretKey,
        ml_dsa_pk_bytes: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let secret_poly = derive_secret_poly(&ml_dsa_sk)?;
        let public_poly = compute_pubkey(&a, &secret_poly);
        Ok(Self {
            ml_dsa_sk,
            ml_dsa_pk_bytes,
            secret_poly,
            public_poly,
        })
    }

    /// Legacy: Derive from ML-DSA-65 secret key only (pk unknown).
    pub fn from_ml_dsa(ml_dsa_sk: MlDsaSecretKey) -> Result<Self, CryptoError> {
        Self::from_ml_dsa_pair(ml_dsa_sk, Vec::new())
    }

    /// Canonical key image (scheme-independent).
    /// Uses the canonical DST "MISAKA_KI_V1:" via canonical_ki module.
    pub fn canonical_spend_id(&self) -> [u8; 32] {
        crate::canonical_ki::canonical_spend_id(&self.secret_poly)
    }

    /// Derive a child spending keypair for change outputs.
    ///
    /// # SEC-FIX M-14: Non-deterministic key generation
    ///
    /// The ML-DSA-65 keypair is generated using system RNG, NOT derived from
    /// the master key + index. This means child keys CANNOT be recovered from
    /// a seed phrase alone — the wallet MUST persist the generated keypairs.
    /// A future version should use seed-based deterministic keygen.
    pub fn derive_child(master_sk_bytes: &[u8], index: u32) -> Result<Self, CryptoError> {
        if index == 0 {
            return Err(CryptoError::ProofInvalid(
                "index 0 is reserved for the master key".into(),
            ));
        }

        let child_kp = crate::pq_sign::MlDsaKeypair::generate();
        let child_pk_bytes = child_kp.public_key.as_bytes().to_vec();

        let salt = format!("MISAKA:child:v1:{}", index);
        let hk = Hkdf::<Sha3_256>::new(Some(salt.as_bytes()), master_sk_bytes);
        let mut expanded = [0u8; N];
        hk.expand(b"misaka/child-ki-seed", &mut expanded)
            .map_err(|_| {
                CryptoError::ProofInvalid("HKDF expand failed for child KI seed".into())
            })?;

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
        zeroize_bytes(&mut expanded);
        let public_poly = compute_pubkey(&a, &secret_poly);

        Ok(Self {
            ml_dsa_sk: child_kp.secret_key,
            ml_dsa_pk_bytes: child_pk_bytes,
            secret_poly,
            public_poly,
        })
    }

    /// Derive the MISAKA address for this spending keypair.
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
    pub fn ml_dsa_pk(&self) -> &[u8] {
        &self.ml_dsa_pk_bytes
    }
}

// 笏笏笏 Tests 笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pq_sign::MlDsaKeypair;

    fn shared_a() -> Poly {
        derive_public_param(&DEFAULT_A_SEED)
    }

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
    fn test_canonical_spend_id_unique() {
        let kp1 = MlDsaKeypair::generate();
        let kp2 = MlDsaKeypair::generate();
        let skp1 = SpendingKeypair::from_ml_dsa(kp1.secret_key).unwrap();
        let skp2 = SpendingKeypair::from_ml_dsa(kp2.secret_key).unwrap();

        assert_ne!(skp1.canonical_spend_id(), skp2.canonical_spend_id());
    }

    // SEC-FIX: test_sign_verify and test_sig_serialization_roundtrip removed
    // (tested legacy LRS pq_sign/legacy_verify which have been deleted).

    #[test]
    fn test_pubkey_verification() {
        let a = shared_a();
        let kp = MlDsaKeypair::generate();
        let skp = SpendingKeypair::from_ml_dsa(kp.secret_key).unwrap();
        let t = skp.public_poly.clone();
        let t_manual = a.mul(&skp.secret_poly);
        assert_eq!(t.to_bytes(), t_manual.to_bytes());
    }
}
