//! ML-DSA-65 (FIPS 204) — REQUIRED transaction signatures.
//!
//! # Security Policy
//!
//! Every transaction MUST carry a valid ML-DSA-65 signature.
//! It is the sole authentication mechanism.
//! satisfies the authentication requirement alone.
//!
//! # Sizes
//!
//! | Component   | Bytes |
//! |-------------|-------|
//! | Public key  | 1,952 |
//! | Secret key  | 4,032 |
//! | Signature   | 3,309 |

use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as PqPk, SecretKey as PqSk};

use crate::error::CryptoError;

// ─── Constants ───────────────────────────────────────────────

pub const ML_DSA_PK_LEN: usize = 1952;
pub const ML_DSA_SK_LEN: usize = 4032;
pub const ML_DSA_SIG_LEN: usize = 3309;


// ─── Strongly-typed wrappers ─────────────────────────────────

/// ML-DSA-65 public key (1952 bytes).
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MlDsaPublicKey(Vec<u8>);

impl MlDsaPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_DSA_PK_LEN {
            return Err(CryptoError::MlDsaInvalidPkLen(bytes.len()));
        }
        // Audit fix: reject zero key (sentinel value, not a valid identity)
        if bytes.iter().all(|&b| b == 0) {
            return Err(CryptoError::MlDsaVerifyFailed);
        }
        // Audit fix: immediate ML-DSA-65 format validation (not deferred to verify)
        mldsa65::PublicKey::from_bytes(bytes)
            .map_err(|_| CryptoError::MlDsaInvalidPkLen(bytes.len()))?;
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    /// Convert to pqcrypto internal type. Returns None if bytes are invalid.
    fn to_pqcrypto(&self) -> Option<mldsa65::PublicKey> {
        mldsa65::PublicKey::from_bytes(&self.0).ok()
    }
}

impl std::fmt::Debug for MlDsaPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsaPk({}..)", hex::encode(&self.0[..8]))
    }
}

/// ML-DSA-65 secret key (4032 bytes). Zeroized on drop.
///
/// SECURITY:
/// - NOT Clone: prevents accidental proliferation of key material in memory.
///   Pass by reference (`&MlDsaSecretKey`) instead.
/// - Uses `Box<[u8; ML_DSA_SK_LEN]>` instead of `Vec<u8>` to avoid
///   reallocation (which would leave un-zeroized copies in freed heap memory).
/// - `as_bytes()` removed to prevent callers from copying the key.
///   Use `with_bytes()` for scoped access instead.
pub struct MlDsaSecretKey(Box<[u8; ML_DSA_SK_LEN]>);

impl MlDsaSecretKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_DSA_SK_LEN {
            return Err(CryptoError::MlDsaInvalidSkLen(bytes.len()));
        }
        let mut buf = Box::new([0u8; ML_DSA_SK_LEN]);
        buf.copy_from_slice(bytes);
        Ok(Self(buf))
    }

    /// Provide scoped access to the key bytes without exposing a long-lived slice.
    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.0[..])
    }

    /// Convert to pqcrypto internal type. Returns None if bytes are invalid.
    fn to_pqcrypto(&self) -> Option<mldsa65::SecretKey> {
        mldsa65::SecretKey::from_bytes(&self.0[..]).ok()
    }
}

impl Drop for MlDsaSecretKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.as_mut_slice().zeroize();
    }
}

// NOTE: Clone intentionally NOT implemented. See struct-level doc comment.

impl std::fmt::Debug for MlDsaSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsaSk([REDACTED {} bytes])", ML_DSA_SK_LEN)
    }
}

/// ML-DSA-65 detached signature (3309 bytes, fixed).
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MlDsaSignature(pub Vec<u8>);

impl MlDsaSignature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_DSA_SIG_LEN {
            return Err(CryptoError::MlDsaInvalidSigLen(bytes.len()));
        }
        // Audit fix: immediate ML-DSA-65 format validation
        mldsa65::DetachedSignature::from_bytes(bytes)
            .map_err(|_| CryptoError::MlDsaInvalidSigLen(bytes.len()))?;
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to pqcrypto internal type. Returns None if bytes are invalid.
    fn to_pqcrypto(&self) -> Option<mldsa65::DetachedSignature> {
        mldsa65::DetachedSignature::from_bytes(&self.0).ok()
    }
}

impl std::fmt::Debug for MlDsaSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsaSig({}..)", hex::encode(&self.0[..8]))
    }
}

// ─── Keypair bundle ──────────────────────────────────────────

/// ML-DSA-65 keypair.
pub struct MlDsaKeypair {
    pub public_key: MlDsaPublicKey,
    pub secret_key: MlDsaSecretKey,
}

impl MlDsaKeypair {
    /// Generate a fresh ML-DSA-65 keypair.
    pub fn generate() -> Self {
        let (pk, sk) = mldsa65::keypair();
        let sk_bytes = sk.as_bytes();
        let mut sk_buf = Box::new([0u8; ML_DSA_SK_LEN]);
        sk_buf.copy_from_slice(sk_bytes);
        Self {
            public_key: MlDsaPublicKey(pk.as_bytes().to_vec()),
            secret_key: MlDsaSecretKey(sk_buf),
        }
    }
}

// ─── Sign / Verify ───────────────────────────────────────────

/// Sign a message directly (no domain prefix).
///
/// Phase 2c-B D5b: reintroduced as the sole signing entry point.
/// Domain separation is now handled upstream (IntentMessage, signing_digest, etc.).
pub fn ml_dsa_sign_raw(
    sk: &MlDsaSecretKey,
    msg: &[u8],
) -> Result<MlDsaSignature, CryptoError> {
    let pq_sk = sk.to_pqcrypto().ok_or(CryptoError::MlDsaVerifyFailed)?;
    let sig = mldsa65::detached_sign(msg, &pq_sk);
    Ok(MlDsaSignature(sig.as_bytes().to_vec()))
}

/// Verify an ML-DSA-65 signature directly (no domain prefix).
///
/// Phase 2c-B D5b: reintroduced as the sole verification entry point.
pub fn ml_dsa_verify_raw(
    pk: &MlDsaPublicKey,
    msg: &[u8],
    sig: &MlDsaSignature,
) -> Result<(), CryptoError> {
    let pq_pk = pk.to_pqcrypto().ok_or(CryptoError::MlDsaVerifyFailed)?;
    let pq_sig = sig.to_pqcrypto().ok_or(CryptoError::MlDsaVerifyFailed)?;
    mldsa65::verify_detached_signature(&pq_sig, msg, &pq_pk)
        .map_err(|_| CryptoError::MlDsaVerifyFailed)
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_and_sign_verify() {
        let kp = MlDsaKeypair::generate();
        let msg = b"MISAKA block 42";
        let sig = ml_dsa_sign_raw(&kp.secret_key, msg).unwrap();
        ml_dsa_verify_raw(&kp.public_key, msg, &sig).expect("valid sig must verify");
    }

    #[test]
    fn test_wrong_message_fails() {
        let kp = MlDsaKeypair::generate();
        let sig = ml_dsa_sign_raw(&kp.secret_key, b"correct").unwrap();
        assert!(ml_dsa_verify_raw(&kp.public_key, b"wrong", &sig).is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let kp1 = MlDsaKeypair::generate();
        let kp2 = MlDsaKeypair::generate();
        let msg = b"test";
        let sig = ml_dsa_sign_raw(&kp1.secret_key, msg).unwrap();
        assert!(ml_dsa_verify_raw(&kp2.public_key, msg, &sig).is_err());
    }

    #[test]
    fn test_pk_length_validation() {
        assert!(MlDsaPublicKey::from_bytes(&[0; 1951]).is_err());
        assert!(MlDsaPublicKey::from_bytes(&[0; 1952]).is_err(),
            "zero pubkey must be rejected");
        assert!(MlDsaPublicKey::from_bytes(&[0; 1953]).is_err());
    }

    #[test]
    fn test_sig_is_fixed_length() {
        let kp = MlDsaKeypair::generate();
        for i in 0..5 {
            let msg = format!("msg {}", i);
            let sig = ml_dsa_sign_raw(&kp.secret_key, msg.as_bytes()).unwrap();
            assert_eq!(sig.as_bytes().len(), ML_DSA_SIG_LEN);
        }
    }

    #[test]
    fn test_serialization_roundtrip() {
        let kp = MlDsaKeypair::generate();
        let pk_bytes = kp.public_key.as_bytes().to_vec();
        let pk2 = MlDsaPublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(kp.public_key, pk2);

        let sig = ml_dsa_sign_raw(&kp.secret_key, b"test").unwrap();
        let sig_bytes = sig.as_bytes().to_vec();
        let sig2 = MlDsaSignature::from_bytes(&sig_bytes).unwrap();
        assert_eq!(sig, sig2);
    }
}
