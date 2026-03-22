//! ML-DSA-65 (FIPS 204 / Dilithium3) — REQUIRED transaction signatures.
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

use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as PqPk, SecretKey as PqSk};

use crate::error::CryptoError;

// ─── Constants ───────────────────────────────────────────────

pub const ML_DSA_PK_LEN: usize = 1952;
pub const ML_DSA_SK_LEN: usize = 4032;
pub const ML_DSA_SIG_LEN: usize = 3309;

/// Domain separation prefix for transaction signing.
const TX_SIGN_DOMAIN: &[u8] = b"MISAKA-v1:ml-dsa-65:tx-auth:";

// ─── Strongly-typed wrappers ─────────────────────────────────

/// ML-DSA-65 public key (1952 bytes).
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MlDsaPublicKey(pub Vec<u8>);

impl MlDsaPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_DSA_PK_LEN {
            return Err(CryptoError::MlDsaInvalidPkLen(bytes.len()));
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to pqcrypto internal type. Returns None if bytes are invalid.
    fn to_pqcrypto(&self) -> Option<dilithium3::PublicKey> {
        dilithium3::PublicKey::from_bytes(&self.0).ok()
    }
}

impl std::fmt::Debug for MlDsaPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsaPk({}..)", hex::encode(&self.0[..8]))
    }
}

/// ML-DSA-65 secret key (4032 bytes). Zeroized on drop.
pub struct MlDsaSecretKey(Vec<u8>);

impl MlDsaSecretKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_DSA_SK_LEN {
            return Err(CryptoError::MlDsaInvalidSkLen(bytes.len()));
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to pqcrypto internal type. Returns None if bytes are invalid.
    fn to_pqcrypto(&self) -> Option<dilithium3::SecretKey> {
        dilithium3::SecretKey::from_bytes(&self.0).ok()
    }
}

impl Drop for MlDsaSecretKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

impl Clone for MlDsaSecretKey {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl std::fmt::Debug for MlDsaSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlDsaSk([REDACTED {} bytes])", self.0.len())
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
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to pqcrypto internal type. Returns None if bytes are invalid.
    fn to_pqcrypto(&self) -> Option<dilithium3::DetachedSignature> {
        dilithium3::DetachedSignature::from_bytes(&self.0).ok()
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
        let (pk, sk) = dilithium3::keypair();
        Self {
            public_key: MlDsaPublicKey(pk.as_bytes().to_vec()),
            secret_key: MlDsaSecretKey(sk.as_bytes().to_vec()),
        }
    }
}

// ─── Sign / Verify ───────────────────────────────────────────

/// Sign a message with domain-separated ML-DSA-65.
///
/// The actual signed payload is `TX_SIGN_DOMAIN || msg`.
pub fn ml_dsa_sign(sk: &MlDsaSecretKey, msg: &[u8]) -> Result<MlDsaSignature, CryptoError> {
    let mut domain_msg = Vec::with_capacity(TX_SIGN_DOMAIN.len() + msg.len());
    domain_msg.extend_from_slice(TX_SIGN_DOMAIN);
    domain_msg.extend_from_slice(msg);

    let pq_sk = sk.to_pqcrypto().ok_or(CryptoError::MlDsaVerifyFailed)?;
    let sig = dilithium3::detached_sign(&domain_msg, &pq_sk);
    Ok(MlDsaSignature(sig.as_bytes().to_vec()))
}

/// Verify an ML-DSA-65 signature with domain separation.
///
/// Returns `Ok(())` on success, `Err(MlDsaVerifyFailed)` on failure.
pub fn ml_dsa_verify(
    pk: &MlDsaPublicKey,
    msg: &[u8],
    sig: &MlDsaSignature,
) -> Result<(), CryptoError> {
    let mut domain_msg = Vec::with_capacity(TX_SIGN_DOMAIN.len() + msg.len());
    domain_msg.extend_from_slice(TX_SIGN_DOMAIN);
    domain_msg.extend_from_slice(msg);

    let pq_pk = pk.to_pqcrypto().ok_or(CryptoError::MlDsaVerifyFailed)?;
    let pq_sig = sig.to_pqcrypto().ok_or(CryptoError::MlDsaVerifyFailed)?;
    dilithium3::verify_detached_signature(&pq_sig, &domain_msg, &pq_pk)
        .map_err(|_| CryptoError::MlDsaVerifyFailed)
}

/// Sign raw bytes WITHOUT domain separation (for non-tx contexts like P2P handshake).
pub fn ml_dsa_sign_raw(sk: &MlDsaSecretKey, msg: &[u8]) -> Result<MlDsaSignature, CryptoError> {
    let pq_sk = sk.to_pqcrypto().ok_or(CryptoError::MlDsaVerifyFailed)?;
    let sig = dilithium3::detached_sign(msg, &pq_sk);
    Ok(MlDsaSignature(sig.as_bytes().to_vec()))
}

/// Verify raw ML-DSA-65 signature without domain separation.
pub fn ml_dsa_verify_raw(
    pk: &MlDsaPublicKey,
    msg: &[u8],
    sig: &MlDsaSignature,
) -> Result<(), CryptoError> {
    let pq_pk = pk.to_pqcrypto().ok_or(CryptoError::MlDsaVerifyFailed)?;
    let pq_sig = sig.to_pqcrypto().ok_or(CryptoError::MlDsaVerifyFailed)?;
    dilithium3::verify_detached_signature(&pq_sig, msg, &pq_pk)
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
        let sig = ml_dsa_sign(&kp.secret_key, msg).unwrap();
        ml_dsa_verify(&kp.public_key, msg, &sig).expect("valid sig must verify");
    }

    #[test]
    fn test_wrong_message_fails() {
        let kp = MlDsaKeypair::generate();
        let sig = ml_dsa_sign(&kp.secret_key, b"correct").unwrap();
        assert!(ml_dsa_verify(&kp.public_key, b"wrong", &sig).is_err());
    }

    #[test]
    fn test_wrong_key_fails() {
        let kp1 = MlDsaKeypair::generate();
        let kp2 = MlDsaKeypair::generate();
        let msg = b"test";
        let sig = ml_dsa_sign(&kp1.secret_key, msg).unwrap();
        assert!(ml_dsa_verify(&kp2.public_key, msg, &sig).is_err());
    }

    #[test]
    fn test_domain_separation_prevents_cross_context() {
        let kp = MlDsaKeypair::generate();
        let msg = b"test";
        // Sign with domain (tx context)
        let sig_domain = ml_dsa_sign(&kp.secret_key, msg).unwrap();
        // Sign raw (non-tx context)
        let sig_raw = ml_dsa_sign_raw(&kp.secret_key, msg).unwrap();
        // Raw verify of domain-signed must fail
        assert!(ml_dsa_verify_raw(&kp.public_key, msg, &sig_domain).is_err());
        // Domain verify of raw-signed must fail
        assert!(ml_dsa_verify(&kp.public_key, msg, &sig_raw).is_err());
    }

    #[test]
    fn test_pk_length_validation() {
        assert!(MlDsaPublicKey::from_bytes(&[0; 1951]).is_err());
        assert!(MlDsaPublicKey::from_bytes(&[0; 1952]).is_ok());
        assert!(MlDsaPublicKey::from_bytes(&[0; 1953]).is_err());
    }

    #[test]
    fn test_sig_is_fixed_length() {
        let kp = MlDsaKeypair::generate();
        for i in 0..5 {
            let msg = format!("msg {}", i);
            let sig = ml_dsa_sign(&kp.secret_key, msg.as_bytes()).unwrap();
            assert_eq!(sig.as_bytes().len(), ML_DSA_SIG_LEN);
        }
    }

    #[test]
    fn test_serialization_roundtrip() {
        let kp = MlDsaKeypair::generate();
        let pk_bytes = kp.public_key.as_bytes().to_vec();
        let pk2 = MlDsaPublicKey::from_bytes(&pk_bytes).unwrap();
        assert_eq!(kp.public_key, pk2);

        let sig = ml_dsa_sign(&kp.secret_key, b"test").unwrap();
        let sig_bytes = sig.as_bytes().to_vec();
        let sig2 = MlDsaSignature::from_bytes(&sig_bytes).unwrap();
        assert_eq!(sig, sig2);
    }
}
