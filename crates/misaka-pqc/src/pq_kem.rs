//! ML-KEM-768 (FIPS 203) — PQ Key Encapsulation Mechanism.
//!
//! Used for PQ-KEM address shared-secret derivation:
//! sender encapsulates against recipient's KEM public key → shared secret
//! → derive one-time output key + encrypt amount.
//!
//! # Sizes
//!
//! | Component     | Bytes |
//! |---------------|-------|
//! | Public key    | 1,184 |
//! | Secret key    | 2,400 |
//! | Ciphertext    | 1,088 |
//! | Shared secret |    32 |

use pqcrypto_mlkem::mlkem768;
use pqcrypto_traits::kem::{
    Ciphertext as PqCt, PublicKey as PqKemPk, SecretKey as PqKemSk, SharedSecret as PqSs,
};
use sha3::{Digest as Sha3Digest, Sha3_256};

use crate::error::CryptoError;

// ─── Constants ───────────────────────────────────────────────

pub const ML_KEM_PK_LEN: usize = 1184;
pub const ML_KEM_SK_LEN: usize = 2400;
pub const ML_KEM_CT_LEN: usize = 1088;
pub const ML_KEM_SS_LEN: usize = 32;

// ─── Backend trait ───────────────────────────────────────────

/// Abstract PQ KEM backend for testability and future algorithm agility.
pub trait PqKemBackend {
    type PublicKey;
    type SecretKey;
    type Ciphertext;
    type SharedSecret;

    /// Generate a fresh KEM keypair.
    fn keygen() -> Result<(Self::SecretKey, Self::PublicKey), CryptoError>;

    /// Deterministic encapsulation (seed-based).
    ///
    /// SEC-FIX N-M6: Deprecated. `pqcrypto-mlkem` does not support seeded
    /// encapsulation, making this inherently misleading. Callers should use
    /// `encapsulate()` (randomized) directly.
    #[deprecated(note = "pqcrypto-mlkem ignores seed — use encapsulate() instead")]
    fn encapsulate_deterministic(
        pk: &Self::PublicKey,
        seed32: &[u8; 32],
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), CryptoError>;

    /// Standard (randomized) encapsulation.
    fn encapsulate(
        pk: &Self::PublicKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), CryptoError>;

    /// Decapsulate to recover shared secret.
    fn decapsulate(
        sk: &Self::SecretKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, CryptoError>;
}

// ─── Strongly-typed wrappers ─────────────────────────────────

/// ML-KEM-768 public key (1184 bytes).
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MlKemPublicKey(pub Vec<u8>);

impl MlKemPublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_KEM_PK_LEN {
            return Err(CryptoError::MlKemInvalidPkLen(bytes.len()));
        }
        // SEC-FIX: Reject all-zero public key (sentinel value).
        // MlDsaPublicKey already does this; MlKemPublicKey was missing the check.
        if bytes.iter().all(|&b| b == 0) {
            return Err(CryptoError::MlKemEncapsulateFailed);
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn to_pqcrypto(&self) -> Result<mlkem768::PublicKey, CryptoError> {
        mlkem768::PublicKey::from_bytes(&self.0).map_err(|_| CryptoError::MlKemEncapsulateFailed)
    }
}

impl std::fmt::Debug for MlKemPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlKemPk({}..)", hex::encode(&self.0[..8]))
    }
}

/// ML-KEM-768 secret key (2400 bytes). Zeroized on drop.
///
/// SEC-FIX N-L3: Uses `Box<[u8; ML_KEM_SK_LEN]>` instead of `Vec<u8>`
/// to prevent reallocation-induced key copies in freed heap memory.
pub struct MlKemSecretKey(Box<[u8; ML_KEM_SK_LEN]>);

impl MlKemSecretKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_KEM_SK_LEN {
            return Err(CryptoError::MlKemInvalidSkLen(bytes.len()));
        }
        let mut buf = Box::new([0u8; ML_KEM_SK_LEN]);
        buf.copy_from_slice(bytes);
        Ok(Self(buf))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &*self.0
    }

    fn to_pqcrypto(&self) -> Result<mlkem768::SecretKey, CryptoError> {
        mlkem768::SecretKey::from_bytes(&*self.0).map_err(|_| CryptoError::MlKemDecapsulateFailed)
    }
}

impl Drop for MlKemSecretKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

// SEC-FIX: Clone removed from MlKemSecretKey.
// Cloning secret key material creates copies that bypass Drop+zeroize protection.
// Use Arc<MlKemSecretKey> for sharing. (MlDsaSecretKey already correctly omits Clone.)

impl std::fmt::Debug for MlKemSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlKemSk([REDACTED {} bytes])", self.0.len())
    }
}

/// ML-KEM-768 ciphertext (1088 bytes).
#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MlKemCiphertext(pub Vec<u8>);

impl MlKemCiphertext {
    /// SEC-FIX TM-14: Validate that bytes can be parsed by pqcrypto before storing.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_KEM_CT_LEN {
            return Err(CryptoError::MlKemInvalidCtLen(bytes.len()));
        }
        mlkem768::Ciphertext::from_bytes(bytes).map_err(|_| CryptoError::MlKemDecapsulateFailed)?;
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn to_pqcrypto(&self) -> Result<mlkem768::Ciphertext, CryptoError> {
        mlkem768::Ciphertext::from_bytes(&self.0).map_err(|_| CryptoError::MlKemDecapsulateFailed)
    }
}

impl std::fmt::Debug for MlKemCiphertext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlKemCt({}..)", hex::encode(&self.0[..8]))
    }
}

/// ML-KEM-768 shared secret (32 bytes). Zeroized on drop.
///
/// # Security (SEC-AUDIT-V5 MED-003)
///
/// PartialEq/Eq intentionally NOT derived — standard `==` on secret
/// material leaks information via timing. Use `ct_eq_32` if comparison
/// is ever needed.  The inner field is `pub(crate)` to prevent external
/// code from constructing or pattern-matching the value.
pub struct MlKemSharedSecret(pub(crate) [u8; 32]);

impl MlKemSharedSecret {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() != ML_KEM_SS_LEN {
            return Err(CryptoError::InvalidSeedLength {
                expected: 32,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for MlKemSharedSecret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

impl std::fmt::Debug for MlKemSharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MlKemSS([REDACTED])")
    }
}

/// ML-KEM-768 keypair bundle.
pub struct MlKemKeypair {
    pub public_key: MlKemPublicKey,
    pub secret_key: MlKemSecretKey,
}

// ─── ML-KEM-768 Backend Implementation ───────────────────────

/// Concrete ML-KEM-768 backend.
pub struct MlKem768Backend;

impl PqKemBackend for MlKem768Backend {
    type PublicKey = MlKemPublicKey;
    type SecretKey = MlKemSecretKey;
    type Ciphertext = MlKemCiphertext;
    type SharedSecret = MlKemSharedSecret;

    fn keygen() -> Result<(Self::SecretKey, Self::PublicKey), CryptoError> {
        let (pk, sk) = mlkem768::keypair();
        let sk_bytes = sk.as_bytes();
        let mut sk_buf = Box::new([0u8; ML_KEM_SK_LEN]);
        sk_buf.copy_from_slice(sk_bytes);
        Ok((
            MlKemSecretKey(sk_buf),
            MlKemPublicKey(pk.as_bytes().to_vec()),
        ))
    }

    /// SEC-FIX N-M6: NOT deterministic — seed is IGNORED by pqcrypto-mlkem.
    /// This method always panics. Use `encapsulate()` instead.
    #[allow(deprecated)]
    fn encapsulate_deterministic(
        _pk: &Self::PublicKey,
        _seed32: &[u8; 32],
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), CryptoError> {
        Err(CryptoError::MlKemEncapsulateFailed)
    }

    fn encapsulate(
        pk: &Self::PublicKey,
    ) -> Result<(Self::Ciphertext, Self::SharedSecret), CryptoError> {
        let pq_pk = pk.to_pqcrypto()?;
        let (ss, ct) = mlkem768::encapsulate(&pq_pk);
        let mut ss_arr = [0u8; 32];
        ss_arr.copy_from_slice(ss.as_bytes());
        Ok((
            MlKemCiphertext(ct.as_bytes().to_vec()),
            MlKemSharedSecret(ss_arr),
        ))
    }

    fn decapsulate(
        sk: &Self::SecretKey,
        ct: &Self::Ciphertext,
    ) -> Result<Self::SharedSecret, CryptoError> {
        let pq_ct = ct.to_pqcrypto()?;
        let pq_sk = sk.to_pqcrypto()?;
        let ss = mlkem768::decapsulate(&pq_ct, &pq_sk);
        let mut ss_arr = [0u8; 32];
        ss_arr.copy_from_slice(ss.as_bytes());
        Ok(MlKemSharedSecret(ss_arr))
    }
}

// ─── Convenience functions ───────────────────────────────────

/// Generate a fresh ML-KEM-768 keypair.
pub fn ml_kem_keygen() -> Result<MlKemKeypair, CryptoError> {
    let (sk, pk) = MlKem768Backend::keygen()?;
    Ok(MlKemKeypair {
        public_key: pk,
        secret_key: sk,
    })
}

/// Encapsulate against a recipient's KEM public key (randomized).
pub fn ml_kem_encapsulate(
    pk: &MlKemPublicKey,
) -> Result<(MlKemCiphertext, MlKemSharedSecret), CryptoError> {
    MlKem768Backend::encapsulate(pk)
}

/// Decapsulate using KEM secret key.
pub fn ml_kem_decapsulate(
    sk: &MlKemSecretKey,
    ct: &MlKemCiphertext,
) -> Result<MlKemSharedSecret, CryptoError> {
    MlKem768Backend::decapsulate(sk, ct)
}

// ─── KDF helper ──────────────────────────────────────────────

/// Derive a sub-key from shared secret + domain tag + index.
///
/// `derived = SHA3-256(domain || ss || le_bytes(index))`
pub fn kdf_derive(ss: &MlKemSharedSecret, domain: &[u8], index: u32) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(domain);
    h.update(ss.as_bytes());
    h.update(&index.to_le_bytes());
    h.finalize().into()
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kem_encap_decap() {
        let kp = ml_kem_keygen().unwrap();
        let (ct, ss_sender) = ml_kem_encapsulate(&kp.public_key).unwrap();
        let ss_recipient = ml_kem_decapsulate(&kp.secret_key, &ct).unwrap();
        assert_eq!(ss_sender.as_bytes(), ss_recipient.as_bytes());
    }

    #[test]
    fn test_kem_wrong_sk_produces_different_ss() {
        let kp1 = ml_kem_keygen().unwrap();
        let kp2 = ml_kem_keygen().unwrap();
        let (ct, ss_sender) = ml_kem_encapsulate(&kp1.public_key).unwrap();
        let ss_wrong = ml_kem_decapsulate(&kp2.secret_key, &ct).unwrap();
        // ML-KEM-768 decapsulation with wrong key produces a pseudorandom output
        // (implicit rejection), not an error. But it won't match.
        assert_ne!(ss_sender.as_bytes(), ss_wrong.as_bytes());
    }

    #[test]
    fn test_kdf_derive_deterministic() {
        let ss = MlKemSharedSecret([0x42; 32]);
        let k1 = kdf_derive(&ss, b"MISAKA:pq-kem-key", 0);
        let k2 = kdf_derive(&ss, b"MISAKA:pq-kem-key", 0);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_kdf_derive_different_index() {
        let ss = MlKemSharedSecret([0x42; 32]);
        let k0 = kdf_derive(&ss, b"MISAKA:pq-kem-key", 0);
        let k1 = kdf_derive(&ss, b"MISAKA:pq-kem-key", 1);
        assert_ne!(k0, k1);
    }

    #[test]
    fn test_kdf_derive_different_domain() {
        let ss = MlKemSharedSecret([0x42; 32]);
        let k_a = kdf_derive(&ss, b"MISAKA:amount-mask", 0);
        let k_b = kdf_derive(&ss, b"MISAKA:pq-kem-key", 0);
        assert_ne!(k_a, k_b);
    }

    #[test]
    fn test_pk_length_validation() {
        assert!(MlKemPublicKey::from_bytes(&[0; 1183]).is_err());
        assert!(MlKemPublicKey::from_bytes(&[1; 1184]).is_ok());
        assert!(MlKemPublicKey::from_bytes(&[0; 1185]).is_err());
        // All-zero key must be rejected
        assert!(MlKemPublicKey::from_bytes(&[0; 1184]).is_err());
    }

    #[test]
    fn test_ct_length_validation() {
        assert!(MlKemCiphertext::from_bytes(&[0; 1087]).is_err());
        assert!(MlKemCiphertext::from_bytes(&[1; 1088]).is_ok());
        assert!(MlKemCiphertext::from_bytes(&[0; 1089]).is_err());
    }
}
