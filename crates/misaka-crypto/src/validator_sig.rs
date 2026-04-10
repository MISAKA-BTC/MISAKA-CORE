//! PQ-Only Validator Signature: ML-DSA-65 (FIPS 204).
//!
//! ECC is COMPLETELY ELIMINATED. No Ed25519, no secp256k1.
//! All validator operations use ML-DSA-65 exclusively.
//!
//! # Domain Separation
//!
//! `digest = SHA3-256("MISAKA-PQ-SIG:v2:" || message)`
//!
//! The v2 domain tag distinguishes from the legacy hybrid scheme,
//! preventing cross-version signature replay.

use sha3::{Digest as Sha3Digest, Sha3_256};

use misaka_pqc::pq_sign::{
    ml_dsa_sign_raw, ml_dsa_verify_raw, MlDsaKeypair, MlDsaPublicKey, MlDsaSecretKey,
    MlDsaSignature, ML_DSA_PK_LEN, ML_DSA_SIG_LEN,
};

const DOMAIN_TAG: &[u8] = b"MISAKA-PQ-SIG:v2:";

// ─── Types ───────────────────────────────────────────────────

/// PQ-only validator public key (ML-DSA-65, 1952 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct ValidatorPqPublicKey {
    pub pq_pk: Vec<u8>, // 1952 bytes
}

impl ValidatorPqPublicKey {
    pub const SIZE: usize = ML_DSA_PK_LEN; // 1952

    /// Create a zeroed public key (sentinel / placeholder).
    ///
    /// Used in the handshake transcript when the initiator's identity
    /// is not yet known to the responder. NEVER represents a real key.
    pub fn zero() -> Self {
        Self {
            pq_pk: vec![0u8; ML_DSA_PK_LEN],
        }
    }

    /// Returns `true` if every byte of the public key is zero.
    ///
    /// A zero key is the sentinel / placeholder used in handshake transcripts;
    /// it MUST NOT be accepted as a real validator identity.
    pub fn is_zero(&self) -> bool {
        self.pq_pk.iter().all(|&b| b == 0)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.pq_pk.clone()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() != ML_DSA_PK_LEN {
            return Err("invalid PQ validator pk length (expected 1952)");
        }
        if data.iter().all(|&b| b == 0) {
            return Err("zero pubkey forbidden (sentinel)");
        }
        // SEC-FIX H-8: Validate that the bytes can actually be parsed as
        // an ML-DSA-65 public key. Reject malformed keys at deserialization
        // time rather than at signature verification time.
        if MlDsaPublicKey::from_bytes(data).is_err() {
            return Err("malformed ML-DSA-65 public key (pqcrypto rejected)");
        }
        Ok(Self {
            pq_pk: data.to_vec(),
        })
    }

    /// Derive a 32-byte canonical validator ID from the PQ public key.
    ///
    /// # Why 32 bytes?
    ///
    /// ML-DSA-65 public keys are 1952 bytes. Truncating the SHA3-256 hash
    /// to 20 bytes (removed in v10) reduced collision resistance
    /// to 80 bits classically / 53 bits quantum (Grover).
    ///
    /// Using the full 32-byte SHA3-256 output provides:
    /// - 128-bit classical collision resistance
    /// - 85-bit quantum collision resistance (Grover)
    ///
    /// This matches the post-quantum security level of ML-DSA-65 itself.
    /// All consensus, slashing, and attestation logic MUST use this ID.
    pub fn to_canonical_id(&self) -> [u8; 32] {
        crate::sha3_256(&self.pq_pk)
    }
}

impl std::fmt::Debug for ValidatorPqPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix_len = self.pq_pk.len().min(8);
        write!(
            f,
            "ValidatorPqPk({}..)",
            hex::encode(&self.pq_pk[..prefix_len])
        )
    }
}

/// PQ-only validator secret key. Securely zeroized on drop.
///
/// ML-DSA-65 secret key for validator signing (4032 bytes, fixed size).
///
/// SEC-FIX: Uses `Box<[u8; 4032]>` instead of `Vec<u8>` to prevent
/// reallocation leaving un-zeroized copies in freed heap memory.
/// Field is private — access via `with_bytes()` scoped accessor only.
/// Clone is intentionally NOT implemented.
pub struct ValidatorPqSecretKey {
    pq_sk: Box<[u8; 4032]>,
}

impl ValidatorPqSecretKey {
    /// Create from raw bytes. Returns None if length != 4032.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 4032 {
            return None;
        }
        let mut buf = Box::new([0u8; 4032]);
        buf.copy_from_slice(bytes);
        Some(Self { pq_sk: buf })
    }

    /// Scoped access to the raw key bytes. The closure cannot store
    /// a reference that outlives the call.
    pub fn with_bytes<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        f(&self.pq_sk[..])
    }
}

impl Drop for ValidatorPqSecretKey {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.pq_sk.as_mut_slice().zeroize();
    }
}

// Clone intentionally removed (ME-5 fix).
// Each clone creates an un-tracked copy of key material.
// Pass by reference (&ValidatorPqSecretKey) instead.

impl std::fmt::Debug for ValidatorPqSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ValidatorPqSk([REDACTED])")
    }
}

/// PQ-only validator signature (ML-DSA-65, 3309 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct ValidatorPqSignature {
    pub pq_sig: Vec<u8>, // 3309 bytes
}

impl ValidatorPqSignature {
    pub const SIZE: usize = ML_DSA_SIG_LEN; // 3309

    pub fn to_bytes(&self) -> Vec<u8> {
        self.pq_sig.clone()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() != ML_DSA_SIG_LEN {
            return Err("invalid PQ validator sig length (expected 3309)");
        }
        // SEC-FIX H-8: Validate that bytes can be parsed by pqcrypto.
        if MlDsaSignature::from_bytes(data).is_err() {
            return Err("malformed ML-DSA-65 signature (pqcrypto rejected)");
        }
        Ok(Self {
            pq_sig: data.to_vec(),
        })
    }
}

impl std::fmt::Debug for ValidatorPqSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let prefix_len = self.pq_sig.len().min(8);
        write!(
            f,
            "ValidatorPqSig({}..)",
            hex::encode(&self.pq_sig[..prefix_len])
        )
    }
}

/// PQ-only validator keypair bundle.
pub struct ValidatorKeypair {
    pub public_key: ValidatorPqPublicKey,
    pub secret_key: ValidatorPqSecretKey,
}

// ─── Domain-separated hash ───────────────────────────────────

/// Compute domain-separated signing digest.
/// `SHA3-256("MISAKA-PQ-SIG:v2:" || message)`
fn signing_digest(message: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DOMAIN_TAG);
    h.update(message);
    h.finalize().into()
}

// ─── Keygen / Sign / Verify ──────────────────────────────────

/// Generate a PQ-only validator keypair (ML-DSA-65).
pub fn generate_validator_keypair() -> ValidatorKeypair {
    let pq_kp = MlDsaKeypair::generate();
    ValidatorKeypair {
        public_key: ValidatorPqPublicKey {
            pq_pk: pq_kp.public_key.as_bytes().to_vec(),
        },
        secret_key: pq_kp.secret_key.with_bytes(|bytes| {
            ValidatorPqSecretKey::from_bytes(bytes).expect("ML-DSA-65 SK is always 4032 bytes")
        }),
    }
}

/// Sign with PQ-only ML-DSA-65.
pub fn validator_sign(
    message: &[u8],
    sk: &ValidatorPqSecretKey,
) -> Result<ValidatorPqSignature, ValidatorVerifyError> {
    let digest = signing_digest(message);

    let pq_sk = sk
        .with_bytes(|bytes| MlDsaSecretKey::from_bytes(bytes))
        .map_err(|_| ValidatorVerifyError::InvalidPqSecretKey)?;
    // Phase 2c-B D5c: domain separation is handled by signing_digest()
    // which includes DOMAIN_TAG in the hash. No additional domain prefix needed.
    let pq_sig =
        ml_dsa_sign_raw(&pq_sk, &digest).map_err(|_| ValidatorVerifyError::InvalidPqSecretKey)?;

    Ok(ValidatorPqSignature {
        pq_sig: pq_sig.as_bytes().to_vec(),
    })
}

/// Verify PQ-only ML-DSA-65 validator signature.
pub fn validator_verify(
    message: &[u8],
    sig: &ValidatorPqSignature,
    pk: &ValidatorPqPublicKey,
) -> Result<(), ValidatorVerifyError> {
    let digest = signing_digest(message);

    let pq_pk = MlDsaPublicKey::from_bytes(&pk.pq_pk)
        .map_err(|_| ValidatorVerifyError::InvalidPqPublicKey)?;
    let pq_sig = MlDsaSignature::from_bytes(&sig.pq_sig)
        .map_err(|_| ValidatorVerifyError::InvalidPqSignature)?;
    ml_dsa_verify_raw(&pq_pk, &digest, &pq_sig).map_err(|_| ValidatorVerifyError::MlDsaFailed)?;

    Ok(())
}

/// Validator verification error — PQ-only.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ValidatorVerifyError {
    #[error("invalid ML-DSA public key")]
    InvalidPqPublicKey,
    #[error("invalid ML-DSA secret key")]
    InvalidPqSecretKey,
    #[error("invalid ML-DSA signature format")]
    InvalidPqSignature,
    #[error("ML-DSA signature verification failed")]
    MlDsaFailed,
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_and_sign_verify() {
        let kp = generate_validator_keypair();
        let msg = b"MISAKA block 42";
        let sig = validator_sign(msg, &kp.secret_key).unwrap();
        validator_verify(msg, &sig, &kp.public_key).expect("valid PQ sig");
    }

    #[test]
    fn test_tampered_message_fails() {
        let kp = generate_validator_keypair();
        let sig = validator_sign(b"correct", &kp.secret_key).unwrap();
        assert!(validator_verify(b"wrong", &sig, &kp.public_key).is_err());
    }

    #[test]
    fn test_corrupted_pq_sig_fails() {
        let kp = generate_validator_keypair();
        let msg = b"test";
        let mut sig = validator_sign(msg, &kp.secret_key).unwrap();
        sig.pq_sig[0] ^= 0xFF;
        let err = validator_verify(msg, &sig, &kp.public_key).unwrap_err();
        assert!(matches!(err, ValidatorVerifyError::MlDsaFailed));
    }

    #[test]
    fn test_wrong_key_fails() {
        let kp1 = generate_validator_keypair();
        let kp2 = generate_validator_keypair();
        let sig = validator_sign(b"test", &kp1.secret_key).unwrap();
        assert!(validator_verify(b"test", &sig, &kp2.public_key).is_err());
    }

    #[test]
    fn test_sig_serialization_roundtrip() {
        let kp = generate_validator_keypair();
        let sig = validator_sign(b"test", &kp.secret_key).unwrap();
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), ValidatorPqSignature::SIZE);
        let sig2 = ValidatorPqSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig, sig2);
        validator_verify(b"test", &sig2, &kp.public_key).unwrap();
    }

    #[test]
    fn test_pk_serialization_roundtrip() {
        let kp = generate_validator_keypair();
        let bytes = kp.public_key.to_bytes();
        assert_eq!(bytes.len(), ValidatorPqPublicKey::SIZE);
        let pk2 = ValidatorPqPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(kp.public_key, pk2);
    }

    #[test]
    fn test_address_derivation() {
        let kp = generate_validator_keypair();
        let addr = kp.public_key.to_canonical_id();
        assert_eq!(addr.len(), 32);
        assert_eq!(kp.public_key.to_canonical_id(), addr); // deterministic
    }

    #[test]
    fn test_short_debug_prefix_does_not_panic() {
        let pk = ValidatorPqPublicKey {
            pq_pk: vec![0xAA, 0xBB, 0xCC],
        };
        let sig = ValidatorPqSignature {
            pq_sig: vec![0x11, 0x22],
        };

        let pk_debug = format!("{:?}", pk);
        let sig_debug = format!("{:?}", sig);

        assert!(pk_debug.contains("ValidatorPqPk("));
        assert!(sig_debug.contains("ValidatorPqSig("));
    }

    #[test]
    fn test_domain_separation() {
        let d1 = signing_digest(b"test");
        let d2 = crate::sha3_256(b"test");
        assert_ne!(d1, d2);
    }
}

// MlDsa65Signer — production block signer.
// Implemented in misaka-node to avoid circular dep (crypto→dag→crypto).
// See narwhal_runtime_bridge.rs for the impl.
