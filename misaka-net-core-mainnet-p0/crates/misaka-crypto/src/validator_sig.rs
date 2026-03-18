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
    MlDsaKeypair, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
    ml_dsa_sign_raw, ml_dsa_verify_raw,
    ML_DSA_PK_LEN, ML_DSA_SIG_LEN,
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

    pub fn to_bytes(&self) -> Vec<u8> {
        self.pq_pk.clone()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() != ML_DSA_PK_LEN {
            return Err("invalid PQ validator pk length (expected 1952)");
        }
        Ok(Self { pq_pk: data.to_vec() })
    }

    /// Derive a 20-byte validator address from the PQ public key.
    pub fn to_address(&self) -> [u8; 20] {
        let hash = crate::sha3_256(&self.pq_pk);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[..20]);
        addr
    }
}

impl std::fmt::Debug for ValidatorPqPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ValidatorPqPk({}..)", hex::encode(&self.pq_pk[..8]))
    }
}

/// PQ-only validator secret key. Zeroized on drop.
pub struct ValidatorPqSecretKey {
    pub pq_sk: Vec<u8>, // 4032 bytes
}

impl Drop for ValidatorPqSecretKey {
    fn drop(&mut self) {
        for b in self.pq_sk.iter_mut() { *b = 0; }
    }
}

impl Clone for ValidatorPqSecretKey {
    fn clone(&self) -> Self {
        Self { pq_sk: self.pq_sk.clone() }
    }
}

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
        Ok(Self { pq_sig: data.to_vec() })
    }
}

impl std::fmt::Debug for ValidatorPqSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ValidatorPqSig({}..)", hex::encode(&self.pq_sig[..8]))
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
        secret_key: ValidatorPqSecretKey {
            pq_sk: pq_kp.secret_key.as_bytes().to_vec(),
        },
    }
}

/// Sign with PQ-only ML-DSA-65.
pub fn validator_sign(message: &[u8], sk: &ValidatorPqSecretKey) -> Result<ValidatorPqSignature, ValidatorVerifyError> {
    let digest = signing_digest(message);

    let pq_sk = MlDsaSecretKey::from_bytes(&sk.pq_sk)
        .map_err(|_| ValidatorVerifyError::InvalidPqSecretKey)?;
    let pq_sig = ml_dsa_sign_raw(&pq_sk, &digest);

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
    ml_dsa_verify_raw(&pq_pk, &digest, &pq_sig)
        .map_err(|_| ValidatorVerifyError::MlDsaFailed)?;

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
        let addr = kp.public_key.to_address();
        assert_eq!(addr.len(), 20);
        assert_eq!(kp.public_key.to_address(), addr); // deterministic
    }

    #[test]
    fn test_domain_separation() {
        let d1 = signing_digest(b"test");
        let d2 = crate::sha3_256(b"test");
        assert_ne!(d1, d2);
    }
}
