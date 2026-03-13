//! Hybrid Signature: Ed25519 + ML-DSA-65.
//!
//! Both signatures MUST verify. Either failing → invalid.

use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier, Signature as EdSig};
use sha3::{Digest as Sha3Digest, Sha3_256};

use misaka_pqc::pq_sign::{
    MlDsaKeypair, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
    ml_dsa_sign_raw, ml_dsa_verify_raw,
    ML_DSA_PK_LEN, ML_DSA_SIG_LEN,
};

const DOMAIN_TAG: &[u8] = b"MISAKA-HYBRID-SIG:v1:";

// ─── Types ───────────────────────────────────────────────────

/// Hybrid public key (Ed25519 + ML-DSA-65).
#[derive(Clone, PartialEq, Eq)]
pub struct HybridPublicKey {
    pub ed25519_pk: [u8; 32],
    pub pq_pk: Vec<u8>, // 1952 bytes
}

impl HybridPublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + self.pq_pk.len());
        buf.extend_from_slice(&self.ed25519_pk);
        buf.extend_from_slice(&self.pq_pk);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() != 32 + ML_DSA_PK_LEN {
            return Err("invalid hybrid pk length");
        }
        let mut ed = [0u8; 32];
        ed.copy_from_slice(&data[..32]);
        Ok(Self { ed25519_pk: ed, pq_pk: data[32..].to_vec() })
    }

    /// Derive a 20-byte address from the hybrid public key.
    pub fn to_address(&self) -> [u8; 20] {
        let hash = crate::sha3_256(&self.to_bytes());
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[..20]);
        addr
    }
}

impl std::fmt::Debug for HybridPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HybridPk(ed={}, pq={}..)",
            hex::encode(&self.ed25519_pk[..4]),
            hex::encode(&self.pq_pk[..4]))
    }
}

/// Hybrid secret key. Zeroized on drop.
pub struct HybridSecretKey {
    pub ed25519_sk: [u8; 32],
    pub pq_sk: Vec<u8>, // 4032 bytes
}

impl Drop for HybridSecretKey {
    fn drop(&mut self) {
        for b in self.ed25519_sk.iter_mut() { *b = 0; }
        for b in self.pq_sk.iter_mut() { *b = 0; }
    }
}

impl Clone for HybridSecretKey {
    fn clone(&self) -> Self {
        Self { ed25519_sk: self.ed25519_sk, pq_sk: self.pq_sk.clone() }
    }
}

impl std::fmt::Debug for HybridSecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HybridSk([REDACTED])")
    }
}

/// Hybrid signature (Ed25519 + ML-DSA-65).
#[derive(Clone, PartialEq, Eq)]
pub struct HybridSignature {
    pub ed25519_sig: [u8; 64],
    pub pq_sig: Vec<u8>, // 3309 bytes
}

impl HybridSignature {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(64 + self.pq_sig.len());
        buf.extend_from_slice(&self.ed25519_sig);
        buf.extend_from_slice(&self.pq_sig);
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() != 64 + ML_DSA_SIG_LEN {
            return Err("invalid hybrid sig length");
        }
        let mut ed = [0u8; 64];
        ed.copy_from_slice(&data[..64]);
        Ok(Self { ed25519_sig: ed, pq_sig: data[64..].to_vec() })
    }

    /// Total byte length.
    pub const SIZE: usize = 64 + ML_DSA_SIG_LEN; // 3373 bytes
}

impl std::fmt::Debug for HybridSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HybridSig(ed={}.., pq={}..)",
            hex::encode(&self.ed25519_sig[..4]),
            hex::encode(&self.pq_sig[..4]))
    }
}

/// Hybrid keypair bundle.
pub struct HybridKeypair {
    pub public_key: HybridPublicKey,
    pub secret_key: HybridSecretKey,
}

// ─── Domain-separated hash ───────────────────────────────────

/// Compute domain-separated signing digest.
/// `SHA3-256("MISAKA-HYBRID-SIG:v1:" || message)`
fn signing_digest(message: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DOMAIN_TAG);
    h.update(message);
    h.finalize().into()
}

// ─── Keygen / Sign / Verify ──────────────────────────────────

/// Generate a hybrid keypair (Ed25519 + ML-DSA-65).
pub fn generate_hybrid_keypair() -> HybridKeypair {
    // Ed25519
    let ed_sk = SigningKey::generate(&mut rand::thread_rng());
    let ed_pk = ed_sk.verifying_key();

    // ML-DSA-65
    let pq_kp = MlDsaKeypair::generate();

    HybridKeypair {
        public_key: HybridPublicKey {
            ed25519_pk: ed_pk.to_bytes(),
            pq_pk: pq_kp.public_key.as_bytes().to_vec(),
        },
        secret_key: HybridSecretKey {
            ed25519_sk: ed_sk.to_bytes(),
            pq_sk: pq_kp.secret_key.as_bytes().to_vec(),
        },
    }
}

/// Sign with hybrid scheme. Both Ed25519 and ML-DSA sign the same digest.
pub fn hybrid_sign(message: &[u8], sk: &HybridSecretKey) -> Result<HybridSignature, HybridVerifyError> {
    let digest = signing_digest(message);

    // Ed25519
    let ed_sk = SigningKey::from_bytes(&sk.ed25519_sk);
    let ed_sig = ed_sk.sign(&digest);

    // ML-DSA-65 (raw — domain separation already in digest)
    let pq_sk = MlDsaSecretKey::from_bytes(&sk.pq_sk)
        .map_err(|_| HybridVerifyError::InvalidPqPublicKey)?;
    let pq_sig = ml_dsa_sign_raw(&pq_sk, &digest);

    Ok(HybridSignature {
        ed25519_sig: ed_sig.to_bytes(),
        pq_sig: pq_sig.as_bytes().to_vec(),
    })
}

/// Verify hybrid signature. **Both** must pass.
pub fn hybrid_verify(
    message: &[u8],
    sig: &HybridSignature,
    pk: &HybridPublicKey,
) -> Result<(), HybridVerifyError> {
    let digest = signing_digest(message);

    // Ed25519 verify
    let ed_pk = VerifyingKey::from_bytes(&pk.ed25519_pk)
        .map_err(|_| HybridVerifyError::InvalidEd25519PublicKey)?;
    let ed_sig = EdSig::from_bytes(&sig.ed25519_sig);
    ed_pk.verify(&digest, &ed_sig)
        .map_err(|_| HybridVerifyError::Ed25519Failed)?;

    // ML-DSA verify
    let pq_pk = MlDsaPublicKey::from_bytes(&pk.pq_pk)
        .map_err(|_| HybridVerifyError::InvalidPqPublicKey)?;
    let pq_sig = MlDsaSignature::from_bytes(&sig.pq_sig)
        .map_err(|_| HybridVerifyError::InvalidPqSignature)?;
    ml_dsa_verify_raw(&pq_pk, &digest, &pq_sig)
        .map_err(|_| HybridVerifyError::MlDsaFailed)?;

    Ok(())
}

/// Hybrid verification error — explicit for debuggability.
#[derive(Debug, Clone, thiserror::Error)]
pub enum HybridVerifyError {
    #[error("invalid Ed25519 public key")]
    InvalidEd25519PublicKey,
    #[error("Ed25519 signature verification failed")]
    Ed25519Failed,
    #[error("invalid ML-DSA public key")]
    InvalidPqPublicKey,
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
        let kp = generate_hybrid_keypair();
        let msg = b"MISAKA block 42";
        let sig = hybrid_sign(msg, &kp.secret_key).unwrap();
        hybrid_verify(msg, &sig, &kp.public_key).expect("valid hybrid sig");
    }

    #[test]
    fn test_tampered_message_fails() {
        let kp = generate_hybrid_keypair();
        let sig = hybrid_sign(b"correct", &kp.secret_key).unwrap();
        assert!(hybrid_verify(b"wrong", &sig, &kp.public_key).is_err());
    }

    #[test]
    fn test_corrupted_ed25519_sig_fails() {
        let kp = generate_hybrid_keypair();
        let msg = b"test";
        let mut sig = hybrid_sign(msg, &kp.secret_key).unwrap();
        sig.ed25519_sig[0] ^= 0xFF;
        let err = hybrid_verify(msg, &sig, &kp.public_key).unwrap_err();
        assert!(matches!(err, HybridVerifyError::Ed25519Failed));
    }

    #[test]
    fn test_corrupted_pq_sig_fails() {
        let kp = generate_hybrid_keypair();
        let msg = b"test";
        let mut sig = hybrid_sign(msg, &kp.secret_key).unwrap();
        sig.pq_sig[0] ^= 0xFF;
        let err = hybrid_verify(msg, &sig, &kp.public_key).unwrap_err();
        assert!(matches!(err, HybridVerifyError::MlDsaFailed));
    }

    #[test]
    fn test_wrong_key_fails() {
        let kp1 = generate_hybrid_keypair();
        let kp2 = generate_hybrid_keypair();
        let sig = hybrid_sign(b"test", &kp1.secret_key).unwrap();
        assert!(hybrid_verify(b"test", &sig, &kp2.public_key).is_err());
    }

    #[test]
    fn test_sig_serialization_roundtrip() {
        let kp = generate_hybrid_keypair();
        let sig = hybrid_sign(b"test", &kp.secret_key).unwrap();
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), HybridSignature::SIZE);
        let sig2 = HybridSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig, sig2);
        hybrid_verify(b"test", &sig2, &kp.public_key).unwrap();
    }

    #[test]
    fn test_pk_serialization_roundtrip() {
        let kp = generate_hybrid_keypair();
        let bytes = kp.public_key.to_bytes();
        let pk2 = HybridPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(kp.public_key, pk2);
    }

    #[test]
    fn test_address_derivation() {
        let kp = generate_hybrid_keypair();
        let addr = kp.public_key.to_address();
        assert_eq!(addr.len(), 20);
        assert_eq!(kp.public_key.to_address(), addr); // deterministic
    }

    #[test]
    fn test_domain_separation() {
        // Same message, different domain → different digest
        let d1 = signing_digest(b"test");
        let d2 = crate::sha3_256(b"test");
        assert_ne!(d1, d2);
    }
}
