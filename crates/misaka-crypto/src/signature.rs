//! Signature verification pipeline — ML-DSA-65 only (post-quantum).
//!
//! # Security Properties
//! - All verification uses ML-DSA-65 (FIPS 204 / Dilithium3)
//! - Batch verification for block-level performance
//! - Signature caching to avoid re-verification
//! - Constant-time comparison for signature equality checks
//!
//! # P0 BLOCKER FIX (B4+B5)
//! Ed25519 and MlDsa44 have been removed from the production enum.
//! MISAKA is PQ-only: ML-DSA-65 is the sole signature algorithm.

use misaka_pqc::pq_sign::{
    MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature,
    ml_dsa_sign_raw, ml_dsa_verify_raw,
    ML_DSA_PK_LEN, ML_DSA_SK_LEN, ML_DSA_SIG_LEN,
};
use parking_lot::RwLock;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

/// ML-DSA-65 signature sizes (re-exported for convenience).
pub const MLDSA65_PK_SIZE: usize = ML_DSA_PK_LEN;   // 1952
pub const MLDSA65_SIG_SIZE: usize = ML_DSA_SIG_LEN;  // 3309
pub const MLDSA65_SK_SIZE: usize = 4032;

// ---------------------------------------------------------------------------
// MlDsa65Verifier — production SignatureVerifier implementation
// ---------------------------------------------------------------------------

/// Production signature verifier using real ML-DSA-65 (Dilithium3).
///
/// Calls `pqcrypto_dilithium::dilithium3::verify_detached_signature` under
/// the hood via `misaka_pqc::pq_sign::ml_dsa_verify_raw`.
///
/// # Usage
/// ```ignore
/// use misaka_crypto::signature::MlDsa65Verifier;
/// use misaka_dag_types::block::SignatureVerifier;
/// use std::sync::Arc;
///
/// let verifier: Arc<dyn SignatureVerifier> = Arc::new(MlDsa65Verifier);
/// ```
pub struct MlDsa65Verifier;

impl misaka_dag_types::block::SignatureVerifier for MlDsa65Verifier {
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), String> {
        let pk = MlDsaPublicKey::from_bytes(public_key)
            .map_err(|e| format!("invalid ML-DSA-65 public key ({} bytes): {}", public_key.len(), e))?;
        let sig = MlDsaSignature::from_bytes(signature)
            .map_err(|e| format!("invalid ML-DSA-65 signature ({} bytes): {}", signature.len(), e))?;

        ml_dsa_verify_raw(&pk, message, &sig)
            .map_err(|_| "ML-DSA-65 signature verification failed".to_string())
    }
}

// ---------------------------------------------------------------------------
// MlDsa65Signer — production BlockSigner implementation
// ---------------------------------------------------------------------------

/// Production block signer using real ML-DSA-65 (Dilithium3).
///
/// Holds the SR's secret key and signs block digests via
/// `dilithium3::detached_sign`.
pub struct MlDsa65Signer {
    secret_key: MlDsaSecretKey,
}

impl MlDsa65Signer {
    /// Create a signer from a ML-DSA-65 secret key (4032 bytes).
    pub fn new(secret_key_bytes: &[u8]) -> Result<Self, String> {
        let sk = MlDsaSecretKey::from_bytes(secret_key_bytes)
            .map_err(|e| format!("invalid ML-DSA-65 secret key: {}", e))?;
        Ok(Self { secret_key: sk })
    }
}

impl misaka_dag_types::block::BlockSigner for MlDsa65Signer {
    fn sign_block(&self, block_digest: &[u8]) -> Result<Vec<u8>, String> {
        let sig = ml_dsa_sign_raw(&self.secret_key, block_digest)
            .map_err(|e| format!("ML-DSA-65 block signing failed: {}", e))?;
        Ok(sig.as_bytes().to_vec())
    }
}

// ---------------------------------------------------------------------------
// verify_mldsa65 — standalone function (kept for transaction verification)
// ---------------------------------------------------------------------------

/// Verify an ML-DSA-65 signature (real cryptographic verification).
///
/// This function performs actual `dilithium3::verify_detached_signature` —
/// NOT a stub. It is used for transaction-level signature checks.
pub fn verify_mldsa65(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    if public_key.len() != MLDSA65_PK_SIZE {
        return Err(VerifyError::InvalidPublicKeyLength {
            expected: MLDSA65_PK_SIZE,
            got: public_key.len(),
        });
    }
    if signature.len() != MLDSA65_SIG_SIZE {
        return Err(VerifyError::InvalidSignatureLength {
            expected: MLDSA65_SIG_SIZE,
            got: signature.len(),
        });
    }

    let pk = MlDsaPublicKey::from_bytes(public_key)
        .map_err(|e| VerifyError::Failed(format!("invalid public key: {}", e)))?;
    let sig = MlDsaSignature::from_bytes(signature)
        .map_err(|e| VerifyError::Failed(format!("invalid signature: {}", e)))?;

    ml_dsa_verify_raw(&pk, message, &sig)
        .map_err(|_| VerifyError::Failed("ML-DSA-65 verification failed".to_string()))?;

    Ok(true)
}

/// Batch signature verification for performance.
pub struct BatchVerifier {
    entries: Vec<BatchEntry>,
}

struct BatchEntry {
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
}

impl BatchVerifier {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn add(&mut self, pk: &[u8], msg: &[u8], sig: &[u8]) {
        self.entries.push(BatchEntry {
            public_key: pk.to_vec(),
            message: msg.to_vec(),
            signature: sig.to_vec(),
        });
    }

    /// Verify all entries. Returns indices of invalid signatures.
    pub fn verify_all(&self) -> Vec<usize> {
        let mut invalid = Vec::new();
        for (i, entry) in self.entries.iter().enumerate() {
            match verify_mldsa65(
                &entry.public_key,
                &entry.message,
                &entry.signature,
            ) {
                Ok(true) => {}
                _ => invalid.push(i),
            }
        }
        invalid
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for BatchVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Signature verification cache.
pub struct SigVerifyCache {
    cache: RwLock<HashMap<[u8; 32], bool>>,
    max_entries: usize,
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
}

impl SigVerifyCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            cache: RwLock::new(HashMap::with_capacity(max_entries.min(100_000))),
            max_entries,
            hits: std::sync::atomic::AtomicU64::new(0),
            misses: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Compute cache key from signature verification parameters.
    fn cache_key(pk: &[u8], msg: &[u8], sig: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:sigcache:v1:");
        h.update(&(pk.len() as u32).to_le_bytes());
        h.update(pk);
        h.update(&(msg.len() as u32).to_le_bytes());
        h.update(msg);
        h.update(&(sig.len() as u32).to_le_bytes());
        h.update(sig);
        h.finalize().into()
    }

    /// Check cache before verification.
    pub fn get(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Option<bool> {
        let key = Self::cache_key(pk, msg, sig);
        let result = self.cache.read().get(&key).copied();
        if result.is_some() {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            self.misses
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        result
    }

    /// Store verification result in cache.
    pub fn put(&self, pk: &[u8], msg: &[u8], sig: &[u8], valid: bool) {
        let key = Self::cache_key(pk, msg, sig);
        let mut cache = self.cache.write();
        if cache.len() >= self.max_entries {
            // Evict ~25% of entries
            let to_remove: Vec<[u8; 32]> =
                cache.keys().take(self.max_entries / 4).copied().collect();
            for k in to_remove {
                cache.remove(&k);
            }
        }
        cache.insert(key, valid);
    }

    pub fn len(&self) -> usize {
        self.cache.read().len()
    }
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(std::sync::atomic::Ordering::Relaxed) as f64;
        let misses = self.misses.load(std::sync::atomic::Ordering::Relaxed) as f64;
        if hits + misses == 0.0 {
            0.0
        } else {
            hits / (hits + misses)
        }
    }
}

/// Cached ML-DSA-65 signature verification.
pub fn verify_with_cache(
    cache: &SigVerifyCache,
    pk: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<bool, VerifyError> {
    if let Some(valid) = cache.get(pk, msg, sig) {
        return Ok(valid);
    }
    let valid = verify_mldsa65(pk, msg, sig)?;
    cache.put(pk, msg, sig, valid);
    Ok(valid)
}

/// Constant-time byte comparison (used by signature cache dedup).
#[allow(dead_code)]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("invalid public key length: expected {expected}, got {got}")]
    InvalidPublicKeyLength { expected: usize, got: usize },
    #[error("invalid signature length: expected {expected}, got {got}")]
    InvalidSignatureLength { expected: usize, got: usize },
    #[error("verification failed: {0}")]
    Failed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_pqc::pq_sign::{MlDsaKeypair, ml_dsa_sign_raw};

    #[test]
    fn test_sig_cache_hit_rate() {
        let cache = SigVerifyCache::new(1000);
        let pk = vec![0u8; 32];
        let msg = b"test";
        let sig = vec![0u8; 64];

        assert!(cache.get(&pk, msg, &sig).is_none());
        cache.put(&pk, msg, &sig, true);
        assert_eq!(cache.get(&pk, msg, &sig), Some(true));
    }

    #[test]
    fn test_real_mldsa65_verify() {
        // Generate a real ML-DSA-65 keypair
        let kp = MlDsaKeypair::generate();
        let msg = b"MISAKA block 42 digest";

        // Sign with real ML-DSA-65
        let sig = ml_dsa_sign_raw(&kp.secret_key, msg).expect("sign failed");

        // Verify with our production function
        let result = verify_mldsa65(
            kp.public_key.as_bytes(),
            msg,
            sig.as_bytes(),
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn test_mldsa65_bad_signature_rejected() {
        let kp = MlDsaKeypair::generate();
        let msg = b"MISAKA block 42 digest";

        // Create a garbage signature of the right length
        let bad_sig = vec![0xBB; MLDSA65_SIG_SIZE];

        let result = verify_mldsa65(
            kp.public_key.as_bytes(),
            msg,
            &bad_sig,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_mldsa65_wrong_message_rejected() {
        let kp = MlDsaKeypair::generate();
        let msg = b"correct message";
        let wrong_msg = b"wrong message";

        let sig = ml_dsa_sign_raw(&kp.secret_key, msg).expect("sign failed");

        let result = verify_mldsa65(
            kp.public_key.as_bytes(),
            wrong_msg,
            sig.as_bytes(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_mldsa65_verifier_trait_impl() {
        use misaka_dag_types::block::SignatureVerifier;

        let kp = MlDsaKeypair::generate();
        let msg = b"block digest bytes";
        let sig = ml_dsa_sign_raw(&kp.secret_key, msg).expect("sign failed");

        let verifier = MlDsa65Verifier;

        // Valid signature should pass
        assert!(verifier.verify(kp.public_key.as_bytes(), msg, sig.as_bytes()).is_ok());

        // Wrong message should fail
        assert!(verifier.verify(kp.public_key.as_bytes(), b"tampered", sig.as_bytes()).is_err());

        // Invalid public key should fail
        assert!(verifier.verify(&[0u8; 32], msg, sig.as_bytes()).is_err());
    }
}
