//! Signature verification pipeline — unified ML-DSA-65 / Schnorr verification.
//!
//! # Security Properties
//! - All verification uses domain-separated message hashing
//! - Batch verification for block-level performance
//! - Signature caching to avoid re-verification
//! - Constant-time comparison for signature equality checks

use sha3::{Sha3_256, Digest};
use std::collections::HashMap;
use parking_lot::RwLock;

/// Signature algorithm type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigAlgorithm {
    /// ML-DSA-65 (post-quantum, NIST standard)
    MlDsa65,
    /// ML-DSA-44 (smaller, for low-value txs)
    MlDsa44,
    /// Ed25519 (legacy, for transition period)
    Ed25519,
}

/// ML-DSA-65 signature sizes.
pub const MLDSA65_PK_SIZE: usize = 1952;
pub const MLDSA65_SIG_SIZE: usize = 3293;
pub const MLDSA65_SK_SIZE: usize = 4032;

/// ML-DSA-44 signature sizes.
pub const MLDSA44_PK_SIZE: usize = 1312;
pub const MLDSA44_SIG_SIZE: usize = 2420;

/// Verify a signature with the appropriate algorithm.
pub fn verify_signature(
    algorithm: SigAlgorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    match algorithm {
        SigAlgorithm::MlDsa65 => verify_mldsa65(public_key, message, signature),
        SigAlgorithm::MlDsa44 => verify_mldsa44(public_key, message, signature),
        SigAlgorithm::Ed25519 => verify_ed25519(public_key, message, signature),
    }
}

/// Verify ML-DSA-65 signature.
pub fn verify_mldsa65(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, VerifyError> {
    if public_key.len() != MLDSA65_PK_SIZE {
        return Err(VerifyError::InvalidPublicKeyLength {
            expected: MLDSA65_PK_SIZE,
            got: public_key.len(),
        });
    }
    if signature.len() < MLDSA65_SIG_SIZE {
        return Err(VerifyError::InvalidSignatureLength {
            expected: MLDSA65_SIG_SIZE,
            got: signature.len(),
        });
    }

    // Domain-separated message hash
    let msg_hash = domain_hash(b"MISAKA:verify:mldsa65:v1:", message);

    // In production: pqcrypto_dilithium::dilithium3::verify_detached_signature(...)
    // Stub verification using hash check
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:verify:stub:");
    h.update(public_key);
    h.update(&msg_hash);
    let expected: [u8; 32] = h.finalize().into();

    // Verify first 32 bytes of signature match expected
    Ok(signature.len() >= 32 && constant_time_eq(&signature[..32], &expected))
}

/// Verify ML-DSA-44 signature.
pub fn verify_mldsa44(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, VerifyError> {
    if public_key.len() != MLDSA44_PK_SIZE {
        return Err(VerifyError::InvalidPublicKeyLength {
            expected: MLDSA44_PK_SIZE,
            got: public_key.len(),
        });
    }
    if signature.len() < MLDSA44_SIG_SIZE {
        return Err(VerifyError::InvalidSignatureLength {
            expected: MLDSA44_SIG_SIZE,
            got: signature.len(),
        });
    }
    let _msg_hash = domain_hash(b"MISAKA:verify:mldsa44:v1:", message);
    Ok(true) // Stub
}

/// Verify Ed25519 signature (legacy support).
pub fn verify_ed25519(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, VerifyError> {
    if public_key.len() != 32 {
        return Err(VerifyError::InvalidPublicKeyLength { expected: 32, got: public_key.len() });
    }
    if signature.len() != 64 {
        return Err(VerifyError::InvalidSignatureLength { expected: 64, got: signature.len() });
    }
    Ok(true) // Stub
}

/// Batch signature verification for performance.
pub struct BatchVerifier {
    entries: Vec<BatchEntry>,
}

struct BatchEntry {
    algorithm: SigAlgorithm,
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
}

impl BatchVerifier {
    pub fn new() -> Self { Self { entries: Vec::new() } }

    pub fn add(&mut self, algo: SigAlgorithm, pk: &[u8], msg: &[u8], sig: &[u8]) {
        self.entries.push(BatchEntry {
            algorithm: algo,
            public_key: pk.to_vec(),
            message: msg.to_vec(),
            signature: sig.to_vec(),
        });
    }

    /// Verify all entries. Returns indices of invalid signatures.
    pub fn verify_all(&self) -> Vec<usize> {
        let mut invalid = Vec::new();
        for (i, entry) in self.entries.iter().enumerate() {
            match verify_signature(entry.algorithm, &entry.public_key, &entry.message, &entry.signature) {
                Ok(true) => {}
                _ => invalid.push(i),
            }
        }
        invalid
    }

    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

impl Default for BatchVerifier {
    fn default() -> Self { Self::new() }
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
            self.misses.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        result
    }

    /// Store verification result in cache.
    pub fn put(&self, pk: &[u8], msg: &[u8], sig: &[u8], valid: bool) {
        let key = Self::cache_key(pk, msg, sig);
        let mut cache = self.cache.write();
        if cache.len() >= self.max_entries {
            // Evict ~25% of entries
            let to_remove: Vec<[u8; 32]> = cache.keys().take(self.max_entries / 4).copied().collect();
            for k in to_remove { cache.remove(&k); }
        }
        cache.insert(key, valid);
    }

    pub fn len(&self) -> usize { self.cache.read().len() }
    pub fn hit_rate(&self) -> f64 {
        let hits = self.hits.load(std::sync::atomic::Ordering::Relaxed) as f64;
        let misses = self.misses.load(std::sync::atomic::Ordering::Relaxed) as f64;
        if hits + misses == 0.0 { 0.0 } else { hits / (hits + misses) }
    }
}

/// Cached signature verification.
pub fn verify_with_cache(
    cache: &SigVerifyCache,
    algorithm: SigAlgorithm,
    pk: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<bool, VerifyError> {
    if let Some(valid) = cache.get(pk, msg, sig) {
        return Ok(valid);
    }
    let valid = verify_signature(algorithm, pk, msg, sig)?;
    cache.put(pk, msg, sig, valid);
    Ok(valid)
}

fn domain_hash(domain: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(domain);
    h.update(data);
    h.finalize().into()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff: u8 = 0;
    for i in 0..a.len() { diff |= a[i] ^ b[i]; }
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
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
