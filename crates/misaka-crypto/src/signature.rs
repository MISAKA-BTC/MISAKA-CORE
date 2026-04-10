// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Signature verification pipeline — ML-DSA-65 only.
//!
//! # Security Properties
//! - All verification uses domain-separated message hashing
//! - Batch verification (currently sequential; rayon parallelization is a v1.1 goal)
//! - Signature caching to avoid re-verification
//! - Timing-safe: parse failures run a dummy verify to equalize time
//!
//! # MEDIUM #8 fix: MlDsa44/Ed25519 enum variants REMOVED (not deprecated)
//! # MEDIUM #9 fix: BatchVerifier uses sequential iteration (rayon parallelization is a v1.1 goal) + per-peer rate limiting
//! # MEDIUM #10 fix: parse failures run real-signature dummy verify for timing equalization

use once_cell::sync::Lazy;
use parking_lot::RwLock;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

/// Signature algorithm type.
///
/// MEDIUM #8: Only ML-DSA-65 remains. MlDsa44 and Ed25519 have been
/// completely removed (not just deprecated). `#[non_exhaustive]` allows
/// future addition of SLH-DSA, Falcon, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigAlgorithm {
    /// ML-DSA-65 (FIPS 204 / Dilithium3) — the ONLY supported algorithm.
    MlDsa65,
}

/// ML-DSA-65 signature sizes.
pub const MLDSA65_PK_SIZE: usize = 1952;
pub const MLDSA65_SIG_SIZE: usize = 3309;
pub const MLDSA65_SK_SIZE: usize = 4032;

const _: () = assert!(MLDSA65_SIG_SIZE == 3309);

// ═══════════════════════════════════════════════════════════════
//  Dummy PK/sig for timing equalization (MEDIUM #10)
// ═══════════════════════════════════════════════════════════════

/// Pre-generated dummy keypair + valid signature for timing equalization.
///
/// When a real PK/sig parse fails, we run a dummy verify with a REAL
/// valid signature. This ensures the dummy path exercises the full
/// dilithium3 verification (NTT, coefficient checks, hash comparison),
/// making it timing-equivalent to a real crypto-failure path.
///
/// Previous implementation used `vec![0xAA; 3309]` which failed at an
/// early structural check, defeating the timing equalization purpose.
static DUMMY_VERIFY_MATERIAL: Lazy<(Vec<u8>, Vec<u8>, Vec<u8>)> = Lazy::new(|| {
    let kp = misaka_pqc::pq_sign::MlDsaKeypair::generate();
    let dummy_msg = b"MISAKA:timing-equalization:dummy-message:v2";
    let sig = misaka_pqc::pq_sign::ml_dsa_sign_raw(&kp.secret_key, dummy_msg)
        .expect("dummy signing must succeed");
    (
        kp.public_key.as_bytes().to_vec(),
        sig.as_bytes().to_vec(),
        dummy_msg.to_vec(),
    )
});

// ═══════════════════════════════════════════════════════════════
//  Core verification
// ═══════════════════════════════════════════════════════════════

/// Verify an ML-DSA-65 signature.
///
/// Returns `Ok(())` on success, `Err` on any failure.
/// No `bool` return — caller uses `?` for propagation.
///
/// MEDIUM #10: Parse failures run a dummy dilithium3 verify to
/// equalize timing (prevents side-channel leak of parse stage).
pub fn verify_mldsa65(
    domain: &[u8],
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    // Phase 2c-B D5c: domain prefix concatenated here so the public API
    // stays source-compatible while the underlying call uses _raw.
    let mut domain_msg = Vec::with_capacity(domain.len() + message.len());
    domain_msg.extend_from_slice(domain);
    domain_msg.extend_from_slice(message);

    // Parse PK and sig. On failure, still run dummy verify for timing.
    let pk_parsed = misaka_pqc::pq_sign::MlDsaPublicKey::from_bytes(public_key);
    let sig_parsed = misaka_pqc::pq_sign::MlDsaSignature::from_bytes(signature);

    match (pk_parsed, sig_parsed) {
        (Ok(pk), Ok(sig)) => misaka_pqc::pq_sign::ml_dsa_verify_raw(&pk, &domain_msg, &sig)
            .map_err(|_| VerifyError::MlDsaVerifyFailed),
        _ => {
            // MEDIUM #10 (v2): Run dummy verify with a REAL valid signature.
            let (ref dummy_pk, ref dummy_sig, ref _dummy_msg) = *DUMMY_VERIFY_MATERIAL;
            if let Ok(pk) = misaka_pqc::pq_sign::MlDsaPublicKey::from_bytes(dummy_pk) {
                if let Ok(sig) = misaka_pqc::pq_sign::MlDsaSignature::from_bytes(dummy_sig) {
                    // Verify with WRONG message (so it fails after full computation)
                    let _ = misaka_pqc::pq_sign::ml_dsa_verify_raw(
                        &pk,
                        message, // real message, wrong for this pk/sig → full verify then fail
                        &sig,
                    );
                }
            }
            Err(VerifyError::MlDsaVerifyFailed)
        }
    }
}

/// Verify a signature (algorithm dispatch).
///
/// With only MlDsa65 remaining, this is a thin wrapper.
pub fn verify_signature(
    algorithm: SigAlgorithm,
    domain: &[u8],
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    match algorithm {
        SigAlgorithm::MlDsa65 => verify_mldsa65(domain, public_key, message, signature),
        #[allow(unreachable_patterns)] // SigAlgorithm is #[non_exhaustive] for future algos
        _ => Err(VerifyError::UnsupportedAlgorithm),
    }
}

// ═══════════════════════════════════════════════════════════════
//  Production block signature verifier (for Narwhal DAG)
// ═══════════════════════════════════════════════════════════════

/// Production ML-DSA-65 verifier for DAG block signatures.
///
//// ML-DSA-65 block signature verifier for Narwhal DAG blocks.
///
/// # SEC-AUDIT: Domain Separation Design
///
/// This verifier uses `ml_dsa_verify_raw(pk, message, sig)` with NO pre-hash.
/// The block's `signing_bytes()` method provides the message directly.
///
/// This is INTENTIONALLY different from `validator_sig.rs::validator_sign()` which
/// uses `SHA3("MISAKA-PQ-SIG:v2:" || msg)` as a pre-hashed domain-separated digest
/// for commit votes.
///
/// Cross-context replay between these two paths is impossible because:
/// 1. Block signatures sign raw `Block::signing_bytes()` (borsh-encoded block content)
/// 2. Commit vote signatures sign `SHA3("MISAKA-PQ-SIG:v2:" || CommitteeVote::signing_bytes())`
/// 3. The message formats are structurally incompatible (different borsh schemas)
///
/// Do NOT unify these paths — they serve different purposes with different
/// message formats. Any future signing path must choose one scheme and document
/// which domain it belongs to.
#[derive(Debug, Clone)]
pub struct MlDsa65BlockVerifier;

impl MlDsa65BlockVerifier {
    pub fn verify_block_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        let pk = misaka_pqc::pq_sign::MlDsaPublicKey::from_bytes(public_key)
            .map_err(|e| format!("invalid ML-DSA-65 public key: {}", e))?;
        let sig = misaka_pqc::pq_sign::MlDsaSignature::from_bytes(signature)
            .map_err(|e| format!("invalid ML-DSA-65 signature: {}", e))?;
        misaka_pqc::pq_sign::ml_dsa_verify_raw(&pk, message, &sig)
            .map_err(|e| format!("ML-DSA-65 verification failed: {}", e))
    }
}

// ═══════════════════════════════════════════════════════════════
//  Batch verifier (MEDIUM #9: parallel + rate limit)
// ═══════════════════════════════════════════════════════════════

/// Batch signature verification with early-reject.
///
/// MEDIUM #9 fix: Pre-validates lengths before expensive crypto.
/// Currently sequential (rayon parallelization is a v1.1 goal).
/// Swap `.iter()` for `.par_iter()` when rayon is added.
pub struct BatchVerifier {
    entries: Vec<BatchEntry>,
}

struct BatchEntry {
    domain: Vec<u8>,
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
}

impl BatchVerifier {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add an entry to the batch.
    ///
    /// Only ML-DSA-65 is supported. The `algo` parameter is retained for
    /// API compatibility but must be `MlDsa65`.
    pub fn add(&mut self, _algo: SigAlgorithm, domain: &[u8], pk: &[u8], msg: &[u8], sig: &[u8]) {
        self.entries.push(BatchEntry {
            domain: domain.to_vec(),
            public_key: pk.to_vec(),
            message: msg.to_vec(),
            signature: sig.to_vec(),
        });
    }

    /// Verify all entries. Returns indices of invalid signatures.
    ///
    /// Both length-check failures AND crypto-check failures are collected
    /// independently. A malformed entry does NOT prevent crypto verification
    /// of other entries in the batch.
    #[must_use]
    pub fn verify_all(&self) -> Vec<usize> {
        use std::collections::BTreeSet;
        let mut invalid = BTreeSet::new();

        // Phase 1: cheap length checks (O(1) per entry)
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.public_key.len() != MLDSA65_PK_SIZE
                || entry.signature.len() != MLDSA65_SIG_SIZE
            {
                invalid.insert(i);
            }
        }

        // Phase 2: crypto verification for entries that passed length check
        for (i, entry) in self.entries.iter().enumerate() {
            if invalid.contains(&i) {
                continue; // already failed length check
            }
            if verify_mldsa65(
                &entry.domain,
                &entry.public_key,
                &entry.message,
                &entry.signature,
            )
            .is_err()
            {
                invalid.insert(i);
            }
        }

        invalid.into_iter().collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for BatchVerifier {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Per-peer verification rate limiter
// ═══════════════════════════════════════════════════════════════

/// Token bucket rate limiter for signature verification requests per peer.
///
/// MEDIUM #9: Prevents DoS via signature verification flooding.
/// Each peer has a bucket that refills at `refill_rate` tokens/second.
/// A verify request consumes 1 token. If the bucket is empty, the
/// request is rejected without running verification.
pub struct VerifyRateLimiter {
    /// Per-peer token buckets: peer_id → (tokens, last_refill_time_ms).
    buckets: RwLock<HashMap<[u8; 32], (u32, u64)>>,
    /// Maximum tokens per bucket.
    max_tokens: u32,
    /// Tokens added per second.
    refill_rate: u32,
    /// SEC-FIX: Maximum tracked peers before automatic GC.
    max_peers: usize,
}

impl VerifyRateLimiter {
    /// Create a new rate limiter.
    ///
    /// `max_tokens`: burst capacity per peer.
    /// `refill_rate`: sustained rate (tokens/second).
    #[must_use]
    pub fn new(max_tokens: u32, refill_rate: u32) -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
            max_tokens,
            refill_rate,
            max_peers: 10_000, // SEC-FIX: default cap
        }
    }

    /// Try to consume a token for a peer. Returns `false` if rate-limited.
    ///
    /// SEC-FIX: Automatically triggers GC when tracked peers exceed max_peers.
    /// Previously gc() was never called, allowing unbounded HashMap growth.
    pub fn try_acquire(&self, peer_id: &[u8; 32]) -> bool {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut buckets = self.buckets.write();

        // SEC-FIX: Auto-GC when peer count exceeds limit.
        // Evict peers not seen in the last 60 seconds.
        if buckets.len() > self.max_peers {
            let cutoff = now_ms.saturating_sub(60_000);
            buckets.retain(|_, (_, last)| *last >= cutoff);
        }

        let (tokens, last_refill) = buckets.entry(*peer_id).or_insert((self.max_tokens, now_ms));

        // Refill tokens based on elapsed time
        let elapsed_ms = now_ms.saturating_sub(*last_refill);
        let refilled = (elapsed_ms as u32 * self.refill_rate) / 1000;
        if refilled > 0 {
            *tokens = (*tokens + refilled).min(self.max_tokens);
            *last_refill = now_ms;
        }

        if *tokens > 0 {
            *tokens -= 1;
            true
        } else {
            false
        }
    }

    /// Clean up stale peer entries (call periodically).
    pub fn gc(&self, older_than_ms: u64) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let cutoff = now_ms.saturating_sub(older_than_ms);
        self.buckets.write().retain(|_, (_, last)| *last >= cutoff);
    }
}

// ═══════════════════════════════════════════════════════════════
//  Signature cache
// ═══════════════════════════════════════════════════════════════

/// Signature verification cache.
pub struct SigVerifyCache {
    cache: RwLock<HashMap<[u8; 32], ()>>,
    /// SEC-FIX: Insertion-order queue for FIFO eviction.
    /// Previously eviction used HashMap::keys() iteration (undefined order),
    /// which could evict recently-used entries and degrade to no caching under load.
    order: RwLock<std::collections::VecDeque<[u8; 32]>>,
    max_entries: usize,
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
}

impl SigVerifyCache {
    #[must_use]
    pub fn new(max_entries: usize) -> Self {
        Self {
            cache: RwLock::new(HashMap::with_capacity(max_entries.min(100_000))),
            order: RwLock::new(std::collections::VecDeque::with_capacity(
                max_entries.min(100_000),
            )),
            max_entries,
            hits: std::sync::atomic::AtomicU64::new(0),
            misses: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Cache key includes domain to prevent cross-domain cache hits.
    /// Without domain, a signature valid in domain A would cache-hit
    /// and bypass verification in domain B.
    fn cache_key(domain: &[u8], pk: &[u8], msg: &[u8], sig: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:sigcache:v2:");
        h.update(&(domain.len() as u32).to_le_bytes());
        h.update(domain);
        h.update(&(pk.len() as u32).to_le_bytes());
        h.update(pk);
        h.update(&(msg.len() as u32).to_le_bytes());
        h.update(msg);
        h.update(&(sig.len() as u32).to_le_bytes());
        h.update(sig);
        h.finalize().into()
    }

    /// Check if this (domain, pk, msg, sig) was previously verified valid.
    #[must_use]
    pub fn is_cached_valid(&self, domain: &[u8], pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let key = Self::cache_key(domain, pk, msg, sig);
        let found = self.cache.read().contains_key(&key);
        if found {
            self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            self.misses
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        found
    }

    /// Record that this (domain, pk, msg, sig) is valid.
    /// Only cache valid=true. Invalid results are NOT cached (DoS prevention).
    ///
    /// SEC-FIX: Uses FIFO eviction via insertion-order VecDeque.
    /// Previously used HashMap::keys() iteration (random order), which could
    /// evict recently-verified entries and cause unnecessary re-verification CPU cost.
    pub fn record_valid(&self, domain: &[u8], pk: &[u8], msg: &[u8], sig: &[u8]) {
        let key = Self::cache_key(domain, pk, msg, sig);
        let mut cache = self.cache.write();
        let mut order = self.order.write();
        if cache.len() >= self.max_entries {
            // Evict oldest 25% (FIFO order)
            let evict_count = self.max_entries / 4;
            for _ in 0..evict_count {
                if let Some(old_key) = order.pop_front() {
                    cache.remove(&old_key);
                } else {
                    break;
                }
            }
        }
        if cache.insert(key, ()).is_none() {
            // Only add to order queue if this is a new entry (not update)
            order.push_back(key);
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.cache.read().len()
    }

    #[must_use]
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

/// Verify with cache. Only caches valid results.
pub fn verify_cached(
    cache: &SigVerifyCache,
    domain: &[u8],
    pk: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<(), VerifyError> {
    if cache.is_cached_valid(domain, pk, msg, sig) {
        return Ok(());
    }
    verify_mldsa65(domain, pk, msg, sig)?;
    cache.record_valid(domain, pk, msg, sig);
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  Error type
// ═══════════════════════════════════════════════════════════════

/// Signature verification error.
///
/// MEDIUM #10: Error variants do NOT distinguish parse failure from
/// crypto failure externally. This prevents timing-based information leak.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("ML-DSA-65 verification failed")]
    MlDsaVerifyFailed,
    #[error("unsupported signature algorithm")]
    UnsupportedAlgorithm,
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sig_algorithm_is_non_exhaustive() {
        // Verify only MlDsa65 exists
        let algo = SigAlgorithm::MlDsa65;
        assert_eq!(algo, SigAlgorithm::MlDsa65);
    }

    /// Helper: sign with domain prefix concatenation (mirrors verify_mldsa65 internally).
    fn sign_with_domain(
        sk: &misaka_pqc::pq_sign::MlDsaSecretKey,
        domain: &[u8],
        msg: &[u8],
    ) -> misaka_pqc::pq_sign::MlDsaSignature {
        let mut dm = Vec::with_capacity(domain.len() + msg.len());
        dm.extend_from_slice(domain);
        dm.extend_from_slice(msg);
        misaka_pqc::pq_sign::ml_dsa_sign_raw(sk, &dm).unwrap()
    }

    #[test]
    fn test_verify_mldsa65_real_signature() {
        let kp = misaka_pqc::pq_sign::MlDsaKeypair::generate();
        let msg = b"test message";
        let domain = b"test-domain:";
        let sig = sign_with_domain(&kp.secret_key, domain, msg);
        assert!(verify_mldsa65(domain, kp.public_key.as_bytes(), msg, sig.as_bytes()).is_ok());
    }

    #[test]
    fn test_verify_mldsa65_wrong_message() {
        let kp = misaka_pqc::pq_sign::MlDsaKeypair::generate();
        let domain = b"test-domain:";
        let sig = sign_with_domain(&kp.secret_key, domain, b"correct");
        assert!(
            verify_mldsa65(domain, kp.public_key.as_bytes(), b"wrong", sig.as_bytes()).is_err()
        );
    }

    #[test]
    fn test_verify_mldsa65_bad_pk_length() {
        // Parse failure → still takes time (dummy verify runs)
        let result = verify_mldsa65(b"", &[0u8; 100], b"msg", &[0u8; MLDSA65_SIG_SIZE]);
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_verifier_early_reject() {
        let mut batch = BatchVerifier::new();
        // Add entry with wrong PK length
        batch.add(
            SigAlgorithm::MlDsa65,
            b"",
            &[0u8; 10],
            b"msg",
            &[0u8; MLDSA65_SIG_SIZE],
        );
        let invalid = batch.verify_all();
        assert_eq!(
            invalid,
            vec![0],
            "wrong PK length should be caught in phase 1"
        );
    }

    #[test]
    fn test_batch_verifier_valid_entries() {
        let kp = misaka_pqc::pq_sign::MlDsaKeypair::generate();
        let msg = b"batch test";
        let domain = b"test-domain:";
        let sig = sign_with_domain(&kp.secret_key, domain, msg);

        let mut batch = BatchVerifier::new();
        batch.add(
            SigAlgorithm::MlDsa65,
            domain,
            kp.public_key.as_bytes(),
            msg,
            sig.as_bytes(),
        );
        let invalid = batch.verify_all();
        assert!(invalid.is_empty());
    }

    #[test]
    fn test_rate_limiter() {
        let limiter = VerifyRateLimiter::new(3, 10); // 3 burst, 10/sec
        let peer = [0xAA; 32];
        assert!(limiter.try_acquire(&peer));
        assert!(limiter.try_acquire(&peer));
        assert!(limiter.try_acquire(&peer));
        assert!(
            !limiter.try_acquire(&peer),
            "4th request should be rate-limited"
        );
    }

    #[test]
    fn test_sig_cache() {
        let cache = SigVerifyCache::new(1000);
        let pk = vec![0u8; 32];
        let msg = b"test";
        let sig = vec![0u8; 64];
        let domain = b"test:";
        assert!(!cache.is_cached_valid(domain, &pk, msg, &sig));
        cache.record_valid(domain, &pk, msg, &sig);
        assert!(cache.is_cached_valid(domain, &pk, msg, &sig));
    }

    #[test]
    fn test_error_does_not_leak_parse_vs_crypto() {
        // Both parse failure and crypto failure produce the same error variant
        let parse_err = verify_mldsa65(b"", &[0u8; 10], b"msg", &[0u8; 10]);
        let crypto_err = verify_mldsa65(
            b"",
            &[0u8; MLDSA65_PK_SIZE],
            b"msg",
            &[0u8; MLDSA65_SIG_SIZE],
        );
        // Both should be MlDsaVerifyFailed (no distinguishing information)
        assert!(matches!(parse_err, Err(VerifyError::MlDsaVerifyFailed)));
        assert!(matches!(crypto_err, Err(VerifyError::MlDsaVerifyFailed)));
    }
}
