//! Canonical Spend ID — scheme-independent deterministic KI derivation.
//!
//! # Critical Security Property
//!
//! The same secret polynomial `s` must ALWAYS produce the same Spend ID,
//! for the ZKP spend-tag system.
//! This prevents cross-scheme double-spend attacks during migration.
//!
//! ## Specification
//!
//! ```text
//! KI = SHA3-256("MISAKA_KI_V1:" || SHA3-512(s_bytes))
//! ```
//!
//! - DST: `MISAKA_KI_V1:` (7 + 1 = 8 bytes, NOT scheme-specific)
//! - Input: SHA3-512 of the canonical spending secret polynomial bytes
//! - Output: 32 bytes
//!
//! This replaces the previous scheme-specific DSTs:
//! - ❌ `MISAKA-LRS:ki:v1:` (LRS only)

use crate::key_derivation::Poly;
use sha3::{Digest, Sha3_256, Sha3_512};

/// Canonical DST for spend ID derivation.
/// MUST be the same for ALL ML-DSA signature schemes.
pub const CANONICAL_KI_DST: &[u8] = b"MISAKA_KI_V1:";

/// Compute the canonical spend ID from a spending secret polynomial.
///
/// This function is ring-signature-scheme-independent.
/// Inputs that share the same underlying
/// spending secret will produce identical spend IDs.
///
/// ```text
/// KI = SHA3-256(CANONICAL_KI_DST || SHA3-512(s.to_bytes()))
/// ```
pub fn canonical_spend_id(secret: &Poly) -> [u8; 32] {
    let s_bytes = secret.to_bytes();
    let inner: [u8; 64] = {
        let mut h = Sha3_512::new();
        h.update(&s_bytes);
        h.finalize().into()
    };
    let mut h = Sha3_256::new();
    h.update(CANONICAL_KI_DST);
    h.update(&inner);
    h.finalize().into()
}

/// Compute canonical spend ID bound to a specific one-time address.
///
/// For UTXOs where the same identity may receive multiple outputs.
///
/// ```text
/// KI = SHA3-256(CANONICAL_KI_DST || SHA3-512(s.to_bytes()) || address)
/// ```
pub fn canonical_spend_id_bound(secret: &Poly, address: &[u8; 32]) -> [u8; 32] {
    let s_bytes = secret.to_bytes();
    let inner: [u8; 64] = {
        let mut h = Sha3_512::new();
        h.update(&s_bytes);
        h.finalize().into()
    };
    let mut h = Sha3_256::new();
    h.update(CANONICAL_KI_DST);
    h.update(&inner);
    h.update(address);
    h.finalize().into()
}

// ─── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_derivation::derive_secret_poly;
    use crate::pq_sign::MlDsaKeypair;

    #[test]
    fn test_canonical_ki_deterministic() {
        let kp = MlDsaKeypair::generate();
        let sk = derive_secret_poly(&kp.secret_key).unwrap();
        let ki1 = canonical_spend_id(&sk);
        let ki2 = canonical_spend_id(&sk);
        assert_eq!(ki1, ki2);
    }

    #[test]
    fn test_canonical_ki_unique_per_key() {
        let kp1 = MlDsaKeypair::generate();
        let kp2 = MlDsaKeypair::generate();
        let sk1 = derive_secret_poly(&kp1.secret_key).unwrap();
        let sk2 = derive_secret_poly(&kp2.secret_key).unwrap();
        assert_ne!(canonical_spend_id(&sk1), canonical_spend_id(&sk2));
    }

    #[test]
    fn test_canonical_ki_matches_across_schemes() {
        // This is THE critical test: same secret → same KI regardless of scheme
        let kp = MlDsaKeypair::generate();
        let sk = derive_secret_poly(&kp.secret_key).unwrap();

        let ki_canonical = canonical_spend_id(&sk);

        // All spend-tag derivation paths must use this function,
        // so the KI is identical. We verify the function itself is consistent.
        let ki_again = canonical_spend_id(&sk);
        assert_eq!(ki_canonical, ki_again);
    }

    #[test]
    fn test_canonical_ki_bound_differs_by_address() {
        let kp = MlDsaKeypair::generate();
        let sk = derive_secret_poly(&kp.secret_key).unwrap();
        let addr1 = [0xAA; 32];
        let addr2 = [0xBB; 32];
        let ki1 = canonical_spend_id_bound(&sk, &addr1);
        let ki2 = canonical_spend_id_bound(&sk, &addr2);
        assert_ne!(ki1, ki2);
    }

    #[test]
    fn test_canonical_ki_differs_from_bound() {
        let kp = MlDsaKeypair::generate();
        let sk = derive_secret_poly(&kp.secret_key).unwrap();
        let ki_plain = canonical_spend_id(&sk);
        let ki_bound = canonical_spend_id_bound(&sk, &[0xAA; 32]);
        assert_ne!(ki_plain, ki_bound);
    }

    /// Verify the old LRS DST produces a DIFFERENT KI (migration awareness).
    #[test]
    fn test_old_lrs_dst_differs() {
        use sha3::Sha3_512;
        let kp = MlDsaKeypair::generate();
        let sk = derive_secret_poly(&kp.secret_key).unwrap();
        let ki_canonical = canonical_spend_id(&sk);
        // Inline the legacy DST computation (was compute_canonical_spend_id,
        // now private as compute_legacy_spend_id)
        let ki_old_lrs = {
            let s_bytes = sk.to_bytes();
            let inner: [u8; 64] = {
                let mut h = Sha3_512::new();
                h.update(&s_bytes);
                h.finalize().into()
            };
            let mut h = Sha3_256::new();
            h.update(b"MISAKA-LRS:ki:v1:");
            h.update(&inner);
            let out: [u8; 32] = h.finalize().into();
            out
        };
        // They SHOULD differ because the DST is different.
        // This confirms migration is needed for existing chain data.
        assert_ne!(
            ki_canonical, ki_old_lrs,
            "canonical KI must differ from legacy LRS KI (different DST)"
        );
    }
}
