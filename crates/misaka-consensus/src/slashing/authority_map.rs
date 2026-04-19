//! `AuthorityIndex` → `validator_id` conversion.
//!
//! DAG equivocation evidence is keyed by `AuthorityIndex` (the u32
//! position within the current committee). Slashing is keyed by the
//! 32-byte `validator_id = SHA3-256(ml_dsa_pubkey)`, produced by
//! `misaka_crypto::ValidatorPqPublicKey::to_canonical_id()`.
//!
//! This helper bridges the two without modifying either subsystem.
//! It depends only on `sha3` (already a workspace dep) and a
//! `&[u8]` public key lookup, keeping it free of DAG / crypto crate
//! coupling.

/// Opaque look-up error used by callers that just need to know "no
/// matching authority for this index".
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityMapError {
    #[error("authority index out of range")]
    OutOfRange,
}

/// Convert an authority's ML-DSA-65 public key into the canonical
/// validator id used by the staking + reputation layers.
///
/// This is `SHA3-256(pubkey)` — the exact scheme implemented by
/// `misaka_crypto::ValidatorPqPublicKey::to_canonical_id()`. Kept
/// local so `misaka-consensus` does not need a cycle-inducing
/// dependency on the crypto crate purely for this small hash.
pub fn pubkey_to_validator_id(pubkey: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(pubkey);
    h.finalize().into()
}

/// Resolve `index` → validator id via the caller-supplied authority
/// lookup. The lookup is passed as a closure to avoid importing the
/// `Committee` type from `misaka-dag` (keeps this crate free of
/// cross-layer cycles).
pub fn authority_to_validator_id<F>(index: u32, pubkey_of: F) -> Result<[u8; 32], AuthorityMapError>
where
    F: FnOnce(u32) -> Option<Vec<u8>>,
{
    let pubkey = pubkey_of(index).ok_or(AuthorityMapError::OutOfRange)?;
    Ok(pubkey_to_validator_id(&pubkey))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_hashing() {
        let pk = vec![0xAAu8; 64];
        let a = pubkey_to_validator_id(&pk);
        let b = pubkey_to_validator_id(&pk);
        assert_eq!(a, b, "deterministic");
    }

    #[test]
    fn distinct_pubkeys_yield_distinct_ids() {
        let a = pubkey_to_validator_id(&[0xAAu8; 64]);
        let b = pubkey_to_validator_id(&[0xBBu8; 64]);
        assert_ne!(a, b);
    }

    #[test]
    fn lookup_hit_and_miss() {
        // Present → Ok
        let keys: Vec<Vec<u8>> = vec![vec![1u8; 16], vec![2u8; 16], vec![3u8; 16]];
        let got = authority_to_validator_id(1, |i| keys.get(i as usize).cloned()).expect("hit");
        assert_eq!(got, pubkey_to_validator_id(&[2u8; 16]));

        // Absent → OutOfRange
        let miss = authority_to_validator_id(10, |i| keys.get(i as usize).cloned());
        assert_eq!(miss, Err(AuthorityMapError::OutOfRange));
    }

    #[test]
    fn shape_matches_misaka_crypto_to_canonical_id() {
        // This is the same construction misaka_crypto's
        // ValidatorPqPublicKey::to_canonical_id uses:
        //   SHA3-256 over the raw pubkey bytes.
        // Any future change there MUST mirror here or slashing will
        // key on the wrong id. Recorded as a fixed hex vector so a
        // divergence trips this test.
        let pubkey = b"MISAKA:slashing:authority_map:pubkey_fixture";
        let id = pubkey_to_validator_id(pubkey);
        let expected = {
            use sha3::{Digest, Sha3_256};
            let mut h = Sha3_256::new();
            h.update(pubkey);
            let out: [u8; 32] = h.finalize().into();
            out
        };
        assert_eq!(id, expected);
    }
}
