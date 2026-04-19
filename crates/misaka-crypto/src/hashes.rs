//! Cryptographic hash functions for MISAKA.
//!
//! All hashing uses domain separation to prevent cross-protocol collisions.
//! SHA3-256 is the primary hash for consensus-critical paths.
//! Blake3 is used for performance-sensitive paths (Merkle trees, PoW).

use sha3::{Digest, Sha3_256};

/// 32-byte hash type used throughout MISAKA.
pub type Hash = [u8; 32];

/// Zero hash constant.
pub const ZERO_HASH: Hash = [0u8; 32];

/// Hash domain constants for isolation.
pub mod domain {
    pub const BLOCK_HASH: &[u8] = b"misaka:block:hash:v1";
    pub const TX_HASH: &[u8] = b"misaka:tx:hash:v1";
    pub const TX_ID: &[u8] = b"misaka:tx:id:v1";
    pub const TX_SIG_HASH: &[u8] = b"misaka:tx:sig:hash:v1";
    pub const MERKLE_ROOT: &[u8] = b"misaka:merkle:root:v1";
    pub const UTXO_COMMIT: &[u8] = b"misaka:utxo:commit:v1";
    pub const SCRIPT_HASH: &[u8] = b"misaka:script:hash:v1";
    pub const ADDRESS_HASH: &[u8] = b"misaka:addr:hash:v1";
    pub const SPEND_TAG: &[u8] = b"misaka:spend-tag:v1"; // wire compat
    pub const KDF: &[u8] = b"misaka:kdf:v1";
}

/// Domain-separated SHA3-256 hash.
pub fn sha3_domain(domain: &[u8], data: &[u8]) -> Hash {
    let mut h = Sha3_256::new();
    h.update(&(domain.len() as u16).to_le_bytes());
    h.update(domain);
    h.update(data);
    h.finalize().into()
}

/// Domain-separated Blake3 hash (faster, for non-consensus paths).
pub fn blake3_domain(domain: &[u8], data: &[u8]) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(&(domain.len() as u16).to_le_bytes());
    h.update(domain);
    h.update(data);
    *h.finalize().as_bytes()
}

/// Double SHA3-256 hash (for extra security on critical paths).
pub fn double_sha3(data: &[u8]) -> Hash {
    let h1: Hash = Sha3_256::digest(data).into();
    Sha3_256::digest(h1).into()
}

/// Hash a transaction for its canonical ID.
pub fn hash_transaction(tx_data: &[u8]) -> Hash {
    sha3_domain(domain::TX_ID, tx_data)
}

/// Hash a block header.
pub fn hash_block_header(header_data: &[u8]) -> Hash {
    sha3_domain(domain::BLOCK_HASH, header_data)
}

/// Hash for signature verification.
pub fn hash_for_signing(sig_data: &[u8]) -> Hash {
    sha3_domain(domain::TX_SIG_HASH, sig_data)
}

/// Hash a script for P2SH.
pub fn hash_script(script: &[u8]) -> Hash {
    blake3_domain(domain::SCRIPT_HASH, script)
}

/// Hash for address derivation.
pub fn hash_for_address(pubkey: &[u8]) -> Hash {
    blake3_domain(domain::ADDRESS_HASH, pubkey)
}

/// Compute a spend-tag from secret and commitment.
pub fn compute_spend_tag(secret: &[u8], commitment: &[u8]) -> Hash {
    let mut h = Sha3_256::new();
    h.update(domain::SPEND_TAG);
    h.update(secret);
    h.update(commitment);
    h.finalize().into()
}

/// Verify that two hashes are equal (constant-time).
pub fn hash_eq(a: &Hash, b: &Hash) -> bool {
    let mut result: u8 = 0;
    for i in 0..32 {
        result |= a[i] ^ b[i];
    }
    result == 0
}

// v1.0 Step 8 (2026-04-19): the `MuHash` XOR stub that lived
// here has been removed. The stub was a testnet-only placeholder
// that never met its mainnet safety bar (XOR is not a secure
// multiset commitment); it was superseded at the storage layer
// by `misaka-muhash::MuHash` (MuHash3072 over a prime — the real
// accumulator) and now further by `misaka-smt::SparseMerkleTree`
// (v1.0 canonical commitment). No production code path consumed
// this stub; `misaka-storage::UtxoSet::muhash` has always
// referenced the real `misaka-muhash` crate. The stub's deletion
// closes the outstanding `TODO(MAINNET-BLOCKER SEC-FIX NM-14)`
// marker without further code change. See
// `docs/design/v100_smt_migration.md` §9 (Step 8).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_separation() {
        let data = b"test";
        let h1 = sha3_domain(domain::BLOCK_HASH, data);
        let h2 = sha3_domain(domain::TX_HASH, data);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8; 32];
        let b = [1u8; 32];
        let c = [2u8; 32];
        assert!(hash_eq(&a, &b));
        assert!(!hash_eq(&a, &c));
    }

    // v1.0 Step 8 (2026-04-19): `test_muhash_commutativity` and
    // `test_muhash_remove` were deleted alongside the XOR stub
    // they exercised. MuHash commutativity + remove correctness
    // are now covered by the real accumulator in the
    // `misaka-muhash` crate (see `misaka-muhash/tests/`), and
    // the order-/mutation-invariants of the v1.0 state
    // commitment are covered by the SMT tests in
    // `misaka-storage/src/utxo_set.rs::tests` (Steps 2-3).
}
