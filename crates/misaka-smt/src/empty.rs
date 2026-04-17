//! Precomputed empty subtree hashes for depths 0..=256.
//!
//! - depth 0 = a leaf-level empty slot: H(DST_EMPTY || 0x0000).
//! - depth d = empty subtree containing 2^d empty leaves:
//!   H(DST_INTERNAL || empty[d-1] || empty[d-1]).
//!
//! These 257 values are FROZEN at v0.7.x. Test vectors in `test_vectors.rs`
//! MUST match exactly across all node implementations forever.

use crate::domain::{DST_EMPTY, SMT_DEPTH};
use crate::hash::{internal_hash, sha3_with_dst, Hash};
use once_cell::sync::Lazy;

/// Precomputed array of empty subtree hashes, indexed by depth.
pub static EMPTY_HASHES: Lazy<[Hash; SMT_DEPTH + 1]> = Lazy::new(|| {
    let mut h = [[0u8; 32]; SMT_DEPTH + 1];
    // depth 0: empty leaf slot
    h[0] = sha3_with_dst(DST_EMPTY, &[&0u16.to_be_bytes()]);
    // depth d: H(empty[d-1] || empty[d-1])
    for d in 1..=SMT_DEPTH {
        h[d] = internal_hash(&h[d - 1], &h[d - 1]);
    }
    h
});

/// Get the empty subtree hash at a given depth.
#[inline]
pub fn empty_hash(depth: usize) -> Hash {
    EMPTY_HASHES[depth]
}

/// Get the empty SMT root (depth 256).
#[inline]
pub fn empty_root() -> Hash {
    EMPTY_HASHES[SMT_DEPTH]
}
