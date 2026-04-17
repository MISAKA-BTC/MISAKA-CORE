//! SHA3-256 wrapper with domain separation for SMT operations.

use sha3::{Digest, Sha3_256};

/// 32-byte hash type.
pub type Hash = [u8; 32];

/// Zero hash constant.
pub const ZERO_HASH: Hash = [0u8; 32];

/// SHA3-256 with domain separation tag, hashing multiple parts.
#[inline]
pub fn sha3_with_dst(dst: &[u8], parts: &[&[u8]]) -> Hash {
    let mut h = Sha3_256::new();
    h.update(dst);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Hash a leaf node: H(DST_LEAF || key || value).
#[inline]
pub fn leaf_hash(key: &Hash, value: &Hash) -> Hash {
    sha3_with_dst(crate::domain::DST_LEAF, &[key, value])
}

/// Hash an internal node: H(DST_INTERNAL || left || right).
#[inline]
pub fn internal_hash(left: &Hash, right: &Hash) -> Hash {
    sha3_with_dst(crate::domain::DST_INTERNAL, &[left, right])
}

/// Finalize an SMT root with tree height binding.
#[inline]
pub fn root_hash(smt_root: &Hash, height: u16) -> Hash {
    sha3_with_dst(crate::domain::DST_ROOT, &[smt_root, &height.to_be_bytes()])
}
