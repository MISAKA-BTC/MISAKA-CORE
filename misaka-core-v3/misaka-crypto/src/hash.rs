//! Core hash functions — SHA3-only (Grover-resistant).
//!
//! # Security Policy
//!
//! - SHA2 is PROHIBITED everywhere in MISAKA Network.
//! - SHA3-256 for standard hashing (128-bit PQ security via 256-bit output).
//! - SHA3-512 for extended hashing (256-bit PQ security).
//!
//! # Note: No PoW
//!
//! MISAKA Network is Pure PoS. There is no Proof-of-Work hash function.
//! Block production is determined by the staking registry, not hash computation.

use sha3::{Sha3_256, Sha3_512, Digest as Sha3Digest};

pub type Digest = [u8; 32];
pub type Digest512 = [u8; 64];

/// Standard hash: SHA3-256 (128-bit post-quantum security).
pub fn sha3_256(data: &[u8]) -> Digest {
    let mut h = Sha3_256::new();
    h.update(data);
    h.finalize().into()
}

/// Extended hash: SHA3-512 (256-bit post-quantum security).
pub fn sha3_512(data: &[u8]) -> Digest512 {
    let mut h = Sha3_512::new();
    h.update(data);
    h.finalize().into()
}

/// Merkle root from a list of leaf digests (SHA3-256).
///
/// Uses domain-separated hashing to prevent second preimage attacks:
/// - Leaf nodes are prefixed with 0x00
/// - Internal nodes are prefixed with 0x01
pub fn merkle_root(leaves: &[Digest]) -> Digest {
    if leaves.is_empty() {
        return sha3_256(&[]);
    }
    // Domain-separate leaf nodes
    let mut layer: Vec<Digest> = leaves.iter().map(|leaf| {
        let mut h = Sha3_256::new();
        h.update(&[0x00]); // Leaf domain tag
        h.update(leaf);
        h.finalize().into()
    }).collect();
    while layer.len() > 1 {
        if layer.len() % 2 == 1 {
            let last = match layer.last() {
                Some(v) => *v,
                None => return sha3_256(&[]),
            };
            layer.push(last);
        }
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            let mut h = Sha3_256::new();
            h.update(&[0x01]); // Internal node domain tag
            h.update(&pair[0]);
            h.update(&pair[1]);
            next.push(h.finalize().into());
        }
        layer = next;
    }
    layer[0]
}

// ─── Tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256_deterministic() {
        let d1 = sha3_256(b"MISAKA");
        let d2 = sha3_256(b"MISAKA");
        assert_eq!(d1, d2);
    }

    #[test]
    fn test_sha3_512_deterministic() {
        let d1 = sha3_512(b"MISAKA");
        let d2 = sha3_512(b"MISAKA");
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 64);
    }

    #[test]
    fn test_merkle_root_empty() {
        let root = merkle_root(&[]);
        assert_eq!(root, sha3_256(&[]));
    }

    #[test]
    fn test_merkle_root_single() {
        let leaf = sha3_256(b"leaf");
        let root = merkle_root(&[leaf]);
        let expected = {
            let mut h = Sha3_256::new();
            h.update(&[0x00]);
            h.update(&leaf);
            let r: [u8; 32] = h.finalize().into();
            r
        };
        assert_eq!(root, expected);
        assert_ne!(root, leaf, "domain separation must change the hash");
    }

    #[test]
    fn test_merkle_root_deterministic() {
        let leaves = vec![sha3_256(b"a"), sha3_256(b"b"), sha3_256(b"c")];
        let r1 = merkle_root(&leaves);
        let r2 = merkle_root(&leaves);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_merkle_root_order_matters() {
        let a = sha3_256(b"a");
        let b = sha3_256(b"b");
        let r1 = merkle_root(&[a, b]);
        let r2 = merkle_root(&[b, a]);
        assert_ne!(r1, r2);
    }
}
