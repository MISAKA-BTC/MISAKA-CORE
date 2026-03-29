//! Domain-separated hashing utilities for MISAKA.
//!
//! All hashes in MISAKA use domain separation to prevent cross-protocol
//! hash collisions. This module provides the core hashing primitives
//! used throughout the codebase.

use blake3::Hasher as Blake3Hasher;
use sha3::{Sha3_256, Digest};

/// 32-byte hash output used throughout MISAKA.
pub type Hash = [u8; 32];

/// Domain separator constants for hash isolation.
pub mod domains {
    pub const BLOCK_HEADER: &[u8] = b"misaka:block:header:v1";
    pub const BLOCK_BODY: &[u8] = b"misaka:block:body:v1";
    pub const TRANSACTION: &[u8] = b"misaka:tx:v1";
    pub const TRANSACTION_ID: &[u8] = b"misaka:txid:v1";
    pub const TRANSACTION_SIG: &[u8] = b"misaka:tx:sig:v1";
    pub const MERKLE_BRANCH: &[u8] = b"misaka:merkle:branch:v1";
    pub const MERKLE_LEAF: &[u8] = b"misaka:merkle:leaf:v1";
    pub const UTXO_COMMITMENT: &[u8] = b"misaka:utxo:commit:v1";
    pub const GHOSTDAG: &[u8] = b"misaka:ghostdag:v1";
    pub const PRUNING: &[u8] = b"misaka:pruning:v1";
    pub const ADDRESS: &[u8] = b"misaka:address:v1";
    pub const DIFFICULTY: &[u8] = b"misaka:difficulty:v1";
    pub const COINBASE: &[u8] = b"misaka:coinbase:v1";
    pub const NULLIFIER: &[u8] = b"misaka:nullifier:v1";
    pub const SHIELDED_NOTE: &[u8] = b"misaka:shielded:note:v1";
    pub const PQC_SIG_DOMAIN: &[u8] = b"misaka:pqc:sig:v1";
    pub const SCRIPT_HASH: &[u8] = b"misaka:script:hash:v1";
    pub const PAYLOAD_HASH: &[u8] = b"misaka:payload:v1";
    pub const MULTI_SIG: &[u8] = b"misaka:multisig:v1";
    pub const HEAVY_HASH: &[u8] = b"misaka:heavyhash:v1";
}

/// Domain-separated Blake3 hasher.
pub struct DomainHasher {
    inner: Blake3Hasher,
}

impl DomainHasher {
    /// Create a new hasher with the given domain separator.
    pub fn new(domain: &[u8]) -> Self {
        let mut inner = Blake3Hasher::new();
        // Write domain length as LE u16 prefix to prevent ambiguity
        let len = domain.len() as u16;
        inner.update(&len.to_le_bytes());
        inner.update(domain);
        Self { inner }
    }

    /// Feed data into the hasher.
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.inner.update(data);
        self
    }

    /// Finalize and return the 32-byte hash.
    pub fn finalize(self) -> Hash {
        let out = self.inner.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(out.as_bytes());
        result
    }

    /// Convenience: hash a single chunk with domain separation.
    pub fn hash_single(domain: &[u8], data: &[u8]) -> Hash {
        let mut h = Self::new(domain);
        h.update(data);
        h.finalize()
    }

    /// Convenience: hash two chunks (e.g. for Merkle internal nodes).
    pub fn hash_pair(domain: &[u8], left: &[u8], right: &[u8]) -> Hash {
        let mut h = Self::new(domain);
        h.update(left);
        h.update(right);
        h.finalize()
    }
}

/// SHA3-256 domain hasher (for PQC compatibility paths).
pub struct Sha3DomainHasher {
    inner: Sha3_256,
    domain: Vec<u8>,
}

impl Sha3DomainHasher {
    pub fn new(domain: &[u8]) -> Self {
        let mut inner = Sha3_256::new();
        let len = domain.len() as u16;
        inner.update(len.to_le_bytes());
        inner.update(domain);
        Self { inner, domain: domain.to_vec() }
    }

    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.inner.update(data);
        self
    }

    pub fn finalize(self) -> Hash {
        let out = self.inner.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&out);
        result
    }

    pub fn hash_single(domain: &[u8], data: &[u8]) -> Hash {
        let mut h = Self::new(domain);
        h.update(data);
        h.finalize()
    }
}

/// Merkle tree utilities using domain-separated hashing.
pub struct MerkleTree;

impl MerkleTree {
    /// Hash a leaf node.
    pub fn hash_leaf(data: &[u8]) -> Hash {
        DomainHasher::hash_single(domains::MERKLE_LEAF, data)
    }

    /// Hash an internal branch node from two children.
    pub fn hash_branch(left: &Hash, right: &Hash) -> Hash {
        let mut h = DomainHasher::new(domains::MERKLE_BRANCH);
        h.update(left);
        h.update(right);
        h.finalize()
    }

    /// Compute the Merkle root of a list of leaf hashes.
    /// Returns all-zeros for empty input.
    pub fn compute_root(leaves: &[Hash]) -> Hash {
        if leaves.is_empty() {
            return [0u8; 32];
        }
        if leaves.len() == 1 {
            return leaves[0];
        }

        let mut current_level: Vec<Hash> = leaves.to_vec();
        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            for chunk in current_level.chunks(2) {
                let hash = if chunk.len() == 2 {
                    Self::hash_branch(&chunk[0], &chunk[1])
                } else {
                    // Odd element: hash with itself
                    Self::hash_branch(&chunk[0], &chunk[0])
                };
                next_level.push(hash);
            }
            current_level = next_level;
        }
        current_level[0]
    }

    /// Generate a Merkle proof (list of sibling hashes + directions).
    pub fn generate_proof(leaves: &[Hash], index: usize) -> Option<MerkleProof> {
        if index >= leaves.len() || leaves.is_empty() {
            return None;
        }

        let mut proof_hashes = Vec::new();
        let mut proof_directions = Vec::new();
        let mut current_level: Vec<Hash> = leaves.to_vec();
        let mut current_index = index;

        while current_level.len() > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            let sibling = if sibling_index < current_level.len() {
                current_level[sibling_index]
            } else {
                current_level[current_index]
            };

            proof_hashes.push(sibling);
            proof_directions.push(current_index % 2 == 0);

            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            for chunk in current_level.chunks(2) {
                let hash = if chunk.len() == 2 {
                    Self::hash_branch(&chunk[0], &chunk[1])
                } else {
                    Self::hash_branch(&chunk[0], &chunk[0])
                };
                next_level.push(hash);
            }
            current_level = next_level;
            current_index /= 2;
        }

        Some(MerkleProof {
            leaf: leaves[index],
            siblings: proof_hashes,
            directions: proof_directions,
            root: current_level[0],
        })
    }

    /// Verify a Merkle proof.
    pub fn verify_proof(proof: &MerkleProof) -> bool {
        let mut current = proof.leaf;
        for (sibling, is_left) in proof.siblings.iter().zip(proof.directions.iter()) {
            current = if *is_left {
                Self::hash_branch(&current, sibling)
            } else {
                Self::hash_branch(sibling, &current)
            };
        }
        current == proof.root
    }
}

/// A Merkle inclusion proof.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MerkleProof {
    pub leaf: Hash,
    pub siblings: Vec<Hash>,
    pub directions: Vec<bool>,
    pub root: Hash,
}

/// Heavy hash function for PoW (matrix-based, ASIC-resistant).
/// Adapted from Kaspa's kHeavyHash with PQ domain separation.
pub fn heavy_hash(header_hash: &Hash, matrix: &[[u16; 64]; 64]) -> Hash {
    let mut xvec = [0u64; 64];
    for i in 0..32 {
        xvec[2 * i] = (header_hash[i] >> 4) as u64;
        xvec[2 * i + 1] = (header_hash[i] & 0x0f) as u64;
    }

    let mut product = [0u64; 64];
    for i in 0..64 {
        let mut sum = 0u64;
        for j in 0..64 {
            sum = sum.wrapping_add((matrix[i][j] as u64).wrapping_mul(xvec[j]));
        }
        product[i] = sum;
    }

    let mut result_nibbles = [0u8; 64];
    for i in 0..64 {
        result_nibbles[i] = (product[i] & 0x0f) as u8;
    }

    let mut pre_hash = [0u8; 32];
    for i in 0..32 {
        pre_hash[i] = (result_nibbles[2 * i] << 4) | result_nibbles[2 * i + 1];
    }

    // XOR with original hash
    for i in 0..32 {
        pre_hash[i] ^= header_hash[i];
    }

    DomainHasher::hash_single(domains::HEAVY_HASH, &pre_hash)
}

/// Generate a PoW matrix from a header hash.
pub fn generate_pow_matrix(seed: &Hash) -> [[u16; 64]; 64] {
    let mut matrix = [[0u16; 64]; 64];
    let mut hasher = Blake3Hasher::new();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();

    for row in &mut matrix {
        let mut buf = [0u8; 128];
        reader.fill(&mut buf);
        for (j, val) in row.iter_mut().enumerate() {
            *val = u16::from_le_bytes([buf[j * 2], buf[j * 2 + 1]]);
        }
    }
    matrix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_separation() {
        let data = b"test data";
        let h1 = DomainHasher::hash_single(domains::BLOCK_HEADER, data);
        let h2 = DomainHasher::hash_single(domains::TRANSACTION, data);
        assert_ne!(h1, h2, "different domains must produce different hashes");
    }

    #[test]
    fn test_merkle_round_trip() {
        let leaves: Vec<Hash> = (0..8u8)
            .map(|i| MerkleTree::hash_leaf(&[i]))
            .collect();
        let root = MerkleTree::compute_root(&leaves);

        for i in 0..leaves.len() {
            let proof = MerkleTree::generate_proof(&leaves, i);
            assert!(proof.is_some());
            let proof = proof.unwrap();
            assert_eq!(proof.root, root);
            assert!(MerkleTree::verify_proof(&proof));
        }
    }

    #[test]
    fn test_merkle_empty() {
        assert_eq!(MerkleTree::compute_root(&[]), [0u8; 32]);
    }

    #[test]
    fn test_merkle_single() {
        let leaf = MerkleTree::hash_leaf(b"only");
        assert_eq!(MerkleTree::compute_root(&[leaf]), leaf);
    }

    #[test]
    fn test_heavy_hash_determinism() {
        let seed = DomainHasher::hash_single(b"test", b"seed");
        let matrix = generate_pow_matrix(&seed);
        let h1 = heavy_hash(&seed, &matrix);
        let h2 = heavy_hash(&seed, &matrix);
        assert_eq!(h1, h2);
    }
}
