//! Inclusion and exclusion proofs for the Sparse Merkle Tree.
//!
//! FROZEN serialization format. Bridge / light client implementers
//! MUST decode this exact layout.

use crate::domain::SMT_DEPTH;
use crate::empty::empty_hash;
use crate::hash::{internal_hash, leaf_hash, Hash};
use crate::key::bit_at;
use borsh::{BorshDeserialize, BorshSerialize};

/// Inclusion or exclusion proof for an SMT key.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SmtProof {
    /// The SMT key being proved.
    pub key: Hash,
    /// Value hash. For inclusion: the actual value. For exclusion: empty_hash(0).
    pub value: Hash,
    /// 256-bit bitmap, MSB = depth 0. Bit set = sibling is non-empty.
    pub bitmap: [u8; 32],
    /// Non-empty siblings, in order from depth 0 (root-side) to leaf.
    /// `len() == popcount(bitmap)`.
    pub siblings: Vec<Hash>,
    /// For non-membership: the actual leaf encountered at the divergence
    /// point (`Some((other_key, other_value))`), or `None` if path ends in empty.
    pub leaf_at_path: Option<(Hash, Hash)>,
}

impl SmtProof {
    /// Verify inclusion: `self.key` with `self.value` is in the tree
    /// rooted at `expected_root`.
    pub fn verify_inclusion(&self, expected_root: &Hash) -> bool {
        if self.leaf_at_path.is_some() {
            return false; // exclusion proof, not inclusion
        }
        let leaf = leaf_hash(&self.key, &self.value);
        let computed = self.compute_root(leaf);
        &computed == expected_root
    }

    /// Verify exclusion: `self.key` is NOT in the tree rooted at `expected_root`.
    pub fn verify_exclusion(&self, expected_root: &Hash) -> bool {
        let leaf = match &self.leaf_at_path {
            None => {
                // Path ends in empty subtree.
                empty_hash(0)
            }
            Some((other_key, other_value)) => {
                if other_key == &self.key {
                    return false; // same key means it IS present
                }
                leaf_hash(other_key, other_value)
            }
        };
        let computed = self.compute_root(leaf);
        &computed == expected_root
    }

    /// Recompute the root from a leaf hash, walking up the path using
    /// the bitmap and siblings.
    fn compute_root(&self, mut cur: Hash) -> Hash {
        let mut sib_idx = self.siblings.len();

        // Walk from leaf (deepest) up to root (depth 0).
        // We recorded siblings from depth 0 to deepest, so we iterate in reverse.
        for depth_from_root in (0..SMT_DEPTH).rev() {
            let bit_index = depth_from_root;
            let nonempty = (self.bitmap[bit_index / 8] >> (7 - (bit_index % 8))) & 1 == 1;

            let sibling = if nonempty {
                // Siblings are stored root-to-leaf, so we need reverse order.
                // sib_idx counts down from the end.
                if sib_idx == 0 {
                    return [0u8; 32]; // malformed proof
                }
                sib_idx -= 1;
                self.siblings[sib_idx]
            } else {
                empty_hash(SMT_DEPTH - 1 - depth_from_root)
            };

            cur = if bit_at(&self.key, depth_from_root) {
                internal_hash(&sibling, &cur)
            } else {
                internal_hash(&cur, &sibling)
            };
        }
        cur
    }
}
