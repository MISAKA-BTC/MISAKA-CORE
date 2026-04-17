//! In-memory reference SMT. Used as the canonical correctness oracle
//! for batched / JMT implementations in v1.0.
//!
//! Storage: `HashMap<Hash, Node>`. Production v1.0 uses RocksDB.
//!
//! This is a **full-depth** SMT: every leaf is at depth 256 (the bottom).
//! Internal nodes span depths 0 (root) to 255. Empty subtrees are
//! represented implicitly via precomputed `empty_hash()` values and are
//! NOT stored in the map.

use crate::domain::SMT_DEPTH;
use crate::empty::{empty_hash, empty_root};
use crate::hash::{internal_hash, leaf_hash, Hash};
use crate::key::bit_at;
use crate::node::Node;
use crate::proof::SmtProof;
use std::collections::HashMap;

/// In-memory Sparse Merkle Tree (reference implementation).
#[derive(Debug, Clone)]
pub struct SparseMerkleTree {
    nodes: HashMap<Hash, Node>,
    root: Hash,
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseMerkleTree {
    /// Create an empty SMT.
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            root: empty_root(),
        }
    }

    /// Get the current root hash.
    pub fn root(&self) -> Hash {
        self.root
    }

    /// Insert or update a key-value pair.
    ///
    /// Walks all 256 levels, collecting siblings, then rebuilds bottom-up.
    pub fn insert(&mut self, key: Hash, value: Hash) {
        let new_leaf = leaf_hash(&key, &value);
        self.nodes.insert(new_leaf, Node::Leaf { key, value });

        // Walk down 256 levels collecting (sibling, go_right) at each depth.
        let mut siblings = Vec::with_capacity(SMT_DEPTH);
        let mut cur = self.root;

        for depth in 0..SMT_DEPTH {
            let go_right = bit_at(&key, depth);
            let (left, right) = self.children_of(cur, depth);
            let (next, sib) = if go_right {
                (right, left)
            } else {
                (left, right)
            };
            siblings.push((sib, go_right));
            cur = next;
        }

        // Rebuild from leaf (depth 256) back to root (depth 0).
        cur = new_leaf;
        for (sib, go_right) in siblings.iter().rev() {
            let (l, r) = if *go_right { (*sib, cur) } else { (cur, *sib) };
            cur = internal_hash(&l, &r);
            self.nodes.insert(cur, Node::Internal { left: l, right: r });
        }
        self.root = cur;
    }

    /// Remove a key from the tree. Returns true if the key was present.
    ///
    /// Reference implementation: rebuilds tree from scratch (O(n * 256)).
    /// Production v1.0 will use incremental deletion.
    pub fn remove(&mut self, key: &Hash) -> bool {
        if !self.contains(key) {
            return false;
        }
        let remaining: Vec<(Hash, Hash)> = self
            .iter_leaves()
            .into_iter()
            .filter(|(k, _)| k != key)
            .collect();
        let mut new_tree = Self::new();
        for (k, v) in remaining {
            new_tree.insert(k, v);
        }
        *self = new_tree;
        true
    }

    /// Look up a value by key.
    pub fn get(&self, key: &Hash) -> Option<Hash> {
        let mut cur = self.root;
        for depth in 0..SMT_DEPTH {
            match self.nodes.get(&cur) {
                Some(Node::Internal { left, right }) => {
                    cur = if bit_at(key, depth) { *right } else { *left };
                }
                _ => return None, // empty subtree, key absent
            }
        }
        // cur is now at depth 256 (leaf level)
        match self.nodes.get(&cur) {
            Some(Node::Leaf { key: ek, value: ev }) if ek == key => Some(*ev),
            _ => None,
        }
    }

    /// Check if a key exists in the tree.
    pub fn contains(&self, key: &Hash) -> bool {
        self.get(key).is_some()
    }

    /// Iterate over all leaf (key, value) pairs.
    pub fn iter_leaves(&self) -> Vec<(Hash, Hash)> {
        self.nodes
            .values()
            .filter_map(|node| match node {
                Node::Leaf { key, value } => Some((*key, *value)),
                _ => None,
            })
            .collect()
    }

    /// Generate an inclusion or exclusion proof for a key.
    ///
    /// Walks all 256 levels, recording non-empty siblings in the bitmap.
    pub fn prove(&self, key: &Hash) -> SmtProof {
        let mut bitmap = [0u8; 32];
        let mut siblings = Vec::new();
        let mut cur = self.root;

        for depth in 0..SMT_DEPTH {
            let go_right = bit_at(key, depth);
            let (left, right) = self.children_of(cur, depth);
            let (next, sib) = if go_right {
                (right, left)
            } else {
                (left, right)
            };
            let empty_sib = empty_hash(SMT_DEPTH - 1 - depth);
            if sib != empty_sib {
                bitmap[depth / 8] |= 1 << (7 - (depth % 8));
                siblings.push(sib);
            }
            cur = next;
        }

        // cur is at depth 256 (leaf level)
        let mut value = crate::empty::empty_hash(0);
        let mut leaf_at_path: Option<(Hash, Hash)> = None;

        match self.nodes.get(&cur) {
            Some(Node::Leaf { key: ek, value: ev }) => {
                if ek == key {
                    // Inclusion proof
                    value = *ev;
                } else {
                    // Different leaf at this position — exclusion proof
                    leaf_at_path = Some((*ek, *ev));
                }
            }
            _ => {
                // Empty slot — key absent, exclusion proof
            }
        }

        SmtProof {
            key: *key,
            value,
            bitmap,
            siblings,
            leaf_at_path,
        }
    }

    /// Get the children of a node at a given depth.
    ///
    /// For stored internal nodes: returns (left, right).
    /// For empty subtrees (not in map): returns (empty_child, empty_child).
    fn children_of(&self, hash: Hash, depth: usize) -> (Hash, Hash) {
        match self.nodes.get(&hash) {
            Some(Node::Internal { left, right }) => (*left, *right),
            _ => {
                // Empty subtree: children are both empty at the next level.
                // At depth d, each child has height (255 - d), so empty_hash(255 - d).
                let child = empty_hash(SMT_DEPTH - 1 - depth);
                (child, child)
            }
        }
    }
}
