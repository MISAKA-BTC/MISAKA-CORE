//! SMT node types.
//!
//! Internal node = hash of two children.
//! Leaf node = (key, value_hash).
//! Empty subtree = represented implicitly via `empty.rs` (no storage).

use crate::hash::Hash;
use borsh::{BorshDeserialize, BorshSerialize};

/// An SMT node stored in the backing map.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Node {
    /// Internal node with left and right child hashes.
    Internal { left: Hash, right: Hash },
    /// Leaf node storing a key-value pair.
    Leaf { key: Hash, value: Hash },
}

impl Node {
    /// Compute this node's hash.
    pub fn hash(&self) -> Hash {
        match self {
            Node::Internal { left, right } => crate::hash::internal_hash(left, right),
            Node::Leaf { key, value } => crate::hash::leaf_hash(key, value),
        }
    }
}
