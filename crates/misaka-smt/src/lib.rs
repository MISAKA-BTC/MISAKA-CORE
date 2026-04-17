//! Sparse Merkle Tree (SHA3-256) — v1.0 state commitment.
//!
//! Provides O(log N) inclusion/exclusion proofs for the UTXO set.
//! Specification frozen at v0.7.x; activation at v1.0 hard fork.
//!
//! # Modules
//!
//! - `domain` — FROZEN domain separation tags
//! - `hash` — SHA3-256 with DST
//! - `empty` — precomputed empty subtree hashes
//! - `key` — UTXO outref -> SMT key derivation
//! - `node` — internal/leaf node types
//! - `tree` — in-memory reference implementation
//! - `proof` — inclusion/exclusion proof + verification
//! - `batch` — batched update wrapper

pub mod batch;
pub mod domain;
pub mod empty;
pub mod hash;
pub mod key;
pub mod node;
pub mod proof;
pub mod test_vectors;
pub mod tree;
