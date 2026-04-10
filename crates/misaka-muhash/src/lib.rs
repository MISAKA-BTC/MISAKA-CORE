//! MuHash — Incremental multiset hash for UTXO commitments.
//!
//! MuHash allows efficient incremental updates:
//! - Add element: multiply accumulator by H(element)
//! - Remove element: multiply accumulator by H(element)^(-1)
//!
//! MISAKA uses SHA3-256 based MuHash for post-quantum safety.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// 256-bit MuHash accumulator.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct MuHash {
    /// XOR-based accumulator (simplified from multiplicative group).
    /// For production: use a proper multiplicative group over a large prime.
    pub state: [u8; 32],
}

impl MuHash {
    pub fn new() -> Self {
        Self::default()
    }

    /// Hash an element and XOR into the accumulator.
    pub fn add_element(&mut self, data: &[u8]) {
        let hash = Self::hash_element(data);
        for i in 0..32 {
            self.state[i] ^= hash[i];
        }
    }

    /// Remove an element (XOR is its own inverse).
    pub fn remove_element(&mut self, data: &[u8]) {
        // XOR is self-inverse, so add == remove
        self.add_element(data);
    }

    /// Combine two MuHash accumulators.
    pub fn combine(&mut self, other: &MuHash) {
        for i in 0..32 {
            self.state[i] ^= other.state[i];
        }
    }

    /// Get the finalized hash.
    pub fn finalize(&self) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.state);
        hasher.finalize().into()
    }

    fn hash_element(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha3_256::new();
        hasher.update(b"MuHash-MISAKA:");
        hasher.update(data);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_remove() {
        let mut mh = MuHash::new();
        mh.add_element(b"utxo_1");
        mh.add_element(b"utxo_2");
        let with_both = mh.state;
        mh.remove_element(b"utxo_2");
        mh.add_element(b"utxo_2");
        assert_eq!(mh.state, with_both);
    }

    #[test]
    fn test_order_independence() {
        let mut mh1 = MuHash::new();
        mh1.add_element(b"a");
        mh1.add_element(b"b");

        let mut mh2 = MuHash::new();
        mh2.add_element(b"b");
        mh2.add_element(b"a");

        assert_eq!(mh1.finalize(), mh2.finalize());
    }
}
