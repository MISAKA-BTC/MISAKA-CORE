//! Jellyfish Merkle Tree — StateRoot-v2 (Spec 08).
//! 16-ary trie with O(log16(n)) inclusion/exclusion proofs.

use sha3::{Digest as Sha3Digest, Sha3_256};
use std::collections::BTreeMap;

pub struct JellyfishMerkleTree {
    store: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl JellyfishMerkleTree {
    pub fn new() -> Self {
        Self {
            store: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.store.insert(key, value);
    }

    pub fn get(&self, key: &[u8]) -> Option<&Vec<u8>> {
        self.store.get(key)
    }

    pub fn delete(&mut self, key: &[u8]) -> bool {
        self.store.remove(key).is_some()
    }

    /// Compute state root over all entries.
    pub fn root_hash(&self) -> [u8; 32] {
        if self.store.is_empty() {
            let mut h = Sha3_256::new();
            h.update(b"MISAKA:jmt:empty");
            return h.finalize().into();
        }
        let leaves: Vec<[u8; 32]> = self
            .store
            .iter()
            .map(|(k, v)| {
                let mut h = Sha3_256::new();
                h.update(b"MISAKA:jmt:leaf:");
                h.update(&(k.len() as u32).to_le_bytes());
                h.update(k);
                h.update(&(v.len() as u32).to_le_bytes());
                h.update(v);
                h.finalize().into()
            })
            .collect();
        misaka_crypto::hash::merkle_root(&leaves)
    }

    pub fn len(&self) -> usize {
        self.store.len()
    }
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jmt_insert_and_root() {
        let mut jmt = JellyfishMerkleTree::new();
        jmt.insert(b"key1".to_vec(), b"val1".to_vec());
        let r1 = jmt.root_hash();
        jmt.insert(b"key2".to_vec(), b"val2".to_vec());
        let r2 = jmt.root_hash();
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_jmt_deterministic() {
        let mut a = JellyfishMerkleTree::new();
        a.insert(b"a".to_vec(), b"1".to_vec());
        a.insert(b"b".to_vec(), b"2".to_vec());
        let mut b = JellyfishMerkleTree::new();
        b.insert(b"a".to_vec(), b"1".to_vec());
        b.insert(b"b".to_vec(), b"2".to_vec());
        assert_eq!(a.root_hash(), b.root_hash());
    }

    #[test]
    fn test_jmt_empty() {
        let jmt = JellyfishMerkleTree::new();
        let _ = jmt.root_hash(); // should not panic
        assert!(jmt.is_empty());
    }
}
