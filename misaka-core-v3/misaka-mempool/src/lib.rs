//! MISAKA Mempool — Q-DAG-CT Native.
//!
//! All legacy UtxoTransaction / LogRing / key_image code has been removed.
//! The mempool operates on QdagTransaction with nullifier-based dedup.
//!
//! Note: The primary mempool implementation is in
//! `misaka_dag::dag_block_producer::DagMempool`.
//! This crate provides the shared interface and utilities.

use std::collections::HashSet;

/// Nullifier-based mempool entry.
#[derive(Debug, Clone)]
pub struct MempoolEntry {
    /// Transaction hash (transcript hash).
    pub tx_hash: [u8; 32],
    /// Nullifiers from all inputs.
    pub nullifiers: Vec<[u8; 32]>,
    /// Serialized QdagTransaction bytes.
    pub tx_bytes: Vec<u8>,
    /// Insertion timestamp (monotonic).
    pub inserted_at_ms: u64,
    /// Priority score (higher = included sooner).
    pub priority: u64,
}

/// Mempool statistics.
#[derive(Debug, Default)]
pub struct MempoolStats {
    pub total_txs: usize,
    pub total_nullifiers: usize,
    pub rejected_duplicate: u64,
    pub rejected_spent: u64,
    pub evicted: u64,
}

/// Shared mempool interface for Q-DAG-CT transactions.
///
/// This is a lightweight wrapper around a nullifier set.
/// The full mempool with TX selection and block production
/// logic lives in `misaka_dag::dag_block_producer::DagMempool`.
pub struct NullifierMempool {
    /// Nullifiers currently in the mempool.
    nullifiers: HashSet<[u8; 32]>,
    /// Nullifiers confirmed on-chain (spent).
    spent: HashSet<[u8; 32]>,
    /// Stats.
    stats: MempoolStats,
}

impl NullifierMempool {
    pub fn new() -> Self {
        Self {
            nullifiers: HashSet::new(),
            spent: HashSet::new(),
            stats: MempoolStats::default(),
        }
    }

    /// Check if a nullifier is available (not in mempool or spent).
    pub fn is_available(&self, nullifier: &[u8; 32]) -> bool {
        !self.nullifiers.contains(nullifier) && !self.spent.contains(nullifier)
    }

    /// Reserve nullifiers for a new transaction.
    pub fn reserve(&mut self, nullifiers: &[[u8; 32]]) -> Result<(), String> {
        for n in nullifiers {
            if self.spent.contains(n) {
                self.stats.rejected_spent += 1;
                return Err(format!("nullifier {} already spent", hex::encode(&n[..8])));
            }
            if self.nullifiers.contains(n) {
                self.stats.rejected_duplicate += 1;
                return Err(format!("nullifier {} already in mempool", hex::encode(&n[..8])));
            }
        }
        for n in nullifiers {
            self.nullifiers.insert(*n);
        }
        self.stats.total_nullifiers += nullifiers.len();
        self.stats.total_txs += 1;
        Ok(())
    }

    /// Mark nullifiers as confirmed (spent on-chain).
    pub fn confirm(&mut self, nullifiers: &[[u8; 32]]) {
        for n in nullifiers {
            self.nullifiers.remove(n);
            self.spent.insert(*n);
        }
    }

    /// Release nullifiers (TX removed from mempool without confirmation).
    pub fn release(&mut self, nullifiers: &[[u8; 32]]) {
        for n in nullifiers {
            self.nullifiers.remove(n);
        }
    }

    /// Evict all mempool nullifiers that are now confirmed.
    pub fn evict_confirmed(&mut self, confirmed: &HashSet<[u8; 32]>) -> usize {
        let before = self.nullifiers.len();
        self.nullifiers.retain(|n| !confirmed.contains(n));
        for n in confirmed { self.spent.insert(*n); }
        let evicted = before - self.nullifiers.len();
        self.stats.evicted += evicted as u64;
        evicted
    }

    pub fn pending_count(&self) -> usize { self.nullifiers.len() }
    pub fn spent_count(&self) -> usize { self.spent.len() }
    pub fn stats(&self) -> &MempoolStats { &self.stats }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reserve_and_confirm() {
        let mut mp = NullifierMempool::new();
        let n = [[0x11u8; 32], [0x22; 32]];
        mp.reserve(&n).unwrap();
        assert_eq!(mp.pending_count(), 2);
        assert!(!mp.is_available(&n[0]));

        mp.confirm(&n);
        assert_eq!(mp.pending_count(), 0);
        assert_eq!(mp.spent_count(), 2);
        assert!(!mp.is_available(&n[0])); // spent
    }

    #[test]
    fn test_duplicate_rejected() {
        let mut mp = NullifierMempool::new();
        mp.reserve(&[[0x11; 32]]).unwrap();
        assert!(mp.reserve(&[[0x11; 32]]).is_err());
    }

    #[test]
    fn test_spent_rejected() {
        let mut mp = NullifierMempool::new();
        mp.confirm(&[[0xAA; 32]]);
        assert!(mp.reserve(&[[0xAA; 32]]).is_err());
    }
}
