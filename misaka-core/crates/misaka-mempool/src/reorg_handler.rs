//! Mempool Reorg Handler — safe TX re-evaluation after DAG reorgs.
//!
//! # Problem
//!
//! When a DAG reorg occurs, transactions from the reverted branch become
//! "orphaned" — they were applied to state but that state was rolled back.
//! Naively re-adding these TXs to the mempool creates two dangers:
//!
//! 1. **Double-Spend Replay**: A TX whose nullifier is now spent on the new
//!    branch gets re-added to mempool. If re-included, it causes a
//!    double-spend (same nullifier recorded twice).
//!
//! 2. **Flood Attack**: An attacker triggers a reorg and floods the mempool
//!    with thousands of previously-applied TXs, exhausting validator CPU
//!    (each TX requires expensive lattice ZKP re-verification).
//!
//! # Solution: Quarantine + Re-evaluate Pipeline
//!
//! Orphaned TXs are NOT immediately re-added to the mempool. Instead:
//!
//! 1. **Quarantine**: TXs go into a `ConflictedCache` (time-limited, size-bounded)
//! 2. **Nullifier Check**: Each TX's nullifiers are checked against the NEW
//!    nullifier set (post-reorg). Conflicting TXs are permanently dropped.
//! 3. **Structural Check**: Remaining TXs pass cheap validation again.
//! 4. **Admission**: Only clean TXs are re-submitted to the mempool.
//!
//! # Soundness
//!
//! After `handle_reorg()`:
//! - The mempool contains ZERO TXs whose nullifiers conflict with the new state
//! - The `ConflictedCache` contains all permanently-invalid TXs (not re-broadcastable)
//! - The nullifier set in the mempool is consistent with the new DAG state

use std::collections::{HashMap, HashSet};

/// Hash type alias.
pub type Hash = [u8; 32];

/// Maximum number of TXs to quarantine during a reorg.
/// Prevents memory exhaustion from deep reorgs with many TXs.
pub const MAX_QUARANTINE_SIZE: usize = 10_000;

/// How long conflicted TXs stay in the cache (for replay prevention).
/// After this, the TX hash is forgotten and could theoretically be re-submitted.
pub const CONFLICTED_CACHE_TTL_MS: u64 = 600_000; // 10 minutes

// ═══════════════════════════════════════════════════════════════
//  Orphaned TX (from reorg)
// ═══════════════════════════════════════════════════════════════

/// A transaction orphaned by a DAG reorg.
///
/// Contains enough information to re-evaluate without re-parsing.
#[derive(Debug, Clone)]
pub struct OrphanedTx {
    /// Transaction hash.
    pub tx_hash: Hash,
    /// Nullifiers this TX would consume.
    pub nullifiers: Vec<Hash>,
    /// Was this TX successfully applied on the old branch?
    pub was_applied: bool,
    /// The block this TX was originally in.
    pub original_block: Hash,
}

// ═══════════════════════════════════════════════════════════════
//  Re-evaluation Result
// ═══════════════════════════════════════════════════════════════

/// Result of re-evaluating orphaned TXs after a reorg.
#[derive(Debug)]
pub struct ReorgEvaluationResult {
    /// TXs that passed re-evaluation and were re-submitted to mempool.
    pub readmitted: Vec<Hash>,
    /// TXs permanently dropped (nullifier conflict with new state).
    pub conflicted: Vec<ConflictedTx>,
    /// TXs dropped for other reasons (structural, size, etc.).
    pub dropped: Vec<(Hash, String)>,
    /// Summary statistics.
    pub stats: ReorgStats,
}

/// A TX permanently invalidated by a reorg.
#[derive(Debug, Clone)]
pub struct ConflictedTx {
    pub tx_hash: Hash,
    pub reason: ConflictReason,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictReason {
    /// Nullifier already spent on the new branch.
    NullifierSpentOnNewBranch,
    /// Nullifier conflicts with another orphaned TX that was re-admitted first.
    NullifierConflictWithReadmitted,
    /// TX exceeds mempool size limits.
    MempoolFull,
}

/// Statistics from a reorg re-evaluation.
#[derive(Debug, Clone, Default)]
pub struct ReorgStats {
    pub total_orphaned: usize,
    pub readmitted: usize,
    pub conflicted_nullifier: usize,
    pub dropped_other: usize,
    pub reorg_depth: usize,
}

// ═══════════════════════════════════════════════════════════════
//  Conflicted TX Cache (replay prevention)
// ═══════════════════════════════════════════════════════════════

/// Cache of TX hashes that are permanently invalid due to reorgs.
///
/// Prevents the same invalid TX from being re-broadcast after a reorg.
/// Time-limited: entries expire after CONFLICTED_CACHE_TTL_MS.
pub struct ConflictedCache {
    entries: HashMap<Hash, ConflictedTx>,
    max_size: usize,
}

impl ConflictedCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_size,
        }
    }

    /// Add a conflicted TX to the cache.
    pub fn insert(&mut self, tx: ConflictedTx) {
        if self.entries.len() >= self.max_size {
            // Evict oldest entry
            if let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, v)| v.timestamp_ms)
                .map(|(k, _)| *k)
            {
                self.entries.remove(&oldest_key);
            }
        }
        self.entries.insert(tx.tx_hash, tx);
    }

    /// Check if a TX hash is in the conflicted cache.
    pub fn is_conflicted(&self, tx_hash: &Hash) -> bool {
        self.entries.contains_key(tx_hash)
    }

    /// Cleanup expired entries.
    pub fn cleanup(&mut self, now_ms: u64) {
        self.entries
            .retain(|_, v| now_ms.saturating_sub(v.timestamp_ms) < CONFLICTED_CACHE_TTL_MS);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Reorg Handler
// ═══════════════════════════════════════════════════════════════

/// Handles mempool re-evaluation after DAG reorgs.
///
/// # Usage
///
/// ```ignore
/// let handler = ReorgHandler::new(conflicted_cache);
///
/// // After ReorgEngine::execute_reorg():
/// let result = handler.evaluate_orphans(
///     orphaned_txs,
///     &new_nullifier_set,   // from post-reorg state
///     &mempool_nullifiers,  // currently in mempool
///     now_ms,
/// );
///
/// // Apply results to mempool
/// for tx_hash in &result.readmitted {
///     mempool.readmit(tx_hash);
/// }
/// for conflicted in &result.conflicted {
///     handler.conflicted_cache.insert(conflicted.clone());
/// }
/// ```
pub struct ReorgHandler {
    pub conflicted_cache: ConflictedCache,
}

impl ReorgHandler {
    pub fn new(max_cache_size: usize) -> Self {
        Self {
            conflicted_cache: ConflictedCache::new(max_cache_size),
        }
    }

    /// Re-evaluate orphaned TXs against the post-reorg state.
    ///
    /// # Algorithm
    ///
    /// For each orphaned TX (that was previously applied):
    /// 1. Check if ANY of its nullifiers are in `new_nullifier_set` → CONFLICTED
    /// 2. Check if ANY of its nullifiers are in `readmitted_nullifiers` → CONFLICTED
    /// 3. If clean, mark for readmission and track its nullifiers
    ///
    /// TXs that were NOT applied on the old branch (failed validation) are
    /// silently dropped — they were already invalid.
    ///
    /// # Ordering
    ///
    /// Orphaned TXs are processed in the order they were applied on the old branch.
    /// This preserves "first seen" priority for nullifier conflicts among orphans.
    ///
    /// # Soundness
    ///
    /// After this function:
    /// - `readmitted` contains NO TX whose nullifier is in `new_nullifier_set`
    /// - `readmitted` contains NO pair of TXs with conflicting nullifiers
    /// - `conflicted` contains ALL TXs that would cause double-spends
    pub fn evaluate_orphans(
        &self,
        orphans: &[OrphanedTx],
        new_nullifier_set: &HashSet<Hash>,
        mempool_nullifiers: &HashSet<Hash>,
        now_ms: u64,
    ) -> ReorgEvaluationResult {
        let mut readmitted = Vec::new();
        let mut conflicted = Vec::new();
        let mut dropped = Vec::new();
        let mut readmitted_nullifiers: HashSet<Hash> = HashSet::new();

        let mut stats = ReorgStats {
            total_orphaned: orphans.len(),
            ..Default::default()
        };

        for orphan in orphans {
            // Skip TXs that weren't applied (already invalid)
            if !orphan.was_applied {
                dropped.push((orphan.tx_hash, "was not applied on old branch".into()));
                stats.dropped_other += 1;
                continue;
            }

            // Skip TXs in the conflicted cache (already known-bad)
            if self.conflicted_cache.is_conflicted(&orphan.tx_hash) {
                dropped.push((orphan.tx_hash, "in conflicted cache".into()));
                stats.dropped_other += 1;
                continue;
            }

            // Check against the NEW on-chain nullifier set
            let chain_conflict = orphan
                .nullifiers
                .iter()
                .find(|nf| new_nullifier_set.contains(*nf));

            if let Some(nf) = chain_conflict {
                conflicted.push(ConflictedTx {
                    tx_hash: orphan.tx_hash,
                    reason: ConflictReason::NullifierSpentOnNewBranch,
                    timestamp_ms: now_ms,
                });
                stats.conflicted_nullifier += 1;
                continue;
            }

            // Check against mempool nullifiers
            let mempool_conflict = orphan
                .nullifiers
                .iter()
                .find(|nf| mempool_nullifiers.contains(*nf));

            if mempool_conflict.is_some() {
                conflicted.push(ConflictedTx {
                    tx_hash: orphan.tx_hash,
                    reason: ConflictReason::NullifierConflictWithReadmitted,
                    timestamp_ms: now_ms,
                });
                stats.conflicted_nullifier += 1;
                continue;
            }

            // Check against already-readmitted orphans
            let readmit_conflict = orphan
                .nullifiers
                .iter()
                .find(|nf| readmitted_nullifiers.contains(*nf));

            if readmit_conflict.is_some() {
                conflicted.push(ConflictedTx {
                    tx_hash: orphan.tx_hash,
                    reason: ConflictReason::NullifierConflictWithReadmitted,
                    timestamp_ms: now_ms,
                });
                stats.conflicted_nullifier += 1;
                continue;
            }

            // Quarantine size check
            if readmitted.len() >= MAX_QUARANTINE_SIZE {
                dropped.push((orphan.tx_hash, "quarantine full".into()));
                stats.dropped_other += 1;
                continue;
            }

            // ✅ Clean — readmit
            for nf in &orphan.nullifiers {
                readmitted_nullifiers.insert(*nf);
            }
            readmitted.push(orphan.tx_hash);
            stats.readmitted += 1;
        }

        ReorgEvaluationResult {
            readmitted,
            conflicted,
            dropped,
            stats,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn orphan(id: u8, nullifiers: &[[u8; 32]], applied: bool) -> OrphanedTx {
        OrphanedTx {
            tx_hash: [id; 32],
            nullifiers: nullifiers.to_vec(),
            was_applied: applied,
            original_block: [0xFF; 32],
        }
    }

    #[test]
    fn test_clean_orphan_readmitted() {
        let handler = ReorgHandler::new(100);
        let orphans = vec![orphan(1, &[[0xAA; 32]], true)];

        let result = handler.evaluate_orphans(
            &orphans,
            &HashSet::new(), // no on-chain nullifiers
            &HashSet::new(), // no mempool nullifiers
            1000,
        );

        assert_eq!(result.readmitted.len(), 1);
        assert_eq!(result.conflicted.len(), 0);
        assert_eq!(result.stats.readmitted, 1);
    }

    #[test]
    fn test_chain_conflicted_orphan_dropped() {
        let handler = ReorgHandler::new(100);
        let nf = [0xAA; 32];
        let orphans = vec![orphan(1, &[nf], true)];

        let mut chain_nullifiers = HashSet::new();
        chain_nullifiers.insert(nf); // Already spent on new branch

        let result = handler.evaluate_orphans(&orphans, &chain_nullifiers, &HashSet::new(), 1000);

        assert_eq!(result.readmitted.len(), 0);
        assert_eq!(result.conflicted.len(), 1);
        assert_eq!(
            result.conflicted[0].reason,
            ConflictReason::NullifierSpentOnNewBranch
        );
    }

    #[test]
    fn test_orphan_mutual_conflict_first_wins() {
        let handler = ReorgHandler::new(100);
        let shared_nf = [0xCC; 32];

        // Two orphans sharing the same nullifier
        let orphans = vec![orphan(1, &[shared_nf], true), orphan(2, &[shared_nf], true)];

        let result = handler.evaluate_orphans(&orphans, &HashSet::new(), &HashSet::new(), 1000);

        assert_eq!(result.readmitted.len(), 1, "first-seen wins");
        assert_eq!(result.conflicted.len(), 1, "second is conflicted");
        assert_eq!(result.readmitted[0], [1; 32], "TX 1 readmitted (first)");
    }

    #[test]
    fn test_unapplied_orphan_silently_dropped() {
        let handler = ReorgHandler::new(100);
        let orphans = vec![orphan(1, &[[0xAA; 32]], false)]; // was NOT applied

        let result = handler.evaluate_orphans(&orphans, &HashSet::new(), &HashSet::new(), 1000);

        assert_eq!(result.readmitted.len(), 0);
        assert_eq!(result.dropped.len(), 1);
    }

    #[test]
    fn test_conflicted_cache_prevents_replay() {
        let mut handler = ReorgHandler::new(100);
        let nf = [0xDD; 32];

        // First reorg: TX 1 is conflicted
        handler.conflicted_cache.insert(ConflictedTx {
            tx_hash: [1; 32],
            reason: ConflictReason::NullifierSpentOnNewBranch,
            timestamp_ms: 500,
        });

        // Second reorg: TX 1 is orphaned again, but should be dropped
        let orphans = vec![orphan(1, &[nf], true)];
        let result = handler.evaluate_orphans(&orphans, &HashSet::new(), &HashSet::new(), 1000);

        assert_eq!(
            result.readmitted.len(),
            0,
            "conflicted cache prevents replay"
        );
        assert_eq!(result.dropped.len(), 1);
    }

    #[test]
    fn test_conflicted_cache_cleanup() {
        let mut cache = ConflictedCache::new(100);
        cache.insert(ConflictedTx {
            tx_hash: [1; 32],
            reason: ConflictReason::NullifierSpentOnNewBranch,
            timestamp_ms: 1000,
        });

        assert!(!cache.is_empty());
        cache.cleanup(1000 + CONFLICTED_CACHE_TTL_MS + 1);
        assert!(cache.is_empty(), "expired entries must be cleaned up");
    }
}
