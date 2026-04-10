// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Generic Stake Aggregator — threshold-aware vote collection.
//!
//! Sui equivalent: consensus/core/src/stake_aggregator.rs
//!
//! Provides a reusable building block for any consensus component that needs
//! to track "has a quorum/validity threshold of stake voted for X?".
//!
//! Used by:
//! - `vote_registry.rs` (commit votes per leader)
//! - `commit_vote_monitor.rs` (checkpoint vote tracking)
//! - `transaction_certifier.rs` (fast-path certification)
//!
//! # Design
//!
//! `StakeAggregator<K, T>` maps a key `K` to a set of voting authorities.
//! `T: ThresholdKind` determines the threshold (quorum = 2f+1, validity = f+1).
//! Duplicate votes from the same authority are automatically idempotent.

use std::collections::{BTreeSet, HashMap};
use std::hash::Hash;
use std::marker::PhantomData;

use crate::narwhal_types::block::AuthorityIndex;
use crate::narwhal_types::committee::{Committee, Stake};

/// Defines the stake threshold for a specific aggregation purpose.
pub trait ThresholdKind: Send + Sync + 'static {
    /// Compute the threshold from the committee.
    fn threshold(committee: &Committee) -> Stake;
    /// Human-readable name for diagnostics.
    fn name() -> &'static str;
}

/// Quorum threshold: 2f+1 (N - floor((N-1)/3)).
/// Required for commit decisions and finality.
pub struct QuorumThreshold;

impl ThresholdKind for QuorumThreshold {
    fn threshold(committee: &Committee) -> Stake {
        committee.quorum_threshold()
    }
    fn name() -> &'static str {
        "quorum"
    }
}

/// Validity threshold: f+1.
/// Guarantees at least one honest voter in the set.
pub struct ValidityThreshold;

impl ThresholdKind for ValidityThreshold {
    fn threshold(committee: &Committee) -> Stake {
        committee.validity_threshold()
    }
    fn name() -> &'static str {
        "validity"
    }
}

/// Result of adding a vote to the aggregator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteOutcome {
    /// Vote registered, threshold not yet reached.
    Registered {
        total_stake: Stake,
        threshold: Stake,
    },
    /// This vote pushed the total over the threshold.
    ThresholdReached { total_stake: Stake },
    /// Duplicate vote from same authority (idempotent, no change).
    Duplicate,
}

impl VoteOutcome {
    pub fn is_threshold_reached(&self) -> bool {
        matches!(self, Self::ThresholdReached { .. })
    }
}

/// Generic stake aggregator for threshold-based vote collection.
///
/// `K` — key type (e.g., BlockRef, TxDigest, CheckpointTarget).
/// `T` — threshold kind (QuorumThreshold or ValidityThreshold).
pub struct StakeAggregator<K: Hash + Eq + Clone, T: ThresholdKind> {
    /// Per-key voter set. BTreeSet for deterministic iteration.
    voters: HashMap<K, BTreeSet<AuthorityIndex>>,
    /// Per-key accumulated stake.
    stakes: HashMap<K, Stake>,
    /// Keys that have reached the threshold.
    reached: HashMap<K, Stake>,
    /// Committee reference.
    committee: Committee,
    /// Computed threshold.
    threshold: Stake,
    _phantom: PhantomData<T>,
}

impl<K: Hash + Eq + Clone, T: ThresholdKind> StakeAggregator<K, T> {
    /// Create a new aggregator for the given committee.
    pub fn new(committee: Committee) -> Self {
        let threshold = T::threshold(&committee);
        Self {
            voters: HashMap::new(),
            stakes: HashMap::new(),
            reached: HashMap::new(),
            committee,
            threshold,
            _phantom: PhantomData,
        }
    }

    /// Add a vote for key `k` from authority `voter`.
    ///
    /// Returns the outcome: Registered, ThresholdReached, or Duplicate.
    /// Duplicate votes are idempotent (no stake change).
    pub fn add_vote(&mut self, k: K, voter: AuthorityIndex) -> VoteOutcome {
        let voter_set = self.voters.entry(k.clone()).or_default();
        if !voter_set.insert(voter) {
            return VoteOutcome::Duplicate;
        }

        let stake = self.committee.stake(voter);
        let total = self.stakes.entry(k.clone()).or_insert(0);
        // SEC-FIX M-1: saturating_add to prevent u64 overflow
        *total = total.saturating_add(stake);

        if *total >= self.threshold && !self.reached.contains_key(&k) {
            self.reached.insert(k, *total);
            VoteOutcome::ThresholdReached {
                total_stake: *total,
            }
        } else {
            VoteOutcome::Registered {
                total_stake: *total,
                threshold: self.threshold,
            }
        }
    }

    /// Check if threshold has been reached for key `k`.
    pub fn has_reached_threshold(&self, k: &K) -> bool {
        self.reached.contains_key(k)
    }

    /// Get the total stake for key `k`.
    pub fn stake_for(&self, k: &K) -> Stake {
        self.stakes.get(k).copied().unwrap_or(0)
    }

    /// Get the set of voters for key `k`.
    pub fn voters_for(&self, k: &K) -> Option<&BTreeSet<AuthorityIndex>> {
        self.voters.get(k)
    }

    /// Get all keys that have reached the threshold.
    pub fn reached_keys(&self) -> impl Iterator<Item = &K> {
        self.reached.keys()
    }

    /// Number of keys being tracked.
    pub fn tracked_count(&self) -> usize {
        self.voters.len()
    }

    /// Number of keys that have reached threshold.
    pub fn reached_count(&self) -> usize {
        self.reached.len()
    }

    /// The threshold value.
    pub fn threshold(&self) -> Stake {
        self.threshold
    }

    /// Remove tracking for a key (GC).
    pub fn remove(&mut self, k: &K) {
        self.voters.remove(k);
        self.stakes.remove(k);
        self.reached.remove(k);
    }

    /// Remove all keys below a given predicate (generic GC).
    pub fn retain<F: Fn(&K) -> bool>(&mut self, pred: F) {
        self.voters.retain(|k, _| pred(k));
        self.stakes.retain(|k, _| pred(k));
        self.reached.retain(|k, _| pred(k));
    }

    /// Clear all state.
    pub fn clear(&mut self) {
        self.voters.clear();
        self.stakes.clear();
        self.reached.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn committee4() -> Committee {
        Committee::new_for_test(4)
    }

    #[test]
    fn quorum_threshold_basic() {
        let mut agg = StakeAggregator::<u64, QuorumThreshold>::new(committee4());

        // Quorum for N=4 is 3
        assert_eq!(agg.threshold(), 3);

        let r1 = agg.add_vote(1, 0);
        assert!(matches!(r1, VoteOutcome::Registered { total_stake: 1, .. }));

        let r2 = agg.add_vote(1, 1);
        assert!(matches!(r2, VoteOutcome::Registered { total_stake: 2, .. }));

        let r3 = agg.add_vote(1, 2);
        assert!(r3.is_threshold_reached());
        assert!(agg.has_reached_threshold(&1));
    }

    #[test]
    fn validity_threshold_basic() {
        let mut agg = StakeAggregator::<u64, ValidityThreshold>::new(committee4());

        // Validity for N=4 is f+1 = 2
        assert_eq!(agg.threshold(), 2);

        agg.add_vote(42, 0);
        let r = agg.add_vote(42, 1);
        assert!(r.is_threshold_reached());
    }

    #[test]
    fn duplicate_vote_idempotent() {
        let mut agg = StakeAggregator::<u64, QuorumThreshold>::new(committee4());

        agg.add_vote(1, 0);
        let dup = agg.add_vote(1, 0);
        assert!(matches!(dup, VoteOutcome::Duplicate));
        assert_eq!(agg.stake_for(&1), 1); // not 2
    }

    #[test]
    fn multiple_keys_independent() {
        let mut agg = StakeAggregator::<u64, QuorumThreshold>::new(committee4());

        agg.add_vote(1, 0);
        agg.add_vote(1, 1);
        agg.add_vote(2, 2);
        agg.add_vote(2, 3);

        assert_eq!(agg.stake_for(&1), 2);
        assert_eq!(agg.stake_for(&2), 2);
        assert!(!agg.has_reached_threshold(&1));
        assert!(!agg.has_reached_threshold(&2));
    }

    #[test]
    fn gc_remove() {
        let mut agg = StakeAggregator::<u64, QuorumThreshold>::new(committee4());

        for i in 0..3 {
            agg.add_vote(1, i);
        }
        assert!(agg.has_reached_threshold(&1));

        agg.remove(&1);
        assert!(!agg.has_reached_threshold(&1));
        assert_eq!(agg.tracked_count(), 0);
    }

    #[test]
    fn retain_gc() {
        let mut agg = StakeAggregator::<u64, QuorumThreshold>::new(committee4());

        agg.add_vote(5, 0);
        agg.add_vote(10, 1);
        agg.add_vote(15, 2);

        agg.retain(|k| *k >= 10);
        assert_eq!(agg.tracked_count(), 2);
        assert_eq!(agg.stake_for(&5), 0); // removed
        assert_eq!(agg.stake_for(&10), 1); // kept
    }

    #[test]
    fn voters_for_deterministic() {
        let mut agg = StakeAggregator::<u64, QuorumThreshold>::new(committee4());

        agg.add_vote(1, 3);
        agg.add_vote(1, 0);
        agg.add_vote(1, 2);

        let voters = agg.voters_for(&1).unwrap();
        // BTreeSet → sorted
        let sorted: Vec<_> = voters.iter().copied().collect();
        assert_eq!(sorted, vec![0, 2, 3]);
    }
}
