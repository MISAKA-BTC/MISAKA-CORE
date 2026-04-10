// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Sui equivalent: consensus/core/src/commit_vote_monitor.rs (118 lines)
//
//! Commit Vote Monitor — tracks vote progress and detects liveness issues.
//!
//! Extracted from `bft.rs` vote tracking logic.
//!
//! Responsibilities:
//! - Track which authorities have voted per checkpoint/round
//! - Detect authorities that consistently fail to vote (liveness monitor)
//! - Report vote equivocations (same authority, different digest)
//! - Feed vote counts to SLO metrics

use crate::narwhal_types::block::AuthorityIndex;
use crate::narwhal_types::committee::{Committee, Stake};
use std::collections::{HashMap, HashSet};

/// A detected vote equivocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoteEquivocation {
    pub authority: AuthorityIndex,
    pub round_or_sequence: u64,
    pub digest_a: [u8; 32],
    pub digest_b: [u8; 32],
}

/// Per-sequence vote tracking.
struct VoteRound {
    /// digest → set of voters
    votes: HashMap<[u8; 32], HashSet<AuthorityIndex>>,
    /// authority → first digest (for equivocation detection)
    first_vote: HashMap<AuthorityIndex, [u8; 32]>,
}

impl VoteRound {
    fn new() -> Self {
        Self {
            votes: HashMap::new(),
            first_vote: HashMap::new(),
        }
    }

    /// Record a vote. Returns equivocation if detected.
    fn record(
        &mut self,
        authority: AuthorityIndex,
        digest: [u8; 32],
        round_id: u64,
    ) -> Option<VoteEquivocation> {
        self.votes.entry(digest).or_default().insert(authority);

        match self.first_vote.get(&authority) {
            Some(&existing) if existing != digest => Some(VoteEquivocation {
                authority,
                round_or_sequence: round_id,
                digest_a: existing,
                digest_b: digest,
            }),
            None => {
                self.first_vote.insert(authority, digest);
                None
            }
            _ => None, // same digest, no equivocation
        }
    }

    /// Stake for a specific digest.
    fn stake_for_digest(&self, digest: &[u8; 32], committee: &Committee) -> Stake {
        // SEC-FIX NM-3: saturating fold to prevent u64 overflow
        self.votes
            .get(digest)
            .map(|voters| voters.iter().fold(0u64, |acc, &a| acc.saturating_add(committee.stake(a))))
            .unwrap_or(0)
    }

    /// Total unique voters across all digests.
    fn unique_voter_count(&self) -> usize {
        self.first_vote.len()
    }
}

/// Commit vote monitor — tracks vote progress across rounds.
///
/// Sui equivalent: `CommitVoteMonitor`.
pub struct CommitVoteMonitor {
    committee: Committee,
    /// Per-round/sequence vote tracking. Bounded to recent N rounds.
    rounds: HashMap<u64, VoteRound>,
    /// Detected equivocations.
    equivocations: Vec<VoteEquivocation>,
    /// Authorities that missed voting in recent rounds.
    missing_voters: HashMap<AuthorityIndex, u64>, // authority → consecutive misses
    /// Maximum rounds to track.
    max_tracked: usize,
    /// Total votes received (monotonic counter).
    total_votes: u64,
}

impl CommitVoteMonitor {
    #[must_use]
    pub fn new(committee: Committee) -> Self {
        Self {
            committee,
            rounds: HashMap::new(),
            equivocations: Vec::new(),
            missing_voters: HashMap::new(),
            max_tracked: 100,
            total_votes: 0,
        }
    }

    /// Record a vote.
    pub fn record_vote(
        &mut self,
        round_id: u64,
        authority: AuthorityIndex,
        digest: [u8; 32],
    ) -> Option<VoteEquivocation> {
        self.total_votes += 1;
        let vr = self.rounds.entry(round_id).or_insert_with(VoteRound::new);
        let eq = vr.record(authority, digest, round_id);
        if let Some(ref e) = eq {
            self.equivocations.push(e.clone());
        }
        // Reset missing counter for this authority
        self.missing_voters.remove(&authority);
        eq
    }

    /// Check vote stake for a digest at a round. Returns true if quorum reached.
    #[must_use]
    pub fn has_quorum(&self, round_id: u64, digest: &[u8; 32]) -> bool {
        self.rounds
            .get(&round_id)
            .map(|vr| {
                self.committee
                    .reached_quorum(vr.stake_for_digest(digest, &self.committee))
            })
            .unwrap_or(false)
    }

    /// Get stake for a digest at a round.
    #[must_use]
    pub fn stake_for(&self, round_id: u64, digest: &[u8; 32]) -> Stake {
        self.rounds
            .get(&round_id)
            .map(|vr| vr.stake_for_digest(digest, &self.committee))
            .unwrap_or(0)
    }

    /// Report missing voters for a completed round.
    ///
    /// Call after a round finalizes. Any authority not in the voter set
    /// gets their miss counter incremented.
    pub fn report_round_complete(&mut self, round_id: u64) {
        let n = self.committee.size();
        let voters: HashSet<AuthorityIndex> = self
            .rounds
            .get(&round_id)
            .map(|vr| vr.first_vote.keys().copied().collect())
            .unwrap_or_default();

        for auth in 0..n as AuthorityIndex {
            if !voters.contains(&auth) {
                *self.missing_voters.entry(auth).or_default() += 1;
            }
        }
    }

    /// Authorities with ≥ threshold consecutive misses.
    #[must_use]
    pub fn chronically_missing(&self, threshold: u64) -> Vec<AuthorityIndex> {
        self.missing_voters
            .iter()
            .filter(|(_, &count)| count >= threshold)
            .map(|(&auth, _)| auth)
            .collect()
    }

    /// All detected equivocations.
    #[must_use]
    pub fn equivocations(&self) -> &[VoteEquivocation] {
        &self.equivocations
    }

    /// GC old rounds.
    pub fn gc(&mut self, keep_after: u64) {
        self.rounds.retain(|&r, _| r >= keep_after);
    }

    /// Total votes recorded.
    #[must_use]
    pub fn total_votes(&self) -> u64 {
        self.total_votes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn committee4() -> Committee {
        Committee::new_for_test(4)
    }

    #[test]
    fn test_vote_quorum() {
        let mut mon = CommitVoteMonitor::new(committee4());
        let digest = [0xAA; 32];
        mon.record_vote(1, 0, digest);
        mon.record_vote(1, 1, digest);
        assert!(!mon.has_quorum(1, &digest));
        mon.record_vote(1, 2, digest);
        assert!(mon.has_quorum(1, &digest));
    }

    #[test]
    fn test_equivocation_detection() {
        let mut mon = CommitVoteMonitor::new(committee4());
        mon.record_vote(1, 0, [0xAA; 32]);
        let eq = mon.record_vote(1, 0, [0xBB; 32]);
        assert!(eq.is_some());
        assert_eq!(mon.equivocations().len(), 1);
    }

    #[test]
    fn test_duplicate_vote_no_equivocation() {
        let mut mon = CommitVoteMonitor::new(committee4());
        mon.record_vote(1, 0, [0xAA; 32]);
        let eq = mon.record_vote(1, 0, [0xAA; 32]);
        assert!(eq.is_none());
    }

    #[test]
    fn test_missing_voter_detection() {
        let mut mon = CommitVoteMonitor::new(committee4());
        mon.record_vote(1, 0, [0xAA; 32]);
        mon.record_vote(1, 1, [0xAA; 32]);
        // Authority 2,3 didn't vote
        mon.report_round_complete(1);
        let missing = mon.chronically_missing(1);
        assert!(missing.contains(&2));
        assert!(missing.contains(&3));
    }

    #[test]
    fn test_gc() {
        let mut mon = CommitVoteMonitor::new(committee4());
        mon.record_vote(1, 0, [0xAA; 32]);
        mon.record_vote(5, 0, [0xBB; 32]);
        mon.gc(3);
        assert_eq!(mon.stake_for(1, &[0xAA; 32]), 0); // GC'd
        assert!(mon.stake_for(5, &[0xBB; 32]) > 0); // kept
    }
}
