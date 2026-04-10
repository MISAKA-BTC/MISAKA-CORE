// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! VoteRegistry — tracks votes per leader with equivocation detection.
//!
//! ## Problem (CRIT)
//!
//! Previous: votes stored in `HashMap<AuthorityIndex, BlockRef>`. If an
//! authority voted twice (equivocation), the second vote silently overwrote
//! the first. This meant equivocation evidence was destroyed.
//!
//! ## Fix
//!
//! Store votes in `BTreeMap` and detect duplicate keys. When a duplicate
//! is found with a different BlockRef, return `VoteEquivocation`.
//!
//! This module is used by the commit pipeline whenever votes (blocks at
//! round R+1 referencing a leader at round R) are aggregated.

// NOTE: StakeAggregator<BlockRef, QuorumThreshold> provides the same
// functionality as this module. Consider migrating in a future refactor.
// The current impl is retained for API stability.

use super::stake_aggregator;
use crate::narwhal_types::block::*;
use crate::narwhal_types::committee::{Committee, Stake};
use std::collections::BTreeMap;

/// A detected vote equivocation (same authority voted for different blocks).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoteEquivocation {
    /// The equivocating authority.
    pub authority: AuthorityIndex,
    /// The leader being voted on.
    pub leader: BlockRef,
    /// First vote (block at voting round referencing the leader).
    pub vote_a: BlockRef,
    /// Second (conflicting) vote.
    pub vote_b: BlockRef,
}

/// Result of registering a vote.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub enum VoteResult {
    /// Vote registered successfully.
    Registered,
    /// Duplicate vote with same BlockRef (no-op).
    Duplicate,
    /// Equivocation: authority voted differently. Evidence returned.
    Equivocation(VoteEquivocation),
}

/// Registry of votes for a specific leader.
///
/// Tracks which authorities voted (by including the leader as ancestor)
/// and detects equivocation. Uses `BTreeMap` for deterministic iteration.
pub struct VoteRegistry {
    /// Leader this registry tracks votes for.
    leader: BlockRef,
    /// Authority → their voting block.
    votes: BTreeMap<AuthorityIndex, BlockRef>,
    /// Detected equivocations.
    equivocations: Vec<VoteEquivocation>,
}

impl VoteRegistry {
    /// Create a new vote registry for the given leader.
    #[must_use]
    pub fn new(leader: BlockRef) -> Self {
        Self {
            leader,
            votes: BTreeMap::new(),
            equivocations: Vec::new(),
        }
    }

    /// Register a vote: authority `voter` produced `voting_block` which
    /// includes `self.leader` as an ancestor.
    pub fn register_vote(&mut self, voter: AuthorityIndex, voting_block: BlockRef) -> VoteResult {
        match self.votes.get(&voter) {
            Some(existing) if *existing == voting_block => VoteResult::Duplicate,
            Some(existing) => {
                let ev = VoteEquivocation {
                    authority: voter,
                    leader: self.leader,
                    vote_a: *existing,
                    vote_b: voting_block,
                };
                self.equivocations.push(ev.clone());
                // Do NOT overwrite — keep the first vote for determinism.
                VoteResult::Equivocation(ev)
            }
            None => {
                self.votes.insert(voter, voting_block);
                VoteResult::Registered
            }
        }
    }

    /// Total vote stake from unique authorities (equivocators counted once).
    #[must_use]
    pub fn vote_stake(&self, committee: &Committee) -> Stake {
        // SEC-FIX M-3: saturating fold to prevent u64 overflow
        self.votes.keys().fold(0u64, |acc, &auth| acc.saturating_add(committee.stake(auth)))
    }

    /// Check if quorum is reached.
    #[must_use]
    pub fn reached_quorum(&self, committee: &Committee) -> bool {
        committee.reached_quorum(self.vote_stake(committee))
    }

    /// Number of unique voters.
    #[must_use]
    pub fn voter_count(&self) -> usize {
        self.votes.len()
    }

    /// All detected equivocations.
    #[must_use]
    pub fn equivocations(&self) -> &[VoteEquivocation] {
        &self.equivocations
    }

    /// The leader this registry tracks.
    #[must_use]
    pub fn leader(&self) -> &BlockRef {
        &self.leader
    }

    /// All voters and their voting blocks.
    #[must_use]
    pub fn votes(&self) -> &BTreeMap<AuthorityIndex, BlockRef> {
        &self.votes
    }

    /// Check if vote stake has reached quorum via StakeAggregator check.
    pub fn reached_quorum_via_aggregator(&self, committee: &Committee) -> bool {
        self.vote_stake(committee) >= committee.quorum_threshold()
    }

    /// Clear all state (for reuse).
    pub fn clear(&mut self) {
        self.votes.clear();
        self.equivocations.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leader_ref() -> BlockRef {
        BlockRef::new(2, 0, BlockDigest([0xAA; 32]))
    }

    fn vote_ref(author: AuthorityIndex) -> BlockRef {
        let mut d = [0u8; 32];
        d[0] = author as u8;
        BlockRef::new(3, author, BlockDigest(d))
    }

    #[test]
    fn test_register_unique_votes() {
        let mut reg = VoteRegistry::new(leader_ref());
        assert!(matches!(
            reg.register_vote(0, vote_ref(0)),
            VoteResult::Registered
        ));
        assert!(matches!(
            reg.register_vote(1, vote_ref(1)),
            VoteResult::Registered
        ));
        assert_eq!(reg.voter_count(), 2);
        assert!(reg.equivocations().is_empty());
    }

    #[test]
    fn test_duplicate_vote_is_noop() {
        let mut reg = VoteRegistry::new(leader_ref());
        reg.register_vote(0, vote_ref(0));
        let result = reg.register_vote(0, vote_ref(0)); // same block
        assert!(matches!(result, VoteResult::Duplicate));
        assert_eq!(reg.voter_count(), 1);
    }

    #[test]
    fn test_equivocation_detected() {
        let mut reg = VoteRegistry::new(leader_ref());
        reg.register_vote(0, vote_ref(0));
        // Same authority, different voting block
        let other = BlockRef::new(3, 0, BlockDigest([0xFF; 32]));
        let result = reg.register_vote(0, other);
        assert!(matches!(result, VoteResult::Equivocation(_)));
        assert_eq!(reg.equivocations().len(), 1);
        // First vote is preserved (not overwritten)
        assert_eq!(*reg.votes().get(&0).unwrap(), vote_ref(0));
    }

    #[test]
    fn test_vote_stake() {
        let committee = Committee::new_for_test(4);
        let mut reg = VoteRegistry::new(leader_ref());
        reg.register_vote(0, vote_ref(0));
        reg.register_vote(1, vote_ref(1));
        reg.register_vote(2, vote_ref(2));
        assert_eq!(reg.vote_stake(&committee), 3);
        assert!(reg.reached_quorum(&committee)); // quorum=3 for n=4
    }

    #[test]
    fn test_equivocator_counted_once_in_stake() {
        let committee = Committee::new_for_test(4);
        let mut reg = VoteRegistry::new(leader_ref());
        reg.register_vote(0, vote_ref(0));
        let other = BlockRef::new(3, 0, BlockDigest([0xFF; 32]));
        reg.register_vote(0, other); // equivocation
        assert_eq!(
            reg.vote_stake(&committee),
            1,
            "equivocator stake counted once"
        );
    }

    #[test]
    fn test_clear() {
        let mut reg = VoteRegistry::new(leader_ref());
        reg.register_vote(0, vote_ref(0));
        reg.register_vote(1, vote_ref(1));
        reg.clear();
        assert_eq!(reg.voter_count(), 0);
        assert!(reg.equivocations().is_empty());
    }
}
