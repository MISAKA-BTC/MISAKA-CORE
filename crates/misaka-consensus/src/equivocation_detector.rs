// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Equivocation detection for consensus voting (finality layer).
//!
//! HI-3 fix: The old commit_finalizer used `HashSet::insert()` for
//! duplicate detection, which silently dropped conflicting votes.
//! This module stores per-voter evidence and permanently bans equivocators.
//!
//! Uses `EquivocationEvidence` from `misaka-types` for cross-layer compatibility.

use misaka_types::equivocation::{AuthorityIndex, EquivocationEvidence, EquivocationLayer};
use std::collections::{HashMap, HashSet};

/// Voting slot — identifies a unique voting position (epoch + round).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VoteSlot {
    pub epoch: u64,
    pub round: u64,
}

impl VoteSlot {
    pub fn new(epoch: u64, round: u64) -> Self {
        Self { epoch, round }
    }

    /// Legacy slot representation for gc/valid_voters_for_slot.
    pub fn as_u64(&self) -> u64 {
        self.round
    }
}

impl From<u64> for VoteSlot {
    fn from(round: u64) -> Self {
        Self { epoch: 0, round }
    }
}

/// A signed vote for equivocation tracking.
///
/// CR-3 fix: Uses `block_id` (canonical hash including parents) instead of
/// `payload_digest` alone. This catches same-payload-different-parents attacks.
#[derive(Clone, Debug)]
pub struct SignedVote {
    pub voter: AuthorityIndex,
    /// Slot — identifies the voting position (epoch + round).
    pub slot: VoteSlot,
    /// Canonical block hash (includes parents, epoch, author, payload).
    /// This is the primary identity for equivocation comparison.
    pub block_id: [u8; 32],
    /// Raw signature bytes (for evidence preservation).
    pub signature: Vec<u8>,
}

/// Result of adding a vote to the detector.
#[derive(Debug)]
#[must_use]
pub enum AddVoteResult {
    /// First vote from this voter for this slot. Accepted.
    Accepted,
    /// Same vote already seen (idempotent). Safe to ignore.
    Duplicate,
    /// Conflicting vote detected. Voter banned, evidence stored.
    Equivocation(EquivocationEvidence),
    /// Voter is already banned from a previous equivocation. Vote rejected.
    Banned,
}

/// Equivocation detector for finality votes.
///
/// CR-3 fix: Detects when a voter submits conflicting votes for the same slot.
/// Comparison uses `block_id` (canonical hash including parents), NOT payload_digest.
/// This catches same-payload-different-parents equivocation attacks.
///
/// Evidence is preserved for governance. Voters are permanently banned.
pub struct EquivocationDetector {
    /// (voter, slot) → first observed vote (for comparison and evidence).
    seen: HashMap<(AuthorityIndex, VoteSlot), SignedVote>,
    /// Accumulated evidence.
    evidence: Vec<EquivocationEvidence>,
    /// Permanently banned voters.
    banned: HashSet<AuthorityIndex>,
}

impl EquivocationDetector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: HashMap::new(),
            evidence: Vec::new(),
            banned: HashSet::new(),
        }
    }

    /// Add a vote. Returns the result of the check.
    ///
    /// Pre-condition: caller MUST have verified `vote.signature` with `verify_vote`
    /// before calling this method. The detector does not re-verify signatures.
    ///
    /// CR-3: Compares on `block_id` (canonical hash), not `payload_digest`.
    /// Same payload with different parents → different block_id → Equivocation.
    pub fn add_vote(&mut self, vote: SignedVote) -> AddVoteResult {
        if self.banned.contains(&vote.voter) {
            return AddVoteResult::Banned;
        }

        let key = (vote.voter, vote.slot);
        match self.seen.get(&key) {
            None => {
                self.seen.insert(key, vote);
                AddVoteResult::Accepted
            }
            Some(existing) if existing.block_id == vote.block_id => {
                // Exact same block — idempotent duplicate
                AddVoteResult::Duplicate
            }
            Some(existing) => {
                // EQUIVOCATION: same voter, same slot, different block_id.
                // This catches both:
                //   1. Different payload (obviously different blocks)
                //   2. Same payload but different parents (CR-3 attack)
                let evidence = EquivocationEvidence::new(
                    vote.voter,
                    EquivocationLayer::FinalityVote,
                    vote.slot.as_u64(),
                    existing.signature.clone(),
                    vote.signature.clone(),
                );
                self.evidence.push(evidence.clone());
                self.banned.insert(vote.voter);
                AddVoteResult::Equivocation(evidence)
            }
        }
    }

    /// Check if a voter is banned.
    #[must_use]
    pub fn is_banned(&self, voter: AuthorityIndex) -> bool {
        self.banned.contains(&voter)
    }

    /// All accumulated evidence.
    #[must_use]
    pub fn evidence(&self) -> &[EquivocationEvidence] {
        &self.evidence
    }

    /// Number of banned voters.
    #[must_use]
    pub fn banned_count(&self) -> usize {
        self.banned.len()
    }

    /// Valid (non-banned) voters who voted for a specific round.
    /// SEC-FIX TM-3: Sort output for deterministic ordering across validators.
    #[must_use]
    pub fn valid_voters_for_slot(&self, slot: u64) -> Vec<AuthorityIndex> {
        let mut voters: Vec<AuthorityIndex> = self
            .seen
            .iter()
            .filter_map(|((voter, s), _)| {
                if s.as_u64() == slot && !self.banned.contains(voter) {
                    Some(*voter)
                } else {
                    None
                }
            })
            .collect();
        voters.sort_unstable();
        voters
    }

    /// Restore banned set from persistent storage (for crash recovery).
    pub fn restore_bans(&mut self, banned_voters: impl IntoIterator<Item = AuthorityIndex>) {
        for voter in banned_voters {
            self.banned.insert(voter);
        }
    }

    /// Get the banned set (for persistence).
    #[must_use]
    pub fn banned_set(&self) -> &HashSet<AuthorityIndex> {
        &self.banned
    }

    /// Prune old slots from the detector (keep only slots with round >= `min_round`).
    ///
    /// This is the primary pruning mechanism (`prune_below` semantics): call
    /// periodically to bound memory by discarding vote records that are no
    /// longer needed for equivocation detection.
    pub fn gc(&mut self, min_round: u64) {
        self.seen.retain(|(_, s), _| s.as_u64() >= min_round);
    }
}

impl Default for EquivocationDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a vote with a given block_id byte.
    fn vote(voter: AuthorityIndex, round: u64, block_id_byte: u8) -> SignedVote {
        SignedVote {
            voter,
            slot: VoteSlot::new(0, round),
            block_id: [block_id_byte; 32],
            signature: vec![voter as u8, round as u8, block_id_byte],
        }
    }

    #[test]
    fn first_vote_accepted() {
        let mut det = EquivocationDetector::new();
        assert!(matches!(
            det.add_vote(vote(0, 1, 0xAA)),
            AddVoteResult::Accepted
        ));
    }

    #[test]
    fn duplicate_vote_is_idempotent() {
        let mut det = EquivocationDetector::new();
        det.add_vote(vote(0, 1, 0xAA));
        assert!(matches!(
            det.add_vote(vote(0, 1, 0xAA)),
            AddVoteResult::Duplicate
        ));
        assert!(!det.is_banned(0));
    }

    #[test]
    fn conflicting_vote_triggers_ban() {
        let mut det = EquivocationDetector::new();
        det.add_vote(vote(5, 10, 0xAA));
        let result = det.add_vote(vote(5, 10, 0xBB)); // different block_id
        assert!(matches!(result, AddVoteResult::Equivocation(_)));
        assert!(det.is_banned(5));
        assert_eq!(det.evidence().len(), 1);
    }

    #[test]
    fn banned_voter_subsequent_votes_rejected() {
        let mut det = EquivocationDetector::new();
        det.add_vote(vote(5, 10, 0xAA));
        det.add_vote(vote(5, 10, 0xBB)); // ban
        assert!(matches!(
            det.add_vote(vote(5, 11, 0xCC)),
            AddVoteResult::Banned
        ));
    }

    #[test]
    fn split_finality_attack_blocked() {
        let mut det = EquivocationDetector::new();
        for v in 0..3 {
            det.add_vote(vote(v, 1, 0xAA));
        }
        det.add_vote(vote(3, 1, 0xAA));
        let r = det.add_vote(vote(3, 1, 0xBB));
        assert!(matches!(r, AddVoteResult::Equivocation(_)));
        assert!(det.is_banned(3));

        let valid = det.valid_voters_for_slot(1);
        assert_eq!(valid.len(), 3);
        assert!(!valid.contains(&3));
    }

    #[test]
    fn restore_bans() {
        let mut det = EquivocationDetector::new();
        det.restore_bans(vec![5, 10]);
        assert!(det.is_banned(5));
        assert!(det.is_banned(10));
        assert!(matches!(
            det.add_vote(vote(5, 1, 0xAA)),
            AddVoteResult::Banned
        ));
    }

    #[test]
    fn gc_removes_old_slots() {
        let mut det = EquivocationDetector::new();
        det.add_vote(vote(0, 5, 0xAA));
        det.add_vote(vote(0, 15, 0xBB));
        det.gc(10);
        assert!(det.valid_voters_for_slot(5).is_empty());
        assert_eq!(det.valid_voters_for_slot(15).len(), 1);
    }

    // ── CR-3 Regression: same payload, different parents ──

    #[test]
    fn cr3_same_payload_different_parents_detected_as_equivocation() {
        let mut det = EquivocationDetector::new();

        // Two blocks with same author/round but different block_id
        // (simulating same payload with different parents)
        let vote_a = SignedVote {
            voter: 5,
            slot: VoteSlot::new(0, 10),
            block_id: [0xAA; 32], // block A (parents: P1, P2)
            signature: vec![1],
        };
        let vote_b = SignedVote {
            voter: 5,
            slot: VoteSlot::new(0, 10),
            block_id: [0xBB; 32], // block B (parents: P1, P3) — different!
            signature: vec![2],
        };

        assert!(matches!(det.add_vote(vote_a), AddVoteResult::Accepted));

        // CR-3 fix: different block_id → Equivocation (not Duplicate)
        let result = det.add_vote(vote_b);
        assert!(
            matches!(result, AddVoteResult::Equivocation(_)),
            "different parents (block_id) must trigger equivocation"
        );
        assert!(det.is_banned(5));
    }

    #[test]
    fn cr3_same_block_id_is_duplicate() {
        let mut det = EquivocationDetector::new();

        let v1 = SignedVote {
            voter: 3,
            slot: VoteSlot::new(0, 5),
            block_id: [0xCC; 32],
            signature: vec![1],
        };
        let v2 = SignedVote {
            voter: 3,
            slot: VoteSlot::new(0, 5),
            block_id: [0xCC; 32], // identical block_id
            signature: vec![2],   // different sig bytes don't matter
        };

        assert!(matches!(det.add_vote(v1), AddVoteResult::Accepted));
        assert!(matches!(det.add_vote(v2), AddVoteResult::Duplicate));
        assert!(!det.is_banned(3));
    }

    #[test]
    fn cr3_different_payload_different_block_id_detected() {
        let mut det = EquivocationDetector::new();

        // Different payload → different block_id → equivocation
        assert!(matches!(
            det.add_vote(vote(7, 20, 0x11)),
            AddVoteResult::Accepted
        ));
        assert!(matches!(
            det.add_vote(vote(7, 20, 0x22)),
            AddVoteResult::Equivocation(_)
        ));
        assert!(det.is_banned(7));
    }
}
