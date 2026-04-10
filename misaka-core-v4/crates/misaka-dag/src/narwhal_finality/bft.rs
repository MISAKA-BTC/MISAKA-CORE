// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! HotStuff-inspired BFT for SR checkpoint voting.
//!
//! All vote signatures are cryptographically verified via the injected
//! `SignatureVerifier` (ML-DSA-65 in production, structural in tests).
//!
//! ## CRIT-1 fix: per-digest vote counting
//!
//! Votes are counted per checkpoint digest, not globally. A quorum of
//! votes for the *same* digest is required to advance phases.
//!
//! ## CRIT-5 fix: dynamic finality threshold
//!
//! `finality_threshold` is passed at construction time from
//! `committee.quorum_threshold()`. No more hardcoded constant.

use super::Checkpoint;
use crate::narwhal_types::block::SignatureVerifier;
use crate::narwhal_types::committee::Stake;
use misaka_types::intent::{AppId, IntentMessage, IntentScope};
use misaka_types::intent_payloads::{BftPrevotePayload, BftPrecommitPayload};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[cfg(test)]
use super::CheckpointDigest;

#[derive(Debug, Clone, PartialEq)]
pub enum BftPhase {
    Propose,
    Prevote,
    Precommit,
    Committed,
}

#[derive(Clone, Debug)]
pub struct VoteEquivocation {
    pub voter: [u8; 32],
    pub phase: String,
    pub digest_a: [u8; 32],
    pub digest_b: [u8; 32],
}

pub struct BftRound {
    pub phase: BftPhase,
    pub checkpoint: Option<Checkpoint>,
    /// Per-digest prevote tracking: digest -> (voter -> signature).
    prevotes_by_digest: HashMap<[u8; 32], HashMap<[u8; 32], Vec<u8>>>,
    /// Per-digest precommit tracking: digest -> (voter -> signature).
    precommits_by_digest: HashMap<[u8; 32], HashMap<[u8; 32], Vec<u8>>>,
    /// Track which checkpoint digest each voter prevoted for (equivocation detection).
    prevote_digests: HashMap<[u8; 32], [u8; 32]>,
    precommit_digests: HashMap<[u8; 32], [u8; 32]>,
    /// Detected vote equivocations.
    pub vote_equivocations: Vec<VoteEquivocation>,
    /// Voter public keys: voter_id (32 bytes) -> ML-DSA-65 public key.
    voter_pubkeys: HashMap<[u8; 32], Vec<u8>>,
    /// Cryptographic signature verifier.
    verifier: Arc<dyn SignatureVerifier>,
    /// Dynamic finality threshold (stake-weighted) — from committee.quorum_threshold().
    finality_threshold: Stake,
    /// Stake weight per voter.
    voter_stakes: HashMap<[u8; 32], Stake>,
    /// The digest that reached prevote quorum (locked value).
    locked_prevote_digest: Option<[u8; 32]>,
    /// Chain context for domain-separated signing payloads.
    chain_id: u32,
    /// Phase 2b: AppId for IntentMessage-based signing.
    app_id: AppId,
    epoch: u64,
    round: u64,
    /// Voters caught equivocating — permanently excluded from this round.
    blacklisted_voters: HashSet<[u8; 32]>,
}

impl BftRound {
    /// Create a new BFT round.
    ///
    /// `finality_threshold` must be `committee.quorum_threshold()` (> 2/3 of total stake).
    ///
    /// SEC-FIX T3-C1: Returns `Err` if BFT safety invariant is violated.
    /// Previous version logged an error but continued, which could allow
    /// finality to advance without the required BFT overlap.
    pub fn try_new(
        voter_pubkeys: HashMap<[u8; 32], Vec<u8>>,
        verifier: Arc<dyn SignatureVerifier>,
        voter_stakes: HashMap<[u8; 32], Stake>,
        finality_threshold: Stake,
        chain_id: u32,
        epoch: u64,
        round: u64,
        genesis_hash: [u8; 32],
    ) -> Result<Self, String> {
        let app_id = AppId::new(chain_id, genesis_hash);
        // SEC-FIX T3-C1 + T3-H10: Use saturating fold instead of .sum()
        let total_stake: u64 = voter_stakes.values().fold(0u64, |a, &s| a.saturating_add(s));
        if total_stake > 0 {
            let f = (total_stake - 1) / 3;
            // Use u128 to prevent overflow in the check itself
            let effective_quorum = finality_threshold as u128 + 1;
            let rhs = total_stake as u128 + f as u128;
            if 2 * effective_quorum <= rhs {
                return Err(format!(
                    "BFT SAFETY VIOLATION: 2*Q={} must be > total+f={} \
                     (threshold={}, total={}, f={})",
                    2 * effective_quorum, rhs, finality_threshold, total_stake, f
                ));
            }
        }
        Ok(Self {
            phase: BftPhase::Propose,
            checkpoint: None,
            prevotes_by_digest: HashMap::new(),
            precommits_by_digest: HashMap::new(),
            prevote_digests: HashMap::new(),
            precommit_digests: HashMap::new(),
            vote_equivocations: Vec::new(),
            voter_pubkeys,
            verifier,
            finality_threshold,
            voter_stakes,
            locked_prevote_digest: None,
            chain_id,
            app_id,
            epoch,
            round,
            blacklisted_voters: HashSet::new(),
        })
    }

    /// Convenience wrapper that panics on BFT invariant violation.
    /// Prefer `try_new` in production paths.
    pub fn new(
        voter_pubkeys: HashMap<[u8; 32], Vec<u8>>,
        verifier: Arc<dyn SignatureVerifier>,
        voter_stakes: HashMap<[u8; 32], Stake>,
        finality_threshold: Stake,
        chain_id: u32,
        epoch: u64,
        round: u64,
        genesis_hash: [u8; 32],
    ) -> Self {
        Self::try_new(
            voter_pubkeys, verifier, voter_stakes, finality_threshold,
            chain_id, epoch, round, genesis_hash,
        )
        .expect("BFT safety invariant violated — cannot construct BftRound")
    }

    pub fn propose(&mut self, checkpoint: Checkpoint) {
        self.checkpoint = Some(checkpoint);
        self.phase = BftPhase::Prevote;
    }

    /// Add a prevote. Returns true if this vote caused the phase to advance to Precommit.
    ///
    /// Quorum is checked per-digest using stake weights: only votes for the SAME
    /// checkpoint_digest count toward the threshold.
    pub fn add_prevote(
        &mut self,
        voter: [u8; 32],
        signature: Vec<u8>,
        checkpoint_digest: [u8; 32],
    ) -> bool {
        if self.phase != BftPhase::Prevote {
            return false;
        }

        // Blacklisted equivocators are permanently excluded
        if self.blacklisted_voters.contains(&voter) {
            return false;
        }

        let pubkey = match self.voter_pubkeys.get(&voter) {
            Some(pk) => pk.clone(),
            None => return false,
        };

        // Phase 2b: IntentMessage-based signature verification
        let payload = BftPrevotePayload {
            epoch: self.epoch,
            round: self.round,
            checkpoint_digest,
            voter,
        };
        let intent = IntentMessage::wrap(
            IntentScope::BftPrevote,
            self.app_id.clone(),
            &payload,
        );
        let digest = intent.signing_digest();
        if self.verifier.verify(&pubkey, &digest, &signature).is_err() {
            return false;
        }

        // Equivocation detection
        if let Some(prev_digest) = self.prevote_digests.get(&voter) {
            if *prev_digest != checkpoint_digest {
                // Record evidence
                self.vote_equivocations.push(VoteEquivocation {
                    voter,
                    phase: "prevote".to_string(),
                    digest_a: *prev_digest,
                    digest_b: checkpoint_digest,
                });
                // CRITICAL: Remove first vote too (no-double-count)
                let prev = *prev_digest;
                if let Some(votes) = self.prevotes_by_digest.get_mut(&prev) {
                    votes.remove(&voter);
                }
                // Add to round blacklist
                self.blacklisted_voters.insert(voter);
                return false; // Reject equivocating vote
            }
            return false; // Duplicate, already counted
        }

        self.prevote_digests.insert(voter, checkpoint_digest);

        // Insert into per-digest prevote map
        let digest_votes = self
            .prevotes_by_digest
            .entry(checkpoint_digest)
            .or_default();
        digest_votes.insert(voter, signature);

        // SEC-FIX T3-H10: saturating fold to prevent u64 overflow
        let stake_sum: u64 = digest_votes
            .keys()
            .filter_map(|v| self.voter_stakes.get(v))
            .fold(0u64, |a, &s| a.saturating_add(s));
        if stake_sum > self.finality_threshold {
            self.locked_prevote_digest = Some(checkpoint_digest);
            self.phase = BftPhase::Precommit;
            return true;
        }
        false
    }

    /// Add a precommit. Returns true if this vote caused finalization (Committed).
    ///
    /// Precommit votes must be for the locked prevote digest.
    /// Quorum is checked per-digest using stake weights.
    pub fn add_precommit(
        &mut self,
        voter: [u8; 32],
        signature: Vec<u8>,
        checkpoint_digest: [u8; 32],
    ) -> bool {
        if self.phase != BftPhase::Precommit {
            return false;
        }

        // Blacklisted equivocators are permanently excluded
        if self.blacklisted_voters.contains(&voter) {
            return false;
        }

        // Precommit must be for the locked digest
        if let Some(locked) = self.locked_prevote_digest {
            if checkpoint_digest != locked {
                return false; // Reject precommit for non-locked digest
            }
        }

        let pubkey = match self.voter_pubkeys.get(&voter) {
            Some(pk) => pk.clone(),
            None => return false,
        };

        // Phase 2b: IntentMessage-based signature verification
        let payload = BftPrecommitPayload {
            epoch: self.epoch,
            round: self.round,
            checkpoint_digest,
            voter,
        };
        let intent = IntentMessage::wrap(
            IntentScope::BftPrecommit,
            self.app_id.clone(),
            &payload,
        );
        let digest = intent.signing_digest();
        if self.verifier.verify(&pubkey, &digest, &signature).is_err() {
            return false;
        }

        // Equivocation detection
        if let Some(prev_digest) = self.precommit_digests.get(&voter) {
            if *prev_digest != checkpoint_digest {
                // Record evidence
                self.vote_equivocations.push(VoteEquivocation {
                    voter,
                    phase: "precommit".to_string(),
                    digest_a: *prev_digest,
                    digest_b: checkpoint_digest,
                });
                // CRITICAL: Remove first vote too (no-double-count)
                let prev = *prev_digest;
                if let Some(votes) = self.precommits_by_digest.get_mut(&prev) {
                    votes.remove(&voter);
                }
                // Add to round blacklist
                self.blacklisted_voters.insert(voter);
                return false;
            }
            return false; // Duplicate
        }

        self.precommit_digests.insert(voter, checkpoint_digest);

        // Insert into per-digest precommit map
        let digest_votes = self
            .precommits_by_digest
            .entry(checkpoint_digest)
            .or_default();
        digest_votes.insert(voter, signature);

        // SEC-FIX T3-H10: saturating fold to prevent u64 overflow
        let stake_sum: u64 = digest_votes
            .keys()
            .filter_map(|v| self.voter_stakes.get(v))
            .fold(0u64, |a, &s| a.saturating_add(s));
        if stake_sum > self.finality_threshold {
            self.phase = BftPhase::Committed;
            return true;
        }
        false
    }

    pub fn is_committed(&self) -> bool {
        self.phase == BftPhase::Committed
    }

    /// Get the number of prevotes for a specific digest.
    pub fn prevote_count_for_digest(&self, digest: &[u8; 32]) -> usize {
        self.prevotes_by_digest
            .get(digest)
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// Get the number of precommits for a specific digest.
    pub fn precommit_count_for_digest(&self, digest: &[u8; 32]) -> usize {
        self.precommits_by_digest
            .get(digest)
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// Total number of unique prevote voters (across all digests).
    pub fn total_prevote_count(&self) -> usize {
        self.prevote_digests.len()
    }

    /// Finality threshold used by this round (stake-weighted).
    pub fn finality_threshold(&self) -> Stake {
        self.finality_threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::narwhal_types::block::PermissiveVerifier;

    fn test_bft_round(num_voters: u8) -> BftRound {
        let mut pubkeys = HashMap::new();
        let mut stakes = HashMap::new();
        for i in 0..num_voters {
            pubkeys.insert([i; 32], vec![0xAA; 1952]);
            stakes.insert([i; 32], 1u64); // uniform stake of 1 per voter
        }
        // Sui-aligned quorum: N - floor((N-1)/3)
        // SR15: 15 - 4 = 11;  SR21: 21 - 6 = 15
        // With uniform stake=1, total_stake == N, threshold in stake units.
        // strict > means we need threshold = N - f - 1 to pass with N - f votes.
        let n = num_voters as u64;
        let f = if n == 0 { 0 } else { (n - 1) / 3 };
        let threshold = n - f - 1; // strict >: n-f votes pass when stake_sum (n-f) > threshold (n-f-1)
                                   // TODO(CR-1 follow-up): vote signatures in these tests use dummy bytes;
                                   // real ML-DSA-65 signing is needed if signature verification paths are tested.
        BftRound::new(
            pubkeys,
            Arc::new(PermissiveVerifier),
            stakes,
            threshold,
            0,
            0,
            0,
            [0u8; 32], // test fixture: zero genesis hash
        )
    }

    #[test]
    fn test_bft_full_flow_sr15() {
        let mut round = test_bft_round(15);
        // SR15: n=15, f=4, threshold = 15-4-1 = 10 (strict >: 11 votes with stake 11 > 10)
        assert_eq!(round.finality_threshold(), 10);

        let cp = Checkpoint {
            epoch: 0,
            sequence: 1,
            last_committed_round: 100,
            tx_merkle_root: [1; 32],
            state_root: [2; 32],
            tx_count: 500,
            timestamp: 1000,
            previous: CheckpointDigest([0; 32]),
            digest: CheckpointDigest([3; 32]),
        };
        round.propose(cp.clone());
        assert_eq!(round.phase, BftPhase::Prevote);

        // 11 prevotes for same digest -> advance (stake 11 > threshold 10)
        for i in 0..11u8 {
            let advanced = round.add_prevote([i; 32], vec![0xAA; 64], cp.digest.0);
            if i < 10 {
                assert!(!advanced);
            } else {
                assert!(advanced);
            }
        }
        assert_eq!(round.phase, BftPhase::Precommit);
        assert_eq!(round.prevote_count_for_digest(&cp.digest.0), 11);

        // 11 precommits -> commit
        for i in 0..11u8 {
            let committed = round.add_precommit([i; 32], vec![0xBB; 64], cp.digest.0);
            if i < 10 {
                assert!(!committed);
            } else {
                assert!(committed);
            }
        }
        assert!(round.is_committed());
    }

    #[test]
    fn test_bft_full_flow_sr21() {
        let mut round = test_bft_round(21);
        // SR21: n=21, f=6, threshold = 21-6-1 = 14 (strict >: 15 votes with stake 15 > 14)
        assert_eq!(round.finality_threshold(), 14);

        let cp = Checkpoint {
            epoch: 0,
            sequence: 1,
            last_committed_round: 100,
            tx_merkle_root: [1; 32],
            state_root: [2; 32],
            tx_count: 500,
            timestamp: 1000,
            previous: CheckpointDigest([0; 32]),
            digest: CheckpointDigest([3; 32]),
        };
        round.propose(cp.clone());

        // Need 15 prevotes for SR21 (stake 15 > threshold 14)
        for i in 0..15u8 {
            let advanced = round.add_prevote([i; 32], vec![0xAA; 64], cp.digest.0);
            if i < 14 {
                assert!(!advanced);
            } else {
                assert!(advanced);
            }
        }
        assert_eq!(round.phase, BftPhase::Precommit);

        for i in 0..15u8 {
            let committed = round.add_precommit([i; 32], vec![0xBB; 64], cp.digest.0);
            if i < 14 {
                assert!(!committed);
            } else {
                assert!(committed);
            }
        }
        assert!(round.is_committed());
    }

    #[test]
    fn test_split_votes_do_not_reach_quorum() {
        // CRIT-1 regression test: split votes must NOT advance phase
        let mut round = test_bft_round(15); // threshold = 10

        let cp = Checkpoint {
            epoch: 0,
            sequence: 1,
            last_committed_round: 100,
            tx_merkle_root: [1; 32],
            state_root: [2; 32],
            tx_count: 500,
            timestamp: 1000,
            previous: CheckpointDigest([0; 32]),
            digest: CheckpointDigest([3; 32]),
        };
        round.propose(cp);

        let digest_a = [0x11; 32];
        let digest_b = [0x22; 32];

        // 5 votes for digest A
        for i in 0..5u8 {
            let advanced = round.add_prevote([i; 32], vec![0xAA; 64], digest_a);
            assert!(!advanced);
        }
        // 5 votes for digest B (different voters)
        for i in 5..10u8 {
            let advanced = round.add_prevote([i; 32], vec![0xAA; 64], digest_b);
            assert!(!advanced);
        }

        // 10 total votes but split — must NOT advance
        assert_eq!(round.phase, BftPhase::Prevote);
        assert_eq!(round.total_prevote_count(), 10);
        assert_eq!(round.prevote_count_for_digest(&digest_a), 5);
        assert_eq!(round.prevote_count_for_digest(&digest_b), 5);
    }

    #[test]
    fn test_precommit_rejects_non_locked_digest() {
        let mut round = test_bft_round(4); // threshold = 2 (strict >: 3 votes with stake 3 > 2)

        let cp = Checkpoint {
            epoch: 0,
            sequence: 1,
            last_committed_round: 100,
            tx_merkle_root: [1; 32],
            state_root: [2; 32],
            tx_count: 500,
            timestamp: 1000,
            previous: CheckpointDigest([0; 32]),
            digest: CheckpointDigest([3; 32]),
        };
        round.propose(cp.clone());

        // 3 prevotes for cp.digest -> advance to Precommit (stake 3 > threshold 2)
        for i in 0..3u8 {
            round.add_prevote([i; 32], vec![0xAA; 64], cp.digest.0);
        }
        assert_eq!(round.phase, BftPhase::Precommit);

        // Try to precommit for a DIFFERENT digest -> rejected
        let wrong_digest = [0xFF; 32];
        let rejected = round.add_precommit([0; 32], vec![0xBB; 64], wrong_digest);
        assert!(!rejected);
        assert_eq!(round.precommit_count_for_digest(&wrong_digest), 0);
    }

    #[test]
    fn test_bft_vote_equivocation_detected() {
        let mut round = test_bft_round(21);
        let cp = Checkpoint {
            epoch: 0,
            sequence: 1,
            last_committed_round: 100,
            tx_merkle_root: [1; 32],
            state_root: [2; 32],
            tx_count: 500,
            timestamp: 1000,
            previous: CheckpointDigest([0; 32]),
            digest: CheckpointDigest([3; 32]),
        };
        round.propose(cp);

        round.add_prevote([1; 32], vec![0xAA; 64], [0x11; 32]);
        round.add_prevote([1; 32], vec![0xBB; 64], [0x22; 32]);

        assert_eq!(round.vote_equivocations.len(), 1);
        assert_eq!(round.vote_equivocations[0].voter, [1; 32]);
        // Fix 4: equivocator's first vote should be removed
        assert_eq!(round.prevote_count_for_digest(&[0x11; 32]), 0);
        // Fix 4: equivocator should be blacklisted (third attempt rejected silently)
        let rejected = round.add_prevote([1; 32], vec![0xCC; 64], [0x33; 32]);
        assert!(!rejected);
        assert_eq!(round.vote_equivocations.len(), 1); // no new equivocation recorded
    }

    #[test]
    fn test_unknown_voter_rejected() {
        let mut round = test_bft_round(3);
        let cp = Checkpoint {
            epoch: 0,
            sequence: 1,
            last_committed_round: 100,
            tx_merkle_root: [1; 32],
            state_root: [2; 32],
            tx_count: 500,
            timestamp: 1000,
            previous: CheckpointDigest([0; 32]),
            digest: CheckpointDigest([3; 32]),
        };
        round.propose(cp.clone());

        let result = round.add_prevote([99; 32], vec![0xAA; 64], cp.digest.0);
        assert!(!result);
        assert_eq!(round.total_prevote_count(), 0);
    }
}
