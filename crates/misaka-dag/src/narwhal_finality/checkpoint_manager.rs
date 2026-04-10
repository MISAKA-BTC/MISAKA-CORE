// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Checkpoint manager — coordinates checkpoint creation and finalization.
//!
//! Creates checkpoints at regular intervals, collects votes from validators,
//! and finalizes when quorum is reached.
//!
//! ## CRIT-5 fix: Stake-weighted finality threshold
//!
//! Quorum is checked against aggregate stake (strict >2/3 of total stake),
//! not a simple vote count. `voter_stakes` is passed at construction.

use std::collections::HashMap;
use std::sync::Arc;

use super::{Checkpoint, CheckpointDigest, CheckpointVote, FinalizedCheckpoint};
use crate::narwhal_types::block::SignatureVerifier;

/// Checkpoint interval — create checkpoint every N commits.
pub const CHECKPOINT_INTERVAL: u64 = 100;

/// Manages checkpoint lifecycle.
pub struct CheckpointManager {
    /// Next checkpoint sequence number.
    next_sequence: u64,
    /// Current epoch.
    epoch: u64,
    /// Pending checkpoint (waiting for votes).
    pending: Option<PendingCheckpoint>,
    /// Finalized checkpoints (bounded — keep last N).
    finalized: Vec<FinalizedCheckpoint>,
    /// Maximum finalized checkpoints to keep in memory.
    max_finalized: usize,
    /// Last finalized digest.
    last_digest: CheckpointDigest,
    /// Signature verifier.
    verifier: Arc<dyn SignatureVerifier>,
    /// Voter public keys.
    voter_pubkeys: HashMap<[u8; 32], Vec<u8>>,
    /// Voter stakes keyed by validator identity.
    voter_stakes: HashMap<[u8; 32], u64>,
    /// Total stake across all voters (cached).
    total_stake: u64,
}

/// A checkpoint awaiting votes.
struct PendingCheckpoint {
    checkpoint: Checkpoint,
    votes: Vec<CheckpointVote>,
    voters_seen: HashMap<[u8; 32], ()>,
}

impl CheckpointManager {
    /// Create a new CheckpointManager.
    ///
    /// `voter_stakes` maps each validator identity to its stake weight.
    /// Quorum is strict >2/3 of total stake.
    pub fn new(
        epoch: u64,
        voter_pubkeys: HashMap<[u8; 32], Vec<u8>>,
        verifier: Arc<dyn SignatureVerifier>,
        voter_stakes: HashMap<[u8; 32], u64>,
    ) -> Self {
        // SEC-FIX T3-H4: saturating fold to prevent u64 overflow
        let total_stake: u64 = voter_stakes.values().fold(0u64, |a, &s| a.saturating_add(s));
        Self {
            next_sequence: 0,
            epoch,
            pending: None,
            finalized: Vec::new(),
            max_finalized: 1000,
            last_digest: CheckpointDigest([0; 32]),
            verifier,
            voter_pubkeys,
            voter_stakes,
            total_stake,
        }
    }

    /// Create a new checkpoint.
    ///
    /// Sequence number is only incremented when finalized (not on creation).
    pub fn create_checkpoint(
        &mut self,
        last_committed_round: u64,
        tx_merkle_root: [u8; 32],
        state_root: [u8; 32],
        tx_count: u64,
        timestamp: u64,
    ) -> Checkpoint {
        let cp = Checkpoint {
            epoch: self.epoch,
            sequence: self.next_sequence,
            last_committed_round,
            tx_merkle_root,
            state_root,
            tx_count,
            timestamp,
            previous: self.last_digest,
            digest: CheckpointDigest([0; 32]),
        };

        let digest = cp.compute_digest();
        let cp = Checkpoint { digest, ..cp };

        self.pending = Some(PendingCheckpoint {
            checkpoint: cp.clone(),
            votes: Vec::new(),
            voters_seen: HashMap::new(),
        });

        cp
    }

    /// Add a vote for the pending checkpoint.
    ///
    /// Returns `Some(FinalizedCheckpoint)` if quorum reached.
    /// Sequence number is incremented only on finalization.
    pub fn add_vote(&mut self, vote: CheckpointVote) -> Option<FinalizedCheckpoint> {
        let pending = self.pending.as_mut()?;

        // Check vote is for the correct checkpoint
        if vote.checkpoint_digest != pending.checkpoint.digest {
            return None;
        }

        // Reject duplicate voters
        if pending.voters_seen.contains_key(&vote.voter) {
            return None;
        }

        // Verify voter is in the committee
        let pubkey = match self.voter_pubkeys.get(&vote.voter) {
            Some(pk) => pk.clone(),
            None => return None,
        };

        // Verify signature
        let mut payload = Vec::with_capacity(64 + 11);
        payload.extend_from_slice(b"checkpoint:");
        payload.extend_from_slice(&vote.checkpoint_digest.0);
        payload.extend_from_slice(&vote.voter);
        if self
            .verifier
            .verify(&pubkey, &payload, &vote.signature)
            .is_err()
        {
            return None;
        }

        pending.voters_seen.insert(vote.voter, ());
        pending.votes.push(vote);

        // Check quorum: strict >2/3 of total stake
        // SEC-FIX T3-H4: saturating fold + u128 for multiplication overflow
        let vote_stake: u64 = pending
            .votes
            .iter()
            .filter_map(|v| self.voter_stakes.get(&v.voter))
            .fold(0u64, |a, &s| a.saturating_add(s));
        if (vote_stake as u128) * 3 > (self.total_stake as u128) * 2 {
            let finalized = FinalizedCheckpoint {
                checkpoint: pending.checkpoint.clone(),
                votes: pending.votes.clone(),
            };
            self.last_digest = pending.checkpoint.digest;

            // Only increment sequence on successful finalization
            self.next_sequence += 1;

            // Store with bounded memory
            self.finalized.push(finalized.clone());
            if self.finalized.len() > self.max_finalized {
                self.finalized.remove(0);
            }

            self.pending = None;
            Some(finalized)
        } else {
            None
        }
    }

    /// Whether a checkpoint is pending votes.
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Number of votes on pending checkpoint.
    pub fn pending_vote_count(&self) -> usize {
        self.pending.as_ref().map(|p| p.votes.len()).unwrap_or(0)
    }

    /// Number of finalized checkpoints.
    pub fn num_finalized(&self) -> usize {
        self.finalized.len()
    }

    /// Last finalized checkpoint.
    pub fn last_finalized(&self) -> Option<&FinalizedCheckpoint> {
        self.finalized.last()
    }

    /// Next sequence number.
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Total stake across all voters.
    pub fn total_stake(&self) -> u64 {
        self.total_stake
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::narwhal_types::block::PermissiveVerifier;

    fn test_manager(num_voters: u8) -> CheckpointManager {
        let mut pubkeys = HashMap::new();
        let mut stakes = HashMap::new();
        for i in 0..num_voters {
            pubkeys.insert([i; 32], vec![0xAA; 1952]);
            // Equal stake per voter (1 unit each)
            stakes.insert([i; 32], 1u64);
        }
        // TODO(CR-1 follow-up): vote signatures in these tests use dummy bytes;
        // real ML-DSA-65 signing is needed if signature verification paths are tested.
        CheckpointManager::new(0, pubkeys, Arc::new(PermissiveVerifier), stakes)
    }

    #[test]
    fn test_checkpoint_lifecycle_sr15() {
        let mut mgr = test_manager(15);
        // SR15: with equal stake=1, total_stake=15, need >10 stake => 11 votes
        assert_eq!(mgr.total_stake(), 15);

        let cp = mgr.create_checkpoint(100, [1; 32], [2; 32], 500, 1000);
        assert!(mgr.has_pending());
        assert_eq!(mgr.pending_vote_count(), 0);
        // Sequence not yet incremented
        assert_eq!(mgr.next_sequence(), 0);

        // Need 11 votes (11*3=33 > 15*2=30)
        for i in 0..11u8 {
            let vote = CheckpointVote {
                voter: [i; 32],
                checkpoint_digest: cp.digest,
                signature: vec![0xAA; 64],
            };
            let result = mgr.add_vote(vote);
            if i < 10 {
                assert!(result.is_none());
            } else {
                assert!(result.is_some());
            }
        }

        assert!(!mgr.has_pending());
        assert_eq!(mgr.num_finalized(), 1);
        // Sequence incremented after finalization
        assert_eq!(mgr.next_sequence(), 1);
    }

    #[test]
    fn test_checkpoint_lifecycle_sr21() {
        let mut mgr = test_manager(21);
        // SR21: with equal stake=1, total_stake=21, need >14 stake => 15 votes
        assert_eq!(mgr.total_stake(), 21);

        let cp = mgr.create_checkpoint(100, [1; 32], [2; 32], 500, 1000);

        // Need 15 votes (15*3=45 > 21*2=42)
        for i in 0..15u8 {
            let vote = CheckpointVote {
                voter: [i; 32],
                checkpoint_digest: cp.digest,
                signature: vec![0xAA; 64],
            };
            let result = mgr.add_vote(vote);
            if i < 14 {
                assert!(result.is_none());
            } else {
                assert!(result.is_some());
            }
        }
        assert_eq!(mgr.num_finalized(), 1);
    }

    #[test]
    fn test_duplicate_voter_rejected() {
        let mut mgr = test_manager(15);
        let cp = mgr.create_checkpoint(100, [1; 32], [2; 32], 500, 1000);

        let vote = CheckpointVote {
            voter: [0; 32],
            checkpoint_digest: cp.digest,
            signature: vec![0xAA; 64],
        };
        assert!(mgr.add_vote(vote.clone()).is_none());
        assert!(mgr.add_vote(vote).is_none()); // duplicate
        assert_eq!(mgr.pending_vote_count(), 1);
    }

    #[test]
    fn test_wrong_digest_rejected() {
        let mut mgr = test_manager(15);
        let _cp = mgr.create_checkpoint(100, [1; 32], [2; 32], 500, 1000);

        let vote = CheckpointVote {
            voter: [0; 32],
            checkpoint_digest: CheckpointDigest([0xFF; 32]),
            signature: vec![0xAA; 64],
        };
        assert!(mgr.add_vote(vote).is_none());
        assert_eq!(mgr.pending_vote_count(), 0);
    }

    #[test]
    fn test_unknown_voter_rejected() {
        let mut mgr = test_manager(3);
        let cp = mgr.create_checkpoint(100, [1; 32], [2; 32], 500, 1000);

        let vote = CheckpointVote {
            voter: [99; 32],
            checkpoint_digest: cp.digest,
            signature: vec![0xAA; 64],
        };
        assert!(mgr.add_vote(vote).is_none());
        assert_eq!(mgr.pending_vote_count(), 0);
    }

    #[test]
    fn test_sequence_only_increments_on_finalization() {
        let mut mgr = test_manager(4); // threshold = 3

        // Create checkpoint but don't finalize
        let _cp = mgr.create_checkpoint(100, [1; 32], [2; 32], 500, 1000);
        assert_eq!(mgr.next_sequence(), 0); // NOT incremented

        // Create another checkpoint (overwrites pending)
        let cp2 = mgr.create_checkpoint(200, [3; 32], [4; 32], 600, 2000);
        assert_eq!(mgr.next_sequence(), 0); // Still 0

        // Finalize cp2
        for i in 0..3u8 {
            mgr.add_vote(CheckpointVote {
                voter: [i; 32],
                checkpoint_digest: cp2.digest,
                signature: vec![0xAA; 64],
            });
        }
        assert_eq!(mgr.next_sequence(), 1); // Now 1
    }
}
