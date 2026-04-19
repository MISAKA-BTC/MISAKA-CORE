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

/// Default checkpoint creation cadence in committed-round units.
///
/// Retained as a `pub const` for backward compatibility — it has been
/// the sole cadence constant in prior releases. New code should
/// construct a [`CheckpointTrigger`] and pass it via
/// [`CheckpointManager::with_trigger`].
///
/// v0.8.9 (Phase 0.5a): lowered 100 → 20 alongside the
/// `FAST_LANE_BLOCK_TIME_SECS: 2 → 10` change to preserve the
/// ~200 s wall-clock checkpoint cadence. This is a raw commit
/// counter (not derived via `fast_depth`); folding it into the
/// `fast_depth(TIME_200_SECS)` family is left as a Phase 2
/// retrofit — cf. docs/investigations/round-interval-10s-impact.md.
pub const CHECKPOINT_INTERVAL: u64 = 20;

/// What counter drives consensus-level checkpoint creation.
///
/// Phase 2 Path X R4 promotes the pre-v0.9.0 hardcoded
/// `CHECKPOINT_INTERVAL = 100` (committed rounds) into a runtime
/// choice. Current variants:
///
/// * [`CheckpointTrigger::CommitInterval`] — checkpoint every N
///   committed rounds. This is the legacy behaviour and remains the
///   default.
/// * [`CheckpointTrigger::RoundInterval`] — same arithmetic as
///   `CommitInterval`; distinct variant for callers that want to
///   express "rounds" semantics explicitly.
/// * [`CheckpointTrigger::EpochBoundary`] — checkpoint at each
///   epoch boundary. **Not yet wired**: the finality-side manager
///   does not currently have direct access to epoch transitions.
///   Until wired, `EpochBoundary` falls back to
///   `CommitInterval(CHECKPOINT_INTERVAL)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointTrigger {
    /// Checkpoint every N committed rounds.
    CommitInterval(u64),
    /// Checkpoint every N rounds (same as `CommitInterval`; distinct
    /// variant so callers can express intent).
    RoundInterval(u64),
    /// Checkpoint at each epoch boundary. Falls back to
    /// `CommitInterval(CHECKPOINT_INTERVAL)` until the epoch subsystem
    /// is wired into this manager.
    EpochBoundary,
}

impl Default for CheckpointTrigger {
    /// Preserves the legacy behaviour — checkpoint every
    /// [`CHECKPOINT_INTERVAL`] committed rounds.
    fn default() -> Self {
        Self::CommitInterval(CHECKPOINT_INTERVAL)
    }
}

impl CheckpointTrigger {
    /// How many committed-round ticks must elapse between checkpoints
    /// under this trigger. `EpochBoundary` degrades to the default
    /// interval until the epoch subsystem is wired.
    #[must_use]
    pub const fn ticks_between(self) -> u64 {
        match self {
            Self::CommitInterval(n) | Self::RoundInterval(n) => n,
            Self::EpochBoundary => CHECKPOINT_INTERVAL,
        }
    }
}

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
    /// Committed round at which the last checkpoint was *created*
    /// (set by [`create_checkpoint`] every time it runs). Used by
    /// [`should_checkpoint`] to pace new checkpoints. Starts at 0 so
    /// the first `should_checkpoint(round)` call returns `true` once
    /// `round >= trigger.ticks_between()` — matching the pre-refactor
    /// convention where the first checkpoint landed at round
    /// `CHECKPOINT_INTERVAL`.
    last_checkpoint_round: u64,
    /// Trigger that gates [`should_checkpoint`]. Defaults to
    /// `CommitInterval(CHECKPOINT_INTERVAL)`.
    trigger: CheckpointTrigger,
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
        let total_stake: u64 = voter_stakes
            .values()
            .fold(0u64, |a, &s| a.saturating_add(s));
        Self {
            next_sequence: 0,
            epoch,
            pending: None,
            finalized: Vec::new(),
            max_finalized: 1000,
            last_digest: CheckpointDigest([0; 32]),
            last_checkpoint_round: 0,
            trigger: CheckpointTrigger::default(),
            verifier,
            voter_pubkeys,
            voter_stakes,
            total_stake,
        }
    }

    /// Override the trigger that gates [`should_checkpoint`]. Builder style.
    #[must_use]
    pub fn with_trigger(mut self, trigger: CheckpointTrigger) -> Self {
        self.trigger = trigger;
        self
    }

    /// The trigger this manager is currently using.
    #[must_use]
    pub fn trigger(&self) -> CheckpointTrigger {
        self.trigger
    }

    /// Whether a new checkpoint should be created at the given
    /// `last_committed_round`.
    ///
    /// Returns `true` when `last_committed_round` is at least
    /// [`CheckpointTrigger::ticks_between`] ahead of the round at
    /// which the previous checkpoint was created. Callers drive this
    /// from their commit loop and, on `true`, invoke
    /// [`create_checkpoint`] which advances `last_checkpoint_round`.
    ///
    /// This method is side-effect free; sampling it from multiple
    /// threads is safe as long as the caller holds the manager's
    /// mutex while deciding whether to call [`create_checkpoint`].
    #[must_use]
    pub fn should_checkpoint(&self, last_committed_round: u64) -> bool {
        last_committed_round >= self.last_checkpoint_round + self.trigger.ticks_between()
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

        // Advance the trigger watermark so that should_checkpoint()
        // does not re-fire until `trigger.ticks_between()` more rounds
        // have been committed. Using `max` guards against the (rare)
        // case where an out-of-order caller passes a stale round.
        self.last_checkpoint_round = self.last_checkpoint_round.max(last_committed_round);

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

    // ── Phase 2 Path X R4 tests: trigger + should_checkpoint ──

    #[test]
    fn default_trigger_is_commit_interval_at_checkpoint_interval() {
        assert_eq!(
            CheckpointTrigger::default(),
            CheckpointTrigger::CommitInterval(CHECKPOINT_INTERVAL)
        );
    }

    #[test]
    fn trigger_ticks_between_matches_variants() {
        assert_eq!(CheckpointTrigger::CommitInterval(50).ticks_between(), 50);
        assert_eq!(CheckpointTrigger::RoundInterval(777).ticks_between(), 777);
        // EpochBoundary falls back to CHECKPOINT_INTERVAL per the
        // "not yet wired" caveat in the variant docs.
        assert_eq!(
            CheckpointTrigger::EpochBoundary.ticks_between(),
            CHECKPOINT_INTERVAL
        );
    }

    #[test]
    fn default_manager_uses_default_trigger() {
        let mgr = test_manager(4);
        assert_eq!(mgr.trigger(), CheckpointTrigger::default());
    }

    #[test]
    fn should_checkpoint_fires_after_interval_with_default_trigger() {
        let mgr = test_manager(4);
        // last_checkpoint_round starts at 0.
        assert!(!mgr.should_checkpoint(CHECKPOINT_INTERVAL - 1));
        assert!(mgr.should_checkpoint(CHECKPOINT_INTERVAL));
        assert!(mgr.should_checkpoint(CHECKPOINT_INTERVAL + 1));
    }

    #[test]
    fn should_checkpoint_respects_custom_commit_interval() {
        let mgr = test_manager(4).with_trigger(CheckpointTrigger::CommitInterval(50));
        assert!(!mgr.should_checkpoint(49));
        assert!(mgr.should_checkpoint(50));
    }

    #[test]
    fn commit_interval_and_round_interval_are_arithmetically_equivalent() {
        let commit_mgr = test_manager(4).with_trigger(CheckpointTrigger::CommitInterval(75));
        let round_mgr = test_manager(4).with_trigger(CheckpointTrigger::RoundInterval(75));
        for r in [0u64, 74, 75, 76, 149, 150] {
            assert_eq!(
                commit_mgr.should_checkpoint(r),
                round_mgr.should_checkpoint(r),
                "CommitInterval and RoundInterval must agree at round={r}"
            );
        }
    }

    #[test]
    fn create_checkpoint_advances_last_checkpoint_round() {
        let mut mgr = test_manager(4).with_trigger(CheckpointTrigger::CommitInterval(100));
        assert!(mgr.should_checkpoint(100));

        mgr.create_checkpoint(100, [1; 32], [2; 32], 500, 1000);

        // After creation, the trigger must not re-fire until 100 more
        // committed rounds elapse.
        assert!(!mgr.should_checkpoint(150));
        assert!(!mgr.should_checkpoint(199));
        assert!(mgr.should_checkpoint(200));
    }

    #[test]
    fn create_checkpoint_with_stale_round_does_not_regress_watermark() {
        let mut mgr = test_manager(4).with_trigger(CheckpointTrigger::CommitInterval(100));
        mgr.create_checkpoint(500, [1; 32], [2; 32], 0, 0);
        // An out-of-order caller passing round=100 should not rewind
        // the watermark; should_checkpoint must still gate on round 500.
        mgr.create_checkpoint(100, [3; 32], [4; 32], 0, 0);
        assert!(!mgr.should_checkpoint(550));
        assert!(mgr.should_checkpoint(600));
    }

    #[test]
    fn epoch_boundary_falls_back_to_checkpoint_interval_until_wired() {
        let mgr = test_manager(4).with_trigger(CheckpointTrigger::EpochBoundary);
        assert!(mgr.should_checkpoint(CHECKPOINT_INTERVAL));
        assert!(!mgr.should_checkpoint(CHECKPOINT_INTERVAL - 1));
    }
}
