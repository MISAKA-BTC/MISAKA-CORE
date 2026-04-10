// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Epoch management — committee rotation and reconfiguration.
//!
//! Sui equivalent: consensus/core/epoch_manager.rs (~600 lines)
//!
//! Handles epoch transitions:
//! 1. Detect epoch boundary (from finalized checkpoint)
//! 2. Close current epoch (flush state, stop proposing)
//! 3. Load new committee from on-chain configuration
//! 4. Start new epoch with fresh DagState

use std::sync::Arc;
use tracing::{info, warn};

use crate::narwhal_types::block::*;
use crate::narwhal_types::committee::{Authority, Committee};

/// Epoch change trigger.
#[derive(Clone, Debug)]
pub enum EpochChangeTrigger {
    /// Checkpoint at this sequence triggers epoch change.
    CheckpointSequence(u64),
    /// Explicit signal from governance.
    GovernanceSignal { new_epoch: u64 },
    /// After N commits in this epoch.
    CommitCount(u64),
}

/// Pending epoch change.
#[derive(Clone, Debug)]
pub struct PendingEpochChange {
    /// Current epoch.
    pub current_epoch: u64,
    /// New epoch number.
    pub new_epoch: u64,
    /// New committee for the next epoch.
    pub new_committee: Committee,
    /// Round at which the epoch changes.
    pub change_round: Round,
}

/// Epoch manager — coordinates epoch transitions.
pub struct EpochManager {
    /// Current epoch.
    current_epoch: u64,
    /// Current committee.
    current_committee: Committee,
    /// Trigger for next epoch change.
    trigger: Option<EpochChangeTrigger>,
    /// Pending epoch change (waiting to be applied).
    pending_change: Option<PendingEpochChange>,
    /// Commits in current epoch.
    commits_in_epoch: u64,
    /// Whether we're in the epoch change grace period.
    in_grace_period: bool,
    /// Maximum commits before auto epoch change (0 = disabled).
    max_commits_per_epoch: u64,
}

impl EpochManager {
    /// Create a new epoch manager.
    pub fn new(epoch: u64, committee: Committee) -> Self {
        Self {
            current_epoch: epoch,
            current_committee: committee,
            trigger: None,
            pending_change: None,
            commits_in_epoch: 0,
            in_grace_period: false,
            max_commits_per_epoch: 0, // disabled by default
        }
    }

    /// Set the epoch change trigger.
    pub fn set_trigger(&mut self, trigger: EpochChangeTrigger) {
        self.trigger = Some(trigger);
    }

    /// Set maximum commits per epoch (0 = disabled).
    pub fn set_max_commits_per_epoch(&mut self, max: u64) {
        self.max_commits_per_epoch = max;
    }

    /// Notify that a commit was finalized.
    ///
    /// Returns `Some(PendingEpochChange)` if the epoch should transition.
    pub fn on_commit(&mut self, commit_index: u64) -> Option<PendingEpochChange> {
        self.commits_in_epoch += 1;

        // Check trigger
        let should_change = match &self.trigger {
            Some(EpochChangeTrigger::CommitCount(count)) => self.commits_in_epoch >= *count,
            Some(EpochChangeTrigger::CheckpointSequence(seq)) => commit_index >= *seq,
            _ => false,
        };

        // Also check max_commits_per_epoch
        let max_reached =
            self.max_commits_per_epoch > 0 && self.commits_in_epoch >= self.max_commits_per_epoch;

        if (should_change || max_reached) && !self.in_grace_period {
            self.in_grace_period = true;
            info!(
                "Epoch {} ending after {} commits",
                self.current_epoch, self.commits_in_epoch
            );
            // Caller must provide the new committee
            None
        } else {
            None
        }
    }

    /// Prepare epoch change with a new committee.
    pub fn prepare_epoch_change(
        &mut self,
        new_committee: Committee,
        change_round: Round,
    ) -> PendingEpochChange {
        let change = PendingEpochChange {
            current_epoch: self.current_epoch,
            new_epoch: self.current_epoch + 1,
            new_committee,
            change_round,
        };
        self.pending_change = Some(change.clone());
        change
    }

    /// Apply the pending epoch change.
    ///
    /// Resets state for the new epoch. Returns the new committee.
    pub fn apply_epoch_change(&mut self) -> Option<Committee> {
        let change = self.pending_change.take()?;

        info!(
            "Epoch transition: {} -> {} (committee size: {} -> {})",
            self.current_epoch,
            change.new_epoch,
            self.current_committee.size(),
            change.new_committee.size(),
        );

        self.current_epoch = change.new_epoch;
        self.current_committee = change.new_committee.clone();
        self.commits_in_epoch = 0;
        self.in_grace_period = false;
        self.trigger = None;

        Some(change.new_committee)
    }

    /// Current epoch.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Current committee.
    pub fn current_committee(&self) -> &Committee {
        &self.current_committee
    }

    /// Whether an epoch change is pending.
    pub fn has_pending_change(&self) -> bool {
        self.pending_change.is_some()
    }

    /// Whether we're in the grace period.
    pub fn in_grace_period(&self) -> bool {
        self.in_grace_period
    }

    /// Commits in the current epoch.
    pub fn commits_in_epoch(&self) -> u64 {
        self.commits_in_epoch
    }
}

/// Build a committee from validator configurations.
///
/// Used during genesis and epoch transitions.
pub fn build_committee(
    epoch: u64,
    validators: &[(String, Vec<u8>, u64)], // (hostname, public_key, stake)
) -> Committee {
    let authorities: Vec<Authority> = validators
        .iter()
        .map(|(hostname, pk, stake)| Authority {
            hostname: hostname.clone(),
            stake: *stake,
            public_key: pk.clone(),
        })
        .collect();
    Committee::new(epoch, authorities)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_change_by_commit_count() {
        let committee = Committee::new_for_test(4);
        let mut mgr = EpochManager::new(0, committee.clone());
        mgr.set_trigger(EpochChangeTrigger::CommitCount(10));

        // First 9 commits: no change
        for i in 0..9 {
            assert!(mgr.on_commit(i).is_none());
        }
        assert!(!mgr.in_grace_period());

        // 10th commit triggers grace period
        mgr.on_commit(9);
        assert!(mgr.in_grace_period());

        // Prepare and apply
        let new_committee = Committee::new_for_test(6);
        mgr.prepare_epoch_change(new_committee, 100);
        assert!(mgr.has_pending_change());

        let result = mgr.apply_epoch_change();
        assert!(result.is_some());
        assert_eq!(mgr.current_epoch(), 1);
        assert_eq!(mgr.current_committee().size(), 6);
        assert_eq!(mgr.commits_in_epoch(), 0);
        assert!(!mgr.in_grace_period());
    }

    #[test]
    fn test_build_committee() {
        let validators = vec![
            ("v0".to_string(), vec![0u8; 1952], 100),
            ("v1".to_string(), vec![1u8; 1952], 100),
            ("v2".to_string(), vec![2u8; 1952], 100),
        ];
        let committee = build_committee(0, &validators);
        assert_eq!(committee.size(), 3);
        assert_eq!(committee.total_stake(), 300);
        assert_eq!(committee.quorum_threshold(), 201); // Sui: N-f = 300-99 = 201
    }

    #[test]
    fn test_sr15_to_sr21_transition() {
        let sr15 = Committee::new_for_test(15);
        let mut mgr = EpochManager::new(0, sr15);
        mgr.set_trigger(EpochChangeTrigger::CommitCount(1000));

        // Simulate commits
        for i in 0..1000 {
            mgr.on_commit(i);
        }
        assert!(mgr.in_grace_period());

        // Expand to SR21
        let sr21 = Committee::new_for_test(21);
        mgr.prepare_epoch_change(sr21, 500);
        let new_committee = mgr.apply_epoch_change().unwrap();

        assert_eq!(mgr.current_epoch(), 1);
        assert_eq!(new_committee.size(), 21);
        assert_eq!(new_committee.quorum_threshold(), 15); // Sui: N-f = 21-6 = 15
    }
}
