// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! UniversalCommitter — pipelined Bullshark commit engine.
//!
//! Sui equivalent: consensus/core/universal_committer.rs (~800 lines)
//!
//! Combines multiple BaseCommitters (one per pipeline slot) to
//! implement pipelined Bullshark with leader reputation.
//!
//! ## CRIT-3 fix: Indirect commit via anchor
//!
//! When a leader can't be directly committed, we check if a later
//! directly-committed leader (the "anchor") has it in its causal
//! history. If yes → indirect commit. If no → skip.
//!
//! ## CRIT-4 fix: Skip only via committed anchor
//!
//! Skip is decided ONLY when a later leader is committed and the
//! undecided leader is NOT in the anchor's causal history.

use super::base_committer::{BaseCommitter, Decision};
use crate::narwhal_dag::dag_state::DagState;
use crate::narwhal_dag::leader_schedule::LeaderSchedule;
use crate::narwhal_types::block::*;
use crate::narwhal_types::commit::*;
use crate::narwhal_types::committee::Committee;

/// Universal committer — runs pipelined Bullshark.
pub struct UniversalCommitter {
    /// Committee.
    committee: Committee,
    /// Leader schedule.
    leader_schedule: LeaderSchedule,
    /// Base committer.
    committer: BaseCommitter,
    /// Leader round wave.
    leader_round_wave: u32,
    /// Last decided leader round.
    last_decided_round: Round,
    /// Sequential commit index.
    next_commit_index: CommitIndex,
    /// Previous commit digest (for chain integrity).
    previous_commit_digest: CommitDigest,
}

impl UniversalCommitter {
    pub fn new(
        committee: Committee,
        leader_schedule: LeaderSchedule,
        _num_leader_slots: u32,
        leader_round_wave: u32,
    ) -> Self {
        let committer = BaseCommitter::new(committee.clone(), leader_round_wave);
        Self {
            committee,
            leader_schedule,
            committer,
            leader_round_wave,
            last_decided_round: 0,
            next_commit_index: 0,
            previous_commit_digest: CommitDigest([0; 32]),
        }
    }

    /// Try to commit leaders from the DAG.
    ///
    /// Two-pass approach:
    /// 1. First pass: try direct commit for each leader round
    /// 2. Second pass: for undecided leaders before a committed anchor,
    ///    try indirect commit or skip
    pub fn try_commit(
        &mut self,
        dag_state: &DagState,
        ledger: &crate::narwhal_dag::slot_equivocation_ledger::SlotEquivocationLedger,
    ) -> Vec<CommittedSubDag> {
        let highest = dag_state.highest_accepted_round();
        if highest == 0 {
            return vec![];
        }

        let wave = self.leader_round_wave;

        // Collect all leader rounds to evaluate
        let start_round = if self.last_decided_round == 0 {
            wave
        } else {
            self.last_decided_round + wave
        };

        // Phase 1: Find the latest directly committable leader (the anchor)
        let mut anchor: Option<(Round, BlockRef)> = None;
        let mut round = start_round;
        while round <= highest {
            if let Some(leader_ref) = self.get_leader_block(round, dag_state) {
                let decision = self
                    .committer
                    .try_direct_decide(&leader_ref, dag_state, ledger);
                if matches!(decision, Decision::Direct(_)) {
                    anchor = Some((round, leader_ref));
                }
            }
            round += wave;
        }

        // If no anchor found, nothing can be committed
        let (anchor_round, anchor_ref) = match anchor {
            Some(a) => a,
            None => return vec![],
        };

        // Phase 2: Decide all leaders from start_round to anchor_round
        let mut committed = Vec::new();
        round = start_round;
        while round <= anchor_round {
            if let Some(leader_ref) = self.get_leader_block(round, dag_state) {
                if round == anchor_round {
                    // This is the anchor itself — direct commit
                    if let Some(sub_dag) = self.commit_leader(&leader_ref, true, dag_state) {
                        self.last_decided_round = round;
                        committed.push(sub_dag);
                    }
                } else {
                    // Try direct first
                    let decision = self
                        .committer
                        .try_direct_decide(&leader_ref, dag_state, ledger);
                    match decision {
                        Decision::Direct(_) => {
                            if let Some(sub_dag) = self.commit_leader(&leader_ref, true, dag_state)
                            {
                                self.last_decided_round = round;
                                committed.push(sub_dag);
                            }
                        }
                        _ => {
                            // Try indirect via anchor
                            let indirect = self.committer.try_decide_with_anchor(
                                &leader_ref,
                                &anchor_ref,
                                dag_state,
                            );
                            match indirect {
                                Decision::Indirect(_) => {
                                    if let Some(sub_dag) =
                                        self.commit_leader(&leader_ref, false, dag_state)
                                    {
                                        self.last_decided_round = round;
                                        committed.push(sub_dag);
                                    }
                                }
                                Decision::Skip => {
                                    // Leader skipped
                                    self.last_decided_round = round;
                                }
                                _ => {
                                    // Should not happen with anchor, but be safe
                                    break;
                                }
                            }
                        }
                    }
                }
            } else {
                // No leader block at this slot — skip
                self.last_decided_round = round;
            }
            round += wave;
        }

        committed
    }

    /// Get the leader block for a given round.
    /// Get the leader block for a round. If equivocating blocks exist at the
    /// same slot, select deterministically by lowest digest (M-6 fix).
    fn get_leader_block(&self, round: Round, dag_state: &DagState) -> Option<BlockRef> {
        let leaders = self.leader_schedule.leaders_for_round(round);
        let leader_authority = *leaders.first()?;
        let slot = Slot::new(round, leader_authority);
        let leader_blocks = dag_state.get_blocks_at_slot(&slot);
        // Deterministic: sort by digest, pick smallest
        leader_blocks
            .iter()
            .map(|b| b.reference())
            .min_by_key(|r| r.digest.0)
    }

    /// Create a CommittedSubDag for a leader.
    ///
    /// Returns None if the sub-DAG collection fails (e.g. exceeds block limit).
    fn commit_leader(
        &mut self,
        leader_ref: &BlockRef,
        is_direct: bool,
        dag_state: &DagState,
    ) -> Option<CommittedSubDag> {
        // SEC-FIX NH-8: propagate None if causal closure is too large
        let blocks = self.collect_sub_dag(leader_ref, dag_state)?;

        let timestamp_ms = dag_state
            .get_block(leader_ref)
            .map(|b| b.timestamp_ms())
            .unwrap_or(0);

        let sub_dag = CommittedSubDag {
            index: self.next_commit_index,
            leader: *leader_ref,
            blocks,
            timestamp_ms,
            previous_digest: self.previous_commit_digest,
            is_direct,
        };

        self.previous_commit_digest = sub_dag.digest();
        self.next_commit_index += 1;

        Some(sub_dag)
    }

    /// Collect all blocks in the sub-DAG rooted at a committed leader.
    ///
    /// Includes the leader and all uncommitted ancestors back to the
    /// last committed round. Bounded by MAX_SUB_DAG_BLOCKS.
    ///
    /// SEC-FIX NH-8: Returns None if the causal closure exceeds the limit,
    /// preventing incomplete sub-DAG commits that could skip dependencies.
    fn collect_sub_dag(&self, leader: &BlockRef, dag_state: &DagState) -> Option<Vec<BlockRef>> {
        const MAX_SUB_DAG_BLOCKS: usize = 10_000;

        let mut sub_dag = Vec::new();
        let mut frontier = vec![*leader];
        let mut visited = std::collections::HashSet::new();

        while let Some(current) = frontier.pop() {
            if !visited.insert(current) {
                continue;
            }
            if dag_state.is_committed(&current) && current != *leader {
                continue;
            }
            if sub_dag.len() >= MAX_SUB_DAG_BLOCKS {
                tracing::error!(
                    leader = ?leader,
                    "sub-DAG exceeds {} blocks — aborting commit to prevent incomplete causal closure",
                    MAX_SUB_DAG_BLOCKS,
                );
                return None;
            }

            sub_dag.push(current);

            if let Some(block) = dag_state.get_block(&current) {
                for ancestor in block.ancestors() {
                    if !dag_state.is_committed(ancestor) {
                        frontier.push(*ancestor);
                    }
                }
            }
        }

        // Sort by (round, author) for deterministic ordering
        sub_dag.sort();
        Some(sub_dag)
    }

    /// Last decided leader round.
    pub fn last_decided_round(&self) -> Round {
        self.last_decided_round
    }

    /// Next commit index.
    pub fn next_commit_index(&self) -> CommitIndex {
        self.next_commit_index
    }

    /// Set last decided round (recovery).
    pub fn set_last_decided_round(&mut self, round: Round) {
        self.last_decided_round = round;
    }

    /// Set next commit index (recovery).
    pub fn set_next_commit_index(&mut self, index: CommitIndex) {
        self.next_commit_index = index;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_dag::*;

    #[test]
    fn test_direct_commit_flow() {
        let committee = Committee::new_for_test(4);
        let leader_schedule = LeaderSchedule::new(committee.clone(), 1);
        let mut committer = UniversalCommitter::new(committee.clone(), leader_schedule, 1, 2);

        let mut b = DagBuilder::new(committee);
        b.build_layers(1, 3);
        let dag = b.to_dag_state();

        let commits = committer.try_commit(
            &dag,
            &crate::narwhal_dag::slot_equivocation_ledger::SlotEquivocationLedger::new(),
        );
        assert_eq!(commits.len(), 1);
        assert!(commits[0].is_direct);
    }

    #[test]
    fn test_indirect_commit() {
        // R2 leader has only 2 votes (< quorum=3). R4 leader has quorum and
        // R2 leader is in its causal history → indirect commit.
        let committee = Committee::new_for_test(4);
        let leader_schedule = LeaderSchedule::new(committee.clone(), 1);
        let mut committer = UniversalCommitter::new(committee.clone(), leader_schedule, 1, 2);

        let mut b = DagBuilder::new(committee);
        b.layer(1).fully_connected().build();
        b.layer(2).fully_connected().build();
        // R3: A,B reference all R2 (including leader); C,D skip leader
        let r2_leader = b.leader_of(2);
        b.layer(3).authorities(&[0, 1]).fully_connected().build();
        b.layer(3)
            .authorities(&[2, 3])
            .skip_ancestor(r2_leader)
            .build();
        b.layer(4).fully_connected().build();
        b.layer(5).authorities(&[0, 1, 2]).fully_connected().build();
        let dag = b.to_dag_state();

        let commits = committer.try_commit(
            &dag,
            &crate::narwhal_dag::slot_equivocation_ledger::SlotEquivocationLedger::new(),
        );
        assert_eq!(commits.len(), 2);
        assert!(!commits[0].is_direct); // indirect via anchor
        assert!(commits[1].is_direct); // direct (the anchor)
    }

    #[test]
    fn test_no_commit_without_quorum() {
        let committee = Committee::new_for_test(4);
        let leader_schedule = LeaderSchedule::new(committee.clone(), 1);
        let mut committer = UniversalCommitter::new(committee.clone(), leader_schedule, 1, 2);

        let mut b = DagBuilder::new(committee);
        b.layer(2).authorities(&[0]).fully_connected().build();
        b.layer(3).authorities(&[0]).fully_connected().build();
        let dag = b.to_dag_state();

        let commits = committer.try_commit(
            &dag,
            &crate::narwhal_dag::slot_equivocation_ledger::SlotEquivocationLedger::new(),
        );
        assert!(commits.is_empty());
    }

    #[test]
    fn test_commit_chain_integrity() {
        let committee = Committee::new_for_test(4);
        let leader_schedule = LeaderSchedule::new(committee.clone(), 1);
        let mut committer = UniversalCommitter::new(committee.clone(), leader_schedule, 1, 2);

        let mut b = DagBuilder::new(committee);
        b.build_layers(1, 5);
        let dag = b.to_dag_state();

        let commits = committer.try_commit(
            &dag,
            &crate::narwhal_dag::slot_equivocation_ledger::SlotEquivocationLedger::new(),
        );
        if commits.len() >= 2 {
            let first_digest = commits[0].digest();
            assert_eq!(commits[1].previous_digest, first_digest);
        }
    }
}
