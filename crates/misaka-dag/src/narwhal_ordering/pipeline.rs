// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Pipelined Bullshark — multi-leader slots per wave.
//!
//! Sui equivalent: consensus/core/commit_observer.rs + pipeline logic (~1,500 lines)
//!
//! Standard Bullshark has 1 leader per wave (e.g., wave=2: leader at rounds 2,4,6...).
//! Pipelined Bullshark supports N leader slots per wave:
//!   - wave=2, pipeline=2: leaders at rounds 2(slot0), 2(slot1), 4(slot0), 4(slot1)...
//!   - Each slot has its own independent commit rule
//!   - Throughput increases linearly with pipeline depth
//!
//! ## Pipeline Architecture
//!
//! ```text
//!  Wave 0 (round 2):  [Leader slot 0] [Leader slot 1]
//!  Wave 1 (round 4):  [Leader slot 0] [Leader slot 1]
//!  ...
//!
//!  Each slot runs an independent BaseCommitter.
//!  The PipelinedCommitter coordinates all slots.
//! ```

use super::base_committer::{BaseCommitter, Decision};
use crate::narwhal_dag::dag_state::DagState;
use crate::narwhal_dag::leader_schedule::LeaderSchedule;
use crate::narwhal_types::block::*;
use crate::narwhal_types::commit::*;
use crate::narwhal_types::committee::Committee;

/// Pipelined Bullshark committer — multiple leader slots per wave.
pub struct PipelinedCommitter {
    /// Committee.
    committee: Committee,
    /// Leader schedule (pipeline-aware).
    leader_schedule: LeaderSchedule,
    /// One BaseCommitter per pipeline slot.
    slot_committers: Vec<BaseCommitter>,
    /// Number of pipeline slots.
    num_slots: u32,
    /// Leader round wave.
    leader_round_wave: u32,
    /// Per-slot last decided round.
    last_decided_rounds: Vec<Round>,
    /// Global sequential commit index.
    next_commit_index: CommitIndex,
    /// Previous commit digest.
    previous_commit_digest: CommitDigest,
}

impl PipelinedCommitter {
    /// Create a new pipelined committer.
    ///
    /// `num_slots`: number of parallel leader slots (1 = standard, 2+ = pipelined).
    /// `leader_round_wave`: rounds between leader waves (typically 2).
    pub fn new(
        committee: Committee,
        leader_schedule: LeaderSchedule,
        num_slots: u32,
        leader_round_wave: u32,
    ) -> Self {
        let slot_committers = (0..num_slots)
            .map(|_| BaseCommitter::new(committee.clone(), leader_round_wave))
            .collect();

        Self {
            committee,
            leader_schedule,
            slot_committers,
            num_slots,
            leader_round_wave,
            last_decided_rounds: vec![0; num_slots as usize],
            next_commit_index: 0,
            previous_commit_digest: CommitDigest([0; 32]),
        }
    }

    /// Try to commit across all pipeline slots.
    ///
    /// Each slot is processed independently. Commits are ordered:
    /// slot 0 of wave N, slot 1 of wave N, slot 0 of wave N+1, etc.
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
        let mut all_committed = Vec::new();

        // Process each wave
        let min_decided = self.last_decided_rounds.iter().copied().min().unwrap_or(0);
        let start_round = if min_decided == 0 {
            wave
        } else {
            min_decided + wave
        };

        let mut round = start_round;
        while round <= highest {
            let mut wave_committed = Vec::new();

            // Find anchor: latest directly committable leader across all slots
            let anchor = self.find_anchor_for_wave(round, dag_state, ledger);

            // Process each slot for this wave
            for slot in 0..self.num_slots {
                let slot_idx = slot as usize;
                if self.last_decided_rounds[slot_idx] >= round {
                    continue; // already decided this slot
                }

                let leader_auth = self.leader_schedule.leader(round, slot);
                let slot_s = Slot::new(round, leader_auth);
                let leader_blocks = dag_state.get_blocks_at_slot(&slot_s);

                if let Some(leader_block) = leader_blocks.first() {
                    let leader_ref = leader_block.reference();
                    let committer = &self.slot_committers[slot_idx];

                    // Try direct commit
                    let decision = committer.try_direct_decide(&leader_ref, dag_state, ledger);
                    match decision {
                        Decision::Direct(ref committed) => {
                            if let Some(sub_dag) = self.build_sub_dag(committed, true, dag_state) {
                                wave_committed.push(sub_dag);
                            }
                            self.last_decided_rounds[slot_idx] = round;
                        }
                        _ => {
                            // Try indirect via anchor
                            if let Some((_, anchor_ref)) = &anchor {
                                let indirect = committer.try_decide_with_anchor(
                                    &leader_ref,
                                    anchor_ref,
                                    dag_state,
                                );
                                match indirect {
                                    Decision::Indirect(ref committed) => {
                                        if let Some(sub_dag) =
                                            self.build_sub_dag(committed, false, dag_state)
                                        {
                                            wave_committed.push(sub_dag);
                                        }
                                        self.last_decided_rounds[slot_idx] = round;
                                    }
                                    Decision::Skip => {
                                        self.last_decided_rounds[slot_idx] = round;
                                    }
                                    _ => {} // undecided
                                }
                            }
                        }
                    }
                } else {
                    // No leader block — skip this slot
                    if anchor.is_some() {
                        self.last_decided_rounds[slot_idx] = round;
                    }
                }
            }

            if wave_committed.is_empty() && anchor.is_none() {
                break; // No progress possible
            }

            all_committed.extend(wave_committed);
            round += wave;
        }

        all_committed
    }

    /// Find the latest directly committable leader across all slots for a given wave.
    fn find_anchor_for_wave(
        &self,
        round: Round,
        dag_state: &DagState,
        ledger: &crate::narwhal_dag::slot_equivocation_ledger::SlotEquivocationLedger,
    ) -> Option<(u32, BlockRef)> {
        let highest = dag_state.highest_accepted_round();
        let wave = self.leader_round_wave;

        // Scan forward from this round to find an anchor
        let mut scan = round;
        while scan <= highest {
            for slot in 0..self.num_slots {
                let leader_auth = self.leader_schedule.leader(scan, slot);
                let slot_s = Slot::new(scan, leader_auth);
                let leader_blocks = dag_state.get_blocks_at_slot(&slot_s);

                if let Some(leader) = leader_blocks.first() {
                    let leader_ref = leader.reference();
                    let committer = &self.slot_committers[slot as usize];
                    if matches!(
                        committer.try_direct_decide(&leader_ref, dag_state, ledger),
                        Decision::Direct(_)
                    ) {
                        return Some((slot, leader_ref));
                    }
                }
            }
            scan += wave;
        }
        None
    }

    /// Build a CommittedSubDag with sequential index and chain linkage.
    fn build_sub_dag(
        &mut self,
        leader: &BlockRef,
        is_direct: bool,
        dag_state: &DagState,
    ) -> Option<CommittedSubDag> {
        let blocks = self.collect_sub_dag(leader, dag_state);
        let timestamp_ms = dag_state
            .get_block(leader)
            .map(|b| b.timestamp_ms())
            .unwrap_or(0);

        let sub_dag = CommittedSubDag {
            index: self.next_commit_index,
            leader: *leader,
            blocks,
            timestamp_ms,
            previous_digest: self.previous_commit_digest,
            is_direct,
        };

        self.previous_commit_digest = sub_dag.digest();
        self.next_commit_index += 1;

        Some(sub_dag)
    }

    /// Collect sub-DAG blocks (same as UniversalCommitter).
    fn collect_sub_dag(&self, leader: &BlockRef, dag_state: &DagState) -> Vec<BlockRef> {
        const MAX: usize = 10_000;
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
            if sub_dag.len() >= MAX {
                break;
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

        sub_dag.sort();
        sub_dag
    }

    /// Number of pipeline slots.
    pub fn num_slots(&self) -> u32 {
        self.num_slots
    }

    /// Next commit index.
    pub fn next_commit_index(&self) -> CommitIndex {
        self.next_commit_index
    }

    /// Last decided round per slot.
    pub fn last_decided_rounds(&self) -> &[Round] {
        &self.last_decided_rounds
    }
}

/// Commit observer — watches for commits and updates reputation.
///
/// Sui equivalent: commit_observer.rs (~400 lines)
pub struct CommitObserver {
    /// Accumulated reputation scores from recent commits.
    reputation_window: Vec<(AuthorityIndex, Vec<AuthorityIndex>)>,
    /// Maximum window size for reputation.
    max_window: usize,
    /// Total commits observed.
    total_commits: u64,
}

impl CommitObserver {
    pub fn new(max_window: usize) -> Self {
        Self {
            reputation_window: Vec::new(),
            max_window,
            total_commits: 0,
        }
    }

    /// Observe a committed sub-DAG and accumulate reputation data.
    pub fn observe(&mut self, sub_dag: &CommittedSubDag) {
        let leader_auth = sub_dag.leader.author;
        let block_authors: Vec<AuthorityIndex> = sub_dag.blocks.iter().map(|b| b.author).collect();

        self.reputation_window.push((leader_auth, block_authors));
        self.total_commits += 1;

        // Trim window
        while self.reputation_window.len() > self.max_window {
            self.reputation_window.remove(0);
        }
    }

    /// Build reputation scores from the observation window.
    pub fn build_reputation_scores(
        &self,
        committee_size: usize,
    ) -> crate::narwhal_dag::leader_schedule::ReputationScores {
        let mut scores = crate::narwhal_dag::leader_schedule::ReputationScores::new(committee_size);
        scores.update_from_commits(&self.reputation_window);
        scores
    }

    /// Total commits observed.
    pub fn total_commits(&self) -> u64 {
        self.total_commits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::narwhal_dag::dag_state::DagStateConfig;

    fn make_block(round: Round, author: AuthorityIndex, ancestors: Vec<BlockRef>) -> VerifiedBlock {
        let block = Block {
            epoch: 0,
            round,
            author,
            timestamp_ms: round as u64 * 1000,
            ancestors,
            transactions: vec![vec![author as u8]],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            state_root_smt: [0u8; 32],
            signature: vec![0xAA; 64],
        };
        VerifiedBlock::new_for_test(block)
    }

    #[test]
    fn test_single_slot_same_as_universal() {
        // pipeline=1 should behave like UniversalCommitter
        let committee = Committee::new_for_test(4);
        let leader_schedule = LeaderSchedule::new(committee.clone(), 1);
        let mut committer = PipelinedCommitter::new(committee.clone(), leader_schedule, 1, 2);
        let mut dag = DagState::new(committee, DagStateConfig::default());

        // Build rounds 1-3 with full connectivity
        let mut prev_refs = Vec::new();
        for round in 1..=3 {
            let mut refs = Vec::new();
            for author in 0..4u32 {
                let b = make_block(round, author, prev_refs.clone());
                refs.push(b.reference());
                dag.accept_block(b);
            }
            prev_refs = refs;
        }

        let commits = committer.try_commit(
            &dag,
            &crate::narwhal_dag::slot_equivocation_ledger::SlotEquivocationLedger::new(u32::MAX),
        );
        assert_eq!(commits.len(), 1);
        assert!(commits[0].is_direct);
    }

    #[test]
    fn test_dual_slot_pipeline() {
        // pipeline=2: two leaders per wave
        let committee = Committee::new_for_test(4);
        let leader_schedule = LeaderSchedule::new(committee.clone(), 2);
        let mut committer = PipelinedCommitter::new(committee.clone(), leader_schedule, 2, 2);
        let mut dag = DagState::new(committee, DagStateConfig::default());

        // Build rounds 1-3
        let mut prev_refs = Vec::new();
        for round in 1..=3 {
            let mut refs = Vec::new();
            for author in 0..4u32 {
                let b = make_block(round, author, prev_refs.clone());
                refs.push(b.reference());
                dag.accept_block(b);
            }
            prev_refs = refs;
        }

        let commits = committer.try_commit(
            &dag,
            &crate::narwhal_dag::slot_equivocation_ledger::SlotEquivocationLedger::new(u32::MAX),
        );
        // With 2 slots, we can potentially commit 2 leaders per wave
        // Leader(round=2, slot=0) = (2*2+0)%4 = 0
        // Leader(round=2, slot=1) = (2*2+1)%4 = 1
        assert!(commits.len() >= 1);
    }

    #[test]
    fn test_commit_observer_reputation() {
        let mut observer = CommitObserver::new(100);

        let sub_dag = CommittedSubDag {
            index: 0,
            leader: BlockRef::new(2, 0, BlockDigest([0; 32])),
            blocks: vec![
                BlockRef::new(1, 0, BlockDigest([1; 32])),
                BlockRef::new(1, 1, BlockDigest([2; 32])),
                BlockRef::new(1, 2, BlockDigest([3; 32])),
            ],
            timestamp_ms: 1000,
            previous_digest: CommitDigest([0; 32]),
            is_direct: true,
        };
        observer.observe(&sub_dag);

        let scores = observer.build_reputation_scores(4);
        // Authority 0: 1 (init) + 1 (leader) + 1 (block) = 3
        assert!(scores.scores[0] > scores.scores[3]); // auth 3 had no block
        assert_eq!(observer.total_commits(), 1);
    }
}
