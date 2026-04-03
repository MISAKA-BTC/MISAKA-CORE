use misaka_dag_types::block::*;
use misaka_dag_types::commit::*;
use misaka_dag_types::committee::*;
use misaka_primary_dag::dag_state::DagState;

/// Single-pipeline commit rule (direct + indirect).
pub struct BaseCommitter {
    committee: Committee,
    /// Offset for this pipeline (enables pipelining).
    leader_offset: u32,
    wave_length: u32,
}

impl BaseCommitter {
    pub fn new(committee: Committee, leader_offset: u32) -> Self {
        let wave_length = committee.wave_length;
        Self { committee, leader_offset, wave_length }
    }

    /// Elect leader for a given round with this pipeline's offset.
    pub fn elect_leader(&self, round: Round) -> Option<Slot> {
        if round < 1 { return None; }
        let leaders = self.committee.elect_leaders(round);
        let idx = self.leader_offset as usize;
        if idx < leaders.len() {
            Some(Slot { round, authority: leaders[idx] })
        } else {
            None
        }
    }

    /// Direct commit: 2-round latency.
    /// Leader at round R, voting at R+1, decision at R+2.
    pub fn try_direct_decide(&self, leader_slot: Slot, dag: &DagState) -> LeaderStatus {
        let leader_refs = dag.get_uncommitted_blocks_at_slot(&leader_slot);
        if leader_refs.is_empty() {
            return LeaderStatus::Undecided(leader_slot);
        }

        let voting_round = leader_slot.round + 1;
        let decision_round = leader_slot.round + 2;

        for leader_ref in &leader_refs {
            // Check if enough blocks at decision_round certify this leader
            let decision_blocks = dag.blocks_at_round(decision_round);
            let mut certified_stake: Stake = 0;

            for d_block in &decision_blocks {
                // A block "certifies" the leader if it has quorum ancestors
                // at voting_round that include the leader as ancestor.
                let voting_ancestors: Vec<&BlockRef> = d_block.ancestors.iter()
                    .filter(|a| a.round == voting_round)
                    .collect();

                let votes_for_leader: Stake = voting_ancestors.iter()
                    .filter(|va| dag.is_ancestor(leader_ref, va))
                    .map(|va| self.committee.stake(va.author))
                    .sum();

                if votes_for_leader >= self.committee.quorum_threshold() {
                    certified_stake += self.committee.stake(d_block.author);
                }
            }

            if certified_stake >= self.committee.quorum_threshold() {
                return LeaderStatus::Commit(*leader_ref);
            }
        }

        // Check for blame (enough non-votes -> skip)
        let voting_blocks = dag.blocks_at_round(voting_round);
        let blame_stake: Stake = voting_blocks.iter()
            .filter(|vb| !leader_refs.iter().any(|lr| vb.ancestors.iter().any(|a| a == lr)))
            .map(|vb| self.committee.stake(vb.author))
            .sum();

        if blame_stake >= self.committee.quorum_threshold() {
            return LeaderStatus::Skip(leader_slot);
        }

        LeaderStatus::Undecided(leader_slot)
    }

    /// Indirect commit: via anchor leader linkage.
    pub fn try_indirect_decide(
        &self,
        leader_slot: Slot,
        decided_leaders: &[(LeaderStatus, bool)],
        dag: &DagState,
    ) -> LeaderStatus {
        let leader_refs = dag.get_uncommitted_blocks_at_slot(&leader_slot);
        if leader_refs.is_empty() {
            return LeaderStatus::Skip(leader_slot);
        }

        // Find anchor: first committed leader at round >= leader + wave_length
        for (status, _) in decided_leaders {
            if let LeaderStatus::Commit(anchor_ref) = status {
                if anchor_ref.round >= leader_slot.round + self.wave_length as u64 {
                    // Check if any leader_ref is an ancestor of anchor
                    for lr in &leader_refs {
                        if dag.is_ancestor(lr, anchor_ref) {
                            return LeaderStatus::Commit(*lr);
                        }
                    }
                    return LeaderStatus::Skip(leader_slot);
                }
            }
        }

        LeaderStatus::Undecided(leader_slot)
    }
}
