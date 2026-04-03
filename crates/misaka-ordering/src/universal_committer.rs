use misaka_dag_types::block::*;
use misaka_dag_types::commit::*;
use misaka_dag_types::committee::*;
use misaka_primary_dag::dag_state::DagState;
use super::base_committer::BaseCommitter;
use std::collections::VecDeque;

/// Universal Committer — multiple pipelined BaseCommitters.
pub struct UniversalCommitter {
    committers: Vec<BaseCommitter>,
}

impl UniversalCommitter {
    pub fn new(committee: Committee) -> Self {
        let num_pipelines = committee.leaders_per_round;
        let committers: Vec<BaseCommitter> = (0..num_pipelines)
            .map(|offset| BaseCommitter::new(committee.clone(), offset))
            .collect();
        Self { committers }
    }

    /// Try to decide leaders and return committed sub-DAGs.
    pub fn try_decide(
        &self,
        last_decided: Slot,
        dag: &DagState,
    ) -> Vec<CommittedSubDag> {
        let highest = dag.highest_accepted_round();
        if highest < 3 { return vec![]; }

        let mut leaders: VecDeque<(LeaderStatus, bool)> = VecDeque::new();

        // Iterate from highest-2 down to last_decided+1
        let start = highest.saturating_sub(2);
        let end = last_decided.round.saturating_add(1);
        if start < end { return vec![]; }

        for round in (end..=start).rev() {
            for committer in self.committers.iter().rev() {
                if let Some(slot) = committer.elect_leader(round) {
                    let mut status = committer.try_direct_decide(slot, dag);
                    if !status.is_decided() {
                        let leaders_vec: Vec<_> = leaders.iter().cloned().collect();
                        status = committer.try_indirect_decide(slot, &leaders_vec, dag);
                    }
                    let is_direct = matches!(&status, LeaderStatus::Commit(_));
                    leaders.push_front((status, is_direct));
                }
            }
        }

        // Extract decided prefix
        let mut committed = Vec::new();
        let mut commit_index = 0u64;
        let mut prev_digest = CommitDigest([0; 32]);

        for (status, is_direct) in leaders {
            match status {
                LeaderStatus::Commit(leader_ref) => {
                    // Collect sub-DAG via BFS
                    let blocks = self.collect_sub_dag(&leader_ref, dag);
                    commit_index += 1;
                    let sub_dag = CommittedSubDag {
                        index: commit_index,
                        leader: leader_ref,
                        blocks,
                        timestamp_ms: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default().as_millis() as u64,
                        previous_digest: prev_digest,
                        is_direct,
                    };
                    prev_digest = sub_dag.digest();
                    committed.push(sub_dag);
                }
                LeaderStatus::Skip(_) => continue,
                LeaderStatus::Undecided(_) => break, // stop at first undecided
            }
        }

        committed
    }

    fn collect_sub_dag(&self, leader: &BlockRef, dag: &DagState) -> Vec<BlockRef> {
        let mut visited = std::collections::HashSet::new();
        let mut queue = VecDeque::new();
        let mut result = Vec::new();

        queue.push_back(*leader);
        visited.insert(*leader);

        while let Some(current) = queue.pop_front() {
            result.push(current);
            if let Some(block) = dag.get_block(&current) {
                for ancestor in &block.ancestors {
                    if ancestor.round > dag.last_committed_round() && !visited.contains(ancestor) {
                        visited.insert(*ancestor);
                        queue.push_back(*ancestor);
                    }
                }
            }
        }

        result.sort_by_key(|r| (r.round, r.author));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_committee(n: u32) -> Committee {
        let auths = (0..n).map(|i| Authority {
            index: i, stake: 100, address: String::new(),
            public_key: vec![0xAA; 1952],
            reputation_score: 5000, is_sr: i < 21,
        }).collect();
        Committee {
            epoch: 0, authorities: auths, total_stake: n as u64 * 100,
            leaders_per_round: 1, wave_length: 3,
        }
    }

    #[test]
    fn test_universal_committer_creation() {
        let c = make_committee(21);
        let uc = UniversalCommitter::new(c);
        assert_eq!(uc.committers.len(), 1);
    }
}
