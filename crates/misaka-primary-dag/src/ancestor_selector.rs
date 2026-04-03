use misaka_dag_types::block::*;
use super::dag_state::DagState;

/// Selects ancestors for a new block proposal.
/// Prioritizes authorities with high reputation scores.
pub struct AncestorSelector;

impl AncestorSelector {
    /// Select best ancestors from the previous round for a new block.
    /// Returns one block per authority (the best available).
    pub fn select(
        dag: &DagState,
        _proposer: AuthorityIndex,
        round: Round,
    ) -> Vec<BlockRef> {
        let committee = dag.committee();
        let prev_round = round.saturating_sub(1);
        let mut ancestors: Vec<(BlockRef, u64)> = Vec::new();

        for auth in &committee.authorities {
            if let Some(block) = dag.get_block_at_slot(&Slot { round: prev_round, authority: auth.index }) {
                let score = auth.stake + auth.reputation_score;
                ancestors.push((block.reference(), score));
            }
        }

        // Sort by reputation (highest first), take up to committee size
        ancestors.sort_by(|a, b| b.1.cmp(&a.1));
        ancestors.into_iter().map(|(r, _)| r).collect()
    }
}
