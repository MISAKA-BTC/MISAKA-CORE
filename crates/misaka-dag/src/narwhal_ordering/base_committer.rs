// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! BaseCommitter — direct and indirect commit decisions.
//!
//! Sui equivalent: consensus/core/base_committer.rs (~1,200 lines)
//!
//! The base committer implements the core Bullshark commit rule:
//! - Direct commit: leader has ≥2f+1 votes in round+1
//! - Indirect commit: leader certified through vote chains from a later
//!   committed leader's causal history
//! - Skip: a later committed leader does NOT have this leader in its
//!   causal history
//!
//! ## CRIT-3 fix: Indirect commit is now a real path
//! ## CRIT-4 fix: Skip only decided by a committed anchor, not by
//!   mere existence of quorum blocks

use crate::narwhal_dag::dag_state::DagState;
use crate::narwhal_dag::slo_metrics;
use crate::narwhal_dag::slot_equivocation_ledger::SlotEquivocationLedger;
use crate::narwhal_dag::vote_registry::{VoteRegistry, VoteResult};
use crate::narwhal_types::block::*;
use crate::narwhal_types::committee::Committee;

/// Decision for a leader block.
#[derive(Clone, Debug)]
pub enum Decision {
    /// Leader committed directly (≥2f+1 votes in round+1).
    Direct(BlockRef),
    /// Leader committed indirectly (certified through later committed leader).
    Indirect(BlockRef),
    /// Leader skipped (later committed leader does NOT have it in causal history).
    Skip,
    /// Not yet decidable (need more blocks).
    Undecided,
}

/// Result of BFS causal history search.
///
/// Separates "not found" (definitive → Skip) from "aborted" (BFS
/// resource limit reached → Undecided, retry with different anchor).
///
/// SECURITY: Returning `NotFound` directly maps to `Decision::Skip`,
/// which is a permanent, irreversible decision. `Aborted` maps to
/// `Decision::Undecided`, allowing retry. Conflating the two was a
/// safety bug (equivocation flooding could force Aborted → false → Skip).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BfsResult {
    /// Target found in causal history.
    Found,
    /// Target definitively not in causal history (BFS completed).
    NotFound,
    /// BFS aborted due to resource limit. Decision is unsafe to make.
    Aborted,
}

/// Base committer — decides on leaders using the Bullshark protocol.
pub struct BaseCommitter {
    /// Committee for quorum calculations.
    committee: Committee,
    /// Leader round offset (which rounds have leaders).
    /// Standard Bullshark: leader every 2 rounds.
    leader_round_wave: u32,
}

impl BaseCommitter {
    pub fn new(committee: Committee, leader_round_wave: u32) -> Self {
        Self {
            committee,
            leader_round_wave,
        }
    }

    /// Try to decide on a leader at the given round.
    ///
    /// Bullshark commit rule:
    /// 1. Leader is at `leader_round`
    /// 2. Voting round is `leader_round + 1`
    /// 3. If ≥quorum blocks at voting round include leader as ancestor → Direct commit
    /// 4. Otherwise → Undecided (caller must try indirect via `try_decide_with_anchor`)
    pub fn try_direct_decide(
        &self,
        leader_ref: &BlockRef,
        dag_state: &DagState,
        ledger: &SlotEquivocationLedger,
    ) -> Decision {
        let voting_round = leader_ref.round + 1;
        let voting_blocks = dag_state.get_blocks_at_round(voting_round);

        if voting_blocks.is_empty() {
            return Decision::Undecided;
        }

        // Count votes: how many voting-round blocks include this leader as ancestor?
        // WP8: Exclude banned (equivocating) authorities from vote counting.
        let mut vote_stake = 0u64;
        for block in &voting_blocks {
            if block.ancestors().contains(leader_ref) {
                if !ledger.is_banned(block.author()) {
                    // SEC-FIX M-2: saturating_add to prevent u64 overflow
                    vote_stake = vote_stake.saturating_add(self.committee.stake(block.author()));
                }
            }
        }

        if self.committee.reached_quorum(vote_stake) {
            Decision::Direct(*leader_ref)
        } else {
            Decision::Undecided
        }
    }

    /// Try to decide on a leader using a later committed anchor.
    ///
    /// This implements indirect commit and skip:
    /// - If the anchor has this leader in its causal history → Indirect commit
    /// - If the anchor does NOT have this leader → Skip
    ///
    /// The anchor must be a leader from a later round that has been
    /// directly committed. This ensures the decision is safe.
    pub fn try_decide_with_anchor(
        &self,
        leader_ref: &BlockRef,
        anchor_ref: &BlockRef,
        dag_state: &DagState,
    ) -> Decision {
        if anchor_ref.round <= leader_ref.round {
            return Decision::Undecided;
        }

        let round_diff = anchor_ref.round - leader_ref.round;
        match self.causal_history_search(leader_ref, anchor_ref, dag_state, round_diff) {
            BfsResult::Found => Decision::Indirect(*leader_ref),
            BfsResult::NotFound => Decision::Skip,
            // SECURITY: Aborted means BFS hit resource limit (possible equivocation
            // flooding). We return Undecided so the caller retries with a different
            // anchor instead of permanently skipping a legitimate leader.
            BfsResult::Aborted => {
                // SLO S3: BFS aborted — possible equivocation flooding attack
                slo_metrics::BFS_ABORTED.inc();
                Decision::Undecided
            }
        }
    }

    /// BFS search for `target` in the causal history of `from`.
    ///
    /// Returns `Found`, `NotFound`, or `Aborted` (resource limit).
    ///
    /// The cap is dynamic: `committee_size * round_diff * 4` to accommodate
    /// equivocating blocks (each slot can have up to ~4 blocks in adversarial
    /// conditions before the DAG evicts them).
    ///
    /// Sui equivalent: core.rs causal history traversal (uses DagState directly).
    fn causal_history_search(
        &self,
        target: &BlockRef,
        from: &BlockRef,
        dag_state: &DagState,
        max_depth: u32,
    ) -> BfsResult {
        if target.round >= from.round {
            return BfsResult::NotFound;
        }
        if from.round - target.round > max_depth {
            return BfsResult::NotFound;
        }

        // Dynamic cap: committee_size × round_diff × 4 (equivocation buffer)
        let committee_size = self.committee.size() as usize;
        let round_diff = (from.round - target.round) as usize;
        let max_bfs_nodes = (committee_size * round_diff * 4).max(1_000).min(100_000);

        let mut frontier = vec![*from];
        let mut visited = std::collections::HashSet::new();

        while let Some(current) = frontier.pop() {
            if current == *target {
                return BfsResult::Found;
            }
            if current.round <= target.round {
                continue;
            }
            if !visited.insert(current) {
                continue;
            }
            if visited.len() > max_bfs_nodes {
                return BfsResult::Aborted;
            }

            if let Some(block) = dag_state.get_block(&current) {
                for ancestor in block.ancestors() {
                    if ancestor.round >= target.round {
                        frontier.push(*ancestor);
                    }
                }
            }
        }

        BfsResult::NotFound
    }

    /// Direct commit decision using VoteRegistry for equivocation-safe vote tracking.
    ///
    /// This is the preferred path — uses VoteRegistry instead of simple counting
    /// to detect and record equivocating voters.
    ///
    /// Sui equivalent: `BaseCommitter::try_direct_decide()` with vote tracking.
    pub fn try_direct_decide_tracked(
        &self,
        leader_ref: &BlockRef,
        dag_state: &DagState,
        ledger: &SlotEquivocationLedger,
    ) -> (Decision, VoteRegistry) {
        let mut registry = VoteRegistry::new(*leader_ref);
        let voting_round = leader_ref.round + 1;
        let voting_blocks = dag_state.get_blocks_at_round(voting_round);

        for block in &voting_blocks {
            if block.ancestors().contains(leader_ref) {
                registry.register_vote(block.author(), block.reference());
            }
        }

        // WP8: Compute quorum using only honest (non-banned) voters
        let honest_stake =
            ledger.effective_stake(&self.committee, registry.votes().keys().copied());
        let decision = if self.committee.reached_quorum(honest_stake) {
            Decision::Direct(*leader_ref)
        } else {
            Decision::Undecided
        };

        (decision, registry)
    }

    /// Indirect commit with bounded depth.
    ///
    /// `max_indirect_depth` limits how far back we look for the leader in
    /// the anchor's causal history. This prevents DoS via deep chains.
    /// Default: 50 rounds (sufficient for any realistic network partition).
    ///
    /// Sui equivalent: indirect commit path in `BaseCommitter`.
    pub fn try_decide_indirect_bounded(
        &self,
        leader_ref: &BlockRef,
        anchor_ref: &BlockRef,
        dag_state: &DagState,
        max_indirect_depth: u32,
    ) -> Decision {
        if anchor_ref.round <= leader_ref.round {
            return Decision::Undecided;
        }

        let actual_depth = anchor_ref.round - leader_ref.round;
        if actual_depth > max_indirect_depth {
            // Too far back — don't search, return Undecided.
            // This is safe: we're not skipping, just deferring.
            return Decision::Undecided;
        }

        self.try_decide_with_anchor(leader_ref, anchor_ref, dag_state)
    }

    /// Check if a round is a leader round.
    pub fn is_leader_round(&self, round: Round) -> bool {
        round % self.leader_round_wave == 0
    }

    /// Leader round wave.
    pub fn leader_round_wave(&self) -> u32 {
        self.leader_round_wave
    }

    /// Committee reference.
    pub fn committee(&self) -> &Committee {
        &self.committee
    }

    /// Maximum indirect depth (default).
    pub const DEFAULT_MAX_INDIRECT_DEPTH: u32 = 50;

    // ── WP4: Multi-anchor, fast-path helpers ─────────────────

    /// Try to decide using multiple anchors in order (WP4).
    ///
    /// Iterates through `anchors` and returns the first non-Undecided
    /// result. This provides resilience when the best anchor doesn't
    /// have the leader in its causal history but an earlier one does.
    pub fn try_decide_with_anchors(
        &self,
        leader_ref: &BlockRef,
        anchors: &[BlockRef],
        dag_state: &DagState,
    ) -> Decision {
        for anchor in anchors {
            let decision = self.try_decide_with_anchor(leader_ref, anchor, dag_state);
            match decision {
                Decision::Undecided => continue, // try next anchor
                other => return other,           // Direct, Indirect, or Skip
            }
        }
        Decision::Undecided
    }

    /// Check if a block voted for a leader (WP4).
    ///
    /// A block at `leader.round + 1` is a "vote" for the leader if it
    /// includes the leader as an ancestor.
    pub fn is_vote(block: &VerifiedBlock, leader_ref: &BlockRef) -> bool {
        block.round() == leader_ref.round + 1 && block.ancestors().contains(leader_ref)
    }

    /// Check if a leader is certified (has ≥ quorum direct votes) (WP4).
    ///
    /// This is equivalent to `try_direct_decide` returning `Direct`,
    /// but as a pure predicate without creating a Decision value.
    pub fn is_certified(
        &self,
        leader_ref: &BlockRef,
        dag_state: &DagState,
        ledger: &SlotEquivocationLedger,
    ) -> bool {
        matches!(
            self.try_direct_decide(leader_ref, dag_state, ledger),
            Decision::Direct(_)
        )
    }

    /// Fast-path optimistic confirmation: does the leader have at least
    /// `threshold` supporting blocks in the voting round? (WP4)
    ///
    /// This is NOT a quorum check — it's a heuristic for signaling
    /// optimistic confirmation to RPC clients before the full commit
    /// pipeline runs. The threshold is typically small (e.g., 3).
    pub fn enough_leader_support(
        &self,
        leader_ref: &BlockRef,
        dag_state: &DagState,
        support_threshold: u32,
        ledger: &SlotEquivocationLedger,
    ) -> bool {
        let voting_round = leader_ref.round + 1;
        let voting_blocks = dag_state.get_blocks_at_round(voting_round);

        // v0.5.9 WP8 follow-up: only count support from non-banned voters.
        // Equivocating validators' support is not counted toward the
        // leader_support threshold.
        let count = voting_blocks
            .iter()
            .filter(|b| b.ancestors().contains(leader_ref))
            .filter(|b| !ledger.is_banned(b.author()))
            .count();

        count >= support_threshold as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_dag::*;

    #[test]
    fn test_direct_commit() {
        // Use CommitFixture — the canonical way to test commit rules.
        let mut f = CommitFixture::new(4).with_wave(2);
        f.set_leader(2, 0);
        f.dag().layer(2).authorities(&[0]).fully_connected().build();
        f.dag()
            .layer(3)
            .authorities(&[0, 1, 2])
            .fully_connected()
            .build();
        f.assert_direct_commit(2);
    }

    #[test]
    fn test_undecided_not_enough_votes() {
        let mut f = CommitFixture::new(4).with_wave(2);
        f.set_leader(2, 0);
        f.dag().layer(2).authorities(&[0]).fully_connected().build();
        // Only 1 voter — not enough for quorum of 3
        f.dag().layer(3).authorities(&[0]).fully_connected().build();
        f.assert_direct_undecided(2);
    }

    #[test]
    fn test_indirect_commit_via_anchor() {
        let mut f = CommitFixture::new(4).with_wave(2);
        f.set_leader(2, 0);
        f.set_leader(4, 0);
        f.dag().layer(2).authorities(&[0]).fully_connected().build();
        // 2 voters for leader (not quorum)
        f.dag()
            .layer(3)
            .authorities(&[0, 1])
            .fully_connected()
            .build();
        // Anchor at round 4 references voters → leader in causal history
        f.dag().layer(4).fully_connected().build();

        f.assert_direct_undecided(2);
        f.assert_indirect_commit(2, 4);
    }

    #[test]
    fn test_skip_via_anchor() {
        let mut f = CommitFixture::new(4).with_wave(2);
        f.set_leader(2, 0);
        f.set_leader(4, 0);
        f.dag().layer(2).authorities(&[0]).fully_connected().build();
        // Voter does NOT reference leader (skips authority 0)
        f.dag().layer(3).authorities(&[1]).skip_ancestor(0).build();
        // Anchor via voter only → leader NOT in causal history → skip
        f.dag()
            .layer(4)
            .skip_ancestor(0) // skip leader from R2
            .build();

        f.assert_skip_via_anchor(2, 4);
    }

    #[test]
    fn test_leader_round() {
        let committee = Committee::new_for_test(4);
        let committer = BaseCommitter::new(committee, 2);
        assert!(committer.is_leader_round(0));
        assert!(!committer.is_leader_round(1));
        assert!(committer.is_leader_round(2));
        assert!(!committer.is_leader_round(3));
        assert!(committer.is_leader_round(4));
    }
}
