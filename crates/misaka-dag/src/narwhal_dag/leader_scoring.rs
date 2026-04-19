// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Sui equivalent: consensus/core/src/leader_scoring.rs (317 lines)
//
//! Leader scoring — distributed vote scoring for reputation-weighted
//! leader election.
//!
//! Computes authority scores based on how well their blocks are
//! propagated (measured by inclusion in next-round blocks).
//! See docs/design/leader_scoring.md.
//!
//! ## Algorithm
//!
//! For each block B in a committed sub-DAG:
//!   For each strong-linked parent P (P.round == B.round - 1):
//!     P.author receives B.author's stake as score.
//!
//! This measures "how many authorities included your block promptly."
//! Good propagation → high score → more likely to be elected leader.

use super::leader_schedule::ReputationScores;
use crate::narwhal_types::block::*;
use crate::narwhal_types::commit::*;
use crate::narwhal_types::committee::{Committee, Stake};

/// Interval between score recalculations (in commits).
pub const SCORING_UPDATE_INTERVAL: u64 = 300;

/// Accumulates vote scores over a window of committed sub-DAGs.
///
/// Sui equivalent: `ScoringSubdag` in `leader_scoring.rs`.
pub struct ScoringSubDag {
    committee: Committee,
    /// Accumulated score per authority.
    scores: Vec<u64>,
    /// Number of sub-DAGs processed in this window.
    subdags_processed: u64,
    /// Commit range covered.
    first_commit: Option<CommitIndex>,
    last_commit: Option<CommitIndex>,
}

impl ScoringSubDag {
    /// Create a new accumulator.
    #[must_use]
    pub fn new(committee: Committee) -> Self {
        let n = committee.size();
        Self {
            committee,
            scores: vec![0; n],
            subdags_processed: 0,
            first_commit: None,
            last_commit: None,
        }
    }

    /// Add a committed sub-DAG to the scoring window.
    ///
    /// `block_lookup` resolves BlockRef → Block (for ancestor inspection).
    ///
    /// Sui equivalent: `ScoringSubdag::add_subdags()`.
    pub fn add_subdag(
        &mut self,
        commit: &CommittedSubDag,
        block_lookup: impl Fn(&BlockRef) -> Option<Block>,
    ) {
        if self.first_commit.is_none() {
            self.first_commit = Some(commit.index);
        }
        self.last_commit = Some(commit.index);
        self.subdags_processed += 1;

        for block_ref in &commit.blocks {
            let block = match block_lookup(block_ref) {
                Some(b) => b,
                None => continue,
            };

            let block_author_stake = self.committee.stake(block.author);

            // Score strong-linked parents (round-adjacent only)
            for ancestor in &block.ancestors {
                // Strong link: ancestor.round == block.round - 1
                if block.round > 0 && ancestor.round == block.round - 1 {
                    if let Some(score) = self.scores.get_mut(ancestor.author as usize) {
                        *score += block_author_stake;
                    }
                }
            }
        }
    }

    /// Calculate final reputation scores from accumulated data.
    ///
    /// Sui equivalent: `ScoringSubdag::calculate_distributed_vote_scores()`.
    #[must_use]
    pub fn calculate_scores(&self) -> ReputationScores {
        let mut result = ReputationScores::new(self.committee.size());
        result.scores = self.scores.clone();
        if let (Some(first), Some(last)) = (self.first_commit, self.last_commit) {
            result.commit_range = (first, last);
        }
        result
    }

    /// Number of sub-DAGs processed.
    #[must_use]
    pub fn subdags_processed(&self) -> u64 {
        self.subdags_processed
    }

    /// Whether this window has enough data to produce meaningful scores.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.subdags_processed >= SCORING_UPDATE_INTERVAL
    }

    /// Reset for next window.
    pub fn reset(&mut self) {
        self.scores.fill(0);
        self.subdags_processed = 0;
        self.first_commit = None;
        self.last_commit = None;
    }
}

/// Computes and manages leader scores across scoring windows.
///
/// Maintains a running ScoringSubDag and produces new ReputationScores
/// every `SCORING_UPDATE_INTERVAL` commits.
pub struct LeaderScorer {
    current_window: ScoringSubDag,
    /// Latest computed scores.
    latest_scores: ReputationScores,
}

impl LeaderScorer {
    /// Create a new scorer.
    #[must_use]
    pub fn new(committee: Committee) -> Self {
        let n = committee.size();
        Self {
            current_window: ScoringSubDag::new(committee),
            latest_scores: ReputationScores::new(n),
        }
    }

    /// Process a committed sub-DAG. Returns new scores if the window is full.
    ///
    /// Sui equivalent: called after each commit in the pipeline.
    pub fn on_commit(
        &mut self,
        commit: &CommittedSubDag,
        block_lookup: impl Fn(&BlockRef) -> Option<Block>,
    ) -> Option<ReputationScores> {
        self.current_window.add_subdag(commit, block_lookup);

        if self.current_window.is_ready() {
            let scores = self.current_window.calculate_scores();
            self.latest_scores = scores.clone();
            self.current_window.reset();
            Some(scores)
        } else {
            None
        }
    }

    /// Get the latest scores (may be stale if window not yet full).
    #[must_use]
    pub fn latest_scores(&self) -> &ReputationScores {
        &self.latest_scores
    }

    /// Current window progress (subdags processed / interval).
    #[must_use]
    pub fn window_progress(&self) -> (u64, u64) {
        (
            self.current_window.subdags_processed(),
            SCORING_UPDATE_INTERVAL,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn committee4() -> Committee {
        Committee::new_for_test(4)
    }

    fn make_block_with_ancestors(
        round: Round,
        author: AuthorityIndex,
        ancestors: Vec<BlockRef>,
    ) -> Block {
        Block {
            epoch: 0,
            round,
            author,
            timestamp_ms: round as u64 * 1000,
            ancestors,
            transactions: vec![],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            state_root_smt: [0u8; 32],
            signature: vec![0xAA; 64],
        }
    }

    #[test]
    fn test_basic_scoring() {
        let committee = committee4();
        let mut scorer = ScoringSubDag::new(committee);

        // Round 1 blocks (parents for round 2)
        let r1: Vec<Block> = (0..4)
            .map(|a| make_block_with_ancestors(1, a, vec![]))
            .collect();
        let r1_refs: Vec<BlockRef> = r1.iter().map(|b| b.reference()).collect();

        // Round 2: all reference all R1 blocks
        let r2: Vec<Block> = (0..4)
            .map(|a| make_block_with_ancestors(2, a, r1_refs.clone()))
            .collect();

        let all_blocks: Vec<Block> = r1.iter().chain(r2.iter()).cloned().collect();
        let commit = CommittedSubDag {
            index: 0,
            leader: r2[0].reference(),
            blocks: all_blocks.iter().map(|b| b.reference()).collect(),
            timestamp_ms: 2000,
            previous_digest: CommitDigest([0; 32]),
            is_direct: true,
        };
        let all = all_blocks.clone();
        scorer.add_subdag(&commit, |r| {
            all.iter().find(|b| b.reference() == *r).cloned()
        });

        let scores = scorer.calculate_scores();
        // Each R1 authority gets 4 votes (from 4 R2 blocks, stake=1 each)
        assert_eq!(scores.scores, vec![4, 4, 4, 4]);
    }

    #[test]
    fn test_missing_authority_lower_score() {
        let committee = committee4();
        let mut scorer = ScoringSubDag::new(committee);

        let r1: Vec<Block> = (0..4)
            .map(|a| make_block_with_ancestors(1, a, vec![]))
            .collect();
        let r1_refs: Vec<BlockRef> = r1.iter().map(|b| b.reference()).collect();

        // R2: A,B,C reference all of R1. D only references A,B,C (not itself from R1).
        let mut r2 = Vec::new();
        for a in 0..3 {
            r2.push(make_block_with_ancestors(2, a, r1_refs.clone()));
        }
        // D references only A1, B1, C1 (not D1)
        let d_ancestors = vec![r1_refs[0], r1_refs[1], r1_refs[2]];
        r2.push(make_block_with_ancestors(2, 3, d_ancestors));

        let all: Vec<Block> = r1.iter().chain(r2.iter()).cloned().collect();
        let commit = CommittedSubDag {
            index: 0,
            leader: r2[0].reference(),
            blocks: all.iter().map(|b| b.reference()).collect(),
            timestamp_ms: 2000,
            previous_digest: CommitDigest([0; 32]),
            is_direct: true,
        };
        let all_c = all.clone();
        scorer.add_subdag(&commit, |r| {
            all_c.iter().find(|b| b.reference() == *r).cloned()
        });

        let scores = scorer.calculate_scores();
        // A,B,C: referenced by all 4 R2 blocks → 4
        // D: referenced by 3 R2 blocks (D didn't reference D1) → 3
        assert_eq!(scores.scores[0], 4);
        assert_eq!(scores.scores[3], 3, "D should have lower score");
    }

    #[test]
    fn test_non_adjacent_rounds_ignored() {
        let committee = committee4();
        let mut scorer = ScoringSubDag::new(committee);

        let r1 = make_block_with_ancestors(1, 0, vec![]);
        // R3 references R1 (skip R2) — NOT a strong link
        let r3 = make_block_with_ancestors(3, 1, vec![r1.reference()]);

        let all = vec![r1.clone(), r3.clone()];
        let commit = CommittedSubDag {
            index: 0,
            leader: r3.reference(),
            blocks: all.iter().map(|b| b.reference()).collect(),
            timestamp_ms: 3000,
            previous_digest: CommitDigest([0; 32]),
            is_direct: true,
        };
        let all_c = all.clone();
        scorer.add_subdag(&commit, |r| {
            all_c.iter().find(|b| b.reference() == *r).cloned()
        });

        let scores = scorer.calculate_scores();
        // R1 author should NOT get a vote (not round-adjacent to R3)
        assert_eq!(scores.scores[0], 0);
    }

    #[test]
    fn test_leader_scorer_window() {
        let committee = committee4();
        let mut scorer = LeaderScorer::new(committee.clone());

        // Process many commits (below interval)
        for i in 0..10 {
            let block = make_block_with_ancestors(1, 0, vec![]);
            let commit = CommittedSubDag {
                index: i,
                leader: block.reference(),
                blocks: vec![block.reference()],
                timestamp_ms: 1000,
                previous_digest: CommitDigest([0; 32]),
                is_direct: true,
            };
            let bc = block.clone();
            let result = scorer.on_commit(&commit, |r| {
                if *r == bc.reference() {
                    Some(bc.clone())
                } else {
                    None
                }
            });
            if i < SCORING_UPDATE_INTERVAL - 1 {
                assert!(result.is_none(), "window not full at commit {}", i);
            }
        }

        let (processed, interval) = scorer.window_progress();
        assert_eq!(processed, 10);
        assert_eq!(interval, SCORING_UPDATE_INTERVAL);
    }

    #[test]
    fn test_reset() {
        let committee = committee4();
        let mut scorer = ScoringSubDag::new(committee);

        let block = make_block_with_ancestors(1, 0, vec![]);
        let commit = CommittedSubDag {
            index: 0,
            leader: block.reference(),
            blocks: vec![block.reference()],
            timestamp_ms: 1000,
            previous_digest: CommitDigest([0; 32]),
            is_direct: true,
        };
        let bc = block.clone();
        scorer.add_subdag(&commit, |r| {
            if *r == bc.reference() {
                Some(bc.clone())
            } else {
                None
            }
        });
        assert_eq!(scorer.subdags_processed(), 1);

        scorer.reset();
        assert_eq!(scorer.subdags_processed(), 0);
        assert_eq!(scorer.calculate_scores().scores, vec![0, 0, 0, 0]);
    }
}
