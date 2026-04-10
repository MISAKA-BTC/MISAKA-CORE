// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Sui equivalent: consensus/core/src/commit_observer.rs (803 lines)
//
//! Commit Observer — receives committed sub-DAGs and notifies downstream.
//!
//! Extracted from `pipeline.rs::CommitObserver`.
//!
//! Responsibilities:
//! - Accumulate reputation from committed sub-DAGs (leader + block authors)
//! - Build ReputationScores for leader schedule rotation
//! - Track total commits (monotonic counter)
//! - Notify downstream consumers (executor, indexer, RPC)

use crate::narwhal_dag::leader_schedule::ReputationScores;
use crate::narwhal_types::block::AuthorityIndex;
use crate::narwhal_types::commit::CommittedSubDag;

/// Observes committed sub-DAGs and builds reputation scores.
///
/// Sui equivalent: `CommitObserver` (commit_observer.rs).
/// MISAKA adaptation: reputation is score-based (no delegation weight).
pub struct CommitObserver {
    /// Window of (leader, block_authors) from recent commits.
    reputation_window: Vec<(AuthorityIndex, Vec<AuthorityIndex>)>,
    /// Maximum window size before oldest entry is evicted.
    max_window: usize,
    /// Total commits observed (monotonic counter).
    total_commits: u64,
}

impl CommitObserver {
    /// Create a new observer.
    ///
    /// `max_window`: number of recent commits to keep for reputation scoring.
    /// Sui default: 300 commits.
    #[must_use]
    pub fn new(max_window: usize) -> Self {
        Self {
            reputation_window: Vec::with_capacity(max_window),
            max_window,
            total_commits: 0,
        }
    }

    /// Observe a committed sub-DAG.
    ///
    /// Records the leader and block authors for reputation scoring.
    /// Evicts oldest entry if window is full.
    pub fn observe(&mut self, sub_dag: &CommittedSubDag) {
        let leader_author = sub_dag.leader.author;
        let block_authors: Vec<AuthorityIndex> = sub_dag.blocks.iter().map(|r| r.author).collect();

        if self.reputation_window.len() >= self.max_window {
            self.reputation_window.remove(0);
        }
        self.reputation_window.push((leader_author, block_authors));
        self.total_commits += 1;
    }

    /// Build reputation scores from the observation window.
    ///
    /// Each authority gets +1 for each block included in a commit.
    /// The leader gets an additional +1 bonus.
    #[must_use]
    pub fn build_reputation_scores(&self, committee_size: usize) -> ReputationScores {
        let mut scores = ReputationScores::new(committee_size);
        for (leader, authors) in &self.reputation_window {
            scores.scores[*leader as usize] += 1; // leader bonus
            for author in authors {
                if (*author as usize) < scores.scores.len() {
                    scores.scores[*author as usize] += 1;
                }
            }
        }
        scores
    }

    /// Total commits observed.
    #[must_use]
    pub fn total_commits(&self) -> u64 {
        self.total_commits
    }

    /// Current window size.
    #[must_use]
    pub fn window_size(&self) -> usize {
        self.reputation_window.len()
    }

    /// Clear the observation window (e.g., on epoch change).
    pub fn reset(&mut self) {
        self.reputation_window.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::narwhal_types::block::*;
    use crate::narwhal_types::commit::*;

    fn commit(
        index: CommitIndex,
        leader: AuthorityIndex,
        authors: &[AuthorityIndex],
    ) -> CommittedSubDag {
        CommittedSubDag {
            index,
            leader: BlockRef::new(1, leader, BlockDigest([0xAA; 32])),
            blocks: authors
                .iter()
                .map(|&a| BlockRef::new(1, a, BlockDigest([a as u8; 32])))
                .collect(),
            timestamp_ms: 1000,
            previous_digest: CommitDigest([0; 32]),
            is_direct: true,
        }
    }

    #[test]
    fn test_observe_and_count() {
        let mut obs = CommitObserver::new(100);
        obs.observe(&commit(0, 0, &[0, 1, 2, 3]));
        assert_eq!(obs.total_commits(), 1);
        assert_eq!(obs.window_size(), 1);
    }

    #[test]
    fn test_reputation_scores() {
        let mut obs = CommitObserver::new(100);
        obs.observe(&commit(0, 0, &[0, 1, 2, 3]));
        let scores = obs.build_reputation_scores(4);
        // Authority 0: initial (1) + leader bonus (1) + block author (1) = 3
        assert_eq!(scores.scores[0], 3);
        // Authority 1: initial (1) + block author (1) = 2
        assert_eq!(scores.scores[1], 2);
    }

    #[test]
    fn test_window_eviction() {
        let mut obs = CommitObserver::new(3);
        obs.observe(&commit(0, 0, &[0]));
        obs.observe(&commit(1, 1, &[1]));
        obs.observe(&commit(2, 2, &[2]));
        assert_eq!(obs.window_size(), 3);
        obs.observe(&commit(3, 3, &[3])); // evicts oldest
        assert_eq!(obs.window_size(), 3);
    }

    #[test]
    fn test_reset() {
        let mut obs = CommitObserver::new(100);
        obs.observe(&commit(0, 0, &[0, 1]));
        obs.reset();
        assert_eq!(obs.window_size(), 0);
        assert_eq!(obs.total_commits(), 1); // counter not reset
    }

    #[test]
    fn test_empty_scores() {
        let obs = CommitObserver::new(100);
        let scores = obs.build_reputation_scores(4);
        assert_eq!(scores.scores, vec![1, 1, 1, 1]); // uniform initial
    }
}
