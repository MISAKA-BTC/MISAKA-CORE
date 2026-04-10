// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Sui equivalent: consensus/core/src/ancestor.rs (461 lines)
//
//! Ancestor selection — chooses which blocks to include as parents.
//!
//! When proposing a new block at round R, we must include ≥2f+1
//! ancestors from round R-1. This module decides which ancestors
//! to select, filtering out underperforming or Byzantine authorities.
//!
//! ## Algorithm
//!
//! 1. Start with all blocks at round R-1.
//! 2. Filter: only ML-DSA-65 verified blocks (enforced by DagState).
//! 3. Score: authorities with low propagation scores may be excluded.
//! 4. Cap: never exclude more than f authorities (maintain quorum).
//! 5. Lock: state transitions locked for N rounds to prevent oscillation.

use crate::narwhal_dag::dag_state::DagState;
use crate::narwhal_dag::leader_schedule::ReputationScores;
use crate::narwhal_types::block::*;
use crate::narwhal_types::committee::{Committee, Stake};

/// Score threshold: authorities with score ≤ this % of highest are candidates for exclusion.
const SCORE_EXCLUSION_PCT: u64 = 20;

/// Rounds to lock an Include↔Exclude transition (prevents oscillation).
#[cfg(not(test))]
const STATE_LOCK_ROUNDS: u32 = 450;
#[cfg(test)]
const STATE_LOCK_ROUNDS: u32 = 5;

/// Per-authority inclusion/exclusion state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AncestorState {
    /// Authority's blocks should be included as ancestors.
    Include,
    /// Authority excluded (low propagation score at time of exclusion).
    Exclude { score: u64 },
}

/// Internal tracking per authority.
#[derive(Clone, Debug)]
struct AncestorInfo {
    state: AncestorState,
    /// Round at which state was last changed.
    locked_until: Round,
}

impl AncestorInfo {
    fn is_locked(&self, current_round: Round) -> bool {
        current_round < self.locked_until
    }

    fn set_lock(&mut self, current_round: Round) {
        self.locked_until = current_round.saturating_add(STATE_LOCK_ROUNDS);
    }
}

/// Manages ancestor inclusion/exclusion for block proposals.
///
/// Sui equivalent: `AncestorStateManager` in `ancestor.rs`.
pub struct AncestorSelector {
    committee: Committee,
    /// Per-authority state.
    infos: Vec<AncestorInfo>,
    /// Current propagation scores (updated externally).
    scores: ReputationScores,
    /// Maximum excluded stake (≤ fault_tolerance).
    max_excluded_stake: Stake,
}

impl AncestorSelector {
    /// Create a new selector for the given committee.
    #[must_use]
    pub fn new(committee: Committee) -> Self {
        let n = committee.size();
        let max_excluded = committee.fault_tolerance();
        Self {
            infos: vec![
                AncestorInfo {
                    state: AncestorState::Include,
                    locked_until: 0,
                };
                n
            ],
            scores: ReputationScores::new(n),
            max_excluded_stake: max_excluded,
            committee,
        }
    }

    /// Update propagation scores (called by round prober or leader scoring).
    pub fn set_scores(&mut self, scores: ReputationScores) {
        self.scores = scores;
    }

    /// Update ancestor states based on current scores.
    ///
    /// Call this periodically (e.g. every round or every N commits).
    /// Sui equivalent: `AncestorStateManager::update_all_ancestors_state()`.
    pub fn update_states(&mut self, current_round: Round) {
        let highest = self.scores.scores.iter().copied().max().unwrap_or(0);
        if highest == 0 {
            return;
        }

        let threshold = (highest * SCORE_EXCLUSION_PCT) / 100;

        let mut excluded_stake: Stake = self
            .infos
            .iter()
            .enumerate()
            .filter(|(_, info)| matches!(info.state, AncestorState::Exclude { .. }))
            .map(|(i, _)| self.committee.stake(i as AuthorityIndex))
            .sum();

        for i in 0..self.infos.len() {
            if self.infos[i].is_locked(current_round) {
                continue;
            }

            let score = self.scores.scores.get(i).copied().unwrap_or(0);

            match &self.infos[i].state {
                AncestorState::Include => {
                    if score <= threshold {
                        let stake = self.committee.stake(i as AuthorityIndex);
                        if excluded_stake + stake <= self.max_excluded_stake {
                            self.infos[i].state = AncestorState::Exclude { score };
                            self.infos[i].set_lock(current_round);
                            excluded_stake += stake;
                        }
                    }
                }
                AncestorState::Exclude { .. } => {
                    if score > threshold {
                        self.infos[i].state = AncestorState::Include;
                        self.infos[i].set_lock(current_round);
                        excluded_stake -= self.committee.stake(i as AuthorityIndex);
                    }
                }
            }
        }
    }

    /// Select ancestors for a block at `round`.
    ///
    /// Returns `BlockRef`s from `round - 1` that should be included,
    /// filtering out excluded authorities.
    ///
    /// Sui equivalent: called from `Core::smart_ancestors_to_propose()`.
    #[must_use]
    pub fn select_ancestors(&self, dag_state: &DagState, round: Round) -> Vec<BlockRef> {
        if round == 0 {
            return vec![];
        }
        let prev_round = round - 1;

        dag_state
            .get_blocks_at_round(prev_round)
            .iter()
            .filter(|b| self.is_included(b.author()))
            .map(|b| b.reference())
            .collect()
    }

    /// Check if an authority is currently included.
    #[must_use]
    pub fn is_included(&self, auth: AuthorityIndex) -> bool {
        self.infos
            .get(auth as usize)
            .map(|info| matches!(info.state, AncestorState::Include))
            .unwrap_or(true) // unknown authorities included by default
    }

    /// Get current state for all authorities.
    #[must_use]
    pub fn states(&self) -> Vec<(AuthorityIndex, AncestorState)> {
        self.infos
            .iter()
            .enumerate()
            .map(|(i, info)| (i as AuthorityIndex, info.state.clone()))
            .collect()
    }

    /// Number of currently excluded authorities.
    #[must_use]
    pub fn excluded_count(&self) -> usize {
        self.infos
            .iter()
            .filter(|i| matches!(i.state, AncestorState::Exclude { .. }))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::narwhal_dag::dag_state::DagStateConfig;

    fn make_block(round: Round, author: AuthorityIndex) -> VerifiedBlock {
        let block = Block {
            epoch: 0,
            round,
            author,
            timestamp_ms: round as u64 * 1000 + author as u64,
            ancestors: vec![],
            transactions: vec![vec![author as u8]],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xAA; 64],
        };
        VerifiedBlock::new_for_test(block)
    }

    #[test]
    fn test_initial_all_included() {
        let sel = AncestorSelector::new(Committee::new_for_test(4));
        for i in 0..4 {
            assert!(sel.is_included(i));
        }
        assert_eq!(sel.excluded_count(), 0);
    }

    #[test]
    fn test_low_score_excluded() {
        let mut sel = AncestorSelector::new(Committee::new_for_test(4));
        let mut scores = ReputationScores::new(4);
        scores.scores = vec![100, 100, 100, 5]; // D has very low score
        sel.set_scores(scores);
        sel.update_states(100);

        assert!(sel.is_included(0));
        assert!(sel.is_included(1));
        assert!(sel.is_included(2));
        assert!(!sel.is_included(3)); // D excluded
    }

    #[test]
    fn test_excluded_stake_cap() {
        // n=4, f=1 → max excluded stake = 1.
        // Only 1 authority can be excluded even if 2 have low scores.
        let mut sel = AncestorSelector::new(Committee::new_for_test(4));
        let mut scores = ReputationScores::new(4);
        scores.scores = vec![100, 100, 5, 5]; // C and D both low
        sel.set_scores(scores);
        sel.update_states(100);

        assert_eq!(
            sel.excluded_count(),
            1,
            "only 1 exclusion allowed (f=1 stake)"
        );
    }

    #[test]
    fn test_re_include_on_score_recovery() {
        let mut sel = AncestorSelector::new(Committee::new_for_test(4));
        let mut scores = ReputationScores::new(4);
        scores.scores = vec![100, 100, 100, 5];
        sel.set_scores(scores);
        sel.update_states(100);
        assert!(!sel.is_included(3));

        // Score recovers after lock
        let mut scores2 = ReputationScores::new(4);
        scores2.scores = vec![100, 100, 100, 80];
        sel.set_scores(scores2);
        sel.update_states(100 + STATE_LOCK_ROUNDS + 1);
        assert!(sel.is_included(3)); // re-included
    }

    #[test]
    fn test_locked_state_prevents_oscillation() {
        let mut sel = AncestorSelector::new(Committee::new_for_test(4));
        let mut scores = ReputationScores::new(4);
        scores.scores = vec![100, 100, 100, 5];
        sel.set_scores(scores);
        sel.update_states(100);
        assert!(!sel.is_included(3));

        // Immediately try to re-include (still locked)
        let mut scores2 = ReputationScores::new(4);
        scores2.scores = vec![100, 100, 100, 80];
        sel.set_scores(scores2);
        sel.update_states(101); // within lock period
        assert!(!sel.is_included(3), "should still be excluded (locked)");
    }

    #[test]
    fn test_select_ancestors_filters_excluded() {
        let committee = Committee::new_for_test(4);
        let mut sel = AncestorSelector::new(committee.clone());
        let mut dag = DagState::new(committee, DagStateConfig::default());

        // Add 4 blocks at round 1
        for auth in 0..4 {
            dag.accept_block(make_block(1, auth));
        }

        // Exclude authority 3
        let mut scores = ReputationScores::new(4);
        scores.scores = vec![100, 100, 100, 5];
        sel.set_scores(scores);
        sel.update_states(100);

        let ancestors = sel.select_ancestors(&dag, 2);
        assert_eq!(ancestors.len(), 3);
        assert!(ancestors.iter().all(|a| a.author != 3));
    }

    #[test]
    fn test_no_scores_no_exclusions() {
        let mut sel = AncestorSelector::new(Committee::new_for_test(4));
        sel.update_states(100); // no scores set
        assert_eq!(sel.excluded_count(), 0);
    }

    #[test]
    fn test_all_equal_scores_no_exclusion() {
        let mut sel = AncestorSelector::new(Committee::new_for_test(4));
        let mut scores = ReputationScores::new(4);
        scores.scores = vec![100, 100, 100, 100]; // all equal
        sel.set_scores(scores);
        sel.update_states(100);
        // threshold = 20% of 100 = 20. All scores (100) > 20 → no exclusions
        assert_eq!(sel.excluded_count(), 0);
    }
}
