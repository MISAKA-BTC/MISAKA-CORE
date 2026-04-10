// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! LeaderSchedule — reputation-weighted leader election.
//!
//! Sui equivalent: consensus/core/leader_schedule.rs (~850 lines)
//!
//! Leaders are selected per-round. Initially round-robin, then
//! reputation-weighted based on commit history.

use std::collections::HashMap;

use crate::narwhal_types::block::*;
use crate::narwhal_types::committee::{Committee, Stake};

// ═══════════════════════════════════════════════════════════
//  Reputation scores
// ═══════════════════════════════════════════════════════════

/// Reputation scores for leader election.
///
/// Authorities that produce blocks included in commits get higher scores.
/// Missing authorities get lower scores, reducing their leader probability.
#[derive(Clone, Debug)]
pub struct ReputationScores {
    /// Score per authority (index → score).
    pub scores: Vec<u64>,
    /// Commit range these scores cover.
    pub commit_range: (u64, u64),
}

impl ReputationScores {
    pub fn new(committee_size: usize) -> Self {
        Self {
            scores: vec![1; committee_size], // uniform initial
            commit_range: (0, 0),
        }
    }

    /// Update scores from committed sub-DAGs.
    ///
    /// Each authority gets +1 for each block included in a commit.
    /// The leader gets an additional +1 bonus.
    pub fn update_from_commits(&mut self, commits: &[(AuthorityIndex, Vec<AuthorityIndex>)]) {
        for (leader, block_authors) in commits {
            if let Some(s) = self.scores.get_mut(*leader as usize) {
                // SEC-FIX TM-1: saturating_add to prevent u64 overflow
                *s = s.saturating_add(1);
            }
            for author in block_authors {
                if let Some(s) = self.scores.get_mut(*author as usize) {
                    *s = s.saturating_add(1);
                }
            }
        }
    }

    /// Normalize scores to sum to `target_sum`.
    pub fn normalized(&self, target_sum: u64) -> Vec<u64> {
        let total: u64 = self.scores.iter().sum();
        if total == 0 {
            return vec![1; self.scores.len()];
        }
        self.scores
            .iter()
            .map(|s| (s * target_sum) / total)
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════
//  Leader schedule
// ═══════════════════════════════════════════════════════════

/// Leader election for each round.
#[derive(Clone, Debug)]
pub struct LeaderSchedule {
    /// Committee.
    committee: Committee,
    /// Number of leader slots per round (pipeline depth).
    /// Sui uses 1 for standard, 2 for pipelined Bullshark.
    num_leader_slots: u32,
    /// Reputation scores (updated periodically).
    reputation: ReputationScores,
    /// Task 6.1: Authorities penalized for equivocation.
    /// Score is reduced to 0 (but not removed from committee — ADA-style).
    equivocation_penalties: std::collections::HashSet<AuthorityIndex>,
}

impl LeaderSchedule {
    /// Create a new leader schedule with round-robin election.
    pub fn new(committee: Committee, num_leader_slots: u32) -> Self {
        let n = committee.size();
        Self {
            committee,
            num_leader_slots,
            reputation: ReputationScores::new(n),
            equivocation_penalties: std::collections::HashSet::new(),
        }
    }

    /// Get the leader for a given round and slot offset.
    ///
    /// With reputation: weighted selection seeded by round number.
    /// Without reputation (or uniform scores): simple round-robin.
    pub fn leader(&self, round: Round, slot_offset: u32) -> AuthorityIndex {
        let n = self.committee.size() as u32;
        if n == 0 {
            return 0;
        }

        // Effective slot = round * num_leader_slots + slot_offset
        let effective = round * self.num_leader_slots + slot_offset;

        // Check if reputation is non-uniform
        let max = self.reputation.scores.iter().max().copied().unwrap_or(1);
        let min = self.reputation.scores.iter().min().copied().unwrap_or(1);

        if max == min && self.equivocation_penalties.is_empty() {
            // Uniform scores, no penalties — round-robin
            effective % n
        } else {
            // Weighted selection using round as seed.
            // Task 6.1: Equivocating authorities get score 0 in leader selection.
            // SEC-FIX TM-1: Use normalized scores to bound weighted_slots size.
            // Raw scores can grow unbounded with many commits; normalizing
            // to 1000 total slots caps memory usage regardless of score magnitude.
            let norm = self.reputation.normalized(1000);
            let mut weighted_slots = Vec::new();
            for (i, &score) in norm.iter().enumerate() {
                let auth = i as AuthorityIndex;
                let effective_score = if self.equivocation_penalties.contains(&auth) {
                    0
                } else {
                    score
                };
                for _ in 0..effective_score {
                    weighted_slots.push(auth);
                }
            }
            if weighted_slots.is_empty() {
                // All penalized or zero scores → fallback to round-robin
                return effective % n;
            }
            let idx = effective as usize % weighted_slots.len();
            weighted_slots[idx]
        }
    }

    /// Convenience alias: leader for round at slot_offset=0.
    pub fn leader_at(&self, round: Round) -> AuthorityIndex {
        self.leader(round, 0)
    }

    /// Get all leaders for a round (one per slot).
    pub fn leaders_for_round(&self, round: Round) -> Vec<AuthorityIndex> {
        (0..self.num_leader_slots)
            .map(|offset| self.leader(round, offset))
            .collect()
    }

    /// Update reputation scores.
    pub fn update_reputation(&mut self, scores: ReputationScores) {
        self.reputation = scores;
    }

    /// Task 6.1: Penalize an authority for equivocation.
    ///
    /// The authority's leader score drops to 0, effectively excluding them
    /// from leader selection. This is ADA-style (no slashing, reversible).
    pub fn penalize_equivocator(&mut self, authority: AuthorityIndex) {
        self.equivocation_penalties.insert(authority);
    }

    /// Task 6.1: Check if an authority is penalized for equivocation.
    pub fn is_equivocator_penalized(&self, authority: AuthorityIndex) -> bool {
        self.equivocation_penalties.contains(&authority)
    }

    /// Task 6.1: Clear equivocation penalties (e.g., on epoch change).
    pub fn clear_equivocation_penalties(&mut self) {
        self.equivocation_penalties.clear();
    }

    /// Task 6.1: Number of penalized equivocators.
    pub fn num_penalized(&self) -> usize {
        self.equivocation_penalties.len()
    }

    /// Number of leader slots per round.
    pub fn num_leader_slots(&self) -> u32 {
        self.num_leader_slots
    }
}

// ═══════════════════════════════════════════════════════════
//  Threshold clock
// ═══════════════════════════════════════════════════════════

/// Tracks when enough authorities have produced blocks at a round.
///
/// A round is "ready" when ≥quorum authorities have produced blocks
/// for that round. This triggers the local node to advance.
pub struct ThresholdClock {
    /// Committee.
    committee: Committee,
    /// Current local round.
    current_round: Round,
    /// Authorities observed at current round.
    observed: HashMap<Round, StakeAggregator>,
}

impl ThresholdClock {
    pub fn new(committee: Committee) -> Self {
        Self {
            current_round: 0,
            observed: HashMap::new(),
            committee,
        }
    }

    /// Observe a block from an authority at a round.
    /// Returns the new round if quorum was reached.
    pub fn observe(&mut self, round: Round, author: AuthorityIndex) -> Option<Round> {
        if round < self.current_round {
            return None;
        }

        let agg = self
            .observed
            .entry(round)
            .or_insert_with(|| StakeAggregator::new(self.committee.clone()));
        agg.add(author);

        // Check if this round reached quorum
        if round >= self.current_round && agg.reached_quorum() {
            let new_round = round + 1;
            if new_round > self.current_round {
                self.current_round = new_round;
                // GC old rounds
                self.observed.retain(|r, _| *r >= round.saturating_sub(2));
                return Some(new_round);
            }
        }
        None
    }

    /// Current round.
    pub fn current_round(&self) -> Round {
        self.current_round
    }

    /// Set current round (e.g., after recovery).
    pub fn set_round(&mut self, round: Round) {
        self.current_round = round;
    }
}

// ═══════════════════════════════════════════════════════════
//  Stake aggregator
// ═══════════════════════════════════════════════════════════

/// Aggregates stake from multiple authorities.
pub struct StakeAggregator {
    committee: Committee,
    stake_by_author: HashMap<AuthorityIndex, Stake>,
    total_stake: Stake,
}

impl StakeAggregator {
    pub fn new(committee: Committee) -> Self {
        Self {
            committee,
            stake_by_author: HashMap::new(),
            total_stake: 0,
        }
    }

    /// Add stake from an authority. Returns true if newly added.
    pub fn add(&mut self, author: AuthorityIndex) -> bool {
        if self.stake_by_author.contains_key(&author) {
            return false;
        }
        let stake = self.committee.stake(author);
        self.stake_by_author.insert(author, stake);
        // SEC-FIX T3-H3: saturating_add to prevent u64 overflow
        self.total_stake = self.total_stake.saturating_add(stake);
        true
    }

    /// Check if quorum reached.
    pub fn reached_quorum(&self) -> bool {
        self.committee.reached_quorum(self.total_stake)
    }

    /// Check if validity threshold reached.
    pub fn reached_validity(&self) -> bool {
        self.committee.reached_validity(self.total_stake)
    }

    /// Current aggregated stake.
    pub fn total(&self) -> Stake {
        self.total_stake
    }
}

// ═══════════════════════════════════════════════════════════
//  Timeout backoff
// ═══════════════════════════════════════════════════════════

/// Exponential backoff for round timeouts.
///
/// Base timeout: 2000ms
/// Max timeout: 60000ms
/// Backoff factor: 1.5x per consecutive timeout
pub struct TimeoutBackoff {
    pub base_ms: u64,
    pub max_ms: u64,
    pub consecutive_timeouts: u32,
}

impl TimeoutBackoff {
    pub fn new(base_ms: u64, max_ms: u64) -> Self {
        Self {
            base_ms,
            max_ms,
            consecutive_timeouts: 0,
        }
    }

    /// Get the current timeout duration in milliseconds.
    pub fn timeout_ms(&self) -> u64 {
        let mut t = self.base_ms;
        for _ in 0..self.consecutive_timeouts {
            t = (t * 3) / 2; // 1.5x
            if t >= self.max_ms {
                return self.max_ms;
            }
        }
        t.min(self.max_ms)
    }

    /// Record a timeout (increase backoff).
    pub fn record_timeout(&mut self) {
        self.consecutive_timeouts = self.consecutive_timeouts.saturating_add(1);
    }

    /// Reset backoff (successful round).
    pub fn reset(&mut self) {
        self.consecutive_timeouts = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_round_robin_leader() {
        let c = Committee::new_for_test(4);
        let ls = LeaderSchedule::new(c, 1);
        assert_eq!(ls.leader(0, 0), 0);
        assert_eq!(ls.leader(1, 0), 1);
        assert_eq!(ls.leader(2, 0), 2);
        assert_eq!(ls.leader(3, 0), 3);
        assert_eq!(ls.leader(4, 0), 0); // wrap
    }

    #[test]
    fn test_reputation_scores() {
        let mut scores = ReputationScores::new(4);
        scores.update_from_commits(&[
            (0, vec![0, 1, 2]), // leader 0, blocks from 0,1,2
            (1, vec![1, 2, 3]), // leader 1, blocks from 1,2,3
        ]);
        // Authority 0: 1 (init) + 1 (leader) + 1 (block) = 3
        // Authority 1: 1 + 1 (leader) + 2 (blocks) = 4
        // Authority 2: 1 + 2 (blocks) = 3
        // Authority 3: 1 + 1 (block) = 2
        assert_eq!(scores.scores, vec![3, 4, 3, 2]);
    }

    #[test]
    fn test_threshold_clock() {
        let c = Committee::new_for_test(4); // quorum = 3
        let mut clock = ThresholdClock::new(c);
        assert_eq!(clock.current_round(), 0);

        // Observe 2 at round 0 — not enough
        assert!(clock.observe(0, 0).is_none());
        assert!(clock.observe(0, 1).is_none());
        // 3rd observation — quorum!
        assert_eq!(clock.observe(0, 2), Some(1));
        assert_eq!(clock.current_round(), 1);
    }

    #[test]
    fn test_stake_aggregator() {
        let c = Committee::new_for_test(4); // quorum = 3
        let mut agg = StakeAggregator::new(c);
        assert!(!agg.reached_quorum());
        agg.add(0);
        agg.add(1);
        assert!(!agg.reached_quorum());
        agg.add(2);
        assert!(agg.reached_quorum());
        assert!(!agg.add(2)); // duplicate
    }

    #[test]
    fn test_timeout_backoff() {
        let mut tb = TimeoutBackoff::new(2000, 60000);
        assert_eq!(tb.timeout_ms(), 2000);
        tb.record_timeout();
        assert_eq!(tb.timeout_ms(), 3000); // 2000 * 1.5
        tb.record_timeout();
        assert_eq!(tb.timeout_ms(), 4500); // 3000 * 1.5
        tb.reset();
        assert_eq!(tb.timeout_ms(), 2000);
    }

    // ── Task 6.1: Equivocation penalty tests ──

    #[test]
    fn task_6_1_equivocator_excluded_from_leader() {
        let c = Committee::new_for_test(4);
        let mut sched = LeaderSchedule::new(c, 1);

        // Before penalty: round-robin works normally
        let leaders_before: Vec<AuthorityIndex> = (0..8).map(|r| sched.leader(r, 0)).collect();
        // Should hit all 4 authorities across 8 rounds
        let unique_before: std::collections::HashSet<_> = leaders_before.iter().collect();
        assert_eq!(unique_before.len(), 4, "all 4 authorities should lead");

        // Penalize authority 0 for equivocation
        sched.penalize_equivocator(0);
        assert!(sched.is_equivocator_penalized(0));

        // After penalty: authority 0 should never be leader
        let leaders_after: Vec<AuthorityIndex> = (0..100).map(|r| sched.leader(r, 0)).collect();
        assert!(
            !leaders_after.contains(&0),
            "equivocator authority 0 must not be selected as leader"
        );
    }

    #[test]
    fn task_6_1_clear_penalties_on_epoch() {
        let c = Committee::new_for_test(4);
        let mut sched = LeaderSchedule::new(c, 1);

        sched.penalize_equivocator(1);
        sched.penalize_equivocator(2);
        assert_eq!(sched.num_penalized(), 2);

        sched.clear_equivocation_penalties();
        assert_eq!(sched.num_penalized(), 0);
        assert!(!sched.is_equivocator_penalized(1));
    }

    #[test]
    fn task_6_1_all_penalized_fallback_to_round_robin() {
        let c = Committee::new_for_test(4);
        let mut sched = LeaderSchedule::new(c, 1);

        // Penalize ALL authorities
        for i in 0..4 {
            sched.penalize_equivocator(i);
        }

        // Should fallback to round-robin (no weighted slots available)
        let leader = sched.leader(5, 0);
        assert!(leader < 4, "fallback should produce valid authority");
    }
}
