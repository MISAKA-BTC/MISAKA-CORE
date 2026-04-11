// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Sui equivalent: consensus/core/src/threshold_clock.rs (215 lines)
//
//! Threshold Clock — determines when we may advance to the next round.
//!
//! The local node advances to round R when it has observed blocks from
//! ≥ 2f+1 stake at round R-1. Before that threshold is reached, the
//! node stays at R-1 and must not propose at R.
//!
//! Extracted from `leader_schedule.rs` for single-responsibility.
//! `leader_schedule.rs` re-exports these types for backward compatibility.

use crate::narwhal_types::block::{AuthorityIndex, Round};
use crate::narwhal_types::committee::{Committee, Stake};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
//  Stake Aggregator
// ═══════════════════════════════════════════════════════════════

/// Aggregates stake from distinct authorities.
///
/// Deduplicates: calling `add(author)` twice has no effect.
/// Sui equivalent: `StakeAggregator` (inlined in threshold_clock.rs).
pub struct StakeAggregator {
    committee: Committee,
    seen: HashMap<AuthorityIndex, Stake>,
    total: Stake,
}

impl StakeAggregator {
    #[must_use]
    pub fn new(committee: Committee) -> Self {
        Self {
            committee,
            seen: HashMap::new(),
            total: 0,
        }
    }

    /// Add an authority's stake. Returns `true` if this was a new addition.
    pub fn add(&mut self, author: AuthorityIndex) -> bool {
        if self.seen.contains_key(&author) {
            return false;
        }
        let stake = self.committee.stake(author);
        self.seen.insert(author, stake);
        // SEC-FIX T3-H2: saturating_add to prevent u64 overflow
        self.total = self.total.saturating_add(stake);
        true
    }

    /// True if accumulated stake ≥ quorum threshold.
    #[must_use]
    pub fn reached_quorum(&self) -> bool {
        self.committee.reached_quorum(self.total)
    }

    /// True if accumulated stake ≥ validity threshold (f+1).
    #[must_use]
    pub fn reached_validity(&self) -> bool {
        self.committee.reached_validity(self.total)
    }

    /// Current accumulated stake.
    #[must_use]
    pub fn total(&self) -> Stake {
        self.total
    }

    /// Number of distinct authorities added.
    #[must_use]
    pub fn count(&self) -> usize {
        self.seen.len()
    }

    /// Reset.
    pub fn clear(&mut self) {
        self.seen.clear();
        self.total = 0;
    }
}

// ═══════════════════════════════════════════════════════════════
//  Threshold Clock
// ═══════════════════════════════════════════════════════════════

/// Determines when the local node may advance to the next round.
///
/// Tracks block arrivals per round. When ≥quorum stake has produced
/// blocks at round R, the node advances to R+1.
///
/// Sui equivalent: `ThresholdClock` in `threshold_clock.rs`.
pub struct ThresholdClock {
    committee: Committee,
    /// Current local round (we may propose at this round).
    current_round: Round,
    /// Per-round stake aggregators.
    observed: HashMap<Round, StakeAggregator>,
}

impl ThresholdClock {
    /// Create a new clock starting at round 0.
    #[must_use]
    pub fn new(committee: Committee) -> Self {
        Self {
            current_round: 0,
            observed: HashMap::new(),
            committee,
        }
    }

    /// Observe a block from `author` at `round`.
    ///
    /// Returns `Some(new_round)` if quorum was reached and the clock
    /// advanced. Returns `None` otherwise.
    ///
    /// Sui equivalent: `ThresholdClock::new_block()` → advance check.
    pub fn observe(&mut self, round: Round, author: AuthorityIndex) -> Option<Round> {
        if round < self.current_round {
            return None; // stale
        }

        let agg = self
            .observed
            .entry(round)
            .or_insert_with(|| StakeAggregator::new(self.committee.clone()));
        agg.add(author);

        if round >= self.current_round && agg.reached_quorum() {
            let new_round = round.saturating_add(1);
            if new_round > self.current_round {
                self.current_round = new_round;
                // GC: keep only recent 2 rounds
                self.observed.retain(|&r, _| r >= round.saturating_sub(2));
                return Some(new_round);
            }
        }
        None
    }

    /// Current round (the round we are allowed to propose at).
    #[must_use]
    pub fn current_round(&self) -> Round {
        self.current_round
    }

    /// Manually set the round (recovery).
    pub fn set_round(&mut self, round: Round) {
        self.current_round = round;
    }

    /// Get stake observed at a round.
    #[must_use]
    pub fn stake_at_round(&self, round: Round) -> Stake {
        self.observed.get(&round).map(|a| a.total()).unwrap_or(0)
    }

    /// Committee reference.
    #[must_use]
    pub fn committee(&self) -> &Committee {
        &self.committee
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn committee4() -> Committee {
        Committee::new_for_test(4)
    }

    #[test]
    fn test_advance_on_quorum() {
        let mut clock = ThresholdClock::new(committee4());
        assert_eq!(clock.current_round(), 0);
        // 3 of 4 = quorum → advance
        assert_eq!(clock.observe(1, 0), None);
        assert_eq!(clock.observe(1, 1), None);
        assert_eq!(clock.observe(1, 2), Some(2)); // quorum reached
        assert_eq!(clock.current_round(), 2);
    }

    #[test]
    fn test_no_advance_below_quorum() {
        let mut clock = ThresholdClock::new(committee4());
        assert_eq!(clock.observe(1, 0), None);
        assert_eq!(clock.observe(1, 1), None);
        assert_eq!(clock.current_round(), 0);
    }

    #[test]
    fn test_duplicate_observer_ignored() {
        let mut clock = ThresholdClock::new(committee4());
        clock.observe(1, 0);
        clock.observe(1, 0); // duplicate
        clock.observe(1, 0); // duplicate
        assert_eq!(clock.stake_at_round(1), 1); // only 1 authority's stake
    }

    #[test]
    fn test_stale_round_ignored() {
        let mut clock = ThresholdClock::new(committee4());
        clock.observe(1, 0);
        clock.observe(1, 1);
        clock.observe(1, 2); // advance to 2
        assert_eq!(clock.observe(0, 3), None); // round 0 is stale
    }

    #[test]
    fn test_skip_round() {
        let mut clock = ThresholdClock::new(committee4());
        // Skip round 1, observe round 5 directly
        clock.observe(5, 0);
        clock.observe(5, 1);
        let result = clock.observe(5, 2);
        assert_eq!(result, Some(6));
        assert_eq!(clock.current_round(), 6);
    }

    #[test]
    fn test_stake_aggregator_dedup() {
        let mut agg = StakeAggregator::new(committee4());
        assert!(agg.add(0));
        assert!(!agg.add(0)); // duplicate
        assert_eq!(agg.count(), 1);
        assert_eq!(agg.total(), 1);
    }

    #[test]
    fn test_stake_aggregator_quorum() {
        let committee = committee4();
        let mut agg = StakeAggregator::new(committee);
        agg.add(0);
        agg.add(1);
        assert!(!agg.reached_quorum()); // 2 < 3
        agg.add(2);
        assert!(agg.reached_quorum()); // 3 = quorum
    }
}
