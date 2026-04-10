// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Ported from sui commit 0f58433, path: consensus/core/src/round_tracker.rs
//
//! Round Tracker — self-node view of round progression and quorum state.
//!
//! Complements the existing components:
//!
//! | Component        | Responsibility                                   |
//! |------------------|--------------------------------------------------|
//! | ThresholdClock   | Advances local round when quorum reached          |
//! | LeaderTimeout    | Timer for leader block arrival at each round       |
//! | RoundProber      | Network-wide peer round queries (remote calls)     |
//! | **RoundTracker** | Local aggregation of round state + metrics export  |
//!
//! RoundTracker is the **single point of truth** for the node's round state.
//! It observes ThresholdClock advancements, tracks per-authority highest
//! accepted rounds, computes quorum round, and exports metrics.
//!
//! See docs/round_tracking.md for the full responsibility separation.

use std::collections::HashMap;

use crate::narwhal_types::block::{AuthorityIndex, Round};
use crate::narwhal_types::committee::Committee;

// ═══════════════════════════════════════════════════════════
//  Configuration
// ═══════════════════════════════════════════════════════════

/// Configuration for [`RoundTracker`].
#[derive(Clone, Debug)]
pub struct RoundTrackerConfig {
    /// Number of recent rounds to keep for propagation delay averaging.
    /// Default: 10.
    pub delay_window: usize,
}

impl Default for RoundTrackerConfig {
    fn default() -> Self {
        Self { delay_window: 10 }
    }
}

// ═══════════════════════════════════════════════════════════
//  Per-authority round state
// ═══════════════════════════════════════════════════════════

/// Round state for a single authority as seen by this node.
#[derive(Debug, Clone, Default)]
pub struct AuthorityRoundState {
    /// Highest round at which we have accepted a block from this authority.
    pub highest_accepted_round: Round,
    /// Number of blocks accepted from this authority (all rounds).
    pub blocks_accepted: u64,
    /// Whether this authority is considered "lagging" relative to quorum round.
    pub is_lagging: bool,
}

// ═══════════════════════════════════════════════════════════
//  Peer sync status
// ═══════════════════════════════════════════════════════════

/// Sync classification for a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSyncStatus {
    /// Peer's highest accepted round is at or above quorum round.
    Synced,
    /// Peer is 1-2 rounds behind quorum round.
    SlightlyBehind,
    /// Peer is 3+ rounds behind quorum round.
    Lagging,
    /// No blocks received from this peer yet.
    Unknown,
}

// ═══════════════════════════════════════════════════════════
//  Metrics
// ═══════════════════════════════════════════════════════════

/// RoundTracker metrics for observability.
#[derive(Debug, Clone, Default)]
pub struct RoundTrackerMetrics {
    /// Total round advancements observed.
    pub round_advancements: u64,
    /// Total blocks observed.
    pub blocks_observed: u64,
    /// Number of quorum round updates.
    pub quorum_round_updates: u64,
    /// Number of authorities currently lagging.
    pub authorities_lagging: u32,
    /// Current propagation delay (own proposed round - quorum round).
    pub propagation_delay: u32,
    /// Smoothed average propagation delay.
    pub avg_propagation_delay: f64,
}

// ═══════════════════════════════════════════════════════════
//  RoundTracker
// ═══════════════════════════════════════════════════════════

/// Tracks round progression from this node's perspective.
///
/// Aggregates information from ThresholdClock (round advancement),
/// accepted blocks (per-authority rounds), and computes derived
/// state like quorum round and propagation delay.
///
/// # Integration
///
/// ```text
/// ThresholdClock.observe() ──> RoundTracker.on_round_advance()
/// BlockManager.accept()   ──> RoundTracker.on_block_accepted()
/// LeaderTimeout.fire()    ──> RoundTracker.on_leader_timeout()
/// RoundProber.probe()     ──> reads RoundTracker.quorum_round()
/// AncestorSelector        ──> reads RoundTracker.peer_sync_status()
/// ```
pub struct RoundTracker {
    /// Our authority index.
    our_authority: AuthorityIndex,
    /// Committee for stake/quorum calculations.
    committee: Committee,
    /// Current local round (from ThresholdClock).
    current_round: Round,
    /// Highest round we have proposed at.
    last_proposed_round: Round,
    /// Per-authority round state.
    authority_state: HashMap<AuthorityIndex, AuthorityRoundState>,
    /// Quorum round: highest round where ≥ quorum authorities have blocks.
    quorum_round: Round,
    /// Recent propagation delays for smoothing.
    delay_history: Vec<u32>,
    /// Configuration.
    config: RoundTrackerConfig,
    /// Leader timeout counter per round (for detecting stuck rounds).
    timeouts_at_current_round: u32,
    /// Total leader timeouts across all rounds.
    total_timeouts: u64,
    /// Metrics.
    metrics: RoundTrackerMetrics,
}

impl RoundTracker {
    /// Create a new tracker for the given committee.
    pub fn new(
        committee: Committee,
        our_authority: AuthorityIndex,
        config: RoundTrackerConfig,
    ) -> Self {
        let mut authority_state = HashMap::new();
        for i in 0..committee.size() as u32 {
            authority_state.insert(i, AuthorityRoundState::default());
        }
        Self {
            our_authority,
            committee,
            current_round: 0,
            last_proposed_round: 0,
            authority_state,
            quorum_round: 0,
            delay_history: Vec::with_capacity(config.delay_window),
            config,
            timeouts_at_current_round: 0,
            total_timeouts: 0,
            metrics: RoundTrackerMetrics::default(),
        }
    }

    // ─── Event handlers ─────────────────────────────────

    /// Called when ThresholdClock advances to a new round.
    ///
    /// This is the primary round advancement signal. It should be called
    /// from CoreEngine whenever threshold_clock.observe() returns Some(new_round).
    pub fn on_round_advance(&mut self, new_round: Round) {
        if new_round > self.current_round {
            self.current_round = new_round;
            self.timeouts_at_current_round = 0;
            self.metrics.round_advancements += 1;

            // Update propagation delay: proposed - quorum
            let delay = self.last_proposed_round.saturating_sub(self.quorum_round);
            self.record_delay(delay);
        }
    }

    /// Called when a block is accepted into the DAG.
    ///
    /// Updates per-authority round state and recomputes quorum round.
    pub fn on_block_accepted(&mut self, round: Round, author: AuthorityIndex) {
        self.metrics.blocks_observed += 1;

        if let Some(state) = self.authority_state.get_mut(&author) {
            if round > state.highest_accepted_round {
                state.highest_accepted_round = round;
            }
            state.blocks_accepted += 1;
        }

        // Recompute quorum round.
        self.recompute_quorum_round();
    }

    /// Called when we propose a block at a given round.
    pub fn on_block_proposed(&mut self, round: Round) {
        if round > self.last_proposed_round {
            self.last_proposed_round = round;
        }
    }

    /// Called when a leader timeout fires.
    pub fn on_leader_timeout(&mut self) {
        self.timeouts_at_current_round += 1;
        self.total_timeouts += 1;
    }

    // ─── Queries ────────────────────────────────────────

    /// Current local round.
    pub fn current_round(&self) -> Round {
        self.current_round
    }

    /// Highest round we have proposed.
    pub fn last_proposed_round(&self) -> Round {
        self.last_proposed_round
    }

    /// Quorum round: highest round where ≥ 2f+1 authorities have blocks.
    pub fn quorum_round(&self) -> Round {
        self.quorum_round
    }

    /// Propagation delay: proposed round - quorum round.
    ///
    /// A high delay means our blocks take long to reach quorum.
    /// This is relevant for PQ networks where block sizes are larger.
    pub fn propagation_delay(&self) -> u32 {
        self.last_proposed_round.saturating_sub(self.quorum_round)
    }

    /// Smoothed average propagation delay.
    pub fn avg_propagation_delay(&self) -> f64 {
        if self.delay_history.is_empty() {
            return 0.0;
        }
        let sum: u64 = self.delay_history.iter().map(|&d| d as u64).sum();
        sum as f64 / self.delay_history.len() as f64
    }

    /// Number of leader timeouts at the current round.
    pub fn timeouts_at_current_round(&self) -> u32 {
        self.timeouts_at_current_round
    }

    /// Total leader timeouts across all rounds.
    pub fn total_timeouts(&self) -> u64 {
        self.total_timeouts
    }

    /// Highest accepted round for a given authority.
    pub fn authority_accepted_round(&self, authority: AuthorityIndex) -> Round {
        self.authority_state
            .get(&authority)
            .map(|s| s.highest_accepted_round)
            .unwrap_or(0)
    }

    /// Sync status for a peer relative to quorum round.
    pub fn peer_sync_status(&self, authority: AuthorityIndex) -> PeerSyncStatus {
        let accepted = self.authority_accepted_round(authority);
        if accepted == 0 {
            return PeerSyncStatus::Unknown;
        }
        let gap = self.quorum_round.saturating_sub(accepted);
        match gap {
            0 => PeerSyncStatus::Synced,
            1..=2 => PeerSyncStatus::SlightlyBehind,
            _ => PeerSyncStatus::Lagging,
        }
    }

    /// Number of authorities currently lagging.
    pub fn num_lagging(&self) -> u32 {
        let mut count = 0;
        for (&auth, _) in &self.authority_state {
            if self.peer_sync_status(auth) == PeerSyncStatus::Lagging {
                count += 1;
            }
        }
        count
    }

    /// Number of authorities that are synced (at or above quorum round).
    pub fn num_synced(&self) -> u32 {
        let mut count = 0;
        for (&auth, _) in &self.authority_state {
            if self.peer_sync_status(auth) == PeerSyncStatus::Synced {
                count += 1;
            }
        }
        count
    }

    /// Snapshot of per-authority highest accepted rounds.
    pub fn authority_rounds(&self) -> Vec<(AuthorityIndex, Round)> {
        let mut rounds: Vec<_> = self
            .authority_state
            .iter()
            .map(|(&auth, s)| (auth, s.highest_accepted_round))
            .collect();
        rounds.sort_by_key(|&(auth, _)| auth);
        rounds
    }

    /// Metrics snapshot.
    pub fn metrics(&self) -> RoundTrackerMetrics {
        let mut m = self.metrics.clone();
        m.authorities_lagging = self.num_lagging();
        m.propagation_delay = self.propagation_delay();
        m.avg_propagation_delay = self.avg_propagation_delay();
        m
    }

    /// Reset for epoch transition.
    pub fn reset_for_epoch(&mut self, committee: Committee) {
        self.committee = committee;
        self.current_round = 0;
        self.last_proposed_round = 0;
        self.quorum_round = 0;
        self.timeouts_at_current_round = 0;
        self.delay_history.clear();
        self.authority_state.clear();
        for i in 0..self.committee.size() as u32 {
            self.authority_state
                .insert(i, AuthorityRoundState::default());
        }
        // Metrics preserved across resets for observability.
    }

    // ─── Internal ───────────────────────────────────────

    fn recompute_quorum_round(&mut self) {
        // Collect all authority accepted rounds, sorted descending.
        let mut rounds: Vec<Round> = self
            .authority_state
            .values()
            .map(|s| s.highest_accepted_round)
            .collect();
        rounds.sort_unstable_by(|a, b| b.cmp(a));

        // Quorum round is the round at position quorum_index (0-based).
        // With n=7, f=2, quorum=5 → index 4 (5th highest).
        let n = self.committee.size();
        let quorum_count = n - (n - 1) / 3; // Same formula as Committee
        let quorum_idx = quorum_count.saturating_sub(1);

        let new_quorum = if quorum_idx < rounds.len() {
            rounds[quorum_idx]
        } else {
            0
        };

        if new_quorum != self.quorum_round {
            self.quorum_round = new_quorum;
            self.metrics.quorum_round_updates += 1;

            // Update lagging status.
            for (&_auth, state) in &mut self.authority_state {
                state.is_lagging =
                    self.quorum_round > 0 && state.highest_accepted_round + 3 <= self.quorum_round;
            }
        }
    }

    fn record_delay(&mut self, delay: u32) {
        if self.delay_history.len() >= self.config.delay_window {
            self.delay_history.remove(0);
        }
        self.delay_history.push(delay);
    }
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_committee(n: usize) -> Committee {
        Committee::new_for_test(n)
    }

    // ── test: basic round advance ────────────────────────

    #[test]
    fn test_round_advance() {
        let committee = make_committee(7);
        let mut tracker = RoundTracker::new(committee, 0, RoundTrackerConfig::default());

        assert_eq!(tracker.current_round(), 0);

        tracker.on_round_advance(1);
        assert_eq!(tracker.current_round(), 1);
        assert_eq!(tracker.metrics().round_advancements, 1);

        // Stale round ignored.
        tracker.on_round_advance(1);
        assert_eq!(tracker.metrics().round_advancements, 1);

        // Skip round.
        tracker.on_round_advance(5);
        assert_eq!(tracker.current_round(), 5);
        assert_eq!(tracker.metrics().round_advancements, 2);
    }

    // ── test: quorum round computation ───────────────────

    #[test]
    fn test_quorum_round() {
        let committee = make_committee(7); // f=2, quorum=5
        let mut tracker = RoundTracker::new(committee, 0, RoundTrackerConfig::default());

        // Authorities 0-3 at round 10 (4 nodes, < quorum=5)
        for auth in 0..4 {
            tracker.on_block_accepted(10, auth);
        }
        assert_eq!(
            tracker.quorum_round(),
            0,
            "4 < quorum=5, quorum round stays 0"
        );

        // Authority 4 at round 10 → quorum reached
        tracker.on_block_accepted(10, 4);
        assert_eq!(tracker.quorum_round(), 10, "5 = quorum, quorum round is 10");

        // Authorities 5-6 at round 8 (behind)
        tracker.on_block_accepted(8, 5);
        tracker.on_block_accepted(8, 6);
        // Still 5 at round 10 → quorum round stays 10
        assert_eq!(tracker.quorum_round(), 10);
    }

    // ── test: peer sync status ───────────────────────────

    #[test]
    fn test_peer_sync_status() {
        let committee = make_committee(7);
        let mut tracker = RoundTracker::new(committee, 0, RoundTrackerConfig::default());

        // Set quorum round to 10
        for auth in 0..5 {
            tracker.on_block_accepted(10, auth);
        }
        assert_eq!(tracker.quorum_round(), 10);

        // Authority 5 at round 10 → synced
        tracker.on_block_accepted(10, 5);
        assert_eq!(tracker.peer_sync_status(5), PeerSyncStatus::Synced);

        // Authority 6 at round 8 → slightly behind (gap=2)
        tracker.on_block_accepted(8, 6);
        assert_eq!(tracker.peer_sync_status(6), PeerSyncStatus::SlightlyBehind);

        // Authority at round 5 would be lagging (gap=5)
        // But we already set authority 0 to 10 above.
        // Let's check an authority that's way behind:
        // Authority 6 is at 8, gap=2, so slightly behind.
        assert_eq!(tracker.num_synced(), 6); // 0-5 at round 10
        assert_eq!(tracker.num_lagging(), 0); // 6 is SlightlyBehind, not Lagging
    }

    // ── test: propagation delay ──────────────────────────

    #[test]
    fn test_propagation_delay() {
        let committee = make_committee(7);
        let mut tracker = RoundTracker::new(committee, 0, RoundTrackerConfig::default());

        // Propose at round 5
        tracker.on_block_proposed(5);
        assert_eq!(tracker.last_proposed_round(), 5);

        // Quorum at round 3
        for auth in 0..5 {
            tracker.on_block_accepted(3, auth);
        }
        assert_eq!(tracker.quorum_round(), 3);

        // Propagation delay = 5 - 3 = 2
        assert_eq!(tracker.propagation_delay(), 2);
    }

    // ── test: leader timeout tracking ────────────────────

    #[test]
    fn test_leader_timeout() {
        let committee = make_committee(7);
        let mut tracker = RoundTracker::new(committee, 0, RoundTrackerConfig::default());

        tracker.on_round_advance(1);
        tracker.on_leader_timeout();
        tracker.on_leader_timeout();
        assert_eq!(tracker.timeouts_at_current_round(), 2);
        assert_eq!(tracker.total_timeouts(), 2);

        // Round advance resets per-round timeout counter
        tracker.on_round_advance(2);
        assert_eq!(tracker.timeouts_at_current_round(), 0);
        assert_eq!(tracker.total_timeouts(), 2); // total preserved

        tracker.on_leader_timeout();
        assert_eq!(tracker.timeouts_at_current_round(), 1);
        assert_eq!(tracker.total_timeouts(), 3);
    }

    // ── test: delay smoothing ────────────────────────────

    #[test]
    fn test_avg_propagation_delay() {
        let committee = make_committee(4);
        let config = RoundTrackerConfig { delay_window: 3 };
        let mut tracker = RoundTracker::new(committee, 0, config);

        // No data yet
        assert_eq!(tracker.avg_propagation_delay(), 0.0);

        // Simulate round advances with different delays
        tracker.on_block_proposed(5);
        for auth in 0..3 {
            tracker.on_block_accepted(3, auth);
        }
        tracker.on_round_advance(1); // delay = 5 - 3 = 2
        assert_eq!(tracker.avg_propagation_delay(), 2.0);

        tracker.on_block_proposed(8);
        for auth in 0..3 {
            tracker.on_block_accepted(5, auth);
        }
        tracker.on_round_advance(2); // delay = 8 - 5 = 3
                                     // avg = (2 + 3) / 2 = 2.5
        assert_eq!(tracker.avg_propagation_delay(), 2.5);
    }

    // ── test: authority_rounds ────────────────────────────

    #[test]
    fn test_authority_rounds() {
        let committee = make_committee(4);
        let mut tracker = RoundTracker::new(committee, 0, RoundTrackerConfig::default());

        tracker.on_block_accepted(5, 0);
        tracker.on_block_accepted(3, 1);
        tracker.on_block_accepted(7, 2);
        tracker.on_block_accepted(4, 3);

        let rounds = tracker.authority_rounds();
        assert_eq!(rounds, vec![(0, 5), (1, 3), (2, 7), (3, 4)]);
    }

    // ── test: reset for epoch ────────────────────────────

    #[test]
    fn test_reset_for_epoch() {
        let committee = make_committee(7);
        let mut tracker = RoundTracker::new(committee.clone(), 0, RoundTrackerConfig::default());

        tracker.on_round_advance(10);
        tracker.on_block_proposed(10);
        for auth in 0..5 {
            tracker.on_block_accepted(10, auth);
        }
        assert_eq!(tracker.quorum_round(), 10);

        tracker.reset_for_epoch(committee);
        assert_eq!(tracker.current_round(), 0);
        assert_eq!(tracker.last_proposed_round(), 0);
        assert_eq!(tracker.quorum_round(), 0);
        // Metrics preserved
        assert!(tracker.metrics().round_advancements > 0);
    }

    // ── test: 21-node quorum round ───────────────────────

    #[test]
    fn test_21_node_quorum() {
        let committee = make_committee(21); // f=6, quorum=15
        let mut tracker = RoundTracker::new(committee, 0, RoundTrackerConfig::default());

        // 14 authorities at round 5 (< quorum=15)
        for auth in 0..14 {
            tracker.on_block_accepted(5, auth);
        }
        assert_eq!(tracker.quorum_round(), 0);

        // 15th authority → quorum
        tracker.on_block_accepted(5, 14);
        assert_eq!(tracker.quorum_round(), 5);

        // Remaining at lower round
        for auth in 15..21 {
            tracker.on_block_accepted(3, auth);
        }
        // 15 at round 5 → quorum stays 5
        assert_eq!(tracker.quorum_round(), 5);
    }

    // ── test: lagging detection ──────────────────────────

    #[test]
    fn test_lagging_detection() {
        let committee = make_committee(7);
        let mut tracker = RoundTracker::new(committee, 0, RoundTrackerConfig::default());

        // 5 authorities at round 10
        for auth in 0..5 {
            tracker.on_block_accepted(10, auth);
        }
        // Authority 5 at round 5 (gap=5, lagging)
        tracker.on_block_accepted(5, 5);
        // Authority 6 at round 2 (gap=8, lagging)
        tracker.on_block_accepted(2, 6);

        assert_eq!(tracker.quorum_round(), 10);
        assert_eq!(tracker.peer_sync_status(5), PeerSyncStatus::Lagging);
        assert_eq!(tracker.peer_sync_status(6), PeerSyncStatus::Lagging);
        assert_eq!(tracker.num_lagging(), 2);
    }
}
