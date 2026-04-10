// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Peer Scorer — reputation tracking for DAG consensus peers.
//!
//! Scores peers based on their behavior:
//! - Valid blocks → positive signal
//! - Invalid blocks / verify failures → strong negative
//! - Equivocation evidence → strongest negative
//! - Slow responses / silent rounds → mild negative
//!
//! Peers below a threshold are:
//! 1. Rate-limited via AdmissionController penalty
//! 2. Deprioritized in ancestor selection
//! 3. Excluded from leader schedule (via bad_nodes)
//!
//! # ADA-Style No-Slash
//!
//! MISAKA does not slash stake. Instead, low-scoring peers are demoted
//! in the soft-power hierarchy (leader selection, ancestor preference).
//! This is reversible — scores recover over time if behavior improves.

use std::collections::HashMap;

use crate::narwhal_types::block::AuthorityIndex;

/// Scoring signals from consensus activity.
#[derive(Debug, Clone, Copy)]
pub enum PeerSignal {
    /// Peer produced a valid block (accepted into DAG).
    ValidBlock,
    /// Peer's block failed signature/structural verification.
    VerifyFailed,
    /// Peer committed equivocation (strongest offense).
    Equivocation,
    /// Peer's ancestor fetch response was slow (> expected RTT).
    SlowResponse,
    /// Peer was silent for a round (didn't produce a block).
    SilentRound,
    /// Peer's block was successfully committed (leader block).
    CommittedLeader,
    /// WP9: Peer sent excessive SyncFetch requests (flooding).
    SyncFetchFlood,
    /// WP9: Peer sent an invalid block that wasted verify resources.
    WastedVerify,
}

impl PeerSignal {
    /// Score delta for this signal.
    fn delta(&self) -> f64 {
        match self {
            Self::ValidBlock => 1.0,
            Self::CommittedLeader => 3.0,
            Self::VerifyFailed => -10.0,
            Self::Equivocation => -100.0,
            Self::SlowResponse => -2.0,
            Self::SilentRound => -1.0,
            Self::SyncFetchFlood => -5.0,
            Self::WastedVerify => -3.0,
        }
    }
}

/// Per-peer score state.
#[derive(Debug, Clone)]
struct PeerScore {
    /// Current score (clamped to [MIN_SCORE, MAX_SCORE]).
    score: f64,
    /// Total valid blocks received.
    valid_blocks: u64,
    /// Total verify failures.
    verify_failures: u64,
    /// Equivocation count.
    equivocations: u64,
    /// Slow response count.
    slow_responses: u64,
    /// Silent round count.
    silent_rounds: u64,
    /// WP9: SyncFetch flood count.
    sync_floods: u64,
}

const INITIAL_SCORE: f64 = 50.0;
const MIN_SCORE: f64 = -200.0;
const MAX_SCORE: f64 = 100.0;
/// Score below which a peer is considered "bad" and penalized.
const BAD_PEER_THRESHOLD: f64 = 0.0;
/// Score below which a peer is excluded from leader selection.
const LEADER_EXCLUSION_THRESHOLD: f64 = -50.0;

impl PeerScore {
    fn new() -> Self {
        Self {
            score: INITIAL_SCORE,
            valid_blocks: 0,
            verify_failures: 0,
            equivocations: 0,
            slow_responses: 0,
            silent_rounds: 0,
            sync_floods: 0,
        }
    }

    fn apply(&mut self, signal: PeerSignal) {
        match signal {
            PeerSignal::ValidBlock => self.valid_blocks += 1,
            PeerSignal::CommittedLeader => self.valid_blocks += 1,
            PeerSignal::VerifyFailed => self.verify_failures += 1,
            PeerSignal::Equivocation => self.equivocations += 1,
            PeerSignal::SlowResponse => self.slow_responses += 1,
            PeerSignal::SilentRound => self.silent_rounds += 1,
            PeerSignal::SyncFetchFlood => self.sync_floods += 1,
            PeerSignal::WastedVerify => self.verify_failures += 1,
        }
        self.score = (self.score + signal.delta()).clamp(MIN_SCORE, MAX_SCORE);
    }

    fn is_bad(&self) -> bool {
        self.score < BAD_PEER_THRESHOLD
    }
    fn is_leader_excluded(&self) -> bool {
        self.score <= LEADER_EXCLUSION_THRESHOLD
    }
}

/// Peer scorer — tracks reputation for all known peers.
pub struct PeerScorer {
    scores: HashMap<AuthorityIndex, PeerScore>,
    /// Decay factor applied per round to move scores toward INITIAL_SCORE.
    decay_rate: f64,
}

impl PeerScorer {
    pub fn new() -> Self {
        Self {
            scores: HashMap::new(),
            decay_rate: 0.5, // recover 0.5 points per round toward initial
        }
    }

    /// Record a signal for a peer.
    pub fn record(&mut self, peer: AuthorityIndex, signal: PeerSignal) {
        self.scores
            .entry(peer)
            .or_insert_with(PeerScore::new)
            .apply(signal);
    }

    /// Apply time-based decay (call once per round).
    ///
    /// Moves all scores toward INITIAL_SCORE, allowing recovery.
    pub fn decay(&mut self) {
        for score in self.scores.values_mut() {
            if score.score < INITIAL_SCORE {
                score.score = (score.score + self.decay_rate).min(INITIAL_SCORE);
            } else if score.score > INITIAL_SCORE {
                score.score = (score.score - self.decay_rate).max(INITIAL_SCORE);
            }
        }
    }

    /// Get the score for a peer.
    pub fn score(&self, peer: AuthorityIndex) -> f64 {
        self.scores
            .get(&peer)
            .map(|s| s.score)
            .unwrap_or(INITIAL_SCORE)
    }

    /// Check if a peer is below the "bad" threshold.
    pub fn is_bad(&self, peer: AuthorityIndex) -> bool {
        self.scores.get(&peer).map(|s| s.is_bad()).unwrap_or(false)
    }

    /// Check if a peer should be excluded from leader selection.
    pub fn is_leader_excluded(&self, peer: AuthorityIndex) -> bool {
        self.scores
            .get(&peer)
            .map(|s| s.is_leader_excluded())
            .unwrap_or(false)
    }

    /// Get all peers that should be excluded from leader selection.
    pub fn leader_excluded_peers(&self) -> Vec<AuthorityIndex> {
        self.scores
            .iter()
            .filter(|(_, s)| s.is_leader_excluded())
            .map(|(&p, _)| p)
            .collect()
    }

    /// Get all "bad" peers (for admission control penalty).
    pub fn bad_peers(&self) -> Vec<AuthorityIndex> {
        self.scores
            .iter()
            .filter(|(_, s)| s.is_bad())
            .map(|(&p, _)| p)
            .collect()
    }

    /// Compute admission penalty factor for a peer (0.0–1.0).
    /// Bad peers get 0.25, very bad get 0.0.
    pub fn admission_penalty_factor(&self, peer: AuthorityIndex) -> f64 {
        let score = self.score(peer);
        if score >= BAD_PEER_THRESHOLD {
            1.0
        } else if score > LEADER_EXCLUSION_THRESHOLD {
            0.25
        } else {
            0.0
        }
    }

    /// Get summary statistics for a peer.
    pub fn peer_stats(&self, peer: AuthorityIndex) -> PeerScorerStats {
        match self.scores.get(&peer) {
            Some(s) => PeerScorerStats {
                score: s.score,
                valid_blocks: s.valid_blocks,
                verify_failures: s.verify_failures,
                equivocations: s.equivocations,
                slow_responses: s.slow_responses,
                silent_rounds: s.silent_rounds,
                is_bad: s.is_bad(),
                is_leader_excluded: s.is_leader_excluded(),
            },
            None => PeerScorerStats::default(),
        }
    }

    /// Number of tracked peers.
    pub fn tracked_count(&self) -> usize {
        self.scores.len()
    }
}

impl Default for PeerScorer {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary statistics for a single peer.
#[derive(Debug, Clone, Default)]
pub struct PeerScorerStats {
    pub score: f64,
    pub valid_blocks: u64,
    pub verify_failures: u64,
    pub equivocations: u64,
    pub slow_responses: u64,
    pub silent_rounds: u64,
    pub is_bad: bool,
    pub is_leader_excluded: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_score() {
        let scorer = PeerScorer::new();
        assert_eq!(scorer.score(0), INITIAL_SCORE);
        assert!(!scorer.is_bad(0));
        assert!(!scorer.is_leader_excluded(0));
    }

    #[test]
    fn test_valid_blocks_increase_score() {
        let mut scorer = PeerScorer::new();
        for _ in 0..20 {
            scorer.record(0, PeerSignal::ValidBlock);
        }
        assert!(scorer.score(0) > INITIAL_SCORE);
        assert!(!scorer.is_bad(0));
    }

    #[test]
    fn test_verify_failures_decrease_score() {
        let mut scorer = PeerScorer::new();
        for _ in 0..10 {
            scorer.record(0, PeerSignal::VerifyFailed);
        }
        assert!(scorer.is_bad(0));
    }

    #[test]
    fn test_equivocation_severe_penalty() {
        let mut scorer = PeerScorer::new();
        scorer.record(0, PeerSignal::Equivocation);
        // -100 from initial 50 = -50 → below both thresholds
        assert!(scorer.is_bad(0));
        assert!(scorer.is_leader_excluded(0));
    }

    #[test]
    fn test_decay_toward_initial() {
        let mut scorer = PeerScorer::new();
        // Tank the score
        for _ in 0..10 {
            scorer.record(0, PeerSignal::VerifyFailed);
        }
        let bad_score = scorer.score(0);
        assert!(bad_score < BAD_PEER_THRESHOLD);

        // Decay for 200 rounds — should recover toward INITIAL_SCORE
        for _ in 0..200 {
            scorer.decay();
        }
        assert!(scorer.score(0) > bad_score);
        // Should be close to INITIAL_SCORE
        assert!((scorer.score(0) - INITIAL_SCORE).abs() < 1.0);
    }

    #[test]
    fn test_leader_excluded_peers() {
        let mut scorer = PeerScorer::new();
        scorer.record(1, PeerSignal::Equivocation); // -50
        scorer.record(2, PeerSignal::ValidBlock); // normal

        let excluded = scorer.leader_excluded_peers();
        assert!(excluded.contains(&1));
        assert!(!excluded.contains(&2));
    }

    #[test]
    fn test_admission_penalty_factor() {
        let mut scorer = PeerScorer::new();

        // Normal peer
        assert_eq!(scorer.admission_penalty_factor(0), 1.0);

        // Bad peer (score < 0 but above leader exclusion)
        // 6 * (-10) + 50 = -10, which is < 0 (bad) but > -50 (not leader-excluded)
        for _ in 0..6 {
            scorer.record(1, PeerSignal::VerifyFailed);
        }
        assert_eq!(scorer.admission_penalty_factor(1), 0.25);

        // Very bad peer (equivocation)
        scorer.record(2, PeerSignal::Equivocation);
        assert_eq!(scorer.admission_penalty_factor(2), 0.0);
    }

    #[test]
    fn test_score_clamped() {
        let mut scorer = PeerScorer::new();
        // Max out positive
        for _ in 0..200 {
            scorer.record(0, PeerSignal::CommittedLeader);
        }
        assert!(scorer.score(0) <= MAX_SCORE);

        // Max out negative
        for _ in 0..50 {
            scorer.record(1, PeerSignal::Equivocation);
        }
        assert!(scorer.score(1) >= MIN_SCORE);
    }
}
