//! Peer Scoring — reputation system stub for ZKP budget enforcement (Task 4.2).
//!
//! When a peer proposes or relays a block that exceeds the ZKP verification
//! budget, their score is reduced. Peers below a threshold are disconnected
//! and temporarily banned.
//!
//! # Scoring Model (Stub)
//!
//! - Initial score: 100
//! - Budget exceeded: -50 per offense
//! - Invalid block (non-budget): -20 per offense
//! - Valid block proposed: +1 per block (slow recovery)
//! - Disconnect threshold: 0
//! - Ban duration: 10 minutes (exponential backoff on repeat)
//!
//! # Integration Points
//!
//! - `block_validation.rs`: calls `penalize_budget_exceeded()` on budget errors
//! - `p2p_network.rs`: checks `should_disconnect()` before relaying
//! - `sync.rs`: checks `is_banned()` before requesting blocks from peer

use std::collections::HashMap;
use std::time::{Duration, Instant};

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

const INITIAL_SCORE: i64 = 100;
const BUDGET_EXCEEDED_PENALTY: i64 = -50;
const INVALID_BLOCK_PENALTY: i64 = -20;
const VALID_BLOCK_REWARD: i64 = 1;
const DISCONNECT_THRESHOLD: i64 = 0;
const BASE_BAN_DURATION: Duration = Duration::from_secs(600); // 10 minutes
const MAX_BAN_DURATION: Duration = Duration::from_secs(86_400); // 24 hours

// ═══════════════════════════════════════════════════════════════
//  Peer Score Entry
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
struct PeerScoreEntry {
    score: i64,
    offenses: u32,
    banned_until: Option<Instant>,
}

impl Default for PeerScoreEntry {
    fn default() -> Self {
        Self {
            score: INITIAL_SCORE,
            offenses: 0,
            banned_until: None,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Peer Scoring Manager
// ═══════════════════════════════════════════════════════════════

/// Peer ID (32-byte public key hash or similar identifier).
pub type PeerId = [u8; 32];

/// Tracks peer reputation for ZKP budget enforcement.
///
/// This is a stub implementation. Production should:
/// - Persist scores across restarts
/// - Use exponential moving average for score decay
/// - Integrate with the P2P layer's connection manager
pub struct PeerScoring {
    scores: HashMap<PeerId, PeerScoreEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PenaltyReason {
    /// Block exceeded ZKP verification budget (units, count, or time).
    ZkpBudgetExceeded,
    /// Block contained invalid transaction (non-budget validation failure).
    InvalidBlock,
}

impl PeerScoring {
    pub fn new() -> Self {
        Self {
            scores: HashMap::new(),
        }
    }

    /// Penalize a peer for submitting a bad block.
    ///
    /// Returns the peer's new score.
    pub fn penalize(&mut self, peer: &PeerId, reason: PenaltyReason) -> i64 {
        let entry = self.scores.entry(*peer).or_default();
        let penalty = match reason {
            PenaltyReason::ZkpBudgetExceeded => BUDGET_EXCEEDED_PENALTY,
            PenaltyReason::InvalidBlock => INVALID_BLOCK_PENALTY,
        };
        entry.score = entry.score.saturating_add(penalty);
        entry.offenses += 1;

        if entry.score <= DISCONNECT_THRESHOLD {
            // Calculate ban duration with exponential backoff
            let backoff_factor = 2u32.saturating_pow(entry.offenses.saturating_sub(1).min(10));
            let ban_duration = std::cmp::min(
                BASE_BAN_DURATION * backoff_factor,
                MAX_BAN_DURATION,
            );
            entry.banned_until = Some(Instant::now() + ban_duration);
        }

        entry.score
    }

    /// Reward a peer for proposing a valid block.
    pub fn reward_valid_block(&mut self, peer: &PeerId) {
        let entry = self.scores.entry(*peer).or_default();
        entry.score = std::cmp::min(entry.score + VALID_BLOCK_REWARD, INITIAL_SCORE);
    }

    /// Should this peer be disconnected?
    pub fn should_disconnect(&self, peer: &PeerId) -> bool {
        self.scores
            .get(peer)
            .map(|e| e.score <= DISCONNECT_THRESHOLD)
            .unwrap_or(false)
    }

    /// Is this peer currently banned?
    pub fn is_banned(&self, peer: &PeerId) -> bool {
        self.scores
            .get(peer)
            .and_then(|e| e.banned_until)
            .map(|until| Instant::now() < until)
            .unwrap_or(false)
    }

    /// Get a peer's current score.
    pub fn score(&self, peer: &PeerId) -> i64 {
        self.scores
            .get(peer)
            .map(|e| e.score)
            .unwrap_or(INITIAL_SCORE)
    }

    /// Remove expired bans (call periodically).
    pub fn cleanup_expired_bans(&mut self) {
        let now = Instant::now();
        for entry in self.scores.values_mut() {
            if let Some(until) = entry.banned_until {
                if now >= until {
                    entry.banned_until = None;
                }
            }
        }
    }
}

impl Default for PeerScoring {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_a() -> PeerId { [0xAA; 32] }
    fn peer_b() -> PeerId { [0xBB; 32] }

    #[test]
    fn test_initial_score() {
        let scoring = PeerScoring::new();
        assert_eq!(scoring.score(&peer_a()), INITIAL_SCORE);
    }

    #[test]
    fn test_penalize_budget_exceeded() {
        let mut scoring = PeerScoring::new();
        let new_score = scoring.penalize(&peer_a(), PenaltyReason::ZkpBudgetExceeded);
        assert_eq!(new_score, INITIAL_SCORE + BUDGET_EXCEEDED_PENALTY);
    }

    #[test]
    fn test_disconnect_after_repeated_offenses() {
        let mut scoring = PeerScoring::new();
        // Two budget violations: 100 - 50 - 50 = 0
        scoring.penalize(&peer_a(), PenaltyReason::ZkpBudgetExceeded);
        scoring.penalize(&peer_a(), PenaltyReason::ZkpBudgetExceeded);
        assert!(scoring.should_disconnect(&peer_a()));
        assert!(scoring.is_banned(&peer_a()));
    }

    #[test]
    fn test_reward_recovers_score() {
        let mut scoring = PeerScoring::new();
        scoring.penalize(&peer_a(), PenaltyReason::InvalidBlock);
        let score_after_penalty = scoring.score(&peer_a());
        scoring.reward_valid_block(&peer_a());
        assert_eq!(scoring.score(&peer_a()), score_after_penalty + VALID_BLOCK_REWARD);
    }

    #[test]
    fn test_score_capped_at_initial() {
        let mut scoring = PeerScoring::new();
        for _ in 0..200 {
            scoring.reward_valid_block(&peer_a());
        }
        assert_eq!(scoring.score(&peer_a()), INITIAL_SCORE);
    }

    #[test]
    fn test_independent_peer_scores() {
        let mut scoring = PeerScoring::new();
        scoring.penalize(&peer_a(), PenaltyReason::ZkpBudgetExceeded);
        assert_eq!(scoring.score(&peer_a()), INITIAL_SCORE + BUDGET_EXCEEDED_PENALTY);
        assert_eq!(scoring.score(&peer_b()), INITIAL_SCORE);
    }
}
