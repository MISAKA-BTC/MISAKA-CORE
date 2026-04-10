//! Peer Scoring — State-Machine Reputation System (Task 3.2).
//!
//! # Design: Cheap vs Expensive Failure Differentiation
//!
//! Not all peer misbehavior is equal in cost to the victim:
//!
//! | Failure Type     | Victim Cost | Penalty | Rationale                          |
//! |------------------|-------------|---------|-------------------------------------|
//! | Cheap Parse Fail | ~0 CPU      | -10     | Malformed header, bad version byte  |
//! | Expensive ZKP Fail | O(ms) CPU | -40     | Valid structure but invalid crypto   |
//! | Budget Exceeded  | O(s) CPU    | -60     | Block designed to exhaust validators |
//! | Double-Spend TX  | O(ms) CPU   | -80     | Attempted consensus attack           |
//!
//! # State Machine: PeerState
//!
//! ```text
//!   ┌──────────┐   score > 0    ┌──────────┐  ban expires   ┌──────────┐
//!   │  Active  │ ──────────────→│ Degraded │ ──────────────→│ Probation│
//!   │ score=100│                │  0<s<50  │                │  s=-100  │
//!   └──────────┘                └──────────┘                └──────────┘
//!        ↑                           │                           │
//!        │  valid blocks (+1)        │  score ≤ 0                │  offense
//!        └───────────────────────────│                           ↓
//!                                    │                     ┌──────────┐
//!                                    └────────────────────→│  Banned  │
//!                                                          │ duration │
//!                                                          └──────────┘
//! ```
//!
//! # Integration Points
//!
//! - `block_validation.rs`: calls `penalize()` with appropriate reason
//! - `p2p_network.rs`: checks `should_disconnect()` before relaying
//! - `sync.rs`: checks `is_banned()` before requesting blocks from peer
//! - `verified_envelope.rs`: `TxVerificationError::is_cheap_failure()` determines penalty tier

use std::collections::HashMap;
use std::time::{Duration, Instant};

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

const INITIAL_SCORE: i64 = 100;
const DISCONNECT_THRESHOLD: i64 = 0;
const DEGRADED_THRESHOLD: i64 = 50;
const MIN_SCORE: i64 = -200;

// ── Penalty tiers (matched to failure cost) ──

/// Cheap parse failure (malformed header, bad version, structural error).
/// Low penalty because the victim spent nearly zero CPU.
const PENALTY_CHEAP_PARSE: i64 = -10;

/// Expensive ZKP failure (valid structure but crypto check failed).
/// Higher penalty because the victim ran polynomial multiplications.
const PENALTY_EXPENSIVE_ZKP: i64 = -40;

/// Budget exceeded (block crafted to exhaust verification budget).
/// Severe penalty — this is an active DoS attempt.
const PENALTY_BUDGET_EXCEEDED: i64 = -60;

/// Double-spend attempt (spend-tag already in chain state).
/// Maximum penalty — this is a consensus attack.
const PENALTY_DOUBLE_SPEND: i64 = -80;

/// Reward for a valid block proposed by this peer.
const REWARD_VALID_BLOCK: i64 = 1;

// ── Ban durations ──

const BASE_BAN_DURATION: Duration = Duration::from_secs(600); // 10 minutes
const MAX_BAN_DURATION: Duration = Duration::from_secs(86_400); // 24 hours

// ═══════════════════════════════════════════════════════════════
//  Peer State
// ═══════════════════════════════════════════════════════════════

/// Current peer lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Normal operation. Score > DEGRADED_THRESHOLD.
    Active,
    /// Reduced trust. 0 < score ≤ DEGRADED_THRESHOLD.
    /// The P2P layer may deprioritize this peer for block requests.
    Degraded,
    /// Score ≤ 0 but ban has expired. One more offense → Banned.
    Probation,
    /// Disconnected and banned for a duration with exponential backoff.
    Banned,
}

#[derive(Debug, Clone)]
struct PeerRecord {
    score: i64,
    state: PeerState,
    total_offenses: u32,
    cheap_offenses: u32,
    expensive_offenses: u32,
    banned_until: Option<Instant>,
    last_activity: Instant,
}

impl Default for PeerRecord {
    fn default() -> Self {
        Self {
            score: INITIAL_SCORE,
            state: PeerState::Active,
            total_offenses: 0,
            cheap_offenses: 0,
            expensive_offenses: 0,
            banned_until: None,
            last_activity: Instant::now(),
        }
    }
}

impl PeerRecord {
    /// Recompute state from current score and ban status.
    fn update_state(&mut self) {
        let now = Instant::now();

        // Check if ban has expired
        if let Some(until) = self.banned_until {
            if now >= until {
                self.banned_until = None;
                self.state = PeerState::Probation;
                return;
            } else {
                self.state = PeerState::Banned;
                return;
            }
        }

        self.state = if self.score > DEGRADED_THRESHOLD {
            PeerState::Active
        } else if self.score > DISCONNECT_THRESHOLD {
            PeerState::Degraded
        } else {
            PeerState::Probation
        };
    }
}

// ═══════════════════════════════════════════════════════════════
//  Penalty Reasons
// ═══════════════════════════════════════════════════════════════

/// Peer ID (32-byte public key hash or similar identifier).
pub type PeerId = [u8; 32];

/// Why a peer is being penalized.
///
/// The penalty amount scales with the cost the misbehavior imposed
/// on the victim validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PenaltyReason {
    /// Malformed header, bad version byte, structural parse failure.
    /// Victim cost: ~0 CPU (rejected before any crypto).
    CheapParseFail,

    /// Valid structure but ZKP verification failed (Σ-protocol, membership, range).
    /// Victim cost: O(ms) — polynomial multiplication was performed.
    ExpensiveZkpFail,

    /// Block exceeded ZKP verification budget.
    /// Victim cost: O(s) — many proofs were verified before budget hit.
    ZkpBudgetExceeded,

    /// Transaction contains a spend-tag already in chain state.
    /// Victim cost: O(ms) — but this is a consensus attack attempt.
    DoubleSpendAttempt,
}

impl PenaltyReason {
    /// Is this a cheap-check failure (pre-crypto)?
    pub fn is_cheap(&self) -> bool {
        matches!(self, Self::CheapParseFail)
    }

    fn penalty(&self) -> i64 {
        match self {
            Self::CheapParseFail => PENALTY_CHEAP_PARSE,
            Self::ExpensiveZkpFail => PENALTY_EXPENSIVE_ZKP,
            Self::ZkpBudgetExceeded => PENALTY_BUDGET_EXCEEDED,
            Self::DoubleSpendAttempt => PENALTY_DOUBLE_SPEND,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Peer Scoring Manager
// ═══════════════════════════════════════════════════════════════

/// Tracks peer reputation with differentiated penalties.
///
/// # Thread Safety
///
/// This struct is NOT internally synchronized. The caller
/// (typically the P2P event loop) must wrap it in a Mutex.
pub struct PeerScoring {
    records: HashMap<PeerId, PeerRecord>,
}

/// Result of applying a penalty — tells the caller what action to take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PenaltyAction {
    /// Score reduced but peer is still allowed.
    ScoreReduced { new_score: i64 },
    /// Peer should be disconnected immediately.
    Disconnect { new_score: i64 },
    /// Peer should be disconnected and banned for the given duration.
    Ban { new_score: i64, duration: Duration },
}

impl PeerScoring {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }

    /// Penalize a peer. Returns the action the caller should take.
    ///
    /// # Fail-Closed
    ///
    /// If the penalty causes score ≤ 0, a ban is always applied.
    /// There is no "warning" state — the first offense that crosses
    /// the threshold results in immediate disconnection + ban.
    pub fn penalize(&mut self, peer: &PeerId, reason: PenaltyReason) -> PenaltyAction {
        let record = self.records.entry(*peer).or_default();
        record.score = (record.score + reason.penalty()).max(MIN_SCORE);
        record.total_offenses += 1;
        record.last_activity = Instant::now();

        if reason.is_cheap() {
            record.cheap_offenses += 1;
        } else {
            record.expensive_offenses += 1;
        }

        if record.score <= DISCONNECT_THRESHOLD {
            // Calculate ban duration with exponential backoff
            let backoff_factor =
                2u32.saturating_pow(record.total_offenses.saturating_sub(1).min(10));
            let ban_duration = std::cmp::min(BASE_BAN_DURATION * backoff_factor, MAX_BAN_DURATION);
            record.banned_until = Some(Instant::now() + ban_duration);
            record.state = PeerState::Banned;
            PenaltyAction::Ban {
                new_score: record.score,
                duration: ban_duration,
            }
        } else if record.score <= DEGRADED_THRESHOLD {
            record.state = PeerState::Degraded;
            PenaltyAction::ScoreReduced {
                new_score: record.score,
            }
        } else {
            record.state = PeerState::Active;
            PenaltyAction::ScoreReduced {
                new_score: record.score,
            }
        }
    }

    /// Reward a peer for proposing a valid block.
    pub fn reward_valid_block(&mut self, peer: &PeerId) {
        let record = self.records.entry(*peer).or_default();
        record.score = std::cmp::min(record.score + REWARD_VALID_BLOCK, INITIAL_SCORE);
        record.last_activity = Instant::now();
        record.update_state();
    }

    /// Get the current state of a peer.
    pub fn peer_state(&self, peer: &PeerId) -> PeerState {
        self.records
            .get(peer)
            .map(|r| {
                // Check ban expiry dynamically
                if let Some(until) = r.banned_until {
                    if Instant::now() >= until {
                        return PeerState::Probation;
                    }
                    return PeerState::Banned;
                }
                r.state
            })
            .unwrap_or(PeerState::Active)
    }

    /// Should this peer be disconnected?
    pub fn should_disconnect(&self, peer: &PeerId) -> bool {
        matches!(self.peer_state(peer), PeerState::Banned)
    }

    /// Is this peer currently banned?
    pub fn is_banned(&self, peer: &PeerId) -> bool {
        matches!(self.peer_state(peer), PeerState::Banned)
    }

    /// Get a peer's current score.
    pub fn score(&self, peer: &PeerId) -> i64 {
        self.records
            .get(peer)
            .map(|r| r.score)
            .unwrap_or(INITIAL_SCORE)
    }

    /// Remove expired bans and transition peers to Probation.
    pub fn cleanup_expired_bans(&mut self) {
        let now = Instant::now();
        for record in self.records.values_mut() {
            if let Some(until) = record.banned_until {
                if now >= until {
                    record.banned_until = None;
                    record.state = PeerState::Probation;
                }
            }
        }
    }

    /// Remove peers that have been inactive for longer than the given duration.
    pub fn evict_stale(&mut self, max_idle: Duration) {
        let now = Instant::now();
        self.records
            .retain(|_, r| now.duration_since(r.last_activity) < max_idle);
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

    fn peer_a() -> PeerId {
        [0xAA; 32]
    }
    fn peer_b() -> PeerId {
        [0xBB; 32]
    }

    #[test]
    fn test_initial_score() {
        let scoring = PeerScoring::new();
        assert_eq!(scoring.score(&peer_a()), INITIAL_SCORE);
        assert_eq!(scoring.peer_state(&peer_a()), PeerState::Active);
    }

    #[test]
    fn test_cheap_parse_fail_mild_penalty() {
        let mut scoring = PeerScoring::new();
        let action = scoring.penalize(&peer_a(), PenaltyReason::CheapParseFail);
        match action {
            PenaltyAction::ScoreReduced { new_score } => {
                assert_eq!(new_score, INITIAL_SCORE + PENALTY_CHEAP_PARSE);
            }
            _ => panic!("expected ScoreReduced for cheap parse fail"),
        }
        assert_eq!(scoring.peer_state(&peer_a()), PeerState::Active);
    }

    #[test]
    fn test_expensive_zkp_fail_severe_penalty() {
        let mut scoring = PeerScoring::new();
        let action = scoring.penalize(&peer_a(), PenaltyReason::ExpensiveZkpFail);
        match action {
            PenaltyAction::ScoreReduced { new_score } => {
                assert_eq!(new_score, INITIAL_SCORE + PENALTY_EXPENSIVE_ZKP);
            }
            _ => panic!("expected ScoreReduced for first expensive fail"),
        }
    }

    #[test]
    fn test_budget_exceeded_causes_ban() {
        let mut scoring = PeerScoring::new();
        // Two budget violations: 100 - 60 - 60 = -20 → banned
        scoring.penalize(&peer_a(), PenaltyReason::ZkpBudgetExceeded);
        let action = scoring.penalize(&peer_a(), PenaltyReason::ZkpBudgetExceeded);
        match action {
            PenaltyAction::Ban { new_score, .. } => {
                assert!(new_score <= DISCONNECT_THRESHOLD);
            }
            _ => panic!("expected Ban after two budget violations"),
        }
        assert!(scoring.is_banned(&peer_a()));
        assert!(scoring.should_disconnect(&peer_a()));
    }

    #[test]
    fn test_double_spend_immediate_ban() {
        let mut scoring = PeerScoring::new();
        // Double-spend: 100 - 80 = 20 (already degraded, not yet banned)
        scoring.penalize(&peer_a(), PenaltyReason::DoubleSpendAttempt);
        assert_eq!(scoring.peer_state(&peer_a()), PeerState::Degraded);
        // Second offense: 20 - 80 = -60 → Banned
        let action = scoring.penalize(&peer_a(), PenaltyReason::DoubleSpendAttempt);
        assert!(matches!(action, PenaltyAction::Ban { .. }));
        assert!(scoring.is_banned(&peer_a()));
    }

    #[test]
    fn test_cheap_needs_many_offenses_to_ban() {
        let mut scoring = PeerScoring::new();
        // Cheap fails: 100 / 10 = 10 offenses to reach 0
        for i in 0..9 {
            let action = scoring.penalize(&peer_a(), PenaltyReason::CheapParseFail);
            assert!(
                matches!(action, PenaltyAction::ScoreReduced { .. }),
                "offense {} should not ban",
                i
            );
        }
        // 10th offense: 100 - 100 = 0 → banned
        let action = scoring.penalize(&peer_a(), PenaltyReason::CheapParseFail);
        assert!(matches!(action, PenaltyAction::Ban { .. }));
    }

    #[test]
    fn test_reward_recovers_score() {
        let mut scoring = PeerScoring::new();
        scoring.penalize(&peer_a(), PenaltyReason::CheapParseFail);
        let score_after = scoring.score(&peer_a());
        scoring.reward_valid_block(&peer_a());
        assert_eq!(scoring.score(&peer_a()), score_after + REWARD_VALID_BLOCK);
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
        assert!(scoring.score(&peer_a()) < INITIAL_SCORE);
        assert_eq!(scoring.score(&peer_b()), INITIAL_SCORE);
    }

    #[test]
    fn test_degraded_state() {
        let mut scoring = PeerScoring::new();
        // 100 - 40 = 60 → Active; 60 - 40 = 20 → Degraded
        scoring.penalize(&peer_a(), PenaltyReason::ExpensiveZkpFail);
        assert_eq!(scoring.peer_state(&peer_a()), PeerState::Active);
        scoring.penalize(&peer_a(), PenaltyReason::ExpensiveZkpFail);
        assert_eq!(scoring.peer_state(&peer_a()), PeerState::Degraded);
    }
}
