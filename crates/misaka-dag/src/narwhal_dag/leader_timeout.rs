// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Sui equivalent: consensus/core/src/leader_timeout.rs (297 lines)
//
//! Leader timeout — detects missing leaders and advances rounds.
//!
//! When the leader for a round does not produce a block within the
//! timeout window, validators emit a "force-new-round" signal so the
//! chain continues making progress.
//!
//! ## Design
//!
//! - Timeout starts when the threshold clock advances to a new round.
//! - If a leader block arrives before the deadline → cancel timeout.
//! - If the deadline fires → record timeout, increase backoff, signal.
//! - Backoff is exponential: `base_ms * 2^consecutive_timeouts`, capped
//!   at `max_ms`.
//! - A successful leader resets backoff to 0.
//!
//! The timeout does NOT propose a block itself (that's the caller's job).
//! It only provides the timing signal. The caller then decides whether to
//! propose a weak (empty) block to advance the round.

use crate::narwhal_types::block::{AuthorityIndex, Round};
use std::time::{Duration, Instant};

/// Configuration for leader timeout.
#[derive(Clone, Debug)]
pub struct LeaderTimeoutConfig {
    /// Base timeout in milliseconds (initial, no backoff).
    pub base_ms: u64,
    /// Maximum timeout in milliseconds (cap after repeated timeouts).
    pub max_ms: u64,
    /// Backoff multiplier (applied per consecutive timeout).
    pub backoff_factor: f64,
}

impl Default for LeaderTimeoutConfig {
    fn default() -> Self {
        Self {
            base_ms: 500,
            max_ms: 8_000,
            backoff_factor: 2.0,
        }
    }
}

/// State of a timeout timer for the current round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TimerState {
    /// Timer is running. Will fire at `deadline`.
    Active {
        round: Round,
        leader: AuthorityIndex,
    },
    /// Timer was cancelled (leader block arrived).
    Cancelled,
    /// Timer fired (timeout occurred).
    Fired {
        round: Round,
        leader: AuthorityIndex,
    },
    /// No timer set (initial state or between rounds).
    Idle,
}

/// Leader timeout manager.
///
/// Tracks the current round's leader timeout and manages backoff.
/// Thread-safe usage pattern: call methods from the consensus event loop.
pub struct LeaderTimeout {
    config: LeaderTimeoutConfig,
    /// Current timer state.
    state: TimerState,
    /// When the current timer was started.
    started_at: Option<Instant>,
    /// Current timeout duration (includes backoff).
    current_timeout: Duration,
    /// Number of consecutive timeouts (resets on leader success).
    consecutive_timeouts: u32,
    /// Total timeouts since creation (monotonic counter).
    total_timeouts: u64,
    /// Total cancellations (leader arrived in time).
    total_cancellations: u64,
}

impl LeaderTimeout {
    /// Create a new leader timeout with the given configuration.
    #[must_use]
    pub fn new(config: LeaderTimeoutConfig) -> Self {
        let initial = Duration::from_millis(config.base_ms);
        Self {
            config,
            state: TimerState::Idle,
            started_at: None,
            current_timeout: initial,
            consecutive_timeouts: 0,
            total_timeouts: 0,
            total_cancellations: 0,
        }
    }

    /// Start a timer for the given round and leader.
    ///
    /// Sui equivalent: `LeaderTimeout::start()` — called when threshold
    /// clock advances to a new round.
    pub fn start(&mut self, round: Round, leader: AuthorityIndex) {
        self.state = TimerState::Active { round, leader };
        self.started_at = Some(Instant::now());
    }

    /// Cancel the timer because the leader block has arrived.
    ///
    /// Sui equivalent: `LeaderTimeout::cancel()` — called when the
    /// leader block for the current round is accepted.
    pub fn cancel(&mut self) {
        if matches!(self.state, TimerState::Active { .. }) {
            self.state = TimerState::Cancelled;
            self.started_at = None;
            self.consecutive_timeouts = 0;
            self.current_timeout = Duration::from_millis(self.config.base_ms);
            self.total_cancellations += 1;
        }
    }

    /// Check if the timer has expired.
    ///
    /// Returns `Some((round, leader))` if the timeout has fired.
    /// Returns `None` if the timer is still running, cancelled, or idle.
    ///
    /// Sui equivalent: `LeaderTimeout::check()` — called periodically
    /// (every event loop iteration).
    #[must_use]
    pub fn check(&mut self) -> Option<(Round, AuthorityIndex)> {
        match self.state {
            TimerState::Active { round, leader } => {
                if let Some(started) = self.started_at {
                    if started.elapsed() >= self.current_timeout {
                        self.fire(round, leader);
                        return Some((round, leader));
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Force the timer to fire (for testing or explicit timeout calls).
    pub fn force_fire(&mut self) {
        if let TimerState::Active { round, leader } = self.state {
            self.fire(round, leader);
        }
    }

    /// Reset to idle (between epochs or on recovery).
    pub fn reset(&mut self) {
        self.state = TimerState::Idle;
        self.started_at = None;
        self.consecutive_timeouts = 0;
        self.current_timeout = Duration::from_millis(self.config.base_ms);
    }

    // ── Accessors ──

    /// Current timer state.
    #[must_use]
    pub fn state(&self) -> &TimerState {
        &self.state
    }

    /// Current timeout duration (includes backoff).
    #[must_use]
    pub fn current_timeout(&self) -> Duration {
        self.current_timeout
    }

    /// Number of consecutive timeouts.
    #[must_use]
    pub fn consecutive_timeouts(&self) -> u32 {
        self.consecutive_timeouts
    }

    /// Total timeouts since creation.
    #[must_use]
    pub fn total_timeouts(&self) -> u64 {
        self.total_timeouts
    }

    /// Total cancellations since creation.
    #[must_use]
    pub fn total_cancellations(&self) -> u64 {
        self.total_cancellations
    }

    /// Time remaining until deadline (None if not active).
    #[must_use]
    pub fn time_remaining(&self) -> Option<Duration> {
        match (&self.state, self.started_at) {
            (TimerState::Active { .. }, Some(started)) => {
                let elapsed = started.elapsed();
                if elapsed < self.current_timeout {
                    Some(self.current_timeout - elapsed)
                } else {
                    Some(Duration::ZERO)
                }
            }
            _ => None,
        }
    }

    // ── Internal ──

    fn fire(&mut self, round: Round, leader: AuthorityIndex) {
        self.state = TimerState::Fired { round, leader };
        self.started_at = None;
        self.consecutive_timeouts += 1;
        self.total_timeouts += 1;
        self.increase_backoff();
    }

    fn increase_backoff(&mut self) {
        let base = self.config.base_ms as f64;
        let factor = self
            .config
            .backoff_factor
            .powi(self.consecutive_timeouts as i32);
        let new_ms = (base * factor).min(self.config.max_ms as f64) as u64;
        self.current_timeout = Duration::from_millis(new_ms);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_config() -> LeaderTimeoutConfig {
        LeaderTimeoutConfig {
            base_ms: 10,
            max_ms: 200,
            backoff_factor: 2.0,
        }
    }

    #[test]
    fn test_initial_state_idle() {
        let lt = LeaderTimeout::new(fast_config());
        assert!(matches!(lt.state(), TimerState::Idle));
        assert_eq!(lt.consecutive_timeouts(), 0);
    }

    #[test]
    fn test_start_and_cancel() {
        let mut lt = LeaderTimeout::new(fast_config());
        lt.start(5, 2);
        assert!(matches!(
            lt.state(),
            TimerState::Active {
                round: 5,
                leader: 2
            }
        ));

        lt.cancel();
        assert!(matches!(lt.state(), TimerState::Cancelled));
        assert_eq!(lt.consecutive_timeouts(), 0);
        assert_eq!(lt.total_cancellations(), 1);
    }

    #[test]
    fn test_timeout_fires() {
        let mut lt = LeaderTimeout::new(LeaderTimeoutConfig {
            base_ms: 1,
            max_ms: 100,
            backoff_factor: 2.0,
        });
        lt.start(3, 1);
        std::thread::sleep(Duration::from_millis(5));

        let result = lt.check();
        assert_eq!(result, Some((3, 1)));
        assert!(matches!(
            lt.state(),
            TimerState::Fired {
                round: 3,
                leader: 1
            }
        ));
        assert_eq!(lt.consecutive_timeouts(), 1);
        assert_eq!(lt.total_timeouts(), 1);
    }

    #[test]
    fn test_check_returns_none_before_deadline() {
        let mut lt = LeaderTimeout::new(LeaderTimeoutConfig {
            base_ms: 10_000,
            max_ms: 10_000,
            backoff_factor: 2.0,
        });
        lt.start(1, 0);
        assert_eq!(lt.check(), None); // 10 seconds hasn't elapsed
    }

    #[test]
    fn test_exponential_backoff() {
        let mut lt = LeaderTimeout::new(fast_config());
        // base=10ms
        assert_eq!(lt.current_timeout(), Duration::from_millis(10));

        lt.start(1, 0);
        lt.force_fire();
        // 1st timeout: 10 * 2^1 = 20ms
        assert_eq!(lt.current_timeout(), Duration::from_millis(20));

        lt.start(2, 0);
        lt.force_fire();
        // 2nd timeout: 10 * 2^2 = 40ms
        assert_eq!(lt.current_timeout(), Duration::from_millis(40));

        lt.start(3, 0);
        lt.force_fire();
        // 3rd timeout: 10 * 2^3 = 80ms
        assert_eq!(lt.current_timeout(), Duration::from_millis(80));

        lt.start(4, 0);
        lt.force_fire();
        // 4th timeout: 10 * 2^4 = 160ms
        assert_eq!(lt.current_timeout(), Duration::from_millis(160));

        lt.start(5, 0);
        lt.force_fire();
        // 5th timeout: 10 * 2^5 = 320 → capped at 200ms
        assert_eq!(lt.current_timeout(), Duration::from_millis(200));
    }

    #[test]
    fn test_cancel_resets_backoff() {
        let mut lt = LeaderTimeout::new(fast_config());
        lt.start(1, 0);
        lt.force_fire(); // backoff increases
        assert!(lt.current_timeout() > Duration::from_millis(10));

        lt.start(2, 0);
        lt.cancel(); // resets backoff
        assert_eq!(lt.current_timeout(), Duration::from_millis(10));
        assert_eq!(lt.consecutive_timeouts(), 0);
    }

    #[test]
    fn test_reset_clears_everything() {
        let mut lt = LeaderTimeout::new(fast_config());
        lt.start(1, 0);
        lt.force_fire();
        lt.start(2, 0);
        lt.force_fire();

        lt.reset();
        assert!(matches!(lt.state(), TimerState::Idle));
        assert_eq!(lt.consecutive_timeouts(), 0);
        assert_eq!(lt.current_timeout(), Duration::from_millis(10));
        // total_timeouts is NOT reset (monotonic counter)
        assert_eq!(lt.total_timeouts(), 2);
    }

    #[test]
    fn test_time_remaining() {
        let mut lt = LeaderTimeout::new(LeaderTimeoutConfig {
            base_ms: 10_000,
            max_ms: 10_000,
            backoff_factor: 2.0,
        });
        assert!(lt.time_remaining().is_none()); // idle

        lt.start(1, 0);
        let remaining = lt.time_remaining().unwrap();
        assert!(remaining > Duration::from_millis(9_000));
    }

    #[test]
    fn test_force_fire() {
        let mut lt = LeaderTimeout::new(fast_config());
        lt.start(7, 3);
        lt.force_fire();
        assert!(matches!(
            lt.state(),
            TimerState::Fired {
                round: 7,
                leader: 3
            }
        ));
    }

    #[test]
    fn test_cancel_idle_is_noop() {
        let mut lt = LeaderTimeout::new(fast_config());
        lt.cancel(); // no-op, not active
        assert!(matches!(lt.state(), TimerState::Idle));
    }

    #[test]
    fn test_cancel_fired_is_noop() {
        let mut lt = LeaderTimeout::new(fast_config());
        lt.start(1, 0);
        lt.force_fire();
        lt.cancel(); // no-op, already fired
        assert!(matches!(lt.state(), TimerState::Fired { .. }));
    }
}
