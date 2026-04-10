// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Consensus clock abstraction — Phase 0-2 completion.
//!
//! Sui equivalent: `consensus/core/src/context.rs` (Clock field)
//!
//! ## Purpose
//!
//! Production consensus uses `SystemTime::now()` for block timestamps
//! and latency tracking. This prevents deterministic replay and testing.
//! The Clock trait abstracts time access so simulators can inject a
//! controllable clock via Context.
//!
//! ## Production vs Test
//!
//! - `SystemClock`: wraps `std::time::SystemTime::now()`, zero overhead
//! - `SimulatedClock`: atomic counter, manually advanced, fully deterministic

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Clock abstraction for consensus components.
///
/// All consensus code that needs wall-clock time MUST go through this
/// trait (via `Context::clock`), never call `SystemTime::now()` directly.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Current time as milliseconds since Unix epoch.
    fn now_millis(&self) -> u64;

    /// Current time as a monotonic instant (for duration measurements).
    fn instant_now(&self) -> Instant;
}

/// Production clock — wraps `SystemTime::now()`.
///
/// Zero-cost: inlined to direct syscall.
#[derive(Debug, Clone)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_millis(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_millis() as u64
    }

    fn instant_now(&self) -> Instant {
        Instant::now()
    }
}

/// Simulated clock for deterministic testing.
///
/// Time is an atomic counter that only advances when explicitly called.
/// All nodes sharing the same `SimulatedClock` see the same time.
#[derive(Debug)]
pub struct SimulatedClock {
    current_ms: AtomicU64,
    /// Cached Instant from creation (monotonic base).
    base_instant: Instant,
}

impl SimulatedClock {
    /// Create a new simulated clock starting at `start_ms` (millis since epoch).
    pub fn new(start_ms: u64) -> Self {
        Self {
            current_ms: AtomicU64::new(start_ms),
            base_instant: Instant::now(),
        }
    }

    /// Advance the clock by `millis` milliseconds.
    pub fn advance(&self, millis: u64) {
        self.current_ms.fetch_add(millis, Ordering::SeqCst);
    }

    /// Set the clock to an absolute value.
    pub fn set(&self, millis: u64) {
        self.current_ms.store(millis, Ordering::SeqCst);
    }

    /// Current value in milliseconds.
    pub fn current(&self) -> u64 {
        self.current_ms.load(Ordering::SeqCst)
    }
}

impl Clock for SimulatedClock {
    fn now_millis(&self) -> u64 {
        self.current_ms.load(Ordering::SeqCst)
    }

    fn instant_now(&self) -> Instant {
        // Simulate monotonic time offset from base
        let elapsed_ms = self.current_ms.load(Ordering::SeqCst);
        self.base_instant + Duration::from_millis(elapsed_ms)
    }
}

/// Default starting time for simulated clock: 2026-01-01 00:00:00 UTC
pub const SIM_CLOCK_DEFAULT_START_MS: u64 = 1_767_225_600_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_returns_reasonable_time() {
        let c = SystemClock;
        let ms = c.now_millis();
        // Should be after 2024-01-01
        assert!(ms > 1_704_067_200_000);
    }

    #[test]
    fn simulated_clock_deterministic() {
        let c = SimulatedClock::new(1000);
        assert_eq!(c.now_millis(), 1000);
        c.advance(500);
        assert_eq!(c.now_millis(), 1500);
        c.advance(100);
        assert_eq!(c.now_millis(), 1600);
    }

    #[test]
    fn simulated_clock_set() {
        let c = SimulatedClock::new(0);
        c.set(42_000);
        assert_eq!(c.now_millis(), 42_000);
    }
}
