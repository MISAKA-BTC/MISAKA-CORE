// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Sui equivalent: consensus/core/src/commit_consumer.rs + subscriber pipeline
//
//! Commit Subscriber — pipeline between CommitObserver and the executor.
//!
//! Receives [`LinearizedOutput`] commits from the linearizer/observer,
//! enforces strict `commit_index` ordering (monotonically increasing),
//! buffers out-of-order commits until gaps are filled, and provides
//! backpressure signals when the buffer is near capacity.
//!
//! # Design
//!
//! ```text
//!   CommitObserver ──> CommitSubscriber ──> Executor
//!                       (ordered buffer)
//! ```
//!
//! The subscriber guarantees that `try_drain()` only yields commits
//! whose indices form a consecutive sequence starting from the last
//! delivered index + 1. Any commit arriving out of order is held in
//! an internal `BTreeMap` until the gap is filled.

use std::collections::BTreeMap;
use std::fmt;

use crate::narwhal_ordering::linearizer::LinearizedOutput;
use crate::narwhal_types::block::BlockRef;

// ═══════════════════════════════════════════════════════════
//  Error type
// ═══════════════════════════════════════════════════════════

/// Errors returned by [`CommitSubscriber`] operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriberError {
    /// Buffer is full — cannot accept more commits.
    BufferFull { capacity: usize, pending: usize },
    /// A commit with this index was already submitted.
    DuplicateCommit { commit_index: u64 },
    /// The commit index is below the last delivered index (stale).
    StaleCommit {
        commit_index: u64,
        last_delivered: u64,
    },
}

impl fmt::Display for SubscriberError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubscriberError::BufferFull { capacity, pending } => {
                write!(f, "subscriber buffer full: {pending}/{capacity}")
            }
            SubscriberError::DuplicateCommit { commit_index } => {
                write!(f, "duplicate commit index: {commit_index}")
            }
            SubscriberError::StaleCommit {
                commit_index,
                last_delivered,
            } => {
                write!(
                    f,
                    "stale commit index {commit_index}, last delivered was {last_delivered}"
                )
            }
        }
    }
}

impl std::error::Error for SubscriberError {}

// ═══════════════════════════════════════════════════════════
//  Finality notification
// ═══════════════════════════════════════════════════════════

/// Notification sent when a commit has been fully processed by the executor.
///
/// The executor sends this back to the consensus layer so that it can
/// advance its GC watermark and release storage for blocks below this
/// commit index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalityNotification {
    /// The commit index that was finalized.
    pub commit_index: u64,
    /// The leader block of the finalized commit.
    pub leader: BlockRef,
    /// Timestamp (ms) when finality was reached.
    pub finality_timestamp_ms: u64,
}

// ═══════════════════════════════════════════════════════════
//  Configuration
// ═══════════════════════════════════════════════════════════

/// Configuration for [`CommitSubscriber`].
#[derive(Debug, Clone)]
pub struct CommitSubscriberConfig {
    /// Maximum number of commits the buffer can hold.
    /// Default: 1024.
    pub buffer_capacity: usize,
    /// Percentage of buffer capacity at which the throttle signal is raised.
    /// Default: 80 (i.e., 80%).
    pub throttle_threshold_pct: u8,
    /// Timeout in milliseconds for waiting on a gap to be filled.
    /// Default: 10_000 (10 seconds).
    pub gap_timeout_ms: u64,
}

impl Default for CommitSubscriberConfig {
    fn default() -> Self {
        Self {
            buffer_capacity: 1024,
            throttle_threshold_pct: 80,
            gap_timeout_ms: 10_000,
        }
    }
}

impl CommitSubscriberConfig {
    /// Compute the absolute throttle threshold (number of buffered items).
    fn throttle_threshold(&self) -> usize {
        (self.buffer_capacity as u64 * self.throttle_threshold_pct as u64 / 100) as usize
    }
}

// ═══════════════════════════════════════════════════════════
//  Metrics
// ═══════════════════════════════════════════════════════════

/// Internal counters for observability.
#[derive(Debug, Clone, Default)]
pub struct SubscriberMetrics {
    /// Total commits submitted (including out-of-order).
    pub total_submitted: u64,
    /// Total commits delivered in order via `try_drain`.
    pub total_delivered: u64,
    /// Number of times a gap was detected on submit.
    pub gaps_detected: u64,
    /// Number of times the throttle signal was raised.
    pub throttle_activations: u64,
    /// Number of duplicate commits rejected.
    pub duplicates_rejected: u64,
    /// Number of stale commits rejected.
    pub stale_rejected: u64,
}

// ═══════════════════════════════════════════════════════════
//  CommitSubscriber
// ═══════════════════════════════════════════════════════════

/// Ordered commit delivery pipeline between the commit observer and the
/// executor.
///
/// Maintains a bounded buffer of [`LinearizedOutput`] commits. Commits
/// are only yielded to the executor in strict `commit_index` order;
/// any out-of-order arrival is held until its predecessor appears.
///
/// # Backpressure
///
/// When the buffer occupancy exceeds `throttle_threshold_pct` of the
/// configured capacity, [`should_throttle`](Self::should_throttle)
/// returns `true`. The upstream producer (commit observer) should use
/// this signal to slow down proposal creation.
pub struct CommitSubscriber {
    /// Configuration.
    config: CommitSubscriberConfig,
    /// Pending commits indexed by `commit_index`.
    /// Using BTreeMap for efficient ordered iteration and gap detection.
    pending: BTreeMap<u64, LinearizedOutput>,
    /// Last commit index delivered to the executor via `try_drain`.
    /// `None` means no commit has been delivered yet.
    last_delivered_index: Option<u64>,
    /// Whether the throttle signal is currently active.
    should_throttle: bool,
    /// Observable metrics.
    metrics: SubscriberMetrics,
}

impl CommitSubscriber {
    /// Create a new subscriber with the given configuration.
    #[must_use]
    pub fn new(config: CommitSubscriberConfig) -> Self {
        Self {
            config,
            pending: BTreeMap::new(),
            last_delivered_index: None,
            should_throttle: false,
            metrics: SubscriberMetrics::default(),
        }
    }

    /// Submit a [`LinearizedOutput`] commit for ordered delivery.
    ///
    /// The commit is buffered internally and will be yielded by
    /// [`try_drain`](Self::try_drain) once all preceding indices
    /// have been delivered.
    ///
    /// # Errors
    ///
    /// - [`SubscriberError::BufferFull`] if the buffer is at capacity.
    /// - [`SubscriberError::DuplicateCommit`] if a commit with the same
    ///   index is already buffered.
    /// - [`SubscriberError::StaleCommit`] if the commit index is at or
    ///   below the last delivered index.
    pub fn submit(&mut self, commit: LinearizedOutput) -> Result<(), SubscriberError> {
        let idx = commit.commit_index;

        // Reject stale commits (already delivered).
        if let Some(last) = self.last_delivered_index {
            if idx <= last {
                self.metrics.stale_rejected += 1;
                return Err(SubscriberError::StaleCommit {
                    commit_index: idx,
                    last_delivered: last,
                });
            }
        }

        // Reject duplicates.
        if self.pending.contains_key(&idx) {
            self.metrics.duplicates_rejected += 1;
            return Err(SubscriberError::DuplicateCommit { commit_index: idx });
        }

        // Reject if buffer is full.
        if self.pending.len() >= self.config.buffer_capacity {
            return Err(SubscriberError::BufferFull {
                capacity: self.config.buffer_capacity,
                pending: self.pending.len(),
            });
        }

        // Detect gap: is this commit non-consecutive?
        let expected_next = match self.last_delivered_index {
            None => {
                // If nothing delivered yet, the first pending key (if any)
                // tells us what we expect next, otherwise this commit's index
                // is fine.
                self.pending.keys().next().copied().unwrap_or(idx)
            }
            Some(last) => last + 1,
        };

        if idx != expected_next && !self.pending.contains_key(&expected_next) {
            self.metrics.gaps_detected += 1;
        }

        self.pending.insert(idx, commit);
        self.metrics.total_submitted += 1;

        // Update throttle signal.
        self.update_throttle_signal();

        Ok(())
    }

    /// Drain all consecutively available commits in index order.
    ///
    /// Starting from `last_delivered_index + 1` (or the lowest buffered
    /// index if nothing has been delivered yet), yields commits as long
    /// as they form an unbroken sequence. Commits after a gap remain
    /// buffered.
    ///
    /// Returns an empty `Vec` if the next expected commit is not yet
    /// available.
    pub fn try_drain(&mut self) -> Vec<LinearizedOutput> {
        let mut drained = Vec::new();

        loop {
            let next = match self.last_delivered_index {
                None => {
                    // First drain: must start from index 0 (strict ordering from genesis).
                    0
                }
                Some(last) => last + 1,
            };

            if let Some(output) = self.pending.remove(&next) {
                self.last_delivered_index = Some(next);
                self.metrics.total_delivered += 1;
                drained.push(output);
            } else {
                break;
            }
        }

        // Update throttle after draining.
        self.update_throttle_signal();

        drained
    }

    /// Returns `true` if the buffer occupancy is above the throttle
    /// threshold, signaling that the upstream producer should slow down.
    #[must_use]
    pub fn should_throttle(&self) -> bool {
        self.should_throttle
    }

    /// Number of commits currently buffered (waiting for delivery).
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// The last commit index that was delivered via `try_drain`.
    ///
    /// Returns `None` if no commit has been delivered yet.
    #[must_use]
    pub fn last_delivered_index(&self) -> Option<u64> {
        self.last_delivered_index
    }

    /// Number of gaps detected since creation.
    #[must_use]
    pub fn gap_count(&self) -> u64 {
        self.metrics.gaps_detected
    }

    /// Snapshot of internal metrics.
    #[must_use]
    pub fn metrics(&self) -> &SubscriberMetrics {
        &self.metrics
    }

    /// Configuration reference.
    #[must_use]
    pub fn config(&self) -> &CommitSubscriberConfig {
        &self.config
    }

    /// Compute the current number of index gaps in the pending buffer.
    ///
    /// A gap exists when consecutive keys in the BTreeMap are not
    /// adjacent (i.e., `key[i+1] != key[i] + 1`).
    #[must_use]
    pub fn current_gap_count(&self) -> usize {
        if self.pending.len() <= 1 {
            return 0;
        }
        let mut gaps = 0;
        let mut prev: Option<u64> = self.last_delivered_index;
        for &idx in self.pending.keys() {
            if let Some(p) = prev {
                if idx != p + 1 {
                    gaps += 1;
                }
            }
            prev = Some(idx);
        }
        gaps
    }

    /// Reset state (e.g., on epoch boundary).
    pub fn reset(&mut self) {
        self.pending.clear();
        self.last_delivered_index = None;
        self.should_throttle = false;
        // Metrics are preserved across resets for observability.
    }

    // ─── internal helpers ───────────────────────────────────

    fn update_throttle_signal(&mut self) {
        let threshold = self.config.throttle_threshold();
        let was_throttled = self.should_throttle;
        self.should_throttle = self.pending.len() >= threshold;

        if self.should_throttle && !was_throttled {
            self.metrics.throttle_activations += 1;
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::narwhal_types::block::{BlockDigest, BlockRef};

    /// Helper: create a minimal `LinearizedOutput` with the given index.
    fn make_commit(index: u64) -> LinearizedOutput {
        LinearizedOutput {
            commit_index: index,
            leader: BlockRef::new(index as u32, 0, BlockDigest([index as u8; 32])),
            transactions: vec![vec![index as u8]],
            blocks: vec![BlockRef::new(
                index as u32,
                0,
                BlockDigest([index as u8; 32]),
            )],
            timestamp_ms: 1000 + index,
            overflow_carryover: vec![],
            leader_state_root: None,
        }
    }

    fn default_subscriber() -> CommitSubscriber {
        CommitSubscriber::new(CommitSubscriberConfig::default())
    }

    // ── test_in_order_delivery ──────────────────────────────

    #[test]
    fn test_in_order_delivery() {
        let mut sub = default_subscriber();

        sub.submit(make_commit(0)).unwrap();
        sub.submit(make_commit(1)).unwrap();
        sub.submit(make_commit(2)).unwrap();

        let drained = sub.try_drain();
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].commit_index, 0);
        assert_eq!(drained[1].commit_index, 1);
        assert_eq!(drained[2].commit_index, 2);
        assert_eq!(sub.last_delivered_index(), Some(2));
        assert_eq!(sub.pending_count(), 0);
    }

    // ── test_gap_detection_and_buffering ────────────────────

    #[test]
    fn test_gap_detection_and_buffering() {
        let mut sub = default_subscriber();

        // Submit index 0, then skip 1 and submit 2.
        sub.submit(make_commit(0)).unwrap();
        let _ = sub.try_drain(); // delivers 0
        assert_eq!(sub.last_delivered_index(), Some(0));

        sub.submit(make_commit(2)).unwrap(); // gap: index 1 missing
        assert!(sub.gap_count() > 0, "gap should be detected");

        let drained = sub.try_drain();
        assert!(
            drained.is_empty(),
            "index 1 is missing, nothing should drain"
        );
        assert_eq!(sub.pending_count(), 1); // index 2 still buffered
    }

    // ── test_gap_fill_delivers_buffered ─────────────────────

    #[test]
    fn test_gap_fill_delivers_buffered() {
        let mut sub = default_subscriber();

        // Deliver index 0 first.
        sub.submit(make_commit(0)).unwrap();
        let _ = sub.try_drain();

        // Submit 3, 2 (out of order, gap at 1).
        sub.submit(make_commit(3)).unwrap();
        sub.submit(make_commit(2)).unwrap();
        assert!(sub.try_drain().is_empty()); // still waiting for 1

        // Fill the gap.
        sub.submit(make_commit(1)).unwrap();
        let drained = sub.try_drain();
        assert_eq!(drained.len(), 3);
        assert_eq!(drained[0].commit_index, 1);
        assert_eq!(drained[1].commit_index, 2);
        assert_eq!(drained[2].commit_index, 3);
        assert_eq!(sub.last_delivered_index(), Some(3));
    }

    // ── test_backpressure_signal ────────────────────────────

    #[test]
    fn test_backpressure_signal() {
        let config = CommitSubscriberConfig {
            buffer_capacity: 10,
            throttle_threshold_pct: 80,
            gap_timeout_ms: 10_000,
        };
        let mut sub = CommitSubscriber::new(config);

        // 80% of 10 = 8. Fill up to 7 — no throttle.
        for i in 0..7 {
            sub.submit(make_commit(i)).unwrap();
        }
        assert!(!sub.should_throttle(), "below 80% should not throttle");

        // At 8 pending (index 7) — throttle kicks in.
        sub.submit(make_commit(7)).unwrap();
        assert!(sub.should_throttle(), "at 80% should throttle");
        assert!(sub.metrics().throttle_activations >= 1);

        // Drain everything, throttle should clear.
        let _ = sub.try_drain();
        assert!(!sub.should_throttle(), "after drain should not throttle");
    }

    // ── test_empty_subscriber ───────────────────────────────

    #[test]
    fn test_empty_subscriber() {
        let sub = default_subscriber();
        assert_eq!(sub.pending_count(), 0);
        assert_eq!(sub.last_delivered_index(), None);
        assert!(!sub.should_throttle());
        assert_eq!(sub.gap_count(), 0);
        assert_eq!(sub.metrics().total_submitted, 0);
        assert_eq!(sub.metrics().total_delivered, 0);
    }

    // ── test_duplicate_commit_rejected ──────────────────────

    #[test]
    fn test_duplicate_commit_rejected() {
        let mut sub = default_subscriber();
        sub.submit(make_commit(0)).unwrap();

        let result = sub.submit(make_commit(0));
        assert_eq!(
            result,
            Err(SubscriberError::DuplicateCommit { commit_index: 0 })
        );
        assert_eq!(sub.metrics().duplicates_rejected, 1);
    }

    // ── test_out_of_order_reordering ────────────────────────

    #[test]
    fn test_out_of_order_reordering() {
        let mut sub = default_subscriber();

        // Submit in reverse order: 4, 3, 2, 1, 0.
        sub.submit(make_commit(4)).unwrap();
        sub.submit(make_commit(3)).unwrap();
        sub.submit(make_commit(2)).unwrap();
        sub.submit(make_commit(1)).unwrap();
        assert!(sub.try_drain().is_empty(), "cannot drain without index 0");

        sub.submit(make_commit(0)).unwrap();
        let drained = sub.try_drain();
        assert_eq!(drained.len(), 5);
        for (i, output) in drained.iter().enumerate() {
            assert_eq!(output.commit_index, i as u64, "must be in order");
        }
    }

    // ── test_metrics ────────────────────────────────────────

    #[test]
    fn test_metrics() {
        let mut sub = default_subscriber();

        // Submit 0, 1, 2 in order.
        sub.submit(make_commit(0)).unwrap();
        sub.submit(make_commit(1)).unwrap();
        sub.submit(make_commit(2)).unwrap();
        assert_eq!(sub.metrics().total_submitted, 3);

        // Drain all.
        let _ = sub.try_drain();
        assert_eq!(sub.metrics().total_delivered, 3);

        // Attempt duplicate.
        let _ = sub.submit(make_commit(2));
        assert_eq!(sub.metrics().stale_rejected, 1);

        // Submit with gap.
        sub.submit(make_commit(5)).unwrap();
        assert!(sub.metrics().gaps_detected >= 1);
    }

    // ── test_buffer_full ────────────────────────────────────

    #[test]
    fn test_buffer_full() {
        let config = CommitSubscriberConfig {
            buffer_capacity: 3,
            throttle_threshold_pct: 80,
            gap_timeout_ms: 10_000,
        };
        let mut sub = CommitSubscriber::new(config);

        sub.submit(make_commit(0)).unwrap();
        sub.submit(make_commit(1)).unwrap();
        sub.submit(make_commit(2)).unwrap();

        let result = sub.submit(make_commit(3));
        assert_eq!(
            result,
            Err(SubscriberError::BufferFull {
                capacity: 3,
                pending: 3,
            })
        );
    }

    // ── test_stale_commit_rejected ──────────────────────────

    #[test]
    fn test_stale_commit_rejected() {
        let mut sub = default_subscriber();

        sub.submit(make_commit(0)).unwrap();
        sub.submit(make_commit(1)).unwrap();
        let _ = sub.try_drain(); // delivers 0, 1

        let result = sub.submit(make_commit(0));
        assert_eq!(
            result,
            Err(SubscriberError::StaleCommit {
                commit_index: 0,
                last_delivered: 1,
            })
        );
    }

    // ── test_reset ──────────────────────────────────────────

    #[test]
    fn test_reset() {
        let mut sub = default_subscriber();

        sub.submit(make_commit(0)).unwrap();
        sub.submit(make_commit(1)).unwrap();
        let _ = sub.try_drain();

        sub.reset();
        assert_eq!(sub.pending_count(), 0);
        assert_eq!(sub.last_delivered_index(), None);
        assert!(!sub.should_throttle());
        // Metrics preserved.
        assert_eq!(sub.metrics().total_delivered, 2);
    }

    // ── test_current_gap_count ──────────────────────────────

    #[test]
    fn test_current_gap_count() {
        let mut sub = default_subscriber();

        sub.submit(make_commit(0)).unwrap();
        let _ = sub.try_drain();

        // Indices 2, 5, 8 — gaps at 1->2 (after delivered 0), 2->5, 5->8
        sub.submit(make_commit(2)).unwrap();
        sub.submit(make_commit(5)).unwrap();
        sub.submit(make_commit(8)).unwrap();

        // Gap between delivered 0 and pending 2, between 2 and 5, between 5 and 8.
        assert_eq!(sub.current_gap_count(), 3);
    }

    // ── test_finality_notification ──────────────────────────

    #[test]
    fn test_finality_notification() {
        let leader = BlockRef::new(1, 0, BlockDigest([0xAA; 32]));
        let notif = FinalityNotification {
            commit_index: 42,
            leader,
            finality_timestamp_ms: 99999,
        };
        assert_eq!(notif.commit_index, 42);
        assert_eq!(notif.leader, leader);
        assert_eq!(notif.finality_timestamp_ms, 99999);
    }
}
