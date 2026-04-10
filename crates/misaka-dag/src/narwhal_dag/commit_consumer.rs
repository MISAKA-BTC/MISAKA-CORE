// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Ported from sui commit 0f58433, path: consensus/core/src/commit_consumer.rs
//
//! Commit Consumer — trait for consuming finalized commits.
//!
//! Extracted from the commit pipeline to cleanly separate "what happens
//! after a commit" from "how commits are produced." This enables:
//!
//! - Executor: processes transactions from committed blocks
//! - Mempool: evicts confirmed transactions
//! - Observer: Phase 2-3 observer_service reads commit stream
//! - Light Client: Phase 4 consumes (commit, quorum proof) pairs
//!
//! # Architecture
//!
//! ```text
//! CoreEngine → Committer → Linearizer → CommitSubscriber
//!                                            │
//!                                            ▼
//!                                     CommitConsumer trait
//!                                       ┌────┴────┐
//!                                       │         │
//!                              ChannelConsumer  LogConsumer (test)
//! ```
//!
//! The CommitSubscriber (existing) handles ordered delivery and
//! back-pressure. CommitConsumer sits downstream, processing each
//! commit after it has been ordered and delivered.

use crate::narwhal_ordering::linearizer::LinearizedOutput;
use crate::narwhal_types::block::BlockRef;
use crate::narwhal_types::commit::CommittedSubDag;

// ═══════════════════════════════════════════════════════════
//  CommitConsumer trait
// ═══════════════════════════════════════════════════════════

/// Trait for consuming finalized commits.
///
/// Implementations receive committed sub-DAGs in strict sequential order
/// (commit index 0, 1, 2, ...). The CommitSubscriber guarantees ordering
/// before calling the consumer.
///
/// # Contract
///
/// - `process` is called exactly once per commit index (no duplicates).
/// - `process` is called in strict ascending order.
/// - `is_saturated` must be cheap (no I/O).
/// - Implementations must not panic on unexpected input.
pub trait CommitConsumer: Send {
    /// Process a finalized commit.
    ///
    /// `output` contains the linearized transactions and metadata.
    /// This is the primary entry point for downstream processing.
    fn process(&mut self, output: &LinearizedOutput);

    /// Back-pressure signal: returns true if the consumer cannot
    /// keep up with the commit rate.
    ///
    /// When saturated, the upstream CommitSubscriber should signal
    /// the consensus layer to slow down block proposal.
    fn is_saturated(&self) -> bool;

    /// Notification that the executor has finalized a commit.
    ///
    /// Used for GC watermark advancement. Default: no-op.
    fn on_finality(&mut self, _commit_index: u64, _leader: BlockRef) {}
}

// ═══════════════════════════════════════════════════════════
//  ChannelCommitConsumer — default channel-based impl
// ═══════════════════════════════════════════════════════════

/// Default CommitConsumer that forwards commits through a bounded channel.
///
/// This is the standard production implementation: the consensus layer
/// pushes LinearizedOutput through the channel, and the executor task
/// receives on the other end.
pub struct ChannelCommitConsumer {
    /// Bounded channel sender.
    tx: tokio::sync::mpsc::Sender<LinearizedOutput>,
    /// Tracks whether the last send was blocked (back-pressure indicator).
    last_send_blocked: bool,
    /// Total commits processed.
    pub total_processed: u64,
    /// Total commits dropped (channel full).
    pub total_dropped: u64,
}

impl ChannelCommitConsumer {
    /// Create with an existing channel sender.
    pub fn new(tx: tokio::sync::mpsc::Sender<LinearizedOutput>) -> Self {
        Self {
            tx,
            last_send_blocked: false,
            total_processed: 0,
            total_dropped: 0,
        }
    }
}

impl CommitConsumer for ChannelCommitConsumer {
    fn process(&mut self, output: &LinearizedOutput) {
        self.total_processed += 1;
        match self.tx.try_send(output.clone()) {
            Ok(()) => {
                self.last_send_blocked = false;
            }
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                self.last_send_blocked = true;
                self.total_dropped += 1;
                // Log but don't panic — the commit is preserved in the
                // commit subscriber's buffer and can be replayed.
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                self.last_send_blocked = true;
                self.total_dropped += 1;
            }
        }
    }

    fn is_saturated(&self) -> bool {
        self.last_send_blocked
    }
}

// ═══════════════════════════════════════════════════════════
//  LogCommitConsumer — test/debug consumer
// ═══════════════════════════════════════════════════════════

/// Test-only consumer that logs commits to a Vec.
///
/// Useful for simulator tests and integration tests where we want
/// to inspect the committed sequence without an executor.
pub struct LogCommitConsumer {
    /// All processed commits (in order).
    pub commits: Vec<CommitRecord>,
    /// Back-pressure threshold: returns saturated after this many pending.
    pub saturation_threshold: usize,
}

/// Minimal record of a processed commit.
#[derive(Debug, Clone)]
pub struct CommitRecord {
    pub commit_index: u64,
    pub leader: BlockRef,
    pub num_transactions: usize,
    pub timestamp_ms: u64,
}

impl LogCommitConsumer {
    /// Create with an optional saturation threshold.
    pub fn new(saturation_threshold: usize) -> Self {
        Self {
            commits: Vec::new(),
            saturation_threshold,
        }
    }

    /// Create with no back-pressure limit.
    pub fn unlimited() -> Self {
        Self::new(usize::MAX)
    }
}

impl CommitConsumer for LogCommitConsumer {
    fn process(&mut self, output: &LinearizedOutput) {
        self.commits.push(CommitRecord {
            commit_index: output.commit_index,
            leader: output.leader,
            num_transactions: output.transactions.len(),
            timestamp_ms: output.timestamp_ms,
        });
    }

    fn is_saturated(&self) -> bool {
        self.commits.len() >= self.saturation_threshold
    }
}

// ═══════════════════════════════════════════════════════════
//  MultiConsumer — fan-out to multiple consumers
// ═══════════════════════════════════════════════════════════

/// Fans out each commit to multiple consumers.
///
/// Used when multiple downstream systems need the same commit stream
/// (e.g., executor + observer + mempool). Saturated when ANY child
/// is saturated (conservative back-pressure).
pub struct MultiConsumer {
    consumers: Vec<Box<dyn CommitConsumer>>,
}

impl MultiConsumer {
    pub fn new(consumers: Vec<Box<dyn CommitConsumer>>) -> Self {
        Self { consumers }
    }
}

impl CommitConsumer for MultiConsumer {
    fn process(&mut self, output: &LinearizedOutput) {
        for consumer in &mut self.consumers {
            consumer.process(output);
        }
    }

    fn is_saturated(&self) -> bool {
        self.consumers.iter().any(|c| c.is_saturated())
    }

    fn on_finality(&mut self, commit_index: u64, leader: BlockRef) {
        for consumer in &mut self.consumers {
            consumer.on_finality(commit_index, leader);
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

    fn make_output(index: u64) -> LinearizedOutput {
        LinearizedOutput {
            commit_index: index,
            leader: BlockRef::new(index as u32, 0, BlockDigest([index as u8; 32])),
            transactions: vec![vec![index as u8; 10]],
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

    // ── test: LogCommitConsumer basic ─────────────────────

    #[test]
    fn test_log_consumer_basic() {
        let mut consumer = LogCommitConsumer::unlimited();

        consumer.process(&make_output(0));
        consumer.process(&make_output(1));
        consumer.process(&make_output(2));

        assert_eq!(consumer.commits.len(), 3);
        assert_eq!(consumer.commits[0].commit_index, 0);
        assert_eq!(consumer.commits[1].commit_index, 1);
        assert_eq!(consumer.commits[2].commit_index, 2);
        assert_eq!(consumer.commits[0].num_transactions, 1);
        assert!(!consumer.is_saturated());
    }

    // ── test: LogCommitConsumer saturation ────────────────

    #[test]
    fn test_log_consumer_saturation() {
        let mut consumer = LogCommitConsumer::new(3);

        consumer.process(&make_output(0));
        consumer.process(&make_output(1));
        assert!(!consumer.is_saturated());

        consumer.process(&make_output(2));
        assert!(consumer.is_saturated());
    }

    // ── test: ChannelCommitConsumer ───────────────────────

    #[test]
    fn test_channel_consumer() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let mut consumer = ChannelCommitConsumer::new(tx);

        consumer.process(&make_output(0));
        consumer.process(&make_output(1));

        assert_eq!(consumer.total_processed, 2);
        assert_eq!(consumer.total_dropped, 0);
        assert!(!consumer.is_saturated());

        // Verify channel received
        let out0 = rx.try_recv().unwrap();
        assert_eq!(out0.commit_index, 0);
        let out1 = rx.try_recv().unwrap();
        assert_eq!(out1.commit_index, 1);
    }

    // ── test: ChannelCommitConsumer back-pressure ─────────

    #[test]
    fn test_channel_consumer_backpressure() {
        let (tx, _rx) = tokio::sync::mpsc::channel(2);
        let mut consumer = ChannelCommitConsumer::new(tx);

        consumer.process(&make_output(0));
        consumer.process(&make_output(1));
        assert!(!consumer.is_saturated());

        // Channel full (capacity 2)
        consumer.process(&make_output(2));
        assert!(consumer.is_saturated());
        assert_eq!(consumer.total_dropped, 1);
    }

    // ── test: MultiConsumer fan-out ──────────────────────

    #[test]
    fn test_multi_consumer() {
        let c1 = LogCommitConsumer::unlimited();
        let c2 = LogCommitConsumer::new(2);

        let mut multi = MultiConsumer::new(vec![Box::new(c1), Box::new(c2)]);

        multi.process(&make_output(0));
        assert!(!multi.is_saturated());

        multi.process(&make_output(1));
        // c2 has threshold 2, now saturated
        assert!(multi.is_saturated());
    }

    // ── test: CommitConsumer trait object ─────────────────

    #[test]
    fn test_trait_object() {
        let mut consumer: Box<dyn CommitConsumer> = Box::new(LogCommitConsumer::unlimited());
        consumer.process(&make_output(0));
        assert!(!consumer.is_saturated());
    }

    // ── test: on_finality default ────────────────────────

    #[test]
    fn test_on_finality_default() {
        let mut consumer = LogCommitConsumer::unlimited();
        let leader = BlockRef::new(1, 0, BlockDigest([0; 32]));
        // Should not panic (default no-op)
        consumer.on_finality(0, leader);
    }
}
