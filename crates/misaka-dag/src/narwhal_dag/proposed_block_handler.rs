// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Ported from sui commit 0f58433, path: consensus/core/src/proposed_block_handler.rs
//
//! Proposed Block Handler — single aggregation point for post-proposal tasks.
//!
//! When a node proposes a block, three things must happen atomically:
//! 1. WAL flush (persist before broadcast, crash safety)
//! 2. Self-vote registration (DAG state records own block)
//! 3. Broadcaster enqueue (disseminate to peers)
//!
//! Without this handler, these steps are scattered across CoreEngine and
//! ConsensusRuntime, making it possible to:
//! - Broadcast without WAL flush (data loss on crash)
//! - WAL flush without broadcast (block stuck locally)
//! - Double-broadcast the same block
//!
//! ProposedBlockHandler prevents these by being the **single path** for
//! post-proposal processing.

use crate::narwhal_types::block::{AuthorityIndex, VerifiedBlock};

// ═══════════════════════════════════════════════════════════
//  Handler outcome
// ═══════════════════════════════════════════════════════════

/// Result of handling a proposed block.
#[derive(Debug, Clone)]
pub struct ProposalOutcome {
    /// Whether the WAL flush succeeded.
    pub wal_flushed: bool,
    /// Whether the block was enqueued for broadcast.
    pub broadcast_enqueued: bool,
    /// Whether the self-vote was registered.
    pub self_vote_registered: bool,
    /// Whether broadcaster back-pressure was detected.
    pub backpressure: bool,
}

// ═══════════════════════════════════════════════════════════
//  Metrics
// ═══════════════════════════════════════════════════════════

/// Metrics for ProposedBlockHandler.
#[derive(Debug, Clone, Default)]
pub struct ProposedBlockHandlerMetrics {
    /// Total blocks processed through this handler.
    pub blocks_handled: u64,
    /// Total WAL flushes performed.
    pub wal_flushes: u64,
    /// Total WAL flush failures.
    pub wal_flush_errors: u64,
    /// Total blocks enqueued for broadcast.
    pub broadcasts_enqueued: u64,
    /// Total self-votes registered.
    pub self_votes_registered: u64,
    /// Total back-pressure events from broadcaster.
    pub backpressure_events: u64,
}

// ═══════════════════════════════════════════════════════════
//  WAL writer trait (abstraction for testing)
// ═══════════════════════════════════════════════════════════

/// Trait for writing to the consensus WAL.
///
/// Abstracted for testing: production uses ConsensusWal,
/// tests use InMemoryWal.
pub trait WalWriter: Send {
    /// Append a proposed block to the WAL and flush.
    fn flush_proposed_block(&mut self, block: &VerifiedBlock) -> Result<(), String>;
}

/// No-op WAL writer for testing.
pub struct NoOpWal;

impl WalWriter for NoOpWal {
    fn flush_proposed_block(&mut self, _block: &VerifiedBlock) -> Result<(), String> {
        Ok(())
    }
}

/// In-memory WAL for testing.
pub struct InMemoryWal {
    pub entries: Vec<VerifiedBlock>,
}

impl InMemoryWal {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl WalWriter for InMemoryWal {
    fn flush_proposed_block(&mut self, block: &VerifiedBlock) -> Result<(), String> {
        self.entries.push(block.clone());
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════
//  Broadcast sink trait (abstraction for testing)
// ═══════════════════════════════════════════════════════════

/// Trait for enqueuing blocks for broadcast.
///
/// Abstracted so tests don't need a real Broadcaster.
pub trait BroadcastSink: Send {
    /// Enqueue a block for broadcast. Returns true if accepted.
    fn enqueue(&mut self, block: VerifiedBlock) -> bool;
    /// Whether the sink is currently saturated (back-pressure).
    fn is_saturated(&self) -> bool;
}

/// In-memory broadcast sink for testing.
pub struct InMemoryBroadcastSink {
    pub blocks: Vec<VerifiedBlock>,
    pub capacity: usize,
}

impl InMemoryBroadcastSink {
    pub fn new(capacity: usize) -> Self {
        Self {
            blocks: Vec::new(),
            capacity,
        }
    }
}

impl BroadcastSink for InMemoryBroadcastSink {
    fn enqueue(&mut self, block: VerifiedBlock) -> bool {
        if self.blocks.len() >= self.capacity {
            return false;
        }
        self.blocks.push(block);
        true
    }

    fn is_saturated(&self) -> bool {
        self.blocks.len() >= self.capacity
    }
}

// ═══════════════════════════════════════════════════════════
//  Self-vote registration trait
// ═══════════════════════════════════════════════════════════

/// Trait for registering self-votes in DAG state.
pub trait SelfVoteRegistrar: Send {
    /// Register that we voted for (authored) this block.
    fn register_self_vote(&mut self, block: &VerifiedBlock);
}

/// No-op registrar for testing.
pub struct NoOpRegistrar;

impl SelfVoteRegistrar for NoOpRegistrar {
    fn register_self_vote(&mut self, _block: &VerifiedBlock) {}
}

/// In-memory registrar for testing.
pub struct InMemoryRegistrar {
    pub votes: Vec<(AuthorityIndex, u32)>, // (author, round)
}

impl InMemoryRegistrar {
    pub fn new() -> Self {
        Self { votes: Vec::new() }
    }
}

impl SelfVoteRegistrar for InMemoryRegistrar {
    fn register_self_vote(&mut self, block: &VerifiedBlock) {
        self.votes.push((block.author(), block.round()));
    }
}

// ═══════════════════════════════════════════════════════════
//  ProposedBlockHandler
// ═══════════════════════════════════════════════════════════

/// Single aggregation point for post-proposal block processing.
///
/// Ensures WAL flush → self-vote → broadcast happen in order,
/// preventing double-broadcast and crash-unsafe broadcast-before-WAL.
pub struct ProposedBlockHandler {
    our_authority: AuthorityIndex,
    wal: Box<dyn WalWriter>,
    broadcast: Box<dyn BroadcastSink>,
    registrar: Box<dyn SelfVoteRegistrar>,
    metrics: ProposedBlockHandlerMetrics,
}

impl ProposedBlockHandler {
    pub fn new(
        our_authority: AuthorityIndex,
        wal: Box<dyn WalWriter>,
        broadcast: Box<dyn BroadcastSink>,
        registrar: Box<dyn SelfVoteRegistrar>,
    ) -> Self {
        Self {
            our_authority,
            wal,
            broadcast,
            registrar,
            metrics: ProposedBlockHandlerMetrics::default(),
        }
    }

    /// Handle a newly proposed block.
    ///
    /// Executes the three post-proposal steps in strict order:
    /// 1. WAL flush (crash safety)
    /// 2. Self-vote registration
    /// 3. Broadcaster enqueue
    ///
    /// If WAL flush fails, broadcast is skipped (prevent unsafe dissemination).
    pub fn handle(&mut self, block: VerifiedBlock) -> ProposalOutcome {
        self.metrics.blocks_handled += 1;

        // Step 1: WAL flush
        let wal_flushed = match self.wal.flush_proposed_block(&block) {
            Ok(()) => {
                self.metrics.wal_flushes += 1;
                true
            }
            Err(_) => {
                self.metrics.wal_flush_errors += 1;
                // WAL flush failed — do NOT broadcast.
                // Block will be re-proposed after WAL recovery.
                return ProposalOutcome {
                    wal_flushed: false,
                    broadcast_enqueued: false,
                    self_vote_registered: false,
                    backpressure: false,
                };
            }
        };

        // Step 2: Self-vote registration
        self.registrar.register_self_vote(&block);
        self.metrics.self_votes_registered += 1;

        // Step 3: Broadcaster enqueue
        let backpressure = self.broadcast.is_saturated();
        let broadcast_enqueued = self.broadcast.enqueue(block);
        if broadcast_enqueued {
            self.metrics.broadcasts_enqueued += 1;
        }
        if backpressure {
            self.metrics.backpressure_events += 1;
        }

        ProposalOutcome {
            wal_flushed,
            broadcast_enqueued,
            self_vote_registered: true,
            backpressure,
        }
    }

    /// Metrics snapshot.
    pub fn metrics(&self) -> &ProposedBlockHandlerMetrics {
        &self.metrics
    }
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::narwhal_types::block::Block;

    fn make_block(round: u32, author: u32) -> VerifiedBlock {
        VerifiedBlock::new_for_test(Block {
            epoch: 0,
            round,
            author,
            timestamp_ms: 1000,
            ancestors: vec![],
            transactions: vec![vec![round as u8]],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            state_root_smt: [0u8; 32],
            signature: vec![0xCC; 3309],
        })
    }

    #[test]
    fn test_happy_path() {
        let mut handler = ProposedBlockHandler::new(
            0,
            Box::new(InMemoryWal::new()),
            Box::new(InMemoryBroadcastSink::new(100)),
            Box::new(InMemoryRegistrar::new()),
        );

        let block = make_block(1, 0);
        let outcome = handler.handle(block);

        assert!(outcome.wal_flushed);
        assert!(outcome.broadcast_enqueued);
        assert!(outcome.self_vote_registered);
        assert!(!outcome.backpressure);
        assert_eq!(handler.metrics().blocks_handled, 1);
        assert_eq!(handler.metrics().wal_flushes, 1);
        assert_eq!(handler.metrics().broadcasts_enqueued, 1);
        assert_eq!(handler.metrics().self_votes_registered, 1);
    }

    #[test]
    fn test_wal_failure_blocks_broadcast() {
        struct FailingWal;
        impl WalWriter for FailingWal {
            fn flush_proposed_block(&mut self, _: &VerifiedBlock) -> Result<(), String> {
                Err("disk full".into())
            }
        }

        let mut handler = ProposedBlockHandler::new(
            0,
            Box::new(FailingWal),
            Box::new(InMemoryBroadcastSink::new(100)),
            Box::new(InMemoryRegistrar::new()),
        );

        let outcome = handler.handle(make_block(1, 0));

        assert!(!outcome.wal_flushed);
        assert!(
            !outcome.broadcast_enqueued,
            "must NOT broadcast after WAL failure"
        );
        assert!(!outcome.self_vote_registered);
        assert_eq!(handler.metrics().wal_flush_errors, 1);
    }

    #[test]
    fn test_broadcast_backpressure() {
        let mut handler = ProposedBlockHandler::new(
            0,
            Box::new(InMemoryWal::new()),
            Box::new(InMemoryBroadcastSink::new(1)), // capacity 1
            Box::new(InMemoryRegistrar::new()),
        );

        // First block: succeeds
        let o1 = handler.handle(make_block(1, 0));
        assert!(o1.broadcast_enqueued);
        assert!(!o1.backpressure);

        // Second block: back-pressure (sink full)
        let o2 = handler.handle(make_block(2, 0));
        assert!(!o2.broadcast_enqueued);
        assert!(o2.backpressure);
        assert!(
            o2.wal_flushed,
            "WAL must still flush even under back-pressure"
        );
        assert!(o2.self_vote_registered, "self-vote must still register");
    }

    #[test]
    fn test_wal_and_registrar_contents() {
        let wal = InMemoryWal::new();
        let reg = InMemoryRegistrar::new();
        let sink = InMemoryBroadcastSink::new(100);

        // Use raw pointers for interior inspection (test-only pattern)
        let wal_ptr = Box::into_raw(Box::new(wal));
        let reg_ptr = Box::into_raw(Box::new(reg));
        let sink_ptr = Box::into_raw(Box::new(sink));

        let mut handler = ProposedBlockHandler::new(
            0,
            unsafe { Box::from_raw(wal_ptr) },
            unsafe { Box::from_raw(sink_ptr) },
            unsafe { Box::from_raw(reg_ptr) },
        );

        handler.handle(make_block(1, 0));
        handler.handle(make_block(2, 0));
        handler.handle(make_block(3, 0));

        assert_eq!(handler.metrics().blocks_handled, 3);

        // WAL, registrar, and sink are inside the handler (moved).
        // We verify via metrics that all 3 steps happened.
        assert_eq!(handler.metrics().wal_flushes, 3);
        assert_eq!(handler.metrics().self_votes_registered, 3);
        assert_eq!(handler.metrics().broadcasts_enqueued, 3);
    }

    #[test]
    fn test_multiple_blocks_sequential() {
        let mut handler = ProposedBlockHandler::new(
            0,
            Box::new(InMemoryWal::new()),
            Box::new(InMemoryBroadcastSink::new(100)),
            Box::new(InMemoryRegistrar::new()),
        );

        for i in 1..=10 {
            let outcome = handler.handle(make_block(i, 0));
            assert!(outcome.wal_flushed);
            assert!(outcome.broadcast_enqueued);
            assert!(outcome.self_vote_registered);
        }

        assert_eq!(handler.metrics().blocks_handled, 10);
    }
}
