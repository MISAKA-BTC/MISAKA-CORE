// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Ported from sui commit 0f58433, path: consensus/core/src/subscriber.rs
//
//! Block Subscriber — receives blocks from peers and feeds them to the DAG.
//!
//! This is the inbound counterpart to [`Broadcaster`](super::broadcaster::Broadcaster).
//! It buffers incoming peer blocks and delivers them to CoreEngine for
//! processing, with back-pressure that degrades gracefully (drops oldest)
//! instead of panicking.
//!
//! # PQ considerations
//!
//! Each block carries a 3,309-byte ML-DSA-65 signature. At the default
//! buffer capacity of 2,000 blocks, the maximum memory usage is:
//!
//! ```text
//! 2,000 × ~3,600 bytes ≈ 7.2 MiB
//! ```
//!
//! This is well within safe limits. The buffer is sized to absorb
//! burst traffic (e.g., post-partition catch-up) without dropping.

use std::collections::VecDeque;
use std::fmt;

use crate::narwhal_types::block::{AuthorityIndex, VerifiedBlock};

// ═══════════════════════════════════════════════════════════
//  Configuration
// ═══════════════════════════════════════════════════════════

/// Configuration for [`BlockSubscriber`].
#[derive(Clone, Debug)]
pub struct BlockSubscriberConfig {
    /// Maximum number of blocks the buffer can hold.
    /// Default: 2,000 (from ProtocolConfig).
    pub buffer_capacity: usize,
    /// Percentage of buffer capacity at which the throttle signal is raised.
    /// Default: 80%.
    pub throttle_threshold_pct: u8,
}

impl Default for BlockSubscriberConfig {
    fn default() -> Self {
        Self {
            buffer_capacity: 2000,
            throttle_threshold_pct: 80,
        }
    }
}

impl BlockSubscriberConfig {
    fn throttle_threshold(&self) -> usize {
        (self.buffer_capacity as u64 * self.throttle_threshold_pct as u64 / 100) as usize
    }
}

// ═══════════════════════════════════════════════════════════
//  Error
// ═══════════════════════════════════════════════════════════

/// Errors from [`BlockSubscriber`] operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockSubscriberError {
    /// Buffer is at capacity; oldest block was evicted to make room.
    Evicted {
        evicted_round: u32,
        evicted_author: AuthorityIndex,
    },
}

impl fmt::Display for BlockSubscriberError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockSubscriberError::Evicted {
                evicted_round,
                evicted_author,
            } => write!(
                f,
                "block subscriber buffer full: evicted block (round={evicted_round}, author={evicted_author})"
            ),
        }
    }
}

impl std::error::Error for BlockSubscriberError {}

// ═══════════════════════════════════════════════════════════
//  Metrics
// ═══════════════════════════════════════════════════════════

/// Block subscriber metrics.
#[derive(Debug, Clone, Default)]
pub struct BlockSubscriberMetrics {
    /// Total blocks received.
    pub blocks_received: u64,
    /// Total blocks delivered to processing.
    pub blocks_delivered: u64,
    /// Total blocks evicted due to buffer overflow.
    pub blocks_evicted: u64,
    /// Number of times the throttle signal was raised.
    pub throttle_activations: u64,
    /// Total bytes received (approximate).
    pub bytes_received: u64,
}

// ═══════════════════════════════════════════════════════════
//  BlockSubscriber
// ═══════════════════════════════════════════════════════════

/// Bounded buffer for blocks received from peers.
///
/// Unlike [`CommitSubscriber`](super::commit_subscriber::CommitSubscriber) which
/// rejects when full (commits must never be lost), BlockSubscriber **evicts**
/// the oldest block when full. This is safe because:
///
/// 1. The synchronizer will re-fetch any missing blocks.
/// 2. Dropping a block delays but does not break consensus.
/// 3. Panicking on buffer overflow would be catastrophic.
///
/// # Back-pressure
///
/// When the buffer occupancy exceeds `throttle_threshold_pct`,
/// [`should_throttle()`](Self::should_throttle) returns `true`.
/// The caller can use this to signal the network layer to slow down
/// peer block fetching.
pub struct BlockSubscriber {
    config: BlockSubscriberConfig,
    buffer: VecDeque<VerifiedBlock>,
    should_throttle: bool,
    metrics: BlockSubscriberMetrics,
}

impl BlockSubscriber {
    /// Create a new subscriber.
    pub fn new(config: BlockSubscriberConfig) -> Self {
        Self {
            buffer: VecDeque::with_capacity(config.buffer_capacity.min(8192)),
            should_throttle: false,
            metrics: BlockSubscriberMetrics::default(),
            config,
        }
    }

    /// Receive a block from a peer.
    ///
    /// If the buffer is full, the oldest block is evicted. This NEVER
    /// panics — it degrades gracefully. The synchronizer will re-fetch
    /// any evicted blocks if they are needed for DAG completion.
    ///
    /// Returns `Ok(())` on normal insert, or `Err(BlockSubscriberError::Evicted)`
    /// if an eviction occurred (informational, not fatal).
    pub fn receive(&mut self, block: VerifiedBlock) -> Result<(), BlockSubscriberError> {
        let inner = block.inner();
        let bytes =
            inner.signature.len() + 256 + inner.transactions.iter().map(|t| t.len()).sum::<usize>();
        self.metrics.blocks_received += 1;
        self.metrics.bytes_received += bytes as u64;

        let mut eviction = None;

        if self.buffer.len() >= self.config.buffer_capacity {
            // Evict oldest to make room — NEVER panic.
            if let Some(evicted) = self.buffer.pop_front() {
                self.metrics.blocks_evicted += 1;
                eviction = Some(BlockSubscriberError::Evicted {
                    evicted_round: evicted.round(),
                    evicted_author: evicted.author(),
                });
            }
        }

        self.buffer.push_back(block);
        self.update_throttle();

        match eviction {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Drain all buffered blocks for processing.
    ///
    /// Returns blocks in FIFO order (oldest first). After draining,
    /// the buffer is empty and the throttle signal is cleared.
    pub fn drain_all(&mut self) -> Vec<VerifiedBlock> {
        let blocks: Vec<VerifiedBlock> = self.buffer.drain(..).collect();
        self.metrics.blocks_delivered += blocks.len() as u64;
        self.update_throttle();
        blocks
    }

    /// Drain up to `max` blocks from the front of the buffer.
    pub fn drain_up_to(&mut self, max: usize) -> Vec<VerifiedBlock> {
        let n = self.buffer.len().min(max);
        let blocks: Vec<VerifiedBlock> = self.buffer.drain(..n).collect();
        self.metrics.blocks_delivered += blocks.len() as u64;
        self.update_throttle();
        blocks
    }

    /// Whether the buffer is above the throttle threshold.
    pub fn should_throttle(&self) -> bool {
        self.should_throttle
    }

    /// Number of blocks currently buffered.
    pub fn buffered_count(&self) -> usize {
        self.buffer.len()
    }

    /// Metrics snapshot.
    pub fn metrics(&self) -> &BlockSubscriberMetrics {
        &self.metrics
    }

    /// Reset (e.g., on epoch boundary).
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.should_throttle = false;
    }

    fn update_throttle(&mut self) {
        let threshold = self.config.throttle_threshold();
        let was = self.should_throttle;
        self.should_throttle = self.buffer.len() >= threshold;
        if self.should_throttle && !was {
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
            signature: vec![0xBB; 3309],
        })
    }

    // ── test: basic receive and drain ────────────────────

    #[test]
    fn test_receive_and_drain() {
        let mut sub = BlockSubscriber::new(BlockSubscriberConfig::default());

        sub.receive(make_block(1, 0)).unwrap();
        sub.receive(make_block(2, 1)).unwrap();
        sub.receive(make_block(3, 2)).unwrap();

        assert_eq!(sub.buffered_count(), 3);
        assert_eq!(sub.metrics().blocks_received, 3);

        let blocks = sub.drain_all();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].round(), 1);
        assert_eq!(blocks[1].round(), 2);
        assert_eq!(blocks[2].round(), 3);
        assert_eq!(sub.buffered_count(), 0);
        assert_eq!(sub.metrics().blocks_delivered, 3);
    }

    // ── test: eviction on overflow (no panic) ────────────

    #[test]
    fn test_eviction_no_panic() {
        let config = BlockSubscriberConfig {
            buffer_capacity: 3,
            throttle_threshold_pct: 80,
        };
        let mut sub = BlockSubscriber::new(config);

        sub.receive(make_block(1, 0)).unwrap();
        sub.receive(make_block(2, 0)).unwrap();
        sub.receive(make_block(3, 0)).unwrap();

        // Buffer full (3/3). Next receive evicts oldest.
        let result = sub.receive(make_block(4, 0));
        assert!(result.is_err());
        match result.unwrap_err() {
            BlockSubscriberError::Evicted { evicted_round, .. } => {
                assert_eq!(evicted_round, 1, "oldest (round 1) should be evicted");
            }
        }
        assert_eq!(sub.buffered_count(), 3); // still 3
        assert_eq!(sub.metrics().blocks_evicted, 1);

        // Drain and verify order: 2, 3, 4
        let blocks = sub.drain_all();
        assert_eq!(blocks[0].round(), 2);
        assert_eq!(blocks[1].round(), 3);
        assert_eq!(blocks[2].round(), 4);
    }

    // ── test: throttle signal ────────────────────────────

    #[test]
    fn test_throttle_signal() {
        let config = BlockSubscriberConfig {
            buffer_capacity: 10,
            throttle_threshold_pct: 80,
        };
        let mut sub = BlockSubscriber::new(config);

        // Fill to 7/10 — below 80%
        for i in 0..7 {
            sub.receive(make_block(i, 0)).unwrap();
        }
        assert!(!sub.should_throttle());

        // Fill to 8/10 — at 80%
        sub.receive(make_block(7, 0)).unwrap();
        assert!(sub.should_throttle());
        assert!(sub.metrics().throttle_activations >= 1);

        // Drain clears throttle
        sub.drain_all();
        assert!(!sub.should_throttle());
    }

    // ── test: drain_up_to ────────────────────────────────

    #[test]
    fn test_drain_up_to() {
        let mut sub = BlockSubscriber::new(BlockSubscriberConfig::default());
        for i in 0..10 {
            sub.receive(make_block(i, 0)).unwrap();
        }

        let batch = sub.drain_up_to(3);
        assert_eq!(batch.len(), 3);
        assert_eq!(batch[0].round(), 0);
        assert_eq!(batch[2].round(), 2);
        assert_eq!(sub.buffered_count(), 7);
    }

    // ── test: PQ byte accounting ─────────────────────────

    #[test]
    fn test_pq_byte_accounting() {
        let mut sub = BlockSubscriber::new(BlockSubscriberConfig::default());
        sub.receive(make_block(1, 0)).unwrap();

        // 3309 sig + 256 overhead + 1 tx byte
        assert_eq!(sub.metrics().bytes_received, 3309 + 256 + 1);
    }

    // ── test: reset ──────────────────────────────────────

    #[test]
    fn test_reset() {
        let mut sub = BlockSubscriber::new(BlockSubscriberConfig::default());
        for i in 0..5 {
            sub.receive(make_block(i, 0)).unwrap();
        }
        sub.reset();
        assert_eq!(sub.buffered_count(), 0);
        assert!(!sub.should_throttle());
        // Metrics preserved
        assert_eq!(sub.metrics().blocks_received, 5);
    }

    // ── test: massive flood (no panic) ───────────────────

    #[test]
    fn test_massive_flood_no_panic() {
        let config = BlockSubscriberConfig {
            buffer_capacity: 100,
            throttle_threshold_pct: 80,
        };
        let mut sub = BlockSubscriber::new(config);

        // Flood with 1000 blocks — must NOT panic
        for i in 0..1000 {
            let _ = sub.receive(make_block(i, i % 21));
        }

        assert_eq!(sub.buffered_count(), 100);
        assert_eq!(sub.metrics().blocks_received, 1000);
        assert_eq!(sub.metrics().blocks_evicted, 900);

        // Drain and verify the last 100 blocks survived
        let blocks = sub.drain_all();
        assert_eq!(blocks.len(), 100);
        assert_eq!(blocks[0].round(), 900); // oldest survivor
        assert_eq!(blocks[99].round(), 999); // newest
    }
}
