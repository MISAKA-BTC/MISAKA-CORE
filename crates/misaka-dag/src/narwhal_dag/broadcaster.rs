// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
// Ported from sui commit 0f58433, path: consensus/core/src/broadcaster.rs
//
//! Block Broadcaster — PQ-aware dissemination of proposed blocks.
//!
//! Receives proposed blocks from CoreEngine via the runtime broadcast channel
//! and distributes them to all peers with batching and back-pressure tuned
//! for ML-DSA-65 signature sizes (3,309 bytes vs Ed25519's 64 bytes).
//!
//! # PQ tuning rationale
//!
//! ML-DSA-65 signatures are ~50× larger than Ed25519. Sending blocks one
//! at a time wastes TLS/framing overhead. Instead we batch multiple blocks
//! per send and use smaller concurrency windows than Sui:
//!
//! | Parameter           | Sui (Ed25519) | MISAKA (ML-DSA-65) | Ratio |
//! |---------------------|---------------|--------------------|-------|
//! | batch_size          | ~20           | 5                  | 1/4   |
//! | window_size         | ~10           | 3                  | 1/3   |
//! | max_pending_bytes   | —             | 64 MiB             | new   |
//! | max_batch_delay_ms  | —             | 50 ms              | new   |
//!
//! The 64 MiB threshold corresponds to ~20,000 ML-DSA-65 signatures,
//! which is sufficient to buffer the entire committee's proposals for
//! multiple rounds without risking OOM.

use std::collections::HashMap;

use crate::narwhal_types::block::{AuthorityIndex, VerifiedBlock};
use crate::narwhal_types::committee::Committee;

// ═══════════════════════════════════════════════════════════
//  Configuration
// ═══════════════════════════════════════════════════════════

/// Broadcaster configuration — loaded from ProtocolConfig.
#[derive(Clone, Debug)]
pub struct BroadcasterConfig {
    /// Maximum blocks per broadcast batch.
    pub batch_size: usize,
    /// Maximum concurrent in-flight batches per peer.
    pub window_size: usize,
    /// Maximum bytes pending per peer before back-pressure engages.
    /// Default: 64 MiB (~20,000 ML-DSA-65 signatures).
    pub max_pending_bytes: usize,
    /// Maximum delay (ms) before flushing a partial batch.
    pub max_batch_delay_ms: u64,
}

impl Default for BroadcasterConfig {
    fn default() -> Self {
        Self {
            batch_size: 5,
            window_size: 3,
            max_pending_bytes: 64 * 1024 * 1024, // 64 MiB
            max_batch_delay_ms: 50,
        }
    }
}

impl BroadcasterConfig {
    /// Construct from ProtocolConfig values.
    pub fn from_protocol_config(
        batch_size: u32,
        window_size: u32,
        max_pending_bytes: u64,
        max_batch_delay_ms: u64,
    ) -> Self {
        Self {
            batch_size: batch_size as usize,
            window_size: window_size as usize,
            max_pending_bytes: max_pending_bytes as usize,
            max_batch_delay_ms,
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Metrics
// ═══════════════════════════════════════════════════════════

/// Broadcaster metrics for observability.
#[derive(Debug, Clone, Default)]
pub struct BroadcasterMetrics {
    /// Total blocks enqueued for broadcast.
    pub blocks_enqueued: u64,
    /// Total batches sent (across all peers).
    pub batches_sent: u64,
    /// Total blocks sent (sum across all peers).
    pub blocks_sent: u64,
    /// Total bytes enqueued (block serialized sizes, approximate).
    pub bytes_enqueued: u64,
    /// Number of times back-pressure was triggered per peer.
    pub backpressure_activations: u64,
    /// Number of blocks dropped due to sustained back-pressure.
    pub blocks_dropped: u64,
    /// Total flush events (timer-triggered partial batch sends).
    pub timer_flushes: u64,
}

// ═══════════════════════════════════════════════════════════
//  Per-peer state
// ═══════════════════════════════════════════════════════════

/// Tracks broadcast state for a single peer.
#[derive(Debug)]
struct PeerState {
    /// Blocks waiting to be batched and sent.
    pending: Vec<VerifiedBlock>,
    /// Estimated bytes of blocks currently pending or in-flight.
    pending_bytes: usize,
    /// Number of batches currently in-flight (sent but not ack'd).
    in_flight_batches: usize,
}

impl PeerState {
    fn new() -> Self {
        Self {
            pending: Vec::new(),
            pending_bytes: 0,
            in_flight_batches: 0,
        }
    }

    fn estimated_block_bytes(block: &VerifiedBlock) -> usize {
        // Block overhead + signature + transactions
        // Signature is always 3,309 bytes for ML-DSA-65.
        // Transactions are variable but typically small.
        // We use signature.len() + 256 (fixed overhead) + tx bytes.
        let inner = block.inner();
        let tx_bytes: usize = inner.transactions.iter().map(|t| t.len()).sum();
        inner.signature.len() + 256 + tx_bytes
    }
}

// ═══════════════════════════════════════════════════════════
//  Broadcaster
// ═══════════════════════════════════════════════════════════

/// PQ-aware block broadcaster.
///
/// Accumulates proposed blocks and distributes them to peers in batches.
/// Back-pressure is applied per-peer when pending bytes exceed the
/// configured threshold.
///
/// # Usage
///
/// ```ignore
/// let mut bcast = Broadcaster::new(committee, our_authority, config);
/// bcast.enqueue(block);
///
/// // In a loop:
/// for (peer, batch) in bcast.take_ready_batches() {
///     network.send_blocks_to(peer, &batch).await;
///     bcast.on_batch_sent(peer, batch.len());
/// }
/// ```
pub struct Broadcaster {
    /// Our authority index (skip self in broadcast).
    our_authority: AuthorityIndex,
    /// Per-peer broadcast state.
    peers: HashMap<AuthorityIndex, PeerState>,
    /// Configuration.
    config: BroadcasterConfig,
    /// Metrics.
    metrics: BroadcasterMetrics,
}

impl Broadcaster {
    /// Create a new broadcaster for the given committee.
    pub fn new(
        committee: &Committee,
        our_authority: AuthorityIndex,
        config: BroadcasterConfig,
    ) -> Self {
        let mut peers = HashMap::new();
        for i in 0..committee.size() as u32 {
            if i != our_authority {
                peers.insert(i, PeerState::new());
            }
        }
        Self {
            our_authority,
            peers,
            config,
            metrics: BroadcasterMetrics::default(),
        }
    }

    /// Enqueue a block for broadcast to all peers.
    ///
    /// The block is added to each peer's pending queue. If a peer's
    /// pending bytes exceed `max_pending_bytes`, the block is dropped
    /// for that peer (logged, not panicked).
    pub fn enqueue(&mut self, block: VerifiedBlock) {
        let block_bytes = PeerState::estimated_block_bytes(&block);
        self.metrics.blocks_enqueued += 1;
        self.metrics.bytes_enqueued += block_bytes as u64;

        for (_peer_id, state) in &mut self.peers {
            if state.pending_bytes + block_bytes > self.config.max_pending_bytes {
                // Back-pressure: drop for this peer.
                self.metrics.backpressure_activations += 1;
                self.metrics.blocks_dropped += 1;
                continue;
            }
            state.pending.push(block.clone());
            state.pending_bytes += block_bytes;
        }
    }

    /// Check if any peer's pending bytes exceed the back-pressure threshold.
    pub fn is_saturated(&self) -> bool {
        self.peers
            .values()
            .any(|s| s.pending_bytes >= self.config.max_pending_bytes)
    }

    /// Take ready batches for all peers.
    ///
    /// A batch is ready when:
    /// - The peer has at least `batch_size` pending blocks, OR
    /// - `force_flush` is true (timer-triggered partial flush)
    ///
    /// Each peer is limited to `window_size` concurrent in-flight batches.
    pub fn take_ready_batches(
        &mut self,
        force_flush: bool,
    ) -> Vec<(AuthorityIndex, Vec<VerifiedBlock>)> {
        let mut result = Vec::new();

        for (&peer_id, state) in &mut self.peers {
            // Respect window limit.
            if state.in_flight_batches >= self.config.window_size {
                continue;
            }

            let ready = state.pending.len() >= self.config.batch_size
                || (force_flush && !state.pending.is_empty());

            if ready {
                let batch_end = state.pending.len().min(self.config.batch_size);
                let batch: Vec<VerifiedBlock> = state.pending.drain(..batch_end).collect();
                let batch_bytes: usize = batch
                    .iter()
                    .map(|b| PeerState::estimated_block_bytes(b))
                    .sum();
                state.pending_bytes = state.pending_bytes.saturating_sub(batch_bytes);
                state.in_flight_batches += 1;

                self.metrics.batches_sent += 1;
                self.metrics.blocks_sent += batch.len() as u64;

                if force_flush && batch.len() < self.config.batch_size {
                    self.metrics.timer_flushes += 1;
                }

                result.push((peer_id, batch));
            }
        }

        result
    }

    /// Notify that a batch to `peer` has been acknowledged.
    ///
    /// Decrements the in-flight count, allowing more batches.
    pub fn on_batch_ack(&mut self, peer: AuthorityIndex) {
        if let Some(state) = self.peers.get_mut(&peer) {
            state.in_flight_batches = state.in_flight_batches.saturating_sub(1);
        }
    }

    /// Get current metrics.
    pub fn metrics(&self) -> &BroadcasterMetrics {
        &self.metrics
    }

    /// Number of blocks pending across all peers.
    pub fn total_pending(&self) -> usize {
        self.peers.values().map(|s| s.pending.len()).sum()
    }

    /// Number of bytes pending across all peers.
    pub fn total_pending_bytes(&self) -> usize {
        self.peers.values().map(|s| s.pending_bytes).sum()
    }

    /// Pending blocks for a specific peer.
    pub fn peer_pending(&self, peer: AuthorityIndex) -> usize {
        self.peers.get(&peer).map(|s| s.pending.len()).unwrap_or(0)
    }
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::narwhal_types::block::{Block, BlockDigest, BlockRef};
    use crate::narwhal_types::committee::Committee;

    fn make_committee(n: usize) -> Committee {
        Committee::new_for_test(n)
    }

    fn make_block(round: u32, author: u32) -> VerifiedBlock {
        let block = Block {
            epoch: 0,
            round,
            author,
            timestamp_ms: 1000,
            ancestors: vec![],
            transactions: vec![vec![round as u8, author as u8]],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            // Simulate ML-DSA-65 signature size (3,309 bytes)
            signature: vec![0xAA; 3309],
        };
        VerifiedBlock::new_for_test(block)
    }

    // ── test: basic enqueue and batch ────────────────────

    #[test]
    fn test_enqueue_and_batch() {
        let committee = make_committee(4);
        let config = BroadcasterConfig {
            batch_size: 2,
            window_size: 3,
            max_pending_bytes: 64 * 1024 * 1024,
            max_batch_delay_ms: 50,
        };
        let mut bcast = Broadcaster::new(&committee, 0, config);

        // Enqueue 2 blocks (enough for one batch)
        bcast.enqueue(make_block(1, 0));
        bcast.enqueue(make_block(2, 0));

        assert_eq!(bcast.metrics().blocks_enqueued, 2);

        // Each peer should have 2 pending
        assert_eq!(bcast.peer_pending(1), 2);
        assert_eq!(bcast.peer_pending(2), 2);
        assert_eq!(bcast.peer_pending(3), 2);

        // Take batches (not force flush)
        let batches = bcast.take_ready_batches(false);
        assert_eq!(batches.len(), 3); // one batch per peer (3 peers)
        for (_, batch) in &batches {
            assert_eq!(batch.len(), 2);
        }

        // After take, pending should be 0
        assert_eq!(bcast.total_pending(), 0);
    }

    // ── test: force flush partial batch ──────────────────

    #[test]
    fn test_force_flush() {
        let committee = make_committee(4);
        let config = BroadcasterConfig {
            batch_size: 5, // high threshold
            window_size: 3,
            max_pending_bytes: 64 * 1024 * 1024,
            max_batch_delay_ms: 50,
        };
        let mut bcast = Broadcaster::new(&committee, 0, config);

        // Only 2 blocks — below batch_size
        bcast.enqueue(make_block(1, 0));
        bcast.enqueue(make_block(2, 0));

        // Without force_flush: no batches
        let batches = bcast.take_ready_batches(false);
        assert_eq!(batches.len(), 0);

        // With force_flush: partial batches
        let batches = bcast.take_ready_batches(true);
        assert_eq!(batches.len(), 3);
        for (_, batch) in &batches {
            assert_eq!(batch.len(), 2);
        }
        assert!(bcast.metrics().timer_flushes > 0);
    }

    // ── test: window limits in-flight ────────────────────

    #[test]
    fn test_window_limits() {
        let committee = make_committee(4);
        let config = BroadcasterConfig {
            batch_size: 1,
            window_size: 2, // max 2 in-flight per peer
            max_pending_bytes: 64 * 1024 * 1024,
            max_batch_delay_ms: 50,
        };
        let mut bcast = Broadcaster::new(&committee, 0, config);

        // Enqueue 5 blocks
        for i in 1..=5 {
            bcast.enqueue(make_block(i, 0));
        }

        // First take: each peer gets up to window_size (2) batches of 1
        let batches1 = bcast.take_ready_batches(false);
        // 3 peers × 1 batch = 3 (but window allows 2, and batch_size=1)
        // Actually each call can emit multiple batches per peer up to window
        // Let me re-check: take_ready_batches iterates once per peer
        // and emits ONE batch per peer per call (if ready).
        assert_eq!(batches1.len(), 3); // one per peer

        // Second take: window still has room (1 in-flight, window=2)
        let batches2 = bcast.take_ready_batches(false);
        assert_eq!(batches2.len(), 3); // one more per peer

        // Third take: window full (2 in-flight, window=2)
        let batches3 = bcast.take_ready_batches(false);
        assert_eq!(batches3.len(), 0); // blocked by window

        // Ack one batch per peer
        for &peer in &[1u32, 2, 3] {
            bcast.on_batch_ack(peer);
        }

        // Now one more batch should be possible
        let batches4 = bcast.take_ready_batches(false);
        assert_eq!(batches4.len(), 3);
    }

    // ── test: back-pressure drops blocks ─────────────────

    #[test]
    fn test_backpressure_drops() {
        let committee = make_committee(4);
        let config = BroadcasterConfig {
            batch_size: 100, // never auto-batch
            window_size: 10,
            max_pending_bytes: 10_000, // very small threshold
            max_batch_delay_ms: 50,
        };
        let mut bcast = Broadcaster::new(&committee, 0, config);

        // Each block is ~3,565 bytes (3309 sig + 256 overhead + tx)
        // 10,000 / 3565 ≈ 2.8, so 3rd block should trigger back-pressure
        bcast.enqueue(make_block(1, 0));
        bcast.enqueue(make_block(2, 0));
        bcast.enqueue(make_block(3, 0)); // should be dropped for some peers
        bcast.enqueue(make_block(4, 0)); // should be dropped

        assert!(bcast.metrics().backpressure_activations > 0);
        assert!(bcast.metrics().blocks_dropped > 0);
    }

    // ── test: self is excluded ───────────────────────────

    #[test]
    fn test_self_excluded() {
        let committee = make_committee(4);
        let bcast = Broadcaster::new(&committee, 0, BroadcasterConfig::default());

        // Authority 0 should not be in peers
        assert_eq!(bcast.peer_pending(0), 0);
        assert_eq!(bcast.peers.len(), 3); // 4 nodes - self = 3
    }

    // ── test: PQ signature size impact ───────────────────

    #[test]
    fn test_pq_byte_accounting() {
        let committee = make_committee(4);
        let config = BroadcasterConfig::default();
        let mut bcast = Broadcaster::new(&committee, 0, config);

        let block = make_block(1, 0);
        let estimated = PeerState::estimated_block_bytes(&block);

        // ML-DSA-65 sig (3309) + overhead (256) + tx (2 bytes)
        assert_eq!(estimated, 3309 + 256 + 2);

        bcast.enqueue(block);

        // 3 peers × (3309 + 256 + 2) = 3 × 3567 = 10701
        assert_eq!(bcast.total_pending_bytes(), 3 * (3309 + 256 + 2));
        assert_eq!(bcast.metrics().bytes_enqueued, 3567);
    }
}
