// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Admission Control — per-peer rate limiting for DAG consensus RPCs.
//!
//! Sui equivalent: Part of `consensus/core/src/network/anemo_network.rs` +
//! internal rate limiting in `Core::add_blocks`.
//!
//! Prevents a single peer from overwhelming the consensus engine with
//! block submissions, fetch requests, or vote gossip.
//!
//! Uses a token bucket algorithm per peer. Peers exceeding their quota
//! are temporarily throttled (429 equivalent).
//!
//! # Integration
//!
//! Called by `anemo_network.rs` handlers before forwarding to CoreEngine:
//! ```ignore
//! if !admission.try_consume(peer_id, RequestKind::SendBlock) {
//!     return Err(AdmissionDenied);
//! }
//! engine.process_block(block);
//! ```

use std::collections::HashMap;
use std::time::Instant;

use crate::narwhal_types::block::AuthorityIndex;

/// Kind of request for differentiated rate limiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestKind {
    /// Incoming block submission.
    SendBlock,
    /// Fetch blocks request (by reference).
    FetchBlocks,
    /// Fetch commits request.
    FetchCommits,
    /// Commit vote gossip.
    CommitVote,
}

impl RequestKind {
    /// Default cost per request kind (tokens consumed).
    pub fn default_cost(&self) -> f64 {
        match self {
            Self::SendBlock => 1.0,
            Self::FetchBlocks => 2.0, // heavier — involves I/O
            Self::FetchCommits => 2.0,
            Self::CommitVote => 0.5, // lightweight
        }
    }
}

/// Per-peer token bucket state.
#[derive(Debug)]
struct PeerBucket {
    tokens: f64,
    last_refill: Instant,
}

impl PeerBucket {
    fn new(burst: f64) -> Self {
        Self {
            tokens: burst,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self, rate: f64, burst: f64) {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        self.tokens = (self.tokens + elapsed * rate).min(burst);
        self.last_refill = Instant::now();
    }

    fn try_consume(&mut self, cost: f64) -> bool {
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

/// Admission controller configuration.
#[derive(Debug, Clone)]
pub struct AdmissionConfig {
    /// Tokens refilled per second per peer.
    pub refill_rate_per_sec: f64,
    /// Maximum burst capacity per peer.
    pub burst_capacity: f64,
    /// Maximum number of tracked peers (LRU eviction beyond this).
    pub max_tracked_peers: usize,
    /// Penalty multiplier for peers with bad scores.
    /// Applied to refill_rate: effective_rate = refill_rate * penalty_factor.
    pub slow_peer_penalty_factor: f64,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            refill_rate_per_sec: 50.0, // 50 requests/sec steady state
            burst_capacity: 200.0,     // can burst to 200
            max_tracked_peers: 1000,
            slow_peer_penalty_factor: 0.25, // slow peers get 25% rate
        }
    }
}

/// Result of an admission check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionResult {
    /// Request admitted.
    Admitted,
    /// Request denied — peer has exhausted their quota.
    Denied {
        peer: AuthorityIndex,
        tokens_remaining: i64,
    },
}

/// Per-peer admission controller with token bucket rate limiting.
pub struct AdmissionController {
    config: AdmissionConfig,
    buckets: HashMap<AuthorityIndex, PeerBucket>,
    /// Peers with reduced rate (slow/misbehaving).
    penalized_peers: HashMap<AuthorityIndex, f64>,
    /// Statistics.
    total_admitted: u64,
    total_denied: u64,
}

impl AdmissionController {
    pub fn new(config: AdmissionConfig) -> Self {
        Self {
            config,
            buckets: HashMap::new(),
            penalized_peers: HashMap::new(),
            total_admitted: 0,
            total_denied: 0,
        }
    }

    /// Try to consume tokens for a request from `peer`.
    ///
    /// Returns `Admitted` if the peer has sufficient tokens,
    /// `Denied` otherwise (peer should back off).
    pub fn try_consume(&mut self, peer: AuthorityIndex, kind: RequestKind) -> AdmissionResult {
        let cost = kind.default_cost();
        let rate = self.effective_rate(peer);
        let burst = self.config.burst_capacity;

        let bucket = self
            .buckets
            .entry(peer)
            .or_insert_with(|| PeerBucket::new(burst));
        bucket.refill(rate, burst);

        if bucket.try_consume(cost) {
            self.total_admitted += 1;
            AdmissionResult::Admitted
        } else {
            self.total_denied += 1;
            AdmissionResult::Denied {
                peer,
                tokens_remaining: bucket.tokens as i64,
            }
        }
    }

    /// Get the effective refill rate for a peer (considering penalties).
    fn effective_rate(&self, peer: AuthorityIndex) -> f64 {
        let base = self.config.refill_rate_per_sec;
        match self.penalized_peers.get(&peer) {
            Some(&factor) => base * factor,
            None => base,
        }
    }

    /// Apply a penalty to a peer (reduce their rate).
    ///
    /// `factor` is a multiplier (0.0 = blocked, 1.0 = normal).
    /// Called by PeerScorer when score drops.
    pub fn penalize_peer(&mut self, peer: AuthorityIndex, factor: f64) {
        let clamped = factor.clamp(0.0, 1.0);
        self.penalized_peers.insert(peer, clamped);
    }

    /// Remove penalty for a peer (restore normal rate).
    pub fn restore_peer(&mut self, peer: AuthorityIndex) {
        self.penalized_peers.remove(&peer);
    }

    /// GC: remove peers that haven't been seen recently.
    pub fn gc(&mut self) {
        if self.buckets.len() <= self.config.max_tracked_peers {
            return;
        }
        // Remove oldest peers (by last_refill time)
        let mut peers: Vec<(AuthorityIndex, Instant)> = self
            .buckets
            .iter()
            .map(|(&p, b)| (p, b.last_refill))
            .collect();
        peers.sort_by_key(|&(_, t)| t);
        let to_remove = self.buckets.len() - self.config.max_tracked_peers;
        for (peer, _) in peers.into_iter().take(to_remove) {
            self.buckets.remove(&peer);
            self.penalized_peers.remove(&peer);
        }
    }

    /// Statistics.
    pub fn stats(&self) -> AdmissionStats {
        AdmissionStats {
            tracked_peers: self.buckets.len(),
            penalized_peers: self.penalized_peers.len(),
            total_admitted: self.total_admitted,
            total_denied: self.total_denied,
        }
    }
}

/// Admission controller statistics.
#[derive(Debug, Clone, Default)]
pub struct AdmissionStats {
    pub tracked_peers: usize,
    pub penalized_peers: usize,
    pub total_admitted: u64,
    pub total_denied: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_controller() -> AdmissionController {
        AdmissionController::new(AdmissionConfig {
            refill_rate_per_sec: 10.0,
            burst_capacity: 5.0,
            max_tracked_peers: 100,
            slow_peer_penalty_factor: 0.25,
        })
    }

    #[test]
    fn test_burst_and_exhaust() {
        let mut ac = default_controller();

        // Burst: 5 tokens → 5 SendBlock requests succeed
        for _ in 0..5 {
            assert_eq!(
                ac.try_consume(0, RequestKind::SendBlock),
                AdmissionResult::Admitted
            );
        }

        // 6th request denied (burst exhausted, no time for refill)
        assert!(matches!(
            ac.try_consume(0, RequestKind::SendBlock),
            AdmissionResult::Denied { .. }
        ));
    }

    #[test]
    fn test_different_peers_independent() {
        let mut ac = default_controller();

        // Exhaust peer 0
        for _ in 0..5 {
            ac.try_consume(0, RequestKind::SendBlock);
        }
        assert!(matches!(
            ac.try_consume(0, RequestKind::SendBlock),
            AdmissionResult::Denied { .. }
        ));

        // Peer 1 still has tokens
        assert_eq!(
            ac.try_consume(1, RequestKind::SendBlock),
            AdmissionResult::Admitted
        );
    }

    #[test]
    fn test_penalty_reduces_rate() {
        let mut ac = default_controller();

        // Penalize peer 0 to 0% → effectively blocked after burst
        ac.penalize_peer(0, 0.0);

        // Burst still works (tokens pre-filled)
        for _ in 0..5 {
            ac.try_consume(0, RequestKind::SendBlock);
        }
        // After exhaustion, refill rate = 0 → permanently denied
        assert!(matches!(
            ac.try_consume(0, RequestKind::SendBlock),
            AdmissionResult::Denied { .. }
        ));
    }

    #[test]
    fn test_restore_penalty() {
        let mut ac = default_controller();
        ac.penalize_peer(0, 0.0);
        ac.restore_peer(0);
        // Should use default rate now
        assert_eq!(
            ac.try_consume(0, RequestKind::SendBlock),
            AdmissionResult::Admitted
        );
    }

    #[test]
    fn test_request_kind_costs() {
        let mut ac = AdmissionController::new(AdmissionConfig {
            burst_capacity: 3.0,
            refill_rate_per_sec: 0.0, // no refill
            ..Default::default()
        });

        // FetchBlocks costs 2.0 → only 1 request fits in burst of 3
        assert_eq!(
            ac.try_consume(0, RequestKind::FetchBlocks),
            AdmissionResult::Admitted
        );
        // 1.0 tokens left → FetchBlocks (2.0) denied
        assert!(matches!(
            ac.try_consume(0, RequestKind::FetchBlocks),
            AdmissionResult::Denied { .. }
        ));
        // CommitVote (0.5) still fits
        assert_eq!(
            ac.try_consume(0, RequestKind::CommitVote),
            AdmissionResult::Admitted
        );
    }

    #[test]
    fn test_stats() {
        let mut ac = default_controller();
        ac.try_consume(0, RequestKind::SendBlock);
        ac.try_consume(1, RequestKind::SendBlock);
        let s = ac.stats();
        assert_eq!(s.tracked_peers, 2);
        assert_eq!(s.total_admitted, 2);
        assert_eq!(s.total_denied, 0);
    }

    #[test]
    fn test_gc_limits_peers() {
        let mut ac = AdmissionController::new(AdmissionConfig {
            max_tracked_peers: 3,
            ..Default::default()
        });

        for i in 0..10 {
            ac.try_consume(i, RequestKind::SendBlock);
        }
        assert_eq!(ac.buckets.len(), 10);

        ac.gc();
        assert!(ac.buckets.len() <= 3);
    }
}
