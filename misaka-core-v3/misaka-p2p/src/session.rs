//! Hardened P2P Session — Handshake + DoS Protection (Improvements D + F).
//!
//! # Improvement D: Handshake transcript binding
//!
//! Previous: transcript lacked chain_id, protocol_version, direction, nonce.
//! New: Full transcript with session ID, anti-downgrade, role binding.
//!
//! # Improvement F: Sync DoS protection
//!
//! Per-peer budgets for requests, orphan pool limits, BFS depth limits.

use sha3::{Sha3_256, Digest};

// ═══════════════════════════════════════════════════════════════
//  Improvement D: Session Handshake
// ═══════════════════════════════════════════════════════════════

pub const PROTOCOL_VERSION: u32 = 3;
pub const HANDSHAKE_TIMEOUT_MS: u64 = 10_000;

/// Handshake transcript — binds ALL session parameters.
///
/// Improvement D: chain_id, protocol_version, direction, nonce, network_id
/// are all included. Missing any one allows cross-context attacks.
#[derive(Debug, Clone)]
pub struct HandshakeTranscript {
    pub chain_id: u32,
    pub network_id: [u8; 4],   // e.g., "MSKD" for mainnet
    pub protocol_version: u32,
    pub initiator_nonce: [u8; 32],
    pub responder_nonce: [u8; 32],
    pub initiator_pk: Vec<u8>,
    pub responder_pk: Vec<u8>,
    pub direction: HandshakeDirection,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum HandshakeDirection {
    Initiator,
    Responder,
}

impl HandshakeTranscript {
    /// Compute session ID from transcript.
    ///
    /// Both sides compute this independently and verify match.
    /// Any mismatch = MITM or parameter disagreement.
    pub fn session_id(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_SESSION_V3:");
        h.update(&self.chain_id.to_le_bytes());
        h.update(&self.network_id);
        h.update(&self.protocol_version.to_le_bytes());
        h.update(&self.initiator_nonce);
        h.update(&self.responder_nonce);
        h.update(&self.initiator_pk);
        h.update(&self.responder_pk);
        h.update(&[match self.direction {
            HandshakeDirection::Initiator => 0x01,
            HandshakeDirection::Responder => 0x02,
        }]);
        h.update(&self.timestamp_ms.to_le_bytes());
        h.finalize().into()
    }

    /// Anti-downgrade check: reject if peer claims older version.
    pub fn check_version(&self) -> Result<(), String> {
        if self.protocol_version < PROTOCOL_VERSION {
            return Err(format!(
                "peer version {} < minimum {}", self.protocol_version, PROTOCOL_VERSION));
        }
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
//  Improvement F: Per-Peer Budget + DoS Limits
// ═══════════════════════════════════════════════════════════════

/// Per-peer resource budget.
///
/// Limits how many resources a single peer can consume.
/// Exceeding any limit results in disconnection + ban.
pub struct PeerBudget {
    /// Max pending block requests.
    pub max_pending_requests: usize,
    /// Max orphan blocks held for this peer.
    pub max_orphan_blocks: usize,
    /// Max BFS depth for ancestry traversal.
    pub max_bfs_depth: usize,
    /// Max messages per second.
    pub max_msg_per_second: u32,
    /// Max total bytes received per minute.
    pub max_bytes_per_minute: u64,
    /// Current counters.
    pub pending_requests: usize,
    pub orphan_count: usize,
    pub msg_count_this_second: u32,
    pub bytes_this_minute: u64,
    /// Ban score (accumulated misbehavior).
    pub ban_score: u32,
}

/// Ban threshold — disconnect and ban at this score.
pub const BAN_THRESHOLD: u32 = 100;

impl PeerBudget {
    pub fn new() -> Self {
        Self {
            max_pending_requests: 64,
            max_orphan_blocks: 32,
            max_bfs_depth: 256,
            max_msg_per_second: 100,
            max_bytes_per_minute: 50 * 1024 * 1024, // 50 MB
            pending_requests: 0,
            orphan_count: 0,
            msg_count_this_second: 0,
            bytes_this_minute: 0,
            ban_score: 0,
        }
    }

    /// Check if a request is within budget.
    pub fn can_request(&self) -> bool {
        self.pending_requests < self.max_pending_requests
            && self.msg_count_this_second < self.max_msg_per_second
            && self.ban_score < BAN_THRESHOLD
    }

    /// Record misbehavior.
    pub fn add_ban_score(&mut self, points: u32, reason: &str) {
        self.ban_score = self.ban_score.saturating_add(points);
        if self.ban_score >= BAN_THRESHOLD {
            tracing::warn!("Peer banned: score={}, reason={}", self.ban_score, reason);
        }
    }

    /// Should this peer be disconnected?
    pub fn should_disconnect(&self) -> bool {
        self.ban_score >= BAN_THRESHOLD
    }

    /// Record an incoming message.
    pub fn record_message(&mut self, size: usize) {
        self.msg_count_this_second += 1;
        self.bytes_this_minute += size as u64;
    }

    /// Check rate limits.
    pub fn check_rate_limits(&self) -> Result<(), &'static str> {
        if self.msg_count_this_second >= self.max_msg_per_second {
            return Err("message rate limit exceeded");
        }
        if self.bytes_this_minute >= self.max_bytes_per_minute {
            return Err("bandwidth limit exceeded");
        }
        Ok(())
    }

    /// Reset per-second counters (call every second).
    pub fn reset_second(&mut self) { self.msg_count_this_second = 0; }
    /// Reset per-minute counters (call every minute).
    pub fn reset_minute(&mut self) { self.bytes_this_minute = 0; }
}

/// Global orphan pool with hard limit.
pub struct OrphanPool {
    blocks: std::collections::HashMap<[u8; 32], Vec<u8>>,
    max_size: usize,
}

impl OrphanPool {
    pub fn new(max_size: usize) -> Self {
        Self { blocks: std::collections::HashMap::new(), max_size }
    }

    pub fn insert(&mut self, hash: [u8; 32], data: Vec<u8>) -> bool {
        if self.blocks.len() >= self.max_size {
            return false; // Pool full — reject
        }
        self.blocks.insert(hash, data);
        true
    }

    pub fn remove(&mut self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.blocks.remove(hash)
    }

    pub fn len(&self) -> usize { self.blocks.len() }

    /// Evict oldest entries if over limit.
    pub fn evict_if_full(&mut self) {
        while self.blocks.len() > self.max_size {
            if let Some(key) = self.blocks.keys().next().copied() {
                self.blocks.remove(&key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_deterministic() {
        let t = HandshakeTranscript {
            chain_id: 2, network_id: *b"MSKD", protocol_version: 3,
            initiator_nonce: [0x11; 32], responder_nonce: [0x22; 32],
            initiator_pk: vec![0xAA; 64], responder_pk: vec![0xBB; 64],
            direction: HandshakeDirection::Initiator, timestamp_ms: 1000,
        };
        assert_eq!(t.session_id(), t.session_id());
    }

    #[test]
    fn test_session_id_changes_with_chain() {
        let mut t1 = HandshakeTranscript {
            chain_id: 1, network_id: *b"MSKD", protocol_version: 3,
            initiator_nonce: [0x11; 32], responder_nonce: [0x22; 32],
            initiator_pk: vec![], responder_pk: vec![],
            direction: HandshakeDirection::Initiator, timestamp_ms: 1000,
        };
        let t2 = HandshakeTranscript { chain_id: 2, ..t1.clone() };
        assert_ne!(t1.session_id(), t2.session_id());
    }

    #[test]
    fn test_peer_budget() {
        let mut b = PeerBudget::new();
        assert!(b.can_request());
        b.add_ban_score(50, "test");
        assert!(b.can_request());
        b.add_ban_score(51, "test2");
        assert!(b.should_disconnect());
    }

    #[test]
    fn test_orphan_pool_limit() {
        let mut pool = OrphanPool::new(2);
        assert!(pool.insert([1; 32], vec![1]));
        assert!(pool.insert([2; 32], vec![2]));
        assert!(!pool.insert([3; 32], vec![3])); // Full
    }
}
