//! # Peer Scoring — Multi-Dimensional Reputation with Decay
//!
//! Scoring drives: dial candidate selection, connection eviction, relay priority, ban decisions.
//!
//! # Score Dimensions
//!
//! | Dimension     | What it measures                     | Range   |
//! |--------------|--------------------------------------|---------|
//! | transport    | Handshake success, TLS quality       | [-100, 100] |
//! | protocol     | Valid messages, spec compliance       | [-100, 100] |
//! | liveness     | Uptime, ping response, staleness     | [-100, 100] |
//! | usefulness   | Good blocks, valid gossip, IBD help  | [-100, 100] |
//! | penalty      | Accumulated violations (never >0)    | [-1000, 0]  |
//!
//! Total = transport + protocol + liveness + usefulness + penalty
//!
//! # Decay
//!
//! Every `DECAY_INTERVAL_SECS`, scores decay toward 0 by `DECAY_RATE`.
//! This prevents ancient good/bad behavior from dominating indefinitely.
//!
//! # Thresholds
//!
//! | Total Score | Action                          |
//! |-----------|--------------------------------------|
//! | ≥ 50      | Preferred dial candidate            |
//! | 0..50     | Normal peer                          |
//! | -50..0    | Deprioritized                        |
//! | -100..-50 | Temporary ban (TEMP_BAN_SECS)        |
//! | ≤ -100    | Permanent ban                        |

use serde::Serialize;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::peer_id::PeerId;

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

/// Score decay interval.
pub const DECAY_INTERVAL_SECS: u64 = 60;
/// Score decay rate (absolute points per interval).
pub const DECAY_RATE: i32 = 1;
/// Temporary ban duration.
pub const TEMP_BAN_SECS: u64 = 600; // 10 minutes
/// Threshold for temporary ban.
pub const TEMP_BAN_THRESHOLD: i32 = -50;
/// Threshold for permanent ban.
pub const PERM_BAN_THRESHOLD: i32 = -100;
/// Threshold for preferred dial candidate.
pub const PREFERRED_THRESHOLD: i32 = 50;
/// Maximum peers from same /24 subnet.
pub const MAX_PEERS_PER_SUBNET: usize = 3;

// ═══════════════════════════════════════════════════════════════
//  Score Structure
// ═══════════════════════════════════════════════════════════════

/// Multi-dimensional peer score.
#[derive(Debug, Clone, Serialize)]
pub struct PeerScore {
    pub transport_score: i32,
    pub protocol_score: i32,
    pub liveness_score: i32,
    pub usefulness_score: i32,
    pub penalty_score: i32,
    #[serde(skip_serializing)]
    last_decay: Instant,
}

impl PeerScore {
    pub fn new() -> Self {
        Self {
            transport_score: 0,
            protocol_score: 0,
            liveness_score: 0,
            usefulness_score: 0,
            penalty_score: 0,
            last_decay: Instant::now(),
        }
    }

    pub fn total(&self) -> i32 {
        self.transport_score
            + self.protocol_score
            + self.liveness_score
            + self.usefulness_score
            + self.penalty_score
    }

    /// Apply time-based decay toward 0.
    pub fn decay(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_decay) < Duration::from_secs(DECAY_INTERVAL_SECS) {
            return;
        }
        self.last_decay = now;

        fn decay_toward_zero(v: &mut i32, rate: i32) {
            if *v > 0 {
                *v = (*v - rate).max(0);
            } else if *v < 0 {
                *v = (*v + rate).min(0);
            }
        }

        decay_toward_zero(&mut self.transport_score, DECAY_RATE);
        decay_toward_zero(&mut self.protocol_score, DECAY_RATE);
        decay_toward_zero(&mut self.liveness_score, DECAY_RATE);
        decay_toward_zero(&mut self.usefulness_score, DECAY_RATE);
        // Penalty decays slower
        decay_toward_zero(&mut self.penalty_score, DECAY_RATE / 2 + 1);
    }

    /// Whether this peer should be temporarily banned.
    pub fn should_temp_ban(&self) -> bool {
        self.total() <= TEMP_BAN_THRESHOLD
    }

    /// Whether this peer should be permanently banned.
    pub fn should_perm_ban(&self) -> bool {
        self.total() <= PERM_BAN_THRESHOLD
    }

    /// Whether this peer is a preferred dial candidate.
    pub fn is_preferred(&self) -> bool {
        self.total() >= PREFERRED_THRESHOLD
    }
}

// ═══════════════════════════════════════════════════════════════
//  Scoring Events
// ═══════════════════════════════════════════════════════════════

/// Events that update a peer's score.
#[derive(Debug, Clone)]
pub enum ScoreEvent {
    // ── Positive events ──
    ValidHandshake,
    ValidBlock,
    ValidVote,
    ValidPeerRecord,
    UsefulGossip,
    SuccessfulRelay,
    PingSuccess,

    // ── Negative events ──
    InvalidPqSignature,
    MalformedFrame,
    StalePeerRecord,
    DuplicateAddressSpam,
    HandshakeTimeout,
    DialFailure,
    InvalidBlockRelay,
    ProtocolViolation,
    RateLimitExceed,
    ExcessiveOrphanSpam,
    EquivocationEvidence,
    NullGossipFlood,
    EclipseClusteringDetected,
}

impl ScoreEvent {
    /// Apply this event to a peer score.
    pub fn apply(&self, score: &mut PeerScore) {
        match self {
            // Positive
            Self::ValidHandshake => score.transport_score = (score.transport_score + 10).min(100),
            Self::ValidBlock => score.usefulness_score = (score.usefulness_score + 5).min(100),
            Self::ValidVote => score.usefulness_score = (score.usefulness_score + 3).min(100),
            Self::ValidPeerRecord => score.protocol_score = (score.protocol_score + 2).min(100),
            Self::UsefulGossip => score.usefulness_score = (score.usefulness_score + 1).min(100),
            Self::SuccessfulRelay => score.usefulness_score = (score.usefulness_score + 2).min(100),
            Self::PingSuccess => score.liveness_score = (score.liveness_score + 1).min(100),

            // Negative
            Self::InvalidPqSignature => score.penalty_score = (score.penalty_score - 50).max(-1000),
            Self::MalformedFrame => score.penalty_score = (score.penalty_score - 20).max(-1000),
            Self::StalePeerRecord => score.protocol_score = (score.protocol_score - 5).max(-100),
            Self::DuplicateAddressSpam => {
                score.penalty_score = (score.penalty_score - 10).max(-1000)
            }
            Self::HandshakeTimeout => {
                score.transport_score = (score.transport_score - 10).max(-100)
            }
            Self::DialFailure => score.transport_score = (score.transport_score - 5).max(-100),
            Self::InvalidBlockRelay => score.penalty_score = (score.penalty_score - 30).max(-1000),
            Self::ProtocolViolation => score.penalty_score = (score.penalty_score - 25).max(-1000),
            Self::RateLimitExceed => score.penalty_score = (score.penalty_score - 10).max(-1000),
            Self::ExcessiveOrphanSpam => {
                score.penalty_score = (score.penalty_score - 15).max(-1000)
            }
            Self::EquivocationEvidence => {
                score.penalty_score = (score.penalty_score - 100).max(-1000)
            }
            Self::NullGossipFlood => score.penalty_score = (score.penalty_score - 10).max(-1000),
            Self::EclipseClusteringDetected => {
                score.penalty_score = (score.penalty_score - 30).max(-1000)
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Score Manager
// ═══════════════════════════════════════════════════════════════

/// Manages scores for all known peers.
///
/// Integrates with the connection manager:
/// - `select_dial_candidates()` → sorted by score
/// - `should_disconnect()` → ban threshold check
/// - `record_event()` → score update + automatic ban
pub struct ScoreManager {
    scores: HashMap<PeerId, PeerScore>,
    /// Temporarily banned peers (PeerId → ban_expires_at).
    temp_bans: HashMap<PeerId, Instant>,
    /// Permanently banned peers.
    perm_bans: std::collections::HashSet<PeerId>,
}

impl ScoreManager {
    pub fn new() -> Self {
        Self {
            scores: HashMap::new(),
            temp_bans: HashMap::new(),
            perm_bans: std::collections::HashSet::new(),
        }
    }

    /// Record a scoring event for a peer.
    ///
    /// Returns `true` if the peer was banned as a result.
    pub fn record_event(&mut self, peer: PeerId, event: ScoreEvent) -> bool {
        let score = self.scores.entry(peer).or_insert_with(PeerScore::new);
        event.apply(score);

        if score.should_perm_ban() {
            self.perm_bans.insert(peer);
            return true;
        }
        if score.should_temp_ban() {
            self.temp_bans
                .insert(peer, Instant::now() + Duration::from_secs(TEMP_BAN_SECS));
            return true;
        }
        false
    }

    /// Check if a peer is currently banned.
    pub fn is_banned(&self, peer: &PeerId) -> bool {
        if self.perm_bans.contains(peer) {
            return true;
        }
        if let Some(expires) = self.temp_bans.get(peer) {
            if Instant::now() < *expires {
                return true;
            }
        }
        false
    }

    /// Get score for a peer.
    pub fn get_score(&self, peer: &PeerId) -> Option<&PeerScore> {
        self.scores.get(peer)
    }

    /// Get total score for a peer (0 if unknown).
    pub fn total_score(&self, peer: &PeerId) -> i32 {
        self.scores.get(peer).map(|s| s.total()).unwrap_or(0)
    }

    /// Select best dial candidates (sorted by score, descending).
    pub fn select_dial_candidates(&self, candidates: &[PeerId], limit: usize) -> Vec<PeerId> {
        let mut scored: Vec<(PeerId, i32)> = candidates
            .iter()
            .filter(|p| !self.is_banned(p))
            .map(|p| (*p, self.total_score(p)))
            .collect();
        scored.sort_by(|a, b| b.1.cmp(&a.1)); // highest score first
        scored.into_iter().take(limit).map(|(p, _)| p).collect()
    }

    /// SEC-H2: Select dial candidates with subnet diversity enforcement.
    ///
    /// Limits the number of peers from the same /24 subnet to prevent
    /// eclipse attacks. `peer_addrs` maps PeerId → IP address for subnet
    /// extraction. Peers without a known address are still eligible (up to limit).
    ///
    /// # Eclipse Attack Mitigation
    ///
    /// An attacker controlling a /24 block can only occupy `MAX_PEERS_PER_SUBNET`
    /// slots in the dial list. This forces honest peers from diverse subnets into
    /// the remaining slots, making it infeasible to monopolize a node's connections.
    pub fn select_dial_candidates_subnet_aware(
        &self,
        candidates: &[PeerId],
        peer_addrs: &HashMap<PeerId, std::net::IpAddr>,
        limit: usize,
    ) -> Vec<PeerId> {
        use crate::subnet::SubnetId;

        let mut scored: Vec<(PeerId, i32)> = candidates
            .iter()
            .filter(|p| !self.is_banned(p))
            .map(|p| (*p, self.total_score(p)))
            .collect();
        scored.sort_by(|a, b| b.1.cmp(&a.1));

        let mut result = Vec::with_capacity(limit);
        let mut subnet_counts: HashMap<SubnetId, usize> = HashMap::new();

        for (peer, _score) in scored {
            if result.len() >= limit {
                break;
            }
            if let Some(ip) = peer_addrs.get(&peer) {
                let subnet = SubnetId::from_ip(ip);
                let count = subnet_counts.entry(subnet).or_insert(0);
                if *count >= MAX_PEERS_PER_SUBNET {
                    continue; // Skip — this subnet is saturated
                }
                *count += 1;
            }
            // Peers without known IP pass through (can't enforce subnet)
            result.push(peer);
        }
        result
    }

    /// Run periodic maintenance (decay + temp ban expiry).
    pub fn tick(&mut self) {
        for score in self.scores.values_mut() {
            score.decay();
        }
        let now = Instant::now();
        self.temp_bans.retain(|_, expires| now < *expires);
    }

    /// Number of known peers.
    pub fn peer_count(&self) -> usize {
        self.scores.len()
    }

    /// Number of banned peers.
    pub fn banned_count(&self) -> usize {
        let temp = self
            .temp_bans
            .values()
            .filter(|e| Instant::now() < **e)
            .count();
        self.perm_bans.len() + temp
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(b: u8) -> PeerId {
        PeerId([b; 32])
    }

    #[test]
    fn test_score_positive_events() {
        let mut score = PeerScore::new();
        ScoreEvent::ValidHandshake.apply(&mut score);
        ScoreEvent::ValidBlock.apply(&mut score);
        assert!(score.total() > 0);
    }

    #[test]
    fn test_score_negative_leads_to_ban() {
        let mut mgr = ScoreManager::new();
        let peer = pid(1);

        // Two invalid PQ signatures → penalty = -100 → perm ban
        mgr.record_event(peer, ScoreEvent::InvalidPqSignature);
        assert!(!mgr.is_banned(&peer)); // -50, not yet banned
        let banned = mgr.record_event(peer, ScoreEvent::InvalidPqSignature);
        assert!(banned);
        assert!(mgr.is_banned(&peer)); // -100 → perm ban
    }

    #[test]
    fn test_score_decay() {
        let mut score = PeerScore::new();
        score.transport_score = 50;
        score.penalty_score = -50;
        score.last_decay = Instant::now() - Duration::from_secs(DECAY_INTERVAL_SECS + 1);
        score.decay();
        assert_eq!(score.transport_score, 50 - DECAY_RATE);
        assert_eq!(score.penalty_score, -50 + (DECAY_RATE / 2 + 1));
    }

    #[test]
    fn test_select_dial_candidates_sorted_by_score() {
        let mut mgr = ScoreManager::new();
        let a = pid(1);
        let b = pid(2);
        let c = pid(3);

        mgr.record_event(a, ScoreEvent::ValidBlock); // +5
        mgr.record_event(b, ScoreEvent::ValidHandshake); // +10
        mgr.record_event(c, ScoreEvent::DialFailure); // -5

        let candidates = mgr.select_dial_candidates(&[a, b, c], 3);
        assert_eq!(candidates[0], b); // highest score first
        assert_eq!(candidates[1], a);
        assert_eq!(candidates[2], c);
    }

    #[test]
    fn test_banned_peer_excluded_from_candidates() {
        let mut mgr = ScoreManager::new();
        let a = pid(1);
        mgr.record_event(a, ScoreEvent::EquivocationEvidence); // -100 → perm ban
        let candidates = mgr.select_dial_candidates(&[a], 1);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_temp_ban_expires() {
        let mut mgr = ScoreManager::new();
        let peer = pid(1);
        // Manually set temp ban in the past
        mgr.temp_bans
            .insert(peer, Instant::now() - Duration::from_secs(1));
        assert!(!mgr.is_banned(&peer)); // expired
    }

    #[test]
    fn test_subnet_diversity_limits_same_slash24() {
        let mut mgr = ScoreManager::new();
        // 5 peers in the same /24 (192.168.1.x)
        let peers: Vec<PeerId> = (1..=5).map(|b| pid(b)).collect();
        let mut addrs = HashMap::new();
        for (i, p) in peers.iter().enumerate() {
            mgr.record_event(*p, ScoreEvent::ValidBlock);
            let ip: std::net::IpAddr = format!("192.168.1.{}", i + 10).parse().unwrap();
            addrs.insert(*p, ip);
        }

        // With subnet awareness: only MAX_PEERS_PER_SUBNET (3) should be selected
        let selected = mgr.select_dial_candidates_subnet_aware(&peers, &addrs, 5);
        assert_eq!(
            selected.len(),
            MAX_PEERS_PER_SUBNET,
            "should cap at {} per /24 subnet",
            MAX_PEERS_PER_SUBNET,
        );
    }

    #[test]
    fn test_subnet_diversity_different_subnets_pass() {
        let mut mgr = ScoreManager::new();
        let peers: Vec<PeerId> = (1..=5).map(|b| pid(b)).collect();
        let mut addrs = HashMap::new();
        for (i, p) in peers.iter().enumerate() {
            mgr.record_event(*p, ScoreEvent::ValidBlock);
            // Each in a DIFFERENT /24
            let ip: std::net::IpAddr = format!("10.{}.1.1", i + 1).parse().unwrap();
            addrs.insert(*p, ip);
        }

        let selected = mgr.select_dial_candidates_subnet_aware(&peers, &addrs, 5);
        assert_eq!(selected.len(), 5, "all peers from different subnets should pass");
    }

    #[test]
    fn test_subnet_diversity_ipv6_same_slash48_capped() {
        let mut mgr = ScoreManager::new();
        // 5 peers in the same /48 (2001:db8:1::/48)
        let peers: Vec<PeerId> = (1..=5).map(|b| pid(b)).collect();
        let mut addrs = HashMap::new();
        for (i, p) in peers.iter().enumerate() {
            mgr.record_event(*p, ScoreEvent::ValidBlock);
            // Same /48, different /64 subnets
            let ip: std::net::IpAddr = format!("2001:db8:1:{:x}::1", i + 1).parse().unwrap();
            addrs.insert(*p, ip);
        }

        let selected = mgr.select_dial_candidates_subnet_aware(&peers, &addrs, 5);
        assert_eq!(
            selected.len(),
            MAX_PEERS_PER_SUBNET,
            "should cap at {} per /48 subnet for IPv6",
            MAX_PEERS_PER_SUBNET,
        );
    }

    #[test]
    fn test_subnet_diversity_ipv6_different_slash48_pass() {
        let mut mgr = ScoreManager::new();
        let peers: Vec<PeerId> = (1..=5).map(|b| pid(b)).collect();
        let mut addrs = HashMap::new();
        for (i, p) in peers.iter().enumerate() {
            mgr.record_event(*p, ScoreEvent::ValidBlock);
            // Each in a DIFFERENT /48
            let ip: std::net::IpAddr = format!("2001:db8:{:x}::1", i + 1).parse().unwrap();
            addrs.insert(*p, ip);
        }

        let selected = mgr.select_dial_candidates_subnet_aware(&peers, &addrs, 5);
        assert_eq!(selected.len(), 5, "all peers from different /48 subnets should pass");
    }
}
