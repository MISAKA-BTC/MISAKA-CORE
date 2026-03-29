//! Per-Peer DAG State Tracking — inflight requests, reputation, anti-DoS.
//!
//! # Design (Kaspa-aligned)
//!
//! Each peer maintains:
//! - Announced DAG tips + best selected tip
//! - Inflight request tracking (with timeout)
//! - Reputation score (decay + penalty)
//! - Ban state (with reason and expiry)
//!
//! # Anti-DoS
//!
//! - Per-peer inflight request limit
//! - Message rate limiting
//! - Orphan/pending flood detection
//! - Automatic ban on threshold breach

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

type Hash = [u8; 32];

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

/// Maximum concurrent inflight requests per peer.
pub const MAX_INFLIGHT_PER_PEER: usize = 32;

/// Inflight request timeout.
pub const INFLIGHT_TIMEOUT_SECS: u64 = 30;

/// Maximum messages per second before rate limiting kicks in.
pub const MAX_MESSAGES_PER_SEC: u32 = 100;

/// Reputation decay interval — subtract 1 penalty point every N seconds.
pub const REPUTATION_DECAY_INTERVAL_SECS: u64 = 60;

/// Ban threshold — peer is banned when penalty reaches this.
pub const BAN_THRESHOLD: u32 = 100;

/// Ban duration (seconds).
pub const BAN_DURATION_SECS: u64 = 3600; // 1 hour

/// Maximum orphan blocks relayed by a single peer before penalty.
pub const MAX_ORPHANS_PER_PEER: usize = 64;

// ═══════════════════════════════════════════════════════════════
//  Inflight Request
// ═══════════════════════════════════════════════════════════════

/// An inflight request to a peer.
#[derive(Debug, Clone)]
pub struct InflightRequest {
    /// What we requested (block hash, header batch, etc.)
    pub request_type: RequestType,
    /// When the request was issued.
    pub issued_at: Instant,
    /// Request ID (monotonic).
    pub request_id: u64,
}

/// Type of inflight request.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RequestType {
    /// Fetching specific block(s) by hash.
    GetBlocks(Vec<Hash>),
    /// Fetching headers after a given hash.
    GetHeaders { after_hash: Hash },
    /// Fetching block bodies.
    GetBodies(Vec<Hash>),
    /// Fetching block locator.
    GetBlockLocator,
    /// Ping/pong liveness check.
    Ping,
}

// ═══════════════════════════════════════════════════════════════
//  Peer DAG State
// ═══════════════════════════════════════════════════════════════

/// Complete state for a single peer.
#[derive(Debug)]
pub struct PeerDagState {
    /// Peer address.
    pub addr: SocketAddr,
    /// Whether this is an inbound connection.
    pub inbound: bool,
    /// When the peer connected.
    pub connected_at: Instant,

    // ─── DAG knowledge ───
    /// Peer's announced DAG tips.
    pub announced_tips: Vec<Hash>,
    /// Peer's best known selected tip (highest blue work).
    pub best_selected_tip: Hash,
    /// Peer's best known blue score.
    pub best_blue_score: u64,
    /// Peer's announced pruning point.
    pub pruning_point: Hash,

    // ─── Inflight tracking ───
    /// Currently inflight requests.
    inflight: HashMap<u64, InflightRequest>,
    /// Next request ID.
    next_request_id: u64,

    // ─── Reputation ───
    /// Cumulative penalty score.
    pub penalty: u32,
    /// Good response count.
    pub good_responses: u64,
    /// Bad response count.
    pub bad_responses: u64,
    /// Ban state.
    pub ban_state: Option<BanState>,
    /// Last reputation decay tick.
    last_decay: Instant,

    // ─── Rate limiting ───
    /// Message timestamps in the current window.
    message_times: VecDeque<Instant>,
    /// Orphan blocks relayed by this peer.
    pub orphan_count: usize,

    // ─── General ───
    /// Last time we received any valid data from this peer.
    pub last_progress: Instant,
    /// Protocol version announced by peer.
    pub protocol_version: u8,
}

/// Ban state for a peer.
#[derive(Debug, Clone)]
pub struct BanState {
    pub reason: String,
    pub banned_at: Instant,
    pub expires_at: Instant,
}

impl PeerDagState {
    /// Create a new peer state.
    pub fn new(addr: SocketAddr, inbound: bool) -> Self {
        let now = Instant::now();
        Self {
            addr,
            inbound,
            connected_at: now,
            announced_tips: Vec::new(),
            best_selected_tip: [0u8; 32],
            best_blue_score: 0,
            pruning_point: [0u8; 32],
            inflight: HashMap::new(),
            next_request_id: 1,
            penalty: 0,
            good_responses: 0,
            bad_responses: 0,
            ban_state: None,
            last_decay: now,
            message_times: VecDeque::new(),
            orphan_count: 0,
            last_progress: now,
            protocol_version: 0,
        }
    }

    // ─── DAG knowledge update ───

    /// Update the peer's announced DAG state (from DagHello or periodic update).
    pub fn update_dag_state(
        &mut self,
        tips: Vec<Hash>,
        blue_score: u64,
        selected_tip: Hash,
        pruning_point: Hash,
    ) {
        self.announced_tips = tips;
        self.best_blue_score = blue_score;
        self.best_selected_tip = selected_tip;
        self.pruning_point = pruning_point;
        self.last_progress = Instant::now();
    }

    // ─── Inflight management ───

    /// Register a new inflight request. Returns the request ID.
    ///
    /// Returns `None` if the peer has too many inflight requests.
    pub fn add_inflight(&mut self, request_type: RequestType) -> Option<u64> {
        if self.inflight.len() >= MAX_INFLIGHT_PER_PEER {
            return None;
        }

        let id = self.next_request_id;
        self.next_request_id += 1;

        self.inflight.insert(
            id,
            InflightRequest {
                request_type,
                issued_at: Instant::now(),
                request_id: id,
            },
        );

        Some(id)
    }

    /// Mark a request as completed. Returns the original request if found.
    pub fn complete_inflight(&mut self, request_id: u64) -> Option<InflightRequest> {
        self.inflight.remove(&request_id)
    }

    /// Get timed-out inflight requests and remove them.
    pub fn timeout_inflight(&mut self) -> Vec<InflightRequest> {
        let timeout = Duration::from_secs(INFLIGHT_TIMEOUT_SECS);
        let now = Instant::now();

        let timed_out: Vec<u64> = self
            .inflight
            .iter()
            .filter(|(_, req)| now.duration_since(req.issued_at) > timeout)
            .map(|(id, _)| *id)
            .collect();

        timed_out
            .iter()
            .filter_map(|id| self.inflight.remove(id))
            .collect()
    }

    /// Number of currently inflight requests.
    pub fn inflight_count(&self) -> usize {
        self.inflight.len()
    }

    /// Can we send more requests to this peer?
    pub fn can_request(&self) -> bool {
        self.inflight.len() < MAX_INFLIGHT_PER_PEER && !self.is_banned()
    }

    // ─── Reputation ───

    /// Add a penalty to the peer's reputation.
    pub fn add_penalty(&mut self, points: u32, reason: &str) {
        self.penalty = self.penalty.saturating_add(points);
        self.bad_responses += 1;

        if self.penalty >= BAN_THRESHOLD && self.ban_state.is_none() {
            let now = Instant::now();
            self.ban_state = Some(BanState {
                reason: reason.to_string(),
                banned_at: now,
                expires_at: now + Duration::from_secs(BAN_DURATION_SECS),
            });
        }
    }

    /// Record a good response (resets staleness timer).
    pub fn record_good_response(&mut self) {
        self.good_responses += 1;
        self.last_progress = Instant::now();
    }

    /// Is the peer currently banned?
    pub fn is_banned(&self) -> bool {
        match &self.ban_state {
            Some(ban) => Instant::now() < ban.expires_at,
            None => false,
        }
    }

    /// Is the peer stale (no progress for a long time)?
    pub fn is_stale(&self, timeout: Duration) -> bool {
        self.last_progress.elapsed() > timeout
    }

    /// Tick reputation decay — call periodically.
    pub fn tick_reputation(&mut self) {
        if self.last_decay.elapsed() > Duration::from_secs(REPUTATION_DECAY_INTERVAL_SECS) {
            self.penalty = self.penalty.saturating_sub(1);
            self.last_decay = Instant::now();

            // Check if ban expired
            if let Some(ban) = &self.ban_state {
                if Instant::now() >= ban.expires_at {
                    self.ban_state = None;
                }
            }
        }
    }

    // ─── Rate limiting ───

    /// Record a message arrival. Returns `false` if rate limit exceeded.
    pub fn record_message(&mut self) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(1);

        // Remove messages outside the 1-second window
        while self
            .message_times
            .front()
            .map(|t| now.duration_since(*t) > window)
            .unwrap_or(false)
        {
            self.message_times.pop_front();
        }

        if self.message_times.len() as u32 >= MAX_MESSAGES_PER_SEC {
            return false; // Rate limit exceeded
        }

        self.message_times.push_back(now);
        true
    }

    /// Record an orphan block from this peer.
    /// Returns `true` if orphan flood threshold is exceeded.
    pub fn record_orphan(&mut self) -> bool {
        self.orphan_count += 1;
        self.orphan_count > MAX_ORPHANS_PER_PEER
    }

    // ─── Summary ───

    /// Get a summary snapshot for RPC/monitoring.
    pub fn summary(&self) -> PeerStateSummary {
        PeerStateSummary {
            addr: self.addr,
            inbound: self.inbound,
            best_blue_score: self.best_blue_score,
            tips_count: self.announced_tips.len(),
            inflight: self.inflight.len(),
            penalty: self.penalty,
            good_responses: self.good_responses,
            bad_responses: self.bad_responses,
            banned: self.is_banned(),
            ban_reason: self.ban_state.as_ref().map(|b| b.reason.clone()),
            orphan_count: self.orphan_count,
            protocol_version: self.protocol_version,
        }
    }
}

/// Summary for RPC/monitoring.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerStateSummary {
    pub addr: SocketAddr,
    pub inbound: bool,
    pub best_blue_score: u64,
    pub tips_count: usize,
    pub inflight: usize,
    pub penalty: u32,
    pub good_responses: u64,
    pub bad_responses: u64,
    pub banned: bool,
    pub ban_reason: Option<String>,
    pub orphan_count: usize,
    pub protocol_version: u8,
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port)
    }

    #[test]
    fn test_inflight_limit() {
        let mut peer = PeerDagState::new(test_addr(6690), false);

        for _ in 0..MAX_INFLIGHT_PER_PEER {
            assert!(peer.add_inflight(RequestType::Ping).is_some());
        }

        // Should reject at limit
        assert!(peer.add_inflight(RequestType::Ping).is_none());
        assert!(!peer.can_request());
    }

    #[test]
    fn test_inflight_complete() {
        let mut peer = PeerDagState::new(test_addr(6690), false);

        let id = peer.add_inflight(RequestType::Ping).unwrap();
        assert_eq!(peer.inflight_count(), 1);

        let req = peer.complete_inflight(id);
        assert!(req.is_some());
        assert_eq!(peer.inflight_count(), 0);
    }

    #[test]
    fn test_penalty_and_ban() {
        let mut peer = PeerDagState::new(test_addr(6690), false);

        // Below threshold — not banned
        peer.add_penalty(50, "test");
        assert!(!peer.is_banned());

        // At threshold — banned
        peer.add_penalty(50, "repeated violations");
        assert!(peer.is_banned());
        assert!(peer.ban_state.is_some());
    }

    #[test]
    fn test_rate_limiting() {
        let mut peer = PeerDagState::new(test_addr(6690), false);

        // Should accept up to MAX_MESSAGES_PER_SEC
        for _ in 0..MAX_MESSAGES_PER_SEC {
            assert!(peer.record_message());
        }

        // Next message should be rate-limited
        assert!(!peer.record_message());
    }

    #[test]
    fn test_orphan_flood_detection() {
        let mut peer = PeerDagState::new(test_addr(6690), false);

        for _ in 0..MAX_ORPHANS_PER_PEER {
            assert!(!peer.record_orphan());
        }

        // Next orphan triggers flood detection
        assert!(peer.record_orphan());
    }

    #[test]
    fn test_summary() {
        let mut peer = PeerDagState::new(test_addr(6690), true);
        peer.update_dag_state(vec![[1; 32]], 100, [1; 32], [0; 32]);
        peer.record_good_response();

        let summary = peer.summary();
        assert!(summary.inbound);
        assert_eq!(summary.best_blue_score, 100);
        assert_eq!(summary.good_responses, 1);
    }
}
