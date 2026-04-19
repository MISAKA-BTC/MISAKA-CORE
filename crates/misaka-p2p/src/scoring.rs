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

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerScore {
    pub transport_score: i32,
    pub protocol_score: i32,
    pub liveness_score: i32,
    pub usefulness_score: i32,
    pub penalty_score: i32,
    /// Last decay time. Non-serializable (`Instant` is monotonic, not
    /// wall-clock) — reset to `Instant::now()` on load, which is the
    /// correct behaviour (decay is always measured against the local
    /// clock from the moment the score was observed).
    #[serde(skip, default = "Instant::now")]
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
    perm_bans: HashSet<PeerId>,
}

impl ScoreManager {
    pub fn new() -> Self {
        Self {
            scores: HashMap::new(),
            temp_bans: HashMap::new(),
            perm_bans: HashSet::new(),
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
//  BLOCKER F: Persistence
// ═══════════════════════════════════════════════════════════════
//
// The running `ScoreManager` is in-memory only. Without persistence,
// every node restart resets the ban list and score history, so an
// attacker who hit the permanent-ban threshold can simply wait for
// the next restart to be welcomed back as a fresh peer. We persist:
//
// * `scores` as-is (the dimensions are plain i32 + `last_decay` is
//   reset to `Instant::now()` on load — the correct behaviour).
// * `perm_bans` as a HashSet<PeerId>.
// * `temp_bans` as `PeerId → wall-clock unix millis expiry`. Instant
//   is monotonic and meaningless across a restart, so we anchor to
//   wall-clock on save and reconstruct Instants on load relative to
//   the current clock. Entries whose wall-clock expiry is in the
//   past are filtered at load time.
//
// The file is written atomically (write-to-tmp + fsync + rename)
// following the BLOCKER A UTXO-snapshot pattern. Corruption at
// startup downgrades to "start with an empty ScoreManager" rather
// than failing the node — the same fallback the UTXO snapshot takes.

/// Persistent, wall-clock-anchored form of the ScoreManager state.
///
/// The HashMaps are serialized as Vec-of-pairs because `PeerId([u8;
/// 32])` is not a JSON-string-map key (serde_json rejects non-string
/// map keys). Vec-of-pairs preserves every (peer, value) entry and
/// survives round-trips without any custom serde plumbing.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedScoreManagerV1 {
    /// Format tag — always `"v1"` for the v0.8.0 mainnet surface.
    /// Bumping the tag forces a clean start on older readers, which
    /// is intentional: a corrupted / incompatible file is safer to
    /// discard than to trust.
    format: String,
    /// Unix millis at save time.
    saved_at_ms: u64,
    /// (peer, score) pairs. Duplicate PeerIds would be a corruption
    /// signal but we defensively deduplicate on load by folding into
    /// a HashMap (last-write-wins).
    scores: Vec<(PeerId, PeerScore)>,
    perm_bans: Vec<PeerId>,
    /// (peer, unix millis expiry) pairs. Entries where
    /// `expires_at_ms <= saved_at_ms` are meaningless and are filtered
    /// at save time; the same filter runs again at load time against
    /// the current wall-clock.
    temp_bans_expires_ms: Vec<(PeerId, u64)>,
}

impl PersistedScoreManagerV1 {
    const FORMAT_TAG: &'static str = "v1";
}

/// Errors that can arise when saving / loading the peer-score file.
#[derive(Debug, thiserror::Error)]
pub enum ScorePersistError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde_json: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("unexpected format tag `{got}` (expected `{expected}`)")]
    FormatMismatch { got: String, expected: String },
}

fn wall_clock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl ScoreManager {
    /// Persist the current scoring state to `path` atomically.
    ///
    /// Behaviour:
    /// * Expired `temp_bans` are filtered before saving — saving an
    ///   already-expired ban would rehydrate it on the next load only
    ///   to be re-filtered; skip the round-trip.
    /// * The file is written as JSON to `path.tmp`, fsynced, then
    ///   renamed over `path`. Readers either see the old contents or
    ///   the full new contents — never a partial write.
    /// * On error, the caller gets the error and the existing `path`
    ///   is left unchanged.
    pub fn save_to_file(&self, path: &Path) -> Result<(), ScorePersistError> {
        let now_instant = Instant::now();
        let now_wall = wall_clock_ms();

        let temp_bans_expires_ms: Vec<(PeerId, u64)> = self
            .temp_bans
            .iter()
            .filter_map(|(peer, expires_at)| {
                let remaining = expires_at.saturating_duration_since(now_instant);
                if remaining.is_zero() {
                    None
                } else {
                    Some((*peer, now_wall.saturating_add(remaining.as_millis() as u64)))
                }
            })
            .collect();

        let persisted = PersistedScoreManagerV1 {
            format: PersistedScoreManagerV1::FORMAT_TAG.to_string(),
            saved_at_ms: now_wall,
            scores: self.scores.iter().map(|(k, v)| (*k, v.clone())).collect(),
            perm_bans: self.perm_bans.iter().copied().collect(),
            temp_bans_expires_ms,
        };

        let bytes = serde_json::to_vec_pretty(&persisted)?;

        // Atomic write: tmp file → fsync → rename.
        let tmp_path = path.with_extension("tmp");
        {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    /// Load scoring state from `path`, reconstructing Instant-based
    /// temp bans from wall-clock expiry.
    ///
    /// Behaviour:
    /// * Missing file → returns `Ok(None)` so the node can initialize
    ///   a fresh `ScoreManager` without failing.
    /// * Format-tag mismatch → returns `FormatMismatch`. Callers log
    ///   + fall back to fresh.
    /// * Corrupt / truncated JSON → returns `SerdeJson`. Same
    ///   fallback policy.
    /// * Temp bans whose wall-clock expiry is already in the past are
    ///   dropped.
    pub fn load_from_file(path: &Path) -> Result<Option<Self>, ScorePersistError> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(ScorePersistError::Io(e)),
        };
        let persisted: PersistedScoreManagerV1 = serde_json::from_slice(&bytes)?;
        if persisted.format != PersistedScoreManagerV1::FORMAT_TAG {
            return Err(ScorePersistError::FormatMismatch {
                got: persisted.format,
                expected: PersistedScoreManagerV1::FORMAT_TAG.to_string(),
            });
        }

        let now_instant = Instant::now();
        let now_wall = wall_clock_ms();

        let mut temp_bans: HashMap<PeerId, Instant> = HashMap::new();
        for (peer, expires_at_ms) in persisted.temp_bans_expires_ms {
            if expires_at_ms > now_wall {
                let remaining = Duration::from_millis(expires_at_ms - now_wall);
                temp_bans.insert(peer, now_instant + remaining);
            }
            // else: already expired, discard
        }

        Ok(Some(Self {
            scores: persisted.scores.into_iter().collect(),
            temp_bans,
            perm_bans: persisted.perm_bans.into_iter().collect(),
        }))
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

        // First invalid PQ signature reaches the temp-ban threshold exactly.
        mgr.record_event(peer, ScoreEvent::InvalidPqSignature);
        assert!(mgr.is_banned(&peer)); // -50 → temp ban
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
        assert_eq!(
            selected.len(),
            5,
            "all peers from different subnets should pass"
        );
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

    // ═══════════════════════════════════════════════════════════
    //  BLOCKER F: Persistence tests
    // ═══════════════════════════════════════════════════════════

    fn tmp_path(label: &str) -> std::path::PathBuf {
        let pid = std::process::id();
        let ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("misaka_score_{}_{}_{}.json", label, pid, ns))
    }

    #[test]
    fn blocker_f_roundtrip_preserves_scores_and_perm_bans() {
        let path = tmp_path("roundtrip");
        let mut mgr = ScoreManager::new();
        let good = pid(0x10);
        let bad = pid(0x20);

        mgr.record_event(good, ScoreEvent::ValidBlock); // +5
        mgr.record_event(good, ScoreEvent::ValidHandshake); // +10
        let banned = mgr.record_event(bad, ScoreEvent::EquivocationEvidence); // -100 → perm
        assert!(banned);
        assert!(mgr.is_banned(&bad));

        mgr.save_to_file(&path).expect("save");

        let restored = ScoreManager::load_from_file(&path)
            .expect("load")
            .expect("file exists");

        assert_eq!(restored.total_score(&good), mgr.total_score(&good));
        assert!(
            restored.is_banned(&bad),
            "permanent ban must survive save/load"
        );
        // Non-banned peer is NOT banned after reload.
        assert!(!restored.is_banned(&good));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn blocker_f_temp_ban_survives_reload_when_not_expired() {
        let path = tmp_path("tempban_live");
        let mut mgr = ScoreManager::new();
        let peer = pid(0x30);

        // Inject a temp ban that expires in 1 hour — definitely still
        // live after the save/load round-trip below.
        mgr.temp_bans
            .insert(peer, Instant::now() + Duration::from_secs(3600));

        mgr.save_to_file(&path).expect("save");
        let restored = ScoreManager::load_from_file(&path)
            .expect("load")
            .expect("file exists");

        assert!(
            restored.is_banned(&peer),
            "in-window temp ban must survive restart"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn blocker_f_expired_temp_ban_is_dropped_on_save_and_load() {
        let path = tmp_path("tempban_expired");
        let mut mgr = ScoreManager::new();
        let peer = pid(0x40);

        // Inject a temp ban that expired 1s ago. It should be filtered
        // out during save (no-op to persist an expired ban) and NOT
        // present after reload.
        mgr.temp_bans
            .insert(peer, Instant::now() - Duration::from_secs(1));

        mgr.save_to_file(&path).expect("save");
        let restored = ScoreManager::load_from_file(&path)
            .expect("load")
            .expect("file exists");

        assert!(
            !restored.is_banned(&peer),
            "expired temp ban must NOT survive save/load"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn blocker_f_missing_file_returns_none_not_error() {
        // Fresh nodes start with no scoring file. Load must return Ok(None).
        let path = tmp_path("missing_file_sentinel");
        assert!(!path.exists());
        let res = ScoreManager::load_from_file(&path).expect("ok");
        assert!(res.is_none(), "missing file must return Ok(None)");
    }

    #[test]
    fn blocker_f_save_is_atomic_tmp_file_disappears() {
        let path = tmp_path("atomic");
        let tmp = path.with_extension("tmp");
        let mut mgr = ScoreManager::new();
        mgr.record_event(pid(0x01), ScoreEvent::ValidBlock);

        mgr.save_to_file(&path).expect("save");

        assert!(path.exists(), "final file must exist");
        assert!(
            !tmp.exists(),
            "tmp file must be renamed away after successful save"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn blocker_f_format_mismatch_returns_named_error() {
        // Handcraft a JSON file with the wrong format tag.
        let path = tmp_path("format_mismatch");
        let bogus = r#"{"format":"v99","saved_at_ms":0,"scores":[],"perm_bans":[],"temp_bans_expires_ms":[]}"#;
        std::fs::write(&path, bogus).unwrap();

        let err = match ScoreManager::load_from_file(&path) {
            Err(e) => e,
            Ok(_) => panic!("expected format-mismatch error, got Ok"),
        };
        match err {
            ScorePersistError::FormatMismatch { got, expected } => {
                assert_eq!(got, "v99");
                assert_eq!(expected, "v1");
            }
            other => panic!("expected FormatMismatch, got {other:?}"),
        }

        let _ = std::fs::remove_file(&path);
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
        assert_eq!(
            selected.len(),
            5,
            "all peers from different /48 subnets should pass"
        );
    }
}
