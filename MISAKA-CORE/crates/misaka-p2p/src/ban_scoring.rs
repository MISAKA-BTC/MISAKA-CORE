//! P2P ban scoring — accumulate misbehavior points to auto-ban peers.
//!
//! Each protocol violation adds ban points. When a peer exceeds the threshold,
//! they are automatically disconnected and banned for a configurable duration.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use parking_lot::RwLock;

/// Ban score threshold — exceeding this triggers automatic ban.
pub const BAN_THRESHOLD: u32 = 100;

/// Default ban duration.
pub const DEFAULT_BAN_DURATION: Duration = Duration::from_secs(86400); // 24 hours

/// Misbehavior categories with their ban point values.
#[derive(Debug, Clone, Copy)]
pub enum Misbehavior {
    /// Sent an invalid block (severe).
    InvalidBlock,
    /// Sent an invalid transaction.
    InvalidTransaction,
    /// Sent malformed P2P message.
    MalformedMessage,
    /// Sent too many messages (rate limit exceeded).
    RateLimitExceeded,
    /// Sent duplicate data.
    DuplicateData,
    /// Failed handshake.
    HandshakeFailure,
    /// Sent data for wrong network.
    WrongNetwork,
    /// Sent unrequested data.
    UnrequestedData,
    /// Version message anomaly.
    VersionAnomaly,
    /// Slow to respond (possible resource waste attack).
    SlowResponse,
    /// Invalid proof-of-work.
    InvalidPoW,
    /// Checkpoint violation.
    CheckpointViolation,
}

impl Misbehavior {
    pub fn points(&self) -> u32 {
        match self {
            Self::InvalidBlock => 100,
            Self::InvalidTransaction => 50,
            Self::MalformedMessage => 10,
            Self::RateLimitExceeded => 20,
            Self::DuplicateData => 5,
            Self::HandshakeFailure => 30,
            Self::WrongNetwork => 100,
            Self::UnrequestedData => 10,
            Self::VersionAnomaly => 15,
            Self::SlowResponse => 5,
            Self::InvalidPoW => 80,
            Self::CheckpointViolation => 100,
        }
    }
    pub fn description(&self) -> &'static str {
        match self {
            Self::InvalidBlock => "sent invalid block",
            Self::InvalidTransaction => "sent invalid transaction",
            Self::MalformedMessage => "sent malformed message",
            Self::RateLimitExceeded => "exceeded rate limit",
            Self::DuplicateData => "sent duplicate data",
            Self::HandshakeFailure => "handshake failure",
            Self::WrongNetwork => "wrong network",
            Self::UnrequestedData => "sent unrequested data",
            Self::VersionAnomaly => "version anomaly",
            Self::SlowResponse => "slow response",
            Self::InvalidPoW => "invalid proof of work",
            Self::CheckpointViolation => "checkpoint violation",
        }
    }
}

/// Per-peer ban score tracker.
#[derive(Debug, Clone)]
pub struct PeerBanScore {
    pub peer_id: String,
    pub score: u32,
    pub violations: Vec<(Misbehavior, u64)>,
    pub last_violation: Option<Instant>,
    pub is_banned: bool,
    pub banned_until: Option<Instant>,
}

/// Ban scoring manager.
pub struct BanScoring {
    peers: RwLock<HashMap<String, PeerBanScore>>,
    threshold: u32,
    ban_duration: Duration,
    decay_rate: f64, // Points per second to decay
}

impl BanScoring {
    pub fn new(threshold: u32, ban_duration: Duration) -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            threshold,
            ban_duration,
            decay_rate: 0.01, // ~1 point per 100 seconds
        }
    }

    /// Record a misbehavior for a peer. Returns true if peer should be banned.
    pub fn record(&self, peer_id: &str, misbehavior: Misbehavior) -> BanDecision {
        let mut peers = self.peers.write();
        let entry = peers.entry(peer_id.to_string()).or_insert(PeerBanScore {
            peer_id: peer_id.to_string(),
            score: 0,
            violations: Vec::new(),
            last_violation: None,
            is_banned: false,
            banned_until: None,
        });

        // Apply decay
        if let Some(last) = entry.last_violation {
            let elapsed = last.elapsed().as_secs_f64();
            let decay = (elapsed * self.decay_rate) as u32;
            entry.score = entry.score.saturating_sub(decay);
        }

        entry.score += misbehavior.points();
        entry.violations.push((misbehavior, now_secs()));
        entry.last_violation = Some(Instant::now());

        tracing::debug!(
            "Ban score for {}: +{} = {} ({})",
            peer_id, misbehavior.points(), entry.score, misbehavior.description()
        );

        if entry.score >= self.threshold {
            entry.is_banned = true;
            entry.banned_until = Some(Instant::now() + self.ban_duration);
            tracing::warn!("Peer {} banned: score {} >= threshold {}", peer_id, entry.score, self.threshold);
            BanDecision::Ban(self.ban_duration)
        } else if entry.score >= self.threshold / 2 {
            BanDecision::Warn(entry.score)
        } else {
            BanDecision::Ok(entry.score)
        }
    }

    /// Check if a peer is currently banned.
    pub fn is_banned(&self, peer_id: &str) -> bool {
        let peers = self.peers.read();
        peers.get(peer_id).map_or(false, |p| {
            p.is_banned && p.banned_until.map_or(true, |until| Instant::now() < until)
        })
    }

    /// Unban a peer.
    pub fn unban(&self, peer_id: &str) {
        let mut peers = self.peers.write();
        if let Some(entry) = peers.get_mut(peer_id) {
            entry.is_banned = false;
            entry.banned_until = None;
            entry.score = 0;
            entry.violations.clear();
        }
    }

    /// Get ban info for a peer.
    pub fn get_info(&self, peer_id: &str) -> Option<PeerBanScore> {
        self.peers.read().get(peer_id).cloned()
    }

    /// Clean up expired bans.
    pub fn cleanup_expired(&self) -> usize {
        let mut peers = self.peers.write();
        let now = Instant::now();
        let mut unbanned = 0;
        for entry in peers.values_mut() {
            if entry.is_banned {
                if let Some(until) = entry.banned_until {
                    if now >= until {
                        entry.is_banned = false;
                        entry.banned_until = None;
                        entry.score = 0;
                        unbanned += 1;
                    }
                }
            }
        }
        unbanned
    }

    /// Get total banned peer count.
    pub fn banned_count(&self) -> usize {
        self.peers.read().values().filter(|p| p.is_banned).count()
    }

    /// Get all banned peer IDs.
    pub fn banned_peers(&self) -> Vec<String> {
        self.peers.read().values()
            .filter(|p| p.is_banned)
            .map(|p| p.peer_id.clone())
            .collect()
    }
}

impl Default for BanScoring {
    fn default() -> Self { Self::new(BAN_THRESHOLD, DEFAULT_BAN_DURATION) }
}

#[derive(Debug)]
pub enum BanDecision {
    Ok(u32),
    Warn(u32),
    Ban(Duration),
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ban_scoring() {
        let scoring = BanScoring::new(100, Duration::from_secs(60));

        // Low-severity violations don't trigger ban
        for _ in 0..5 {
            match scoring.record("peer1", Misbehavior::DuplicateData) {
                BanDecision::Ok(_) => {},
                other => panic!("expected Ok, got {:?}", other),
            }
        }

        // High-severity violation triggers ban
        match scoring.record("peer2", Misbehavior::InvalidBlock) {
            BanDecision::Ban(_) => {},
            other => panic!("expected Ban, got {:?}", other),
        }
        assert!(scoring.is_banned("peer2"));
    }
}
