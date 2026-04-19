//! # Peerstore — Phase P1 persistent peer records (v0.9.2)
//!
//! RocksDB-backed peer record store. Companion to the in-memory
//! [`misaka_p2p::discovery::PeerStore`] — this module handles the
//! on-disk persistence layer so restart-across-boundary peer
//! recovery is possible without re-hitting the seed list.
//!
//! ## Design goals
//!
//! 1. **Crash-safe persistence** — every non-trivial `PeerEvent`
//!    round-trips through RocksDB before `record_connection_*`
//!    returns. No in-memory-only delta.
//! 2. **Off hot-path** — writes flow through a `tokio::mpsc`
//!    channel to a background `PeerstoreUpdater` task. The
//!    consensus / transport hot paths emit one non-blocking
//!    `try_send` per event.
//! 3. **Bounded growth** — `max_peerstore_entries` cap (default
//!    10,000) with trust-score-ordered eviction. Banned peers
//!    are retained beyond the cap as evidence.
//! 4. **Schema stability** — `PeerStoreRecord` has a tiny
//!    version byte prefix so future shape changes can gate on
//!    it without a migration.
//!
//! ## Non-goals
//!
//! - **Gossip / PEX protocol** — that's Phase P2.
//! - **Trust-score policy evolution** — the policy here is a
//!    deliberate minimum (fixed weights per event). P2 will
//!    introduce Sybil-aware scoring once real gossip traffic
//!    exists to reason about.
//!
//! See `docs/design/phase_p1_peerstore.md`.

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

/// Initial trust score for a newly-discovered peer. Neutral
/// value; movement is driven entirely by observed events.
pub const INITIAL_TRUST_SCORE: f32 = 0.5;

/// A peer is auto-banned for 24 h when its trust score falls
/// below this threshold.
pub const BAN_TRUST_THRESHOLD: f32 = 0.1;

/// A peer is treated as "highly trusted" for priority dial
/// selection once its trust score exceeds this value.
pub const PROMOTE_TRUST_THRESHOLD: f32 = 0.8;

/// Default auto-ban duration (seconds).
pub const AUTO_BAN_DURATION_SECS: u64 = 24 * 3600;

/// Default entry cap. Override via `NodeConfig.max_peerstore_entries`.
pub const DEFAULT_MAX_PEERSTORE_ENTRIES: usize = 10_000;

/// Inactive peer TTL (seconds). Records with `last_seen` older
/// than this are candidates for eviction. Banned records are
/// exempt.
pub const DEFAULT_INACTIVE_PEER_TTL_SECS: u64 = 30 * 24 * 3600;

/// Current on-disk schema version of `PeerStoreRecord`. Bump
/// when a field is added / removed / retyped. Forward-compat:
/// decoders MAY reject unknown versions.
pub const PEERSTORE_SCHEMA_VERSION: u8 = 1;

// ═══════════════════════════════════════════════════════════════
//  Types
// ═══════════════════════════════════════════════════════════════

/// 32-byte peer identifier. Derived from the peer's ML-DSA-65
/// transport public key (Phase P0) so identity is stable across
/// IP changes.
pub type PeerId = [u8; 32];

/// Origin of a peerstore entry. Used for diversity selection in
/// P2 (outbound picks balance across sources to resist Sybil
/// flooding from any single source).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerSource {
    /// Listed in the operator's `[[seeds]]` / `--seeds`.
    SeedConfig,
    /// Advertised via Phase P2 gossip by another peer.
    PeerExchange,
    /// Resolved from the on-chain committee registry (P3).
    CommitteeRegistry,
    /// Added explicitly via CLI / RPC.
    Manual,
}

/// Role the peer self-declares. Used for gossip filtering and
/// outbound diversity. Byzantine peers MAY lie here; the label
/// is advisory.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerRole {
    Validator,
    FullNode,
    Unknown,
}

/// One network address of a peer. A peer may have multiple
/// (IPv4 + IPv6 + DNS + advertised external), tracked
/// per-address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerAddr {
    /// `host:port`. Host may be IP literal or DNS name.
    pub addr: String,
    /// Unix-seconds timestamp of the most recent successful
    /// dial via this address. 0 means "never succeeded".
    pub last_success: u64,
    /// Consecutive failure count. Resets on success. Used by
    /// dial-candidate ranking (high value → deprioritised).
    pub failure_count: u32,
}

/// Trust score tracked per peer. Movement rules are in
/// [`apply_peer_event`].
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TrustScore {
    /// Current value in `[0.0, 1.0]`. Clamped on every update.
    pub value: f32,
    /// Unix-seconds timestamp of the last mutation (for decay).
    pub updated_at: u64,
}

impl Default for TrustScore {
    fn default() -> Self {
        Self {
            value: INITIAL_TRUST_SCORE,
            updated_at: 0,
        }
    }
}

/// Events that move a peer's trust score / ban state. Emitted
/// by the transport + consensus hot paths; consumed by the
/// background `PeerstoreUpdater`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PeerEvent {
    /// A dial + handshake succeeded.
    ConnectionEstablished,
    /// The transport layer failed to reach the peer.
    ConnectionFailedUnreachable,
    /// The handshake started but failed (wrong PK, version
    /// skew, etc.).
    HandshakeFailed { reason: String },
    /// A block from this peer passed verification.
    ValidBlockReceived,
    /// A block from this peer failed verification.
    InvalidBlockReceived,
    /// Equivocation detected (self-conflicting blocks at the
    /// same round). Immediately bans the peer.
    EquivocationDetected,
    /// Any other protocol rule violation.
    ProtocolViolation { detail: String },
    /// P2 only: the peer advertised a gossip entry that failed
    /// signature / TTL validation.
    AdvertiseValidationFailed { detail: String },
}

/// Persistent per-peer record. This is the serialised value
/// type stored under `StorageCf::Peerstore`. Keep the struct
/// small — one entry per observed peer, plus trust score that
/// decays on a 1 / day schedule, means the typical testnet
/// footprint is < 1 KiB/peer × a few thousand peers = a few
/// MiB total.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PeerStoreRecord {
    /// Schema version. Readers MUST check this and return a
    /// typed error on unknown versions rather than panic.
    pub schema_version: u8,
    /// Stable identifier. Matches the RocksDB key.
    pub peer_id: PeerId,
    /// ML-DSA-65 transport public key (1952 bytes), or `None`
    /// for temporary addr-only records. Populated from handshake.
    pub public_key: Option<Vec<u8>>,
    /// All observed addresses for this peer.
    pub addrs: Vec<PeerAddr>,
    /// Unix seconds — first observation.
    pub first_seen: u64,
    /// Unix seconds — most recent interaction of any kind.
    pub last_seen: u64,
    /// Unix seconds — last dial attempt.
    pub last_dial_attempt: u64,
    /// Unix seconds — last successful handshake.
    pub last_dial_success: u64,
    /// Cumulative successful handshakes.
    pub successful_connections: u64,
    /// Cumulative dial / handshake failures.
    pub failed_connections: u64,
    /// Self-declared role (may lie).
    pub role: PeerRole,
    /// Trust score.
    pub trust_score: TrustScore,
    /// If the peer is currently banned, the unix-seconds
    /// deadline after which it may be dialed again. `None` →
    /// not banned.
    pub banned_until: Option<u64>,
    /// How this record was discovered.
    pub source: PeerSource,
}

impl PeerStoreRecord {
    /// Fresh record for a peer just discovered via `source`.
    /// Caller is responsible for the `now` parameter (clock
    /// injection makes tests deterministic).
    #[must_use]
    pub fn new(peer_id: PeerId, source: PeerSource, now: u64) -> Self {
        Self {
            schema_version: PEERSTORE_SCHEMA_VERSION,
            peer_id,
            public_key: None,
            addrs: Vec::new(),
            first_seen: now,
            last_seen: now,
            last_dial_attempt: 0,
            last_dial_success: 0,
            successful_connections: 0,
            failed_connections: 0,
            role: PeerRole::Unknown,
            trust_score: TrustScore {
                value: INITIAL_TRUST_SCORE,
                updated_at: now,
            },
            banned_until: None,
            source,
        }
    }

    /// Returns true if the record is currently banned at `now`.
    #[must_use]
    pub fn is_banned(&self, now: u64) -> bool {
        matches!(self.banned_until, Some(until) if until > now)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Event → record mutation (pure, no I/O)
// ═══════════════════════════════════════════════════════════════

/// Apply an event to a record in place. Pure function — I/O is
/// the caller's responsibility. Trust-score deltas per event:
///
/// | Event                             | Δ      |
/// |-----------------------------------|--------|
/// | `ConnectionEstablished`           | +0.05  |
/// | `ConnectionFailedUnreachable`     | -0.02  |
/// | `HandshakeFailed`                 | -0.10  |
/// | `ValidBlockReceived`              | +0.01  |
/// | `InvalidBlockReceived`            | -0.30  |
/// | `EquivocationDetected`            | clamp → 0.0 + auto-ban |
/// | `ProtocolViolation`               | -0.50  |
/// | `AdvertiseValidationFailed`       | -0.20  |
///
/// Result is clamped to `[0.0, 1.0]`. Falling below
/// [`BAN_TRUST_THRESHOLD`] triggers an auto-ban for
/// [`AUTO_BAN_DURATION_SECS`].
pub fn apply_peer_event(record: &mut PeerStoreRecord, event: &PeerEvent, now: u64) {
    let delta: f32 = match event {
        PeerEvent::ConnectionEstablished => {
            record.successful_connections = record.successful_connections.saturating_add(1);
            record.last_dial_success = now;
            record.last_dial_attempt = now;
            record.last_seen = now;
            0.05
        }
        PeerEvent::ConnectionFailedUnreachable => {
            record.failed_connections = record.failed_connections.saturating_add(1);
            record.last_dial_attempt = now;
            -0.02
        }
        PeerEvent::HandshakeFailed { .. } => {
            record.failed_connections = record.failed_connections.saturating_add(1);
            record.last_dial_attempt = now;
            -0.10
        }
        PeerEvent::ValidBlockReceived => {
            record.last_seen = now;
            0.01
        }
        PeerEvent::InvalidBlockReceived => {
            record.last_seen = now;
            -0.30
        }
        PeerEvent::EquivocationDetected => {
            // Zero out and auto-ban immediately.
            record.trust_score.value = 0.0;
            record.trust_score.updated_at = now;
            record.banned_until = Some(now + AUTO_BAN_DURATION_SECS);
            record.last_seen = now;
            return;
        }
        PeerEvent::ProtocolViolation { .. } => {
            record.last_seen = now;
            -0.50
        }
        PeerEvent::AdvertiseValidationFailed { .. } => -0.20,
    };

    let new_value = (record.trust_score.value + delta).clamp(0.0, 1.0);
    record.trust_score.value = new_value;
    record.trust_score.updated_at = now;

    // Auto-ban if we slid below the threshold on a non-ban event.
    if new_value < BAN_TRUST_THRESHOLD && record.banned_until.is_none() {
        record.banned_until = Some(now + AUTO_BAN_DURATION_SECS);
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests (pure-logic)
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(now: u64) -> PeerStoreRecord {
        PeerStoreRecord::new([1u8; 32], PeerSource::SeedConfig, now)
    }

    #[test]
    fn initial_record_has_neutral_trust_and_unbanned() {
        let r = sample_record(100);
        assert_eq!(r.trust_score.value, INITIAL_TRUST_SCORE);
        assert_eq!(r.banned_until, None);
        assert!(!r.is_banned(100));
        assert_eq!(r.schema_version, PEERSTORE_SCHEMA_VERSION);
    }

    #[test]
    fn connection_established_raises_trust_and_counts_success() {
        let mut r = sample_record(100);
        apply_peer_event(&mut r, &PeerEvent::ConnectionEstablished, 200);
        assert!(r.trust_score.value > INITIAL_TRUST_SCORE);
        assert_eq!(r.successful_connections, 1);
        assert_eq!(r.last_dial_success, 200);
        assert_eq!(r.last_seen, 200);
    }

    #[test]
    fn invalid_block_drops_trust_but_does_not_ban_from_initial() {
        let mut r = sample_record(100);
        apply_peer_event(&mut r, &PeerEvent::InvalidBlockReceived, 200);
        assert!(r.trust_score.value < INITIAL_TRUST_SCORE);
        assert_eq!(r.banned_until, None);
    }

    #[test]
    fn equivocation_immediately_bans_and_zeros_score() {
        let mut r = sample_record(100);
        apply_peer_event(&mut r, &PeerEvent::EquivocationDetected, 200);
        assert_eq!(r.trust_score.value, 0.0);
        assert_eq!(r.banned_until, Some(200 + AUTO_BAN_DURATION_SECS));
        assert!(r.is_banned(200));
    }

    #[test]
    fn repeated_invalid_blocks_cross_ban_threshold() {
        let mut r = sample_record(100);
        // 2× InvalidBlockReceived: 0.5 → 0.2 → -0.1 → clamp 0.0.
        // After first event score = 0.2, still above ban threshold.
        // After second event score clamps to 0.0 (< 0.1 ban threshold)
        // → auto-ban fires.
        apply_peer_event(&mut r, &PeerEvent::InvalidBlockReceived, 200);
        assert!(r.trust_score.value >= BAN_TRUST_THRESHOLD);
        assert_eq!(r.banned_until, None);
        apply_peer_event(&mut r, &PeerEvent::InvalidBlockReceived, 300);
        assert!(r.trust_score.value < BAN_TRUST_THRESHOLD);
        assert_eq!(r.banned_until, Some(300 + AUTO_BAN_DURATION_SECS));
    }

    #[test]
    fn trust_score_is_clamped_to_unit_interval() {
        let mut r = sample_record(100);
        // Pump +0.05 many times, expect ceiling at 1.0.
        for _ in 0..100 {
            apply_peer_event(&mut r, &PeerEvent::ConnectionEstablished, 100);
        }
        assert_eq!(r.trust_score.value, 1.0);

        // Now drain it with -0.50, expect floor at 0.0.
        apply_peer_event(&mut r, &PeerEvent::ProtocolViolation { detail: "test".into() }, 100);
        apply_peer_event(&mut r, &PeerEvent::ProtocolViolation { detail: "test".into() }, 100);
        apply_peer_event(&mut r, &PeerEvent::ProtocolViolation { detail: "test".into() }, 100);
        assert_eq!(r.trust_score.value, 0.0);
    }

    #[test]
    fn serde_roundtrip_preserves_record_exactly() {
        let mut original = sample_record(100);
        original.addrs.push(PeerAddr {
            addr: "1.2.3.4:6690".into(),
            last_success: 150,
            failure_count: 2,
        });
        original.public_key = Some(vec![0xAB; 1952]);
        original.role = PeerRole::Validator;
        original.trust_score.value = 0.73;
        original.banned_until = Some(9999);

        let encoded = bincode::serialize(&original).expect("encode");
        let decoded: PeerStoreRecord = bincode::deserialize(&encoded).expect("decode");
        assert_eq!(original, decoded);
    }

    #[test]
    fn banned_until_controls_is_banned() {
        let mut r = sample_record(100);
        r.banned_until = Some(500);
        assert!(r.is_banned(100));
        assert!(r.is_banned(499));
        assert!(!r.is_banned(500)); // strictly greater
        assert!(!r.is_banned(501));
    }
}
