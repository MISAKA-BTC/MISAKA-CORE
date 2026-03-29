//! Relay Protocol — enables LOCAL (home) nodes to participate via relay.
//!
//! ```text
//! ┌──────────────┐                    ┌──────────────┐
//! │  LOCAL Node   │ ──outbound TCP──► │  Relay Node   │
//! │  (home PC)    │                   │  (VPS)        │
//! │               │ ◄──enveloped───── │               │
//! │  NAT / no     │   messages        │  Public IP    │
//! │  port forward │                   │  Accepts      │
//! └──────────────┘                    │  inbound      │
//!                                     └───────┬───────┘
//!                                             │
//!                    ┌────────────────────────┼────────────────────────┐
//!                    │                        │                        │
//!            ┌───────▼──────┐  ┌──────────────▼──────┐  ┌────────────▼───┐
//!            │  Other Nodes  │  │  Other LOCAL Nodes   │  │  DAG Network   │
//!            └──────────────┘  └─────────────────────┘  └────────────────┘
//! ```
//!
//! # Security Model
//!
//! - All messages MUST be signed by the sender's ML-DSA-65 key
//! - Relay NEVER modifies message content (envelope-only)
//! - Rate limits per session (tx/s, bytes/s)
//! - Max payload size enforced
//! - Relay amplification prevented (1:1 forwarding ratio)
//! - Session authentication via PQ handshake

use serde::{Deserialize, Serialize};
use misaka_types::validator::ValidatorId;

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

/// Maximum relay message payload size (bytes).
pub const MAX_RELAY_PAYLOAD: usize = 256 * 1024; // 256 KB

/// Maximum messages per second per session.
pub const MAX_MESSAGES_PER_SEC: u32 = 100;

/// Maximum bytes per second per session.
pub const MAX_BYTES_PER_SEC: u64 = 10 * 1024 * 1024; // 10 MB/s

/// Heartbeat interval (seconds).
pub const HEARTBEAT_INTERVAL_SECS: u64 = 30;

/// Session timeout if no heartbeat (seconds).
pub const SESSION_TIMEOUT_SECS: u64 = 120;

/// Maximum concurrent relay sessions per relay node.
pub const MAX_RELAY_SESSIONS: usize = 256;

// ═══════════════════════════════════════════════════════════════
//  Relay Messages
// ═══════════════════════════════════════════════════════════════

/// Relay protocol messages.
///
/// All messages are wrapped in a signed envelope at the transport layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelayMessage {
    /// LOCAL node registers with a relay.
    /// Sent once after PQ handshake completes.
    Register(RelayRegister),

    /// Periodic heartbeat to maintain the session.
    /// Relay drops the session if no heartbeat within SESSION_TIMEOUT_SECS.
    Heartbeat(RelayHeartbeat),

    /// Envelope: relay forwards a message to/from a LOCAL node.
    /// The relay does NOT inspect the inner payload.
    Envelope(RelayEnvelope),

    /// Relay forwards a network-wide broadcast to the LOCAL node.
    Forward(RelayForward),

    /// Relay acknowledges a registration or heartbeat.
    Ack(RelayAck),

    /// Relay rejects a message (rate limit, invalid, etc.).
    Reject(RelayReject),
}

/// Registration request from LOCAL node to relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayRegister {
    /// Node ID (SHA3-256 of ML-DSA-65 public key).
    pub node_id: [u8; 32],
    /// Stake amount (verified against on-chain state).
    pub stake: u64,
    /// Protocol version.
    pub protocol_version: u8,
    /// ML-DSA-65 signature over (node_id || stake || protocol_version || timestamp).
    pub signature: Vec<u8>,
    /// Registration timestamp (ms since epoch).
    pub timestamp_ms: u64,
}

/// Heartbeat from LOCAL node to relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayHeartbeat {
    pub node_id: [u8; 32],
    /// Sequence number (monotonically increasing per session).
    pub seq: u64,
    /// Timestamp (ms since epoch).
    pub timestamp_ms: u64,
    /// Signature over (node_id || seq || timestamp).
    pub signature: Vec<u8>,
}

/// Envelope: point-to-point message routed through relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayEnvelope {
    /// Source node ID.
    pub source_id: [u8; 32],
    /// Destination node ID (relay looks up session).
    pub destination_id: [u8; 32],
    /// Inner message payload (opaque to relay).
    pub payload: Vec<u8>,
    /// Payload signature by source node.
    pub signature: Vec<u8>,
}

/// Broadcast forward from relay to LOCAL node.
///
/// Contains network-wide messages (new blocks, votes, etc.)
/// that the LOCAL node would normally receive via P2P.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayForward {
    /// Message type tag (for efficient dispatch).
    pub msg_type: RelayForwardType,
    /// Payload (serialized DAG/BFT message).
    pub payload: Vec<u8>,
    /// Original sender's signature.
    pub sender_signature: Vec<u8>,
    /// Relay's own signature (proves relay vouches for delivery).
    pub relay_signature: Vec<u8>,
}

/// Type tags for relay-forwarded messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayForwardType {
    NewDagBlock,
    Transaction,
    BftProposal,
    BftPrevote,
    BftPrecommit,
    SlashEvidence,
    CheckpointVote,
}

/// Relay acknowledgment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayAck {
    pub session_id: [u8; 16],
    pub accepted: bool,
    /// Relay's current connected node count (for load balancing).
    pub relay_load: u32,
}

/// Relay rejection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayReject {
    pub reason: RejectReason,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RejectReason {
    RateLimitExceeded,
    PayloadTooLarge,
    InvalidSignature,
    SessionFull,
    InsufficientStake,
    InvalidProtocolVersion,
}

// ═══════════════════════════════════════════════════════════════
//  Relay Session State (relay-side)
// ═══════════════════════════════════════════════════════════════

/// Per-session state maintained by the relay node.
#[derive(Debug, Clone)]
pub struct RelaySession {
    /// Registered node ID.
    pub node_id: [u8; 32],
    /// Session ID (random, assigned by relay).
    pub session_id: [u8; 16],
    /// Node's verified stake.
    pub stake: u64,
    /// Last heartbeat timestamp (ms).
    pub last_heartbeat_ms: u64,
    /// Last heartbeat sequence number.
    pub last_seq: u64,
    /// Messages forwarded this second (rate limiter).
    pub messages_this_second: u32,
    /// Bytes forwarded this second (rate limiter).
    pub bytes_this_second: u64,
    /// Total messages forwarded in session.
    pub total_messages: u64,
    /// Total valid messages (for contribution scoring).
    pub valid_messages: u64,
    /// Creation timestamp.
    pub created_ms: u64,
}

impl RelaySession {
    /// Check if the session has timed out.
    pub fn is_timed_out(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_heartbeat_ms) > SESSION_TIMEOUT_SECS * 1000
    }

    /// Check rate limits. Returns true if message is allowed.
    pub fn check_rate_limit(&self, payload_size: usize) -> bool {
        self.messages_this_second < MAX_MESSAGES_PER_SEC
            && self.bytes_this_second + payload_size as u64 <= MAX_BYTES_PER_SEC
            && payload_size <= MAX_RELAY_PAYLOAD
    }

    /// Record a forwarded message for rate limiting.
    pub fn record_message(&mut self, payload_size: usize, valid: bool) {
        self.messages_this_second += 1;
        self.bytes_this_second += payload_size as u64;
        self.total_messages += 1;
        if valid {
            self.valid_messages += 1;
        }
    }

    /// Reset per-second rate counters (call every second).
    pub fn reset_rate_counters(&mut self) {
        self.messages_this_second = 0;
        self.bytes_this_second = 0;
    }

    /// Contribution ratio: valid / total (for scoring).
    pub fn contribution_ratio_bps(&self) -> u32 {
        if self.total_messages == 0 {
            return 0;
        }
        ((self.valid_messages * 10_000) / self.total_messages).min(10_000) as u32
    }
}

// ═══════════════════════════════════════════════════════════════
//  Relay Registry (relay-side)
// ═══════════════════════════════════════════════════════════════

/// Manages all active relay sessions.
#[derive(Debug)]
pub struct RelayRegistry {
    sessions: std::collections::HashMap<[u8; 32], RelaySession>,
    max_sessions: usize,
}

impl RelayRegistry {
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
            max_sessions,
        }
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn get_session(&self, node_id: &[u8; 32]) -> Option<&RelaySession> {
        self.sessions.get(node_id)
    }

    pub fn get_session_mut(&mut self, node_id: &[u8; 32]) -> Option<&mut RelaySession> {
        self.sessions.get_mut(node_id)
    }

    /// Register a new relay session.
    pub fn register(
        &mut self,
        node_id: [u8; 32],
        stake: u64,
        now_ms: u64,
    ) -> Result<[u8; 16], RejectReason> {
        if self.sessions.len() >= self.max_sessions {
            return Err(RejectReason::SessionFull);
        }

        // Generate session ID
        let mut session_id = [0u8; 16];
        use sha3::{Digest, Sha3_256};
        let h = Sha3_256::digest(
            &[&node_id[..], &now_ms.to_le_bytes()[..]].concat(),
        );
        session_id.copy_from_slice(&h[..16]);

        self.sessions.insert(
            node_id,
            RelaySession {
                node_id,
                session_id,
                stake,
                last_heartbeat_ms: now_ms,
                last_seq: 0,
                messages_this_second: 0,
                bytes_this_second: 0,
                total_messages: 0,
                valid_messages: 0,
                created_ms: now_ms,
            },
        );

        Ok(session_id)
    }

    /// Remove timed-out sessions.
    pub fn cleanup_stale(&mut self, now_ms: u64) -> usize {
        let before = self.sessions.len();
        self.sessions.retain(|_, s| !s.is_timed_out(now_ms));
        before - self.sessions.len()
    }

    /// Reset all rate counters (call every second).
    pub fn tick_rate_counters(&mut self) {
        for session in self.sessions.values_mut() {
            session.reset_rate_counters();
        }
    }

    /// Get all active node IDs (for broadcast).
    pub fn active_node_ids(&self) -> Vec<[u8; 32]> {
        self.sessions.keys().copied().collect()
    }
}

// ═══════════════════════════════════════════════════════════════
//  LOCAL Node Relay Client State
// ═══════════════════════════════════════════════════════════════

/// Relay connection state maintained by a LOCAL node.
#[derive(Debug, Clone)]
pub struct RelayClientState {
    /// Connected relay endpoints.
    pub relays: Vec<RelayEndpoint>,
    /// Minimum required relays.
    pub min_relays: u32,
    /// Reconnect backoff base (ms).
    pub backoff_base_ms: u64,
    /// Maximum backoff (ms).
    pub max_backoff_ms: u64,
}

/// A single relay endpoint.
#[derive(Debug, Clone)]
pub struct RelayEndpoint {
    /// Relay address.
    pub address: String,
    /// Session ID (assigned by relay after registration).
    pub session_id: Option<[u8; 16]>,
    /// Whether the connection is active.
    pub connected: bool,
    /// Last heartbeat sent timestamp.
    pub last_heartbeat_ms: u64,
    /// Consecutive connection failures.
    pub failure_count: u32,
    /// Relay's reported load (for selecting least-loaded relay).
    pub relay_load: u32,
}

impl RelayClientState {
    pub fn new(min_relays: u32) -> Self {
        Self {
            relays: Vec::new(),
            min_relays,
            backoff_base_ms: 1000,
            max_backoff_ms: 60_000,
        }
    }

    /// Number of active relay connections.
    pub fn active_relay_count(&self) -> u32 {
        self.relays.iter().filter(|r| r.connected).count() as u32
    }

    /// Whether the minimum relay requirement is met.
    pub fn meets_relay_requirement(&self) -> bool {
        self.active_relay_count() >= self.min_relays
    }

    /// Compute reconnect backoff for a relay with N failures.
    pub fn backoff_ms(&self, failure_count: u32) -> u64 {
        let exp = 2u64.saturating_pow(failure_count.min(10));
        (self.backoff_base_ms * exp).min(self.max_backoff_ms)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_session_timeout() {
        let session = RelaySession {
            node_id: [0x01; 32],
            session_id: [0; 16],
            stake: 1_000_000,
            last_heartbeat_ms: 1000,
            last_seq: 0,
            messages_this_second: 0,
            bytes_this_second: 0,
            total_messages: 0,
            valid_messages: 0,
            created_ms: 1000,
        };
        // Not timed out at 1000 + 100_000 = 101_000 (< 120_000)
        assert!(!session.is_timed_out(101_000));
        // Timed out at 1000 + 121_000 = 122_000
        assert!(session.is_timed_out(122_000));
    }

    #[test]
    fn test_relay_rate_limit() {
        let mut session = RelaySession {
            node_id: [0x01; 32],
            session_id: [0; 16],
            stake: 1_000_000,
            last_heartbeat_ms: 0,
            last_seq: 0,
            messages_this_second: 99,
            bytes_this_second: 0,
            total_messages: 0,
            valid_messages: 0,
            created_ms: 0,
        };
        assert!(session.check_rate_limit(1000));
        session.messages_this_second = 100;
        assert!(!session.check_rate_limit(1000)); // Over limit
    }

    #[test]
    fn test_relay_registry_register_and_cleanup() {
        let mut registry = RelayRegistry::new(10);
        let _ = registry.register([0x01; 32], 1_000_000, 1000);
        let _ = registry.register([0x02; 32], 2_000_000, 2000);
        assert_eq!(registry.session_count(), 2);

        // Cleanup stale at time = 200_000 (both timed out)
        let removed = registry.cleanup_stale(200_000);
        assert_eq!(removed, 2);
        assert_eq!(registry.session_count(), 0);
    }

    #[test]
    fn test_relay_registry_max_sessions() {
        let mut registry = RelayRegistry::new(2);
        assert!(registry.register([0x01; 32], 1_000, 0).is_ok());
        assert!(registry.register([0x02; 32], 1_000, 0).is_ok());
        assert_eq!(
            registry.register([0x03; 32], 1_000, 0).unwrap_err(),
            RejectReason::SessionFull
        );
    }

    #[test]
    fn test_relay_client_meets_requirement() {
        let mut client = RelayClientState::new(2);
        client.relays.push(RelayEndpoint {
            address: "1.2.3.4:6690".into(),
            session_id: Some([0; 16]),
            connected: true,
            last_heartbeat_ms: 0,
            failure_count: 0,
            relay_load: 10,
        });
        assert!(!client.meets_relay_requirement());

        client.relays.push(RelayEndpoint {
            address: "5.6.7.8:6690".into(),
            session_id: Some([1; 16]),
            connected: true,
            last_heartbeat_ms: 0,
            failure_count: 0,
            relay_load: 5,
        });
        assert!(client.meets_relay_requirement());
    }

    #[test]
    fn test_backoff_exponential() {
        let client = RelayClientState::new(2);
        assert_eq!(client.backoff_ms(0), 1000);
        assert_eq!(client.backoff_ms(1), 2000);
        assert_eq!(client.backoff_ms(2), 4000);
        assert_eq!(client.backoff_ms(3), 8000);
        assert_eq!(client.backoff_ms(10), 60_000); // capped
    }

    #[test]
    fn test_contribution_ratio() {
        let mut session = RelaySession {
            node_id: [0; 32],
            session_id: [0; 16],
            stake: 0,
            last_heartbeat_ms: 0,
            last_seq: 0,
            messages_this_second: 0,
            bytes_this_second: 0,
            total_messages: 100,
            valid_messages: 80,
            created_ms: 0,
        };
        assert_eq!(session.contribution_ratio_bps(), 8000); // 80%
        session.total_messages = 0;
        session.valid_messages = 0;
        assert_eq!(session.contribution_ratio_bps(), 0);
    }
}
