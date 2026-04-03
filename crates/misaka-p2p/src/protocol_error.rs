//! # Protocol Error Types — Kaspa-Aligned P2P Error Handling
//!
//! Comprehensive error taxonomy for P2P protocol violations.
//! Each variant maps to a specific remediation action:
//! - Ignorable: log at debug, continue
//! - Reject: log at warn, disconnect peer
//! - Ban: disconnect + score penalty (may lead to ban)

use std::fmt;

use crate::payload_type::MisakaPayloadType;

/// Default timeout for P2P operations.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Short timeout for repeated operations (e.g., IBD zoom-in).
pub const SHORT_TIMEOUT_SECS: u64 = 10;

/// Maximum times IBD chain negotiation may restart before error.
pub const MAX_NEGOTIATION_RESTARTS: u32 = 32;

/// Maximum block locator length (log2 of max DAG size ≈ 64).
pub const MAX_BLOCK_LOCATOR_LEN: usize = 64;

#[derive(Debug, Clone)]
pub enum ProtocolError {
    // ── Connection-Level ──
    /// The connection was closed by the remote peer.
    ConnectionClosed,

    /// We attempted to connect to ourselves.
    LoopbackConnection(String),

    /// A peer with the same identity already exists.
    PeerAlreadyExists(String),

    /// The peer's protocol version is incompatible.
    VersionMismatch { ours: u32, theirs: u32 },

    /// The peer's network (chain_id) does not match ours.
    NetworkMismatch { ours: u32, theirs: u32 },

    // ── Routing-Level ──
    /// No registered flow for the given message type.
    NoRouteForMessageType(MisakaPayloadType),

    /// The incoming route for a specific flow has reached capacity.
    IncomingRouteCapacityReached(MisakaPayloadType, String),

    /// The outgoing route to the peer is full.
    OutgoingRouteCapacityReached(String),

    // ── Flow-Level ──
    /// A flow timed out waiting for a response.
    Timeout(String),

    /// The peer sent an empty or malformed payload.
    EmptyPayload,

    /// The peer sent a message that violates protocol rules.
    ProtocolViolation(String),

    /// The peer sent an explicit reject message.
    Rejected(String),

    /// The peer sent a reject that can be safely ignored (e.g., inv overflow).
    IgnorableReject(String),

    /// IBD-specific: the peer sent an invalid chain segment.
    InvalidChainSegment(String),

    /// IBD-specific: negotiation exceeded restart limit.
    NegotiationExhausted { peer: String, restarts: u32 },

    // ── Crypto-Level (PQ) ──
    /// ML-KEM decapsulation failed.
    KemDecapsulationFailed,

    /// ML-DSA signature verification failed.
    SignatureVerificationFailed,

    /// AEAD frame decryption failed (tampered or replayed).
    AeadDecryptionFailed,

    /// Nonce replay detected.
    NonceReplay { expected_min: u64, received: u64 },

    /// Session expired (exceeded MAX_SESSION_LIFETIME).
    SessionExpired,

    // ── Routing Setup ──
    /// Attempted to subscribe to an already-registered route.
    DuplicateRoute(String),

    // ── Generic ──
    /// Catch-all with static lifetime message.
    Other(&'static str),

    /// Catch-all with owned message.
    OtherOwned(String),
}

impl ProtocolError {
    /// Whether we can still send an outgoing message to the peer
    /// (i.e., the connection is not already closed).
    pub fn can_send_outgoing_message(&self) -> bool {
        !matches!(
            self,
            ProtocolError::ConnectionClosed
                | ProtocolError::OutgoingRouteCapacityReached(_)
                | ProtocolError::SessionExpired
        )
    }

    /// Convert to a reject reason string for the wire protocol.
    pub fn to_reject_message(&self) -> String {
        match self {
            ProtocolError::VersionMismatch { ours, theirs } => {
                format!("version mismatch: ours={ours}, theirs={theirs}")
            }
            ProtocolError::NetworkMismatch { ours, theirs } => {
                format!("network mismatch: ours={ours}, theirs={theirs}")
            }
            ProtocolError::LoopbackConnection(id) => {
                format!("loopback connection: {id}")
            }
            ProtocolError::PeerAlreadyExists(id) => {
                format!("peer already exists: {id}")
            }
            ProtocolError::ProtocolViolation(msg) => {
                format!("protocol violation: {msg}")
            }
            ProtocolError::SignatureVerificationFailed => {
                "PQ signature verification failed".to_string()
            }
            other => format!("{other}"),
        }
    }

    /// Classify reject reasons from the wire into Rejected vs IgnorableReject.
    pub fn from_reject_message(reason: String) -> Self {
        if reason.contains("inv overflow") || reason.contains("duplicate") {
            ProtocolError::IgnorableReject(reason)
        } else {
            ProtocolError::Rejected(reason)
        }
    }

    /// Whether this error should trigger a score penalty for the peer.
    pub fn should_penalize(&self) -> bool {
        matches!(
            self,
            ProtocolError::ProtocolViolation(_)
                | ProtocolError::InvalidChainSegment(_)
                | ProtocolError::SignatureVerificationFailed
                | ProtocolError::AeadDecryptionFailed
                | ProtocolError::NonceReplay { .. }
                | ProtocolError::Rejected(_)
        )
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtocolError::ConnectionClosed => write!(f, "connection closed"),
            ProtocolError::LoopbackConnection(id) => write!(f, "loopback connection: {id}"),
            ProtocolError::PeerAlreadyExists(id) => write!(f, "peer already exists: {id}"),
            ProtocolError::VersionMismatch { ours, theirs } => {
                write!(f, "version mismatch (ours={ours}, theirs={theirs})")
            }
            ProtocolError::NetworkMismatch { ours, theirs } => {
                write!(f, "network mismatch (ours={ours}, theirs={theirs})")
            }
            ProtocolError::NoRouteForMessageType(t) => {
                write!(f, "no route for message type: {t:?}")
            }
            ProtocolError::IncomingRouteCapacityReached(t, peer) => {
                write!(f, "incoming route capacity reached for {t:?} from {peer}")
            }
            ProtocolError::OutgoingRouteCapacityReached(peer) => {
                write!(f, "outgoing route capacity reached for {peer}")
            }
            ProtocolError::Timeout(ctx) => write!(f, "timeout: {ctx}"),
            ProtocolError::EmptyPayload => write!(f, "empty payload"),
            ProtocolError::ProtocolViolation(msg) => write!(f, "protocol violation: {msg}"),
            ProtocolError::Rejected(reason) => write!(f, "rejected: {reason}"),
            ProtocolError::IgnorableReject(reason) => write!(f, "ignorable reject: {reason}"),
            ProtocolError::InvalidChainSegment(msg) => {
                write!(f, "invalid chain segment: {msg}")
            }
            ProtocolError::NegotiationExhausted { peer, restarts } => {
                write!(
                    f,
                    "negotiation exhausted with {peer} after {restarts} restarts"
                )
            }
            ProtocolError::KemDecapsulationFailed => write!(f, "ML-KEM decapsulation failed"),
            ProtocolError::SignatureVerificationFailed => {
                write!(f, "ML-DSA signature verification failed")
            }
            ProtocolError::AeadDecryptionFailed => write!(f, "AEAD decryption failed"),
            ProtocolError::NonceReplay {
                expected_min,
                received,
            } => write!(
                f,
                "nonce replay (expected >= {expected_min}, got {received})"
            ),
            ProtocolError::SessionExpired => write!(f, "PQ session expired"),
            ProtocolError::DuplicateRoute(id) => write!(f, "duplicate route: {id}"),
            ProtocolError::Other(msg) => write!(f, "{msg}"),
            ProtocolError::OtherOwned(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for ProtocolError {}
