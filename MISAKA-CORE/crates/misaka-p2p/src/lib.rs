//! # misaka-p2p — Post-Quantum Native P2P Network Layer
//!
//! Kaspa-aligned architecture with ML-KEM-768 / ML-DSA-65 throughout.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                         Hub                                  │
//! │  (central peer registry, event loop, broadcast)              │
//! │                                                              │
//! │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
//! │  │ Router A │  │ Router B │  │ Router C │  │ Router D │   │
//! │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
//! │       │              │              │              │         │
//! │  ┌────▼──────────────▼──────────────▼──────────────▼────┐   │
//! │  │              FlowContext (shared state)               │   │
//! │  │  OrphanBlocksPool │ ProcessQueue │ TxSpread          │   │
//! │  └──────────────────────────────────────────────────────┘   │
//! │                                                              │
//! │  ┌─── Flows ──────────────────────────────────────────────┐ │
//! │  │ PingFlow │ BlockRelayFlow │ TxRelayFlow │ AddressFlow  │ │
//! │  │ IbdFlow  │ (negotiate + streams)                       │ │
//! │  └────────────────────────────────────────────────────────┘ │
//! └──────────────────────────────────────────────────────────────┘
//! ```

// ─── Core Identity ───
pub mod peer_id;
pub mod peer_record;

// ─── Subnet Identification ───
pub mod subnet;

// ─── Transport Security (PQ-AEAD) ───
pub mod handshake;
pub mod secure_transport;

// ─── Connection Guard ───
pub mod connection_guard;

// ─── Discovery & Gossip ───
pub mod discovery;

// ─── Peer Management ───
pub mod peer;
pub mod peer_state;
pub mod scoring;

// ─── Validator / Sentry ───
pub mod validator_network;
pub mod sentry_bridge;

// ─── Sync Protocol (legacy) ───
pub mod sync;

// ═══════════════════════════════════════════════════════════════
//  Kaspa-Aligned Architecture (v10+)
// ═══════════════════════════════════════════════════════════════

pub mod payload_type;
pub mod protocol_error;
pub mod router;
pub mod hub;
pub mod flow_context;
pub mod flow_trait;
pub mod flows;

// ═══════════════════════════════════════════════════════════════
//  Re-exports — Legacy
// ═══════════════════════════════════════════════════════════════

pub use discovery::{DiscoveryBackend, PeerStore, GOSSIP_BATCH_SIZE, MAX_PEER_STORE_SIZE};
pub use handshake::{
    HandshakeResult, InitiatorHandshake, FRESHNESS_NONCE_SIZE, MIN_PROTOCOL_VERSION,
    PROTOCOL_VERSION,
};
pub use peer::{
    build_peer_discovery_response, sanitize_peer_discovery_entries, PeerAdvertisementCandidate,
    PeerDiscoveryEntry, PeerDiscoveryValidationSummary, PeerManager, PeerModeLabel,
    MAX_DISCOVERY_RESPONSE_PEERS,
};
pub use peer_id::PeerId;
pub use peer_record::{
    CapabilityFlags, NetworkAddress, PeerRecord, PeerRecordError, PeerRoles, DEFAULT_TTL_SECS,
    MAX_ADDRESSES, MAX_RECORD_SIZE,
};
pub use peer_state::{
    BanState, InflightRequest, PeerDagState, PeerStateSummary, RequestType, BAN_DURATION_SECS,
    BAN_THRESHOLD, INFLIGHT_TIMEOUT_SECS, MAX_INFLIGHT_PER_PEER, MAX_MESSAGES_PER_SEC,
    MAX_ORPHANS_PER_PEER,
};
pub use scoring::{
    PeerScore, ScoreEvent, ScoreManager, PERM_BAN_THRESHOLD, PREFERRED_THRESHOLD,
    TEMP_BAN_THRESHOLD,
};
pub use secure_transport::{
    decode_binary_message, decrypt_frame, encode_binary_message, encode_wire_frame, encrypt_frame,
    AeadError, DirectionalKeys, MsgType, NonceCounter, RecvNonceTracker, SessionGuard,
    MAX_FRAME_SIZE, MAX_NONCE_GAP, MAX_SESSION_LIFETIME_SECS, REKEY_THRESHOLD,
};
pub use sync::{
    IbdAction, IbdEngine, IbdMessage, IbdPhase as LegacyIbdPhase, IbdProgress as LegacyIbdProgress,
    LogLevel, IBD_BODY_BATCH, IBD_HEADER_BATCH, MAX_BODY_WORKERS as LEGACY_MAX_BODY_WORKERS,
    PRUNING_POINT_QUORUM,
};
pub use validator_network::{
    check_validator_state, evaluate_inbound, AdmissionDecision, NetworkRole, SentryConfig,
    ValidatorNetworkConfig, ValidatorOperationalState,
};
pub use sentry_bridge::{
    MessagePriority, SentryBridge, SentryBridgeConfig, SentryConnectionState,
    SentryEndpoint, SentryInbound, SentryOutbound, SentryStatus, SentryStatusSnapshot,
    scrub_hello_for_validator, scrub_peer_record_for_relay,
};
pub use connection_guard::{
    ConnectionGuard, GuardConfig, GuardDecision, GuardRejectReason,
    is_bogon_ip, validate_advertised_address,
    MAX_HALF_OPEN, MAX_HANDSHAKE_ATTEMPTS_PER_IP, MAX_INBOUND_PER_IP, MAX_INBOUND_PER_SUBNET,
};
pub use subnet::SubnetId;

// ═══════════════════════════════════════════════════════════════
//  Re-exports — New Architecture
// ═══════════════════════════════════════════════════════════════

pub use payload_type::{MisakaMessage, MisakaPayloadType, OverflowPolicy, BLANK_ROUTE_ID};
pub use protocol_error::ProtocolError;
pub use router::{
    Router, IncomingRoute, SharedIncomingRoute, HubEvent,
    Peer as RouterPeer, PeerKey, PeerProperties,
    FLOW_CHANNEL_CAPACITY, OUTGOING_CHANNEL_CAPACITY,
};
pub use hub::{Hub, ConnectionInitializer};
pub use flow_context::{
    FlowConfig, FlowContext, Hash as FlowHash,
    OrphanBlocksPool, OrphanOutput, ProcessQueue, ProcessQueueEntry,
    TransactionsSpread, BlockLogEvent, BlockEventLogger,
    MAX_ORPHANS, MAX_PROCESS_QUEUE,
};
pub use flow_trait::{Flow, spawn_flow};
pub use flows::ibd::{IbdFlow, ChainNegotiationOutput};
pub mod message_validation;
pub mod ban_scoring;
pub mod protocol_handler;
pub mod connection_pool;
pub mod peer_manager;
pub mod message_router;
pub mod peer_discovery;
pub mod block_locator;
pub mod inv_manager;
pub mod relay_service;
pub mod address_exchange;
pub mod flow_registry;
pub mod flow_dispatcher;
