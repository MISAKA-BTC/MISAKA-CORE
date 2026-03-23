// ─── Core Identity ───
pub mod peer_id;
pub mod peer_record;

// ─── Transport Security ───
pub mod handshake;
pub mod secure_transport;

// ─── Discovery & Gossip ───
pub mod discovery;

// ─── Peer Management ───
pub mod peer;
pub mod peer_state;
pub mod scoring;

// ─── Validator / Sentry Isolation ───
pub mod validator_network;

// ─── Sync Protocol ───
pub mod sync;

// ═══════════════════════════════════════════════════════════════
//  Re-exports
// ═══════════════════════════════════════════════════════════════

pub use discovery::{DiscoveryBackend, PeerStore, GOSSIP_BATCH_SIZE, MAX_PEER_STORE_SIZE};
pub use handshake::{HandshakeResult, InitiatorHandshake};
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
    AeadError, DirectionalKeys, MsgType, NonceCounter, MAX_FRAME_SIZE, REKEY_THRESHOLD,
};
pub use sync::{
    IbdAction, IbdEngine, IbdMessage, IbdPhase, IbdProgress, LogLevel, IBD_BODY_BATCH,
    IBD_HEADER_BATCH, MAX_BODY_WORKERS, PRUNING_POINT_QUORUM,
};
pub use validator_network::{
    check_validator_state, evaluate_inbound, AdmissionDecision, NetworkRole, SentryConfig,
    ValidatorNetworkConfig, ValidatorOperationalState,
};
