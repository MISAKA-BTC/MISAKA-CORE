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

pub use peer_id::PeerId;
pub use peer_record::{
    PeerRecord, PeerRecordError, NetworkAddress, CapabilityFlags, PeerRoles,
    MAX_ADDRESSES, MAX_RECORD_SIZE, DEFAULT_TTL_SECS,
};
pub use handshake::{HandshakeResult, InitiatorHandshake};
pub use secure_transport::{
    DirectionalKeys, NonceCounter, AeadError, MsgType,
    encrypt_frame, decrypt_frame, encode_wire_frame,
    encode_binary_message, decode_binary_message,
    MAX_FRAME_SIZE, REKEY_THRESHOLD,
};
pub use discovery::{
    DiscoveryBackend, PeerStore,
    MAX_PEER_STORE_SIZE, GOSSIP_BATCH_SIZE,
};
pub use peer::PeerManager;
pub use peer_state::{
    PeerDagState, PeerStateSummary, BanState,
    InflightRequest, RequestType,
    MAX_INFLIGHT_PER_PEER, INFLIGHT_TIMEOUT_SECS,
    BAN_THRESHOLD, BAN_DURATION_SECS,
    MAX_MESSAGES_PER_SEC, MAX_ORPHANS_PER_PEER,
};
pub use scoring::{
    PeerScore, ScoreEvent, ScoreManager,
    TEMP_BAN_THRESHOLD, PERM_BAN_THRESHOLD, PREFERRED_THRESHOLD,
};
pub use validator_network::{
    NetworkRole, ValidatorNetworkConfig, SentryConfig,
    AdmissionDecision, ValidatorOperationalState,
    evaluate_inbound, check_validator_state,
};
pub use sync::{
    IbdEngine, IbdPhase, IbdAction, IbdMessage, IbdProgress, LogLevel,
    IBD_HEADER_BATCH, IBD_BODY_BATCH, MAX_BODY_WORKERS,
    PRUNING_POINT_QUORUM,
};
