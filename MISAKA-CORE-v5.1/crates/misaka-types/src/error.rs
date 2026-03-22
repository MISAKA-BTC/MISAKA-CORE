//! Error types for MISAKA Network.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MisakaError {
    // ── Serialization ────────────────────────
    #[error("MCS-1 deserialization error: {0}")]
    DeserializationError(String),

    #[error("MCS-1 field too large: {field} ({size} > {max})")]
    FieldTooLarge {
        field: String,
        size: usize,
        max: usize,
    },

    // ── Crypto / Signatures ──────────────────
    #[error("unknown signature scheme: 0x{0:02x}")]
    UnknownSignatureScheme(u8),

    #[error("invalid public key length: expected {expected}, got {got}")]
    InvalidPublicKeyLength { expected: usize, got: usize },

    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("scheme mismatch: key={key:?}, sig={sig:?}")]
    SchemeMismatch {
        key: crate::scheme::SignatureScheme,
        sig: crate::scheme::SignatureScheme,
    },

    // ── PQC-specific ─────────────────────────
    #[error("Falcon-512 error: {0}")]
    FalconError(String),

    #[error("Kyber-768 error: {0}")]
    KyberError(String),

    #[error("LaRRS ring signature error: {0}")]
    LaRRSError(String),

    #[error("Jamtis stealth address error: {0}")]
    JamtisError(String),

    // ── Transaction ──────────────────────────
    #[error("empty actions list")]
    EmptyActions,

    #[error("empty inputs list")]
    EmptyInputs,

    #[error("duplicate input: {0}")]
    DuplicateInput(String),

    #[error("gas budget exceeded: charged={charged}, limit={limit}")]
    GasBudgetExceeded { charged: u64, limit: u64 },

    #[error("arithmetic overflow")]
    ArithmeticOverflow,

    // ── Consensus ────────────────────────────
    #[error("insufficient commit power for finality")]
    ForkInsufficientCommitPower,

    #[error("invalid validator set hash")]
    InvalidValidatorSetHash,

    #[error("quorum not reached: got {got}, need {need}")]
    QuorumNotReached { got: u64, need: u64 },

    // ── Bridge ───────────────────────────────
    #[error("bridge: unknown source chain {0}")]
    BridgeUnknownChain(u32),

    #[error("bridge: attestation already exists")]
    BridgeAttestationExists,

    #[error("bridge: insufficient attestations ({got}/{need})")]
    BridgeInsufficientAttestations { got: usize, need: usize },

    // ── Governance ───────────────────────────
    #[error("proposal not found: {0}")]
    ProposalNotFound(u64),

    #[error("voting period ended")]
    VotingPeriodEnded,

    // ── Storage ──────────────────────────────
    #[error("object not found: {0}")]
    ObjectNotFound(String),

    #[error("version mismatch: expected {expected}, got {got}")]
    VersionMismatch { expected: u64, got: u64 },

    // ── P2P ──────────────────────────────────
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("peer limit reached")]
    PeerLimitReached,
}
