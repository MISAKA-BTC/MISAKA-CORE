//! Domain-specific error types for the MISAKA Bridge Relayer.
//!
//! Replaces ad-hoc `anyhow` / `String` errors with structured enums
//! for programmatic classification, metrics, and alerting.

use std::fmt;

/// Top-level relayer error.
#[derive(Debug)]
pub enum RelayerError {
    /// Solana RPC communication failure.
    SolanaRpc(SolanaRpcError),
    /// Misaka RPC communication failure.
    MisakaRpc(MisakaRpcError),
    /// Idempotency store (SQLite) failure.
    Store(StoreError),
    /// Configuration error (should cause immediate exit).
    Config(String),
}

impl fmt::Display for RelayerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SolanaRpc(e) => write!(f, "solana rpc: {}", e),
            Self::MisakaRpc(e) => write!(f, "misaka rpc: {}", e),
            Self::Store(e) => write!(f, "store: {}", e),
            Self::Config(msg) => write!(f, "config: {}", msg),
        }
    }
}

impl std::error::Error for RelayerError {}

impl From<SolanaRpcError> for RelayerError {
    fn from(e: SolanaRpcError) -> Self { Self::SolanaRpc(e) }
}
impl From<MisakaRpcError> for RelayerError {
    fn from(e: MisakaRpcError) -> Self { Self::MisakaRpc(e) }
}
impl From<StoreError> for RelayerError {
    fn from(e: StoreError) -> Self { Self::Store(e) }
}

// ─── Solana RPC Errors ──────────────────────────────────────

#[derive(Debug)]
pub enum SolanaRpcError {
    /// HTTP-level transport failure (timeout, DNS, TLS, etc).
    Transport(String),
    /// Solana JSON-RPC returned an error object.
    RpcError { method: String, message: String },
    /// Response was not valid JSON or missing expected fields.
    MalformedResponse { method: String, detail: String },
    /// Transaction submission failed.
    SendTransactionFailed(String),
    /// Event parsing failure (non-fatal for individual events).
    EventParseError(String),
}

impl fmt::Display for SolanaRpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(msg) => write!(f, "transport: {}", msg),
            Self::RpcError { method, message } => write!(f, "rpc '{}': {}", method, message),
            Self::MalformedResponse { method, detail } => write!(f, "malformed response from '{}': {}", method, detail),
            Self::SendTransactionFailed(msg) => write!(f, "sendTransaction: {}", msg),
            Self::EventParseError(msg) => write!(f, "event parse: {}", msg),
        }
    }
}

impl std::error::Error for SolanaRpcError {}

// ─── Misaka RPC Errors ──────────────────────────────────────

#[derive(Debug)]
pub enum MisakaRpcError {
    /// HTTP-level transport failure.
    Transport(String),
    /// HTTP non-2xx status.
    HttpStatus { status: u16, body: String },
    /// Response JSON missing expected fields.
    MalformedResponse(String),
    /// Mint submission was rejected by the Misaka node.
    MintRejected(String),
}

impl fmt::Display for MisakaRpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(msg) => write!(f, "transport: {}", msg),
            Self::HttpStatus { status, body } => write!(f, "HTTP {}: {}", status, body),
            Self::MalformedResponse(msg) => write!(f, "malformed: {}", msg),
            Self::MintRejected(msg) => write!(f, "mint rejected: {}", msg),
        }
    }
}

impl std::error::Error for MisakaRpcError {}

// ─── Store Errors ───────────────────────────────────────────

#[derive(Debug)]
pub enum StoreError {
    /// SQLite operation failed.
    Sqlite(String),
    /// Data integrity issue (e.g., unexpected state transition).
    Integrity(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(msg) => write!(f, "sqlite: {}", msg),
            Self::Integrity(msg) => write!(f, "integrity: {}", msg),
        }
    }
}

impl std::error::Error for StoreError {}
