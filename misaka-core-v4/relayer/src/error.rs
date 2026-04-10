//! Domain-specific error types for the MISAKA Bridge Relayer (Burn & Mint).
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
    /// Burn verification failure.
    BurnVerification(BurnVerificationError),
    /// API error.
    Api(String),
    /// Configuration error (should cause immediate exit).
    Config(String),
}

impl fmt::Display for RelayerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SolanaRpc(e) => write!(f, "solana rpc: {}", e),
            Self::MisakaRpc(e) => write!(f, "misaka rpc: {}", e),
            Self::Store(e) => write!(f, "store: {}", e),
            Self::BurnVerification(e) => write!(f, "burn verification: {}", e),
            Self::Api(msg) => write!(f, "api: {}", msg),
            Self::Config(msg) => write!(f, "config: {}", msg),
        }
    }
}

impl std::error::Error for RelayerError {}

impl From<SolanaRpcError> for RelayerError {
    fn from(e: SolanaRpcError) -> Self {
        Self::SolanaRpc(e)
    }
}
impl From<MisakaRpcError> for RelayerError {
    fn from(e: MisakaRpcError) -> Self {
        Self::MisakaRpc(e)
    }
}
impl From<StoreError> for RelayerError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}
impl From<BurnVerificationError> for RelayerError {
    fn from(e: BurnVerificationError) -> Self {
        Self::BurnVerification(e)
    }
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
            Self::MalformedResponse { method, detail } => {
                write!(f, "malformed response from '{}': {}", method, detail)
            }
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

// ─── Burn Verification Errors ──────────────────────────────

#[derive(Debug)]
pub enum BurnVerificationError {
    /// Transaction not found or not finalized.
    TransactionNotFound(String),
    /// Transaction failed (err field is not null).
    TransactionFailed(String),
    /// No SPL Token Burn instruction found in the transaction.
    NoBurnInstruction(String),
    /// Burn mint does not match expected MISAKA mint.
    MintMismatch { expected: String, found: String },
    /// Owner does not match claimed wallet.
    OwnerMismatch { expected: String, found: String },
    /// Burn amount is zero.
    ZeroAmount,
    /// RPC error during verification.
    RpcError(String),
}

impl fmt::Display for BurnVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransactionNotFound(sig) => write!(f, "tx not found or not finalized: {}", sig),
            Self::TransactionFailed(sig) => write!(f, "tx failed: {}", sig),
            Self::NoBurnInstruction(sig) => write!(f, "no SPL burn instruction in tx: {}", sig),
            Self::MintMismatch { expected, found } => {
                write!(f, "mint mismatch: expected={}, found={}", expected, found)
            }
            Self::OwnerMismatch { expected, found } => {
                write!(f, "owner mismatch: expected={}, found={}", expected, found)
            }
            Self::ZeroAmount => write!(f, "burn amount is zero"),
            Self::RpcError(msg) => write!(f, "rpc: {}", msg),
        }
    }
}

impl std::error::Error for BurnVerificationError {}

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
