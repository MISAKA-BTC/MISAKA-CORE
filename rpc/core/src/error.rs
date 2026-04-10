//! RPC error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("General RPC error: {0}")]
    General(String),
    #[error("Method not found: {0}")]
    MethodNotFound(String),
    #[error("Invalid params: {0}")]
    InvalidParams(String),
    #[error("Internal error: {0}")]
    InternalError(String),
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    #[error("Consensus error: {0}")]
    ConsensusError(String),
    #[error("P2P error: {0}")]
    P2pError(String),
}

pub type RpcResult<T> = std::result::Result<T, RpcError>;
