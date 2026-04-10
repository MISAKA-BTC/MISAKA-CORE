//! RPC error types.

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("method not found: {0}")]
    MethodNotFound(String),
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("server error: {0}")]
    Server(String),
    #[error("not connected")]
    NotConnected,
    #[error("subscription error: {0}")]
    Subscription(String),
    #[error("rate limited")]
    RateLimited,
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("consensus error: {0}")]
    Consensus(String),
    #[error("mining error: {0}")]
    Mining(String),
    #[error("timeout")]
    Timeout,
}

pub type RpcResult<T> = Result<T, RpcError>;
