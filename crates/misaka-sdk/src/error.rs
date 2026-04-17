//! SDK error types.

#[derive(Debug, thiserror::Error)]
pub enum SdkError {
    #[error("fee not set — call set_fee() or estimate_fee() before build()")]
    FeeNotSet,
    #[error("validation failed: {0}")]
    ValidationFailed(String),
    #[error("signing failed: {0}")]
    SigningFailed(String),
    #[error("keygen failed: {0}")]
    KeygenFailed(String),
    #[error("insufficient collateral: required {required}, available {available}")]
    InsufficientCollateral { required: u64, available: u64 },
    #[error("too many collateral inputs: {0} (max 3)")]
    TooManyCollateralInputs(usize),
    #[error("serialization failed: {0}")]
    SerializationFailed(String),
    #[error("rpc error: {0}")]
    RpcError(String),
}
