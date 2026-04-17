// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation

#[derive(Debug, thiserror::Error)]
pub enum LoadgenError {
    #[error("RPC error: {0}")]
    RpcError(String),

    #[error("tx submission rejected: {reason}")]
    TxRejected { reason: String },

    #[error("tx observation timeout after {timeout_ms}ms")]
    ObservationTimeout { timeout_ms: u64 },

    #[error("keypair generation failed: {0}")]
    KeygenFailed(String),

    #[error("tx construction failed: {0}")]
    TxConstructionFailed(String),

    #[error("config error: {0}")]
    ConfigError(String),

    #[error("serialization error: {0}")]
    SerializationError(String),
}
