// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation

use misaka_types::dag_types::CommitDigest;

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("block not found at height {0}")]
    BlockNotFound(u64),

    #[error("commit not found: {0}")]
    CommitNotFound(u64),

    #[error("snapshot not found for height {0}")]
    SnapshotNotFound(u64),

    #[error("state root mismatch at height {height}: expected {expected}, got {actual}")]
    StateRootMismatch {
        height: u64,
        expected: String,
        actual: String,
    },

    #[error("tx execution error at height {height}, tx {tx_index}: {message}")]
    TxExecutionError {
        height: u64,
        tx_index: usize,
        tx_hash: [u8; 32],
        message: String,
    },

    #[error("deserialization error: {0}")]
    DeserializationError(String),

    #[error("storage error: {0}")]
    StorageError(String),

    #[error("genesis mismatch")]
    GenesisMismatch,

    #[error("replay aborted: {0}")]
    Aborted(String),
}

/// A single transaction mismatch found during replay.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TxMismatch {
    pub block_height: u64,
    pub tx_index: usize,
    pub tx_hash: [u8; 32],
    pub expected_state_root: [u8; 32],
    pub actual_state_root: [u8; 32],
    pub error: Option<String>,
}

/// Supply invariant violation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SupplyViolation {
    pub height: u64,
    pub total_emitted_before: u64,
    pub total_emitted_after: u64,
    pub reason: String,
}
