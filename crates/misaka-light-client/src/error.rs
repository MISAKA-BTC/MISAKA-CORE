// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation

#[derive(Debug, thiserror::Error)]
pub enum LightClientError {
    #[error("quorum not reached: got {got}, need {need}")]
    QuorumNotReached { got: u128, need: u128 },

    #[error("unknown voter: {0}")]
    UnknownVoter(String),

    #[error("duplicate vote from: {0}")]
    DuplicateVote(String),

    #[error("signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    #[error("epoch mismatch: expected {expected}, got {got}")]
    EpochMismatch { expected: u64, got: u64 },

    #[error("epoch gap: expected {expected}, got {got}")]
    EpochGap { expected: u64, got: u64 },

    #[error("commit replay: index {0} already verified")]
    CommitReplay(u64),

    #[error("committee hash mismatch")]
    CommitteeHashMismatch,

    #[error("trust root not initialized")]
    NotInitialized,

    #[error("unsupported protocol version: {0}")]
    UnsupportedProtocolVersion(u64),

    #[error("fork detected: commit index {index} already exists with different content")]
    ForkDetected { index: u64 },

    #[error("storage error: {0}")]
    StorageError(String),

    #[error("chain_id mismatch: expected {expected}, got {got}")]
    ChainIdMismatch { expected: u32, got: u32 },

    #[error("slot mismatch in votes")]
    SlotMismatch,

    #[error("block hash mismatch in votes")]
    BlockHashMismatch,

    #[error("empty committee")]
    EmptyCommittee,
}
