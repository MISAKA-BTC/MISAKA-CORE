// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Unified error type for genesis building and manifest validation.

/// Genesis builder / manifest error.
#[derive(Debug, thiserror::Error)]
pub enum GenesisBuilderError {
    // ── Manifest errors (ported from misaka-node genesis_committee::ManifestError) ──
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML parse error: {0}")]
    TomlParse(String),

    #[error("duplicate authority_index: {0}")]
    DuplicateIndex(u32),

    #[error("duplicate public_key for authority {0}")]
    DuplicateKey(u32),

    #[error("authority {0} public_key wrong length: {1} bytes, expected {2}")]
    WrongKeyLength(u32, usize, usize),

    #[error("authority {0} has zero stake")]
    ZeroStake(u32),

    #[error("authority {0} network_address is invalid: {1}")]
    InvalidNetworkAddress(u32, String),

    #[error("authority {0} public_key is not a valid ML-DSA-65 key: {1}")]
    InvalidPublicKey(u32, String),

    #[error("duplicate network_address: {0}")]
    DuplicateNetworkAddress(String),

    #[error("authority_index gap: expected {expected}, got {got}")]
    IndexGap { expected: u32, got: u32 },

    #[error("empty committee")]
    EmptyCommittee,

    #[error("validator not in genesis: authority_index={0}")]
    ValidatorNotInGenesis(u32),

    // ── Builder errors ──
    #[error("genesis_timestamp_ms not set — builder must not call chrono::Utc::now()")]
    TimestampNotSet,

    #[error("no validators provided")]
    NoValidators,

    #[error("mainnet genesis requires at least one treasury UTXO")]
    MainnetWithoutTreasury,

    #[error("chain_id not set")]
    ChainIdNotSet,

    #[error("authority {index} public_key length {got}, expected {expected}")]
    InvalidPkLength {
        index: u32,
        got: usize,
        expected: usize,
    },

    #[error("deserialization error: {0}")]
    DeserializeError(String),

    #[error("genesis hash mismatch: stored {stored}, computed {computed}")]
    HashMismatch { stored: String, computed: String },
}

/// Backward-compatible alias for code migrating from `ManifestError`.
pub type ManifestError = GenesisBuilderError;
