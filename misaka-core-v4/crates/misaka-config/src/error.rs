// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Configuration errors.

/// Error type for configuration loading and validation.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    IoError(String),
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("invalid chain ID: {0}")]
    InvalidChainId(u32),
    #[error("wrong testnet chain ID: {0} (expected 1 or 2)")]
    WrongTestnetChainId(u32),
    #[error("invalid port: {0}")]
    InvalidPort(u16),
    #[error("min ring size {0} exceeds max anonymity set {1}")]
    RingSizeExceedsAnonymitySet(usize, usize),
    #[error("configuration error: {0}")]
    Custom(String),
    #[error("multiple validation errors: {0:?}")]
    Multiple(Vec<ConfigError>),
}
