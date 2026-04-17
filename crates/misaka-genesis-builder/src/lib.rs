// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Deterministic genesis block construction for MISAKA Network.
//!
//! Consolidates genesis generation logic that was previously spread across
//! `misaka-types`, `misaka-cli`, and `misaka-node` into a single crate
//! with a fluent builder API and a complete, auditable genesis hash.
//!
//! # Usage
//!
//! ```ignore
//! use misaka_genesis_builder::GenesisBuilder;
//! use misaka_protocol_config::ProtocolVersion;
//!
//! let genesis = GenesisBuilder::new()
//!     .with_protocol_version(ProtocolVersion::V1)
//!     .with_chain_id(2)
//!     .with_genesis_timestamp_ms(1_700_000_000_000)
//!     .add_validator(pk_bytes, 1000, "127.0.0.1:16111")
//!     .with_treasury(treasury_addr, amount)
//!     .build()?;
//!
//! println!("genesis hash: {}", genesis.hash_hex());
//! ```

// ── Safety: test-utils must never ship in release builds ────────
#[cfg(all(not(debug_assertions), not(test), feature = "test-utils"))]
compile_error!(
    "FATAL: 'test-utils' feature MUST NOT be compiled in release mode. \
     Remove `test-utils` from your Cargo.toml features."
);

pub mod builder;
pub mod error;
pub mod genesis;
pub mod manifest;

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

// ── Re-exports ──────────────────────────────────────────────────
pub use builder::GenesisBuilder;
pub use error::{GenesisBuilderError, ManifestError};
pub use genesis::Genesis;
pub use manifest::{
    GenesisCommitteeManifest, GenesisCommitteeSection, GenesisManifestToml, GenesisValidator,
};
