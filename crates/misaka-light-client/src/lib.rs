// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! # misaka-light-client
//!
//! Trust-minimized PQ light client for MISAKA Network.
//!
//! Verifies ML-DSA-65 quorum proofs without trusting a full node,
//! using only genesis + epoch chain as trust root.
//!
//! ## Design
//!
//! - **Trust model**: Genesis-anchored, committee-chained
//! - **Verification**: Real ML-DSA-65 (no stub verifiers)
//! - **Dependencies**: misaka-types + misaka-crypto only (no misaka-dag, no rocksdb)
//! - **Storage**: Pluggable via `LightStorage` trait (MemoryStorage for tests)
//! - **Transport**: Pluggable via `CommitStreamProvider` trait (fixture-based for now)
//!
//! ## Current limitations
//!
//! - **WASM**: Not supported (pqcrypto-mldsa uses C FFI). Requires pure-Rust ML-DSA.
//! - **RPC stream**: No observer commit stream endpoint exists. Tests use fixtures.
//! - **Tx inclusion**: Merkle proof not yet implemented (API defined, impl deferred).
//! - **Persistent storage**: sled/file backends are future features.

pub mod client;
pub mod error;
pub mod storage;
pub mod stream;
pub mod trust_root;
pub mod verification;
pub mod verified_commit;
pub mod verified_epoch;

#[cfg(test)]
mod tests;

pub use client::LightClient;
pub use error::LightClientError;
pub use storage::{LightStorage, MemoryStorage};
pub use stream::{CommitStreamProvider, FixtureStreamProvider, UnverifiedCommit};
pub use trust_root::TrustRoot;
pub use verification::{committee_hash, quorum_threshold};
pub use verified_commit::VerifiedCommit;
pub use verified_epoch::VerifiedEpoch;
