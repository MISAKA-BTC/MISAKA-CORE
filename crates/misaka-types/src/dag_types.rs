// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Lightweight DAG type definitions for cross-crate use.
//!
//! These types mirror the core DAG types in `misaka-dag/narwhal_types/`
//! but without borsh derives or Arc wrappers. They exist here so that
//! crates that cannot depend on `misaka-dag` (e.g., `misaka-light-client`)
//! can still reference commit digests, block refs, etc.
//!
//! `misaka-dag` retains its own full-featured versions for consensus use.

/// Consensus round number.
pub type Round = u32;

/// Block timestamp in milliseconds since Unix epoch.
pub type BlockTimestampMs = u64;

/// Narwhal-layer stake weight (u64, distinct from ValidatorIdentity's u128).
pub type Stake = u64;

/// Sequential commit index.
pub type CommitIndex = u64;

/// Authority identifier within a committee (0-based index).
pub type AuthorityIndex = u32;

/// BLAKE3 hash of a block's content (excluding signature).
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, serde::Serialize, serde::Deserialize,
)]
pub struct BlockDigest(pub [u8; 32]);

/// Reference to a specific block in the DAG.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockRef {
    pub round: Round,
    pub author: AuthorityIndex,
    pub digest: BlockDigest,
}

/// Hash digest of a committed sub-DAG.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, serde::Serialize, serde::Deserialize)]
pub struct CommitDigest(pub [u8; 32]);
