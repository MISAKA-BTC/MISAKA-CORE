// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation

use misaka_types::dag_types::{BlockRef, CommitDigest, CommitIndex};

/// A commit that has been verified against the current epoch's committee quorum.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifiedCommit {
    pub epoch: u64,
    pub commit_index: CommitIndex,
    pub commit_digest: CommitDigest,
    pub leader: BlockRef,
    pub block_refs: Vec<BlockRef>,
    pub timestamp_ms: u64,
    pub block_hash: [u8; 32],
    pub slot: u64,
    /// Total verified ML-DSA-65 stake weight for this commit.
    pub verified_stake: u128,
}
