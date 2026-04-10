// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Commit types — ordered output from the consensus engine.
//!
//! Sui equivalent: consensus/types/commit.rs (~350 lines)

use super::block::*;
use serde::{Deserialize, Serialize};

/// Sequential commit index.
pub type CommitIndex = u64;

/// Digest of a commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CommitDigest(pub [u8; 32]);

/// A committed sub-DAG rooted at a leader block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommittedSubDag {
    /// Sequential commit number.
    pub index: CommitIndex,
    /// The leader block that triggered this commit.
    pub leader: BlockRef,
    /// All blocks in the committed sub-DAG (deterministic order).
    pub blocks: Vec<BlockRef>,
    /// Timestamp (max of leader timestamp and previous commit).
    pub timestamp_ms: BlockTimestampMs,
    /// Previous commit digest (chain linkage).
    pub previous_digest: CommitDigest,
    /// Whether this was a direct commit (fast path) or indirect.
    pub is_direct: bool,
}

impl CommittedSubDag {
    pub fn digest(&self) -> CommitDigest {
        let mut h = blake3::Hasher::new();
        h.update(b"MISAKA:commit:v1:");
        h.update(&self.index.to_le_bytes());
        h.update(&self.leader.digest.0);
        for b in &self.blocks {
            h.update(&b.digest.0);
        }
        h.update(&self.timestamp_ms.to_le_bytes());
        h.update(&self.previous_digest.0);
        CommitDigest(*h.finalize().as_bytes())
    }
}

/// Decision status for a leader.
#[derive(Clone, Debug)]
pub enum LeaderStatus {
    Commit(BlockRef),
    Skip(Slot),
    Undecided(Slot),
}

impl LeaderStatus {
    pub fn is_decided(&self) -> bool {
        matches!(self, Self::Commit(_) | Self::Skip(_))
    }
    pub fn into_committed(self) -> Option<BlockRef> {
        match self {
            Self::Commit(r) => Some(r),
            _ => None,
        }
    }
}

/// Commit reference — lightweight pointer to a commit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitRef {
    pub index: CommitIndex,
    pub digest: CommitDigest,
}

/// Commit vote — piggy-backed on blocks to vote for a commit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitVote {
    pub commit_index: CommitIndex,
    pub commit_digest: CommitDigest,
}
