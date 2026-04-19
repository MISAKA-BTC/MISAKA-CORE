// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Commit stream provider abstraction.
//!
//! The light client does NOT trust the stream — every commit
//! received is verified via ML-DSA-65 quorum proof before acceptance.

use misaka_types::dag_types::{BlockRef, CommitDigest, CommitIndex};
use misaka_types::validator::{CommitteeVote, EpochTransitionProof};

use crate::error::LightClientError;

/// A commit received from the network (not yet verified).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UnverifiedCommit {
    pub epoch: u64,
    pub commit_index: CommitIndex,
    pub commit_digest: CommitDigest,
    pub leader: BlockRef,
    pub block_refs: Vec<BlockRef>,
    pub timestamp_ms: u64,
    pub chain_id: u32,
    pub slot: u64,
    pub block_hash: [u8; 32],
    /// ML-DSA-65 quorum votes from the epoch's committee.
    pub votes: Vec<CommitteeVote>,
}

/// Abstract commit stream provider.
///
/// Implemented by RPC client, gRPC stream, or test fixture.
/// The observer is untrusted transport — every commit is verified.
pub trait CommitStreamProvider {
    /// Get the next unverified commit, or None if the stream is exhausted.
    fn next_commit(&mut self) -> Result<Option<UnverifiedCommit>, LightClientError>;

    /// Get the next epoch transition proof, or None.
    fn next_epoch_transition(&mut self) -> Result<Option<EpochTransitionProof>, LightClientError>;
}

/// Vec-based fixture provider for testing.
pub struct FixtureStreamProvider {
    commits: Vec<UnverifiedCommit>,
    transitions: Vec<EpochTransitionProof>,
    commit_idx: usize,
    transition_idx: usize,
}

impl FixtureStreamProvider {
    pub fn new(commits: Vec<UnverifiedCommit>, transitions: Vec<EpochTransitionProof>) -> Self {
        Self {
            commits,
            transitions,
            commit_idx: 0,
            transition_idx: 0,
        }
    }
}

impl CommitStreamProvider for FixtureStreamProvider {
    fn next_commit(&mut self) -> Result<Option<UnverifiedCommit>, LightClientError> {
        if self.commit_idx < self.commits.len() {
            let c = self.commits[self.commit_idx].clone();
            self.commit_idx += 1;
            Ok(Some(c))
        } else {
            Ok(None)
        }
    }

    fn next_epoch_transition(&mut self) -> Result<Option<EpochTransitionProof>, LightClientError> {
        if self.transition_idx < self.transitions.len() {
            let t = self.transitions[self.transition_idx].clone();
            self.transition_idx += 1;
            Ok(Some(t))
        } else {
            Ok(None)
        }
    }
}
