// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Narwhal finality — BFT checkpoint voting.
//!
//! Sui equivalent: consensus finality layer (~2,000 lines)

use serde::{Deserialize, Serialize};

// Phase 2c-B D9: BFT module is test-only (not used in production consensus path).
#[cfg(test)]
pub mod bft;
// Phase 3a foundation (2026-04-19): ZK-forward-compatible Cert V2
// types. Storage layer only; wire stays V1. See
// `docs/design/v091_phase3a_cert_v2.md`.
pub mod cert_v2;
pub mod checkpoint_manager;

/// Checkpoint digest (32 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CheckpointDigest(pub [u8; 32]);

/// Finality checkpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Checkpoint {
    pub epoch: u64,
    pub sequence: u64,
    pub last_committed_round: u64,
    pub tx_merkle_root: [u8; 32],
    pub state_root: [u8; 32],
    pub tx_count: u64,
    pub timestamp: u64,
    pub previous: CheckpointDigest,
    pub digest: CheckpointDigest,
}

impl Checkpoint {
    /// Compute digest.
    pub fn compute_digest(&self) -> CheckpointDigest {
        let mut h = blake3::Hasher::new();
        h.update(b"MISAKA:checkpoint:v1:");
        h.update(&self.epoch.to_le_bytes());
        h.update(&self.sequence.to_le_bytes());
        h.update(&self.last_committed_round.to_le_bytes());
        h.update(&self.tx_merkle_root);
        h.update(&self.state_root);
        h.update(&self.tx_count.to_le_bytes());
        h.update(&self.timestamp.to_le_bytes());
        h.update(&self.previous.0);
        CheckpointDigest(*h.finalize().as_bytes())
    }
}

/// A vote for a checkpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointVote {
    pub voter: [u8; 32],
    pub checkpoint_digest: CheckpointDigest,
    pub signature: Vec<u8>,
}

/// Finalized checkpoint with quorum signatures.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalizedCheckpoint {
    pub checkpoint: Checkpoint,
    pub votes: Vec<CheckpointVote>,
}
