// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Common equivocation evidence types shared across consensus layers.
//!
//! Used by:
//! - `misaka-dag/narwhal_dag/vote_registry.rs` (DAG block votes)
//! - `misaka-dag/narwhal_dag/dag_state.rs` (block equivocation)
//! - `misaka-consensus/equivocation_detector.rs` (finality votes)

use serde::{Deserialize, Serialize};

/// Authority index within the committee.
pub type AuthorityIndex = u32;

/// Which consensus layer detected the equivocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EquivocationLayer {
    /// DAG block production: same (author, round), different block digest.
    DagBlock,
    /// DAG commit vote: same (voter, leader_round), different vote.
    DagCommitVote,
    /// Finality vote: same (voter, checkpoint_sequence), different digest.
    FinalityVote,
}

/// Evidence of equivocation: two conflicting signed artifacts from the same authority.
///
/// This is the common type used across all consensus layers. Each layer
/// fills in the appropriate fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EquivocationEvidence {
    /// The equivocating authority.
    pub voter: AuthorityIndex,
    /// Which layer detected this.
    pub layer: EquivocationLayer,
    /// Slot/round/sequence where the conflict occurred.
    pub slot: u64,
    /// First observed artifact (opaque bytes: block hash, vote sig, etc).
    pub artifact_a: Vec<u8>,
    /// Conflicting artifact.
    pub artifact_b: Vec<u8>,
    /// Timestamp (ms) when detected.
    pub detected_at_ms: u64,
}

impl EquivocationEvidence {
    /// Create new evidence with current timestamp.
    pub fn new(
        voter: AuthorityIndex,
        layer: EquivocationLayer,
        slot: u64,
        artifact_a: Vec<u8>,
        artifact_b: Vec<u8>,
    ) -> Self {
        let detected_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            voter,
            layer,
            slot,
            artifact_a,
            artifact_b,
            detected_at_ms,
        }
    }
}
