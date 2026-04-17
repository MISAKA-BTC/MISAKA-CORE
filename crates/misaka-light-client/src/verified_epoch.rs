// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation

use misaka_types::validator::ValidatorIdentity;

/// A verified epoch: one link in the epoch chain.
///
/// The first link comes from the TrustRoot (genesis committee).
/// Each subsequent link was verified via EpochTransitionProof
/// signed by 2f+1 of the previous epoch's committee.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VerifiedEpoch {
    pub epoch: u64,
    pub committee: Vec<ValidatorIdentity>,
    /// SHA3-256 hash of the committee (same algorithm as ValidatorSet::set_hash).
    pub committee_hash: [u8; 32],
    /// Highest verified commit index in this epoch.
    pub highest_commit_index: u64,
}
