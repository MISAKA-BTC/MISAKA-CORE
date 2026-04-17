// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Error types for authority aggregation.

use crate::committee::{AuthorityIndex, StakeWeight};

/// Error from a single authority request.
#[derive(Debug, thiserror::Error)]
pub enum AuthorityError {
    #[error("authority {authority} timed out after {timeout_ms}ms")]
    Timeout {
        authority: AuthorityIndex,
        timeout_ms: u64,
    },

    #[error("authority {authority} network error: {message}")]
    Network {
        authority: AuthorityIndex,
        message: String,
    },

    #[error("authority {authority} rejected request: {reason}")]
    Rejected {
        authority: AuthorityIndex,
        reason: String,
    },

    #[error("authority {authority} returned invalid response: {reason}")]
    InvalidResponse {
        authority: AuthorityIndex,
        reason: String,
    },
}

impl AuthorityError {
    /// The authority that caused this error.
    pub fn authority(&self) -> AuthorityIndex {
        match self {
            Self::Timeout { authority, .. }
            | Self::Network { authority, .. }
            | Self::Rejected { authority, .. }
            | Self::InvalidResponse { authority, .. } => *authority,
        }
    }
}

/// Error from the quorum aggregation process.
#[derive(Debug, thiserror::Error)]
pub enum QuorumError {
    #[error(
        "quorum impossible: remaining_stake={remaining_stake}, \
         accumulated_stake={accumulated_stake}, threshold={threshold}"
    )]
    QuorumImpossible {
        remaining_stake: StakeWeight,
        accumulated_stake: StakeWeight,
        threshold: StakeWeight,
    },

    #[error("total timeout after {elapsed_ms}ms with {responses_received} responses")]
    TotalTimeout {
        elapsed_ms: u64,
        responses_received: usize,
    },

    #[error("all authorities failed")]
    AllFailed,

    #[error("no authorities in committee")]
    EmptyCommittee,
}
