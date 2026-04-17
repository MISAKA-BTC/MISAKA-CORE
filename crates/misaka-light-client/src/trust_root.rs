// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation

use misaka_protocol_config::ProtocolVersion;
use misaka_types::validator::ValidatorIdentity;

/// Trust root: bootstraps the light client from genesis.
///
/// This is the single trusted input. Everything else is verified
/// cryptographically from this root through the epoch chain.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrustRoot {
    pub chain_id: u32,
    pub genesis_hash: [u8; 32],
    pub protocol_version: ProtocolVersion,
    pub initial_epoch: u64,
    /// The genesis committee validators with their ML-DSA-65 public keys.
    pub initial_committee: Vec<ValidatorIdentity>,
}
