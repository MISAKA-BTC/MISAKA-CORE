// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Deterministic test placeholders for genesis construction.
//!
//! Gated behind `#[cfg(any(test, feature = "test-utils"))]`.
//! The `test-utils` feature has a compile_error! guard in lib.rs
//! to prevent accidental inclusion in release builds.

use sha3::{Digest, Sha3_256};

/// ML-DSA-65 public key length.
const PK_LEN: usize = 1952;

/// Generate a deterministic placeholder ML-DSA-65 public key for testing.
///
/// First 32 bytes = `SHA3-256("MISAKA_TESTNET_VALIDATOR:" || index_le_bytes)`.
/// Remaining bytes are zero-filled. These are NOT valid ML-DSA-65 keys
/// and will fail `ValidatorPqPublicKey::from_bytes()` validation.
#[must_use]
pub fn placeholder_validator_pk(index: usize) -> Vec<u8> {
    let mut pk = vec![0u8; PK_LEN];
    let mut h = Sha3_256::new();
    h.update(b"MISAKA_TESTNET_VALIDATOR:");
    h.update(&(index as u32).to_le_bytes());
    let seed = h.finalize();
    pk[..32].copy_from_slice(&seed);
    pk
}

/// Derive a deterministic 32-byte validator ID from an index.
///
/// `SHA3-256("MISAKA:validator:id:v1:" || index_as_u64_le)`
///
/// Ported from `misaka-cli/src/genesis.rs:derive_validator_id`.
#[must_use]
pub fn derive_validator_id(index: usize) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:validator:id:v1:");
    h.update(&(index as u64).to_le_bytes());
    let hash = h.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&hash);
    id
}

/// Create a pre-filled [`crate::GenesisBuilder`] with placeholder validators.
///
/// Useful for tests that need a valid genesis without caring about
/// specific validator keys. The placeholder PKs are NOT valid ML-DSA-65
/// keys, so this builder skips PK length validation only.
#[must_use]
pub fn test_genesis_builder(validator_count: usize) -> crate::GenesisBuilder {
    let mut builder = crate::GenesisBuilder::new()
        .with_protocol_version(misaka_protocol_config::ProtocolVersion::V1)
        .with_chain_id(2)
        .with_genesis_timestamp_ms(1_700_000_000_000)
        .with_treasury([0x01; 32], 10_000_000_000);

    for i in 0..validator_count {
        builder = builder.add_validator(
            placeholder_validator_pk(i),
            1_000_000,
            &format!("127.0.0.{}:16111", i + 1),
        );
    }
    builder
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholder_pk_is_deterministic() {
        assert_eq!(placeholder_validator_pk(0), placeholder_validator_pk(0));
    }

    #[test]
    fn placeholder_pk_has_correct_length() {
        assert_eq!(placeholder_validator_pk(0).len(), PK_LEN);
    }

    #[test]
    fn placeholder_pks_differ_by_index() {
        assert_ne!(placeholder_validator_pk(0), placeholder_validator_pk(1));
    }

    #[test]
    fn derive_validator_id_is_deterministic() {
        assert_eq!(derive_validator_id(0), derive_validator_id(0));
    }

    #[test]
    fn derive_validator_id_differs_by_index() {
        assert_ne!(derive_validator_id(0), derive_validator_id(1));
    }
}
