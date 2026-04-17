// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Genesis block representation with complete, deterministic hash.
//!
//! The v2 hash covers *all* genesis fields (protocol version, chain ID,
//! timestamp, validators, treasury UTXOs), unlike the v1 hash in
//! `misaka_types::genesis::compute_genesis_hash` which only covered
//! `chain_id + committee_pks`.

use misaka_protocol_config::ProtocolVersion;
use misaka_types::genesis::GenesisUtxo;
use sha3::{Digest, Sha3_256};

use crate::error::GenesisBuilderError;
use crate::manifest::GenesisValidator;

/// Domain prefix for the v2 genesis hash.
///
/// Distinct from `MISAKA-GENESIS:v1:` so that old and new hashes never
/// collide even when the field values happen to overlap.
pub const GENESIS_HASH_DOMAIN_V2: &[u8] = b"MISAKA-GENESIS:v2:";

/// ML-DSA-65 public key length (bytes).
const PK_LEN: usize = 1952;

/// A fully constructed, immutable genesis block.
///
/// Created exclusively by [`crate::GenesisBuilder::build`].
/// The `hash` field is computed once at build time and never mutated.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Genesis {
    pub protocol_version: ProtocolVersion,
    pub chain_id: u32,
    pub genesis_timestamp_ms: u64,
    pub validators: Vec<GenesisValidator>,
    pub treasury_utxos: Vec<GenesisUtxo>,
    /// SHA3-256 of all fields above. Computed at `build()` time.
    hash: [u8; 32],
}

impl Genesis {
    /// Create a `Genesis` from pre-validated fields.
    /// Only called by [`crate::GenesisBuilder::build`].
    pub(crate) fn new(
        protocol_version: ProtocolVersion,
        chain_id: u32,
        genesis_timestamp_ms: u64,
        validators: Vec<GenesisValidator>,
        treasury_utxos: Vec<GenesisUtxo>,
    ) -> Self {
        let hash = Self::compute_hash(
            protocol_version.as_u64(),
            chain_id,
            genesis_timestamp_ms,
            &validators,
            &treasury_utxos,
        );
        Self {
            protocol_version,
            chain_id,
            genesis_timestamp_ms,
            validators,
            treasury_utxos,
            hash,
        }
    }

    /// The 32-byte genesis hash.
    #[must_use]
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }

    /// Hex-encoded genesis hash.
    #[must_use]
    pub fn hash_hex(&self) -> String {
        hex::encode(self.hash)
    }

    /// Build a [`misaka_types::chain_context::ChainContext`] from this genesis.
    #[must_use]
    pub fn chain_context(&self) -> misaka_types::chain_context::ChainContext {
        misaka_types::chain_context::ChainContext::new(self.chain_id, self.hash)
    }

    /// Extract committee public keys in canonical (authority_index) order.
    ///
    /// Useful for interop with code that still expects the old
    /// `compute_genesis_hash(chain_id, &pks)` signature.
    #[must_use]
    pub fn committee_public_keys(&self) -> Vec<Vec<u8>> {
        self.validators
            .iter()
            .map(|v| decode_pk(&v.public_key).unwrap_or_default())
            .collect()
    }

    /// Legacy v1 hash (chain_id + committee PKs only).
    ///
    /// Provided for backward compatibility during testnet migration.
    /// New chains should use [`Self::hash`] exclusively.
    #[must_use]
    pub fn legacy_hash(&self) -> [u8; 32] {
        #[allow(deprecated)]
        misaka_types::genesis::compute_genesis_hash(self.chain_id, &self.committee_public_keys())
    }

    // ── Serialization (bincode v1) ──────────────────────────────

    /// Serialize to bytes for storage (RocksDB, file).
    ///
    /// Uses bincode v1 (serde-based). Field serialization order follows
    /// struct declaration order, which is stable across compilations
    /// because `serde::Serialize` derive emits fields in declaration order.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        // bincode v1 serialization is infallible for types that implement
        // Serialize without custom error paths.
        bincode::serialize(self).expect("Genesis bincode serialization is infallible")
    }

    /// Deserialize from bytes, verifying hash integrity.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GenesisBuilderError> {
        let genesis: Self = bincode::deserialize(bytes)
            .map_err(|e| GenesisBuilderError::DeserializeError(e.to_string()))?;
        let expected = Self::compute_hash(
            genesis.protocol_version.as_u64(),
            genesis.chain_id,
            genesis.genesis_timestamp_ms,
            &genesis.validators,
            &genesis.treasury_utxos,
        );
        if genesis.hash != expected {
            return Err(GenesisBuilderError::HashMismatch {
                stored: hex::encode(genesis.hash),
                computed: hex::encode(expected),
            });
        }
        Ok(genesis)
    }

    // ── Hash computation ────────────────────────────────────────

    /// Compute SHA3-256 over all genesis fields.
    ///
    /// Uses explicit field-by-field hashing with little-endian encoding
    /// and length prefixes for variable-length data. This avoids any
    /// dependency on a serialization framework's internal ordering and
    /// canonicalizes hex-encoded PKs to raw bytes before hashing.
    fn compute_hash(
        protocol_version: u64,
        chain_id: u32,
        genesis_timestamp_ms: u64,
        validators: &[GenesisValidator],
        treasury_utxos: &[GenesisUtxo],
    ) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(GENESIS_HASH_DOMAIN_V2);
        h.update(protocol_version.to_le_bytes());
        h.update(chain_id.to_le_bytes());
        h.update(genesis_timestamp_ms.to_le_bytes());

        // Length-prefix validators to prevent ambiguity.
        h.update((validators.len() as u64).to_le_bytes());
        for v in validators {
            h.update(v.authority_index.to_le_bytes());
            // Decode hex PK to raw bytes for canonical representation.
            // PKs are validated during build(), so decode_pk cannot fail here.
            let pk_bytes = decode_pk(&v.public_key).unwrap_or_else(|()| vec![0u8; PK_LEN]);
            h.update(&pk_bytes);
            h.update(v.stake.to_le_bytes());
            // Length-prefix the variable-length network address.
            h.update((v.network_address.len() as u64).to_le_bytes());
            h.update(v.network_address.as_bytes());
        }

        // Length-prefix treasury UTXOs.
        h.update((treasury_utxos.len() as u64).to_le_bytes());
        for u in treasury_utxos {
            h.update(u.output.amount.to_le_bytes());
            h.update(&u.output.address);
        }

        h.finalize().into()
    }
}

/// Decode a hex-encoded (optionally 0x-prefixed) public key to raw bytes.
pub(crate) fn decode_pk(hex_str: &str) -> Result<Vec<u8>, ()> {
    let trimmed = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(trimmed).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GenesisBuilder;
    use misaka_types::genesis::GenesisUtxo;
    use misaka_types::utxo::TxOutput;

    fn make_pk(seed: u8) -> Vec<u8> {
        let mut pk = vec![seed; PK_LEN];
        // Vary enough bytes to avoid the all-zeros sentinel check
        pk[0] = seed;
        pk[1] = seed.wrapping_add(1);
        pk
    }

    fn base_builder() -> GenesisBuilder {
        GenesisBuilder::new()
            .with_protocol_version(ProtocolVersion::V1)
            .with_chain_id(2)
            .with_genesis_timestamp_ms(1_700_000_000_000)
            .add_validator(make_pk(0xAA), 1000, "127.0.0.1:16111")
            .add_validator(make_pk(0xBB), 1000, "127.0.0.2:16111")
            .with_treasury([0x01; 32], 10_000_000_000)
    }

    // (a) genesis_hash_is_deterministic
    #[test]
    fn genesis_hash_is_deterministic() {
        let g1 = base_builder().build().expect("build ok");
        let g2 = base_builder().build().expect("build ok");
        assert_eq!(g1.hash(), g2.hash());
    }

    // (b) genesis_hash_differs_by_protocol_version
    #[test]
    fn genesis_hash_differs_by_protocol_version() {
        let g1 = base_builder().build().expect("build ok");
        let g2 = base_builder()
            .with_protocol_version(ProtocolVersion::new(2))
            .build()
            .expect("build ok");
        assert_ne!(g1.hash(), g2.hash());
    }

    // (c) genesis_hash_differs_by_utxo
    #[test]
    fn genesis_hash_differs_by_utxo() {
        let g1 = base_builder().build().expect("build ok");
        let g2 = base_builder()
            .with_treasury([0x01; 32], 10_000_000_001) // +1
            .build()
            .expect("build ok");
        assert_ne!(g1.hash(), g2.hash());
    }

    // (d) genesis_hash_differs_by_timestamp
    #[test]
    fn genesis_hash_differs_by_timestamp() {
        let g1 = base_builder().build().expect("build ok");
        let g2 = base_builder()
            .with_genesis_timestamp_ms(1_700_000_000_001) // +1
            .build()
            .expect("build ok");
        assert_ne!(g1.hash(), g2.hash());
    }

    // (h) from_bytes_roundtrip
    #[test]
    fn from_bytes_roundtrip() {
        let g1 = base_builder().build().expect("build ok");
        let bytes = g1.to_bytes();
        let g2 = Genesis::from_bytes(&bytes).expect("from_bytes ok");
        assert_eq!(g1.hash(), g2.hash());
        assert_eq!(g1.chain_id, g2.chain_id);
        assert_eq!(g1.genesis_timestamp_ms, g2.genesis_timestamp_ms);
        assert_eq!(g1.validators.len(), g2.validators.len());
        assert_eq!(g1.treasury_utxos.len(), g2.treasury_utxos.len());
    }

    // Hash v2 differs from legacy v1
    #[test]
    fn v2_hash_differs_from_legacy_v1() {
        let g = base_builder().build().expect("build ok");
        assert_ne!(g.hash(), g.legacy_hash());
    }

    // Tampered bytes fail from_bytes
    #[test]
    fn tampered_bytes_rejected() {
        let g = base_builder().build().expect("build ok");
        let mut bytes = g.to_bytes();
        // Flip a byte in the middle
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        assert!(Genesis::from_bytes(&bytes).is_err());
    }
}
