// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Fluent builder for deterministic genesis construction.
//!
//! ```ignore
//! let genesis = GenesisBuilder::new()
//!     .with_protocol_version(ProtocolVersion::V1)
//!     .with_chain_id(2)
//!     .with_genesis_timestamp_ms(1_700_000_000_000)
//!     .add_validator(pk_bytes, 1000, "127.0.0.1:16111")
//!     .with_treasury(addr, amount)
//!     .build()?;
//! ```
//!
//! **Invariant**: the builder NEVER calls `chrono::Utc::now()`.
//! The caller must supply `genesis_timestamp_ms` explicitly.

use misaka_protocol_config::ProtocolVersion;
use misaka_types::genesis::GenesisUtxo;
use misaka_types::utxo::TxOutput;

use crate::error::GenesisBuilderError;
use crate::genesis::Genesis;
use crate::manifest::GenesisValidator;

/// ML-DSA-65 public key length.
const PK_LEN: usize = 1952;

/// Fluent genesis builder.
///
/// All fields must be set before calling [`build`](GenesisBuilder::build).
/// `protocol_version` defaults to `V1` if unset.
pub struct GenesisBuilder {
    protocol_version: Option<ProtocolVersion>,
    chain_id: Option<u32>,
    genesis_timestamp_ms: Option<u64>,
    validators: Vec<GenesisValidator>,
    treasury_utxos: Vec<GenesisUtxo>,
}

impl GenesisBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            protocol_version: None,
            chain_id: None,
            genesis_timestamp_ms: None,
            validators: Vec::new(),
            treasury_utxos: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_protocol_version(mut self, v: ProtocolVersion) -> Self {
        self.protocol_version = Some(v);
        self
    }

    #[must_use]
    pub fn with_chain_id(mut self, id: u32) -> Self {
        self.chain_id = Some(id);
        self
    }

    /// Set the genesis timestamp in milliseconds.
    ///
    /// **Required**. Omitting this causes [`build`](Self::build) to fail
    /// with [`GenesisBuilderError::TimestampNotSet`].
    /// The builder intentionally does NOT fall back to `chrono::Utc::now()`
    /// — determinism requires the caller to supply the timestamp explicitly.
    #[must_use]
    pub fn with_genesis_timestamp_ms(mut self, ts: u64) -> Self {
        self.genesis_timestamp_ms = Some(ts);
        self
    }

    /// Add a validator. `authority_index` is assigned automatically (0, 1, 2 ...).
    #[must_use]
    pub fn add_validator(
        mut self,
        pubkey_bytes: Vec<u8>,
        stake: u64,
        network_address: &str,
    ) -> Self {
        let index = self.validators.len() as u32;
        self.validators.push(GenesisValidator {
            authority_index: index,
            public_key: format!("0x{}", hex::encode(&pubkey_bytes)),
            stake,
            network_address: network_address.to_string(),
            solana_stake_account: None,
        });
        self
    }

    /// Bulk-set validators (replaces any previously added).
    #[must_use]
    pub fn with_validators(mut self, validators: Vec<GenesisValidator>) -> Self {
        self.validators = validators;
        self
    }

    /// Add a treasury UTXO.
    #[must_use]
    pub fn with_treasury(mut self, address: [u8; 32], amount: u64) -> Self {
        self.treasury_utxos.push(GenesisUtxo {
            output: TxOutput {
                amount,
                address,
                spending_pubkey: None,
            },
            label: "treasury".into(),
        });
        self
    }

    /// Add an arbitrary genesis UTXO.
    #[must_use]
    pub fn add_utxo(mut self, utxo: GenesisUtxo) -> Self {
        self.treasury_utxos.push(utxo);
        self
    }

    /// Build the genesis block, validating all invariants.
    ///
    /// # Errors
    ///
    /// - [`GenesisBuilderError::TimestampNotSet`] if `with_genesis_timestamp_ms` was not called
    /// - [`GenesisBuilderError::ChainIdNotSet`] if `with_chain_id` was not called
    /// - [`GenesisBuilderError::NoValidators`] if no validators were added
    /// - [`GenesisBuilderError::MainnetWithoutTreasury`] if `chain_id == 1` and no treasury
    /// - [`GenesisBuilderError::InvalidPkLength`] if any PK is not 1952 bytes
    pub fn build(self) -> Result<Genesis, GenesisBuilderError> {
        let chain_id = self.chain_id.ok_or(GenesisBuilderError::ChainIdNotSet)?;
        let genesis_timestamp_ms = self
            .genesis_timestamp_ms
            .ok_or(GenesisBuilderError::TimestampNotSet)?;
        let protocol_version = self.protocol_version.unwrap_or(ProtocolVersion::V1);

        if self.validators.is_empty() {
            return Err(GenesisBuilderError::NoValidators);
        }
        if chain_id == 1 && self.treasury_utxos.is_empty() {
            return Err(GenesisBuilderError::MainnetWithoutTreasury);
        }

        // Validate PK lengths.
        for v in &self.validators {
            let pk = crate::genesis::decode_pk(&v.public_key).map_err(|()| {
                GenesisBuilderError::InvalidPkLength {
                    index: v.authority_index,
                    got: 0,
                    expected: PK_LEN,
                }
            })?;
            if pk.len() != PK_LEN {
                return Err(GenesisBuilderError::InvalidPkLength {
                    index: v.authority_index,
                    got: pk.len(),
                    expected: PK_LEN,
                });
            }
        }

        Ok(Genesis::new(
            protocol_version,
            chain_id,
            genesis_timestamp_ms,
            self.validators,
            self.treasury_utxos,
        ))
    }
}

impl Default for GenesisBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pk(seed: u8) -> Vec<u8> {
        let mut pk = vec![seed; PK_LEN];
        pk[0] = seed;
        pk[1] = seed.wrapping_add(1);
        pk
    }

    // (e) missing_timestamp_is_error
    #[test]
    fn missing_timestamp_is_error() {
        let result = GenesisBuilder::new()
            .with_protocol_version(ProtocolVersion::V1)
            .with_chain_id(2)
            .add_validator(make_pk(0xAA), 1000, "127.0.0.1:16111")
            .with_treasury([0x01; 32], 1000)
            .build();
        assert!(matches!(result, Err(GenesisBuilderError::TimestampNotSet)));
    }

    // (f) missing_validators_is_error
    #[test]
    fn missing_validators_is_error() {
        let result = GenesisBuilder::new()
            .with_protocol_version(ProtocolVersion::V1)
            .with_chain_id(2)
            .with_genesis_timestamp_ms(1_700_000_000_000)
            .with_treasury([0x01; 32], 1000)
            .build();
        assert!(matches!(result, Err(GenesisBuilderError::NoValidators)));
    }

    // (g) mainnet_without_treasury_is_error
    #[test]
    fn mainnet_without_treasury_is_error() {
        let result = GenesisBuilder::new()
            .with_protocol_version(ProtocolVersion::V1)
            .with_chain_id(1) // mainnet
            .with_genesis_timestamp_ms(1_700_000_000_000)
            .add_validator(make_pk(0xAA), 1000, "127.0.0.1:16111")
            .build();
        assert!(matches!(
            result,
            Err(GenesisBuilderError::MainnetWithoutTreasury)
        ));
    }

    // (j) invalid_pk_length_rejected
    #[test]
    fn invalid_pk_length_rejected() {
        let short_pk = vec![0xAA; 100]; // not 1952
        let result = GenesisBuilder::new()
            .with_protocol_version(ProtocolVersion::V1)
            .with_chain_id(2)
            .with_genesis_timestamp_ms(1_700_000_000_000)
            .add_validator(short_pk, 1000, "127.0.0.1:16111")
            .with_treasury([0x01; 32], 1000)
            .build();
        assert!(matches!(
            result,
            Err(GenesisBuilderError::InvalidPkLength { .. })
        ));
    }

    #[test]
    fn chain_id_not_set_is_error() {
        let result = GenesisBuilder::new()
            .with_protocol_version(ProtocolVersion::V1)
            .with_genesis_timestamp_ms(1_700_000_000_000)
            .add_validator(make_pk(0xAA), 1000, "127.0.0.1:16111")
            .with_treasury([0x01; 32], 1000)
            .build();
        assert!(matches!(result, Err(GenesisBuilderError::ChainIdNotSet)));
    }

    #[test]
    fn successful_build() {
        let genesis = GenesisBuilder::new()
            .with_protocol_version(ProtocolVersion::V1)
            .with_chain_id(2)
            .with_genesis_timestamp_ms(1_700_000_000_000)
            .add_validator(make_pk(0xAA), 1000, "127.0.0.1:16111")
            .add_validator(make_pk(0xBB), 1000, "127.0.0.2:16111")
            .with_treasury([0x01; 32], 10_000_000_000)
            .build()
            .expect("build ok");

        assert_eq!(genesis.chain_id, 2);
        assert_eq!(genesis.genesis_timestamp_ms, 1_700_000_000_000);
        assert_eq!(genesis.validators.len(), 2);
        assert_eq!(genesis.treasury_utxos.len(), 1);
        assert!(!genesis.hash_hex().is_empty());
    }

    #[test]
    fn protocol_version_defaults_to_v1() {
        let genesis = GenesisBuilder::new()
            .with_chain_id(2)
            .with_genesis_timestamp_ms(1_700_000_000_000)
            .add_validator(make_pk(0xAA), 1000, "127.0.0.1:16111")
            .with_treasury([0x01; 32], 1000)
            .build()
            .expect("build ok");
        assert_eq!(genesis.protocol_version, ProtocolVersion::V1);
    }

    #[test]
    fn testnet_without_treasury_is_ok() {
        let result = GenesisBuilder::new()
            .with_chain_id(2) // testnet
            .with_genesis_timestamp_ms(1_700_000_000_000)
            .add_validator(make_pk(0xAA), 1000, "127.0.0.1:16111")
            .build();
        assert!(result.is_ok());
    }
}
