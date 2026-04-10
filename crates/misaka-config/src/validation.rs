// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Testnet-specific configuration and validation.
//!
//! Extracted from `misaka-node/src/config_validation.rs`.

use serde::{Deserialize, Serialize};
use super::error::ConfigError;

/// Testnet-specific configuration.
///
/// Contains additional fields for development and testing that don't
/// exist in production `NodeConfig`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TestnetConfig {
    pub chain_id: u32,
    pub listen_addr: String,
    pub listen_port: u16,
    pub data_dir: String,
    pub safe_mode_threshold: u64,
    pub max_anonymity_set: usize,
    pub min_ring_size: usize,
    pub default_ring_scheme: u8,
    pub log_level: String,
    pub max_msg_size: usize,
    pub max_mempool_size: usize,
    pub max_tx_size: usize,
    pub min_fee: u64,
    pub max_block_txs: usize,
    pub ws_checkpoint: Option<String>,
}

impl Default for TestnetConfig {
    fn default() -> Self {
        Self {
            chain_id: 2,
            listen_addr: "0.0.0.0".into(),
            listen_port: 16111,
            data_dir: "./testnet_data".into(),
            safe_mode_threshold: 10,
            max_anonymity_set: 16,
            min_ring_size: 4,
            default_ring_scheme: 0x03,
            log_level: "info".into(),
            max_msg_size: 1_048_576,
            max_mempool_size: 5000,
            max_tx_size: 131_072,
            min_fee: 1,
            max_block_txs: 1000,
            ws_checkpoint: None,
        }
    }
}

impl TestnetConfig {
    /// Validate all config invariants.
    pub fn validate(&self) -> Result<(), Vec<ConfigError>> {
        let mut errors = Vec::new();

        if self.chain_id == 0 {
            errors.push(ConfigError::InvalidChainId(self.chain_id));
        }
        if self.chain_id != 1 && self.chain_id != 2 {
            errors.push(ConfigError::WrongTestnetChainId(self.chain_id));
        }
        if self.listen_port == 0 {
            errors.push(ConfigError::InvalidPort(self.listen_port));
        }
        if self.min_ring_size > self.max_anonymity_set {
            errors.push(ConfigError::RingSizeExceedsAnonymitySet(
                self.min_ring_size, self.max_anonymity_set,
            ));
        }

        // Mainnet: ws_checkpoint mandatory
        if self.chain_id == 1 {
            match &self.ws_checkpoint {
                None => {
                    errors.push(ConfigError::Custom(
                        "ws_checkpoint required on mainnet (chain_id=1)".into(),
                    ));
                }
                Some(cp) if cp == &format!("0:{}", "0".repeat(64)) => {
                    errors.push(ConfigError::Custom(
                        "ws_checkpoint is all-zero on mainnet — replace with actual genesis hash before launch".into(),
                    ));
                }
                _ => {}
            }
        }

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }

    /// Check if a ring scheme tag is allowed.
    #[must_use]
    pub fn is_ring_scheme_allowed(&self, scheme: u8) -> bool {
        matches!(scheme, 0x03 | 0x01)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_validates() {
        assert!(TestnetConfig::default().validate().is_ok());
    }

    #[test]
    fn test_ring_size_exceeds_anonymity_set() {
        let mut c = TestnetConfig::default();
        c.min_ring_size = 20;
        c.max_anonymity_set = 16;
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_mainnet_needs_checkpoint() {
        let mut c = TestnetConfig::default();
        c.chain_id = 1;
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_ring_scheme_allowed() {
        let c = TestnetConfig::default();
        assert!(c.is_ring_scheme_allowed(0x03));
        assert!(c.is_ring_scheme_allowed(0x01));
        assert!(!c.is_ring_scheme_allowed(0x99));
    }
}
