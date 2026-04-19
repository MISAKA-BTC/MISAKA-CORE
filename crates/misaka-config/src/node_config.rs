// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Node configuration struct.
//!
//! Extracted from `misaka-node/src/config.rs`.

use super::error::ConfigError;
use super::prune_mode::PruneMode;
use serde::{Deserialize, Serialize};

/// Full node configuration.
///
/// Loaded from config.json at startup. Validated before use.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeConfig {
    pub chain_id: u32,
    pub listen_addr: String,
    pub listen_port: u16,
    pub data_dir: String,
    pub log_level: String,
    /// Weak subjectivity checkpoint (required on mainnet).
    pub ws_checkpoint: Option<String>,
    /// Maximum block transactions.
    pub max_block_txs: usize,
    /// Maximum mempool size.
    pub max_mempool_size: usize,
    /// Maximum message size (bytes).
    pub max_msg_size: usize,
    /// Minimum transaction fee.
    pub min_fee: u64,
    /// P2P peer list (comma-separated host:port).
    pub peers: Option<String>,
    /// RPC bind address.
    pub rpc_bind: Option<String>,
    /// Metrics bind address.
    pub metrics_bind: Option<String>,

    // ── Faucet ──
    pub faucet_enabled: bool,
    pub faucet_amount: u64,
    pub faucet_cooldown_secs: u64,

    // ── Staking ──
    pub staking_min_stake: u64,
    pub staking_unbonding_period: u64,
    pub staking_max_validators: u32,

    // ── Consensus timing ──
    pub consensus_fast_block_time_secs: u64,
    pub consensus_zkp_block_time_secs: u64,

    // ── DAG pruning ──
    pub dag_retention_rounds: u64,
    /// Runtime storage retention mode. Defaults to
    /// [`PruneMode::Archival`] on new configs; existing JSON configs
    /// without this field deserialise to the default via
    /// [`serde(default)`]. See [`PruneMode`] for TOML/JSON shape.
    #[serde(default)]
    pub prune_mode: PruneMode,

    // ── Security ──
    pub security_require_encrypted_keystore: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            chain_id: 2, // testnet
            listen_addr: "0.0.0.0".into(),
            listen_port: 16111,
            data_dir: "./data".into(),
            log_level: "info".into(),
            ws_checkpoint: None,
            max_block_txs: 1000,
            max_mempool_size: 5000,
            max_msg_size: 1_048_576,
            min_fee: 1,
            peers: None,
            rpc_bind: None,
            metrics_bind: None,
            faucet_enabled: false,
            faucet_amount: 1_000_000_000,
            faucet_cooldown_secs: 300,
            staking_min_stake: 100_000_000_000,
            staking_unbonding_period: 43200,
            staking_max_validators: 50,
            consensus_fast_block_time_secs: 10,
            consensus_zkp_block_time_secs: 30,
            dag_retention_rounds: 10_000,
            prune_mode: PruneMode::default(),
            security_require_encrypted_keystore: true,
        }
    }
}

impl NodeConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ConfigError> {
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

        // Mainnet: ws_checkpoint required
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

        // R7 L-10: Validate operational safety bounds
        if self.max_mempool_size == 0 {
            errors.push(ConfigError::Custom("max_mempool_size must be > 0".into()));
        }
        if self.max_msg_size == 0 || self.max_msg_size > 16_777_216 {
            errors.push(ConfigError::Custom("max_msg_size must be 1..16MiB".into()));
        }
        if self.dag_retention_rounds == 0 {
            errors.push(ConfigError::Custom(
                "dag_retention_rounds must be > 0".into(),
            ));
        }
        if self.max_block_txs == 0 {
            errors.push(ConfigError::Custom("max_block_txs must be > 0".into()));
        }

        if let Err(e) = self.prune_mode.validate() {
            errors.push(e);
        }

        if errors.is_empty() {
            Ok(())
        } else if errors.len() == 1 {
            Err(errors.into_iter().next().unwrap())
        } else {
            Err(ConfigError::Multiple(errors))
        }
    }

    /// Check if this is a mainnet configuration.
    #[must_use]
    pub fn is_mainnet(&self) -> bool {
        self.chain_id == 1
    }

    /// Check if this is a testnet configuration.
    #[must_use]
    pub fn is_testnet(&self) -> bool {
        self.chain_id == 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_testnet() {
        let c = NodeConfig::default();
        assert!(c.is_testnet());
        assert!(!c.is_mainnet());
    }

    #[test]
    fn test_mainnet_requires_checkpoint() {
        let mut c = NodeConfig::default();
        c.chain_id = 1;
        c.ws_checkpoint = None;
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_mainnet_rejects_zero_checkpoint() {
        let mut c = NodeConfig::default();
        c.chain_id = 1;
        // Validation rejects exactly `0:` followed by 64 zero hex chars
        // (matching the canonical zeroed checkpoint hash form).
        c.ws_checkpoint = Some(format!("0:{}", "0".repeat(64)));
        assert!(c.validate().is_err());
    }

    #[test]
    fn test_mainnet_accepts_valid_checkpoint() {
        let mut c = NodeConfig::default();
        c.chain_id = 1;
        c.ws_checkpoint = Some("42:abcdef1234567890abcdef1234567890".into());
        assert!(c.validate().is_ok());
    }

    #[test]
    fn test_zero_port_rejected() {
        let mut c = NodeConfig::default();
        c.listen_port = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn default_prune_mode_is_archival() {
        let c = NodeConfig::default();
        assert_eq!(c.prune_mode, PruneMode::Archival);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn validate_rejects_pruned_below_floor() {
        let mut c = NodeConfig::default();
        c.prune_mode = PruneMode::Pruned { keep_rounds: 1 };
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_accepts_pruned_at_floor_or_above() {
        let mut c = NodeConfig::default();
        c.prune_mode = PruneMode::Pruned {
            keep_rounds: super::super::prune_mode::MIN_KEEP_ROUNDS,
        };
        assert!(c.validate().is_ok());
    }

    #[test]
    fn json_config_without_prune_mode_field_defaults_to_archival() {
        // Legacy JSON configs (written before PruneMode was added) must
        // deserialise — serde(default) on the field fills in Archival.
        let json = r#"{
            "chain_id": 2,
            "listen_addr": "0.0.0.0",
            "listen_port": 16111,
            "data_dir": "./data",
            "log_level": "info",
            "ws_checkpoint": null,
            "max_block_txs": 1000,
            "max_mempool_size": 5000,
            "max_msg_size": 1048576,
            "min_fee": 1,
            "peers": null,
            "rpc_bind": null,
            "metrics_bind": null,
            "faucet_enabled": false,
            "faucet_amount": 1000000000,
            "faucet_cooldown_secs": 300,
            "staking_min_stake": 100000000000,
            "staking_unbonding_period": 43200,
            "staking_max_validators": 50,
            "consensus_fast_block_time_secs": 2,
            "consensus_zkp_block_time_secs": 30,
            "dag_retention_rounds": 10000,
            "security_require_encrypted_keystore": true
        }"#;
        let c: NodeConfig = serde_json::from_str(json).expect("legacy JSON must parse");
        assert_eq!(c.prune_mode, PruneMode::Archival);
    }
}
