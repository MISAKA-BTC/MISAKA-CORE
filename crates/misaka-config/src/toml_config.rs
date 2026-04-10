// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! TOML configuration deserialization.
//!
//! The TOML config files use nested sections (`[chain]`, `[node]`, `[p2p]`, etc.)
//! while `NodeConfig` is flat. This module provides a TOML-specific wrapper that
//! deserializes nested TOML and converts to `NodeConfig`.

use serde::Deserialize;
use super::node_config::NodeConfig;

/// Top-level TOML configuration structure.
///
/// All sections are optional — missing sections use `NodeConfig::default()` values.
/// Unknown top-level sections (e.g. `[faucet]`, `[staking]`) are captured in `_extra`
/// and silently ignored, so existing TOML configs with extra sections still parse.
#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct TomlConfig {
    pub chain: ChainSection,
    pub node: NodeSection,
    pub p2p: P2pSection,
    pub rpc: RpcSection,
    pub consensus: ConsensusSection,
    pub weak_subjectivity: WeakSubjectivitySection,
    /// Catch-all for unrecognised top-level sections (faucet, staking, bridge, etc.).
    #[serde(flatten)]
    pub _extra: std::collections::HashMap<String, toml::Value>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct ChainSection {
    pub chain_id: Option<u32>,
    pub chain_name: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct NodeSection {
    pub mode: Option<String>,
    pub data_dir: Option<String>,
    pub log_level: Option<String>,
    pub max_block_txs: Option<usize>,
    pub max_mempool_size: Option<usize>,
    pub max_msg_size: Option<usize>,
    pub min_fee: Option<u64>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct P2pSection {
    pub port: Option<u16>,
    pub listen_addr: Option<String>,
    pub peers: Option<String>,
    // Additional fields from mainnet.toml that we accept but don't map yet:
    pub max_inbound_peers: Option<usize>,
    pub max_outbound_peers: Option<usize>,
    pub max_handshake_attempts_per_ip: Option<usize>,
    pub max_half_open: Option<usize>,
    pub half_open_timeout_secs: Option<u64>,
    pub max_inbound_per_subnet: Option<usize>,
    pub max_inbound_per_ip: Option<usize>,
    pub max_session_lifetime_secs: Option<u64>,
    pub min_protocol_version: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct RpcSection {
    pub port: Option<u16>,
    pub bind: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct ConsensusSection {
    pub fast_block_time_secs: Option<u64>,
    pub zkp_block_time_secs: Option<u64>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct WeakSubjectivitySection {
    pub checkpoint: Option<String>,
    pub ws_period_epochs: Option<u64>,
}

impl From<TomlConfig> for NodeConfig {
    fn from(t: TomlConfig) -> Self {
        let defaults = NodeConfig::default();

        let rpc_bind = t.rpc.bind.or_else(|| {
            t.rpc.port.map(|p| format!("0.0.0.0:{}", p))
        });

        NodeConfig {
            chain_id: t.chain.chain_id.unwrap_or(defaults.chain_id),
            listen_addr: t.p2p.listen_addr.unwrap_or(defaults.listen_addr),
            listen_port: t.p2p.port.unwrap_or(defaults.listen_port),
            data_dir: t.node.data_dir.unwrap_or(defaults.data_dir),
            log_level: t.node.log_level.unwrap_or(defaults.log_level),
            ws_checkpoint: t.weak_subjectivity.checkpoint.or(defaults.ws_checkpoint),
            max_block_txs: t.node.max_block_txs.unwrap_or(defaults.max_block_txs),
            max_mempool_size: t.node.max_mempool_size.unwrap_or(defaults.max_mempool_size),
            max_msg_size: t.node.max_msg_size.unwrap_or(defaults.max_msg_size),
            min_fee: t.node.min_fee.unwrap_or(defaults.min_fee),
            peers: t.p2p.peers.or(defaults.peers),
            rpc_bind: rpc_bind.or(defaults.rpc_bind),
            metrics_bind: defaults.metrics_bind,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mainnet_style_toml() {
        let toml_str = r#"
[chain]
chain_id = 1
chain_name = "MISAKA Mainnet"

[node]
data_dir = "./misaka-data"
log_level = "info"

[p2p]
port = 6690

[rpc]
port = 3001

[weak_subjectivity]
checkpoint = "42:abcdef1234567890abcdef1234567890"
"#;
        let toml_cfg: TomlConfig = toml::from_str(toml_str).unwrap();
        let config = NodeConfig::from(toml_cfg);
        assert_eq!(config.chain_id, 1);
        assert_eq!(config.data_dir, "./misaka-data");
        assert_eq!(config.listen_port, 6690);
        assert_eq!(config.rpc_bind, Some("0.0.0.0:3001".to_string()));
        assert!(config.ws_checkpoint.is_some());
    }

    #[test]
    fn test_empty_toml_uses_defaults() {
        let toml_cfg: TomlConfig = toml::from_str("").unwrap();
        let config = NodeConfig::from(toml_cfg);
        let defaults = NodeConfig::default();
        assert_eq!(config.chain_id, defaults.chain_id);
        assert_eq!(config.listen_port, defaults.listen_port);
    }

    #[test]
    fn test_partial_toml() {
        let toml_str = r#"
[chain]
chain_id = 1
"#;
        let toml_cfg: TomlConfig = toml::from_str(toml_str).unwrap();
        let config = NodeConfig::from(toml_cfg);
        assert_eq!(config.chain_id, 1);
        // Everything else should be defaults
        let defaults = NodeConfig::default();
        assert_eq!(config.listen_port, defaults.listen_port);
        assert_eq!(config.data_dir, defaults.data_dir);
    }
}
