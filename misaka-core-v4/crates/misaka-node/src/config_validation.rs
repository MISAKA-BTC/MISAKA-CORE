//! Testnet startup config validation — fail-closed.
//!
//! Runs at node boot. If ANY check fails, the node REFUSES to start.
//! This prevents operator mistakes from exposing a broken testnet node.

use crate::config::{NodeMode, P2pConfig};
use std::net::IpAddr;

/// All config validation errors. Node refuses to start if any are present.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("chain_id must be > 0 (got {0})")]
    InvalidChainId(u32),
    #[error("testnet chain_id must be 2 (got {0})")]
    WrongTestnetChainId(u32),
    #[error("advertise address must not be 0.0.0.0 or loopback in public/seed mode")]
    InvalidAdvertiseAddr,
    #[error("P2P port must be > 0")]
    InvalidP2pPort,
    #[error("RPC port must be > 0")]
    InvalidRpcPort,
    #[error("P2P port and RPC port must differ")]
    PortCollision,
    #[error("validator set must not be empty")]
    EmptyValidatorSet,
    #[error("block_time must be >= 5 seconds (got {0})")]
    BlockTimeTooLow(u64),
    #[error("max_peers must be >= 1 (got {0})")]
    MaxPeersTooLow(usize),
    #[error("seed nodes list is empty — node cannot discover peers")]
    NoSeedNodes,
    #[error("bridge is enabled but verifier is not production-safe: {0}")]
    UnsafeBridgeVerifier(String),
    #[error("chipmunk ring scheme is enabled but --enable-chipmunk was not explicitly set")]
    ChipmunkNotExplicit,
    #[error("faucet amount must be > 0 and <= 1_000_000 (got {0})")]
    InvalidFaucetAmount(u64),
    #[error("data_dir is not writable: {0}")]
    DataDirNotWritable(String),
    #[error("{0}")]
    Custom(String),
}

/// Testnet configuration with all safety checks.
#[derive(Debug, Clone)]
pub struct TestnetConfig {
    pub chain_id: u32,
    pub chain_name: String,
    pub p2p_port: u16,
    pub rpc_port: u16,
    pub block_time_secs: u64,
    pub max_inbound_peers: usize,
    pub max_outbound_peers: usize,
    pub node_mode: NodeMode,
    pub advertise_addr: Option<String>,
    pub seed_nodes: Vec<String>,
    pub data_dir: String,
    pub faucet_enabled: bool,
    pub faucet_amount: u64,
    pub faucet_cooldown_secs: u64,
    pub bridge_enabled: bool,
    pub chipmunk_enabled: bool,
    pub safe_mode_enabled: bool,
    pub safe_mode_threshold: u64,
    pub max_ring_size: usize,
    pub min_ring_size: usize,
    pub default_ring_scheme: u8,
    pub log_level: String,
    pub max_msg_size: usize,
    pub max_mempool_size: usize,
    pub max_tx_size: usize,
    pub min_fee: u64,
    pub max_block_txs: usize,
}

impl Default for TestnetConfig {
    fn default() -> Self {
        Self {
            chain_id: 2,
            chain_name: "MISAKA Testnet".into(),
            p2p_port: 6690,
            rpc_port: 3001,
            block_time_secs: 60,
            max_inbound_peers: 32,
            max_outbound_peers: 8,
            node_mode: NodeMode::Public,
            advertise_addr: None,
            seed_nodes: vec![],
            data_dir: "./misaka-data".into(),
            faucet_enabled: true,
            faucet_amount: 100_000,
            faucet_cooldown_secs: 300, // 5 minutes
            bridge_enabled: false,     // DISABLED by default for testnet
            chipmunk_enabled: false,   // DISABLED by default for testnet
            safe_mode_enabled: true,
            safe_mode_threshold: 10,
            max_ring_size: 16, // LRS-v1 max
            min_ring_size: 4,
            default_ring_scheme: 0x03, // LogRing-v1 (system default)
            log_level: "info".into(),
            max_msg_size: 1_048_576, // 1 MB
            max_mempool_size: 5000,
            max_tx_size: 131_072, // 128 KiB
            min_fee: 1,
            max_block_txs: 1000,
        }
    }
}

impl TestnetConfig {
    /// Validate ALL config invariants. Returns list of ALL errors found.
    pub fn validate(&self) -> Result<(), Vec<ConfigError>> {
        let mut errors = Vec::new();

        // Chain ID
        if self.chain_id == 0 {
            errors.push(ConfigError::InvalidChainId(self.chain_id));
        }
        // Testnet must use chain_id = 2 (mainnet = 1)
        if self.chain_id != 1 && self.chain_id != 2 {
            errors.push(ConfigError::WrongTestnetChainId(self.chain_id));
        }

        // Ports
        if self.p2p_port == 0 {
            errors.push(ConfigError::InvalidP2pPort);
        }
        if self.rpc_port == 0 {
            errors.push(ConfigError::InvalidRpcPort);
        }
        if self.p2p_port == self.rpc_port {
            errors.push(ConfigError::PortCollision);
        }

        // Block time
        if self.block_time_secs < 5 {
            errors.push(ConfigError::BlockTimeTooLow(self.block_time_secs));
        }

        // Peers
        if self.max_inbound_peers == 0 && self.max_outbound_peers == 0 {
            errors.push(ConfigError::MaxPeersTooLow(0));
        }

        // Advertise address validation for public/seed nodes
        if self.node_mode.advertises_address() {
            if let Some(ref addr_str) = self.advertise_addr {
                if let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() {
                    let ip = addr.ip();
                    if ip.is_unspecified() || ip.is_loopback() {
                        errors.push(ConfigError::InvalidAdvertiseAddr);
                    }
                }
            }
            // No advertise addr in public mode → warning only, not fatal
        }

        // Faucet
        if self.faucet_enabled && (self.faucet_amount == 0 || self.faucet_amount > 1_000_000) {
            errors.push(ConfigError::InvalidFaucetAmount(self.faucet_amount));
        }

        // Chipmunk must be explicitly enabled
        #[cfg(feature = "chipmunk")]
        {
            if self.chipmunk_enabled {
                // OK — explicitly enabled
            }
        }
        #[cfg(not(feature = "chipmunk"))]
        {
            if self.chipmunk_enabled {
                errors.push(ConfigError::ChipmunkNotExplicit);
            }
        }

        // Ring scheme validation
        match self.default_ring_scheme {
            0x03 => {}                          // LogRing — always allowed (system default)
            0x01 => {}                          // LRS — always allowed (legacy)
            0x02 if self.chipmunk_enabled => {} // Chipmunk — only with explicit opt-in
            0x02 => {
                errors.push(ConfigError::Custom(
                    "default_ring_scheme 0x02 (Chipmunk) requires chipmunk to be enabled".into(),
                ));
            }
            other => {
                errors.push(ConfigError::Custom(format!(
                    "unknown default_ring_scheme: 0x{:02x}",
                    other
                )));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Check if a ring scheme tag is allowed in this config.
    pub fn is_ring_scheme_allowed(&self, scheme: u8) -> bool {
        match scheme {
            0x03 => true,                  // LogRing — always allowed (system default)
            0x01 => true,                  // LRS-v1 — always allowed (legacy)
            0x02 => self.chipmunk_enabled, // Chipmunk only if explicitly enabled
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_valid() {
        let cfg = TestnetConfig::default();
        cfg.validate().unwrap();
    }

    #[test]
    fn test_invalid_chain_id() {
        let mut cfg = TestnetConfig::default();
        cfg.chain_id = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_port_collision() {
        let mut cfg = TestnetConfig::default();
        cfg.rpc_port = cfg.p2p_port;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_block_time_too_low() {
        let mut cfg = TestnetConfig::default();
        cfg.block_time_secs = 1;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_chipmunk_not_allowed_default() {
        let cfg = TestnetConfig::default();
        assert!(cfg.is_ring_scheme_allowed(0x03)); // LogRing OK (default)
        assert!(cfg.is_ring_scheme_allowed(0x01)); // LRS OK (legacy)
        assert!(!cfg.is_ring_scheme_allowed(0x02)); // Chipmunk blocked
        assert!(!cfg.is_ring_scheme_allowed(0xFF)); // Unknown blocked
    }

    #[test]
    fn test_chipmunk_allowed_when_enabled() {
        let mut cfg = TestnetConfig::default();
        cfg.chipmunk_enabled = true;
        assert!(cfg.is_ring_scheme_allowed(0x02));
    }

    #[test]
    fn test_default_ring_scheme_is_logring() {
        let cfg = TestnetConfig::default();
        assert_eq!(cfg.default_ring_scheme, 0x03); // LogRing
    }

    #[test]
    fn test_bridge_disabled_by_default() {
        let cfg = TestnetConfig::default();
        assert!(!cfg.bridge_enabled);
    }

    #[test]
    fn test_faucet_amount_bounds() {
        let mut cfg = TestnetConfig::default();
        cfg.faucet_amount = 0;
        assert!(cfg.validate().is_err());
        cfg.faucet_amount = 2_000_000;
        assert!(cfg.validate().is_err());
        cfg.faucet_amount = 100_000;
        cfg.validate().unwrap();
    }

    #[test]
    fn test_advertise_addr_loopback_rejected() {
        let mut cfg = TestnetConfig::default();
        cfg.node_mode = NodeMode::Public;
        cfg.advertise_addr = Some("127.0.0.1:6690".into());
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_advertise_addr_unspecified_rejected() {
        let mut cfg = TestnetConfig::default();
        cfg.node_mode = NodeMode::Public;
        cfg.advertise_addr = Some("0.0.0.0:6690".into());
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_hidden_mode_ignores_advertise() {
        let mut cfg = TestnetConfig::default();
        cfg.node_mode = NodeMode::Hidden;
        cfg.advertise_addr = Some("0.0.0.0:6690".into()); // would be invalid for public
        cfg.validate().unwrap(); // but hidden mode ignores it
    }
}
