//! Node configuration — NodeMode, NodeRole, P2P settings, CLI mapping.

use std::net::{IpAddr, SocketAddr};
use serde::{Serialize, Deserialize};

// ─── Node Mode ──────────────────────────────────────────────

/// P2P operating mode.
///
/// Controls inbound/outbound behavior, peer advertisement, and discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeMode {
    /// Normal P2P node: accepts inbound, advertises IP, relays everything.
    Public,
    /// Privacy-focused: outbound only, never advertises IP, never in peer lists.
    Hidden,
    /// Bootstrap node: accepts inbound, serves peer discovery, does not propose blocks.
    Seed,
}

impl NodeMode {
    /// Parse from CLI string.
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "hidden" => Self::Hidden,
            "seed" => Self::Seed,
            "validator" => Self::Public, // validator is Public mode + validator role
            _ => Self::Public,
        }
    }

    /// Whether this mode accepts inbound TCP connections.
    pub fn accepts_inbound(&self) -> bool {
        matches!(self, Self::Public | Self::Seed)
    }

    /// Whether this mode advertises its address to peers.
    pub fn advertises_address(&self) -> bool {
        matches!(self, Self::Public | Self::Seed)
    }

    /// Whether this mode relays peer discovery (GetPeers responses).
    pub fn serves_peer_discovery(&self) -> bool {
        matches!(self, Self::Public | Self::Seed)
    }
}

impl std::fmt::Display for NodeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Public => write!(f, "public"),
            Self::Hidden => write!(f, "hidden"),
            Self::Seed => write!(f, "seed"),
        }
    }
}

// ─── Node Role ──────────────────────────────────────────────

/// Node role — determines whether this node participates in block production.
///
/// Separated from NodeMode because mode controls P2P behavior while role
/// controls consensus participation. A public node is NOT a validator
/// unless explicitly configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeRole {
    /// Full node — syncs chain, serves RPC, relays P2P, does NOT produce blocks.
    FullNode,
    /// Validator — produces blocks when it is this node's turn.
    Validator,
}

impl NodeRole {
    /// Determine role from mode + explicit validator flag + validator set params.
    ///
    /// Block production is enabled ONLY when:
    /// - `is_validator` is explicitly true, AND
    /// - mode is not Seed (seed nodes never produce blocks), AND
    /// - `validator_index < validator_count`
    pub fn determine(mode: NodeMode, is_validator: bool, validator_index: usize, validator_count: usize) -> Self {
        if mode == NodeMode::Seed {
            return Self::FullNode;
        }
        if is_validator && validator_index < validator_count && validator_count > 0 {
            Self::Validator
        } else {
            Self::FullNode
        }
    }

    /// Whether this role produces blocks.
    pub fn produces_blocks(&self) -> bool {
        matches!(self, Self::Validator)
    }
}

impl std::fmt::Display for NodeRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FullNode => write!(f, "full-node"),
            Self::Validator => write!(f, "validator"),
        }
    }
}

// ─── Address validation ────────────────────────────────────

/// Check if an IP address is valid for advertising to peers.
///
/// Rejects: unspecified (0.0.0.0, ::), loopback (127.x, ::1).
pub fn is_valid_advertise_ip(ip: &IpAddr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback()
}

/// Check if a socket address is valid for advertising.
pub fn is_valid_advertise_addr(addr: &SocketAddr) -> bool {
    is_valid_advertise_ip(&addr.ip()) && addr.port() > 0
}

// ─── P2P Config ─────────────────────────────────────────────

/// P2P-specific configuration derived from NodeMode + CLI overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pConfig {
    pub mode: NodeMode,
    /// Accept inbound connections (overridable; defaults from mode).
    pub listen: bool,
    /// Advertise our address in Hello/GetPeers (overridable; defaults from mode).
    pub advertise_address: bool,
    /// Explicit advertise address (--advertise-addr). Takes priority over listen addr.
    pub advertise_addr: Option<SocketAddr>,
    /// Max inbound peers (0 for hidden mode).
    pub max_inbound_peers: usize,
    /// Max outbound peers.
    pub max_outbound_peers: usize,
    /// Seed node addresses for initial bootstrap.
    pub seed_nodes: Vec<String>,
    /// SOCKS5 proxy for Tor (future).
    pub proxy: Option<String>,
}

impl P2pConfig {
    /// Build from NodeMode with sensible defaults.
    pub fn from_mode(mode: NodeMode) -> Self {
        match mode {
            NodeMode::Public => Self {
                mode,
                listen: true,
                advertise_address: true,
                advertise_addr: None,
                max_inbound_peers: 48,
                max_outbound_peers: 16,
                seed_nodes: vec![],
                proxy: None,
            },
            NodeMode::Hidden => Self {
                mode,
                listen: false,
                advertise_address: false,
                advertise_addr: None,
                max_inbound_peers: 0,
                max_outbound_peers: 16,
                seed_nodes: vec![],
                proxy: None,
            },
            NodeMode::Seed => Self {
                mode,
                listen: true,
                advertise_address: true,
                advertise_addr: None,
                max_inbound_peers: 128,
                max_outbound_peers: 32,
                seed_nodes: vec![],
                proxy: None,
            },
        }
    }

    /// Apply CLI overrides.
    pub fn with_overrides(
        mut self,
        max_inbound: Option<usize>,
        max_outbound: Option<usize>,
        outbound_only: bool,
        hide_ip: bool,
        seeds: Vec<String>,
        proxy: Option<String>,
        advertise_addr: Option<SocketAddr>,
    ) -> Self {
        if let Some(n) = max_inbound { self.max_inbound_peers = n; }
        if let Some(n) = max_outbound { self.max_outbound_peers = n; }
        if outbound_only {
            self.listen = false;
            self.max_inbound_peers = 0;
        }
        if hide_ip {
            self.advertise_address = false;
            self.advertise_addr = None; // hide-my-ip overrides advertise-addr
        }
        if !seeds.is_empty() {
            self.seed_nodes = seeds;
        }
        self.proxy = proxy;
        // Validate and set advertise addr (only if not hidden/hide-ip)
        if self.advertise_address {
            if let Some(addr) = advertise_addr {
                if is_valid_advertise_addr(&addr) {
                    self.advertise_addr = Some(addr);
                }
                // Invalid advertise addrs are silently dropped (logged at caller)
            }
        }
        self
    }

    /// Get the address string to send in Hello/GetPeers.
    /// Returns None if this node should not advertise.
    pub fn effective_advertise_addr(&self, listen_port: u16) -> Option<String> {
        if !self.advertise_address {
            return None;
        }
        // Priority 1: explicit --advertise-addr
        if let Some(addr) = &self.advertise_addr {
            return Some(addr.to_string());
        }
        // Priority 2: no valid address available → don't advertise
        // (listen addr is typically 0.0.0.0 which is invalid)
        // Caller should log a warning suggesting --advertise-addr
        let _ = listen_port;
        None
    }
}

// ─── Full Node Config ───────────────────────────────────────

/// Complete node configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub node_name: String,
    pub data_dir: String,
    pub rpc_addr: SocketAddr,
    pub p2p_addr: SocketAddr,
    pub static_peers: Vec<SocketAddr>,
    pub is_proposer: bool,
    pub validator_index: usize,
    pub block_time_secs: u64,
    pub genesis_path: String,
    pub log_level: String,
    pub p2p: P2pConfig,
    pub role: NodeRole,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_name: "misaka-node-0".into(),
            data_dir: "./data".into(),
            rpc_addr: "127.0.0.1:3001".parse().unwrap(),
            p2p_addr: "0.0.0.0:6690".parse().unwrap(),
            static_peers: vec![],
            is_proposer: false,
            validator_index: 0,
            block_time_secs: 60,
            genesis_path: String::new(),
            log_level: "info".into(),
            p2p: P2pConfig::from_mode(NodeMode::Public),
            role: NodeRole::FullNode,
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unspecified_addr_rejected() {
        let addr: SocketAddr = "0.0.0.0:6690".parse().unwrap();
        assert!(!is_valid_advertise_addr(&addr));
    }

    #[test]
    fn test_ipv6_unspecified_rejected() {
        let addr: SocketAddr = "[::]:6690".parse().unwrap();
        assert!(!is_valid_advertise_addr(&addr));
    }

    #[test]
    fn test_loopback_rejected() {
        let addr: SocketAddr = "127.0.0.1:6690".parse().unwrap();
        assert!(!is_valid_advertise_addr(&addr));
    }

    #[test]
    fn test_ipv6_loopback_rejected() {
        let addr: SocketAddr = "[::1]:6690".parse().unwrap();
        assert!(!is_valid_advertise_addr(&addr));
    }

    #[test]
    fn test_valid_public_addr_accepted() {
        let addr: SocketAddr = "133.167.126.51:6690".parse().unwrap();
        assert!(is_valid_advertise_addr(&addr));
    }

    #[test]
    fn test_private_addr_accepted() {
        // Private addresses are valid for LANs / testnets
        let addr: SocketAddr = "192.168.1.100:6690".parse().unwrap();
        assert!(is_valid_advertise_addr(&addr));
    }

    #[test]
    fn test_zero_port_rejected() {
        let addr: SocketAddr = "1.2.3.4:0".parse().unwrap();
        assert!(!is_valid_advertise_addr(&addr));
    }

    #[test]
    fn test_public_mode_no_block_production() {
        let role = NodeRole::determine(NodeMode::Public, false, 0, 1);
        assert_eq!(role, NodeRole::FullNode);
        assert!(!role.produces_blocks());
    }

    #[test]
    fn test_seed_mode_never_produces_blocks() {
        // Even if is_validator=true, seed mode never produces blocks
        let role = NodeRole::determine(NodeMode::Seed, true, 0, 1);
        assert_eq!(role, NodeRole::FullNode);
        assert!(!role.produces_blocks());
    }

    #[test]
    fn test_validator_role_requires_explicit_flag() {
        let role = NodeRole::determine(NodeMode::Public, true, 0, 1);
        assert_eq!(role, NodeRole::Validator);
        assert!(role.produces_blocks());
    }

    #[test]
    fn test_validator_index_out_of_range() {
        let role = NodeRole::determine(NodeMode::Public, true, 5, 3);
        assert_eq!(role, NodeRole::FullNode);
    }

    #[test]
    fn test_hidden_mode_can_be_validator() {
        let role = NodeRole::determine(NodeMode::Hidden, true, 0, 4);
        assert_eq!(role, NodeRole::Validator);
    }

    #[test]
    fn test_hide_ip_clears_advertise_addr() {
        let cfg = P2pConfig::from_mode(NodeMode::Public)
            .with_overrides(
                None, None, false, true, vec![], None,
                Some("1.2.3.4:6690".parse().unwrap()),
            );
        assert!(!cfg.advertise_address);
        assert!(cfg.advertise_addr.is_none());
    }

    #[test]
    fn test_effective_advertise_with_explicit_addr() {
        let mut cfg = P2pConfig::from_mode(NodeMode::Public);
        cfg.advertise_addr = Some("133.167.126.51:6690".parse().unwrap());
        assert_eq!(
            cfg.effective_advertise_addr(6690),
            Some("133.167.126.51:6690".to_string())
        );
    }

    #[test]
    fn test_effective_advertise_no_addr_returns_none() {
        let cfg = P2pConfig::from_mode(NodeMode::Public);
        // No explicit advertise addr, listen is 0.0.0.0 → None
        assert_eq!(cfg.effective_advertise_addr(6690), None);
    }

    #[test]
    fn test_hidden_mode_effective_advertise_none() {
        let cfg = P2pConfig::from_mode(NodeMode::Hidden);
        assert_eq!(cfg.effective_advertise_addr(6690), None);
    }
}
