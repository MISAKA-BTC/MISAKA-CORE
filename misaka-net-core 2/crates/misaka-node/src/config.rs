//! Node configuration — NodeMode, P2P settings, CLI mapping.

use std::net::SocketAddr;
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

    /// Whether this mode participates in block production.
    pub fn can_propose_blocks(&self) -> bool {
        matches!(self, Self::Public | Self::Hidden)
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

// ─── P2P Config ─────────────────────────────────────────────

/// P2P-specific configuration derived from NodeMode + CLI overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pConfig {
    pub mode: NodeMode,
    /// Accept inbound connections (overridable; defaults from mode).
    pub listen: bool,
    /// Advertise our address in Hello/GetPeers (overridable; defaults from mode).
    pub advertise_address: bool,
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
                max_inbound_peers: 48,
                max_outbound_peers: 16,
                seed_nodes: vec![],
                proxy: None,
            },
            NodeMode::Hidden => Self {
                mode,
                listen: false,
                advertise_address: false,
                max_inbound_peers: 0,
                max_outbound_peers: 16,
                seed_nodes: vec![],
                proxy: None,
            },
            NodeMode::Seed => Self {
                mode,
                listen: true,
                advertise_address: true,
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
    ) -> Self {
        if let Some(n) = max_inbound { self.max_inbound_peers = n; }
        if let Some(n) = max_outbound { self.max_outbound_peers = n; }
        if outbound_only {
            self.listen = false;
            self.max_inbound_peers = 0;
        }
        if hide_ip {
            self.advertise_address = false;
        }
        if !seeds.is_empty() {
            self.seed_nodes = seeds;
        }
        self.proxy = proxy;
        self
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
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_name: "misaka-node-0".into(),
            data_dir: "./data".into(),
            rpc_addr: "127.0.0.1:3001".parse().unwrap(),
            p2p_addr: "0.0.0.0:6690".parse().unwrap(),
            static_peers: vec![],
            is_proposer: true,
            validator_index: 0,
            block_time_secs: 60,
            genesis_path: String::new(),
            log_level: "info".into(),
            p2p: P2pConfig::from_mode(NodeMode::Public),
        }
    }
}
