//! MISAKA Network — PQ-first UTXO node.
//!
//! Usage:
//!   misaka-node                              # public full node (no block production)
//!   misaka-node --mode hidden --validator    # hidden validator mode
//!   misaka-node --mode seed --p2p-port 6690  # seed node
//!   misaka-node --block-time 10 --validator  # fast blocks for testing
//!   misaka-node --mode hidden --proxy 127.0.0.1:9050  # Tor (future)
//!
//! Advertise address:
//!   --advertise-addr 133.167.126.51:6690
//!     Tells peers to connect back on this external address.
//!     Without this, the node will NOT be discoverable via peer exchange.
//!     Ignored when --hide-my-ip or --mode hidden is set.

pub mod config;
pub mod chain_store;
pub mod block_producer;
pub mod rpc_server;
pub mod p2p_network;
pub mod sync;

pub use misaka_execution::block_apply::{self, execute_block, rollback_last_block, BlockResult};

use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use crate::block_producer::{NodeState, SharedState};
use crate::chain_store::ChainStore;
use crate::config::{NodeMode, NodeRole, P2pConfig};

#[derive(Parser, Debug)]
#[command(name = "misaka-node", version, about = "MISAKA Network validator node")]
struct Cli {
    /// Node name
    #[arg(long, default_value = "misaka-node-0")]
    name: String,

    /// P2P mode: public, hidden, seed
    #[arg(long, default_value = "public")]
    mode: String,

    /// RPC listen port
    #[arg(long, default_value = "3001")]
    rpc_port: u16,

    /// P2P listen port
    #[arg(long, default_value = "6690")]
    p2p_port: u16,

    /// Block time in seconds
    #[arg(long, default_value = "60")]
    block_time: u64,

    /// Validator index (for multi-validator testnet)
    #[arg(long, default_value = "0")]
    validator_index: usize,

    /// Total validator count
    #[arg(long, default_value = "1")]
    validators: usize,

    /// Enable block production (validator role).
    /// Without this flag, the node runs as a full node and does NOT produce blocks.
    #[arg(long)]
    validator: bool,

    /// Static peers (comma-separated)
    #[arg(long, value_delimiter = ',')]
    peers: Vec<String>,

    /// Seed nodes (comma-separated)
    #[arg(long, value_delimiter = ',')]
    seeds: Vec<String>,

    /// Data directory
    #[arg(long, default_value = "./data")]
    data_dir: String,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Chain ID
    #[arg(long, default_value = "2")]
    chain_id: u32,

    // ─── P2P overrides ───────────────────────────────────

    /// External address to advertise to peers for discovery.
    /// Example: --advertise-addr 133.167.126.51:6690
    /// If not set, this node will NOT appear in peer exchange.
    /// Ignored when --hide-my-ip is set.
    #[arg(long, value_name = "HOST:PORT")]
    advertise_addr: Option<String>,

    /// Force outbound-only (no inbound connections)
    #[arg(long)]
    outbound_only: bool,

    /// Do not advertise this node's IP to peers
    #[arg(long)]
    hide_my_ip: bool,

    /// Max inbound peer connections
    #[arg(long)]
    max_inbound_peers: Option<usize>,

    /// Max outbound peer connections
    #[arg(long)]
    max_outbound_peers: Option<usize>,

    /// SOCKS5 proxy address for Tor (future)
    #[arg(long)]
    proxy: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Tracing
    let level = match cli.log_level.as_str() {
        "trace" => Level::TRACE, "debug" => Level::DEBUG,
        "warn" => Level::WARN, "error" => Level::ERROR, _ => Level::INFO,
    };
    tracing::subscriber::set_global_default(
        FmtSubscriber::builder().with_max_level(level).with_target(false).compact().finish()
    )?;

    // Parse NodeMode
    let node_mode = NodeMode::from_str_loose(&cli.mode);

    // Parse advertise address
    let advertise_addr: Option<SocketAddr> = cli.advertise_addr
        .as_deref()
        .and_then(|s| {
            match s.parse::<SocketAddr>() {
                Ok(addr) => {
                    if config::is_valid_advertise_addr(&addr) {
                        Some(addr)
                    } else {
                        warn!("Invalid --advertise-addr '{}': must not be 0.0.0.0/loopback", s);
                        None
                    }
                }
                Err(e) => {
                    warn!("Failed to parse --advertise-addr '{}': {}", s, e);
                    None
                }
            }
        });

    // Determine role
    let role = NodeRole::determine(node_mode, cli.validator, cli.validator_index, cli.validators);

    // Build P2P config
    let p2p_config = P2pConfig::from_mode(node_mode).with_overrides(
        cli.max_inbound_peers,
        cli.max_outbound_peers,
        cli.outbound_only,
        cli.hide_my_ip,
        cli.seeds.clone(),
        cli.proxy.clone(),
        advertise_addr,
    );

    // Banner
    info!("╔═══════════════════════════════════════════════════════════╗");
    info!("║  MISAKA Network v0.4.1 — Post-Quantum Privacy L1       ║");
    info!("╚═══════════════════════════════════════════════════════════╝");

    let mode_label = match node_mode {
        NodeMode::Public => "🌐 PUBLIC  — accepts inbound, advertises IP",
        NodeMode::Hidden => "🔒 HIDDEN  — outbound only, IP never advertised",
        NodeMode::Seed   => "🌱 SEED    — bootstrap node, peer discovery",
    };
    info!("Mode: {}", mode_label);
    info!("Role: {} (block production {})", role,
        if role.produces_blocks() { "ENABLED" } else { "disabled" });

    // Log listen/advertise addresses clearly
    info!("P2P listening on 0.0.0.0:{}", cli.p2p_port);
    if let Some(ref addr) = p2p_config.advertise_addr {
        info!("Advertising as {}", addr);
    } else if p2p_config.advertise_address {
        warn!("No valid advertise address — this node will NOT be discoverable. Use --advertise-addr <HOST:PORT>");
    }

    if !role.produces_blocks() {
        match node_mode {
            NodeMode::Public => info!("Block production disabled for public node (use --validator to enable)"),
            NodeMode::Seed => info!("Block production disabled for seed node"),
            _ => {}
        }
    }

    if cli.proxy.is_some() {
        info!("Proxy: {} (Tor/I2P support is experimental)", cli.proxy.as_deref().unwrap_or(""));
    }

    // Genesis
    let now_ms = chrono::Utc::now().timestamp_millis() as u64;
    let mut chain = ChainStore::new();
    let genesis = chain.store_genesis(now_ms);
    info!("Genesis block: height=0 hash={}", hex::encode(&genesis.hash[..8]));

    // Shared state
    let state: SharedState = Arc::new(RwLock::new(NodeState {
        chain,
        height: 0,
        tx_count_total: 0,
        validator_count: cli.validators,
        genesis_timestamp_ms: now_ms,
        chain_id: cli.chain_id,
        chain_name: if cli.chain_id == 1 { "MISAKA Mainnet".into() } else { "MISAKA Testnet".into() },
        version: "v0.4.1".into(),
        pending_txs: std::collections::VecDeque::new(),
        spent_key_images: std::collections::HashSet::new(),
        faucet_drips: std::collections::HashMap::new(),
    }));

    // Parse peer addresses
    let static_peers: Vec<SocketAddr> = cli.peers.iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    // Start P2P
    let p2p = Arc::new(p2p_network::P2pNetwork::new(cli.chain_id, cli.name.clone(), p2p_config.clone()));
    let p2p_addr: SocketAddr = format!("0.0.0.0:{}", cli.p2p_port).parse()?;
    p2p.start_listener(p2p_addr).await?;

    // Connect to static peers + seed nodes
    let mut all_peers = static_peers;
    for seed in &p2p_config.seed_nodes {
        if let Ok(addr) = seed.parse::<SocketAddr>() {
            all_peers.push(addr);
        }
    }
    if !all_peers.is_empty() {
        info!("Connecting to {} peers...", all_peers.len());
        p2p.connect_to_peers(&all_peers, 0).await;
    }

    // RPC server (pass p2p handle for /api/get_peers)
    let rpc_addr: SocketAddr = format!("0.0.0.0:{}", cli.rpc_port).parse()?;
    let rpc_state = state.clone();
    let rpc_p2p = p2p.clone();
    tokio::spawn(async move {
        if let Err(e) = rpc_server::run_rpc_server(rpc_state, rpc_p2p, rpc_addr).await {
            tracing::error!("RPC server error: {}", e);
        }
    });

    info!(
        "Node '{}' ready | mode={} | role={} | RPC=:{} | P2P=:{} | block={}s | val={}/{}",
        cli.name, node_mode, role, cli.rpc_port, cli.p2p_port, cli.block_time,
        cli.validator_index, cli.validators
    );

    // Block production — only for validator role
    if role.produces_blocks() {
        block_producer::run_block_producer(state.clone(), cli.block_time, cli.validator_index).await;
    } else {
        // Keep the process alive
        loop { tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await; }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_mode_parse() {
        assert_eq!(NodeMode::from_str_loose("public"), NodeMode::Public);
        assert_eq!(NodeMode::from_str_loose("hidden"), NodeMode::Hidden);
        assert_eq!(NodeMode::from_str_loose("HIDDEN"), NodeMode::Hidden);
        assert_eq!(NodeMode::from_str_loose("seed"), NodeMode::Seed);
        assert_eq!(NodeMode::from_str_loose("invalid"), NodeMode::Public);
    }

    #[test]
    fn test_chain_store_genesis() {
        let mut chain = ChainStore::new();
        let g = chain.store_genesis(1_700_000_000_000);
        assert_eq!(g.height, 0);
        assert_ne!(g.hash, [0u8; 32]);
    }

    #[test]
    fn test_public_mode_no_block_production_by_default() {
        // Public mode without --validator → FullNode → no blocks
        let role = NodeRole::determine(NodeMode::Public, false, 0, 1);
        assert!(!role.produces_blocks());
    }

    #[test]
    fn test_seed_mode_never_produces_blocks() {
        // Seed mode even with --validator → FullNode
        let role = NodeRole::determine(NodeMode::Seed, true, 0, 1);
        assert!(!role.produces_blocks());
    }

    #[test]
    fn test_validator_flag_enables_block_production() {
        let role = NodeRole::determine(NodeMode::Public, true, 0, 1);
        assert!(role.produces_blocks());
    }
}
