//! MISAKA Network — Post-Quantum Privacy BlockDAG
//!
//! # Architecture: Q-DAG-CT + Unified ZKP
//!
//! - **GhostDAG BlockDAG**: Multi-parent blocks, deterministic total ordering
//! - **Unified ZKP**: Position-hiding membership + algebraic nullifier + key ownership
//! - **ML-DSA-65 / ML-KEM-768**: Post-quantum identity + stealth addresses
//! - **BDLOP Commitments**: Lattice-based confidential amounts
//!
//! All linear chain code has been removed. DAG is the sole consensus mechanism.
//! All ring signatures (LogRing) have been replaced by Unified ZKP.

// Usage:
//   misaka-node                              # public full node (observer)
//   misaka-node --mode public --validator    # validator mode
//   misaka-node --mode hidden --validator    # hidden validator mode

pub mod config;
pub mod config_validation;
pub mod dag_rpc;

use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, Level};
use tracing_subscriber::FmtSubscriber;

use crate::config::{NodeMode, NodeRole, P2pConfig};

#[derive(Parser, Debug)]
#[command(name = "misaka-node", version, about = "MISAKA Network — Post-Quantum Privacy BlockDAG")]
struct Cli {
    #[arg(long, default_value = "misaka-node-0")]
    name: String,
    #[arg(long, default_value = "public")]
    mode: String,
    #[arg(long, default_value = "3001")]
    rpc_port: u16,
    #[arg(long, default_value = "9733")]
    p2p_port: u16,
    #[arg(long, default_value = "2")]
    chain_id: u32,
    #[arg(long)]
    validator: bool,
    #[arg(long, default_value = "0")]
    validator_index: u32,
    #[arg(long, default_value = "1")]
    validators: u32,
    #[arg(long)]
    peers: Vec<String>,
    #[arg(long)]
    seeds: Vec<String>,
    #[arg(long, default_value = "info")]
    log_level: String,
    #[arg(long, default_value = "5")]
    block_time: u64,
    #[arg(long)]
    advertise_addr: Option<String>,
    #[arg(long)]
    max_inbound_peers: Option<usize>,
    #[arg(long)]
    max_outbound_peers: Option<usize>,
    #[arg(long)]
    outbound_only: bool,
    #[arg(long)]
    hide_my_ip: bool,
    #[arg(long)]
    proxy: Option<String>,
    #[arg(long, default_value = "./misaka-data")]
    data_dir: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // ── Tracing ──
    let level = match cli.log_level.as_str() {
        "trace" => Level::TRACE, "debug" => Level::DEBUG,
        "warn" => Level::WARN, "error" => Level::ERROR, _ => Level::INFO,
    };
    tracing::subscriber::set_global_default(
        FmtSubscriber::builder().with_max_level(level).with_target(false).compact().finish()
    )?;

    let node_mode = NodeMode::from_str_loose(&cli.mode);

    // ── Config Validation ──
    {
        use config_validation::TestnetConfig;
        let cfg = TestnetConfig {
            chain_id: cli.chain_id,
            chain_name: if cli.chain_id == 1 { "MISAKA Mainnet".into() } else { "MISAKA Testnet".into() },
            p2p_port: cli.p2p_port,
            rpc_port: cli.rpc_port,
            block_time_secs: cli.block_time,
            max_inbound_peers: cli.max_inbound_peers.unwrap_or(32),
            max_outbound_peers: cli.max_outbound_peers.unwrap_or(8),
            node_mode,
            advertise_addr: cli.advertise_addr.clone(),
            seed_nodes: cli.seeds.clone(),
            data_dir: cli.data_dir.clone(),
            ..TestnetConfig::default()
        };
        match cfg.validate() {
            Ok(()) => info!("Config OK (chain={}, mode={}, rpc={}, p2p={})",
                cfg.chain_id, node_mode, cfg.rpc_port, cfg.p2p_port),
            Err(errors) => {
                for e in &errors { error!("Config FAILED: {}", e); }
                std::process::exit(1);
            }
        }
    }

    let advertise_addr: Option<SocketAddr> = cli.advertise_addr
        .as_deref()
        .and_then(|s| s.parse::<SocketAddr>().ok()
            .filter(|addr| config::is_valid_advertise_addr(addr)));

    let role = NodeRole::determine(node_mode, cli.validator, cli.validator_index, cli.validators);
    let p2p_config = P2pConfig::from_mode(node_mode).with_overrides(
        cli.max_inbound_peers, cli.max_outbound_peers,
        cli.outbound_only, cli.hide_my_ip,
        cli.seeds.clone(), cli.proxy.clone(), advertise_addr,
    );

    // ── Crash Recovery ──
    {
        let data_path = std::path::Path::new(&cli.data_dir);
        let (height, root) = misaka_storage::run_startup_check(data_path);
        if height > 0 {
            info!("Recovered: blue_score={}, root={}", height, hex::encode(&root[..8]));
        }
    }

    // ════════════════════════════════════════════════════════
    //  DAG Node Startup (Q-DAG-CT + UnifiedZKP)
    // ════════════════════════════════════════════════════════

    start_dag_node(cli, node_mode, role, p2p_config).await
}

async fn start_dag_node(
    cli: Cli,
    node_mode: NodeMode,
    role: NodeRole,
    _p2p_config: P2pConfig,
) -> anyhow::Result<()> {
    use std::collections::HashSet;
    use misaka_dag::{
        Hash, ZERO_HASH,
        GhostDagManager, DagStateManager,
        DagNodeState, DagMempool,
        dag_store::ThreadSafeDagStore,
        dag_finality::FinalityManager,
        dag_block::{DAG_VERSION, DagBlockHeader},
        dag_block_producer::run_dag_block_producer,
    };

    // ── Banner ──
    info!("╔═══════════════════════════════════════════════════════════╗");
    info!("║  MISAKA Network v3.0.0 — Post-Quantum Privacy BlockDAG  ║");
    info!("║  Q-DAG-CT + Unified ZKP + ML-DSA-65 + BDLOP             ║");
    info!("╚═══════════════════════════════════════════════════════════╝");

    let mode_label = match node_mode {
        NodeMode::Public => "🌐 PUBLIC",
        NodeMode::Hidden => "🔒 HIDDEN",
        NodeMode::Seed   => "🌱 SEED",
    };
    info!("Mode: {} | Role: {} | Chain: {}", mode_label, role, cli.chain_id);

    // ── Genesis ──
    let genesis_header = DagBlockHeader {
        version: DAG_VERSION,
        chain_id: cli.chain_id,
        epoch: 0,
        parents: vec![],
        timestamp_ms: chrono::Utc::now().timestamp_millis() as u64,
        tx_root: ZERO_HASH,
        proposer_id: [0u8; 32],
        proposer_randomness_commitment: [0u8; 32],
        protocol_version: 1,
        blue_score: 0,
    };
    let genesis_hash = genesis_header.compute_hash();

    // ── DAG Store ──
    let dag_store = ThreadSafeDagStore::new(genesis_hash, genesis_header);
    info!("Genesis: hash={}", hex::encode(&genesis_hash[..8]));

    // ── GhostDAG ──
    let k = 18u64;
    let ghostdag = GhostDagManager::new(genesis_hash, k);
    info!("GhostDAG: k={}", k);

    // ── State Manager ──
    let state_manager = DagStateManager::new(HashSet::new());

    // ── Mempool ──
    let mempool = DagMempool::new(10_000);

    // ── Finality Manager ──
    let finality_manager = FinalityManager::new(genesis_hash, 0);

    // ── Proposer ID ──
    let proposer_id = if role.produces_blocks() {
        let pk_hex = std::env::var("MISAKA_VALIDATOR_PK").unwrap_or_else(|_| {
            error!("FATAL: MISAKA_VALIDATOR_PK not set. Use --validator with env var.");
            std::process::exit(1);
        });
        let pk_bytes = hex::decode(&pk_hex).unwrap_or_else(|e| {
            error!("FATAL: Invalid MISAKA_VALIDATOR_PK hex: {}", e);
            std::process::exit(1);
        });
        let mut id = [0u8; 32];
        let hash = misaka_crypto::sha3_256(&pk_bytes);
        id.copy_from_slice(&hash);
        info!("Validator: {}", hex::encode(&id[..8]));
        id
    } else {
        [0u8; 32]
    };

    // ── Shared State ──
    let node_state = DagNodeState {
        dag_store,
        ghostdag,
        state_manager,
        mempool,
        proposer_id,
        block_interval_ms: cli.block_time * 1000,
        max_txs_per_block: 500,
        blocks_produced: 0,
    };
    let shared = Arc::new(RwLock::new(node_state));

    // ── DAG RPC ──
    let rpc_addr: SocketAddr = format!("0.0.0.0:{}", cli.rpc_port).parse()?;
    let rpc_shared = shared.clone();
    tokio::spawn(async move {
        if let Err(e) = dag_rpc::run_dag_rpc(rpc_shared, rpc_addr).await {
            error!("DAG RPC error: {}", e);
        }
    });

    info!("Node '{}' ready | RPC=:{} | P2P=:{} | block={}s",
        cli.name, cli.rpc_port, cli.p2p_port, cli.block_time);

    // ── Block Production ──
    if role.produces_blocks() {
        info!("Block production ENABLED (Q-DAG-CT native)");
        run_dag_block_producer(shared.clone()).await;
    } else {
        info!("Running as observer (no block production)");

        // ── Finality Monitor ──
        let fin_shared = shared.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let s = fin_shared.read().await;
                let tips = s.dag_store.get_current_tips();
                let max_score = s.dag_store.max_blue_score();
                info!("Status: tips={}, max_blue_score={}, blocks={}",
                    tips.len(), max_score, s.blocks_produced);
            }
        });

        // Keep alive
        loop { tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await; }
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_mode_parse() {
        assert_eq!(NodeMode::from_str_loose("public"), NodeMode::Public);
        assert_eq!(NodeMode::from_str_loose("hidden"), NodeMode::Hidden);
        assert_eq!(NodeMode::from_str_loose("seed"), NodeMode::Seed);
        assert_eq!(NodeMode::from_str_loose("invalid"), NodeMode::Public);
    }

    #[test]
    fn test_public_mode_no_block_production_by_default() {
        let role = NodeRole::determine(NodeMode::Public, false, 0, 1);
        assert!(!role.produces_blocks());
    }

    #[test]
    fn test_seed_mode_never_produces_blocks() {
        let role = NodeRole::determine(NodeMode::Seed, true, 0, 1);
        assert!(!role.produces_blocks());
    }

    #[test]
    fn test_validator_flag_enables_block_production() {
        let role = NodeRole::determine(NodeMode::Public, true, 0, 1);
        assert!(role.produces_blocks());
    }
}
