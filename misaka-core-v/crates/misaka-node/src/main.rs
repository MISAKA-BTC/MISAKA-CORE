//! MISAKA Network — PQ-first UTXO node.
//!
//! # Consensus Modes
//!
//! - **v1 (default):** Linear blockchain with single-parent blocks
//! - **v2 (`experimental_dag` feature):** GhostDAG BlockDAG with multi-parent blocks
//!
//! Build with DAG consensus:
//!   `cargo build -p misaka-node --features experimental_dag`
//!
//! # Mainnet Safety
//!
//! - Config validation is MANDATORY at startup.
//! - Dev features are rejected in release builds.
//! - MockVerifier is rejected when bridge is enabled.

// ── Production Safety: reject dev feature in release builds ──
#[cfg(all(not(debug_assertions), feature = "dev"))]
compile_error!("DO NOT compile production build with 'dev' feature enabled.");

#[cfg(all(not(debug_assertions), feature = "dev-rpc"))]
compile_error!("DO NOT compile production build with 'dev-rpc' feature enabled.");

#[cfg(all(not(debug_assertions), feature = "dev-bridge-mock"))]
compile_error!("DO NOT compile production build with 'dev-bridge-mock' feature enabled.");

// ── DAG mode is EXPERIMENTAL — block in release builds ──
#[cfg(all(not(debug_assertions), feature = "experimental_dag"))]
compile_error!(
    "DO NOT compile production build with 'experimental_dag' feature. \
     DAG consensus is incomplete (no P2P, placeholder UTXO root, placeholder checkpoint). \
     Use linear chain (v1) for mainnet."
);

// Usage:
//   misaka-node                              # v1 public full node (no block production)
//   misaka-node --mode hidden --validator    # v1 hidden validator mode
//   misaka-node --block-time 10 --validator  # v1 fast blocks for testing
//
// DAG mode (requires --features experimental_dag):
//   misaka-node --validator                  # DAG validator node
//   misaka-node --dag-k 18 --validator       # custom GhostDAG k parameter

pub mod config;
pub mod config_validation;

// ── v1 modules (linear chain) ──
#[cfg(not(feature = "experimental_dag"))]
pub mod chain_store;
#[cfg(not(feature = "experimental_dag"))]
pub mod block_producer;
#[cfg(not(feature = "experimental_dag"))]
pub mod rpc_server;
#[cfg(not(feature = "experimental_dag"))]
pub mod p2p_network;
#[cfg(not(feature = "experimental_dag"))]
pub mod sync;

// ── v2 modules (DAG) ──
#[cfg(feature = "experimental_dag")]
pub mod dag_rpc;

#[cfg(not(feature = "experimental_dag"))]
pub use misaka_execution::block_apply::{self, execute_block, rollback_last_block, BlockResult};

use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, Level};
use tracing_subscriber::FmtSubscriber;

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

    /// Faucet drip amount in base units (0 = disabled)
    #[arg(long, default_value = "1000000")]
    faucet_amount: u64,

    /// Faucet cooldown per address in milliseconds
    #[arg(long, default_value = "300000")]
    faucet_cooldown_ms: u64,

    // ─── P2P overrides ───────────────────────────────────

    /// External address to advertise to peers for discovery.
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

    // ─── DAG-specific options ────────────────────────────

    /// GhostDAG k parameter (concurrent block tolerance).
    /// Only used with --features experimental_dag.
    #[arg(long, default_value = "18")]
    dag_k: u64,

    /// DAG checkpoint interval (blue_score units).
    #[arg(long, default_value = "50")]
    dag_checkpoint_interval: u64,

    /// Maximum transactions per DAG block.
    #[arg(long, default_value = "256")]
    dag_max_txs: usize,

    /// DAG mempool maximum size.
    #[arg(long, default_value = "10000")]
    dag_mempool_size: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // ════════════════════════════════════════════════════════
    //  共通初期化 (v1/v2 共通)
    // ════════════════════════════════════════════════════════

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

    // ── Runtime Defense-in-Depth: reject dev features on production networks ──
    // This is a SECOND layer after compile_error! guards above.
    // Catches edge cases where debug builds accidentally run against mainnet.
    {
        let is_mainnet = cli.chain_id == 1;
        let mut dev_features_active = Vec::new();

        #[cfg(feature = "dev")]
        dev_features_active.push("dev");
        #[cfg(feature = "dev-rpc")]
        dev_features_active.push("dev-rpc");
        #[cfg(feature = "dev-bridge-mock")]
        dev_features_active.push("dev-bridge-mock");
        #[cfg(feature = "faucet")]
        dev_features_active.push("faucet");

        if is_mainnet && !dev_features_active.is_empty() {
            error!("╔═══════════════════════════════════════════════════════════╗");
            error!("║  FATAL: Dev features active on MAINNET (chain_id=1)     ║");
            error!("║  Active features: {:?}", dev_features_active);
            error!("║  Refusing to start. Rebuild WITHOUT dev features.       ║");
            error!("╚═══════════════════════════════════════════════════════════╝");
            std::process::exit(1);
        }

        if !dev_features_active.is_empty() {
            warn!("⚠ Dev features active: {:?} — DO NOT use in production!", dev_features_active);
        }
    }

    // ── MANDATORY: Config Validation ──
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
            Ok(()) => {
                info!("Config validation passed (chain_id={}, mode={}, p2p={}, rpc={})",
                    cfg.chain_id, node_mode, cfg.p2p_port, cfg.rpc_port);
            }
            Err(errors) => {
                for e in &errors {
                    error!("Config validation FAILED: {}", e);
                }
                std::process::exit(1);
            }
        }
    }

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

    // ── Crash Recovery Check ──
    {
        let data_path = std::path::Path::new(&cli.data_dir);
        let (recovered_height, recovered_root) = misaka_storage::run_startup_check(data_path);
        if recovered_height > 0 {
            info!(
                "Recovered from persistent state: height={}, root={}",
                recovered_height,
                hex::encode(&recovered_root[..8])
            );
        }
    }

    // ════════════════════════════════════════════════════════
    //  分岐: v1 (linear chain) vs v2 (DAG)
    // ════════════════════════════════════════════════════════

    #[cfg(feature = "experimental_dag")]
    {
        start_dag_node(cli, node_mode, role, p2p_config).await
    }

    #[cfg(not(feature = "experimental_dag"))]
    {
        start_v1_node(cli, node_mode, role, p2p_config).await
    }
}

// ════════════════════════════════════════════════════════════════
//  v2: DAG Node Startup
// ════════════════════════════════════════════════════════════════

#[cfg(feature = "experimental_dag")]
async fn start_dag_node(
    cli: Cli,
    node_mode: NodeMode,
    role: NodeRole,
    p2p_config: P2pConfig,
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

    // ══════════════════════════════════════════════════════
    //  EXPERIMENTAL GUARD (C3 audit fix)
    //
    //  DAG consensus is NOT production-ready:
    //  - P2P relay is not implemented (placeholder only)
    //  - Finality monitor uses genesis_hash as checkpoint
    //  - UTXO state transitions are not persisted in DAG mode
    //  - State root in DAG blocks is zeroed
    //
    //  Require explicit opt-in via environment variable.
    // ══════════════════════════════════════════════════════
    if std::env::var("MISAKA_DAG_EXPERIMENTAL").as_deref() != Ok("1") {
        error!("╔═══════════════════════════════════════════════════════════╗");
        error!("║  DAG CONSENSUS IS EXPERIMENTAL — NOT PRODUCTION READY   ║");
        error!("║                                                          ║");
        error!("║  Missing subsystems:                                     ║");
        error!("║  • P2P block relay (placeholder only)                    ║");
        error!("║  • Persistent UTXO state transitions                     ║");
        error!("║  • Real finality checkpoints                             ║");
        error!("║                                                          ║");
        error!("║  To run anyway:  MISAKA_DAG_EXPERIMENTAL=1               ║");
        error!("╚═══════════════════════════════════════════════════════════╝");
        std::process::exit(1);
    }

    warn!("⚠ DAG CONSENSUS EXPERIMENTAL MODE — NOT FOR PRODUCTION USE ⚠");

    // ══════════════════════════════════════════════════════
    //  Banner
    // ══════════════════════════════════════════════════════

    info!("╔═══════════════════════════════════════════════════════════╗");
    info!("║  MISAKA Network v2.0.0-alpha — Privacy BlockDAG (DAG)  ║");
    info!("║  Consensus: GhostDAG (k={})                             ║", cli.dag_k);
    info!("╚═══════════════════════════════════════════════════════════╝");

    let mode_label = match node_mode {
        NodeMode::Public => "🌐 PUBLIC  — accepts inbound, advertises IP",
        NodeMode::Hidden => "🔒 HIDDEN  — outbound only, IP never advertised",
        NodeMode::Seed   => "🌱 SEED    — bootstrap node, peer discovery",
    };
    info!("Mode: {}", mode_label);
    info!("Role: {} (block production {})", role,
        if role.produces_blocks() { "ENABLED" } else { "disabled" });

    // ══════════════════════════════════════════════════════
    //  Layer 1: Storage & State (基盤層)
    // ══════════════════════════════════════════════════════

    // ── 1a. UTXO Set (v1 資産をそのまま流用) ──
    let utxo_set = misaka_storage::utxo_set::UtxoSet::new(1000);
    info!("Layer 1: UtxoSet initialized (max_delta_history=1000)");

    // ── 1b. Genesis ブロック生成 ──
    let now_ms = chrono::Utc::now().timestamp_millis() as u64;

    let genesis_header = DagBlockHeader {
        version: DAG_VERSION,
        parents: vec![],
        timestamp_ms: now_ms,
        tx_root: ZERO_HASH,
        proposer_id: [0u8; 32], // Genesis has no proposer
        nonce: 0,
        blue_score: 0,
        bits: 0,
    };
    let genesis_hash = genesis_header.compute_hash();

    // ── 1c. DAG Store 初期化 (Genesis で bootstrap) ──
    let dag_store = Arc::new(ThreadSafeDagStore::new(genesis_hash, genesis_header));

    info!(
        "Layer 1: DAG Store initialized | genesis={}",
        hex::encode(&genesis_hash[..8])
    );

    // ══════════════════════════════════════════════════════
    //  Layer 2: Consensus & Finality (合意形成層)
    // ══════════════════════════════════════════════════════

    // ── 2a. GhostDAG エンジン ──
    let ghostdag = GhostDagManager::new(cli.dag_k, genesis_hash);
    info!(
        "Layer 2: GhostDAG engine initialized (k={}, genesis={})",
        cli.dag_k,
        hex::encode(&genesis_hash[..8])
    );

    // ── 2b. Finality マネージャ ──
    let finality_manager = FinalityManager::new(cli.dag_checkpoint_interval);
    info!(
        "Layer 2: Finality manager initialized (checkpoint_interval={})",
        cli.dag_checkpoint_interval
    );

    // ══════════════════════════════════════════════════════
    //  Layer 3: Execution (遅延状態評価層)
    // ══════════════════════════════════════════════════════

    // ── 3. DagStateManager ──
    //
    // 既知の Key Image 集合で初期化。
    // 新規起動時は空、チェックポイントからの復元時は
    // 永続化された KI セットを渡す。
    let state_manager = DagStateManager::new(HashSet::new());
    info!("Layer 3: DAG State Manager initialized (delayed evaluation mode)");

    // ══════════════════════════════════════════════════════
    //  Layer 4: Mempool & Block Production (生成層)
    // ══════════════════════════════════════════════════════

    // ── 4a. DAG Mempool ──
    let mempool = DagMempool::new(cli.dag_mempool_size);
    info!(
        "Layer 4: DAG Mempool initialized (max_size={})",
        cli.dag_mempool_size
    );

    // ── 4b. Proposer ID (バリデータ公開鍵ハッシュ) ──
    let proposer_id: [u8; 32] = {
        use sha3::{Sha3_256, Digest};
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_DAG_PROPOSER:");
        h.update(cli.name.as_bytes());
        h.update(cli.validator_index.to_le_bytes());
        h.finalize().into()
    };

    // ══════════════════════════════════════════════════════
    //  DI 結合: DagNodeState (全レイヤーの統合)
    // ══════════════════════════════════════════════════════
    //
    // ┌─────────────────────────────────────────────────┐
    // │              DagNodeState                       │
    // │  ┌────────────┐  ┌───────────────┐             │
    // │  │  dag_store  │  │   ghostdag     │  Layer 1+2 │
    // │  └────────────┘  └───────────────┘             │
    // │  ┌────────────────────┐  ┌───────────┐         │
    // │  │  state_manager      │  │  utxo_set  │ Layer 3 │
    // │  └────────────────────┘  └───────────┘         │
    // │  ┌────────────┐  ┌──────────────┐              │
    // │  │  mempool    │  │  finality_mgr │  Layer 4    │
    // │  └────────────┘  └──────────────┘              │
    // └─────────────────────────────────────────────────┘

    let dag_node_state = DagNodeState {
        dag_store: dag_store.clone(),
        ghostdag,
        state_manager,
        utxo_set,
        mempool,
        chain_id: cli.chain_id,
        proposer_id,
        genesis_hash,
        blocks_produced: 0,
    };

    let shared_state: Arc<RwLock<DagNodeState>> = Arc::new(RwLock::new(dag_node_state));

    info!("DI wiring complete — all layers bound to DagNodeState");

    // ══════════════════════════════════════════════════════
    //  Layer 5: Network (DAG P2P)
    // ══════════════════════════════════════════════════════

    // TODO Phase 3: DAG P2P ネットワーク (dag_p2p.rs)
    // let p2p = Arc::new(DagP2pNetwork::new(dag_store.clone(), ...));
    // let p2p_addr: SocketAddr = format!("0.0.0.0:{}", cli.p2p_port).parse()?;
    // tokio::spawn(async move { p2p.start_listening().await; });
    info!("Layer 5: DAG P2P — placeholder (Phase 3)");

    // ══════════════════════════════════════════════════════
    //  Layer 6: RPC Server (DAG RPC)
    // ══════════════════════════════════════════════════════

    let rpc_addr: SocketAddr = format!("0.0.0.0:{}", cli.rpc_port).parse()?;
    let rpc_state = shared_state.clone();

    let rpc_handle = tokio::spawn(async move {
        if let Err(e) = dag_rpc::run_dag_rpc_server(rpc_state, rpc_addr).await {
            error!("DAG RPC server error: {}", e);
        }
    });

    info!("Layer 6: DAG RPC server starting on :{}", cli.rpc_port);

    // ══════════════════════════════════════════════════════
    //  Layer 7: Block Production Loop
    // ══════════════════════════════════════════════════════

    info!(
        "Node '{}' ready | mode={} | role={} | consensus=GhostDAG(k={}) | RPC=:{} | block={}s",
        cli.name, node_mode, role, cli.dag_k, cli.rpc_port, cli.block_time,
    );

    if role.produces_blocks() {
        info!("Starting DAG block production loop (interval={}s, max_txs={})",
            cli.block_time, cli.dag_max_txs);

        // ── Finality monitoring task ──
        let finality_state = shared_state.clone();
        let finality_interval = cli.dag_checkpoint_interval;
        tokio::spawn(async move {
            run_finality_monitor(finality_state, finality_interval).await;
        });

        // ── Block production (メインループ — ブロッキング) ──
        run_dag_block_producer(
            shared_state.clone(),
            cli.block_time,
            cli.dag_max_txs,
        ).await;
    } else {
        info!("Block production disabled — running as DAG full node");
        // Keep alive
        loop { tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await; }
    }

    Ok(())
}

/// ファイナリティ監視タスク — 定期的にチェックポイントを作成する。
#[cfg(feature = "experimental_dag")]
async fn run_finality_monitor(
    state: Arc<RwLock<misaka_dag::DagNodeState>>,
    checkpoint_interval: u64,
) {
    use misaka_dag::dag_finality::FinalityManager;

    let mut finality = FinalityManager::new(checkpoint_interval);
    let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(30));

    loop {
        ticker.tick().await;

        let guard = state.read().await;
        let max_score = guard.dag_store.max_blue_score();

        if finality.should_checkpoint(max_score) {
            let stats = &guard.state_manager.stats;
            let cp = finality.create_checkpoint(
                // SEC: use actual selected parent chain tip, not genesis
                guard.dag_store.selected_parent_chain_tip()
                    .unwrap_or_else(|| {
                        panic!(
                            "DAG checkpoint: no selected parent chain tip available at score {}. \
                             Cannot create checkpoint without a finalized chain tip.",
                            max_score
                        )
                    }),
                max_score,
                // SEC: compute actual UTXO merkle root, not [0u8; 32]
                guard.state_manager.compute_utxo_root()
                    .unwrap_or_else(|e| {
                        panic!(
                            "DAG checkpoint: failed to compute UTXO merkle root: {}. \
                             Cannot create checkpoint without valid state root.",
                            e
                        )
                    }),
                stats.txs_applied + stats.txs_coinbase,
                stats.txs_applied,
            );
            info!(
                "Checkpoint created: score={}, txs={}, ki={}",
                cp.blue_score, cp.total_applied_txs, cp.total_key_images,
            );
        }
    }
}

// ════════════════════════════════════════════════════════════════
//  v1: Linear Chain Node Startup (既存コード — 変更なし)
// ════════════════════════════════════════════════════════════════

#[cfg(not(feature = "experimental_dag"))]
async fn start_v1_node(
    cli: Cli,
    node_mode: NodeMode,
    role: NodeRole,
    p2p_config: P2pConfig,
) -> anyhow::Result<()> {
    use crate::block_producer::{NodeState, SharedState};
    use crate::chain_store::ChainStore;

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
        mempool: misaka_mempool::UtxoMempool::new(10_000),
        utxo_set: misaka_storage::utxo_set::UtxoSet::new(1000),
        coinbase_pending: Vec::new(),
        faucet_drips: std::collections::HashMap::new(),
        faucet_amount: cli.faucet_amount,
        faucet_cooldown_ms: cli.faucet_cooldown_ms,
    }));

    // Parse peer addresses
    let static_peers: Vec<SocketAddr> = cli.peers.iter()
        .filter_map(|s| s.parse().ok())
        .collect();

    // Start P2P
    let p2p = Arc::new(p2p_network::P2pNetwork::new(cli.chain_id, cli.name.clone(), p2p_config.clone()));
    let p2p_addr: SocketAddr = format!("0.0.0.0:{}", cli.p2p_port).parse()?;
    p2p.start_listener(p2p_addr).await?;

    // Connect to peers
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

    // RPC server
    let rpc_addr: SocketAddr = format!("0.0.0.0:{}", cli.rpc_port).parse()?;
    let rpc_state = state.clone();
    let rpc_p2p = p2p.clone();
    tokio::spawn(async move {
        if let Err(e) = rpc_server::run_rpc_server(rpc_state, rpc_p2p, rpc_addr).await {
            error!("RPC server error: {}", e);
        }
    });

    info!(
        "Node '{}' ready | mode={} | role={} | RPC=:{} | P2P=:{} | block={}s | val={}/{}",
        cli.name, node_mode, role, cli.rpc_port, cli.p2p_port, cli.block_time,
        cli.validator_index, cli.validators
    );

    // Block production
    if role.produces_blocks() {
        block_producer::run_block_producer(state.clone(), cli.block_time, cli.validator_index).await;
    } else {
        loop { tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await; }
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════
//  Tests
// ════════════════════════════════════════════════════════════════

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

    #[cfg(not(feature = "experimental_dag"))]
    #[test]
    fn test_chain_store_genesis() {
        let mut chain = chain_store::ChainStore::new();
        let g = chain.store_genesis(1_700_000_000_000);
        assert_eq!(g.height, 0);
        assert_ne!(g.hash, [0u8; 32]);
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
