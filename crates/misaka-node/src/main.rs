//! MISAKA Network — PQ-first UTXO node.
//!
//! # Consensus Modes
//!
//! - **DAG (default):** GhostDAG BlockDAG with multi-parent blocks, PQ-encrypted P2P,
//!   economic finality checkpoints. This is the production consensus layer.
//! - **v1 (legacy):** Linear blockchain with single-parent blocks.
//!   Build with: `cargo build -p misaka-node --no-default-features`
//!
//! # Mainnet Safety
//!
//! - Config validation is MANDATORY at startup.
//! - Dev features are rejected in release builds.
//! - MockVerifier is rejected when bridge is enabled.
#![allow(deprecated)] // StakingRegistry::new (wide use; migration to new_with_config_arc is a separate PR)

// ── Production Safety: reject dev feature in release builds ──
#[cfg(all(not(debug_assertions), feature = "dev"))]
compile_error!("DO NOT compile production build with 'dev' feature enabled.");

#[cfg(all(not(debug_assertions), feature = "dev-rpc"))]
compile_error!("DO NOT compile production build with 'dev-rpc' feature enabled.");

#[cfg(all(not(debug_assertions), feature = "dev-bridge-mock"))]
compile_error!("DO NOT compile production build with 'dev-bridge-mock' feature enabled.");

// SEC-FIX [Audit #11]: Additional production safety compile guards.
// Faucet is allowed in release builds when `testnet` feature is enabled.
#[cfg(all(not(debug_assertions), feature = "faucet", not(feature = "testnet")))]
compile_error!(
    "FATAL: 'faucet' feature MUST NOT be compiled in release mode. \
     Faucet endpoints distribute tokens freely and must not be available on mainnet. \
     For public testnet, use --features testnet instead."
);

#[cfg(all(not(debug_assertions), feature = "legacy-p2p"))]
compile_error!(
    "FATAL: 'legacy-p2p' feature MUST NOT be compiled in release mode. \
     The legacy P2P transport uses plaintext TCP with no encryption or peer authentication. \
     Production builds MUST use the DAG PQ-encrypted transport only."
);

// Phase 2c-B D8: TOFU feature and compile_error deleted.

// ── DAG mode: PRODUCTION DEFAULT ──
// The DAG consensus layer has graduated from experimental to default.

// ── ML-DSA-65 VERIFIER ──
// MlDsa65Verifier is now ALWAYS compiled (via misaka_crypto, no feature gate).
// The qdag_ct compile_error guard has been removed because:
// 1. MlDsa65Verifier routes through misaka_crypto::MlDsa65BlockVerifier
// 2. CoreEngine requires BlockVerifier as a mandatory constructor parameter
// 3. There is no code path where blocks can bypass signature verification
// Safety layers remain:
//   Layer 1 (CI): tests/multi_node_chaos.rs MUST pass before tagged releases.
//                 See: scripts/dag_release_gate.sh
//   Layer 2 (Checklist): All of the following must be true for mainnet:
//     ☑ multi_node_chaos::test_random_order_convergence passes
//     ☑ multi_node_chaos::test_crash_and_catchup passes
//     ☑ multi_node_chaos::test_wide_dag_convergence passes
//     ☐ P2P IBD validated on ≥3 testnet nodes (Sakura VPS)
//     ☐ Crash recovery validated (kill -9 mid-sync → restart → correct state)

// Usage (DAG is default):
//   misaka-node --validator                    # DAG validator node
//   misaka-node --dag-k 18 --validator         # custom GhostDAG k parameter
//   misaka-node --mode hidden                  # hidden DAG full node
//
// Legacy v1 linear chain (build with --no-default-features):
//   misaka-node --validator                    # v1 linear validator
//   misaka-node --block-time 10 --validator    # v1 fast blocks for testing

pub mod config;
pub mod config_validation;
pub mod genesis_committee;
pub mod identity;
pub mod indexer;
pub mod metrics;
pub mod migrate;
pub mod rpc_auth;
pub mod rpc_rate_limit;
pub mod safe_mode;
// REMOVED: privacy modules deprecated
pub mod solana_stake_verify;
pub mod sr21_election;
pub mod staking_config_builder;
#[cfg(test)]
pub(crate) mod test_env;
pub mod validator_api;
pub mod validator_lifecycle_bootstrap;
pub mod validator_lifecycle_persistence;

// ── v1 modules (linear chain) ──
#[cfg(not(feature = "dag"))]
pub mod block_producer;
#[cfg(not(feature = "dag"))]
pub mod chain_store;
#[cfg(not(feature = "dag"))]
pub mod p2p_network;
#[cfg(not(feature = "dag"))]
pub mod rpc_server;
// Phase 36 (C-T6-3): SyncEngine excluded from production builds (dag feature is default).
// Retained for non-dag legacy mode only; will be removed when legacy mode is dropped.
#[cfg(not(feature = "dag"))]
pub mod sync;
#[cfg(not(feature = "dag"))]
pub mod sync_relay_transport;

// ── v2 modules (DAG — GhostDAG compat, being phased out) ──
#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
pub mod dag_narwhal_dissemination_service;
#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
pub mod dag_p2p_network;
#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
pub mod dag_p2p_surface;
#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
pub mod dag_p2p_transport;
#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
pub mod dag_rpc;
#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
pub mod dag_rpc_service;
#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
pub mod dag_tx_dissemination_service;
#[cfg(feature = "dag")]
pub mod narwhal_block_relay_transport;
#[cfg(feature = "dag")]
pub mod narwhal_consensus;
#[cfg(feature = "dag")]
pub mod narwhal_runtime_bridge;
// Phase 2c-B D1: narwhal_tx_executor deleted (replaced by utxo_executor)
#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
pub mod jsonrpc;
#[cfg(feature = "dag")]
pub mod utxo_executor;
pub mod ws;
#[cfg(not(feature = "dag"))]
pub use misaka_execution::block_apply::{self, execute_block, undo_last_block, BlockResult};

use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
#[cfg(feature = "dag")]
use tokio::sync::Mutex;
use tokio::sync::RwLock;
#[cfg(feature = "dag")]
use tracing::debug;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use crate::config::{NodeMode, NodeRole, P2pConfig};

#[cfg(feature = "dag")]
#[derive(serde::Serialize, serde::Deserialize)]
struct LocalDagValidatorKeyFile {
    validator_id_hex: String,
    public_key_hex: String,
    secret_key_hex: String,
    stake_weight: u128,
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Permissionless-SR preflight check: returns `true` iff the validator
/// identified by `fingerprint` is present in the `StakingRegistry` AND
/// its state is `Active` (i.e., already promoted past the LOCKED →
/// ACTIVE gate by γ-3 manual activate, Group 2 auto_activate_locked,
/// or the REST Solana-verified path).
///
/// Callers combine this with `manifest.contains(...)` to decide whether
/// a node enters OBSERVER MODE at startup. Extracted as a free function
/// so it is unit-testable without spinning up the full node runtime.
fn is_dynamic_active_validator(
    registry: &misaka_consensus::staking::StakingRegistry,
    fingerprint: &[u8; 32],
) -> bool {
    registry
        .get(fingerprint)
        .map(|v| v.state == misaka_consensus::staking::ValidatorState::Active)
        .unwrap_or(false)
}

/// PR-B: Convert (proposed_blocks, expected_per_validator) to an
/// uptime basis-points value clamped to `[0, 10_000]`.
///
/// Semantics:
/// - `expected == 0` → `10_000` (quiet / bootstrap epoch — don't punish
///   validators when no blocks were produced OR no active set existed to
///   divide across).
/// - otherwise `uptime_bps = min(10_000, proposed * 10_000 / expected)`.
///
/// u128 arithmetic avoids overflow on pathological `proposed` values
/// (`proposed * 10_000` can exceed u64 only when proposed ≥ ~1.8e15,
/// well outside realistic epoch sizes, but u128 is free).
///
/// Exposed as a pure function so the commit-loop wiring in
/// `start_narwhal_node` has a unit-testable surface.
fn compute_uptime_bps(proposed: u64, expected: u64) -> u64 {
    if expected == 0 {
        return 10_000;
    }
    let ratio = (proposed as u128).saturating_mul(10_000) / (expected as u128);
    ratio.min(10_000) as u64
}

fn requires_explicit_advertise_addr(
    node_mode: NodeMode,
    role: NodeRole,
    seeds_present: bool,
    accept_observers: bool,
) -> bool {
    if node_mode == NodeMode::Hidden {
        return false;
    }
    if node_mode == NodeMode::Seed {
        return true;
    }
    if accept_observers {
        return true;
    }
    seeds_present && role == NodeRole::Validator
}

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

    /// RPC bind address.
    ///
    /// SECURITY: default is `127.0.0.1` (loopback-only). Override to
    /// `0.0.0.0` ONLY when the RPC port is firewalled to a trusted
    /// private network (e.g. VPS-to-VPS validator mesh). Mainnet
    /// operators SHOULD front misaka-api with nginx + TLS instead of
    /// exposing this directly. Accepts env `MISAKA_RPC_BIND`.
    #[arg(long, default_value = "127.0.0.1", env = "MISAKA_RPC_BIND")]
    rpc_bind: String,

    /// P2P listen port
    #[arg(long, default_value = "6690")]
    p2p_port: u16,

    /// Block time in seconds (legacy — sets both fast and zkp if they are not specified)
    #[arg(long, default_value = "60")]
    block_time: u64,

    /// Fast lane block interval (transparent/ring-sig TXs) in seconds.
    /// GhostDAG allows parallel blocks, so 1-2s is safe.
    #[arg(long)]
    fast_block_time: Option<u64>,

    /// ZKP batch lane interval in seconds.
    /// Proof verification is heavier, so batching at longer intervals is optimal.
    #[arg(long)]
    zkp_batch_time: Option<u64>,

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

    /// Seed nodes (comma-separated host:port)
    #[arg(long, value_delimiter = ',')]
    seeds: Vec<String>,

    /// Seed node transport public keys (comma-separated hex, 0x-prefixed).
    /// Must correspond 1:1 to --seeds entries.
    /// Phase 2b (M7): Required for PK pinning, prevents MITM on seed connections.
    #[arg(long, value_delimiter = ',')]
    seed_pubkeys: Vec<String>,

    /// Data directory
    #[arg(long, default_value = "./data")]
    data_dir: String,

    /// Path to genesis committee manifest (TOML)
    #[arg(long)]
    genesis_path: Option<String>,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Log output format: "compact" (human-readable) or "json" (structured)
    #[arg(long, default_value = "compact", env = "MISAKA_LOG_FORMAT")]
    log_format: String,

    /// Chain ID
    #[arg(long, default_value = "2")]
    chain_id: u32,

    /// Faucet drip amount in base units (0 = disabled)
    #[arg(long, default_value = "1000000")]
    faucet_amount: u64,

    /// Faucet cooldown per address in milliseconds (0 = no cooldown)
    #[arg(long, default_value = "10000")]
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
    /// Only used in DAG consensus mode (default).
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

    /// Experimental HTTP peers used for checkpoint vote gossip.
    /// Format: `http://HOST:RPC_PORT`, comma-separated.
    #[cfg(feature = "dag")]
    #[arg(long, value_delimiter = ',')]
    dag_rpc_peers: Vec<String>,

    /// Use the zero-knowledge block path for txs that carry ZK proof.
    /// When enabled, TXs with CompositeProof are routed through
    /// the ZK candidate resolution path.
    #[arg(long)]
    experimental_zk_path: bool,

    // ─── SEC-FIX-6: Reward address configuration ────────
    /// Proposer reward payout address (hex-encoded, 32 bytes).
    /// Block proposer rewards are sent here. REQUIRED for mainnet validators.
    #[arg(long, env = "MISAKA_PROPOSER_ADDRESS")]
    proposer_payout_address: Option<String>,

    /// Treasury address (hex-encoded, 32 bytes).
    /// Protocol fee share is sent here. REQUIRED for mainnet validators.
    #[arg(long, env = "MISAKA_TREASURY_ADDRESS")]
    treasury_address: Option<String>,

    // ─── Validator Registration (misakastake.com) ──────────
    /// Generate L1 validator key and exit. Does NOT start the node.
    /// Use this to get the L1 Public Key for misakastake.com registration.
    #[arg(long)]
    keygen_only: bool,

    /// Print the ML-DSA-65 public key (hex) from validator.key and exit.
    /// Creates validator.key if it does not exist. Used by start-testnet.sh
    /// to build genesis_committee.toml automatically.
    #[arg(long)]
    emit_validator_pubkey: bool,

    /// Solana TX signature from misakastake.com staking deposit.
    /// Required for mainnet validator activation. The node verifies
    /// this TX on Solana before allowing block production.
    #[arg(long, env = "MISAKA_STAKE_SIGNATURE")]
    stake_signature: Option<String>,

    /// MISAKA staking program ID on Solana (for stake verification).
    #[arg(long, env = "MISAKA_STAKING_PROGRAM_ID")]
    staking_program_id: Option<String>,

    /// 0.9.0 β-3: Testnet-only override. When set, validators registered via
    /// `/api/register_validator` are activated **without** on-chain Solana
    /// stake verification — the request is trusted as-is. This bypasses the
    /// `solana_stake_verified` gate in `StakingRegistry::activate()` and
    /// skips the background verifier. MUST NOT be enabled on mainnet nodes.
    #[arg(long, env = "MISAKA_ALLOW_UNVERIFIED_VALIDATORS")]
    allow_unverified_validators: bool,

    // ─── Config file loading ────────────────────────────────
    /// Path to a TOML or JSON configuration file.
    /// Values from the file serve as defaults; explicit CLI args override them.
    #[arg(long, env = "MISAKA_CONFIG_PATH")]
    config: Option<String>,

    // ─── Phase 2 Path X R6 — storage schema migration ──────
    /// Run offline migration of the storage DB's schema-version marker
    /// and exit. Required to trigger migration mode. Must equal the
    /// current build's `CURRENT_STORAGE_SCHEMA_VERSION` (v0.9.0 = 2).
    ///
    /// See `crates/misaka-node/src/migrate.rs` for the full flow.
    #[arg(long, value_name = "VERSION")]
    migrate_to: Option<u32>,

    /// Optional expected source schema version. When set, migration
    /// refuses to proceed unless the DB's observed marker matches.
    /// Use to guard against running against a DB already stamped by a
    /// different build.
    #[arg(long, value_name = "VERSION", requires = "migrate_to")]
    migrate_from: Option<u32>,

    /// Print the migration plan but do not mutate the DB. Useful to
    /// verify what will happen before stamping a production DB.
    #[arg(long, requires = "migrate_to")]
    migrate_dry_run: bool,

    /// Explicit path to the storage RocksDB directory. Defaults to
    /// `<data-dir>/storage` — the layout the running node uses.
    #[arg(long, value_name = "PATH", requires = "migrate_to")]
    migrate_db: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut cli = Cli::parse();

    // ════════════════════════════════════════════════════════
    //  Config file loading (SEC-FIX: TOML config support)
    // ════════════════════════════════════════════════════════
    //
    // Priority: explicit CLI args > config file > built-in defaults.
    // Since clap has already applied its defaults, we detect "was this
    // explicitly set?" by comparing against the known clap default values.
    // If the CLI value matches the clap default AND the config file
    // provides a different value, we use the config file value.
    //
    // Option A: `loaded_config` is lifted to function-level scope (previously
    // an inner-block local) so `start_narwhal_node` / `start_dag_node` can
    // pass `Some(&loaded_config)` to `build_staking_config_for_chain`
    // instead of the `None` placeholder Group 1 left behind. The surrounding
    // CLI-override logic is unchanged; only the block braces moved.
    let config_source: &str;

    let loaded_config: Option<misaka_config::NodeConfig> = if let Some(ref config_path) = cli.config
    {
        config_source = "file";
        Some(
            misaka_config::load_config(std::path::Path::new(config_path))
                .map_err(|e| anyhow::anyhow!("failed to load config '{}': {}", config_path, e))?,
        )
    } else if cli.chain_id == 1 {
        // Auto-detect mainnet config if --chain-id 1 and no --config given
        let default_path = std::path::Path::new("configs/mainnet.toml");
        if default_path.exists() {
            // Warn — mainnet.toml found but not explicitly specified.
            // Use eprintln here because tracing isn't initialized yet.
            eprintln!(
                "WARNING: Loading configs/mainnet.toml automatically (chain_id=1). \
                     Pass --config configs/mainnet.toml explicitly to suppress this warning."
            );
            config_source = "file(auto)";
            match misaka_config::load_config(default_path) {
                Ok(cfg) => Some(cfg),
                Err(e) => {
                    // Phase 1: mainnet config parse failure is FATAL.
                    // Do NOT fall back to CLI defaults on chain_id=1 —
                    // this would skip weak_subjectivity checkpoint validation.
                    eprintln!("FATAL: failed to parse configs/mainnet.toml: {}", e);
                    eprintln!("Mainnet MUST have a valid configuration file.");
                    std::process::exit(1);
                }
            }
        } else {
            // Phase 1: mainnet without config file is FATAL.
            eprintln!(
                    "FATAL: chain_id=1 (mainnet) but configs/mainnet.toml not found. \
                     Mainnet MUST have a valid configuration file with weak_subjectivity checkpoint."
                );
            std::process::exit(1);
        }
    } else {
        config_source = "defaults+CLI";
        None
    };

    if let Some(ref cfg) = loaded_config {
        // Apply config file values as defaults — only override CLI fields
        // that still hold the clap-default value.
        //
        // Clap defaults (must match the #[arg(default_value = ...)] above):
        //   chain_id=2, rpc_port=3001, p2p_port=6690, data_dir="./data", log_level="info"

        if cli.chain_id == 2 {
            cli.chain_id = cfg.chain_id;
        }
        if cli.rpc_port == 3001 {
            if let Some(ref rpc_bind) = cfg.rpc_bind {
                // Extract port from "0.0.0.0:PORT" format
                if let Some(port_str) = rpc_bind.rsplit(':').next() {
                    if let Ok(port) = port_str.parse::<u16>() {
                        cli.rpc_port = port;
                    }
                }
            }
        }
        if cli.p2p_port == 6690 {
            cli.p2p_port = cfg.listen_port;
        }
        if cli.data_dir == "./data" {
            cli.data_dir = cfg.data_dir.clone();
        }
        if cli.log_level == "info" {
            cli.log_level = cfg.log_level.clone();
        }
        if cli.peers.is_empty() {
            if let Some(ref peers_str) = cfg.peers {
                cli.peers = peers_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }
    }

    // Startup banner (printed to stderr so it appears before tracing init)
    eprintln!(
        "MISAKA node config: chain_id={}, data_dir={}, rpc_port={}, p2p_port={}, config_source={}",
        cli.chain_id, cli.data_dir, cli.rpc_port, cli.p2p_port, config_source
    );

    // ════════════════════════════════════════════════════════
    //  共通初期化 (v1/v2 共通)
    // ════════════════════════════════════════════════════════

    // Tracing
    let level = match cli.log_level.as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };
    if cli.log_format == "json" {
        tracing::subscriber::set_global_default(
            FmtSubscriber::builder()
                .with_max_level(level)
                .with_target(true)
                .json()
                .finish(),
        )?;
    } else {
        tracing::subscriber::set_global_default(
            FmtSubscriber::builder()
                .with_max_level(level)
                .with_target(false)
                .compact()
                .finish(),
        )?;
    }

    info!(
        "Effective config: chain_id={}, data_dir={}, rpc_port={}, p2p_port={}, config_source={}",
        cli.chain_id,
        cli.data_dir,
        cli.rpc_port,
        cli.p2p_port,
        if cli.config.is_some() {
            "file"
        } else {
            "defaults+CLI"
        }
    );

    // Parse NodeMode
    let node_mode = NodeMode::from_str_loose(&cli.mode);

    // ════════════════════════════════════════════════════════
    //  --keygen-only: Generate L1 key and exit
    // ════════════════════════════════════════════════════════
    //
    // Operator flow:
    //   1. VPS$ misaka-node --keygen-only --name my-validator --data-dir ./data
    //   2. → Prints L1 Public Key (hex 64 chars)
    //   3. → Saves secret key to ./data/l1-secret-key.json
    //   4. Operator copies L1 Public Key to misakastake.com
    //   5. Stakes tokens (testnet: 1M MISAKA / mainnet: 10M MISAKA)
    //   6. Gets Solana TX signature back
    //   7. VPS$ misaka-node --validator --stake-signature <SIG> --data-dir ./data
    //
    // Solana private keys are NEVER needed on the VPS.
    // ── Phase 2 Path X R6-a: offline schema migration ─────────────
    //
    // Early exit path — runs after config is loaded (so --data-dir and
    // --migrate-db reflect the effective data directory) and before the
    // rest of node startup. On success the process returns Ok(()); on
    // any inconsistency it propagates the anyhow::Error to produce a
    // non-zero exit code.
    if let Some(to) = cli.migrate_to {
        let db_path = match cli.migrate_db.as_deref() {
            Some(p) => std::path::PathBuf::from(p),
            None => crate::migrate::default_db_path(std::path::Path::new(&cli.data_dir)),
        };
        let args = crate::migrate::MigrateArgs {
            to,
            from: cli.migrate_from,
            dry_run: cli.migrate_dry_run,
            db_path,
        };
        return crate::migrate::run(&args);
    }

    #[cfg(feature = "dag")]
    if cli.keygen_only {
        use misaka_crypto::validator_sig::generate_validator_keypair;
        use sha3::{Digest, Sha3_256};

        let data_dir = std::path::Path::new(&cli.data_dir);
        std::fs::create_dir_all(data_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(data_dir, std::fs::Permissions::from_mode(0o700))?;
        }

        let output_path = data_dir.join("l1-secret-key.json");

        // Check if key already exists
        if output_path.exists() {
            // Try reading as encrypted keystore (new format) or legacy JSON
            let pub_path = data_dir.join("l1-public-key.json");
            let (pub_key, node_name) = if pub_path.exists() {
                let raw = std::fs::read_to_string(&pub_path)?;
                let existing: serde_json::Value = serde_json::from_str(&raw)?;
                (
                    existing["l1PublicKey"].as_str().unwrap_or("").to_string(),
                    existing["nodeName"].as_str().unwrap_or("").to_string(),
                )
            } else {
                ("(see l1-public-key.json)".to_string(), "".to_string())
            };

            println!();
            println!("══════════════════════════════════════════════════");
            println!("  L1 Key already exists");
            println!("══════════════════════════════════════════════════");
            println!();
            println!("  L1 Public Key:  {}", pub_key);
            println!("  Node Name:      {}", node_name);
            println!("  Key File:       {}", output_path.display());
            println!();
            println!("  To regenerate, delete {} first.", output_path.display());
            println!();
            return Ok(());
        }

        // Generate ML-DSA-65 keypair
        let keypair = generate_validator_keypair();
        let pk_bytes = keypair.public_key.to_bytes();

        // L1 Public Key = SHA3-256(ml_dsa_pk)[0..32] = 64 hex chars
        let l1_pubkey: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(b"MISAKA:l1:validator:pubkey:v1:");
            h.update(&pk_bytes);
            h.finalize().into()
        };
        let l1_pubkey_hex = hex::encode(l1_pubkey);

        // Validator ID (32 bytes, canonical SHA3-256) — used internally by the staking registry
        let validator_id = keypair.public_key.to_canonical_id();
        let validator_id_hex = hex::encode(validator_id);

        // Save secret key file as ENCRYPTED keystore (not plaintext)
        // SEC-FIX: Previously stored mlDsaSecretKey in plaintext JSON.
        // Now uses the same argon2id+chacha20poly1305 keystore as runtime.
        {
            use misaka_crypto::keystore::{encrypt_keystore, save_keystore};

            let passphrase = std::env::var("MISAKA_VALIDATOR_PASSPHRASE")
                .unwrap_or_default()
                .into_bytes();
            if cli.chain_id == 1 && passphrase.is_empty() {
                anyhow::bail!(
                    "FATAL: MISAKA_VALIDATOR_PASSPHRASE must be set for mainnet keygen. \
                     An empty passphrase means the keystore can be decrypted trivially."
                );
            }
            if passphrase.is_empty() {
                eprintln!("  ⚠  WARNING: MISAKA_VALIDATOR_PASSPHRASE is empty.");
                eprintln!("     The encrypted keystore will use an empty passphrase.");
                eprintln!("     Set MISAKA_VALIDATOR_PASSPHRASE for production use.");
            }

            let keystore = keypair
                .secret_key
                .with_bytes(|sk_bytes| {
                    encrypt_keystore(
                        sk_bytes,
                        &hex::encode(&pk_bytes),
                        &validator_id_hex,
                        if cli.chain_id == 1 {
                            10_000_000
                        } else {
                            1_000_000
                        },
                        &passphrase,
                    )
                })
                .map_err(|e| anyhow::anyhow!("keystore encryption failed: {}", e))?;

            // save_keystore writes to tmp with 0600 then renames (no race window)
            save_keystore(&output_path, &keystore)
                .map_err(|e| anyhow::anyhow!("failed to save encrypted keystore: {}", e))?;
        }

        // Also save public info separately (safe to share)
        let pub_path = data_dir.join("l1-public-key.json");
        let pub_file = serde_json::json!({
            "version": 1,
            "nodeName": cli.name,
            "l1PublicKey": l1_pubkey_hex,
            "validatorId": validator_id_hex,
            "chainId": cli.chain_id,
        });
        std::fs::write(&pub_path, serde_json::to_string_pretty(&pub_file)?)?;

        // Print registration info
        println!();
        println!("══════════════════════════════════════════════════");
        println!("  MISAKA L1 Validator Key Generated");
        println!("══════════════════════════════════════════════════");
        println!();
        println!("  L1 Public Key:  {}", l1_pubkey_hex);
        println!("  Validator ID:   {}", validator_id_hex);
        println!("  Node Name:      {}", cli.name);
        println!("  Chain ID:       {}", cli.chain_id);
        println!();
        println!("  Secret key:     {} (encrypted)", output_path.display());
        println!("  Public key:     {}", pub_path.display());
        println!();
        println!("══════════════════════════════════════════════════");
        println!("  Next Steps:");
        println!("══════════════════════════════════════════════════");
        println!();
        println!("  1. Go to https://misakastake.com");
        println!("  2. Connect your Solana wallet");
        println!("  3. Enter L1 Public Key: {}", l1_pubkey_hex);
        println!(
            "  4. Stake {} MISAKA",
            if cli.chain_id == 1 {
                "10,000,000"
            } else {
                "1,000,000"
            }
        );
        println!("  5. Copy the Solana TX signature");
        println!("  6. Start your validator:");
        println!();
        println!("     misaka-node --validator \\");
        println!("       --stake-signature <SOLANA_TX_SIG> \\");
        println!("       --data-dir {} \\", cli.data_dir);
        println!("       --name {}", cli.name);
        println!();
        println!("  ⚠  Keep l1-secret-key.json SECRET. Never share it.");
        println!("  ⚠  Solana private key is NOT needed on this VPS.");
        println!();

        return Ok(());
    }

    // ── emit-validator-pubkey: print ML-DSA-65 PK hex and exit ──
    // Runs before config validation since it only needs to generate/load a key.
    #[cfg(feature = "dag")]
    if cli.emit_validator_pubkey {
        let data_dir = std::path::Path::new(&cli.data_dir);
        std::fs::create_dir_all(data_dir)?;
        let identity =
            crate::identity::ValidatorIdentity::load_or_create(&data_dir.join("validator.key"))?;
        println!("0x{}", hex::encode(identity.public_key()));
        return Ok(());
    }

    // ── Runtime Defense-in-Depth: reject dev features on production networks ──
    // This is a SECOND layer after compile_error! guards above.
    // Catches edge cases where debug builds accidentally run against mainnet.
    {
        let is_mainnet = cli.chain_id == 1;
        #[allow(unused_mut)]
        let mut dev_features_active: Vec<&str> = Vec::new();

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

        // SEC-FIX: RPC API key is MANDATORY on mainnet.
        // Without it, all Private-tier RPC methods (admin, debug, validator ops)
        // are accessible without authentication — a total compromise vector.
        if is_mainnet {
            match std::env::var("MISAKA_RPC_API_KEY") {
                Ok(k) if !k.is_empty() => {
                    info!("RPC API key configured (mainnet mandatory)");
                }
                _ => {
                    error!("╔═══════════════════════════════════════════════════════════╗");
                    error!("║  FATAL: MISAKA_RPC_API_KEY not set on mainnet            ║");
                    error!("║                                                           ║");
                    error!("║  Without an API key, all Private-tier RPC methods are     ║");
                    error!("║  accessible without authentication. This is a critical    ║");
                    error!("║  security vulnerability on a production network.          ║");
                    error!("║                                                           ║");
                    error!("║  Set: export MISAKA_RPC_API_KEY='<your-secret-key>'       ║");
                    error!("╚═══════════════════════════════════════════════════════════╝");
                    std::process::exit(1);
                }
            }
        }

        if !dev_features_active.is_empty() {
            warn!(
                "⚠ Dev features active: {:?} — DO NOT use in production!",
                dev_features_active
            );
        }
        if cli.experimental_zk_path {
            info!("ZK block path ENABLED — txs with ZK proof will use CompositeProof verification");
        }
    }

    // Phase 2b' (M7'): Build parsed seed entries before config validation
    // so they're available both for validation and for transport.
    //
    // SEC-FIX: the old code silently dropped seeds to `vec![]` when
    // `--seed-pubkeys` was absent and printed a misleading warning that
    // "seeds will connect without PK pinning (TOFU)". In reality there is
    // no TOFU path — the Narwhal relay handshake is strictly PK-pinned
    // (tcp_initiator_handshake takes &peer.public_key). Without pubkeys
    // the seeds were silently ignored, which made `--seeds` look like it
    // worked while the node was actually running in solo mode.
    //
    // The correct behaviour is to hard-fail if `--seeds` is provided
    // without matching `--seed-pubkeys`, and to build SeedEntry structs
    // one-to-one otherwise.
    let parsed_seeds: Vec<misaka_types::seed_entry::SeedEntry> = {
        if cli.seeds.is_empty() {
            vec![]
        } else if cli.seed_pubkeys.is_empty() {
            error!(
                "FATAL: --seeds provided ({}) but --seed-pubkeys is empty. \
                 The Narwhal relay handshake is PK-pinned; there is no TOFU \
                 mode. Obtain the seed's ML-DSA-65 public key from its \
                 operator (misaka-node --emit-validator-pubkey prints it \
                 on stdout) and pass it as `--seed-pubkeys 0x<hex>`, one \
                 per --seeds entry in the same order.",
                cli.seeds.len()
            );
            std::process::exit(1);
        } else if cli.seed_pubkeys.len() != cli.seeds.len() {
            error!(
                "FATAL: --seed-pubkeys count ({}) != --seeds count ({}). \
                 Each seed must have a corresponding pubkey in the same order.",
                cli.seed_pubkeys.len(),
                cli.seeds.len()
            );
            std::process::exit(1);
        } else {
            cli.seeds
                .iter()
                .zip(cli.seed_pubkeys.iter())
                .map(|(addr, pk)| misaka_types::seed_entry::SeedEntry {
                    address: addr.clone(),
                    transport_pubkey: pk.clone(),
                })
                .collect()
        }
    };

    // ── MANDATORY: Config Validation ──
    {
        use config_validation::TestnetConfig;
        let cfg = TestnetConfig {
            chain_id: cli.chain_id,
            chain_name: if cli.chain_id == 1 {
                "MISAKA Mainnet".into()
            } else {
                "MISAKA Testnet".into()
            },
            p2p_port: cli.p2p_port,
            rpc_port: cli.rpc_port,
            block_time_secs: cli.block_time,
            max_inbound_peers: cli.max_inbound_peers.unwrap_or(32),
            max_outbound_peers: cli.max_outbound_peers.unwrap_or(8),
            node_mode,
            advertise_addr: cli.advertise_addr.clone(),
            seed_nodes: cli.seeds.clone(),
            parsed_seeds: parsed_seeds.clone(),
            data_dir: cli.data_dir.clone(),
            ..TestnetConfig::default()
        };

        match cfg.validate() {
            Ok(()) => {
                info!(
                    "Config validation passed (chain_id={}, mode={}, p2p={}, rpc={})",
                    cfg.chain_id, node_mode, cfg.p2p_port, cfg.rpc_port
                );
            }
            Err(errors) => {
                for e in &errors {
                    error!("Config validation FAILED: {}", e);
                }
                std::process::exit(1);
            }
        }
    }

    let role = NodeRole::determine(
        node_mode,
        cli.validator,
        cli.validator_index,
        cli.validators,
    );

    let accept_observers = env_flag_enabled("MISAKA_ACCEPT_OBSERVERS");

    // Parse advertise address
    //
    // v0.5.13 audit P0: in dialable public/seed profiles a missing or invalid
    // advertise address silently fell back to `None`, which meant the
    // node thought it was joined to the network but was not dialable
    // by its peers. Public operators would see solo-mode behaviour
    // without any loud signal. Now:
    //   - If the operator passed a value and it is bad, we fail fast.
    //   - If the operator passed nothing in dialable profiles
    //     (seed / public validator with seeds / observer-accepting
    //     operator), we fail fast because peers must be able to dial
    //     back.
    //   - Hidden mode and purely outbound observer/full-node cases
    //     continue to allow no advertise address.
    let advertise_addr: Option<SocketAddr> = match cli.advertise_addr.as_deref() {
        Some(s) => match s.parse::<SocketAddr>() {
            Ok(addr) => {
                if config::is_valid_advertise_addr(&addr) {
                    Some(addr)
                } else {
                    error!(
                        "FATAL: --advertise-addr '{}' is 0.0.0.0 or loopback — peers cannot dial \
                         this address. Pass the real public IP:port or unset --advertise-addr.",
                        s
                    );
                    std::process::exit(1);
                }
            }
            Err(e) => {
                error!(
                    "FATAL: --advertise-addr '{}' does not parse as SocketAddr: {}. Fix or \
                     remove the flag.",
                    s, e
                );
                std::process::exit(1);
            }
        },
        None => {
            if requires_explicit_advertise_addr(
                node_mode,
                role,
                !cli.seeds.is_empty(),
                accept_observers,
            ) {
                error!(
                    "FATAL: this node profile is dialable (mode={}, role={}, seeds={}, \
                     MISAKA_ACCEPT_OBSERVERS={}) but --advertise-addr is missing. Pass \
                     --advertise-addr <public-ip>:<relay-port> (typically :16110).",
                    node_mode,
                    role,
                    !cli.seeds.is_empty(),
                    accept_observers
                );
                std::process::exit(1);
            } else if matches!(
                node_mode,
                crate::config::NodeMode::Public | crate::config::NodeMode::Seed
            ) {
                warn!(
                    "⚠ no --advertise-addr configured: this is acceptable only for hidden mode \
                     or outbound-only observer/full-node usage. Dialable peers should set \
                     --advertise-addr <public-ip>:<relay-port>."
                );
            }
            None
        }
    };

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
    //
    // Phase 2 Path X R1 step 3: prefer Kaspa-aligned committed-tip
    // keys in the Narwhal consensus RocksDB (populated by R1 step 2
    // above on every committed block). Falls back to the legacy
    // `chain.db` state CF when the new keys are absent (DBs from
    // builds before R1 step 2). The subdir `"narwhal_consensus"`
    // matches the layout of `RocksDbConsensusStore::open` below.
    {
        let data_path = std::path::Path::new(&cli.data_dir);
        let (recovered_height, recovered_root) =
            misaka_storage::run_startup_check_kaspa_aware(data_path, "narwhal_consensus");
        if recovered_height > 0 {
            info!(
                "Recovered from persistent state: height={}, root={}",
                recovered_height,
                hex::encode(&recovered_root[..8])
            );
        }
    }

    // Phase 2b' (M9'): Weak subjectivity checkpoint verification at startup.
    // Parse the ws_checkpoint from config_validation (if present) and verify.
    // Currently, the checkpoint string comes from mainnet.toml's [weak_subjectivity] section.
    // The config validation (L192) already rejects all-zero on mainnet.
    // Here we verify the actual block hash if the node has synced past the checkpoint.
    {
        // Try to get ws_checkpoint from environment or config
        let ws_str = std::env::var("MISAKA_WS_CHECKPOINT").ok();
        if let Some(ref ws) = ws_str {
            match crate::ws::WsCheckpoint::parse(ws) {
                Ok(cp) => {
                    // We don't have a block store yet at this point in the startup,
                    // so we do a deferred check: log the checkpoint and verify later
                    // when the block store is initialized (Phase 3 will add post-sync hook).
                    if cp.hash == [0u8; 32] {
                        if cli.chain_id == 1 {
                            error!("FATAL: ws checkpoint hash is all-zero on mainnet");
                            std::process::exit(1);
                        } else {
                            warn!("ws checkpoint hash is all-zero (non-mainnet, continuing)");
                        }
                    } else {
                        info!(
                            "Weak subjectivity checkpoint configured: height={} hash={}",
                            cp.height,
                            hex::encode(&cp.hash[..8]),
                        );
                    }
                }
                Err(e) => {
                    if cli.chain_id == 1 {
                        error!("FATAL: invalid ws checkpoint: {}", e);
                        std::process::exit(1);
                    } else {
                        warn!("invalid ws checkpoint (non-mainnet, ignoring): {}", e);
                    }
                }
            }
        }
    }

    // ════════════════════════════════════════════════════════
    //  分岐: v1 (linear chain) vs v2 (DAG)
    // ════════════════════════════════════════════════════════

    #[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
    {
        start_dag_node(cli, node_mode, role, p2p_config, loaded_config).await
    }

    #[cfg(all(feature = "dag", not(feature = "ghostdag-compat")))]
    {
        start_narwhal_node(cli, p2p_config, loaded_config).await
    }

    #[cfg(not(feature = "dag"))]
    {
        start_v1_node(cli, node_mode, role, p2p_config, loaded_config).await
    }
}

// ════════════════════════════════════════════════════════════════
//  v3: Mysticeti-equivalent Node (GhostDAG-free)
// ════════════════════════════════════════════════════════════════

/// Resolve `genesis_committee.toml`: CLI → cwd → next to binary → `config/` next to binary.
#[cfg(feature = "dag")]
fn resolve_genesis_committee_path(cli_path: Option<&str>) -> std::path::PathBuf {
    use std::path::{Path, PathBuf};
    if let Some(p) = cli_path {
        return PathBuf::from(p);
    }
    let cwd_default = Path::new("genesis_committee.toml");
    if cwd_default.exists() {
        return cwd_default.to_path_buf();
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let next_to_exe = dir.join("genesis_committee.toml");
            if next_to_exe.exists() {
                return next_to_exe;
            }
            let in_config = dir.join("config").join("genesis_committee.toml");
            if in_config.exists() {
                return in_config;
            }
        }
    }
    cwd_default.to_path_buf()
}

/// 0.9.0 β-3: Spawn a background task that verifies a validator's Solana
/// stake signature off the request path.
///
/// Rationale: the REST `/api/register_validator` handler must return
/// quickly and must not hold the `StakingRegistry` write lock during the
/// Solana RPC round-trip. Instead we insert the validator as LOCKED
/// (solana_stake_verified = false), then kick off this task. On RPC
/// success it takes the write lock, calls `mark_stake_verified` and
/// `activate` (LOCKED → ACTIVE), then triggers a committee hot-reload.
/// On failure the validator stays LOCKED.
///
/// The task owns cheap clones of every handle — no references into the
/// closure frame — so it outlives the HTTP response.
#[cfg(all(feature = "dag", not(feature = "ghostdag-compat")))]
fn spawn_verify_stake_background(
    validator_id: [u8; 32],
    l1_pubkey_hex: String,
    signature: String,
    min_stake: u64,
    registry: std::sync::Arc<tokio::sync::RwLock<misaka_consensus::staking::StakingRegistry>>,
    committee: std::sync::Arc<tokio::sync::RwLock<misaka_dag::narwhal_types::committee::Committee>>,
    current_epoch: std::sync::Arc<tokio::sync::RwLock<u64>>,
    msg_tx: tokio::sync::mpsc::Sender<misaka_dag::narwhal_dag::runtime::ConsensusMessage>,
    genesis_path: std::path::PathBuf,
) {
    tokio::spawn(async move {
        let id_short = hex::encode(&validator_id[..8]);
        let rpc_url = crate::solana_stake_verify::solana_rpc_url();
        let program_id = crate::solana_stake_verify::staking_program_id();

        if rpc_url.is_empty() || program_id.is_empty() {
            tracing::warn!(
                "verify_stake_background[{}]: Solana RPC or program ID not configured \
                 — validator stays LOCKED",
                id_short,
            );
            return;
        }

        let verified = match crate::solana_stake_verify::verify_solana_stake(
            &rpc_url,
            &signature,
            &l1_pubkey_hex,
            &program_id,
            min_stake,
        )
        .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(
                    "verify_stake_background[{}]: ON-CHAIN FAILED: {} — validator stays LOCKED",
                    id_short,
                    e,
                );
                return;
            }
        };

        tracing::info!(
            "verify_stake_background[{}]: ON-CHAIN SUCCESS — amount={} sig={}...",
            id_short,
            verified.amount,
            &signature[..16.min(signature.len())],
        );

        let epoch = *current_epoch.read().await;
        {
            let mut reg = registry.write().await;
            if let Err(e) =
                reg.mark_stake_verified(&validator_id, signature.clone(), Some(verified.amount))
            {
                tracing::warn!(
                    "verify_stake_background[{}]: mark_stake_verified failed: {}",
                    id_short,
                    e,
                );
                return;
            }
            if let Err(e) = reg.activate(&validator_id, epoch) {
                tracing::warn!(
                    "verify_stake_background[{}]: activate failed: {} — stake verified \
                     but validator not promoted to ACTIVE",
                    id_short,
                    e,
                );
                return;
            }
        }

        // Hot-reload committee so the newly-ACTIVE validator enters the
        // authority set. Uses the same merged source-of-truth as the REST
        // registration handler.
        match crate::genesis_committee::GenesisCommitteeManifest::load(&genesis_path) {
            Ok(new_manifest) => {
                let registry_guard = registry.read().await;
                match crate::genesis_committee::build_committee_from_sources(
                    &new_manifest,
                    &registry_guard,
                ) {
                    Ok(new_committee) => {
                        drop(registry_guard);
                        *committee.write().await = new_committee.clone();
                        let _ = msg_tx
                            .send(
                                misaka_dag::narwhal_dag::runtime::ConsensusMessage::ReloadCommittee(
                                    new_committee,
                                ),
                            )
                            .await;
                        tracing::info!(
                            "verify_stake_background[{}]: committee hot-reloaded — validator ACTIVE",
                            id_short,
                        );
                    }
                    Err(e) => tracing::warn!(
                        "verify_stake_background[{}]: build_committee_from_sources failed: {}",
                        id_short,
                        e,
                    ),
                }
            }
            Err(e) => tracing::warn!(
                "verify_stake_background[{}]: GenesisCommitteeManifest::load failed: {}",
                id_short,
                e,
            ),
        }
    });
}

#[cfg(all(feature = "dag", not(feature = "ghostdag-compat")))]
async fn start_narwhal_node(
    mut cli: Cli,
    p2p_config: P2pConfig,
    loaded_config: Option<misaka_config::NodeConfig>,
) -> anyhow::Result<()> {
    use std::collections::{BTreeMap, BTreeSet};

    use misaka_dag::narwhal_dag::core_engine::ProposeContext;
    use misaka_dag::narwhal_dag::runtime::{
        spawn_consensus_runtime, ConsensusMessage, RuntimeConfig,
    };
    use misaka_dag::narwhal_types::block::{BlockRef, VerifiedBlock};
    use misaka_dag::{DagStateConfig, NarwhalBlock};
    use misaka_p2p::narwhal_block_relay::{
        NarwhalBlockProposal, NarwhalBlockRequest, NarwhalBlockResponse, NarwhalRelayMessage,
    };

    info!("╔═══════════════════════════════════════════════════════════╗");
    info!("║  MISAKA Network — Mysticeti-equivalent Consensus v3     ║");
    info!("╚═══════════════════════════════════════════════════════════╝");

    let data_dir = std::path::Path::new(&cli.data_dir);
    std::fs::create_dir_all(data_dir)?;

    // ── CRIT #1 fix: Load persistent validator identity (not generate fresh) ──
    let validator_key_path = data_dir.join("validator.key");
    let identity = crate::identity::ValidatorIdentity::load_or_create(&validator_key_path)?;
    tracing::info!(
        fingerprint = %hex::encode(identity.fingerprint()),
        "Loaded validator identity"
    );

    // ── SEC-FIX: bundled validator key guard ──
    //
    // The distribution ships `config/bundled-validator.key`, a *shared*
    // demonstration key matching `authority_index=0` in the default
    // `genesis_committee.toml`. If two machines both bootstrap with this
    // same file and connect to the same testnet, they will sign conflicting
    // blocks for the same slot (equivocation) and get ejected by the
    // (future) slashing pipeline. On mainnet this would be a guaranteed
    // loss-of-funds event.
    //
    // We fail-closed on mainnet and warn loudly on non-mainnet chains.
    const BUNDLED_VALIDATOR_KEY_SHA256: &str =
        "9a6d82004781195a9af06c768fdc3b70e148c63ef0c08fcc7298d52efee12c93";
    if let Ok(bytes) = std::fs::read(&validator_key_path) {
        use sha2::{Digest as _, Sha256};
        let file_sha256 = hex::encode(Sha256::digest(&bytes));
        if file_sha256 == BUNDLED_VALIDATOR_KEY_SHA256 {
            if cli.chain_id == 1 {
                anyhow::bail!(
                    "FATAL: refusing to start on mainnet (chain_id=1) with the bundled \
                     demonstration validator key. The bundled key is shared among all \
                     downloads of this distribution and must NEVER be used on mainnet. \
                     Delete {} and restart to generate a fresh, unique validator key, \
                     or run `misaka-cli --emit-validator-pubkey` to produce one under \
                     a different data_dir.",
                    validator_key_path.display(),
                );
            } else {
                tracing::warn!(
                    "⚠ Starting with the BUNDLED demonstration validator key. \
                     This key is shared among every download of the distribution. \
                     Do NOT use it to join the public testnet as a validator — \
                     multiple users sharing this identity will equivocate. \
                     Safe for: single-node smoke tests and self-hosted testnet only. \
                     To run as a real validator, delete {} and restart.",
                    validator_key_path.display(),
                );
            }
        }
    }

    // ── CRIT #1 fix: Load genesis committee from manifest (not placeholders) ──
    let genesis_path = resolve_genesis_committee_path(cli.genesis_path.as_deref());
    tracing::info!(path = %genesis_path.display(), "Loading genesis committee manifest");

    // ── 0.9.0 β-2 / γ-2.5: bootstrap StakingRegistry + run JSON migration ──
    //
    // start_narwhal_node previously had no StakingRegistry of its own (the
    // REST `/api/register_validator` route wrote to `registered_validators.json`
    // directly). 0.9.0 consolidates the system-A REST flow onto the same
    // StakingRegistry that system-B (`/api/v1/validators/*`) already uses, so
    // we bootstrap it here — before the rpc_router closures capture the Arc
    // handles — and run the one-shot JSON → registry migration.
    //
    // γ-2.5: the bootstrap body moved to `validator_lifecycle_bootstrap` so
    // `start_dag_node` can share the same code path. Pure refactor — behavior
    // matches the pre-γ-2.5 inline implementation for `seed_on_fresh = false`.
    // γ-3: allocate StakingConfig as a process-wide Arc once; share via clone.
    // Group 1: route construction through `build_staking_config_for_chain` so
    // mainnet/testnet selection and any NodeConfig-level override live in one
    // place.
    //
    // Option A: `loaded_config` is now passed through `main()` → entry fn,
    // so the NodeConfig.staking_unbonding_period override from testnet.toml
    // is honored. On pure-CLI runs (no config file) `loaded_config` is
    // `None` and we fall back to chain defaults.
    let staking_config: Arc<misaka_consensus::staking::StakingConfig> = Arc::new(
        crate::staking_config_builder::build_staking_config_for_chain(
            cli.chain_id,
            loaded_config.as_ref(),
        ),
    );
    tracing::info!(
        "StakingConfig[narwhal]: chain_id={}, unbonding_epochs={}, min_stake={}, max_validators={}, nodeconfig={}",
        cli.chain_id,
        staking_config.unbonding_epochs,
        staking_config.min_validator_stake,
        staking_config.max_active_validators,
        if loaded_config.is_some() { "provided" } else { "none" },
    );
    let lifecycle_bootstrap = crate::validator_lifecycle_bootstrap::bootstrap_validator_lifecycle(
        data_dir,
        cli.chain_id,
        staking_config.clone(),
        &genesis_path,
        "narwhal",
        /* seed_on_fresh = */ false,
    )
    .await?;
    // narwhal path does not yet wire the store handle downstream (the
    // persist-on-shutdown path lives in `start_dag_node`); hold a binding
    // anyway so `install_global_store` stays referenced and the store
    // survives for the globally-registered instance.
    let _validator_lifecycle_store = lifecycle_bootstrap.store;
    let validator_registry = lifecycle_bootstrap.registry;
    // γ-3.1: consumed below when constructing `NarwhalMempoolIngress` so the
    // mempool admission pipeline can filter stake txs against the same
    // StakingConfig the executor and registry see.
    let staking_config_arc = lifecycle_bootstrap.staking_config;
    let current_epoch: Arc<RwLock<u64>> = Arc::new(RwLock::new(lifecycle_bootstrap.current_epoch));
    // γ-persistence: share the epoch-progress handle with REST write handlers
    // (`/api/register_validator` and `/api/deregister_validator`) so each
    // mutation can call `persist_global_state` to atomically snapshot
    // registry + epoch + progress to disk. Previously this was discarded
    // here as `_validator_epoch_progress` (reserved-for-future), so REST
    // writes only updated in-memory state and were lost on restart.
    let validator_epoch_progress: Arc<
        Mutex<validator_lifecycle_persistence::ValidatorEpochProgress>,
    > = Arc::new(Mutex::new(lifecycle_bootstrap.epoch_progress));

    // 0.9.0 β-2: use `load()` (TOML only) + `build_committee_from_sources`.
    // The legacy `load_with_registered` merge is now a no-op because the
    // migration above has already renamed `registered_validators.json`, but
    // we switch to the explicit split call to keep the code self-describing.
    let manifest = crate::genesis_committee::GenesisCommitteeManifest::load(&genesis_path)?;
    manifest.validate()?;
    let manifest_validator_count = manifest.validators.len();

    // Auto-detect authority_index from genesis committee by matching our pubkey.
    // This removes the need for users to manually set --validator-index and
    // --validators when joining a multi-validator network.
    let auto_detected = manifest.find_by_pubkey(identity.public_key());
    if let Some(detected_idx) = auto_detected {
        if cli.validator_index == 0 && detected_idx != 0 {
            tracing::info!(
                "Auto-detected authority_index={} from genesis committee (overriding default --validator-index=0)",
                detected_idx,
            );
        }
    }
    let authority_index = auto_detected.unwrap_or(cli.validator_index as u32);
    let _effective_validator_count = manifest_validator_count;

    // Override CLI values with auto-detected / manifest values
    if cli.validators != manifest_validator_count {
        tracing::info!(
            "Adjusting --validators from {} to {} (matching genesis committee)",
            cli.validators,
            manifest_validator_count,
        );
        cli.validators = manifest_validator_count;
    }
    if cli.validator_index != authority_index as usize {
        cli.validator_index = authority_index as usize;
    }
    if cli.validator {
        let expected_manifest_entry =
            manifest
                .validators
                .get(cli.validator_index)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "missing genesis entry for validator index {}",
                        cli.validator_index
                    )
                })?;
        let expected_network_addr = expected_manifest_entry
            .network_address
            .parse::<SocketAddr>()
            .map_err(|e| {
                anyhow::anyhow!(
                    "invalid network_address '{}' for authority {}: {}",
                    expected_manifest_entry.network_address,
                    expected_manifest_entry.authority_index,
                    e
                )
            })?;
        if expected_network_addr.port() != cli.p2p_port {
            anyhow::bail!(
                "p2p port mismatch for authority {}: --p2p-port={} but genesis committee expects {}",
                expected_manifest_entry.authority_index,
                cli.p2p_port,
                expected_network_addr.port(),
            );
        }
    }
    // ── SEC-FIX v0.5.7: observer mode auto-detection ──
    //
    // If our validator.key fingerprint is in the genesis committee, run as
    // a normal validator. Otherwise, run in OBSERVER mode:
    //
    //  * skip the propose loop (we have no stake → cannot lead)
    //  * synthesise an authority_index above any committee member so the
    //    Narwhal relay outbound dialer treats every committee peer as
    //    "higher index" — wait, the dial filter actually requires
    //    `peer.authority_index > self.authority_index`, so a high
    //    sentinel index would *exclude* every real peer. Instead we set
    //    `observer_self = true` on the relay config, which bypasses the
    //    ordering filter entirely (see narwhal_block_relay_transport.rs).
    //  * the operator must run with `MISAKA_ACCEPT_OBSERVERS=1` for the
    //    handshake to succeed; otherwise we get repeated
    //    `Rejecting unknown relay peer` warnings on the operator side
    //    and `outbound handshake failed` on our side, and the node
    //    falls back to local self-progress.
    // Permissionless SR: a node counts as a full validator if EITHER
    // (a) it is listed in genesis_committee.toml (static committee), OR
    // (b) it is present in the StakingRegistry with state == Active
    //     (dynamic committee, reached via L1 StakeDeposit + γ-3 flow or
    //     the REST Solana-verified path β-2/β-3).
    //
    // Previously is_observer was `!manifest.contains(...)` only, so a
    // node that registered itself via StakeDeposit and was hot-reloaded
    // into the committee (Phase 8) would still enter OBSERVER MODE at
    // startup and skip the propose loop — invisible SR. `validator_id`
    // in the registry is the canonical SHA3-256(ML-DSA-65 pubkey), which
    // is bit-equivalent to `ValidatorIdentity::fingerprint()`.
    let in_static_committee = manifest.contains(authority_index, identity.public_key());
    let in_dynamic_committee = {
        let reg = validator_registry.read().await;
        is_dynamic_active_validator(&reg, &identity.fingerprint())
    };
    let is_observer = !in_static_committee && !in_dynamic_committee;
    if is_observer {
        tracing::warn!(
            "🔭 OBSERVER MODE: validator.key fingerprint={} is not in the \
             genesis committee and not ACTIVE in the staking registry. This \
             node will receive and verify blocks from the operator's \
             authority but will NOT propose. Operator must enable observer \
             acceptance (MISAKA_ACCEPT_OBSERVERS=1) for the handshake to \
             succeed. To become a validator, submit a StakeDeposit tx or \
             register via /api/register_validator.",
            hex::encode(identity.fingerprint()),
        );
    } else if in_static_committee {
        tracing::info!(
            "✅ VALIDATOR MODE (static): authority_index={} fingerprint={}",
            authority_index,
            hex::encode(identity.fingerprint()),
        );
    } else {
        // Dynamic-only: not in genesis TOML but ACTIVE in registry.
        tracing::info!(
            "✅ VALIDATOR MODE (dynamic): fingerprint={} — not in genesis \
             TOML but ACTIVE in staking registry; joining propose loop.",
            hex::encode(identity.fingerprint()),
        );
    }

    // 0.9.0 β-3: loud warning if the testnet override is active. This flag
    // makes `/api/register_validator` skip on-chain Solana verification, so
    // leaking it into a mainnet deployment is catastrophic.
    if cli.allow_unverified_validators {
        tracing::warn!(
            "SECURITY: --allow-unverified-validators is ENABLED. New validators \
             registered via /api/register_validator will be ACTIVATED without \
             on-chain Solana stake verification. This flag is for testnet/CI use \
             only — NEVER enable on mainnet."
        );
    }

    info!("startup[1/6]: building committee from manifest + StakingRegistry...");
    // 0.9.0 β-2: merge genesis TOML with any ACTIVE validators in the
    // StakingRegistry. At bootstrap nothing is ACTIVE yet (the registry
    // was either restored from snapshot or created fresh), so this is
    // equivalent to `manifest.to_committee()` on first boot; on restart
    // it picks up validators that had reached ACTIVE before shutdown.
    let committee = {
        let registry_guard = validator_registry.read().await;
        crate::genesis_committee::build_committee_from_sources(&manifest, &registry_guard)?
    };
    let committee_shared: std::sync::Arc<
        tokio::sync::RwLock<misaka_dag::narwhal_types::committee::Committee>,
    > = std::sync::Arc::new(tokio::sync::RwLock::new(committee.clone()));
    info!("startup[2/6]: parsing validator keys...");
    let relay_public_key = identity.validator_public_key()?;
    let relay_secret_key = Arc::new(identity.validator_secret_key()?);
    info!("startup[3/6]: validator keys OK");

    struct IdentityBlockSigner {
        identity: crate::identity::ValidatorIdentity,
    }
    impl std::fmt::Debug for IdentityBlockSigner {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                f,
                "IdentityBlockSigner({}..)",
                hex::encode(&self.identity.fingerprint()[..8])
            )
        }
    }
    impl misaka_dag::BlockSigner for IdentityBlockSigner {
        fn sign(&self, message: &[u8]) -> Vec<u8> {
            self.identity.sign_block(message).unwrap_or_else(|e| {
                tracing::error!("Block signing failed: {}", e);
                vec![]
            })
        }
        fn public_key(&self) -> Vec<u8> {
            self.identity.public_key().to_vec()
        }
    }
    // Phase 10 (Item 1): snapshot the identity fingerprint BEFORE `identity`
    // is moved into `IdentityBlockSigner`. The commit loop below uses this
    // copy to detect self-activation and exit-for-restart.
    let self_fingerprint_for_restart: [u8; 32] = identity.fingerprint();
    let signer: std::sync::Arc<dyn misaka_dag::BlockSigner> =
        std::sync::Arc::new(IdentityBlockSigner { identity });

    let store_path = data_dir.join("narwhal_consensus");

    // Guard: on a fresh start (no chain.db), wipe any leftover RocksDB data.
    // Without this, a genesis reset that deletes chain.db but leaves
    // narwhal_consensus/ intact causes the tx/addr index to contain entries
    // from the old chain while the UTXO set starts empty — producing the
    // "balance 0 but 199 historical transactions" inconsistency.
    {
        let chain_db = data_dir.join("chain.db");
        if !chain_db.exists() && store_path.exists() {
            warn!(
                "Fresh start detected (no chain.db) but stale RocksDB found at {} — \
                 wiping to prevent index inconsistency",
                store_path.display()
            );
            if let Err(e) = std::fs::remove_dir_all(&store_path) {
                error!(
                    "Failed to remove stale RocksDB at {}: {}",
                    store_path.display(),
                    e
                );
                anyhow::bail!(
                    "Cannot remove stale narwhal_consensus directory: {e}. \
                     Delete it manually and restart."
                );
            }
            let snapshot = data_dir.join("narwhal_utxo_snapshot.json");
            if snapshot.exists() {
                warn!("Removing stale UTXO snapshot: {}", snapshot.display());
                let _ = std::fs::remove_file(&snapshot);
            }
            info!("Stale data removed — proceeding with clean genesis");
        }
    }

    info!(
        "startup[4/6]: opening RocksDB at {}...",
        store_path.display()
    );
    let rocks_store = std::sync::Arc::new(
        misaka_dag::narwhal_dag::rocksdb_store::RocksDbConsensusStore::open(&store_path)?,
    );
    let tx_index_store = rocks_store.clone();
    let tx_index_store_rpc = rocks_store.clone();
    let addr_index_store_rpc = rocks_store.clone();
    // Phase 2 Path X R1 step 2: share the consensus RocksDB with the
    // Kaspa-aligned `startup_integrity` committed-tip writer. Used
    // below in the Narwhal commit loop to call
    // `misaka_storage::write_committed_state` on every commit that
    // advances the UTXO tip, and on shutdown. See
    // `docs/design/v090_phase2_tail_work.md` §2 for the wider plan.
    let integrity_store = rocks_store.clone();
    let store: std::sync::Arc<dyn misaka_dag::narwhal_dag::store::ConsensusStore> =
        rocks_store.clone();
    info!("startup[5/6]: RocksDB opened OK");
    let committee_pks: Vec<Vec<u8>> = committee
        .authorities
        .iter()
        .map(|auth| auth.public_key.clone())
        .collect();
    let genesis_hash = misaka_types::genesis::compute_genesis_hash(cli.chain_id, &committee_pks);
    let chain_ctx = misaka_types::chain_context::ChainContext::new(cli.chain_id, genesis_hash);
    info!(
        "ChainContext: chain_id={}, genesis_hash={}",
        chain_ctx.chain_id,
        hex::encode(&chain_ctx.genesis_hash[..8]),
    );

    // Runtime config
    //
    // leader_round_wave = 1 (v0.9.0): every round is a leader round, so
    // every authority rotates through the leader slot at rate 1 per
    // committee size. Earlier testnet used wave=2, which combined with
    // `leader(r) = r % n` only elected EVEN authorities (indices 0,2,4,...)
    // for even committee sizes — odd-indexed validators NEVER became
    // leaders, so any tx submitted through them via mempool only entered
    // their own block and was never included in the leader sub-DAG
    // (faucet stuck at “承認待ち” in wallets pointing to odd-index nodes).
    let config = RuntimeConfig {
        committee: committee.clone(),
        authority_index,
        leader_round_wave: 1,
        timeout_base_ms: 2000,
        timeout_max_ms: 60_000,
        dag_config: DagStateConfig::default(),
        checkpoint_interval: 100,
        custom_verifier: None, // production MlDsa65Verifier (default)
        retention_rounds: 10_000,
    };

    info!("startup[6/6]: spawning consensus runtime...");
    let (msg_tx, mut commit_rx, mut block_rx, metrics, backpressure, runtime_handle) =
        spawn_consensus_runtime(config, signer, Some(store), chain_ctx);

    let our_manifest_entry = manifest
        .validators
        .iter()
        .find(|validator| validator.authority_index == authority_index)
        .ok_or_else(|| anyhow::anyhow!("missing local validator in genesis manifest"))?;
    let relay_listen_port = our_manifest_entry
        .network_address
        .parse::<SocketAddr>()
        .map(|addr| addr.port())
        .unwrap_or(cli.p2p_port);
    // SEC-FIX v0.5.7: hidden mode used to advertise to nobody but the
    // Narwhal relay still bound 0.0.0.0:<relay_port>, leaking an inbound
    // listener that contradicted the operator's "hidden" choice. The
    // bind IP is now derived from `cli.mode`:
    //   - public / seed → 0.0.0.0  (accept inbound)
    //   - hidden        → 127.0.0.1 (loopback only — outbound dial works
    //                     through the kernel's normal routing, but no
    //                     external host can connect inbound)
    let node_mode_for_bind = crate::config::NodeMode::from_str_loose(&cli.mode);
    let relay_bind_octets = match node_mode_for_bind {
        crate::config::NodeMode::Hidden => [127, 0, 0, 1],
        crate::config::NodeMode::Public | crate::config::NodeMode::Seed => [0, 0, 0, 0],
    };
    let relay_listen_addr = SocketAddr::from((relay_bind_octets, relay_listen_port));
    info!(
        "Narwhal relay bind: {} (mode={:?})",
        relay_listen_addr, node_mode_for_bind
    );
    let mut relay_peers: Vec<crate::narwhal_block_relay_transport::RelayPeer> = manifest
        .validators
        .iter()
        .filter(|validator| validator.authority_index != authority_index)
        .filter_map(|validator| {
            let address = validator.network_address.parse::<SocketAddr>().ok()?;
            let public_key = misaka_crypto::validator_sig::ValidatorPqPublicKey::from_bytes(
                &hex::decode(validator.public_key.trim_start_matches("0x")).ok()?,
            )
            .ok()?;
            Some(crate::narwhal_block_relay_transport::RelayPeer {
                authority_index: validator.authority_index,
                address,
                public_key,
                force_dial: false,
            })
        })
        .collect();

    // ── SEC-FIX: `--seeds` → Narwhal relay wiring ─────────────────────
    //
    // Historically the `--seeds` argument was parsed but never wired into
    // the Narwhal relay transport. `relay_peers` was built exclusively from
    // `genesis_committee.toml`, so a user running the bundled distribution
    // against a remote seed would silently operate in solo mode (see the
    // v0.5.5 audit finding "node is not connecting to the seed IP").
    //
    // This block reconciles each --seeds/--seed-pubkeys pair against the
    // committee (validation of counts already happened in `main()` before
    // this function was called):
    //
    //  1. If the seed's pubkey matches an existing committee member, the
    //     member's `network_address` is overridden with the `--seeds`
    //     address. This handles the common case of a bundled genesis file
    //     shipped with a placeholder / loopback address for a validator
    //     that is actually reachable at a different host.
    //
    //  2. If the pubkey does not match any committee member, the seed is
    //     added as a synthetic observer peer (authority_index beyond the
    //     committee range). Such peers receive broadcasts so they can
    //     relay traffic, but their blocks will still be rejected by
    //     `BlockVerifier` because their authority_index is out of range —
    //     so observer seeds cannot forge consensus participation.
    //
    // All --seeds peers have `force_dial = true`, which bypasses the
    // `authority_index > self.authority_index` ordering filter in the
    // Narwhal relay transport. This ensures a validator behind NAT can
    // always proactively dial the seed, even when the seed's
    // authority_index is lower than ours.
    if !cli.seeds.is_empty() && cli.seeds.len() == cli.seed_pubkeys.len() {
        let mut synthetic_index = manifest.validators.len() as u32;
        for (addr_s, pk_s) in cli.seeds.iter().zip(cli.seed_pubkeys.iter()) {
            // v0.5.11 audit Mid #8: previously we emitted a warning and
            // `continue`d on invalid seed address / pubkey / ML-DSA key,
            // which let a typo silently disable a seed. Fail closed
            // instead: the operator wants every seed they asked for, so
            // any malformed entry is a configuration error that must
            // stop startup.
            let addr = addr_s.parse::<SocketAddr>().unwrap_or_else(|e| {
                error!(
                    "FATAL: --seeds entry '{}' is not a valid SocketAddr: {}. \
                     Refusing to start with a malformed seed — fix the config.",
                    addr_s, e
                );
                std::process::exit(1);
            });
            let pk_hex = pk_s.trim_start_matches("0x");
            let pk_bytes = hex::decode(pk_hex).unwrap_or_else(|e| {
                error!(
                    "FATAL: --seed-pubkeys entry for '{}' is not valid hex: {}. \
                     Refusing to start.",
                    addr_s, e
                );
                std::process::exit(1);
            });
            let pk = misaka_crypto::validator_sig::ValidatorPqPublicKey::from_bytes(&pk_bytes)
                .unwrap_or_else(|e| {
                    error!(
                        "FATAL: --seed-pubkeys entry for '{}' is not a valid ML-DSA-65 \
                         public key: {}. Refusing to start.",
                        addr_s, e
                    );
                    std::process::exit(1);
                });
            let pk_snapshot = pk.to_bytes();
            if let Some(existing) = relay_peers
                .iter_mut()
                .find(|p| p.public_key.to_bytes() == pk_snapshot)
            {
                let old_addr = existing.address;
                existing.address = addr;
                existing.force_dial = true;
                info!(
                    "--seeds: overriding committee authority_index={} address {} → {} (force_dial=true)",
                    existing.authority_index, old_addr, addr,
                );
            } else {
                info!(
                    "--seeds: adding observer peer synthetic_authority_index={} addr={}",
                    synthetic_index, addr,
                );
                relay_peers.push(crate::narwhal_block_relay_transport::RelayPeer {
                    authority_index: synthetic_index,
                    address: addr,
                    public_key: pk,
                    force_dial: true,
                });
                synthetic_index = synthetic_index.saturating_add(1);
            }
        }
    }

    if relay_peers.is_empty() {
        warn!(
            "SOLO MODE: no relay peers configured. This node will propose, \
             self-vote, and self-commit without any remote participants. \
             To join a multi-validator network, add the other validators to \
             genesis_committee.toml or pass --seeds + --seed-pubkeys at \
             startup."
        );
    } else {
        info!(
            "Narwhal relay peers configured: {} (committee members and/or --seeds)",
            relay_peers.len()
        );
    }

    let (relay_in_tx, mut relay_in_rx) = tokio::sync::mpsc::channel(1024);
    let (relay_out_tx, relay_out_rx) = tokio::sync::mpsc::channel(1024);
    let block_cache: Arc<RwLock<BTreeMap<BlockRef, NarwhalBlock>>> =
        Arc::new(RwLock::new(BTreeMap::new()));
    let connected_peers: Arc<RwLock<BTreeSet<u32>>> = Arc::new(RwLock::new(BTreeSet::new()));
    let observer_count: Arc<std::sync::atomic::AtomicU32> =
        Arc::new(std::sync::atomic::AtomicU32::new(0));
    #[derive(Clone, serde::Serialize)]
    struct ObserverInfo {
        peer_id: String,
        address: String,
        public_key: String,
        connected_at: u64,
    }
    let observer_registry: Arc<RwLock<std::collections::HashMap<String, ObserverInfo>>> =
        Arc::new(RwLock::new(std::collections::HashMap::new()));
    // SEC-FIX v0.5.7: opt-in observer acceptance.
    //
    // Validators set `MISAKA_ACCEPT_OBSERVERS=1` (typically only on the
    // public-facing operator node) to allow read-only observers to connect.
    // Observers do not contribute to consensus — see
    // narwhal_block_relay_transport.rs::OBSERVER_SENTINEL_AUTHORITY.
    let accept_observers = env_flag_enabled("MISAKA_ACCEPT_OBSERVERS");
    if accept_observers {
        info!(
            "Narwhal relay: MISAKA_ACCEPT_OBSERVERS=1 — accepting connections \
             from observers (read-only peers not in genesis_committee)"
        );
    }
    let relay_transport_handle =
        crate::narwhal_block_relay_transport::spawn_narwhal_block_relay_transport(
            crate::narwhal_block_relay_transport::NarwhalRelayTransportConfig {
                listen_addr: relay_listen_addr,
                chain_id: cli.chain_id,
                authority_index,
                public_key: relay_public_key,
                secret_key: relay_secret_key,
                peers: relay_peers,
                guard_config: p2p_config.guard.clone(),
                accept_observers,
                observer_self: is_observer,
            },
            relay_in_tx,
            relay_out_rx,
        )
        .map_err(|err| {
            anyhow::anyhow!(
                "Failed to bind Narwhal relay on {}: {}",
                relay_listen_addr,
                err
            )
        })?;

    info!(
        "Mysticeti-equivalent consensus runtime started (authority={}, committee={})",
        authority_index,
        committee.size()
    );

    // v0.5.9: process-global safe-mode flag. Tripped on state_root
    // mismatch. Polled by the commit loop, propose loop, and write RPC
    // handlers. Drop-in against v0.5.7/v0.5.8 — no wire changes.
    let safe_mode = Arc::new(crate::safe_mode::SafeMode::new());

    // Shared UtxoSet snapshot for RPC queries and mempool admission.
    // Both RPC and mempool share the same Arc to avoid duplicating ~600MB.
    let shared_utxo_set: Arc<tokio::sync::RwLock<misaka_storage::utxo_set::UtxoSet>> = Arc::new(
        tokio::sync::RwLock::new(misaka_storage::utxo_set::UtxoSet::new(36)),
    );
    let utxo_set_writer = shared_utxo_set.clone();
    let utxo_set_rpc = shared_utxo_set.clone();

    // Phase 1: Spawn propose loop — drains mempool into CoreEngine
    let (mempool_propose_tx, mempool_propose_rx) =
        crate::narwhal_consensus::mempool_propose_channel(10_000);
    // Audit #26: Pass AppId so submit_tx can verify IntentMessage signatures
    let mempool_app_id = misaka_types::intent::AppId::new(cli.chain_id, genesis_hash);
    let narwhal_mempool = crate::narwhal_consensus::NarwhalMempoolIngress::new_with_shared_utxo(
        cli.dag_mempool_size,
        shared_utxo_set.clone(),
        mempool_propose_tx.clone(),
        mempool_app_id,
        // γ-3.1: inject the process-wide Arc<StakingConfig> so the mempool
        // can filter stake txs (envelope + min_validator_stake) before they
        // enter the DAG relay pipeline.
        staking_config_arc.clone(),
    );
    // Shared state_root: updated by executor after each commit, read by propose loop
    let shared_state_root = std::sync::Arc::new(tokio::sync::RwLock::new([0u8; 32]));
    let propose_state_root = shared_state_root.clone();

    // Ring buffer of recent committed block summaries for the explorer RPC.
    #[derive(Clone, serde::Serialize)]
    struct BlockSummary {
        height: u64,
        hash: String,
        tx_count: usize,
        txs_accepted: usize,
        timestamp_ms: u64,
        author: u32,
        state_root: String,
        fees: u64,
    }
    let recent_blocks: Arc<tokio::sync::RwLock<std::collections::VecDeque<BlockSummary>>> =
        Arc::new(tokio::sync::RwLock::new(
            std::collections::VecDeque::with_capacity(64),
        ));
    let recent_blocks_writer = recent_blocks.clone();
    let recent_blocks_rpc = recent_blocks.clone();

    // Shared persistent block height (from UtxoExecutor), survives restarts
    let shared_block_height: Arc<std::sync::atomic::AtomicU64> =
        Arc::new(std::sync::atomic::AtomicU64::new(0));
    let block_height_writer = shared_block_height.clone();
    let block_height_rpc = shared_block_height.clone();

    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    struct TxInputSummary {
        utxo_refs: Vec<String>,
    }
    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    struct TxOutputSummary {
        address: String,
        amount: u64,
    }
    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    struct CommittedTxDetail {
        height: u64,
        status: String,
        tx_type: String,
        inputs: Vec<TxInputSummary>,
        outputs: Vec<TxOutputSummary>,
        fee: u64,
        timestamp_ms: u64,
        leader_authority: u32,
        participating_validators: Vec<u32>,
        memo: String,
    }
    #[derive(Clone, serde::Serialize, serde::Deserialize)]
    struct AddressTxRef {
        tx_hash: String,
        direction: String,
        amount: u64,
        height: u64,
        timestamp_ms: u64,
        tx_type: String,
    }

    // In-memory cache (bounded) + RocksDB for persistence
    let committed_txs: Arc<
        tokio::sync::RwLock<std::collections::HashMap<[u8; 32], CommittedTxDetail>>,
    > = Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()));
    let committed_txs_writer = committed_txs.clone();
    let committed_txs_rpc = committed_txs.clone();

    // SEC-FIX v0.5.7: do not spawn the propose loop in observer mode.
    // Observers receive blocks from committee members but never propose
    // (they have no stake and no committee membership). Without this
    // gate, the propose loop would still run and emit blocks signed by
    // an unknown identity, which committee verifiers would reject and
    // log as `unknown peer pubkey` noise.
    let propose_loop_handle = if is_observer {
        info!("Observer mode: skipping propose loop (read-only node)");
        None
    } else {
        Some(crate::narwhal_consensus::spawn_propose_loop(
            msg_tx.clone(),
            mempool_propose_rx,
            crate::narwhal_consensus::ProposeLoopConfig {
                max_block_txs: cli.dag_max_txs,
                backpressure: backpressure.clone(),
                ..crate::narwhal_consensus::ProposeLoopConfig::default()
            },
            propose_state_root,
            Some(safe_mode.clone()),
        ))
    };

    // Start RPC server (minimal — submit_tx + status)
    let rpc_port = cli.rpc_port;
    // SECURITY: default to localhost-only binding (127.0.0.1). Operators may
    // pass `--rpc-bind 0.0.0.0` (or env `MISAKA_RPC_BIND=0.0.0.0`) when the
    // RPC port is firewalled to a trusted network.
    let rpc_addr: std::net::SocketAddr =
        format!("{}:{}", cli.rpc_bind, rpc_port)
            .parse()
            .map_err(|e| {
                anyhow::anyhow!("invalid --rpc-bind '{}:{}': {}", cli.rpc_bind, rpc_port, e)
            })?;
    let msg_tx_rpc = msg_tx.clone();
    let metrics_rpc = metrics.clone();

    // SEC-FIX [Audit H3]: Load RPC auth state for write endpoint protection.
    let auth_state =
        crate::rpc_auth::ApiKeyState::from_env_checked(cli.chain_id).unwrap_or_else(|e| {
            error!("RPC auth config error: {}", e);
            std::process::exit(1);
        });

    const RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

    let rpc_router = axum::Router::new()
        .route("/api/health", axum::routing::get({
            let msg_tx = msg_tx_rpc.clone();
            let safe_mode = safe_mode.clone();
            move || {
                let msg_tx = msg_tx.clone();
                let safe_mode = safe_mode.clone();
                async move {
                    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                    let _ = msg_tx.try_send(ConsensusMessage::GetStatus(reply_tx));
                    // v0.5.9: surface safe-mode so operators can detect
                    // a halted node with a single curl call.
                    let safe_mode_json = safe_mode.status().map(|(commit, reason)| {
                        serde_json::json!({
                            "halted": true,
                            "haltedAtCommit": commit,
                            "reason": reason,
                        })
                    }).unwrap_or_else(|| serde_json::json!({"halted": false}));
                    match tokio::time::timeout(RPC_TIMEOUT, reply_rx).await {
                        Ok(Ok(status)) => axum::Json(serde_json::json!({
                            "status": if safe_mode.is_halted() { "safe_mode" } else { "ok" },
                            "consensus": "mysticeti-equivalent",
                            "blocks": status.num_blocks,
                            "round": status.highest_accepted_round,
                            "safeMode": safe_mode_json,
                        })),
                        _ => axum::Json(serde_json::json!({
                            "status": "error",
                            "consensus": "stopped",
                            "safeMode": safe_mode_json,
                        })),
                    }
                }
            }
        }))
        .route("/api/ready", axum::routing::get({
            let msg_tx = msg_tx_rpc.clone();
            move || {
                let msg_tx = msg_tx.clone();
                async move {
                    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                    let _ = msg_tx.try_send(ConsensusMessage::GetStatus(reply_tx));
                    match tokio::time::timeout(RPC_TIMEOUT, reply_rx).await {
                        Ok(Ok(_)) => (axum::http::StatusCode::OK, "ready"),
                        _ => (axum::http::StatusCode::SERVICE_UNAVAILABLE, "not ready"),
                    }
                }
            }
        }))
        .route("/api/status", axum::routing::get({
            let msg_tx = msg_tx_rpc.clone();
            move || {
                let msg_tx = msg_tx.clone();
                async move {
                    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                    let _ = msg_tx.try_send(ConsensusMessage::GetStatus(reply_tx));
                    match tokio::time::timeout(RPC_TIMEOUT, reply_rx).await {
                        Ok(Ok(status)) => axum::Json(serde_json::json!(status)),
                        _ => axum::Json(serde_json::json!({"error": "runtime busy or closed"})),
                    }
                }
            }
        }))
        .nest(
            "/api/metrics",
            axum::Router::new()
                .route("/", axum::routing::get({
                    let m = metrics_rpc.clone();
                    move || {
                        let m = m.clone();
                        async move {
                            misaka_dag::narwhal_dag::prometheus::PrometheusExporter::new(m).export()
                        }
                    }
                }))
                .route_layer(axum::middleware::from_fn_with_state(
                    auth_state.clone(),
                    crate::rpc_auth::require_api_key,
                )),
        )
        .route("/api/get_mempool_info", axum::routing::get({
            let narwhal_mempool = narwhal_mempool.clone();
            move || {
                let narwhal_mempool = narwhal_mempool.clone();
                async move { axum::Json(narwhal_mempool.mempool_info().await) }
            }
        }))
        .route("/api/register_validator", axum::routing::post({
            // 0.9.0 β-2: compatibility wrapper over `StakingRegistry::register`.
            // Response shape remains identical to 0.8.8 (`{ok, message, note}`)
            // so existing Python/bash clients keep working. The new
            // `intent_verified: bool` field is appended for clients that opt
            // in by sending `intent_signature` in the body.
            let reload_genesis_path = genesis_path.clone();
            let reload_msg_tx = msg_tx.clone();
            let reload_committee = committee_shared.clone();
            let route_registry = validator_registry.clone();
            let route_epoch = current_epoch.clone();
            // γ-persistence: capture the lifecycle progress handle so this
            // handler can call `persist_global_state` after a successful
            // registration. Without this the registry mutation lives only
            // in-memory and is lost on the next restart.
            let route_epoch_progress = validator_epoch_progress.clone();
            let allow_unverified = cli.allow_unverified_validators;
            move |body: axum::body::Bytes| {
                let reload_genesis_path = reload_genesis_path.clone();
                let reload_msg_tx = reload_msg_tx.clone();
                let reload_committee = reload_committee.clone();
                let route_registry = route_registry.clone();
                let route_epoch = route_epoch.clone();
                let route_epoch_progress = route_epoch_progress.clone();
                async move {
                    let req: Result<crate::genesis_committee::RegisterValidatorRequest, _> =
                        serde_json::from_slice(&body);
                    let rv = match req {
                        Ok(rv) => rv,
                        Err(e) => return axum::Json(serde_json::json!({
                            "ok": false,
                            "error": format!("invalid JSON: {e}"),
                        })),
                    };
                    let pk_hex = rv.public_key.strip_prefix("0x")
                        .unwrap_or(&rv.public_key);
                    let pubkey_bytes = match hex::decode(pk_hex) {
                        Ok(b) if b.len() == 1952 => b,
                        _ => return axum::Json(serde_json::json!({
                            "ok": false,
                            "error": "public_key must be a 1952-byte ML-DSA-65 key (hex)",
                        })),
                    };
                    if rv.network_address.parse::<std::net::SocketAddr>().is_err() {
                        return axum::Json(serde_json::json!({
                            "ok": false,
                            "error": "network_address must be ip:port",
                        }));
                    }

                    // Derive validator_id via the canonical ML-DSA-65 → 32-byte id.
                    let pq_pk = match misaka_crypto::validator_sig::ValidatorPqPublicKey::from_bytes(
                        &pubkey_bytes,
                    ) {
                        Ok(p) => p,
                        Err(e) => return axum::Json(serde_json::json!({
                            "ok": false,
                            "error": format!("invalid ML-DSA-65 key: {e}"),
                        })),
                    };
                    let validator_id = pq_pk.to_canonical_id();

                    // 0.9.0 β-2: optional ML-DSA-65 intent_signature verification.
                    // Binds the request to (pubkey, network_address) with a
                    // domain-tagged digest so it cannot be replayed to other
                    // endpoints.
                    let intent_verified = match rv.intent_signature.as_deref() {
                        Some(sig_hex) if !sig_hex.trim().is_empty() => {
                            let sig_hex = sig_hex.trim().strip_prefix("0x").unwrap_or(sig_hex.trim());
                            let sig_bytes = match hex::decode(sig_hex) {
                                Ok(b) => b,
                                Err(e) => return axum::Json(serde_json::json!({
                                    "ok": false,
                                    "error": format!("intent_signature hex decode failed: {e}"),
                                })),
                            };
                            let digest = crate::genesis_committee::RegisterValidatorRequest::signing_payload(
                                &pubkey_bytes, &rv.network_address,
                            );
                            let pk = match misaka_pqc::pq_sign::MlDsaPublicKey::from_bytes(&pubkey_bytes) {
                                Ok(p) => p,
                                Err(e) => return axum::Json(serde_json::json!({
                                    "ok": false,
                                    "error": format!("intent_signature: pubkey parse failed: {e}"),
                                })),
                            };
                            let sig = match misaka_pqc::pq_sign::MlDsaSignature::from_bytes(&sig_bytes) {
                                Ok(s) => s,
                                Err(e) => return axum::Json(serde_json::json!({
                                    "ok": false,
                                    "error": format!("intent_signature: sig parse failed: {e}"),
                                })),
                            };
                            if misaka_pqc::pq_sign::ml_dsa_verify_raw(&pk, &digest, &sig).is_err() {
                                return axum::Json(serde_json::json!({
                                    "ok": false,
                                    "error": "intent_signature verification failed",
                                }));
                            }
                            true
                        }
                        _ => false,
                    };

                    // Bootstrap parameters — mirror `start_dag_node`'s /api/v1/validators/register
                    // so a validator that registers via system A vs system B
                    // produces the same ValidatorAccount shape.
                    let epoch = *route_epoch.read().await;
                    let stake_tx_hash = {
                        use sha3::{Digest, Sha3_256};
                        let mut h = Sha3_256::new();
                        h.update(b"MISAKA:stake_lock:");
                        h.update(&pubkey_bytes);
                        h.update(epoch.to_le_bytes());
                        let r: [u8; 32] = h.finalize().into();
                        r
                    };
                    let reward_address = [0u8; 32]; // System A REST path has no reward hint
                    let commission_bps: u32 = 500;  // 5% default (matches bootstrap path)

                    let mut registry = route_registry.write().await;
                    let min_stake = registry.config().min_validator_stake;

                    // Idempotency: if already present in any state, return
                    // the 0.8.8-compatible "already registered" note.
                    if registry.get(&validator_id).is_some() {
                        drop(registry);
                        return axum::Json(serde_json::json!({
                            "ok": true,
                            "message": "already registered",
                            "intent_verified": intent_verified,
                        }));
                    }

                    let reg_result = registry.register(
                        validator_id,
                        pubkey_bytes,
                        min_stake,
                        commission_bps,
                        reward_address,
                        epoch,
                        stake_tx_hash,
                        0,
                        // β-3: when `--allow-unverified-validators` is set
                        // (testnet), trust the registration and mark the Solana
                        // flag true up-front so `activate()` below succeeds.
                        // Otherwise register as LOCKED/unverified and let the
                        // background verifier flip the flag on RPC success.
                        allow_unverified,
                        rv.solana_stake_signature.clone(),
                        // L1 path flag — set only by utxo_executor (γ-3).
                        false,
                    );
                    if let Err(e) = reg_result {
                        drop(registry);
                        return axum::Json(serde_json::json!({
                            "ok": false,
                            "error": format!("register failed: {e}"),
                        }));
                    }
                    if let Err(e) = registry.set_network_address(
                        &validator_id,
                        Some(rv.network_address.clone()),
                    ) {
                        tracing::warn!(
                            "register_validator: set_network_address failed for {}: {}",
                            rv.network_address, e,
                        );
                    }
                    // β-3: testnet override — promote LOCKED → ACTIVE
                    // immediately, no Solana RPC. Logs at warn! so the bypass
                    // is visible in production logs if the flag ever leaks
                    // into a non-testnet deployment.
                    if allow_unverified {
                        match registry.activate(&validator_id, epoch) {
                            Ok(()) => tracing::warn!(
                                "register_validator[unverified]: validator {} \
                                 ACTIVATED without Solana verification \
                                 (--allow-unverified-validators)",
                                hex::encode(&validator_id[..8]),
                            ),
                            Err(e) => tracing::warn!(
                                "register_validator[unverified]: activate failed \
                                 for {}: {} — validator stays LOCKED",
                                hex::encode(&validator_id[..8]), e,
                            ),
                        }
                    }
                    let total_now = registry.all_validators().count();
                    drop(registry);

                    tracing::info!(
                        "New validator registered via /api/register_validator \
                         (total in registry: {}, intent_verified: {})",
                        total_now, intent_verified,
                    );

                    // γ-persistence: snapshot the registry + epoch progress
                    // to `validator_lifecycle_chain_N.json` so the
                    // registration survives node restart. The companion
                    // `/api/v1/validators/*` path (system B, validator_api.rs)
                    // has always done this after every mutation; the
                    // system-A `/api/register_validator` path was missing
                    // the call, which is why nodes that went through this
                    // endpoint came back up with only the genesis TOML
                    // committee after a restart.
                    //
                    // Persist BEFORE hot-reload so a crash between write
                    // and reload still leaves the on-disk state
                    // authoritative; the committee will pick it up on
                    // next startup.
                    if let Err(e) =
                        crate::validator_lifecycle_persistence::persist_global_state(
                            &route_registry,
                            &route_epoch,
                            &route_epoch_progress,
                        )
                        .await
                    {
                        tracing::warn!(
                            "register_validator: persist_global_state failed                              (registration stays in-memory, will be lost on                              restart): {}",
                            e
                        );
                    }

                    // Hot-reload committee into consensus using the merged
                    // (genesis TOML + StakingRegistry ACTIVE) source of truth.
                    if let Ok(new_manifest) = crate::genesis_committee::GenesisCommitteeManifest::load(&reload_genesis_path) {
                        let registry_guard = route_registry.read().await;
                        if let Ok(new_committee) = crate::genesis_committee::build_committee_from_sources(
                            &new_manifest, &registry_guard,
                        ) {
                            drop(registry_guard);
                            *reload_committee.write().await = new_committee.clone();
                            let _ = reload_msg_tx.send(
                                misaka_dag::narwhal_dag::runtime::ConsensusMessage::ReloadCommittee(new_committee)
                            ).await;
                            tracing::info!("Committee hot-reloaded after registration");
                        }
                    }

                    // 0.9.0 β-3: fire-and-forget Solana stake verification.
                    // Three response states:
                    //   - "bypassed": --allow-unverified-validators set (testnet)
                    //   - "pending":  signature provided, background task spawned
                    //   - "skipped":  no signature, validator stays LOCKED
                    let stake_verification_status = if allow_unverified {
                        "bypassed"
                    } else {
                        match rv
                            .solana_stake_signature
                            .as_deref()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                        {
                            Some(sig) => {
                                spawn_verify_stake_background(
                                    validator_id,
                                    hex::encode(validator_id),
                                    sig.to_string(),
                                    min_stake,
                                    route_registry.clone(),
                                    reload_committee.clone(),
                                    route_epoch.clone(),
                                    reload_msg_tx.clone(),
                                    reload_genesis_path.clone(),
                                );
                                "pending"
                            }
                            None => "skipped",
                        }
                    };

                    axum::Json(serde_json::json!({
                        "ok": true,
                        "message": format!("registered as validator #{}", total_now),
                        "note": "committee reloaded (no restart needed)",
                        "intent_verified": intent_verified,
                        "stake_verification": stake_verification_status,
                    }))
                }
            }
        }))
        .route("/api/deregister_validator", axum::routing::post({
            // 0.9.0 β-2: routed through `StakingRegistry`:
            //   - Active    → `exit()` (enters unbonding via γ-5 unlock)
            //   - Locked    → `force_remove_locked()` (no unbonding needed)
            //   - Exiting   → already-exiting, no-op
            //   - Unlocked  → already-unlocked, no-op
            let reload_genesis_path = genesis_path.clone();
            let reload_msg_tx = msg_tx.clone();
            let reload_committee = committee_shared.clone();
            let route_registry = validator_registry.clone();
            let route_epoch = current_epoch.clone();
            // γ-persistence: same rationale as register_validator above —
            // deregistration (exit / force_remove_locked) must be durable.
            let route_epoch_progress = validator_epoch_progress.clone();
            move |body: axum::body::Bytes| {
                let reload_genesis_path = reload_genesis_path.clone();
                let reload_msg_tx = reload_msg_tx.clone();
                let reload_committee = reload_committee.clone();
                let route_registry = route_registry.clone();
                let route_epoch = route_epoch.clone();
                let route_epoch_progress = route_epoch_progress.clone();
                async move {
                    #[derive(serde::Deserialize)]
                    struct DeregisterRequest {
                        public_key: Option<String>,
                        network_address: Option<String>,
                    }
                    let req: Result<DeregisterRequest, _> = serde_json::from_slice(&body);
                    let dr = match req {
                        Ok(dr) => dr,
                        Err(e) => return axum::Json(serde_json::json!({
                            "ok": false,
                            "error": format!("invalid JSON: {e}"),
                        })),
                    };
                    if dr.public_key.is_none() && dr.network_address.is_none() {
                        return axum::Json(serde_json::json!({
                            "ok": false,
                            "error": "must provide public_key and/or network_address",
                        }));
                    }

                    // Identify candidate validator_ids by pubkey match and/or
                    // network_address match. We iterate the registry under a
                    // read lock, collect matches, then take write lock for
                    // state transitions.
                    let pk_needle: Option<Vec<u8>> = dr.public_key.as_deref().and_then(|s| {
                        let trimmed = s.strip_prefix("0x").unwrap_or(s);
                        let lower = trimmed.to_lowercase();
                        hex::decode(&lower).ok().filter(|b| b.len() == 1952)
                    });
                    let addr_needle: Option<&str> = dr.network_address.as_deref();

                    let matches: Vec<[u8; 32]> = {
                        let registry = route_registry.read().await;
                        registry
                            .all_validators()
                            .filter(|v| {
                                let pk_ok = pk_needle.as_ref()
                                    .map(|needle| needle == &v.pubkey)
                                    .unwrap_or(false);
                                let addr_ok = addr_needle
                                    .zip(v.network_address.as_deref())
                                    .map(|(a, b)| a == b)
                                    .unwrap_or(false);
                                pk_ok || addr_ok
                            })
                            .map(|v| v.validator_id)
                            .collect()
                    };

                    if matches.is_empty() {
                        return axum::Json(serde_json::json!({
                            "ok": false,
                            "error": "no matching validator found",
                        }));
                    }

                    let epoch = *route_epoch.read().await;
                    let mut removed = 0usize;
                    let mut errors: Vec<String> = Vec::new();
                    {
                        let mut registry = route_registry.write().await;
                        for id in &matches {
                            let state_label = registry
                                .get(id)
                                .map(|a| a.state.label())
                                .unwrap_or("UNKNOWN");
                            match state_label {
                                "ACTIVE" => {
                                    match registry.exit(id, epoch) {
                                        Ok(()) => removed += 1,
                                        Err(e) => errors.push(format!(
                                            "exit({}): {}", hex::encode(&id[..8]), e,
                                        )),
                                    }
                                }
                                "LOCKED" => {
                                    match registry.force_remove_locked(id) {
                                        Ok(()) => removed += 1,
                                        Err(e) => errors.push(format!(
                                            "force_remove_locked({}): {}",
                                            hex::encode(&id[..8]), e,
                                        )),
                                    }
                                }
                                "EXITING" | "UNLOCKED" => {
                                    tracing::info!(
                                        "deregister: {} already in {} state — no-op",
                                        hex::encode(&id[..8]), state_label,
                                    );
                                }
                                other => {
                                    errors.push(format!(
                                        "{}: unexpected state {}",
                                        hex::encode(&id[..8]), other,
                                    ));
                                }
                            }
                        }
                    }
                    tracing::info!(
                        "Deregistered {} validator(s) via /api/deregister_validator",
                        removed,
                    );
                    // γ-persistence: same as register_validator — durably
                    // snapshot the registry before triggering hot-reload so
                    // the mutation survives a restart.
                    if removed > 0 {
                        if let Err(e) =
                            crate::validator_lifecycle_persistence::persist_global_state(
                                &route_registry,
                                &route_epoch,
                                &route_epoch_progress,
                            )
                            .await
                        {
                            tracing::warn!(
                                "deregister_validator: persist_global_state                                  failed (change stays in-memory, will be                                  lost on restart): {}",
                                e
                            );
                        }
                    }
                    // Hot-reload committee on registry changes.
                    if removed > 0 {
                        if let Ok(new_manifest) = crate::genesis_committee::GenesisCommitteeManifest::load(&reload_genesis_path) {
                            let registry_guard = route_registry.read().await;
                            if let Ok(new_committee) = crate::genesis_committee::build_committee_from_sources(
                                &new_manifest, &registry_guard,
                            ) {
                                drop(registry_guard);
                                *reload_committee.write().await = new_committee.clone();
                                let _ = reload_msg_tx.send(
                                    misaka_dag::narwhal_dag::runtime::ConsensusMessage::ReloadCommittee(new_committee)
                                ).await;
                                tracing::info!("Committee hot-reloaded after deregistration");
                            }
                        }
                    }
                    let remaining = route_registry.read().await.all_validators().count();
                    let mut resp = serde_json::json!({
                        "ok": true,
                        "message": format!("removed {} validator(s)", removed),
                        "remaining": remaining,
                        "note": "committee reloaded (no restart needed)",
                    });
                    if !errors.is_empty() {
                        resp["errors"] = serde_json::Value::Array(
                            errors.into_iter().map(serde_json::Value::String).collect(),
                        );
                    }
                    axum::Json(resp)
                }
            }
        }))
        // (duplicate deregister_validator route removed — hot-reload version above)
        .route("/api/get_committee", axum::routing::get({
            // 0.9.0 β-2: combined view of genesis TOML + StakingRegistry ACTIVE
            // validators via `build_committee_from_sources`. Response shape is
            // preserved — each entry still has {authority_index, public_key,
            // network_address, stake} — but authority_index is now the
            // positional index in the merged committee.
            let gp = genesis_path.clone();
            let route_registry = validator_registry.clone();
            move || {
                let gp = gp.clone();
                let route_registry = route_registry.clone();
                async move {
                    let manifest = match crate::genesis_committee::GenesisCommitteeManifest::load(&gp) {
                        Ok(m) => m,
                        Err(e) => return axum::Json(serde_json::json!({
                            "error": format!("{e}"),
                        })),
                    };
                    let registry = route_registry.read().await;
                    let committee = match crate::genesis_committee::build_committee_from_sources(
                        &manifest, &registry,
                    ) {
                        Ok(c) => c,
                        Err(e) => return axum::Json(serde_json::json!({
                            "error": format!("build_committee_from_sources: {e}"),
                        })),
                    };
                    drop(registry);
                    let validators: Vec<serde_json::Value> = committee
                        .authorities
                        .iter()
                        .enumerate()
                        .map(|(i, a)| serde_json::json!({
                            "authority_index": i as u32,
                            "public_key": format!("0x{}", hex::encode(&a.public_key)),
                            "network_address": a.hostname,
                            "stake": a.stake,
                        }))
                        .collect();
                    axum::Json(serde_json::json!({
                        "epoch": committee.epoch,
                        "validators": validators,
                    }))
                }
            }
        }))
        // SEC-FIX v0.5.7: write endpoint now goes through the SHARED
        // `rpc_auth::require_api_key` middleware (Bearer + IP allowlist
        // + fail-closed on missing ConnectInfo). The previous inline
        // bearer check skipped IP allowlist entirely and made
        // `MISAKA_RPC_WRITE_ALLOWLIST` a no-op for write routes.
        .route(
            "/api/submit_tx",
            axum::routing::post({
                let narwhal_mempool = narwhal_mempool.clone();
                let safe_mode = safe_mode.clone();
                move |body: axum::body::Bytes| {
                    let narwhal_mempool = narwhal_mempool.clone();
                    let safe_mode = safe_mode.clone();
                    async move {
                        // v0.5.9: refuse writes while the node is halted
                        // on a state divergence.
                        if let Some((commit, reason)) = safe_mode.status() {
                            return axum::Json(serde_json::json!({
                                "accepted": false,
                                "safeMode": true,
                                "haltedAtCommit": commit,
                                "reason": reason,
                                "error": "node is in safe mode — write RPC disabled",
                            }));
                        }
                        // SECURITY: size limit (128 KiB) to prevent memory DoS
                        if body.len() > 131_072 {
                            return axum::Json(serde_json::json!({
                                "error": format!(
                                    "tx body too large: {} bytes (max 131072)",
                                    body.len()
                                ),
                                "accepted": false
                            }));
                        }
                        axum::Json(narwhal_mempool.submit_tx(&body).await)
                    }
                }
            })
            .route_layer(axum::middleware::from_fn_with_state(
                auth_state.clone(),
                crate::rpc_auth::require_api_key,
            )),
        )
        // ── Testnet: Faucet endpoint (inside auth layer) ──
        .route("/api/faucet", axum::routing::post({
            let narwhal_mempool = narwhal_mempool.clone();
            let faucet_chain_id = cli.chain_id;
            let faucet_cooldown_ms = cli.faucet_cooldown_ms;
            let faucet_cooldowns: std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<[u8; 32], u64>>> =
                std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
            let faucet_global_last: std::sync::Arc<std::sync::atomic::AtomicU64> =
                std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            const GLOBAL_FAUCET_MIN_INTERVAL_MS: u64 = 2000;
            move |body: axum::Json<serde_json::Value>| {
                let narwhal_mempool = narwhal_mempool.clone();
                let faucet_cooldowns = faucet_cooldowns.clone();
                let faucet_global_last = faucet_global_last.clone();
                async move {
                    let address_str = body.get("address").and_then(|v| v.as_str()).unwrap_or("");
                    let spending_pk_hex = body.get("spendingPubkey").and_then(|v| v.as_str());

                    let addr_bytes: Option<[u8; 32]> = if address_str.len() == 64 {
                        hex::decode(address_str).ok().and_then(|b| <[u8; 32]>::try_from(b).ok())
                    } else if address_str.starts_with("misakatest1") || address_str.starts_with("misaka1") {
                        misaka_types::address::decode_address(address_str, faucet_chain_id).ok()
                    } else {
                        None
                    };

                    let addr = match addr_bytes {
                        Some(a) => a,
                        None => {
                            return axum::Json(serde_json::json!({
                                "accepted": false,
                                "error": "invalid address format",
                            }));
                        }
                    };

                    // Global rate limit: at most one faucet tx every 2 seconds
                    {
                        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
                        let last = faucet_global_last.load(std::sync::atomic::Ordering::Relaxed);
                        if now_ms.saturating_sub(last) < GLOBAL_FAUCET_MIN_INTERVAL_MS {
                            return axum::Json(serde_json::json!({
                                "accepted": false,
                                "error": "rate limited: too many faucet requests globally",
                            }));
                        }
                        faucet_global_last.store(now_ms, std::sync::atomic::Ordering::Relaxed);
                    }

                    // Per-address cooldown to prevent rapid-fire OOM
                    if faucet_cooldown_ms > 0 {
                        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
                        let mut cooldowns = faucet_cooldowns.lock().await;
                        if let Some(&last_ms) = cooldowns.get(&addr) {
                            let elapsed = now_ms.saturating_sub(last_ms);
                            if elapsed < faucet_cooldown_ms {
                                let remaining = faucet_cooldown_ms - elapsed;
                                return axum::Json(serde_json::json!({
                                    "accepted": false,
                                    "error": format!("cooldown: retry after {}ms", remaining),
                                    "cooldownRemainingMs": remaining,
                                }));
                            }
                        }
                        cooldowns.insert(addr, now_ms);
                        // Evict stale entries (> 10x cooldown) to prevent unbounded growth
                        if cooldowns.len() > 10_000 {
                            let cutoff = now_ms.saturating_sub(faucet_cooldown_ms * 10);
                            cooldowns.retain(|_, &mut ts| ts > cutoff);
                        }
                    }

                    let spending_pubkey = spending_pk_hex.and_then(|h| hex::decode(h).ok());

                    const MAX_FAUCET_DRIP: u64 = 100_000_000_000_000;
                    let faucet_amount: u64 = std::env::var("MISAKA_FAUCET_AMOUNT")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(1_000_000_000)
                        .min(MAX_FAUCET_DRIP);

                    axum::Json(narwhal_mempool.submit_faucet_tx(
                        addr,
                        spending_pubkey,
                        faucet_amount,
                    ).await)
                }
            }
        }).route_layer(axum::middleware::from_fn_with_state(
            auth_state.clone(),
            crate::rpc_auth::require_api_key,
        )))
        // ── Testnet: Balance query ──
        .route("/api/get_balance", axum::routing::post({
            let utxo_set = utxo_set_rpc.clone();
            let balance_chain_id = cli.chain_id;
            move |body: axum::body::Bytes| {
                let utxo_set = utxo_set.clone();
                async move {
                    let req: serde_json::Value = serde_json::from_slice(&body)
                        .unwrap_or(serde_json::json!({}));
                    let address = req["address"].as_str().unwrap_or("");
                    axum::Json(query_utxos_by_address(&utxo_set, address, balance_chain_id).await)
                }
            }
        }))
        // ── Testnet: Chain info ──
        .route("/api/get_chain_info", axum::routing::get({
            let msg_tx = msg_tx_rpc.clone();
            let metrics2 = metrics_rpc.clone();
            let connected_peers = connected_peers.clone();
            let chain_id_for_rpc = cli.chain_id;
            // v0.5.11 audit Mid #10: expose the config-level node mode
            // (public/hidden/seed) as a distinct field. The existing
            // "mode" field is retained as a back-compat alias but has
            // always been topology-derived (solo/joined from peer_count),
            // which confused operators who expected it to reflect the
            // `[node].mode` setting.
            let node_mode_str: &'static str = match crate::config::NodeMode::from_str_loose(&cli.mode) {
                crate::config::NodeMode::Public => "public",
                crate::config::NodeMode::Hidden => "hidden",
                crate::config::NodeMode::Seed => "seed",
            };
            let is_observer_for_rpc = is_observer;
            let observer_count_rpc = observer_count.clone();
            // Fix: previously a `let committee_size_rpc = manifest_validator_count;`
            // snapshot was taken at router build time, so
            // `/api/get_chain_info.validatorCount` stayed pinned at the
            // genesis size even after the REST register path / epoch
            // boundary hot-reloaded `committee_shared` (observed during
            // Option C smoke test: register_validator produced
            // "Hot-reloading committee: 1 -> 2 validators" but
            // get_chain_info still returned 1). Read the live
            // `committee_shared` inside the closure instead.
            let committee_shared_for_rpc = committee_shared.clone();
            let block_height = block_height_rpc.clone();
            let genesis_hash_hex = hex::encode(genesis_hash);
            move || {
                let msg_tx = msg_tx.clone();
                let metrics2 = metrics2.clone();
                let connected_peers = connected_peers.clone();
                let block_height = block_height.clone();
                let genesis_hash_hex = genesis_hash_hex.clone();
                let committee_shared = committee_shared_for_rpc.clone();
                async move {
                    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                    let _ = msg_tx.try_send(ConsensusMessage::GetStatus(reply_tx));
                    let status = tokio::time::timeout(RPC_TIMEOUT, reply_rx).await.ok().and_then(|r| r.ok());
                    let peers_snapshot: Vec<u32> =
                        connected_peers.read().await.iter().copied().collect();
                    let observers = observer_count_rpc.load(std::sync::atomic::Ordering::Relaxed);
                    let validator_peers: Vec<u32> = peers_snapshot.iter()
                        .copied()
                        .filter(|&a| a != crate::narwhal_block_relay_transport::OBSERVER_SENTINEL_AUTHORITY)
                        .collect();
                    let peer_count = validator_peers.len() + observers as usize;
                    let topology = if peer_count == 0 { "solo" } else { "joined" };
                    let role = if is_observer_for_rpc { "observer" } else { "validator" };
                    let height = block_height.load(std::sync::atomic::Ordering::Relaxed);
                    // Live read of the committee set. Survives REST
                    // hot-reload and epoch-boundary `build_sr21_committee`.
                    let validator_count = committee_shared.read().await.size();
                    axum::Json(serde_json::json!({
                        "chain": misaka_types::constants::CHAIN_DISPLAY_NAME,
                        "ticker": misaka_types::constants::CURRENCY_TICKER,
                        "currencyName": misaka_types::constants::CURRENCY_NAME,
                        "decimals": misaka_types::constants::DECIMALS,
                        "addressPrefix": misaka_types::constants::TESTNET_ADDRESS_PREFIX,
                        "iconUrl": "/api/chain-icon.svg",
                        "consensus": "Mysticeti-equivalent",
                        "chainId": chain_id_for_rpc,
                        "genesisHash": genesis_hash_hex,
                        "version": env!("CARGO_PKG_VERSION"),
                        "pqSignature": "ML-DSA-65 (FIPS 204)",
                        "status": status,
                        "blockHeight": height,
                        "mode": topology,
                        "topology": topology,
                        "nodeMode": node_mode_str,
                        "role": role,
                        "peerCount": peer_count,
                        "validatorCount": validator_count,
                        "observerCount": observers,
                        "peers": peers_snapshot,
                        "metrics": {
                            "blocksProposed": misaka_dag::narwhal_dag::metrics::ConsensusMetrics::get(
                                &metrics2.blocks_proposed),
                            "commitsTotal": misaka_dag::narwhal_dag::metrics::ConsensusMetrics::get(
                                &metrics2.commits_total),
                        }
                    }))
                }
            }
        }))
        // ── Testnet: Get block by round ──
        .route("/api/get_block", axum::routing::post({
            let msg_tx = msg_tx_rpc.clone();
            move |body: axum::body::Bytes| {
                let msg_tx = msg_tx.clone();
                async move {
                    let req: serde_json::Value = serde_json::from_slice(&body)
                        .unwrap_or(serde_json::json!({}));
                    let round = req["round"].as_u64().unwrap_or(0);
                    axum::Json(serde_json::json!({
                        "round": round,
                        "note": "Block content query requires DagState read access (Phase 2)"
                    }))
                }
            }
        }))
        // ── Testnet: Network peers ──
        .route("/api/get_peers", axum::routing::get({
            let connected_peers = connected_peers.clone();
            let observer_count_peers = observer_count.clone();
            move || {
                let connected_peers = connected_peers.clone();
                let observer_count_peers = observer_count_peers.clone();
                async move {
                    let peers: Vec<u32> = connected_peers.read().await.iter().copied().collect();
                    let observers = observer_count_peers.load(std::sync::atomic::Ordering::Relaxed);
                    axum::Json(serde_json::json!({
                        "peers": peers,
                        "count": peers.len(),
                        "observerCount": observers,
                    }))
                }
            }
        }))
        // ── Admin: Connected observers with public keys ──
        .route("/api/admin/observers", axum::routing::get({
            let observer_registry_rpc = observer_registry.clone();
            move || {
                let observer_registry_rpc = observer_registry_rpc.clone();
                async move {
                    let observers: Vec<ObserverInfo> = observer_registry_rpc.read().await.values().cloned().collect();
                    axum::Json(serde_json::json!({
                        "observers": observers,
                        "count": observers.len(),
                    }))
                }
            }
        }))
        // ── Explorer: Supply info ──
        .route("/api/get_supply", axum::routing::get(|| async {
            axum::Json(serde_json::json!({
                "maxSupply": 10_000_000_000u64,
                "genesisSupply": 10_000_000_000u64,
                "inflationYear0Bps": 500,
                "inflationDecayBps": 50,
                "inflationFloorBps": 100,
                "unit": "base_units",
                "decimals": 9
            }))
        }))
        .route("/api/chain-icon.svg", axum::routing::get(|| async {
            axum::response::Response::builder()
                .header("content-type", "image/svg+xml")
                .header("cache-control", "public, max-age=86400")
                .body(axum::body::Body::from(include_str!("../../../assets/misaka-icon.svg")))
                .expect("static SVG response")
        }))
        .route("/api/chain_registry", axum::routing::get(|| async {
            let json: serde_json::Value = serde_json::from_str(
                include_str!("../../../configs/chain.json")
            ).expect("configs/chain.json must be valid JSON");
            axum::Json(json)
        }))
        // ── Explorer: Recent blocks ──
        .route("/api/get_recent_blocks", axum::routing::get({
            let recent_blocks = recent_blocks_rpc.clone();
            move || {
                let recent_blocks = recent_blocks.clone();
                async move {
                    let buf = recent_blocks.read().await;
                    let blocks: Vec<serde_json::Value> = buf.iter().take(20).map(|b| {
                        serde_json::json!({
                            "height": b.height,
                            "hash": b.hash,
                            "txCount": b.tx_count,
                            "txsAccepted": b.txs_accepted,
                            "timestamp": b.timestamp_ms,
                            "author": b.author,
                            "stateRoot": b.state_root,
                            "fees": b.fees,
                        })
                    }).collect();
                    let total = buf.len();
                    let highest = buf.front().map(|b| b.height).unwrap_or(0);
                    axum::Json(serde_json::json!({
                        "blocks": blocks,
                        "highestCommit": highest,
                        "totalBlocks": total,
                    }))
                }
            }
        }))
        // ── Bridge mint endpoint (CRITICAL #14) ──
        // Receives mint requests from the bridge relayer, validates attestation
        // signatures, and queues the mint for execution.
        // SEC-FIX v0.5.7: bridge mint write endpoint also moves to the
        // shared `rpc_auth::require_api_key` middleware (Bearer + IP
        // allowlist). The previous inline check skipped IP enforcement.
        .route(
            "/api/bridge/submit_mint",
            axum::routing::post({
                move |body: axum::body::Bytes| async move {
                    // Parse the mint request
                    let request: serde_json::Value = match serde_json::from_slice(&body) {
                        Ok(v) => v,
                        Err(e) => {
                            return axum::Json(serde_json::json!({
                                "error": format!("invalid JSON: {}", e),
                                "accepted": false
                            }));
                        }
                    };

                    let burn_event_id =
                        request["burn_event_id"].as_str().unwrap_or("");
                    let amount = request["amount"].as_u64().unwrap_or(0);

                    if burn_event_id.is_empty() || amount == 0 {
                        return axum::Json(serde_json::json!({
                            "error": "missing burn_event_id or amount",
                            "accepted": false
                        }));
                    }

                    // SEC-FIX CRITICAL: Bridge mint is NOT IMPLEMENTED.
                    // Previously returned accepted:true without performing any mint,
                    // causing users to permanently lose tokens burned on Solana.
                    // Now explicitly rejects all mint requests until implementation
                    // is complete (attestation verification + UTXO creation).
                    tracing::warn!(
                        "[BRIDGE] Mint request REJECTED (not implemented): burn_id={}, amount={}",
                        burn_event_id, amount
                    );

                    axum::Json(serde_json::json!({
                        "error": "bridge mint not yet implemented — do not burn tokens",
                        "accepted": false,
                        "status": "rejected"
                    }))
                }
            })
            .route_layer(axum::middleware::from_fn_with_state(
                auth_state.clone(),
                crate::rpc_auth::require_api_key,
            )),
        )
        .route("/api/bridge/mint_status/:tx_id", axum::routing::get({
            move |path: axum::extract::Path<String>| {
                async move {
                    let tx_id = path.0;
                    // TODO: Look up mint status from on-chain state
                    axum::Json(serde_json::json!({
                        "tx_id": tx_id,
                        "status": "pending",
                        "reason": "mint pipeline not yet fully implemented"
                    }))
                }
            }
        }))
        // ── Testnet manifest ──
        .route("/api/testnet_info", axum::routing::get({
            // SEC-FIX v0.5.6: version and seedNodes used to be hardcoded
            // (version="0.5.1", seedNodes=["160.16.131.119:3000"], which
            // did not even match `seeds.txt` in the distribution). Bind
            // the handler over the runtime CLI so its output actually
            // reflects what the operator launched.
            let chain_id_for_rpc = cli.chain_id;
            let seed_nodes_for_rpc: Vec<String> = cli.seeds.clone();
            move || {
                let seed_nodes_for_rpc = seed_nodes_for_rpc.clone();
                async move {
                    axum::Json(serde_json::json!({
                        "network": misaka_types::constants::CHAIN_TESTNET_NAME,
                        "chainId": chain_id_for_rpc,
                        "networkId": misaka_types::constants::TESTNET_NETWORK_ID,
                        "ticker": misaka_types::constants::CURRENCY_TICKER,
                        "currencyName": misaka_types::constants::CURRENCY_NAME,
                        "decimals": misaka_types::constants::DECIMALS,
                        "addressPrefix": misaka_types::constants::TESTNET_ADDRESS_PREFIX,
                        "iconUrl": "/api/chain-icon.svg",
                        "consensus": "Mysticeti-equivalent",
                        "pqSignature": "ML-DSA-65 (FIPS 204)",
                        "version": env!("CARGO_PKG_VERSION"),
                        "seedNodes": seed_nodes_for_rpc,
                        "maxSupply": 10_000_000_000u64,
                        "bridge": {
                            "ui": "https://testbridge.misakastake.com",
                            "solanaNetwork": "devnet",
                            "solanaRpc": "https://api.devnet.solana.com",
                            "programId": "GVb76FKRY7anhraL8WFEjXrNCuRXzQJ6TYj4BmgpiDQZ",
                            "tokenMint": "Dc5ni2yXsMeLuSVRg5fdYjgyKJyQFafBWfjmGSsUFMBA",
                            "explorer": "https://explorer.solana.com/address/GVb76FKRY7anhraL8WFEjXrNCuRXzQJ6TYj4BmgpiDQZ?cluster=devnet"
                        }
                    }))
                }
            }
        }))
        // ── UTXO query endpoints ──
        .route("/api/get_indexed_utxos", axum::routing::post({
            let utxo_set = utxo_set_rpc.clone();
            let idx_chain_id = cli.chain_id;
            move |body: axum::Json<serde_json::Value>| {
                let utxo_set = utxo_set.clone();
                async move {
                    let address_str = body.get("address").and_then(|v| v.as_str()).unwrap_or("");
                    axum::Json(query_utxos_by_address(&utxo_set, address_str, idx_chain_id).await)
                }
            }
        }))
        .route("/api/get_utxos_by_address", axum::routing::post({
            let utxo_set = utxo_set_rpc.clone();
            let utxo_chain_id = cli.chain_id;
            move |body: axum::Json<serde_json::Value>| {
                let utxo_set = utxo_set.clone();
                async move {
                    let address_str = body.get("address").and_then(|v| v.as_str()).unwrap_or("");
                    axum::Json(query_utxos_by_address(&utxo_set, address_str, utxo_chain_id).await)
                }
            }
        }))
        .route("/api/get_address_history", axum::routing::post({
            let rocks = addr_index_store_rpc.clone();
            move |body: axum::Json<serde_json::Value>| {
                let rocks = rocks.clone();
                async move {
                    let address = body.get("address").and_then(|v| v.as_str()).unwrap_or("");
                    let page = body.get("page").and_then(|v| v.as_u64()).unwrap_or(1).max(1);
                    let page_size = body.get("pageSize").and_then(|v| v.as_u64()).unwrap_or(20).min(100);

                    let all_entries = match rocks.get_addr_entries(address) {
                        Ok(entries) => entries,
                        Err(e) => {
                            tracing::warn!("get_addr_entries failed: {}", e);
                            Vec::new()
                        }
                    };

                    let total = all_entries.len() as u64;
                    let skip = ((page - 1) * page_size) as usize;
                    let txs: Vec<serde_json::Value> = all_entries
                        .into_iter()
                        .rev()
                        .skip(skip)
                        .take(page_size as usize)
                        .filter_map(|bytes| serde_json::from_slice::<AddressTxRef>(&bytes).ok())
                        .map(|r| serde_json::json!({
                            "txHash": r.tx_hash,
                            "direction": r.direction,
                            "amount": r.amount,
                            "height": r.height,
                            "timestampMs": r.timestamp_ms,
                            "txType": r.tx_type,
                        }))
                        .collect();

                    axum::Json(serde_json::json!({
                        "address": address,
                        "transactions": txs,
                        "page": page,
                        "pageSize": page_size,
                        "total": total,
                    }))
                }
            }
        }))
        .route("/api/get_address_balance", axum::routing::post({
            let utxo_set = utxo_set_rpc.clone();
            let balance_chain_id = cli.chain_id;
            move |body: axum::Json<serde_json::Value>| {
                let utxo_set = utxo_set.clone();
                async move {
                    let address = body.get("address").and_then(|v| v.as_str()).unwrap_or("");
                    let result = query_utxos_by_address(&utxo_set, address, balance_chain_id).await;
                    let balance = result.get("balance").and_then(|v| v.as_u64()).unwrap_or(0);
                    axum::Json(serde_json::json!({
                        "address": address,
                        "balance": balance,
                        "confirmed": balance,
                        "unconfirmed": 0,
                    }))
                }
            }
        }))
        .route("/api/get_tx_status", axum::routing::post({
            let mempool = narwhal_mempool.clone();
            let committed = committed_txs_rpc.clone();
            let rocks = tx_index_store_rpc.clone();
            move |body: axum::Json<serde_json::Value>| {
                let mempool = mempool.clone();
                let committed = committed.clone();
                let rocks = rocks.clone();
                async move {
                    let tx_hash_hex = body.get("txHash").and_then(|v| v.as_str()).unwrap_or("");
                    let hash_bytes: Option<[u8; 32]> = hex::decode(tx_hash_hex)
                        .ok()
                        .and_then(|b| b.try_into().ok());

                    match hash_bytes {
                        Some(h) => {
                            if mempool.contains_tx(&h).await {
                                return axum::Json(serde_json::json!({
                                    "txHash": tx_hash_hex,
                                    "status": "pending",
                                    "blockHeight": null,
                                }));
                            }

                            // Try in-memory cache first
                            {
                                let tx_map = committed.read().await;
                                if let Some(detail) = tx_map.get(&h) {
                                    return axum::Json(serde_json::json!({
                                        "txHash": tx_hash_hex,
                                        "status": detail.status,
                                        "blockHeight": detail.height,
                                        "txType": detail.tx_type,
                                        "inputs": detail.inputs,
                                        "outputs": detail.outputs,
                                        "fee": detail.fee,
                                        "timestampMs": detail.timestamp_ms,
                                        "leaderAuthority": detail.leader_authority,
                                        "participatingValidators": detail.participating_validators,
                                        "memo": detail.memo,
                                    }));
                                }
                            }

                            // Fallback to RocksDB
                            if let Ok(Some(bytes)) = rocks.get_tx_detail(&h) {
                                if let Ok(detail) = serde_json::from_slice::<CommittedTxDetail>(&bytes) {
                                    return axum::Json(serde_json::json!({
                                        "txHash": tx_hash_hex,
                                        "status": detail.status,
                                        "blockHeight": detail.height,
                                        "txType": detail.tx_type,
                                        "inputs": detail.inputs,
                                        "outputs": detail.outputs,
                                        "fee": detail.fee,
                                        "timestampMs": detail.timestamp_ms,
                                        "leaderAuthority": detail.leader_authority,
                                        "participatingValidators": detail.participating_validators,
                                        "memo": detail.memo,
                                    }));
                                }
                            }

                            axum::Json(serde_json::json!({
                                "txHash": tx_hash_hex,
                                "status": "unknown",
                                "blockHeight": null,
                            }))
                        }
                        None => axum::Json(serde_json::json!({
                            "txHash": tx_hash_hex,
                            "status": "unknown",
                            "blockHeight": null,
                        })),
                    }
                }
            }
        }));

    // v0.5.11 audit Confirmed Finding #1: use
    // `into_make_service_with_connect_info::<SocketAddr>()` so the shared
    // rpc_auth middleware can read the peer IP via the ConnectInfo
    // extension. Without this, MISAKA_RPC_WRITE_ALLOWLIST always fails
    // closed with 403 because the middleware cannot determine the
    // caller's address. The write routes under
    // rpc_server.rs / dag_rpc_legacy.rs / validator_api.rs all already
    // read ConnectInfo; main.rs was the missing wiring.
    // R4-M14 FIX: Apply explicit body size limit to DAG RPC router,
    // consistent with rpc_server.rs (128 KiB) instead of Axum default (~2 MiB).
    let rpc_router = rpc_router.layer(axum::extract::DefaultBodyLimit::max(131_072));

    let rpc_server = axum::serve(
        tokio::net::TcpListener::bind(rpc_addr).await?,
        rpc_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    );

    info!("RPC server listening on {}", rpc_addr);

    // Track start time for uptime metric
    let start_time = std::time::Instant::now();

    let shutdown_utxo_snapshot_path =
        std::path::Path::new(&cli.data_dir).join("narwhal_utxo_snapshot.json");

    // Graceful shutdown: handle SIGINT + SIGTERM
    let shutdown_msg_tx = msg_tx.clone();
    let shutdown_handle = tokio::spawn(async move {
        #[cfg(unix)]
        {
            let sigterm_result =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
            let mut sigterm = match sigterm_result {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        "Failed to register SIGTERM handler: {e}; falling back to SIGINT only"
                    );
                    tokio::signal::ctrl_c().await.ok();
                    let _ = shutdown_msg_tx.try_send(ConsensusMessage::Shutdown);
                    return;
                }
            };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    info!("Received SIGINT, initiating graceful shutdown...");
                }
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, initiating graceful shutdown...");
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
            info!("Received shutdown signal, initiating graceful shutdown...");
        }
        let _ = shutdown_msg_tx.try_send(ConsensusMessage::Shutdown);
    });

    // Phase 2: Block broadcast consumer — sends proposed blocks to P2P peers.
    // block_rx receives VerifiedBlock from CoreEngine::propose_block.
    // These must be broadcast to other validators for DAG acceptance.
    let relay_cache_for_broadcast = block_cache.clone();
    let relay_out_tx_for_broadcast = relay_out_tx.clone();
    let block_broadcast_handle = tokio::spawn(async move {
        let mut blocks_broadcast = 0u64;
        while let Some(block) = block_rx.recv().await {
            blocks_broadcast += 1;
            let block_ref = block.reference();
            let block_body = block.inner().clone();
            relay_cache_for_broadcast
                .write()
                .await
                .insert(block_ref, block_body.clone());
            let _ = relay_out_tx_for_broadcast
                .send(
                    crate::narwhal_block_relay_transport::OutboundNarwhalRelayEvent::Broadcast(
                        NarwhalRelayMessage::BlockProposal(NarwhalBlockProposal {
                            block: block_body,
                        }),
                    ),
                )
                .await;
            tracing::debug!(
                "Block broadcast round={} author={} txs={} total_broadcast={}",
                block.round(),
                block.author(),
                block.transactions().len(),
                blocks_broadcast
            );
        }
        tracing::info!(
            "Block broadcast channel closed (total: {})",
            blocks_broadcast
        );
    });

    let relay_msg_tx = msg_tx.clone();
    let relay_out_tx_for_ingress = relay_out_tx.clone();
    let relay_cache_for_ingress = block_cache.clone();
    let connected_peers_for_ingress = connected_peers.clone();
    let observer_count_for_ingress = observer_count.clone();
    let observer_registry_for_ingress = observer_registry.clone();
    let relay_ingress_handle = tokio::spawn(async move {
        while let Some(event) = relay_in_rx.recv().await {
            match event {
                crate::narwhal_block_relay_transport::InboundNarwhalRelayEvent::PeerConnected {
                    authority_index,
                    peer_id,
                    address,
                    public_key,
                } => {
                    connected_peers_for_ingress
                        .write()
                        .await
                        .insert(authority_index);
                    if authority_index == crate::narwhal_block_relay_transport::OBSERVER_SENTINEL_AUTHORITY {
                        observer_count_for_ingress.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if let Some(pk_bytes) = public_key {
                            let pid_hex = peer_id.short_hex();
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            observer_registry_for_ingress.write().await.insert(
                                pid_hex.clone(),
                                ObserverInfo {
                                    peer_id: pid_hex,
                                    address: address.to_string(),
                                    public_key: format!("0x{}", hex::encode(&pk_bytes)),
                                    connected_at: now,
                                },
                            );
                        }
                    }
                    info!(
                        "narwhal_peer_connected authority={} peer_id={} addr={}",
                        authority_index,
                        peer_id.short_hex(),
                        address
                    );
                    // 0.9.0-dev: Catch-up for late-connecting peers.
                    // A newly connected committee peer may have missed our
                    // most recent BlockProposal broadcasts (which only reach
                    // already-connected peers at the moment of send).
                    //
                    // BOUNDED REPLAY: we only re-send blocks from the last
                    // PEER_REPLAY_ROUND_WINDOW rounds. Replaying the full
                    // cache would flood a reconnecting peer with thousands
                    // of stale blocks that all get rejected by the verifier
                    // as "timestamp too far in past", saturating the
                    // ProcessNetworkBlock channel and effectively halting
                    // consensus. For older rounds, the peer should use the
                    // normal BlockRequest/fetch_requests path triggered by
                    // suspended blocks with missing ancestors.
                    //
                    // v0.8.8.1 (hotfix/peer-replay-window): raised 3 → 100.
                    // A 3-round window on a chain running at the fast lane
                    // rate is only ~6 s of history; any peer joining while
                    // others are past round ~20 cannot satisfy ancestor
                    // references through BlockRequest fast enough and hits
                    // the MAX_SUSPENDED_PER_AUTHOR=16 quarantine threshold
                    // before fetch_requests round-trip completes. 100 rounds
                    // spans ~200 s at 2 s blocks (≈33 min at 10 s blocks),
                    // covering any realistic reconnect gap without triggering
                    // the documented stale-flood failure on production-scale
                    // chains — block_cache in this file is unbounded but on
                    // a freshly cold-reset or short-lived chain it contains
                    // only recent rounds by definition. Long-running chain
                    // overflow is a separate pre-existing concern (cache
                    // never evicts — needs a follow-up fix).
                    //
                    // Observers are excluded — they receive broadcasts only.
                    const PEER_REPLAY_ROUND_WINDOW: u32 = 100;
                    if authority_index
                        != crate::narwhal_block_relay_transport::OBSERVER_SENTINEL_AUTHORITY
                    {
                        // v0.8.8.1 (hotfix/peer-replay-window): also record
                        // cache_total and round_range so the cold-reset
                        // diagnostic can distinguish "window too narrow"
                        // from "cache empty" from "cutoff clips real blocks".
                        let (cache_snapshot, cache_total, max_round, cutoff, round_min) = {
                            let cache = relay_cache_for_ingress.read().await;
                            let cache_total = cache.len();
                            let max_round = cache.keys().map(|r| r.round).max().unwrap_or(0);
                            let cutoff = max_round.saturating_sub(PEER_REPLAY_ROUND_WINDOW);
                            let mut round_min = u32::MAX;
                            let blocks: Vec<NarwhalBlock> = cache
                                .iter()
                                .filter(|(r, _)| r.round >= cutoff)
                                .map(|(r, b)| {
                                    if r.round < round_min {
                                        round_min = r.round;
                                    }
                                    b.clone()
                                })
                                .collect();
                            let round_min = if round_min == u32::MAX { 0 } else { round_min };
                            (blocks, cache_total, max_round, cutoff, round_min)
                        };
                        let replay_count = cache_snapshot.len();
                        let relay_out_tx = relay_out_tx_for_ingress.clone();
                        if replay_count > 0 {
                            tokio::spawn(async move {
                                for block in cache_snapshot {
                                    let _ = relay_out_tx.send(
                                        crate::narwhal_block_relay_transport::OutboundNarwhalRelayEvent::ToAuthority {
                                            authority_index,
                                            message: NarwhalRelayMessage::BlockProposal(
                                                NarwhalBlockProposal { block },
                                            ),
                                        },
                                    ).await;
                                }
                            });
                            info!(
                                "narwhal_peer_replay authority={} blocks={} window_rounds={} round_range={}..{} max_round={} cutoff={} cache_total={}",
                                authority_index, replay_count, PEER_REPLAY_ROUND_WINDOW,
                                round_min, max_round, max_round, cutoff, cache_total
                            );
                        } else {
                            info!(
                                "narwhal_peer_replay authority={} blocks=0 window_rounds={} max_round={} cutoff={} cache_total={}",
                                authority_index, PEER_REPLAY_ROUND_WINDOW, max_round, cutoff, cache_total
                            );
                        }
                    }
                }
                crate::narwhal_block_relay_transport::InboundNarwhalRelayEvent::PeerDisconnected {
                    authority_index,
                    peer_id,
                    address,
                } => {
                    if authority_index == crate::narwhal_block_relay_transport::OBSERVER_SENTINEL_AUTHORITY {
                        let prev = observer_count_for_ingress.load(std::sync::atomic::Ordering::Relaxed);
                        if prev > 0 {
                            observer_count_for_ingress.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        observer_registry_for_ingress.write().await.remove(&peer_id.short_hex());
                        let remaining = observer_count_for_ingress.load(std::sync::atomic::Ordering::Relaxed);
                        if remaining == 0 {
                            connected_peers_for_ingress
                                .write()
                                .await
                                .remove(&authority_index);
                        }
                    } else {
                        connected_peers_for_ingress
                            .write()
                            .await
                            .remove(&authority_index);
                    }
                    info!(
                        "narwhal_peer_disconnected authority={} peer_id={} addr={}",
                        authority_index,
                        peer_id.short_hex(),
                        address
                    );
                }
                crate::narwhal_block_relay_transport::InboundNarwhalRelayEvent::Message {
                    authority_index,
                    message,
                    ..
                } => match message {
                    NarwhalRelayMessage::BlockProposal(NarwhalBlockProposal { block }) => {
                        let block_ref = block.reference();
                        // SEC-FIX: Do NOT cache before verification.
                        // Previously the block was cached before verification,
                        // allowing forged blocks to be served to other peers via
                        // BlockRequest — turning honest nodes into amplifiers of
                        // forged content.
                        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                        if relay_msg_tx
                            .try_send(ConsensusMessage::ProcessNetworkBlock {
                                block: VerifiedBlock::new_pending_verification(block.clone()),
                                reply: reply_tx,
                            })
                            .is_err()
                        {
                            break;
                        }
                        if let Ok(outcome) = reply_rx.await {
                            if outcome.sig_verify_failed {
                                // Task D / audit follow-up: the sender pushed a
                                // block whose ML-DSA-65 signature or structural
                                // check failed inside CoreEngine. Surface that
                                // fact to operators so bad peers are visible
                                // even though the production code path currently
                                // has no PeerScorer wired up.
                                warn!(
                                    "peer_sig_verify_failed from={} round={}",
                                    authority_index, block_ref.round,
                                );
                            }
                            if !outcome.accepted.is_empty() {
                                // Cache ONLY after verification succeeded
                                relay_cache_for_ingress
                                    .write()
                                    .await
                                    .insert(block_ref, block);
                                info!(
                                    "block_accepted from={} round={} accepted={} highest_accepted_round={}",
                                    authority_index,
                                    block_ref.round,
                                    outcome.accepted.len(),
                                    outcome.highest_accepted_round,
                                );
                            }
                            for fetch in outcome.fetch_requests {
                                let relay_out_tx = relay_out_tx_for_ingress.clone();
                                // v0.8.8.1 observability: record each fetch
                                // dispatch so diff analysis can see whether
                                // the pull-based catch-up path is keeping up
                                // with suspension accumulation.
                                let missing_round = fetch.block_ref.round;
                                let missing_author = fetch.block_ref.author;
                                let fetch_attempt = fetch.attempt;
                                let fetch_delay_ms = fetch.delay_ms;
                                tokio::spawn(async move {
                                    if fetch.delay_ms > 0 {
                                        tokio::time::sleep(std::time::Duration::from_millis(
                                            fetch.delay_ms,
                                        ))
                                        .await;
                                    }
                                    tracing::info!(
                                        target: "misaka::fetch::req",
                                        missing_round = missing_round,
                                        missing_author = missing_author,
                                        attempt = fetch_attempt,
                                        delay_ms = fetch_delay_ms,
                                        to_peer = authority_index,
                                        "block_request_dispatched"
                                    );
                                    let _ = relay_out_tx
                                        .send(crate::narwhal_block_relay_transport::OutboundNarwhalRelayEvent::ToAuthority {
                                            authority_index,
                                            message: NarwhalRelayMessage::BlockRequest(
                                                NarwhalBlockRequest {
                                                    refs: vec![fetch.block_ref],
                                                },
                                            ),
                                        })
                                        .await;
                                });
                            }
                        }
                    }
                    NarwhalRelayMessage::BlockResponse(NarwhalBlockResponse { blocks }) => {
                        // v0.8.8.1 observability: record BlockResponse receipt
                        // so the fetch round-trip can be correlated with the
                        // `block_request_dispatched` events. rtt is not
                        // computed here (caller-side per-ref would need a
                        // wait table) but the count is enough to tell
                        // whether the pull path returns any blocks at all.
                        let response_block_count = blocks.len();
                        tracing::info!(
                            target: "misaka::fetch::resp",
                            from_peer = authority_index,
                            blocks = response_block_count,
                            "block_request_response"
                        );
                        for block in blocks {
                            let block_ref = block.reference();
                            // SEC-FIX: Cache AFTER verification, not before.
                            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                            if relay_msg_tx
                                .try_send(ConsensusMessage::ProcessNetworkBlock {
                                    block: VerifiedBlock::new_pending_verification(block.clone()),
                                    reply: reply_tx,
                                })
                                .is_err()
                            {
                                break;
                            }
                            if let Ok(outcome) = reply_rx.await {
                                if outcome.sig_verify_failed {
                                    warn!(
                                        "peer_sig_verify_failed from={} round={} (BlockResponse)",
                                        authority_index, block_ref.round,
                                    );
                                }
                                if !outcome.accepted.is_empty() {
                                    relay_cache_for_ingress
                                        .write()
                                        .await
                                        .insert(block_ref, block);
                                    info!(
                                        "block_accepted from={} round={} accepted={} highest_accepted_round={}",
                                        authority_index,
                                        block_ref.round,
                                        outcome.accepted.len(),
                                        outcome.highest_accepted_round,
                                    );
                                }
                            }
                        }
                    }
                    NarwhalRelayMessage::BlockRequest(NarwhalBlockRequest { refs }) => {
                        let blocks: Vec<NarwhalBlock> = {
                            let cache = relay_cache_for_ingress.read().await;
                            refs.iter()
                                .filter_map(|block_ref| cache.get(block_ref).cloned())
                                .collect()
                        };
                        let _ = relay_out_tx_for_ingress
                            .send(crate::narwhal_block_relay_transport::OutboundNarwhalRelayEvent::ToAuthority {
                                authority_index,
                                message: NarwhalRelayMessage::BlockResponse(
                                    NarwhalBlockResponse { blocks },
                                ),
                            })
                            .await;
                    }
                    NarwhalRelayMessage::CommitVote(vote) => {
                        // v0.5.12 audit Mid 5 fix: feed CommitVote into
                        // the consensus runtime so per-round vote
                        // equivocation is detected and the offending
                        // author is banned via the shared
                        // SlotEquivocationLedger. Previously this was
                        // telemetry-only (`debug!` → /dev/null), leaving
                        // CommitVote-based detection disconnected from
                        // enforcement.
                        debug!(
                            "narwhal_commit_vote from={} round={} author={}",
                            authority_index,
                            vote.vote.round,
                            vote.vote.author
                        );
                        let (vote_reply_tx, vote_reply_rx) =
                            tokio::sync::oneshot::channel();
                        if relay_msg_tx
                            .try_send(ConsensusMessage::RecordCommitVote {
                                author: vote.vote.author,
                                round: vote.vote.round,
                                digest: vote.vote.digest.0,
                                reply: vote_reply_tx,
                            })
                            .is_err()
                        {
                            warn!(
                                "commit_vote_drop: runtime busy, vote \
                                 from={} round={} author={} not recorded",
                                authority_index, vote.vote.round, vote.vote.author
                            );
                        } else if let Ok(true) = vote_reply_rx.await {
                            warn!(
                                "commit_vote_equivocation_banned: relay_peer={} \
                                 equivocating_author={} round={}",
                                authority_index, vote.vote.author, vote.vote.round
                            );
                        }
                    }
                },
            }
        }
    });

    // Main loop: process committed outputs
    tokio::select! {
        _ = rpc_server => {
            info!("RPC server stopped");
        }
        _ = block_broadcast_handle => {
            info!("Block broadcast task stopped");
        }
        _ = relay_ingress_handle => {
            info!("Narwhal relay ingress stopped");
        }
        relay_result = relay_transport_handle => {
            match relay_result {
                Ok(()) => {
                    return Err(anyhow::anyhow!(
                        "Narwhal relay transport stopped unexpectedly; refusing to continue"
                    ));
                }
                Err(err) => {
                    return Err(anyhow::anyhow!(
                        "Narwhal relay transport task failed: {}",
                        err
                    ));
                }
            }
        }
        _ = async {
            // Phase 2b (M6): UtxoExecutor replaces NarwhalTxExecutor.
            // This is the HARD FORK cutover point. Committed transactions are now:
            // - borsh-decoded (not serde_json)
            // - verified via signing_digest_with_chain (IntentMessage in Phase 2c)
            // - fail-closed: any validation failure causes panic (state divergence)
            // See docs/architecture.md §4 for the validation pipeline.
            // Phase 2c-A: use real genesis_hash (computed from committee PKs)
            let app_id = misaka_types::intent::AppId::new(cli.chain_id, genesis_hash);

            // R7 C-1: Build executor from persisted UTXO snapshot (if any),
            // falling back to the canonical set from mempool, then to fresh.
            let utxo_snapshot_path = std::path::Path::new(&cli.data_dir)
                .join("narwhal_utxo_snapshot.json");
            let mut tx_executor = {
                match misaka_storage::utxo_set::UtxoSet::load_from_file(
                    &utxo_snapshot_path, 1000,
                ) {
                    Ok(Some(restored)) => {
                        info!(
                            "Restored UTXO snapshot: height={}, utxos={}",
                            restored.height, restored.len()
                        );
                        {
                            // Mempool and RPC share the same Arc, one write suffices
                            let mut shared = utxo_set_writer.write().await;
                            *shared = restored.clone();
                        }
                        crate::utxo_executor::UtxoExecutor::with_utxo_set(restored, app_id.clone())
                    }
                    _ => {
                        let canonical = narwhal_mempool.utxo_set();
                        let snapshot = canonical.read().await;
                        crate::utxo_executor::UtxoExecutor::with_utxo_set(
                            snapshot.clone(),
                            app_id.clone(),
                        )
                    }
                }
            };

            // Option C (v0.9.0-dev): on a fresh start (no restored snapshot
            // above), seed the UTXO set from the genesis manifest's
            // `[initial_utxos] source = ...` if present. This lets
            // operators carry v0.8.8 balances into a fresh v0.9.0-dev
            // chain: run `misaka-cli migrate-utxo-snapshot` against the
            // old snapshot, point the TOML at the resulting JSON, and
            // start the node with an empty data_dir.
            //
            // Idempotency: we seed only when the executor's UTXO set is
            // empty AND no `narwhal_utxo_snapshot.json` was loaded
            // earlier. A second boot with a warm chain.db sees a
            // non-empty utxo_set (from snapshot or from mempool's
            // canonical) and skips the whole block.
            if tx_executor.utxo_count() == 0 {
                match manifest.load_initial_utxos() {
                    Ok(Some(seeds)) => {
                        let mut seeded: usize = 0;
                        let mut total_seeded: u64 = 0;
                        for seed in &seeds {
                            let tx_hash = crate::genesis_committee::synthetic_seed_tx_hash(
                                manifest.epoch,
                                &seed.label,
                                &seed.address,
                            );
                            let outref = misaka_types::utxo::OutputRef {
                                tx_hash,
                                output_index: 0,
                            };
                            let output = misaka_types::utxo::TxOutput {
                                amount: seed.amount,
                                address: seed.address,
                                spending_pubkey: seed.spending_pubkey.clone(),
                            };
                            // Use the test-only mut accessor added in Phase 10:
                            // seeding bypasses tx validation intentionally
                            // (these UTXOs have no originating transaction).
                            let utxo_set = tx_executor.utxo_set_mut();
                            match utxo_set.add_output(
                                outref.clone(),
                                output.clone(),
                                /* height = */ 0,
                                /* is_emission = */ false,
                            ) {
                                Ok(()) => {
                                    if let Some(spk) = &seed.spending_pubkey {
                                        let _ = utxo_set
                                            .register_spending_key(outref, spk.clone());
                                    }
                                    seeded += 1;
                                    total_seeded = total_seeded.saturating_add(seed.amount);
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "Option C seed: failed to add utxo {} (label={}): {}",
                                        hex::encode(&seed.address[..8]),
                                        seed.label,
                                        e
                                    );
                                }
                            }
                        }
                        tracing::info!(
                            "Option C: seeded {} initial UTXOs from genesis ({} base units total) — \
                             source: {}",
                            seeded,
                            total_seeded,
                            manifest
                                .initial_utxos_source
                                .as_deref()
                                .map(|p| p.display().to_string())
                                .unwrap_or_else(|| "<none>".into()),
                        );
                        // Mirror the seeded state into the mempool's canonical
                        // UTXO set (same Arc that /api/get_utxos_by_address
                        // reads) so the first RPC query returns these UTXOs.
                        {
                            let mut shared = utxo_set_writer.write().await;
                            *shared = tx_executor.utxo_set().clone();
                        }
                    }
                    Ok(None) => {
                        tracing::debug!(
                            "Option C: no [initial_utxos] section in genesis — starting with empty UTXO set"
                        );
                    }
                    Err(e) => {
                        tracing::error!(
                            "Option C: failed to load initial_utxos ({}). Starting with empty UTXO set.",
                            e
                        );
                    }
                }
            } else {
                tracing::debug!(
                    "Option C: skipping initial UTXO seed ({} UTXOs already loaded from snapshot/mempool)",
                    tx_executor.utxo_count()
                );
            }
            // v0.5.9: commit loop holds a handle to the safe-mode flag so
            // it can break out on state_root mismatch.
            let safe_mode = safe_mode.clone();

            let mut total_committed_txs = 0u64;
            let mut total_accepted_txs = 0u64;

            // PR-B: per-epoch propose accounting. `propose_count` tallies
            // how many commits each authority produced during the current
            // epoch; `epoch_block_count` is the total. At an epoch
            // boundary they drive `StakingRegistry::update_uptime` and
            // zero-count ACTIVE validators are slashed `Minor` (1%).
            // Both are cleared after the boundary block fires.
            //
            // Key type: `[u8; 32]` = `SHA3-256(ML-DSA-65 pubkey)`, the
            // canonical `validator_id` used by `StakingRegistry`. The
            // `leader_address` derived a few lines below is the same
            // hash; we reuse that value rather than recomputing.
            let mut propose_count: std::collections::HashMap<[u8; 32], u64> =
                std::collections::HashMap::new();
            let mut epoch_block_count: u64 = 0;

            while let Some(output) = commit_rx.recv().await {
                // v0.5.9: if safe-mode has already been tripped, drop
                // any further committed sub-dags without applying.
                if safe_mode.is_halted() {
                    tracing::warn!(
                        "safe_mode active — dropping committed sub-dag index={} without applying",
                        output.commit_index
                    );
                    break;
                }
                // SEC-FIX: Derive the commit leader's address from their pubkey.
                // This is used to verify SystemEmission outputs go to the correct
                // proposer, preventing Byzantine reward redirection.
                let committee_guard = committee_shared.read().await;
                let leader_address: Option<[u8; 32]> = {
                    let author_idx = output.leader.author as usize;
                    if author_idx < committee_guard.authorities.len() {
                        let pk = &committee_guard.authorities[author_idx].public_key;
                        if !pk.is_empty() {
                            use sha3::{Digest, Sha3_256};
                            let addr: [u8; 32] = Sha3_256::digest(pk).into();
                            Some(addr)
                        } else {
                            tracing::error!(
                                "Commit leader author={} has empty public key in committee — \
                                 leader_address will be None (SystemEmission will be rejected on mainnet)",
                                author_idx
                            );
                            None
                        }
                    } else {
                        tracing::warn!(
                            "Commit leader author={} exceeds committee size={}",
                            author_idx,
                            committee_guard.authorities.len()
                        );
                        None
                    }
                };
                // PR-B: propose accounting. `leader_address` just above is
                // the `SHA3-256` of the leader's pubkey, i.e. the same
                // `validator_id` the staking registry keys on. Count this
                // commit against that validator so the epoch-boundary
                // uptime update can compute a ratio. `None` (malformed
                // committee entry or out-of-range author_idx) is skipped
                // — already logged above as an error/warn.
                epoch_block_count = epoch_block_count.saturating_add(1);
                if let Some(leader_vid) = leader_address {
                    *propose_count.entry(leader_vid).or_insert(0) =
                        propose_count.get(&leader_vid).copied().unwrap_or(0) + 1;
                }

                // γ-3: acquire the registry write lock for the batch and
                // pass a mut ref through. The lock is held for the span of
                // one commit batch so all `StakeDeposit` / `StakeWithdraw`
                // txs in a batch mutate the registry atomically relative to
                // the REST api (which takes read locks).
                let current_epoch_for_stake = *current_epoch.read().await;
                let mut registry_guard = validator_registry.write().await;
                let exec_result = tx_executor.execute_committed(
                    output.commit_index,
                    &output.transactions,
                    leader_address,
                    Some(&mut *registry_guard),
                    current_epoch_for_stake,
                );

                // γ-5: epoch-boundary unbonding settlement.
                //
                // `execute_committed` just bumped `tx_executor.height` by 1.
                // If that bump crossed an `EPOCH_LENGTH` multiple, walk the
                // registry for `Exiting` validators whose unbonding period
                // has now completed, unlock them, and materialize the
                // unlocked stake as a transparent UTXO directed at each
                // validator's `reward_address`. The registry write lock is
                // still held here, so the settle and the commit it follows
                // are atomic relative to REST-side readers.
                //
                // Note: the ghostdag-compat epoch hook lives at
                // `apply_sr21_election_at_epoch_boundary` (L6085-equivalent)
                // but that code path does not carry a `UtxoExecutor`, so
                // γ-5 settlement is wired here in `start_narwhal_node`
                // instead. See γ-5 preflight notes for the routing detail.
                let new_height = tx_executor.height();
                if new_height > 0 {
                    let epoch_len = misaka_types::constants::EPOCH_LENGTH;
                    let prev_epoch = new_height.saturating_sub(1) / epoch_len;
                    let new_epoch = new_height / epoch_len;
                    if new_epoch > prev_epoch {
                        let settled = registry_guard.settle_unlocks(new_epoch);
                        if !settled.is_empty() {
                            tracing::info!(
                                "γ-5: epoch {} boundary at height {} — settling {} unbonded validator(s)",
                                new_epoch,
                                new_height,
                                settled.len()
                            );
                            tx_executor.apply_settled_unlocks(&settled, new_epoch);
                        }

                        // PR-B: update uptime_bps from this epoch's propose
                        // accounting, then slash validators that produced
                        // zero blocks (downtime Minor — 1%).
                        //
                        // Ordering rationale: uptime is measured over the
                        // CLOSING epoch, BEFORE auto_activate_locked admits
                        // new validators. New validators have no proposing
                        // history yet and must not be scored on this pass.
                        //
                        // `expected = epoch_block_count / active_count`.
                        // When `active_count == 0` (bootstrap edge) we
                        // assign 100% to every currently-Active validator
                        // rather than divide by zero.
                        {
                            let active_count = registry_guard.active_count().max(1) as u64;
                            let expected = if active_count == 0 {
                                0
                            } else {
                                epoch_block_count / active_count
                            };

                            // Snapshot (id, current_uptime_unused) so we can drop
                            // the immutable borrow before calling update_uptime (mut).
                            let active_ids: Vec<[u8; 32]> = registry_guard
                                .all_validators()
                                .filter(|v| v.state == misaka_consensus::staking::ValidatorState::Active)
                                .map(|v| v.validator_id)
                                .collect();

                            let mut zero_uptime_ids: Vec<[u8; 32]> = Vec::new();
                            for vid in &active_ids {
                                let proposed = propose_count.get(vid).copied().unwrap_or(0);
                                let uptime_bps = compute_uptime_bps(proposed, expected);
                                registry_guard.update_uptime(vid, uptime_bps);
                                if proposed == 0 && expected > 0 {
                                    zero_uptime_ids.push(*vid);
                                }
                            }

                            for vid in &zero_uptime_ids {
                                match registry_guard.slash(
                                    vid,
                                    misaka_consensus::staking::SlashSeverity::Minor,
                                    new_epoch,
                                ) {
                                    Ok((slashed, _reporter_reward)) => {
                                        tracing::warn!(
                                            "PR-B: downtime slash Minor (1%) for {} — \
                                             produced 0 blocks in epoch {} — slashed {} base units",
                                            hex::encode(&vid[..8]),
                                            new_epoch,
                                            slashed,
                                        );
                                    }
                                    Err(e) => {
                                        // Cooldown / non-slashable state — log and move on.
                                        tracing::debug!(
                                            "PR-B: downtime slash skipped for {}: {:?}",
                                            hex::encode(&vid[..8]),
                                            e,
                                        );
                                    }
                                }
                            }

                            if !active_ids.is_empty() {
                                tracing::info!(
                                    "PR-B: uptime updated for {} active validators at epoch {} — \
                                     epoch_blocks={}, expected_per_validator={}, downtime_slashed={}",
                                    active_ids.len(),
                                    new_epoch,
                                    epoch_block_count,
                                    expected,
                                    zero_uptime_ids.len(),
                                );
                            }
                        }

                        // Group 2: auto-activate LOCKED → ACTIVE for validators
                        // whose stake was verified since the last boundary.
                        // Runs AFTER `settle_unlocks` so retired stake frees
                        // `max_active_validators` headroom in the same epoch.
                        let activated = registry_guard.auto_activate_locked(new_epoch);
                        if !activated.is_empty() {
                            tracing::info!(
                                "Group 2: epoch {} boundary — auto-activated {} LOCKED→ACTIVE validator(s)",
                                new_epoch,
                                activated.len(),
                            );
                        }

                        // Phase 10 (Item 1): Deferred VALIDATOR restart.
                        //
                        // If THIS node was started in OBSERVER MODE (not in
                        // genesis TOML, not ACTIVE in the registry at boot)
                        // and the epoch-boundary auto_activate_locked just
                        // promoted it, the relay transport and propose loop
                        // were already configured for observer-only operation
                        // at boot and cannot be switched in place. Drop the
                        // registry write lock cleanly and exit with status 0;
                        // a supervisor configured with `Restart=always`
                        // (systemd) will restart the node, and the updated
                        // `is_dynamic_active_validator(...)` check at boot
                        // will place it in VALIDATOR MODE (dynamic).
                        //
                        // Exit is gated on `is_observer` so this path never
                        // fires for nodes that were already validators at
                        // boot (they have nothing to restart).
                        if is_observer {
                            if activated.contains(&self_fingerprint_for_restart) {
                                tracing::warn!(
                                    "🔄 Phase 10: self-activated at epoch {} — exiting so \
                                     supervisor can restart in VALIDATOR MODE (dynamic). \
                                     fingerprint={}. Ensure Restart=always in the systemd unit.",
                                    new_epoch,
                                    hex::encode(self_fingerprint_for_restart),
                                );
                                // Drop registry write lock before exit so the
                                // serialized snapshot path (if any) sees a
                                // consistent state. The explicit drop is
                                // cosmetic in practice — process exit tears
                                // down all held guards — but keeps the
                                // intent obvious to readers.
                                drop(registry_guard);
                                std::process::exit(0);
                            }
                        }

                        // Group 2: SR21 election on the freshly-updated
                        // registry. On the narwhal path there is no
                        // `DagNodeState` / `shared_state` to receive the
                        // result (that container lives only in
                        // `start_dag_node`), so the election outcome is
                        // emitted as structured logs and a gauge metric.
                        // Phase 8 (dynamic committee) will add the runtime
                        // write-back plumbing proper.
                        let identities = crate::sr21_election::registry_to_validator_identities(
                            &*registry_guard,
                        );
                        if !identities.is_empty() {
                            let election = crate::sr21_election::run_election_for_chain(
                                &identities,
                                cli.chain_id,
                                new_epoch,
                            );
                            tracing::info!(
                                "Group 2: SR21 election at epoch {} — candidates={} active={} dropped={} total_stake={}",
                                new_epoch,
                                identities.len(),
                                election.num_active,
                                election.dropped_count,
                                election.total_active_stake,
                            );
                        } else {
                            tracing::debug!(
                                "Group 2: SR21 election at epoch {} — no ACTIVE validators in registry; skipped",
                                new_epoch,
                            );
                        }

                        // Phase 8 (Gap A): epoch-boundary committee hot-reload.
                        //
                        // After settle_unlocks (γ-5) + auto_activate_locked
                        // (Group 2) the registry's ACTIVE set may have
                        // changed. Rebuild the committee from
                        // (genesis manifest + ACTIVE validators) and
                        // publish it to the narwhal runtime via the same
                        // `ReloadCommittee` channel the REST path uses
                        // (β-2 / β-3). Still under `registry_guard.write()`
                        // so the committee reflects the exact post-mutation
                        // state atomically.
                        //
                        // Error handling: `build_committee_from_sources` can
                        // fail if genesis TOML is corrupt (shouldn't happen
                        // post-startup) or if the merged authority set has
                        // duplicate pubkeys (would already have failed at
                        // REST register). We log warn! and skip the reload
                        // rather than halt — the existing committee stays
                        // in place, which is the same behavior as a
                        // failed REST hot-reload.
                        //
                        // PR-A: use `build_sr21_committee` so the narwhal
                        // committee reflects the SR21 top-21 stake-ranked
                        // cap, not the raw merged set. REST hot-reload
                        // paths (main.rs:1169, 2232, 2411, 2459) still use
                        // the unfiltered `build_committee_from_sources` for
                        // event-driven rebuilds; the top-21 cap is applied
                        // once per epoch at the boundary only.
                        match crate::genesis_committee::build_sr21_committee(
                            &manifest,
                            &*registry_guard,
                            cli.chain_id,
                            new_epoch,
                        ) {
                            Ok(new_committee) => {
                                let new_size = new_committee.size();
                                {
                                    let mut committee_w = committee_shared.write().await;
                                    *committee_w = new_committee.clone();
                                }
                                if let Err(e) = msg_tx
                                    .send(
                                        misaka_dag::narwhal_dag::runtime::ConsensusMessage::ReloadCommittee(
                                            new_committee,
                                        ),
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        "PR-A: ReloadCommittee send failed at epoch {}: {}",
                                        new_epoch, e
                                    );
                                } else {
                                    tracing::info!(
                                        "PR-A: SR21 committee hot-reloaded at epoch {} — {} authorities (top-21 cap applied)",
                                        new_epoch, new_size
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "PR-A: build_sr21_committee failed at epoch {}: {} — keeping existing committee",
                                    new_epoch, e
                                );
                            }
                        }

                        // PR-B: reset per-epoch counters after the boundary
                        // block has consumed them. The next epoch starts
                        // from zero; missing this clear would accumulate
                        // propose counts across epochs and inflate uptime.
                        propose_count.clear();
                        epoch_block_count = 0;
                    }
                }

                drop(registry_guard);
                total_committed_txs += output.transactions.len() as u64;
                total_accepted_txs += exec_result.txs_accepted as u64;

                // SEC-FIX C-12: Generate block reward for the commit leader.
                // R7 C-4: Skip when the batch already contained a SystemEmission
                // to prevent double emission in the same commit.
                if let Some(addr) = leader_address.filter(|_| !exec_result.had_system_emission) {
                    let author_idx = output.leader.author as usize;
                    let leader_pk = if author_idx < committee_guard.authorities.len() {
                        let pk = &committee_guard.authorities[author_idx].public_key;
                        if !pk.is_empty() { Some(pk.clone()) } else { None }
                    } else {
                        None
                    };
                    let reward = tx_executor.generate_block_reward(addr, leader_pk);
                    if reward > 0 {
                        tracing::info!(
                            "Block reward: {} MISAKA to leader {} (commit {})",
                            reward as f64 / 1_000_000_000.0,
                            hex::encode(&addr[..8]),
                            output.commit_index,
                        );
                    }
                }

                drop(committee_guard);

                // Update shared persistent block height
                block_height_writer.store(
                    tx_executor.height(),
                    std::sync::atomic::Ordering::Relaxed,
                );
                // Update shared state_root for propose loop
                let new_root = tx_executor.state_root();
                *shared_state_root.write().await = new_root;

                // SEC-FIX C-9: Verify state_root against leader's proposed value.
                // Detects Byzantine proposers embedding false state commitments.
                //
                // v0.5.9: on mismatch, trip the process-global safe-mode
                // flag and stop processing further commits. The propose
                // loop and write RPC handlers poll the same flag.
                if let Some(leader_root) = output.leader_state_root {
                    if leader_root != new_root {
                        let reason = format!(
                            "state_root mismatch at commit {}: leader proposed {} \
                             but local execution computed {}",
                            output.commit_index,
                            hex::encode(leader_root),
                            hex::encode(new_root),
                        );
                        tracing::error!(
                            "STATE ROOT MISMATCH at commit {}: \
                             leader proposed {} but local execution computed {}. \
                             Potential Byzantine proposer or state divergence!",
                            output.commit_index,
                            hex::encode(&leader_root[..8]),
                            hex::encode(&new_root[..8]),
                        );
                        safe_mode.trip(output.commit_index, reason);
                        // Exit the commit loop. We cannot safely apply
                        // further committed sub-dags on top of a state
                        // that has already diverged from the leader.
                        break;
                    }
                }

                {
                    let summary = BlockSummary {
                        height: tx_executor.height(),
                        hash: hex::encode(output.leader.digest.0),
                        tx_count: output.transactions.len(),
                        txs_accepted: exec_result.txs_accepted,
                        timestamp_ms: output.timestamp_ms,
                        author: output.leader.author,
                        state_root: hex::encode(&new_root[..8]),
                        fees: exec_result.total_fees,
                    };
                    let mut buf = recent_blocks_writer.write().await;
                    if buf.len() >= 64 { buf.pop_back(); }
                    buf.push_front(summary);
                }

                // Update shared UtxoSet for RPC queries and mempool admission.
                // Clone is expensive (~800MB copy). Use block_in_place to yield the
                // async worker thread so RPC handlers remain responsive during the copy.
                if exec_result.txs_accepted > 0 || output.commit_index % 100 == 1 {
                    let fresh = tokio::task::block_in_place(|| {
                        tx_executor.utxo_set().clone()
                    });
                    let mut shared = utxo_set_writer.write().await;
                    *shared = fresh;
                }

                // Index committed transaction hashes for get_tx_status
                // and remove them from the mempool so status transitions
                // from "pending" to "confirmed".
                // Persist full CommittedTxDetail + AddressTxRef to RocksDB.
                if !output.transactions.is_empty() {
                    let current_height = tx_executor.height();
                    let leader_authority = output.leader.author as u32;
                    let mut participating: Vec<u32> = output
                        .blocks
                        .iter()
                        .map(|b| b.author as u32)
                        .collect::<std::collections::BTreeSet<u32>>()
                        .into_iter()
                        .collect();
                    if !participating.contains(&leader_authority) {
                        participating.push(leader_authority);
                        participating.sort_unstable();
                    }

                    let mut tx_map = committed_txs_writer.write().await;
                    let mut mempool_guard = narwhal_mempool.mempool.lock().await;
                    for raw_tx in &output.transactions {
                        if let Ok(tx) = borsh::from_slice::<misaka_types::utxo::UtxoTransaction>(raw_tx) {
                            let hash = tx.tx_hash();
                            let hash_hex = hex::encode(hash);
                            let tx_type_str = format!("{:?}", tx.tx_type);
                            let memo = String::from_utf8(tx.extra.clone()).unwrap_or_default();

                            let inputs_summary: Vec<TxInputSummary> = tx.inputs.iter().map(|inp| {
                                TxInputSummary {
                                    utxo_refs: inp.utxo_refs.iter().map(|r| {
                                        format!("{}:{}", hex::encode(r.tx_hash), r.output_index)
                                    }).collect(),
                                }
                            }).collect();

                            let outputs_summary: Vec<TxOutputSummary> = tx.outputs.iter().map(|out| {
                                TxOutputSummary {
                                    address: misaka_types::address::encode_address(&out.address, cli.chain_id),
                                    amount: out.amount,
                                }
                            }).collect();

                            let detail = CommittedTxDetail {
                                height: current_height,
                                status: "confirmed".to_string(),
                                tx_type: tx_type_str.clone(),
                                inputs: inputs_summary,
                                outputs: outputs_summary.clone(),
                                fee: tx.fee,
                                timestamp_ms: output.timestamp_ms,
                                leader_authority,
                                participating_validators: participating.clone(),
                                memo: memo.clone(),
                            };

                            // Persist to RocksDB
                            if let Ok(json_bytes) = serde_json::to_vec(&detail) {
                                if let Err(e) = tx_index_store.put_tx_detail(&hash, &json_bytes) {
                                    tracing::warn!("Failed to persist tx_index: {}", e);
                                }
                            }

                            // Persist address index entries for outputs
                            for out_summary in &outputs_summary {
                                let addr_ref = AddressTxRef {
                                    tx_hash: hash_hex.clone(),
                                    direction: "receive".to_string(),
                                    amount: out_summary.amount,
                                    height: current_height,
                                    timestamp_ms: output.timestamp_ms,
                                    tx_type: tx_type_str.clone(),
                                };
                                if let Ok(ref_bytes) = serde_json::to_vec(&addr_ref) {
                                    let addr_key = format!(
                                        "{}:{:016x}:{}",
                                        out_summary.address, current_height, hash_hex
                                    );
                                    if let Err(e) = tx_index_store.put_addr_entry(
                                        addr_key.as_bytes(),
                                        &ref_bytes,
                                    ) {
                                        tracing::warn!("Failed to persist addr_index: {}", e);
                                    }
                                }
                            }

                            // In-memory cache
                            tx_map.insert(hash, detail);
                            mempool_guard.remove(&hash);
                        }
                    }
                    // Evict oldest entries from in-memory cache if too large
                    if tx_map.len() > 10_000 {
                        let excess = tx_map.len() - 10_000;
                        let mut entries: Vec<([u8; 32], u64)> = tx_map
                            .iter()
                            .map(|(k, v)| (*k, v.height))
                            .collect();
                        entries.sort_unstable_by_key(|&(_, h)| h);
                        for (k, _) in entries.into_iter().take(excess) {
                            tx_map.remove(&k);
                        }
                    }
                }

                info!(
                    "Committed: index={}, txs={} (accepted={}), \
                     fees={}, utxos_created={}, state_root={}, total={}/{} accepted",
                    output.commit_index,
                    output.transactions.len(),
                    exec_result.txs_accepted,
                    exec_result.total_fees,
                    exec_result.utxos_created,
                    hex::encode(&new_root[..8]),
                    total_accepted_txs,
                    total_committed_txs,
                );

                // Persist UTXO snapshot when user TXs land.
                // Only save when actual transactions are accepted to avoid
                // wasteful 2GB+ writes on empty blocks. The snapshot is saved
                // synchronously here (blocking) because spawn_blocking + clone
                // doubles memory usage and triggers OOM on small servers.
                if exec_result.txs_accepted > 0 {
                    if let Err(e) = tx_executor.utxo_set().save_to_file(&utxo_snapshot_path) {
                        tracing::warn!("Failed to save UTXO snapshot: {}", e);
                    } else {
                        tracing::info!(
                            "UTXO snapshot saved at commit {} (height={}) [triggered by {} accepted tx(s)]",
                            output.commit_index,
                            tx_executor.utxo_set().height,
                            exec_result.txs_accepted,
                        );
                    }

                    // Phase 2 Path X R1 step 2: mirror the committed tip
                    // (height + state_root) under the Kaspa-aligned
                    // `StorePrefixes::VirtualState` keyspace so crash
                    // recovery can read it without the legacy
                    // `RocksBlockStore`. Parallels the fs-JSON snapshot
                    // above — same cadence, same trigger. Best-effort:
                    // a failure here does not invalidate the commit.
                    let committed_state = misaka_storage::CommittedState {
                        height: tx_executor.utxo_set().height,
                        state_root: new_root,
                        tip_hash: [0u8; 32], // reserved — populated in a later step
                    };
                    if let Err(e) = misaka_storage::write_committed_state(
                        integrity_store.raw_db(),
                        &committed_state,
                    ) {
                        tracing::warn!(
                            "Failed to persist startup_integrity committed state: {}",
                            e
                        );
                    }
                }
            }
            // Graceful shutdown: save UTXO snapshot so balances survive restart.
            // This is a single save (not per-commit clone) so OOM is not a concern.
            if let Err(e) = tx_executor.utxo_set().save_to_file(&utxo_snapshot_path) {
                tracing::warn!("Failed to save UTXO snapshot on shutdown: {}", e);
            } else {
                tracing::info!(
                    "UTXO snapshot saved on shutdown (height={})",
                    tx_executor.utxo_set().height,
                );
            }

            // Phase 2 Path X R1 step 2: persist the final committed
            // tip on shutdown. `tx_executor.state_root()` recomputes
            // from the current UTXO set; `tx_executor.utxo_set().height`
            // is the last applied height. Recomputing on shutdown
            // avoids depending on the per-commit-loop local
            // `new_root`, which is out of scope here.
            let shutdown_committed = misaka_storage::CommittedState {
                height: tx_executor.utxo_set().height,
                state_root: tx_executor.state_root(),
                tip_hash: [0u8; 32],
            };
            if let Err(e) = misaka_storage::write_committed_state(
                integrity_store.raw_db(),
                &shutdown_committed,
            ) {
                tracing::warn!(
                    "Failed to persist startup_integrity committed state on shutdown: {}",
                    e
                );
            }
        } => {
            info!("Commit channel closed");
        }
        _ = shutdown_handle => {
            info!("Shutdown signal received");
            let _ = runtime_handle.await;
            let uptime = start_time.elapsed();
            info!(
                "MISAKA node stopped gracefully (uptime: {}s, blocks_proposed: {})",
                uptime.as_secs(),
                misaka_dag::narwhal_dag::metrics::ConsensusMetrics::get(&metrics.blocks_proposed),
            );
        }
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════
//  Shared RPC helpers for Narwhal mode
// ════════════════════════════════════════════════════════════════

/// Query UTXOs by address string (hex or bech32). Returns JSON response
/// compatible with both `/api/get_utxos_by_address` and `/api/get_indexed_utxos`.
async fn query_utxos_by_address(
    utxo_set: &Arc<tokio::sync::RwLock<misaka_storage::utxo_set::UtxoSet>>,
    address_str: &str,
    chain_id: u32,
) -> serde_json::Value {
    let addr_bytes: Option<[u8; 32]> = if address_str.len() == 64 {
        hex::decode(address_str)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
    } else if let Some(hex_part) = address_str.strip_prefix("misakatest1") {
        hex::decode(hex_part)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
    } else if address_str.starts_with("misaka1") || address_str.starts_with("msk1") {
        misaka_types::address::decode_address(address_str, chain_id).ok()
    } else {
        None
    };

    let addr = match addr_bytes {
        Some(a) => a,
        None => {
            return serde_json::json!({
                "address": address_str,
                "utxos": [],
                "balance": 0,
                "utxoCount": 0,
                "error": "invalid address format",
            });
        }
    };

    let guard = utxo_set.read().await;
    let entries = guard.get_utxos_by_address(&addr);
    let mut balance: u64 = 0;
    let utxos: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            balance = balance.saturating_add(e.output.amount);
            serde_json::json!({
                "txHash": hex::encode(e.outref.tx_hash),
                "outputIndex": e.outref.output_index,
                "amount": e.output.amount,
                "address": hex::encode(e.output.address),
                "createdAt": e.created_at,
                "isEmission": e.is_emission,
                "hasSpendingKey": e.output.spending_pubkey.is_some(),
            })
        })
        .collect();

    serde_json::json!({
        "address": address_str,
        "utxos": utxos,
        "balance": balance,
        "utxoCount": utxos.len(),
    })
}

// ════════════════════════════════════════════════════════════════
//  v2: DAG Node Startup (GhostDAG compat — being phased out)
// ════════════════════════════════════════════════════════════════

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
fn local_validator_key_path(
    data_dir: &std::path::Path,
    validator_index: usize,
) -> std::path::PathBuf {
    data_dir.join(format!("dag_validator_{validator_index}.json"))
}

// 0.9.0 β-2: removed `#[cfg(feature = "ghostdag-compat")]` so
// `start_narwhal_node` (the default `dag` path without ghostdag-compat) can
// call this helper to locate the lifecycle snapshot file.
//
// γ-2.5: bumped to `pub(crate)` so the extracted
// `validator_lifecycle_bootstrap` module can share the same path convention.
pub(crate) fn validator_lifecycle_snapshot_path(
    data_dir: &std::path::Path,
    chain_id: u32,
) -> std::path::PathBuf {
    data_dir.join(format!("validator_lifecycle_chain_{chain_id}.json"))
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
fn load_or_create_local_dag_validator(
    data_dir: &std::path::Path,
    role: NodeRole,
    validator_index: usize,
    chain_id: u32,
) -> anyhow::Result<Option<misaka_dag::LocalDagValidator>> {
    use misaka_crypto::keystore::{
        decrypt_keystore, encrypt_keystore, is_plaintext_keyfile, load_keystore, save_keystore,
    };
    use misaka_crypto::validator_sig::{
        generate_validator_keypair, ValidatorPqPublicKey, ValidatorPqSecretKey,
    };
    use misaka_types::validator::{ValidatorIdentity, ValidatorPublicKey};

    if !role.produces_blocks() {
        return Ok(None);
    }

    let plaintext_path = local_validator_key_path(data_dir, validator_index);
    let encrypted_path = data_dir.join(format!("dag_validator_{validator_index}.enc.json"));

    // Read passphrase from env var or file. For testnet, allow empty
    // passphrase (encrypts with empty string — still better than
    // plaintext). For mainnet (chain_id=1), require a non-empty
    // passphrase.
    //
    // v0.5.13 audit P0-1: the deploy script writes the passphrase to a
    // chmod 600 file at `/opt/misaka/.passphrase` and sets
    // `MISAKA_VALIDATOR_PASSPHRASE_FILE` in the systemd unit, but
    // previously the runtime only read `MISAKA_VALIDATOR_PASSPHRASE`
    // (env var). On restart the env var was empty and the node
    // couldn't decrypt its own keystore. Now we check both: env var
    // first (convenience for local dev), file fallback (production
    // systemd contract). The file path is read from
    // `MISAKA_VALIDATOR_PASSPHRASE_FILE`; its trailing whitespace is
    // stripped so a trailing newline from `echo > file` doesn't
    // become part of the key material.
    fn read_passphrase(chain_id: u32) -> anyhow::Result<Vec<u8>> {
        let from_env = std::env::var("MISAKA_VALIDATOR_PASSPHRASE")
            .ok()
            .filter(|s| !s.is_empty());
        let passphrase = if let Some(env_value) = from_env {
            env_value.into_bytes()
        } else if let Ok(file_path) = std::env::var("MISAKA_VALIDATOR_PASSPHRASE_FILE") {
            if file_path.is_empty() {
                Vec::new()
            } else {
                let raw = std::fs::read(&file_path).map_err(|e| {
                    anyhow::anyhow!(
                        "FATAL: failed to read MISAKA_VALIDATOR_PASSPHRASE_FILE='{}': {}",
                        file_path,
                        e
                    )
                })?;
                // Strip trailing newline/whitespace so shells like
                // `echo "$PASS" > file` do not inject it into the
                // passphrase bytes.
                let end = raw
                    .iter()
                    .rposition(|b| !matches!(*b, b'\n' | b'\r' | b' ' | b'\t'))
                    .map(|p| p + 1)
                    .unwrap_or(0);
                raw[..end].to_vec()
            }
        } else if std::path::Path::new("/run/secrets/validator_passphrase").exists() {
            let raw = std::fs::read("/run/secrets/validator_passphrase").map_err(|e| {
                anyhow::anyhow!(
                    "FATAL: failed to read Docker secret /run/secrets/validator_passphrase: {}",
                    e
                )
            })?;
            let end = raw
                .iter()
                .rposition(|b| !matches!(*b, b'\n' | b'\r' | b' ' | b'\t'))
                .map(|p| p + 1)
                .unwrap_or(0);
            raw[..end].to_vec()
        } else {
            Vec::new()
        };
        // SEC-FIX: mainnet MUST have a non-empty passphrase
        if chain_id == 1 && passphrase.is_empty() {
            anyhow::bail!(
                "FATAL: MISAKA_VALIDATOR_PASSPHRASE or MISAKA_VALIDATOR_PASSPHRASE_FILE \
                 must be set and non-empty on mainnet (chain_id=1). An empty passphrase \
                 means the keystore can be decrypted trivially."
            );
        }
        Ok(passphrase)
    }

    let keypair_and_identity = if encrypted_path.exists() {
        // ── Load from encrypted keystore ──
        let passphrase = read_passphrase(chain_id)?;
        let keystore = load_keystore(&encrypted_path)
            .map_err(|e| anyhow::anyhow!("failed to load encrypted keystore: {}", e))?;

        let secret_bytes = decrypt_keystore(&keystore, &passphrase).map_err(|e| {
            anyhow::anyhow!(
                "failed to decrypt validator key at '{}': {}. \
                 Set MISAKA_VALIDATOR_PASSPHRASE env var with the correct passphrase.",
                encrypted_path.display(),
                e
            )
        })?;

        let validator_id_vec = hex::decode(&keystore.validator_id_hex)?;
        let mut validator_id = [0u8; 32];
        if validator_id_vec.len() != 32 {
            anyhow::bail!(
                "invalid validator id length in '{}': expected 32, got {}",
                encrypted_path.display(),
                validator_id_vec.len()
            );
        }
        validator_id.copy_from_slice(&validator_id_vec);

        let public_key = ValidatorPqPublicKey::from_bytes(&hex::decode(&keystore.public_key_hex)?)
            .map_err(anyhow::Error::msg)?;

        // SEC-FIX: Use from_bytes() instead of direct field construction.
        // Ensures length validation (4032 bytes) is always enforced.
        let secret_key = ValidatorPqSecretKey::from_bytes(&secret_bytes).ok_or_else(|| {
            anyhow::anyhow!(
                "invalid validator secret key length: {} (expected 4032)",
                secret_bytes.len()
            )
        })?;
        let keypair = misaka_crypto::validator_sig::ValidatorKeypair {
            public_key,
            secret_key,
        };
        let identity = ValidatorIdentity {
            validator_id,
            stake_weight: keystore.stake_weight,
            public_key: ValidatorPublicKey {
                bytes: keypair.public_key.to_bytes(),
            },
            is_active: true,
        };
        info!(
            "Layer 2: loaded encrypted DAG validator key | id={} | file={}",
            hex::encode(identity.validator_id),
            encrypted_path.display()
        );
        (keypair, identity)
    } else if plaintext_path.exists() && is_plaintext_keyfile(&plaintext_path) {
        // SEC-FIX: On mainnet, refuse to start with plaintext keyfile.
        // Migration leaves a .bak file that may contain the plaintext secret key.
        // Force operators to manually encrypt and verify before mainnet deployment.
        if chain_id == 1 {
            anyhow::bail!(
                "FATAL: Plaintext validator key detected at '{}' on mainnet (chain_id=1). \
                 Encrypt the keyfile manually before starting: \
                 misaka-cli encrypt-keystore --input {} --output {}",
                plaintext_path.display(),
                plaintext_path.display(),
                plaintext_path.with_extension("enc.json").display()
            );
        }
        // ── Migrate plaintext → encrypted (testnet/devnet only) ──
        warn!(
            "Layer 2: ⚠ plaintext validator key detected at '{}' — migrating to encrypted format",
            plaintext_path.display()
        );

        let raw = std::fs::read_to_string(&plaintext_path)?;
        let persisted: LocalDagValidatorKeyFile = serde_json::from_str(&raw)?;

        let validator_id_vec = hex::decode(&persisted.validator_id_hex)?;
        let mut validator_id = [0u8; 32];
        if validator_id_vec.len() != 32 {
            anyhow::bail!("invalid validator id in plaintext key file");
        }
        validator_id.copy_from_slice(&validator_id_vec);

        let public_key = ValidatorPqPublicKey::from_bytes(&hex::decode(&persisted.public_key_hex)?)
            .map_err(anyhow::Error::msg)?;

        let secret_bytes = hex::decode(&persisted.secret_key_hex)?;
        let passphrase = read_passphrase(chain_id)?;

        // Encrypt and save
        let keystore = encrypt_keystore(
            &secret_bytes,
            &persisted.public_key_hex,
            &persisted.validator_id_hex,
            persisted.stake_weight,
            &passphrase,
        )
        .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;

        save_keystore(&encrypted_path, &keystore)
            .map_err(|e| anyhow::anyhow!("failed to save encrypted keystore: {}", e))?;

        // Rename old plaintext file to .bak (don't delete — operator may want it)
        let backup_path = plaintext_path.with_extension("json.plaintext.bak");
        if let Err(e) = std::fs::rename(&plaintext_path, &backup_path) {
            warn!(
                "Could not rename plaintext key file: {} (delete manually)",
                e
            );
        } else {
            warn!(
                "Layer 2: plaintext key backed up to '{}' — DELETE THIS FILE after verifying the encrypted key works",
                backup_path.display()
            );
        }

        // SEC-FIX: Use from_bytes() instead of direct field construction.
        // Ensures length validation (4032 bytes) is always enforced.
        let secret_key = ValidatorPqSecretKey::from_bytes(&secret_bytes).ok_or_else(|| {
            anyhow::anyhow!(
                "invalid validator secret key length: {} (expected 4032)",
                secret_bytes.len()
            )
        })?;
        let keypair = misaka_crypto::validator_sig::ValidatorKeypair {
            public_key,
            secret_key,
        };
        let identity = ValidatorIdentity {
            validator_id,
            stake_weight: persisted.stake_weight,
            public_key: ValidatorPublicKey {
                bytes: keypair.public_key.to_bytes(),
            },
            is_active: true,
        };
        info!(
            "Layer 2: migrated to encrypted keystore | id={} | file={}",
            hex::encode(identity.validator_id),
            encrypted_path.display()
        );
        (keypair, identity)
    } else {
        // ── Generate new key → encrypted ──
        let keypair = generate_validator_keypair();
        let identity = ValidatorIdentity {
            validator_id: keypair.public_key.to_canonical_id(),
            stake_weight: 1_000_000,
            public_key: ValidatorPublicKey {
                bytes: keypair.public_key.to_bytes(),
            },
            is_active: true,
        };

        let passphrase = read_passphrase(chain_id)?;
        let keystore = keypair
            .secret_key
            .with_bytes(|sk_bytes| {
                encrypt_keystore(
                    sk_bytes,
                    &hex::encode(&identity.public_key.bytes),
                    &hex::encode(identity.validator_id),
                    identity.stake_weight,
                    &passphrase,
                )
            })
            .map_err(|e| anyhow::anyhow!("encryption failed: {}", e))?;

        save_keystore(&encrypted_path, &keystore)
            .map_err(|e| anyhow::anyhow!("failed to save encrypted keystore: {}", e))?;

        info!(
            "Layer 2: created encrypted DAG validator key | id={} | file={}",
            hex::encode(identity.validator_id),
            encrypted_path.display()
        );
        (keypair, identity)
    };

    Ok(Some(misaka_dag::LocalDagValidator {
        keypair: keypair_and_identity.0,
        identity: keypair_and_identity.1,
    }))
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
fn normalize_experimental_validator_identity(
    identity: &misaka_types::validator::ValidatorIdentity,
) -> anyhow::Result<misaka_types::validator::ValidatorIdentity> {
    use misaka_crypto::validator_sig::ValidatorPqPublicKey;

    let public_key = ValidatorPqPublicKey::from_bytes(&identity.public_key.bytes)
        .map_err(|e| anyhow::anyhow!("invalid validator public key: {}", e))?;
    let expected_id = public_key.to_canonical_id();
    if expected_id != identity.validator_id {
        anyhow::bail!(
            "validator identity mismatch: derived={}, declared={}",
            hex::encode(expected_id),
            hex::encode(identity.validator_id)
        );
    }

    // SEC-FIX [v9.1]: stake_weight は自己申告値を信用しない。
    //
    // 旧実装は stake_weight: 1 に固定していたため、預入枚数がコンセンサスに
    // 全く反映されていなかった。
    //
    // 修正: リモートバリデータの自己申告 stake_weight も信用しない（1 に固定を維持）。
    // 正しい stake_weight は Solana オンチェーン検証でのみ設定される。
    // discover_checkpoint_validators_from_rpc_peers() の呼び出し後に
    // verify_and_update_remote_stakes() で Solana 上の実際の預入額に更新する。
    //
    // Phase C compile-hygiene slice:
    // experimental checkpoint identities stay fail-safe at stake=1 here.
    // Committee bootstrap and Solana-backed reconciliation are handled on the
    // explicit committee path; self-reported remote stake is never trusted.
    let stake_weight = 1;

    Ok(misaka_types::validator::ValidatorIdentity {
        stake_weight,
        is_active: true,
        ..identity.clone()
    })
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
pub(crate) fn dag_validator_set(
    state: &misaka_dag::DagNodeState,
) -> misaka_consensus::ValidatorSet {
    misaka_consensus::ValidatorSet::new(state.known_validators.clone())
}

/// DEPRECATED: Count-based quorum calculation. Use stake-weighted quorum instead.
///
/// SECURITY WARNING (HIGH #5): This function ignores stake distribution.
/// With skewed stake (e.g., 60/5/5/5/5/5/5/5/5), count-majority (8 of 9)
/// does NOT imply stake-majority. Bridge/relayer relying on this for finality
/// will produce false positives.
///
/// For production use: `Committee::quorum_threshold()` or
/// `ValidatorSet::quorum_threshold()`.
#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
#[cfg(test)]
pub(crate) fn expected_dag_quorum_threshold(validator_count: usize) -> u128 {
    let total = validator_count.max(1) as u128;
    total * 2 / 3 + 1
}

/// Stake-weighted quorum threshold — the ONLY correct function for production.
///
/// Delegates to `Committee::quorum_threshold()` which uses the Sui-aligned
/// formula: `N - floor((N-1)/3)` where N = total_stake.
#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
pub(crate) fn dag_quorum_threshold_from_committee(
    committee: &misaka_dag::narwhal_types::committee::Committee,
) -> u64 {
    committee.quorum_threshold()
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
pub(crate) fn apply_sr21_election_at_epoch_boundary(
    state: &mut misaka_dag::DagNodeState,
    next_epoch: u64,
) -> sr21_election::ElectionResult {
    let election_result =
        sr21_election::run_election_for_chain(&state.known_validators, state.chain_id, next_epoch);
    state.num_active_srs = election_result.num_active.max(1);
    state.runtime_active_sr_validator_ids = election_result
        .active_srs
        .iter()
        .map(|elected| elected.validator_id)
        .collect();

    if let Some(ref lv) = state.local_validator {
        if let Some(new_index) =
            sr21_election::find_sr_index(&election_result, &lv.identity.validator_id)
        {
            state.sr_index = new_index;
            info!(
                "SR21 Election: local validator assigned SR_index={} (epoch={})",
                new_index, next_epoch
            );
        } else {
            warn!(
                "SR21 Election: local validator NOT in active set (epoch={}) — block production paused",
                next_epoch
            );
        }
    }

    election_result
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
pub(crate) fn deterministic_dag_genesis_header(
    chain_id: u32,
) -> misaka_dag::dag_block::DagBlockHeader {
    use misaka_dag::dag_block::{DagBlockHeader, DAG_VERSION, ZERO_HASH};
    use sha3::{Digest, Sha3_256};

    let mut h = Sha3_256::new();
    h.update(b"MISAKA_DAG_GENESIS_V1:");
    h.update(chain_id.to_le_bytes());
    let proposer_id: [u8; 32] = h.finalize().into();

    DagBlockHeader {
        version: DAG_VERSION,
        parents: vec![],
        timestamp_ms: 0,
        tx_root: ZERO_HASH,
        proposer_id,
        nonce: 0,
        blue_score: 0,
        bits: 0,
    }
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
fn normalize_dag_rpc_peer(peer: &str) -> Option<String> {
    let trimmed = peer.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }

    let normalized = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{}", trimmed)
    };

    if reqwest::Url::parse(&normalized).is_err() {
        return None;
    }

    Some(normalized)
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
fn normalize_dag_rpc_peers(peers: &[String]) -> Vec<String> {
    let mut normalized = peers
        .iter()
        .filter_map(|peer| normalize_dag_rpc_peer(peer))
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
#[derive(Debug, serde::Deserialize)]
struct DagRpcValidatorIdentityWire {
    #[serde(rename = "validatorId")]
    validator_id: String,
    #[serde(rename = "stakeWeight")]
    stake_weight: String,
    #[serde(rename = "publicKeyHex")]
    public_key_hex: String,
    #[serde(rename = "isActive")]
    is_active: bool,
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
impl DagRpcValidatorIdentityWire {
    fn into_validator_identity(self) -> anyhow::Result<misaka_types::validator::ValidatorIdentity> {
        use misaka_types::validator::{ValidatorIdentity, ValidatorPublicKey};

        let validator_id_vec = hex::decode(&self.validator_id)?;
        if validator_id_vec.len() != 32 {
            anyhow::bail!(
                "invalid validator id length from RPC peer: expected 32 bytes, got {}",
                validator_id_vec.len()
            );
        }

        let mut validator_id = [0u8; 32];
        validator_id.copy_from_slice(&validator_id_vec);

        let public_key_bytes = hex::decode(&self.public_key_hex)?;
        let public_key = ValidatorPublicKey::from_bytes(&public_key_bytes)
            .map_err(|e| anyhow::anyhow!("invalid validator public key from RPC peer: {}", e))?;
        let stake_weight = self
            .stake_weight
            .parse::<u128>()
            .map_err(|e| anyhow::anyhow!("invalid validator stake weight from RPC peer: {}", e))?;

        Ok(ValidatorIdentity {
            validator_id,
            stake_weight,
            public_key,
            is_active: self.is_active,
        })
    }
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
#[derive(Debug, Default, serde::Deserialize)]
struct DagRpcValidatorAttestationWire {
    #[serde(rename = "localValidator")]
    local_validator: Option<DagRpcValidatorIdentityWire>,
    #[serde(rename = "knownValidators", default)]
    known_validators: Vec<DagRpcValidatorIdentityWire>,
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
#[derive(Debug, Default, serde::Deserialize)]
struct DagRpcChainInfoWire {
    #[serde(rename = "validatorAttestation", default)]
    validator_attestation: DagRpcValidatorAttestationWire,
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
fn validator_identity_matches(
    left: &misaka_types::validator::ValidatorIdentity,
    right: &misaka_types::validator::ValidatorIdentity,
) -> bool {
    left.validator_id == right.validator_id
        && left.stake_weight == right.stake_weight
        && left.is_active == right.is_active
        && left.public_key.bytes == right.public_key.bytes
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
fn merge_discovered_checkpoint_validators(
    state: &mut misaka_dag::DagNodeState,
    identities: Vec<misaka_types::validator::ValidatorIdentity>,
) -> anyhow::Result<bool> {
    let mut changed = false;

    for identity in identities {
        let validator_id = identity.validator_id;
        let before = state
            .known_validators
            .iter()
            .find(|existing| existing.validator_id == validator_id)
            .cloned();
        register_experimental_checkpoint_validator(state, identity)?;
        let after = state
            .known_validators
            .iter()
            .find(|existing| existing.validator_id == validator_id)
            .cloned();

        changed |= match (before.as_ref(), after.as_ref()) {
            (None, Some(_)) => true,
            (Some(before), Some(after)) => !validator_identity_matches(before, after),
            _ => false,
        };
    }

    Ok(changed)
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
async fn discover_checkpoint_validators_from_rpc_peers(
    peers: &[String],
) -> Vec<misaka_types::validator::ValidatorIdentity> {
    use std::collections::BTreeMap;

    if peers.is_empty() {
        return Vec::new();
    }

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            warn!("Failed to build DAG validator discovery client: {}", e);
            return Vec::new();
        }
    };

    let mut discovered = BTreeMap::<[u8; 32], misaka_types::validator::ValidatorIdentity>::new();

    for peer in peers {
        let endpoint = format!("{}/api/get_chain_info", peer);
        let response = match client
            .post(&endpoint)
            .json(&serde_json::json!({}))
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                debug!(
                    "DAG validator discovery skipped peer {}: request failed: {}",
                    endpoint, e
                );
                continue;
            }
        };

        let body = match response.json::<DagRpcChainInfoWire>().await {
            Ok(body) => body,
            Err(e) => {
                debug!(
                    "DAG validator discovery skipped peer {}: decode failed: {}",
                    endpoint, e
                );
                continue;
            }
        };

        let attestation = body.validator_attestation;
        let mut candidates = attestation.known_validators;
        if let Some(local) = attestation.local_validator {
            candidates.push(local);
        }

        for candidate in candidates {
            match candidate.into_validator_identity() {
                Ok(identity) => {
                    discovered.insert(identity.validator_id, identity);
                }
                Err(e) => {
                    debug!(
                        "DAG validator discovery ignored malformed identity from {}: {}",
                        endpoint, e
                    );
                }
            }
        }
    }

    discovered.into_values().collect()
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
fn local_vote_gossip_payload(
    state: &misaka_dag::DagNodeState,
) -> Option<(
    misaka_types::validator::DagCheckpointVote,
    misaka_types::validator::ValidatorIdentity,
    Vec<String>,
)> {
    let vote = state.latest_checkpoint_vote.clone()?;
    let local_validator = state.local_validator.as_ref()?;
    if state.attestation_rpc_peers.is_empty() {
        return None;
    }
    let current_target = state
        .latest_checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.validator_target())?;
    if vote.target != current_target {
        return None;
    }
    Some((
        vote,
        local_validator.identity.clone(),
        state.attestation_rpc_peers.clone(),
    ))
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
fn maybe_spawn_local_vote_gossip(state: &misaka_dag::DagNodeState) {
    if let Some((vote, identity, peers)) = local_vote_gossip_payload(state) {
        tokio::spawn(async move {
            gossip_checkpoint_vote_to_peers(peers, vote, identity).await;
        });
    }
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
async fn gossip_checkpoint_vote_to_peers(
    peers: Vec<String>,
    vote: misaka_types::validator::DagCheckpointVote,
    validator_identity: misaka_types::validator::ValidatorIdentity,
) {
    if peers.is_empty() {
        return;
    }

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(client) => client,
        Err(e) => {
            warn!("Failed to build DAG attestation gossip client: {}", e);
            return;
        }
    };

    let payload = serde_json::json!({
        "vote": vote,
        "validator_identity": validator_identity,
    });

    for peer in peers {
        let endpoint = format!("{}/api/submit_checkpoint_vote", peer);
        match client.post(&endpoint).json(&payload).send().await {
            Ok(resp) => match resp.json::<serde_json::Value>().await {
                Ok(body) => {
                    let accepted = body["accepted"].as_bool().unwrap_or(false);
                    if accepted {
                        info!(
                            "Gossiped DAG checkpoint vote to {} | score={}",
                            endpoint, body["target"]["blueScore"]
                        );
                    } else {
                        warn!(
                            "DAG checkpoint vote rejected by {}: {}",
                            endpoint,
                            body["error"].as_str().unwrap_or("unknown error")
                        );
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to decode DAG checkpoint gossip response from {}: {}",
                        endpoint, e
                    );
                }
            },
            Err(e) => {
                warn!(
                    "Failed to gossip DAG checkpoint vote to {}: {}",
                    endpoint, e
                );
            }
        }
    }
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
fn prune_checkpoint_attestation_state(state: &mut misaka_dag::DagNodeState) {
    let Some(current_target) = state
        .latest_checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.validator_target())
    else {
        state.latest_checkpoint_vote = None;
        state.latest_checkpoint_finality = None;
        state.checkpoint_vote_pool.clear();
        return;
    };

    state
        .checkpoint_vote_pool
        .retain(|target, _| *target == current_target);

    if state
        .latest_checkpoint_vote
        .as_ref()
        .map(|vote| vote.target != current_target)
        .unwrap_or(false)
    {
        state.latest_checkpoint_vote = None;
    }

    if state
        .latest_checkpoint_finality
        .as_ref()
        .map(|proof| proof.target != current_target)
        .unwrap_or(false)
    {
        state.latest_checkpoint_finality = None;
    }
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
fn checkpoint_rollover_blocked_by_pending_finality(state: &misaka_dag::DagNodeState) -> bool {
    let Some(current_target) = state
        .latest_checkpoint
        .as_ref()
        .map(|checkpoint| checkpoint.validator_target())
    else {
        return false;
    };

    // Validators should not roll to a newer checkpoint target until the
    // current target has reached local finality. Otherwise peers can keep
    // pruning each other's votes as stale and never accumulate quorum.
    if state.local_validator.is_none() {
        return false;
    }

    !state
        .latest_checkpoint_finality
        .as_ref()
        .map(|proof| proof.target == current_target)
        .unwrap_or(false)
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
fn register_experimental_checkpoint_validator(
    state: &mut misaka_dag::DagNodeState,
    identity: misaka_types::validator::ValidatorIdentity,
) -> anyhow::Result<()> {
    let normalized = normalize_experimental_validator_identity(&identity)?;

    if let Some(existing) = state
        .known_validators
        .iter_mut()
        .find(|existing| existing.validator_id == normalized.validator_id)
    {
        *existing = normalized;
        return Ok(());
    }

    let max_validators = state.validator_count.max(1);
    if state.known_validators.len() >= max_validators {
        anyhow::bail!(
            "validator registry full: known={}, max={}",
            state.known_validators.len(),
            max_validators
        );
    }

    state.known_validators.push(normalized);
    state
        .known_validators
        .sort_by(|a, b| a.validator_id.cmp(&b.validator_id));
    Ok(())
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
fn recompute_latest_checkpoint_finality(
    state: &mut misaka_dag::DagNodeState,
) -> anyhow::Result<()> {
    use misaka_consensus::verify_dag_checkpoint_finality;
    use misaka_types::validator::DagCheckpointFinalityProof;

    prune_checkpoint_attestation_state(state);
    state.latest_checkpoint_finality = None;

    let checkpoint = match &state.latest_checkpoint {
        Some(checkpoint) => checkpoint,
        None => return Ok(()),
    };
    let target = checkpoint.validator_target();
    let commits = state
        .checkpoint_vote_pool
        .get(&target)
        .cloned()
        .unwrap_or_default();
    if commits.is_empty() || state.known_validators.len() < state.validator_count.max(1) {
        return Ok(());
    }

    let proof = DagCheckpointFinalityProof { target, commits };
    let validator_set = dag_validator_set(state);
    if verify_dag_checkpoint_finality(&validator_set, &proof).is_ok() {
        state.latest_checkpoint_finality = Some(proof);
    }

    Ok(())
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
pub(crate) fn ingest_checkpoint_vote(
    state: &mut misaka_dag::DagNodeState,
    vote: misaka_types::validator::DagCheckpointVote,
    validator_identity: Option<misaka_types::validator::ValidatorIdentity>,
) -> anyhow::Result<()> {
    use misaka_consensus::verify_dag_checkpoint_vote;
    let had_validator_identity = validator_identity.is_some();

    prune_checkpoint_attestation_state(state);
    let checkpoint = state
        .latest_checkpoint
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no latest checkpoint available"))?;
    let expected_target = checkpoint.validator_target();
    if vote.target != expected_target {
        anyhow::bail!(
            "checkpoint vote target mismatch: expected_score={}, got_score={}",
            expected_target.blue_score,
            vote.target.blue_score
        );
    }

    if let Some(identity) = validator_identity {
        if identity.validator_id != vote.voter {
            anyhow::bail!(
                "validator identity mismatch for vote: identity={}, vote={}",
                hex::encode(identity.validator_id),
                hex::encode(vote.voter)
            );
        }
        register_experimental_checkpoint_validator(state, identity)?;
    }

    if !state
        .known_validators
        .iter()
        .any(|validator| validator.validator_id == vote.voter)
    {
        anyhow::bail!(
            "unknown checkpoint voter {}; provide validator identity first",
            hex::encode(vote.voter)
        );
    }

    let validator_set = dag_validator_set(state);
    verify_dag_checkpoint_vote(&validator_set, &vote)
        .map_err(|e| anyhow::anyhow!("checkpoint vote verification failed: {}", e))?;

    let commits = state
        .checkpoint_vote_pool
        .entry(vote.target.clone())
        .or_default();
    if commits.iter().any(|existing| existing.voter == vote.voter) {
        return Ok(());
    }
    commits.push(vote);
    commits.sort_by(|a, b| a.voter.cmp(&b.voter));

    recompute_latest_checkpoint_finality(state)?;
    if had_validator_identity {
        maybe_spawn_local_vote_gossip(state);
    }
    Ok(())
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
pub(crate) fn make_local_checkpoint_vote(
    local_validator: &misaka_dag::LocalDagValidator,
    checkpoint: &misaka_dag::DagCheckpoint,
) -> anyhow::Result<misaka_types::validator::DagCheckpointVote> {
    use misaka_crypto::validator_sig::validator_sign;
    use misaka_types::validator::{DagCheckpointVote, ValidatorSignature};

    let target = checkpoint.validator_target();
    let stub = DagCheckpointVote {
        voter: local_validator.identity.validator_id,
        target,
        signature: ValidatorSignature { bytes: vec![] },
    };
    let sig = validator_sign(&stub.signing_bytes(), &local_validator.keypair.secret_key)
        .map_err(|e| anyhow::anyhow!("failed to sign DAG checkpoint vote: {}", e))?;
    Ok(DagCheckpointVote {
        signature: ValidatorSignature {
            bytes: sig.to_bytes(),
        },
        ..stub
    })
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
pub(crate) fn refresh_local_checkpoint_attestation(
    state: &mut misaka_dag::DagNodeState,
) -> anyhow::Result<()> {
    let (identity, vote) = match (&state.local_validator, &state.latest_checkpoint) {
        (Some(local_validator), Some(checkpoint)) => (
            local_validator.identity.clone(),
            make_local_checkpoint_vote(local_validator, checkpoint)?,
        ),
        _ => {
            state.latest_checkpoint_vote = None;
            state.latest_checkpoint_finality = None;
            return Ok(());
        }
    };

    register_experimental_checkpoint_validator(state, identity)?;
    state.latest_checkpoint_vote = Some(vote.clone());
    ingest_checkpoint_vote(state, vote, None)
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
async fn start_dag_node(
    cli: Cli,
    node_mode: NodeMode,
    role: NodeRole,
    _p2p_config: P2pConfig,
    loaded_config: Option<misaka_config::NodeConfig>,
) -> anyhow::Result<()> {
    // SEC-FIX: Block ghostdag-compat on mainnet.
    // The GhostDAG compatibility path is the legacy runtime (pre-Narwhal).
    // It uses serde_json TX deserialization (vs borsh in Narwhal), has privacy
    // endpoint remnants, and lacks many security fixes applied to Narwhal path.
    // Mainnet MUST use the Narwhal/Bullshark runtime (start_narwhal_node).
    if cli.chain_id == 1 {
        anyhow::bail!(
            "FATAL: ghostdag-compat mode is not supported on mainnet (chain_id=1). \
             Use the default Narwhal/Bullshark runtime. \
             Remove the ghostdag-compat feature flag from the build."
        );
    }

    // Extract guard config before the p2p_config is consumed
    let guard_config = _p2p_config.guard.clone();
    use misaka_dag::{
        dag_block_producer::run_dag_block_producer_dual, dag_finality::FinalityManager,
        dag_store::ThreadSafeDagStore, load_runtime_snapshot, save_runtime_snapshot, DagMempool,
        DagNodeState, DagStateManager, DagStore, GhostDagEngine, ZERO_HASH,
    };
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    // ══════════════════════════════════════════════════════
    //  DAG Consensus — Production Mode
    //
    //  Known limitations (tracked for mainnet):
    //  - DAG-native wallet / explorer integration in progress
    //  - Finality checkpoints persisted inside local runtime snapshot
    //
    //  Testnet operation:
    //  - JSON snapshot restore + periodic save implemented
    //  - P2P DAG relay + IBD pipeline operational
    // ══════════════════════════════════════════════════════

    info!("╔═══════════════════════════════════════════════════════════╗");
    info!("║  MISAKA Network — DAG Consensus (GhostDAG)              ║");
    info!("╚═══════════════════════════════════════════════════════════╝");

    let snapshot_path: PathBuf =
        std::path::Path::new(&cli.data_dir).join("dag_runtime_snapshot.json");
    let validator_lifecycle_path =
        validator_lifecycle_snapshot_path(std::path::Path::new(&cli.data_dir), cli.chain_id);
    let runtime_recovery_observation =
        Arc::new(RwLock::new(dag_rpc::DagRuntimeRecoveryObservation::new(
            snapshot_path.clone(),
            validator_lifecycle_path.clone(),
            std::path::Path::new(&cli.data_dir).join("dag_wal.journal"),
            std::path::Path::new(&cli.data_dir).join("dag_wal.journal.tmp"),
        )));
    if let Err(e) = std::fs::create_dir_all(&cli.data_dir) {
        anyhow::bail!("failed to create data dir '{}': {}", cli.data_dir, e);
    }
    let local_validator = load_or_create_local_dag_validator(
        std::path::Path::new(&cli.data_dir),
        role,
        cli.validator_index,
        cli.chain_id,
    )?;
    let attestation_rpc_peers = normalize_dag_rpc_peers(&cli.dag_rpc_peers);
    let genesis_path = resolve_genesis_committee_path(cli.genesis_path.as_deref());
    let manifest = crate::genesis_committee::GenesisCommitteeManifest::load(&genesis_path)?;
    let genesis_bootstrap_known_validators = if cli.chain_id == 1 {
        Vec::new()
    } else {
        manifest.bootstrap_validator_identities(cli.chain_id)?
    };
    let genesis_bootstrap_runtime_active_sr_validator_ids = genesis_bootstrap_known_validators
        .iter()
        .take(misaka_types::constants::NUM_SUPER_REPRESENTATIVES)
        .map(|validator| validator.validator_id)
        .collect::<Vec<_>>();
    let parsed_seeds: Vec<misaka_types::seed_entry::SeedEntry> = if cli.seeds.is_empty() {
        vec![]
    } else if cli.seed_pubkeys.is_empty() {
        anyhow::bail!(
            "FATAL: --seeds provided ({}) but --seed-pubkeys is empty. \
             The committee relay handshake is PK-pinned; there is no TOFU mode.",
            cli.seeds.len()
        );
    } else if cli.seed_pubkeys.len() != cli.seeds.len() {
        anyhow::bail!(
            "FATAL: --seed-pubkeys count ({}) != --seeds count ({}). \
             Each seed requires a corresponding pubkey in the same order.",
            cli.seed_pubkeys.len(),
            cli.seeds.len()
        );
    } else {
        cli.seeds
            .iter()
            .zip(cli.seed_pubkeys.iter())
            .map(|(addr, pk)| misaka_types::seed_entry::SeedEntry {
                address: addr.clone(),
                transport_pubkey: pk.clone(),
            })
            .collect()
    };

    // γ-2.5 / γ-3: bootstrap StakingRegistry via the shared extraction.
    // Behavior matches the pre-γ-2.5 inline dag path (seed_on_fresh=true,
    // log_prefix="Layer 6"). γ-3 adds a process-wide `Arc<StakingConfig>`
    // that is threaded through to downstream consumers.
    // Group 1: same config glue helper as the narwhal path above.
    // Option A: `loaded_config` threaded in via function parameter.
    let staking_config: Arc<misaka_consensus::staking::StakingConfig> = Arc::new(
        crate::staking_config_builder::build_staking_config_for_chain(
            cli.chain_id,
            loaded_config.as_ref(),
        ),
    );
    tracing::info!(
        "StakingConfig[dag]: chain_id={}, unbonding_epochs={}, min_stake={}, max_validators={}, nodeconfig={}",
        cli.chain_id,
        staking_config.unbonding_epochs,
        staking_config.min_validator_stake,
        staking_config.max_active_validators,
        if loaded_config.is_some() { "provided" } else { "none" },
    );
    let lifecycle_bootstrap = crate::validator_lifecycle_bootstrap::bootstrap_validator_lifecycle(
        std::path::Path::new(&cli.data_dir),
        cli.chain_id,
        staking_config.clone(),
        &genesis_path,
        "Layer 6",
        /* seed_on_fresh = */ true,
    )
    .await?;
    let validator_lifecycle_store = lifecycle_bootstrap.store;
    let validator_registry = lifecycle_bootstrap.registry;
    // γ-3.1: dag path uses misaka_dag::DagMempool (different mempool type
    // than narwhal_consensus::NarwhalMempoolIngress), which does not yet
    // carry StakingConfig. This binding stays underscore-prefixed until the
    // DagMempool admit path is γ-3.1-equivalent (separate follow-up; misaka-mempool
    // vs misaka-dag are independent crates with parallel admission pipelines).
    let _staking_config_arc = lifecycle_bootstrap.staking_config;
    let restored_epoch = lifecycle_bootstrap.current_epoch;
    let restored_epoch_progress = lifecycle_bootstrap.epoch_progress;

    // ── Extract PQ transport keys before local_validator is moved into DagNodeState ──
    let transport_keys: Option<(
        misaka_crypto::validator_sig::ValidatorPqPublicKey,
        misaka_crypto::validator_sig::ValidatorPqSecretKey,
    )> = local_validator
        .as_ref()
        .map(|lv| (lv.keypair.public_key.clone(), lv.keypair.secret_key.clone()));

    // ══════════════════════════════════════════════════════
    //  Banner
    // ══════════════════════════════════════════════════════

    info!("╔═══════════════════════════════════════════════════════════╗");
    info!("║  MISAKA Network v2.0.0-alpha — Privacy BlockDAG (DAG)  ║");
    info!(
        "║  Consensus: GhostDAG (k={})                             ║",
        cli.dag_k
    );
    info!("╚═══════════════════════════════════════════════════════════╝");

    let mode_label = match node_mode {
        NodeMode::Public => "🌐 PUBLIC  — accepts inbound, advertises IP",
        NodeMode::Hidden => "🔒 HIDDEN  — outbound only, IP never advertised",
        NodeMode::Seed => "🌱 SEED    — bootstrap node, peer discovery",
    };
    info!("Mode: {}", mode_label);
    info!(
        "Role: {} (block production {})",
        role,
        if role.produces_blocks() {
            "ENABLED"
        } else {
            "disabled"
        }
    );
    if !attestation_rpc_peers.is_empty() {
        info!(
            "Layer 5: experimental DAG attestation gossip peers = {}",
            attestation_rpc_peers.join(", ")
        );
    }

    // ══════════════════════════════════════════════════════
    //  Layer 1: Storage & State (基盤層)
    // ══════════════════════════════════════════════════════

    // ── 1a. Restore from snapshot if available, otherwise bootstrap genesis ──
    let (
        dag_store,
        utxo_set,
        state_manager,
        latest_checkpoint,
        known_validators,
        runtime_active_sr_validator_ids,
        latest_checkpoint_vote,
        latest_checkpoint_finality,
        checkpoint_vote_pool,
        genesis_hash,
    ) = match load_runtime_snapshot(&snapshot_path, 1000) {
        Ok(Some(restored)) => {
            {
                let mut recovery = runtime_recovery_observation.write().await;
                recovery.mark_startup_snapshot_restored(true);
            }
            info!(
                "Layer 1: restored DAG runtime snapshot | genesis={} | height={}",
                hex::encode(&restored.genesis_hash[..8]),
                restored.utxo_set.height,
            );
            if let Some(cp) = restored.latest_checkpoint.as_ref() {
                info!(
                    "Layer 1: restored latest checkpoint | score={} | block={}",
                    cp.blue_score,
                    hex::encode(&cp.block_hash[..8]),
                );
            }
            (
                Arc::new(restored.dag_store),
                restored.utxo_set,
                restored.state_manager,
                restored.latest_checkpoint,
                restored.known_validators,
                restored.runtime_active_sr_validator_ids,
                restored.latest_checkpoint_vote,
                restored.latest_checkpoint_finality,
                restored.checkpoint_vote_pool,
                restored.genesis_hash,
            )
        }
        Ok(None) => {
            {
                let mut recovery = runtime_recovery_observation.write().await;
                recovery.mark_startup_snapshot_restored(false);
            }
            let utxo_set = misaka_storage::utxo_set::UtxoSet::new(1000);
            info!("Layer 1: UtxoSet initialized (max_delta_history=1000)");

            let genesis_header = deterministic_dag_genesis_header(cli.chain_id);
            let genesis_hash = genesis_header.compute_hash();
            let dag_store = Arc::new(ThreadSafeDagStore::new(genesis_hash, genesis_header));
            let state_manager = DagStateManager::new(HashSet::new(), HashSet::new());

            if let Err(e) = save_runtime_snapshot(
                &snapshot_path,
                &dag_store,
                &utxo_set,
                &state_manager.stats,
                None,
                &[],
                &[],
                None,
                None,
                &std::collections::HashMap::new(),
            ) {
                warn!("Failed to persist initial DAG snapshot: {}", e);
            }

            info!(
                "Layer 1: DAG Store initialized | genesis={}",
                hex::encode(&genesis_hash[..8])
            );
            (
                dag_store,
                utxo_set,
                state_manager,
                None,
                Vec::new(),
                Vec::new(),
                None,
                None,
                std::collections::HashMap::new(),
                genesis_hash,
            )
        }
        Err(e) => anyhow::bail!("failed to load DAG runtime snapshot: {}", e),
    };

    let mut known_validators: Vec<misaka_types::validator::ValidatorIdentity> = known_validators;
    let mut runtime_active_sr_validator_ids: Vec<[u8; 32]> = runtime_active_sr_validator_ids;
    let mut seeded_known_validators_from_genesis = false;

    if known_validators.is_empty() && !genesis_bootstrap_known_validators.is_empty() {
        info!(
            "Layer 1 / Phase C: seeding validator registry from genesis committee | validators={} | chain_id={}",
            genesis_bootstrap_known_validators.len(),
            cli.chain_id
        );
        known_validators = genesis_bootstrap_known_validators.clone();
        seeded_known_validators_from_genesis = true;
    }

    if runtime_active_sr_validator_ids.is_empty() && !known_validators.is_empty() {
        if seeded_known_validators_from_genesis {
            runtime_active_sr_validator_ids =
                genesis_bootstrap_runtime_active_sr_validator_ids.clone();
            info!(
                "Layer 1 / Phase C: seeding runtime active SR set from genesis committee | active={} | min_stake={}",
                runtime_active_sr_validator_ids.len(),
                sr21_election::effective_min_sr_stake(cli.chain_id),
            );
        } else {
            let bootstrap_election = sr21_election::run_election_for_chain(
                &known_validators,
                cli.chain_id,
                manifest.epoch,
            );
            runtime_active_sr_validator_ids = bootstrap_election
                .active_srs
                .iter()
                .map(|elected| elected.validator_id)
                .collect();
            info!(
                "Layer 1 / Phase C: seeding runtime active SR set from restored validator registry | active={} | min_stake={}",
                runtime_active_sr_validator_ids.len(),
                sr21_election::effective_min_sr_stake(cli.chain_id),
            );
        }
    }

    let initial_sr_index = local_validator
        .as_ref()
        .and_then(|validator| {
            runtime_active_sr_validator_ids
                .iter()
                .position(|validator_id| *validator_id == validator.identity.validator_id)
        })
        .unwrap_or(cli.validator_index);
    let initial_num_active_srs = runtime_active_sr_validator_ids.len().max(1);

    // ══════════════════════════════════════════════════════
    //  Layer 2: Consensus & Finality (合意形成層)
    // ══════════════════════════════════════════════════════

    // ── 2a. GhostDAG エンジン ──
    let ghostdag = GhostDagEngine::new(cli.dag_k, genesis_hash);
    let mut reachability = misaka_dag::reachability::ReachabilityStore::new(genesis_hash);

    // ── 2a-fix: チェックポイント復元時に reachability tree を再構築 ──
    //
    // ReachabilityStore はシリアライズされないため、スナップショット復元後は
    // genesis のみが tree に存在する。dag_store に残っている全ブロックの
    // selected_parent → child 関係を blue_score 昇順で再挿入する。
    {
        let snap = dag_store.snapshot();
        let all = snap.all_hashes();
        if all.len() > 1 {
            // blue_score でトポロジカルソート（genesis が最小）
            let mut blocks_with_score: Vec<([u8; 32], u64)> = all
                .iter()
                .filter(|h| **h != genesis_hash)
                .filter_map(|h| snap.get_ghostdag_data(h).map(|gd| (*h, gd.blue_score)))
                .collect();
            blocks_with_score.sort_by_key(|&(_, score)| score);

            let mut rebuilt = 0usize;
            let mut skipped = 0usize;
            for (hash, _score) in &blocks_with_score {
                if let Some(gd) = snap.get_ghostdag_data(hash) {
                    let sp = gd.selected_parent;
                    if sp != ZERO_HASH {
                        match reachability.add_child(sp, *hash) {
                            Ok(()) => rebuilt += 1,
                            Err(_) => skipped += 1,
                        }
                    }
                }
            }
            if rebuilt > 0 {
                info!(
                    "Layer 2: rebuilt reachability tree from snapshot ({} blocks, {} skipped)",
                    rebuilt, skipped
                );
            }
        }
    }

    info!(
        "Layer 2: GhostDAG engine initialized (k={}, genesis={})",
        cli.dag_k,
        hex::encode(&genesis_hash[..8])
    );

    // ── 2b. Finality マネージャ ──
    let _finality_manager = FinalityManager::new(cli.dag_checkpoint_interval);
    info!(
        "Layer 2: Finality manager initialized (checkpoint_interval={})",
        cli.dag_checkpoint_interval
    );

    // ══════════════════════════════════════════════════════
    //  Layer 3: Execution (遅延状態評価層)
    // ══════════════════════════════════════════════════════

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
        use sha3::{Digest, Sha3_256};
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

    let known_block_hashes: HashSet<_> = dag_store.snapshot().all_hashes().into_iter().collect();

    let dag_node_state = DagNodeState {
        dag_store: dag_store.clone(),
        ghostdag,
        state_manager,
        utxo_set,
        virtual_state: misaka_dag::VirtualState::new(genesis_hash),
        ingestion_pipeline: misaka_dag::IngestionPipeline::new(known_block_hashes),
        quarantined_blocks: std::collections::HashSet::new(),
        mempool,
        chain_id: cli.chain_id,
        validator_count: cli.validators,
        known_validators,
        proposer_id,
        sr_index: initial_sr_index,
        num_active_srs: initial_num_active_srs,
        runtime_active_sr_validator_ids,
        local_validator,
        genesis_hash,
        snapshot_path: snapshot_path.clone(),
        latest_checkpoint,
        latest_checkpoint_vote,
        latest_checkpoint_finality,
        checkpoint_vote_pool,
        attestation_rpc_peers,
        blocks_produced: 0,
        reachability,
        persistent_backend: None, // Set below after RocksDB initialization
        faucet_cooldowns: std::collections::HashMap::new(),
        pending_transactions: std::collections::HashMap::new(),
    };
    #[allow(unused_mut)]
    let mut dag_node_state = dag_node_state;

    // ── 1b. RocksDB Persistent Backend (optional, feature-gated) ──
    #[cfg(feature = "rocksdb")]
    {
        use misaka_dag::persistent_store::{PersistentDagBackend, RocksDbDagStore};

        let rocks_path = std::path::Path::new(&cli.data_dir).join("dag_rocksdb");
        match RocksDbDagStore::open(&rocks_path, genesis_hash, {
            // Re-create genesis header for RocksDB init (idempotent if already exists)
            let snapshot = dag_node_state.dag_store.snapshot();
            snapshot
                .get_header(&genesis_hash)
                .cloned()
                .unwrap_or_else(|| deterministic_dag_genesis_header(cli.chain_id))
        }) {
            Ok(rocks) => {
                let rocks = Arc::new(rocks);

                // Migration: if RocksDB has only genesis but in-memory has more blocks,
                // import the in-memory dump into RocksDB.
                let rocks_count = rocks.block_count();
                let mem_count = dag_node_state.dag_store.block_count();
                if rocks_count <= 1 && mem_count > 1 {
                    info!(
                        "Layer 1: Migrating {} blocks from in-memory store to RocksDB...",
                        mem_count,
                    );
                    let dump = dag_node_state.dag_store.export_dump();
                    if let Err(e) =
                        misaka_dag::persistent_store::import_from_memory_dump(&rocks, &dump)
                    {
                        error!(
                            "RocksDB migration failed: {} — continuing with in-memory only",
                            e
                        );
                    } else {
                        info!("Layer 1: RocksDB migration complete ({} blocks)", mem_count);
                    }
                }

                dag_node_state.persistent_backend = Some(rocks);
                info!(
                    "Layer 1: RocksDB persistent backend opened at {} ({} blocks)",
                    rocks_path.display(),
                    dag_node_state
                        .persistent_backend
                        .as_ref()
                        .map(|r| r.block_count())
                        .unwrap_or(0),
                );
            }
            Err(e) => {
                error!(
                    "Layer 1: RocksDB open failed: {} — falling back to in-memory + JSON snapshot",
                    e,
                );
                // persistent_backend remains None — node continues with in-memory store
            }
        }
    }

    #[cfg(not(feature = "rocksdb"))]
    {
        info!("Layer 1: RocksDB feature not enabled — using in-memory store + JSON snapshot");
    }

    let shared_state: Arc<RwLock<DagNodeState>> = Arc::new(RwLock::new(dag_node_state));
    info!("DI wiring complete — all layers bound to DagNodeState");
    info!("Narwhal dissemination shadow ingress service ready");

    // ══════════════════════════════════════════════════════
    //  Layer 5: Network (DAG P2P)
    // ══════════════════════════════════════════════════════

    // ── 5a. Crash-Safe Recovery: WAL scan + discard incomplete ──
    {
        use misaka_storage::dag_recovery;
        let data_dir = std::path::Path::new(&cli.data_dir);
        let recovery = dag_recovery::bootstrap(data_dir, 1000);
        match recovery {
            dag_recovery::DagRecoveryResult::Recovered { rolled_back, .. } => {
                {
                    let mut recovery = runtime_recovery_observation.write().await;
                    recovery.mark_startup_wal_state("recovered", rolled_back);
                }
                if rolled_back > 0 {
                    warn!(
                        "Layer 5: DAG recovery rolled back {} incomplete block(s) from WAL",
                        rolled_back
                    );
                } else {
                    info!("Layer 5: DAG recovery — WAL clean, no incomplete blocks");
                }
            }
            dag_recovery::DagRecoveryResult::Fresh => {
                {
                    let mut recovery = runtime_recovery_observation.write().await;
                    recovery.mark_startup_wal_state("fresh", 0);
                }
                info!("Layer 5: DAG recovery — fresh start (no WAL)");
            }
            dag_recovery::DagRecoveryResult::Failed { reason } => {
                {
                    let mut recovery = runtime_recovery_observation.write().await;
                    recovery.mark_startup_wal_state("failed", 0);
                }
                error!("Layer 5: DAG recovery FAILED: {}", reason);
                error!("Node cannot start safely. Delete data dir and resync.");
                std::process::exit(1);
            }
        }

        if let Err(e) = dag_recovery::compact_wal_after_recovery(data_dir) {
            warn!("Layer 5: DAG recovery cleanup skipped: {}", e);
        }
    }

    // Refresh and gossip checkpoint attestation only after crash recovery has
    // settled the DAG view, so we never rebroadcast a vote against a stale
    // pre-recovery checkpoint target.
    {
        let startup_gossip = {
            let mut guard = shared_state.write().await;
            prune_checkpoint_attestation_state(&mut guard);
            if let Err(e) = refresh_local_checkpoint_attestation(&mut guard) {
                warn!(
                    "Failed to refresh local checkpoint attestation on startup: {}",
                    e
                );
            }
            local_vote_gossip_payload(&guard)
        };

        if let Some((vote, identity, peers)) = startup_gossip {
            tokio::spawn(async move {
                gossip_checkpoint_vote_to_peers(peers, vote, identity).await;
            });
        }
    }
    {
        let state = shared_state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                let peers = {
                    let guard = state.read().await;
                    guard.attestation_rpc_peers.clone()
                };
                if peers.is_empty() {
                    continue;
                }

                let discovered = discover_checkpoint_validators_from_rpc_peers(&peers).await;
                if discovered.is_empty() {
                    continue;
                }

                let follow_up = {
                    let mut guard = state.write().await;
                    match merge_discovered_checkpoint_validators(&mut guard, discovered) {
                        Ok(false) => None,
                        Ok(true) => {
                            if let Err(e) = recompute_latest_checkpoint_finality(&mut guard) {
                                warn!(
                                    "Failed to recompute checkpoint finality after validator discovery: {}",
                                    e
                                );
                            }
                            if guard.local_validator.is_some() && guard.latest_checkpoint.is_some()
                            {
                                if let Err(e) = refresh_local_checkpoint_attestation(&mut guard) {
                                    warn!(
                                        "Failed to refresh local checkpoint attestation after validator discovery: {}",
                                        e
                                    );
                                }
                            }
                            if let Err(e) = save_runtime_snapshot(
                                &guard.snapshot_path,
                                &guard.dag_store,
                                &guard.utxo_set,
                                &guard.state_manager.stats,
                                guard.latest_checkpoint.as_ref(),
                                &guard.known_validators,
                                &guard.runtime_active_sr_validator_ids,
                                guard.latest_checkpoint_vote.as_ref(),
                                guard.latest_checkpoint_finality.as_ref(),
                                &guard.checkpoint_vote_pool,
                            ) {
                                warn!(
                                    "Failed to persist DAG snapshot after validator discovery: {}",
                                    e
                                );
                            }
                            local_vote_gossip_payload(&guard)
                        }
                        Err(e) => {
                            warn!("Failed to merge discovered DAG validators: {}", e);
                            None
                        }
                    }
                };

                if let Some((vote, identity, peers)) = follow_up {
                    gossip_checkpoint_vote_to_peers(peers, vote, identity).await;
                }
            }
        });
    }
    {
        let state = shared_state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                let gossip = {
                    let mut guard = state.write().await;
                    if let Err(e) = refresh_local_checkpoint_attestation(&mut guard) {
                        warn!("Failed to refresh local checkpoint attestation: {}", e);
                        None
                    } else {
                        local_vote_gossip_payload(&guard)
                    }
                };

                if let Some((vote, identity, peers)) = gossip {
                    gossip_checkpoint_vote_to_peers(peers, vote, identity).await;
                }
            }
        });
    }

    // ── 5b. P2P Event Loop ──
    let (p2p_event_loop, p2p_inbound_tx, mut p2p_outbound_rx, dag_p2p_observation) =
        dag_p2p_network::DagP2pEventLoop::new(shared_state.clone(), cli.chain_id);

    // Spawn the P2P event loop
    let _p2p_handle = tokio::spawn(async move {
        p2p_event_loop.run().await;
    });

    // Spawn outbound message consumer.
    // ── STOP LINE REMOVED (v4 semantic finalization) ──
    // The outbound channel is now consumed by dag_p2p_transport::run_dag_p2p_transport,
    // which handles PQ-encrypted TCP connections with ML-KEM-768 + ML-DSA-65 handshake.
    //
    // If no transport keys are available (non-validator node), fall back to
    // observation-only mode (log outbound traffic without sending).
    let p2p_listen_addr: SocketAddr = format!("0.0.0.0:{}", cli.p2p_port).parse()?;

    // Parse seed peer addresses for outbound P2P connections
    let seed_addrs: Vec<SocketAddr> = cli
        .seeds
        .iter()
        .filter_map(|s| {
            s.parse::<SocketAddr>().ok().or_else(|| {
                warn!("Invalid seed address '{}' — skipping", s);
                None
            })
        })
        .collect();

    if let Some((transport_pk, transport_sk)) = transport_keys {
        let seed_count = seed_addrs.len();
        let transport_inbound_tx = p2p_inbound_tx.clone();
        let transport_observation = dag_p2p_observation.clone();
        let transport_state = shared_state.clone();
        let transport_node_name = cli.name.clone();
        let transport_guard_config = guard_config.clone();
        let _transport_handle = tokio::spawn(async move {
            dag_p2p_transport::run_dag_p2p_transport(
                p2p_listen_addr,
                transport_pk,
                transport_sk,
                transport_inbound_tx,
                p2p_outbound_rx,
                cli.chain_id,
                transport_node_name,
                node_mode,
                transport_state,
                seed_addrs,
                parsed_seeds.clone(),
                transport_observation,
                transport_guard_config,
            )
            .await;
        });
        info!(
            "Layer 5: DAG P2P PQ-encrypted transport on {} | seeds={} (ML-KEM-768 + ChaCha20-Poly1305)",
            p2p_listen_addr, seed_count,
        );
    } else {
        // Non-validator: observation-only outbound consumer
        let _outbound_handle = tokio::spawn(async move {
            while let Some(event) = p2p_outbound_rx.recv().await {
                let target = event
                    .peer_id
                    .map(|id| hex::encode(&id.0[..4]))
                    .unwrap_or_else(|| "broadcast".to_string());
                tracing::debug!(
                    "DAG P2P outbound → {} (no transport — observation only): {:?}",
                    target,
                    std::mem::discriminant(&event.message)
                );
            }
        });
        warn!("Layer 5: DAG P2P transport NOT started — no local validator keys");
    }

    info!(
        "Layer 5: DAG P2P event loop started (inbound_ch={}, outbound_ch={})",
        dag_p2p_network::INBOUND_CHANNEL_SIZE,
        dag_p2p_network::OUTBOUND_CHANNEL_SIZE,
    );

    // ══════════════════════════════════════════════════════
    //  Layer 6: RPC Server (DAG RPC)
    // ══════════════════════════════════════════════════════

    // SECURITY: default to localhost-only binding. Use --rpc-bind 0.0.0.0 for public.
    let rpc_addr: SocketAddr = format!("127.0.0.1:{}", cli.rpc_port).parse()?;
    let rpc_state = shared_state.clone();
    let rpc_observation = dag_p2p_observation.clone();
    let rpc_runtime_recovery = runtime_recovery_observation.clone();

    // ── Validator Staking Registry ──
    //
    // 0.9.0 β-1 / γ-2.5: the `registered_validators.json` → StakingRegistry
    // migration used to fire here. γ-2.5 moved it inside
    // `bootstrap_validator_lifecycle` (called far above, at the snapshot
    // load point) so that both narwhal + dag paths share the same order of
    // operations. `validator_registry` is already Arc<RwLock<_>>'d by the
    // bootstrap; only `current_epoch` and `epoch_progress` still need their
    // caller-specific lock shapes.
    let current_epoch: Arc<RwLock<u64>> = Arc::new(RwLock::new(restored_epoch));
    let epoch_progress: Arc<Mutex<validator_lifecycle_persistence::ValidatorEpochProgress>> =
        Arc::new(Mutex::new(restored_epoch_progress));
    info!(
        "Layer 6: Validator staking registry initialized (min_stake={})",
        if cli.chain_id == 1 {
            "10M MISAKA (mainnet)"
        } else {
            "1M MISAKA (testnet)"
        }
    );

    // ── SEC-STAKE: Auto-register local validator with stake proof from misakastake.com ──
    //
    // If --stake-signature is provided (from misakastake.com), the node:
    // 1. Calls Solana RPC to verify the TX (finalized, correct program, correct L1 key)
    // 2. Extracts the REAL staked amount from the on-chain event
    // 3. Registers with solana_stake_verified=true and the verified amount
    //
    // If Solana RPC is not configured, accepts the signature format-only (backward compat).
    {
        let local_validator_ref = shared_state.read().await;
        if let Some(ref lv) = local_validator_ref.local_validator {
            let validator_id = lv.identity.validator_id;
            let has_stake_sig = cli.stake_signature.is_some();
            drop(local_validator_ref);

            // R3-H2 FIX: Pre-fetch config with read lock before Solana RPC
            // to avoid holding write lock across external network calls.
            let (already_registered, min_validator_stake) = {
                let registry = validator_registry.read().await;
                (
                    registry.get(&validator_id).is_some(),
                    registry.config().min_validator_stake,
                )
            };
            let epoch = *current_epoch.read().await;

            if !already_registered {
                let shared_guard = shared_state.read().await;
                if let Some(lv) = shared_guard.local_validator.as_ref() {
                    let pubkey_bytes = lv.identity.public_key.bytes.clone();
                    let mut reward_address = [0u8; 32];
                    reward_address.copy_from_slice(&validator_id);
                    drop(shared_guard);

                    // Read L1 public key from key file (for Solana event matching)
                    let l1_pubkey_hex = {
                        let key_path =
                            std::path::Path::new(&cli.data_dir).join("l1-public-key.json");
                        if key_path.exists() {
                            let raw = std::fs::read_to_string(&key_path).unwrap_or_default();
                            let parsed: serde_json::Value =
                                serde_json::from_str(&raw).unwrap_or_default();
                            parsed["l1PublicKey"].as_str().unwrap_or("").to_string()
                        } else {
                            String::new()
                        }
                    };

                    // Determine stake amount and verification status
                    // (Solana RPC calls happen here WITHOUT holding registry lock)
                    let (stake_amount, stake_verified, stake_sig) = if let Some(ref sig) =
                        cli.stake_signature
                    {
                        let rpc_url = solana_stake_verify::solana_rpc_url();
                        let program_id = cli
                            .staking_program_id
                            .clone()
                            .unwrap_or_else(solana_stake_verify::staking_program_id);

                        if !rpc_url.is_empty()
                            && !program_id.is_empty()
                            && !l1_pubkey_hex.is_empty()
                        {
                            // Full on-chain verification
                            let min_stake = min_validator_stake;
                            match solana_stake_verify::verify_solana_stake(
                                &rpc_url,
                                sig,
                                &l1_pubkey_hex,
                                &program_id,
                                min_stake,
                            )
                            .await
                            {
                                Ok(verified) => {
                                    info!(
                                        "SEC-STAKE: On-chain verification SUCCESS — \
                                     amount={} l1_key={}... program={}",
                                        verified.amount,
                                        &verified.l1_public_key[..16],
                                        &verified.program_id[..16.min(verified.program_id.len())],
                                    );
                                    (verified.amount, true, Some(sig.clone()))
                                }
                                Err(e) => {
                                    error!(
                                        "SEC-STAKE: On-chain verification FAILED: {} — \
                                     validator will NOT be activated until verified. \
                                     Fix the issue and restart with --stake-signature",
                                        e
                                    );
                                    // SEC-FIX [v9.1]: verification failure → verified=false.
                                    // 旧実装は verified=true を返しており、RPC タイムアウトや
                                    // 不正な signature でもバリデータが ACTIVE になれた。
                                    // 修正: 検証失敗時は LOCKED 状態で留まり、activate() を拒否する。
                                    (min_validator_stake, false, Some(sig.clone()))
                                }
                            }
                        } else {
                            // SEC-FIX [v9.1]: Solana RPC not configured → verified=false.
                            // 旧実装は verified=true を返しており、RPC 未設定でも
                            // 適当な --stake-signature を渡すだけで ACTIVE になれた。
                            // 修正: RPC が未設定の場合は検証不可能なので LOCKED で留まる。
                            if rpc_url.is_empty() {
                                error!(
                                    "SEC-STAKE: MISAKA_SOLANA_RPC_URL not set — \
                                 cannot verify stake. Set env var and restart."
                                );
                            }
                            if program_id.is_empty() {
                                error!(
                                    "SEC-STAKE: MISAKA_STAKING_PROGRAM_ID not set — \
                                 cannot verify stake. Set env var and restart."
                                );
                            }
                            (min_validator_stake, false, Some(sig.clone()))
                        }
                    } else {
                        // No signature provided — unverified
                        (min_validator_stake, false, None)
                    };

                    // R3-H2: Write lock acquired only AFTER Solana RPC completes
                    let mut registry = validator_registry.write().await;
                    // Re-check after lock reacquisition (another task may have registered)
                    if registry.get(&validator_id).is_some() {
                        drop(registry);
                    } else {
                        match registry.register(
                            validator_id,
                            pubkey_bytes,
                            stake_amount,
                            500, // 5% default commission
                            reward_address,
                            epoch,
                            [0u8; 32], // stake_tx_hash placeholder
                            0,
                            stake_verified,
                            stake_sig.clone(),
                            // 0.9.0: bootstrap path is the Solana/off-chain variant.
                            // l1_stake_verified is written only by `utxo_executor`
                            // when a L1 StakeDeposit tx is finalized (γ-3).
                            false,
                        ) {
                            Ok(()) => {
                                if stake_verified {
                                    info!(
                                    "SEC-STAKE: Local validator {} registered with verified stake \
                                 (amount={}, sig={}...)",
                                    hex::encode(validator_id),
                                    stake_amount,
                                    stake_sig
                                        .as_deref()
                                        .map(|s| &s[..16.min(s.len())])
                                        .unwrap_or("?"),
                                );

                                    // SEC-FIX [v9.1]: Solana 検証済みの実際の預入額を
                                    // ValidatorIdentity.stake_weight に反映する。
                                    //
                                    // 旧実装: stake_weight は keystore ファイルから読み込んだ値のまま
                                    // (デフォルト 1_000_000) で、Solana 上の実際の預入額と無関係だった。
                                    // つまり VRF 提案者選出も BFT クォーラムも全バリデータ等重みで
                                    // 動作しており、10M 預けても 100M 預けても同じ影響力だった。
                                    //
                                    // 修正: Solana 検証成功時に verified.amount を stake_weight に設定。
                                    // これにより VRF 選出確率とコンセンサス重みが預入枚数に比例する。
                                    {
                                        let mut guard = shared_state.write().await;
                                        if let Some(ref mut lv) = guard.local_validator {
                                            let old_weight = lv.identity.stake_weight;
                                            lv.identity.stake_weight = stake_amount as u128;
                                            info!(
                                            "SEC-STAKE: Updated local validator stake_weight: {} → {} \
                                         (consensus weight now reflects Solana deposit)",
                                            old_weight, lv.identity.stake_weight,
                                        );
                                        }
                                        // known_validators 内の自分のエントリも更新
                                        if let Some(kv) = guard
                                            .known_validators
                                            .iter_mut()
                                            .find(|v| v.validator_id == validator_id)
                                        {
                                            kv.stake_weight = stake_amount as u128;
                                        }
                                    }
                                } else {
                                    warn!(
                                    "SEC-STAKE: Local validator {} registered WITHOUT stake proof. \
                                 Cannot activate until you stake at misakastake.com and restart \
                                 with --stake-signature <SOLANA_TX_SIG>",
                                    hex::encode(validator_id),
                                );
                                }
                            }
                            Err(e) => {
                                warn!("SEC-STAKE: Failed to auto-register local validator: {}", e);
                            }
                        }
                    } // end re-check else
                    drop(registry);
                    // γ-persistence: snapshot after auto-register so that a
                    // Solana-verified local validator survives a restart
                    // without re-running the full bootstrap path.
                    if let Err(e) = crate::validator_lifecycle_persistence::persist_global_state(
                        &validator_registry,
                        &current_epoch,
                        &epoch_progress,
                    )
                    .await
                    {
                        warn!(
                            "SEC-STAKE: persist_global_state after auto-register                              failed (change stays in-memory): {}",
                            e
                        );
                    }
                } // end if let Some(lv)
            } else if has_stake_sig {
                // Already registered — update stake verification if new sig provided
                let mut registry = validator_registry.write().await;
                if let Some(account) = registry.get(&validator_id) {
                    if !account.solana_stake_verified {
                        if let Some(ref sig) = cli.stake_signature {
                            // SEC-FIX: Pass None for on_chain_amount in local validator path.
                            // Local validators have their stake verified via CLI (trusted path).
                            match registry.mark_stake_verified(&validator_id, sig.clone(), None) {
                                Ok(()) => {
                                    info!(
                                        "SEC-STAKE: Local validator {} stake verified on restart (sig={}...)",
                                        hex::encode(validator_id),
                                        &sig[..16.min(sig.len())],
                                    );
                                }
                                Err(e) => {
                                    warn!("SEC-STAKE: Failed to verify stake: {}", e);
                                }
                            }
                        }
                    } else {
                        info!(
                            "SEC-STAKE: Local validator {} already verified",
                            hex::encode(validator_id),
                        );
                    }
                }
                drop(registry);
                // γ-persistence: if mark_stake_verified fired, durably
                // snapshot the registry so the verification survives a
                // restart without re-reading the CLI --stake-signature.
                if let Err(e) = crate::validator_lifecycle_persistence::persist_global_state(
                    &validator_registry,
                    &current_epoch,
                    &epoch_progress,
                )
                .await
                {
                    warn!(
                        "SEC-STAKE: persist_global_state after                          mark_stake_verified failed (change stays in-memory): {}",
                        e
                    );
                }
            }
        } else {
            drop(local_validator_ref);
        }
    }

    let rpc_registry = validator_registry.clone();
    let rpc_epoch = current_epoch.clone();
    let rpc_epoch_progress = epoch_progress.clone();
    let lifecycle_registry = validator_registry.clone();
    let lifecycle_epoch = current_epoch.clone();
    let lifecycle_epoch_progress = epoch_progress.clone();
    let lifecycle_store = validator_lifecycle_store.clone();
    let finality_epoch_state = shared_state.clone();
    let finality_epoch_registry = validator_registry.clone();
    let finality_epoch = current_epoch.clone();
    let finality_epoch_progress = epoch_progress.clone();
    let finality_epoch_store = validator_lifecycle_store.clone();
    let finality_runtime_recovery = runtime_recovery_observation.clone();
    let checkpoint_interval = cli.dag_checkpoint_interval.max(1);
    let startup_finalized_score = {
        let guard = shared_state.read().await;
        guard
            .latest_checkpoint_finality
            .as_ref()
            .map(|proof| proof.target.blue_score)
    };
    if let Some(finalized_score) = startup_finalized_score {
        let mut recovery = finality_runtime_recovery.write().await;
        recovery.mark_checkpoint_finality(Some(finalized_score));
    }
    let startup_replayed_finality = validator_lifecycle_store
        .replay_restored_finality_and_persist(
            &validator_registry,
            &current_epoch,
            &epoch_progress,
            startup_finalized_score,
            checkpoint_interval,
        )
        .await?;
    if startup_replayed_finality {
        let next_epoch = *current_epoch.read().await;
        info!(
            "Layer 6: validator lifecycle replayed restored finality on startup | epoch={} | finalized_blue_score={}",
            next_epoch,
            startup_finalized_score.unwrap_or_default()
        );
    }
    let validator_epoch_secs = std::env::var("MISAKA_VALIDATOR_EPOCH_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(86_400);
    tokio::spawn(async move {
        let mut ticker =
            tokio::time::interval(tokio::time::Duration::from_secs(validator_epoch_secs));
        loop {
            ticker.tick().await;
            let should_use_fallback_clock = {
                lifecycle_epoch_progress
                    .lock()
                    .await
                    .should_use_fallback_clock()
            };
            if !should_use_fallback_clock {
                continue;
            }
            let next_epoch = {
                let mut epoch = lifecycle_epoch.write().await;
                *epoch = epoch.saturating_add(1);
                *epoch
            };
            info!(
                "Layer 6: validator lifecycle epoch advanced to {} via fallback clock",
                next_epoch
            );
            if let Err(e) = lifecycle_store
                .persist_state(
                    &lifecycle_registry,
                    &lifecycle_epoch,
                    &lifecycle_epoch_progress,
                )
                .await
            {
                warn!(
                    "Layer 6: failed to persist validator lifecycle epoch tick: {}",
                    e
                );
            }
        }
    });

    // ═══════════════════════════════════════════════════════════════
    //  SEC-FIX [v9.1]: Epoch 毎の Solana ステーク再検証
    //
    //  1. ローカルバリデータ: verify_stake_still_active() でアンステーク検出
    //  2. 全バリデータ: scrape_all_validator_stakes() で実際の預入額を取得
    //  3. known_validators の stake_weight を Solana 上の実データで更新
    // ═══════════════════════════════════════════════════════════════
    let stake_verify_state = shared_state.clone();
    let stake_verify_registry = validator_registry.clone();
    let stake_verify_data_dir = cli.data_dir.clone();
    tokio::spawn(async move {
        // 初回は起動3分後、以降は6時間毎に再検証
        tokio::time::sleep(tokio::time::Duration::from_secs(180)).await;
        let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(6 * 3600));
        loop {
            ticker.tick().await;
            info!("SEC-STAKE: Starting periodic Solana stake re-verification...");

            // ── ローカルバリデータの l1_public_key を読む ──
            let l1_pubkey_hex = {
                let key_path =
                    std::path::Path::new(&stake_verify_data_dir).join("l1-public-key.json");
                if key_path.exists() {
                    let raw = std::fs::read_to_string(&key_path).unwrap_or_default();
                    let parsed: serde_json::Value = serde_json::from_str(&raw).unwrap_or_default();
                    parsed["l1PublicKey"].as_str().unwrap_or("").to_string()
                } else {
                    String::new()
                }
            };

            // ── Solana から全バリデータのステーク情報を一括取得 ──
            match solana_stake_verify::scrape_all_validator_stakes().await {
                Ok(stake_map) => {
                    info!(
                        "SEC-STAKE: Scraped {} validator stakes from Solana",
                        stake_map.len()
                    );

                    // ── ローカルバリデータの再検証 ──
                    if !l1_pubkey_hex.is_empty() {
                        if let Some(info) = stake_map.get(&l1_pubkey_hex) {
                            let min_stake = {
                                let reg = stake_verify_registry.read().await;
                                reg.config().min_validator_stake
                            };
                            let staked_misaka = info.total_staked as f64 / 1_000_000_000.0;

                            if info.total_staked >= min_stake {
                                // ステーク有効 → stake_weight を更新
                                let mut guard = stake_verify_state.write().await;
                                if let Some(ref mut lv) = guard.local_validator {
                                    let old = lv.identity.stake_weight;
                                    lv.identity.stake_weight = info.total_staked as u128;
                                    if old != lv.identity.stake_weight {
                                        info!(
                                            "SEC-STAKE: Local validator stake_weight updated: {} → {} ({:.0} MISAKA)",
                                            old, lv.identity.stake_weight, staked_misaka,
                                        );
                                    }
                                    // known_validators 内の自分も更新
                                    let vid = lv.identity.validator_id;
                                    if let Some(kv) = guard
                                        .known_validators
                                        .iter_mut()
                                        .find(|v| v.validator_id == vid)
                                    {
                                        kv.stake_weight = info.total_staked as u128;
                                    }
                                }
                            } else {
                                // ステーク不足 → 警告（自動 exit は将来実装）
                                warn!(
                                    "SEC-STAKE: ⚠️ Local validator stake BELOW MINIMUM! \
                                     staked={:.0} MISAKA < min={:.0} MISAKA. \
                                     Validator may be deactivated.",
                                    staked_misaka,
                                    min_stake as f64 / 1_000_000_000.0,
                                );
                            }
                        } else {
                            warn!(
                                "SEC-STAKE: Local validator L1 key {}... NOT FOUND on Solana. \
                                 Stake may have been withdrawn.",
                                &l1_pubkey_hex[..16.min(l1_pubkey_hex.len())],
                            );
                        }
                    }

                    // ── リモートバリデータの stake_weight 更新 ──
                    //
                    // Solana 上の全登録 PDA を走査し、l1_public_key → validator_id
                    // のマッピングを構築。known_validators の stake_weight を更新。
                    //
                    // 注: l1_public_key と L1 の validator_id は異なる鍵体系。
                    // ここでは Solana 上の l1_key バイトと L1 ノードの公開鍵の
                    // SHA3 アドレスを突き合わせることはできないため、
                    // リモートバリデータの更新は l1_key を RPC で共有する
                    // 仕組みが必要（将来課題）。
                    // 現時点ではローカルバリデータのみ stake_weight を更新する。
                }
                Err(e) => {
                    warn!(
                        "SEC-STAKE: Solana scraping failed (non-fatal, will retry next epoch): {}",
                        e
                    );
                }
            }
        }
    });
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(10));
        loop {
            ticker.tick().await;
            let Some(finalized_score) = ({
                let guard = finality_epoch_state.read().await;
                guard
                    .latest_checkpoint_finality
                    .as_ref()
                    .map(|proof| proof.target.blue_score)
            }) else {
                continue;
            };

            let maybe_next_epoch = {
                let mut progress = finality_epoch_progress.lock().await;
                let mut epoch = finality_epoch.write().await;
                if progress.apply_finalized_checkpoint_score(
                    &mut *epoch,
                    finalized_score,
                    checkpoint_interval,
                ) {
                    Some(*epoch)
                } else {
                    None
                }
            };

            if let Some(next_epoch) = maybe_next_epoch {
                info!(
                    "Layer 6: validator lifecycle synchronized to finalized checkpoint | epoch={} | finalized_blue_score={}",
                    next_epoch, finalized_score
                );

                // ── SR21 Auto-Election at epoch boundary ──
                //
                // γ-5 NOTE: `StakingRegistry::settle_unlocks` is deliberately
                // NOT called here. This epoch hook runs only under
                // `#[cfg(all(dag, ghostdag-compat))]` (=> `start_dag_node`),
                // which does not instantiate a `UtxoExecutor` and therefore
                // has no `staked_receipt_table` to drain or `utxo_set` to
                // issue the unlocked-stake UTXO into. γ-5 settlement is
                // wired in `start_narwhal_node`'s commit loop instead
                // (the default `dag`-without-`ghostdag-compat` build). If a
                // future reconciliation unifies the two paths (or moves
                // UtxoExecutor into this path), add a
                // `settle_unlocks(next_epoch) + apply_settled_unlocks(..)`
                // pair here as well.
                {
                    let mut wguard = finality_epoch_state.write().await;
                    apply_sr21_election_at_epoch_boundary(&mut wguard, next_epoch);
                }
                {
                    let mut recovery = finality_runtime_recovery.write().await;
                    recovery.mark_checkpoint_finality(Some(finalized_score));
                }
                if let Err(e) = finality_epoch_store
                    .persist_state(
                        &finality_epoch_registry,
                        &finality_epoch,
                        &finality_epoch_progress,
                    )
                    .await
                {
                    warn!(
                        "Layer 6: failed to persist finalized-checkpoint epoch progress: {}",
                        e
                    );
                }
            }
        }
    });
    let _rpc_service = crate::dag_rpc_service::DagRpcServerService::new(
        rpc_state,
        Some(rpc_observation),
        Some(rpc_runtime_recovery),
        Some(rpc_registry),
        rpc_epoch,
        Some(rpc_epoch_progress),
        rpc_addr,
        cli.chain_id,
        [0u8; 32], // ghostdag compat path — genesis_hash not used
    );
    _rpc_service.start().await?;

    info!("Layer 6: DAG RPC server starting on :{}", cli.rpc_port);

    // ══════════════════════════════════════════════════════
    //  Layer 7: Block Production Loop
    // ══════════════════════════════════════════════════════

    info!(
        "Node '{}' ready | mode={} | role={} | consensus=GhostDAG(k={}) | RPC=:{} | SR={}/21",
        cli.name, node_mode, role, cli.dag_k, cli.rpc_port, cli.validator_index,
    );

    if role.produces_blocks() {
        let fast_time = cli.fast_block_time.unwrap_or(2);
        let zkp_time = cli.zkp_batch_time.unwrap_or(30);
        let startup_sync_grace_secs = std::env::var("MISAKA_DAG_STARTUP_SYNC_GRACE_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        info!(
            "Starting SR21 DUAL-LANE block production | SR_index={} | fast={}s | zkp={}s | max_txs={}",
            cli.validator_index, fast_time, zkp_time, cli.dag_max_txs
        );
        info!(
            "21 SR Round-Robin: {} produces when block_count % {} == {}",
            cli.name, cli.validators, cli.validator_index
        );
        if startup_sync_grace_secs > 0 {
            info!(
                "Layer 7: delaying DAG block production for {}s to allow startup sync",
                startup_sync_grace_secs
            );
            tokio::time::sleep(tokio::time::Duration::from_secs(startup_sync_grace_secs)).await;
        }

        // ── Finality monitoring task ──
        let finality_state = shared_state.clone();
        let runtime_recovery = runtime_recovery_observation.clone();
        let finality_interval = cli.dag_checkpoint_interval;
        tokio::spawn(async move {
            run_finality_monitor(finality_state, runtime_recovery, finality_interval).await;
        });

        // ── Dual-lane block production (メインループ — ブロッキング) ──
        run_dag_block_producer_dual(shared_state.clone(), fast_time, zkp_time, cli.dag_max_txs)
            .await;
    } else {
        info!("Block production disabled — running as DAG full node");
        // Keep alive
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        }
    }

    Ok(())
}

/// ファイナリティ監視タスク — 定期的にチェックポイントを作成する。
#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
async fn run_finality_monitor(
    state: Arc<RwLock<misaka_dag::DagNodeState>>,
    runtime_recovery: Arc<RwLock<dag_rpc::DagRuntimeRecoveryObservation>>,
    checkpoint_interval: u64,
) {
    use misaka_dag::dag_finality::FinalityManager;
    use misaka_dag::save_runtime_snapshot;
    let initial_checkpoint = {
        let guard = state.read().await;
        guard.latest_checkpoint.clone()
    };
    let mut finality = FinalityManager::new(checkpoint_interval);
    if let Some(checkpoint) = initial_checkpoint {
        finality = finality.with_checkpoint(checkpoint);
    }
    // Do not anchor checkpoint creation to a coarse per-process 30s phase.
    // In natural multi-validator starts, staggered boot times can otherwise
    // make one validator finalize bucket N while another is still waiting to
    // even create it. A shorter poll interval keeps checkpoint creation tied
    // to DAG progress rather than process start time.
    let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(5));

    loop {
        ticker.tick().await;

        let mut guard = state.write().await;
        let snapshot = guard.dag_store.snapshot();
        let max_score = guard.dag_store.max_blue_score();
        let blocked_by_pending_finality = checkpoint_rollover_blocked_by_pending_finality(&guard);

        // Keep voting for the current checkpoint target until it reaches
        // local finality. Rolling over here prunes the previous vote pool and
        // can strand peers at voteCount=1 on different targets.
        if blocked_by_pending_finality {
            continue;
        }

        let should_advance_bucket = finality.should_checkpoint(max_score);

        if should_advance_bucket {
            let Some((checkpoint_tip, checkpoint_score)) =
                finality.checkpoint_candidate(&guard.ghostdag, &snapshot)
            else {
                continue;
            };
            let stats = &guard.state_manager.stats;
            let cp = finality.create_checkpoint(
                checkpoint_tip,
                checkpoint_score,
                // Use the current UTXO state commitment from storage.
                guard.utxo_set.compute_state_root(),
                stats.txs_applied + stats.txs_coinbase,
                stats.txs_applied,
            );
            guard.latest_checkpoint = Some(cp.clone());
            prune_checkpoint_attestation_state(&mut guard);
            if let Err(e) = refresh_local_checkpoint_attestation(&mut guard) {
                warn!("Failed to refresh local checkpoint attestation: {}", e);
            }
            let vote_gossip = local_vote_gossip_payload(&guard);
            if let Err(e) = save_runtime_snapshot(
                &guard.snapshot_path,
                &guard.dag_store,
                &guard.utxo_set,
                &guard.state_manager.stats,
                guard.latest_checkpoint.as_ref(),
                &guard.known_validators,
                &guard.runtime_active_sr_validator_ids,
                guard.latest_checkpoint_vote.as_ref(),
                guard.latest_checkpoint_finality.as_ref(),
                &guard.checkpoint_vote_pool,
            ) {
                error!("Failed to persist checkpoint snapshot: {}", e);
            } else {
                let mut recovery = runtime_recovery.write().await;
                recovery.mark_checkpoint_persisted(cp.blue_score, cp.block_hash);
                recovery.mark_checkpoint_finality(
                    guard
                        .latest_checkpoint_finality
                        .as_ref()
                        .map(|proof| proof.target.blue_score),
                );
            }
            info!(
                "Checkpoint created: score={}, txs={}, ki={}",
                cp.blue_score, cp.total_applied_txs, cp.total_spent_count,
            );
            if let Some((vote, identity, peers)) = vote_gossip {
                tokio::spawn(async move {
                    gossip_checkpoint_vote_to_peers(peers, vote, identity).await;
                });
            }
        }
    }
}

// ════════════════════════════════════════════════════════════════
//  v1: Linear Chain Node Startup (既存コード — 変更なし)
// ════════════════════════════════════════════════════════════════

#[cfg(not(feature = "dag"))]
async fn start_v1_node(
    cli: Cli,
    node_mode: NodeMode,
    role: NodeRole,
    p2p_config: P2pConfig,
    _loaded_config: Option<misaka_config::NodeConfig>,
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
        NodeMode::Seed => "🌱 SEED    — bootstrap node, peer discovery",
    };
    info!("Mode: {}", mode_label);
    info!(
        "Role: {} (block production {})",
        role,
        if role.produces_blocks() {
            "ENABLED"
        } else {
            "disabled"
        }
    );

    info!("P2P listening on 0.0.0.0:{}", cli.p2p_port);
    if let Some(ref addr) = p2p_config.advertise_addr {
        info!("Advertising as {}", addr);
    } else if p2p_config.advertise_address {
        warn!(
            "No valid advertise address — this node will NOT be discoverable. Use --advertise-addr <HOST:PORT>"
        );
    }

    if !role.produces_blocks() {
        match node_mode {
            NodeMode::Public => {
                info!("Block production disabled for public node (use --validator to enable)")
            }
            NodeMode::Seed => info!("Block production disabled for seed node"),
            _ => {}
        }
    }

    // Genesis
    let now_ms = chrono::Utc::now().timestamp_millis() as u64;
    let mut chain = ChainStore::new();
    let genesis = chain.store_genesis(now_ms);
    info!(
        "Genesis block: height=0 hash={}",
        hex::encode(&genesis.hash[..8])
    );

    // ── Restore UTXO state from snapshot if available ──
    let data_path = std::path::Path::new(&cli.data_dir);
    if let Err(e) = std::fs::create_dir_all(data_path) {
        anyhow::bail!("failed to create data dir '{}': {}", cli.data_dir, e);
    }
    let utxo_snapshot_path = data_path.join("utxo_snapshot.json");
    // SEC-FIX: Use load_from_file_with_burns to also restore processed_burns
    // for bridge replay protection across restarts.
    // SEC-FIX: Also restore total_emitted for supply cap enforcement across restarts.
    let (utxo_set, restored_height, restored_burn_ids, restored_total_emitted) =
        match misaka_storage::utxo_set::UtxoSet::load_from_file_with_burns(
            &utxo_snapshot_path,
            1000,
        ) {
            Ok(Some((restored, burn_ids, total_emitted))) => {
                let h = restored.height;
                info!(
                    "Layer 1: restored UTXO snapshot | height={} | utxos={} | burn_ids={} | total_emitted={}",
                    h,
                    restored.len(),
                    burn_ids.len(),
                    total_emitted,
                );
                (restored, h, burn_ids, total_emitted)
            }
            Ok(None) => {
                info!("Layer 1: no UTXO snapshot found — starting fresh");
                (
                    misaka_storage::utxo_set::UtxoSet::new(1000),
                    0,
                    Vec::new(),
                    0u64,
                )
            }
            Err(e) => {
                warn!(
                    "Layer 1: UTXO snapshot load failed ({}) — starting fresh",
                    e
                );
                (
                    misaka_storage::utxo_set::UtxoSet::new(1000),
                    0,
                    Vec::new(),
                    0u64,
                )
            }
        };

    // Shared state
    let state: SharedState = Arc::new(RwLock::new(NodeState {
        chain,
        height: restored_height,
        tx_count_total: 0,
        validator_count: cli.validators,
        genesis_timestamp_ms: now_ms,
        chain_id: cli.chain_id,
        chain_name: if cli.chain_id == 1 {
            "MISAKA Mainnet".into()
        } else {
            "MISAKA Testnet".into()
        },
        version: "v0.4.1".into(),
        mempool: misaka_mempool::UtxoMempool::new(10_000),
        utxo_set,
        coinbase_pending: Vec::new(),
        faucet_drips: std::collections::HashMap::new(),
        faucet_amount: cli.faucet_amount,
        faucet_cooldown_ms: cli.faucet_cooldown_ms,
        data_dir: cli.data_dir.clone(),
        experimental_zk_path: cli.experimental_zk_path,
        // SEC-FIX-6: Parse reward addresses from CLI/env. If not set, coinbase
        // generation is skipped (no more hardcoded [0x01; 32] / [0x02; 32]).
        proposer_payout_address: cli.proposer_payout_address.as_deref().and_then(|hex_str| {
            let bytes = hex::decode(hex_str).ok()?;
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(arr)
            } else {
                tracing::warn!(
                    "proposer_payout_address must be 32 bytes hex, got {} bytes",
                    bytes.len()
                );
                None
            }
        }),
        treasury_address: cli.treasury_address.as_deref().and_then(|hex_str| {
            let bytes = hex::decode(hex_str).ok()?;
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(arr)
            } else {
                tracing::warn!(
                    "treasury_address must be 32 bytes hex, got {} bytes",
                    bytes.len()
                );
                None
            }
        }),
        // Audit #21: Proposer's ML-DSA-65 spending pubkey for coinbase outputs.
        // Without this, coinbase outputs are permanently unspendable.
        proposer_spending_pubkey: std::env::var("MISAKA_PROPOSER_SPENDING_PUBKEY")
            .ok()
            .and_then(|hex_str| {
                let bytes = hex::decode(hex_str.trim()).ok()?;
                if bytes.len() == 1952 {
                    Some(bytes)
                } else {
                    tracing::warn!(
                        "MISAKA_PROPOSER_SPENDING_PUBKEY must be 1952 bytes (ML-DSA-65), got {}",
                        bytes.len()
                    );
                    None
                }
            }),
    }));

    // Parse peer addresses
    let _static_peers: Vec<SocketAddr> = cli.peers.iter().filter_map(|s| s.parse().ok()).collect();

    // SEC-FIX [Audit #2]: The old p2p_network uses plaintext TCP with no
    // cryptographic authentication. It is now gated behind `legacy-p2p` feature.
    // Production builds MUST use the DAG P2P transport (ML-KEM-768 + ChaCha20-Poly1305).
    #[cfg(feature = "legacy-p2p")]
    warn!(
        "⚠️  SECURITY WARNING: legacy plaintext P2P is enabled. \
         This transport has NO encryption, NO peer authentication. \
         Use DAG P2P transport for production."
    );

    #[cfg(not(feature = "legacy-p2p"))]
    warn!(
        "Legacy P2P disabled (no `legacy-p2p` feature). \
         V1 node P2P will not start — use DAG node for production."
    );

    // Start P2P — only when legacy-p2p feature is enabled
    #[cfg(feature = "legacy-p2p")]
    let p2p = Arc::new(p2p_network::P2pNetwork::new(
        cli.chain_id,
        cli.name.clone(),
        p2p_config.clone(),
    ));
    #[cfg(feature = "legacy-p2p")]
    let p2p_addr: SocketAddr = format!("0.0.0.0:{}", cli.p2p_port).parse()?;
    #[cfg(feature = "legacy-p2p")]
    p2p.start_listener(p2p_addr).await?;

    // Stub P2P for RPC server when legacy transport is disabled
    #[cfg(not(feature = "legacy-p2p"))]
    let p2p = Arc::new(p2p_network::P2pNetwork::new(
        cli.chain_id,
        cli.name.clone(),
        p2p_config.clone(),
    ));

    // Connect to peers (only when legacy transport is active)
    #[cfg(feature = "legacy-p2p")]
    {
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
    }

    // SECURITY: default to localhost-only binding. Use --rpc-bind 0.0.0.0 for public.
    let rpc_addr: SocketAddr = format!("127.0.0.1:{}", cli.rpc_port).parse()?;
    let rpc_state = state.clone();
    let rpc_p2p = p2p.clone();
    let cli_chain_id = cli.chain_id;
    tokio::spawn(async move {
        if let Err(e) = rpc_server::run_rpc_server(rpc_state, rpc_p2p, rpc_addr, cli_chain_id).await
        {
            error!("RPC server error: {}", e);
        }
    });

    info!(
        "Node '{}' ready | mode={} | role={} | RPC=:{} | P2P=:{} | block={}s | val={}/{}{}",
        cli.name,
        node_mode,
        role,
        cli.rpc_port,
        cli.p2p_port,
        cli.block_time,
        cli.validator_index,
        cli.validators,
        if cli.experimental_zk_path {
            " | privacyPath=ZK"
        } else {
            ""
        }
    );

    // Block production
    if role.produces_blocks() {
        // SEC-FIX-6: Warn if reward addresses are not configured
        if cli.proposer_payout_address.is_none() || cli.treasury_address.is_none() {
            warn!(
                "⚠ Validator running WITHOUT reward addresses configured. \
                 Coinbase rewards will be skipped until --proposer-payout-address \
                 and --treasury-address are set (or env MISAKA_PROPOSER_ADDRESS / \
                 MISAKA_TREASURY_ADDRESS)."
            );
        }
        block_producer::run_block_producer(state.clone(), cli.block_time, cli.validator_index)
            .await;
    } else {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
        }
    }

    Ok(())
}

// ════════════════════════════════════════════════════════════════
//  Tests
// ════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        crate::test_env::env_lock()
    }

    #[test]
    fn test_node_mode_parse() {
        assert_eq!(NodeMode::from_str_loose("public"), NodeMode::Public);
        assert_eq!(NodeMode::from_str_loose("hidden"), NodeMode::Hidden);
        assert_eq!(NodeMode::from_str_loose("HIDDEN"), NodeMode::Hidden);
        assert_eq!(NodeMode::from_str_loose("seed"), NodeMode::Seed);
        assert_eq!(NodeMode::from_str_loose("invalid"), NodeMode::Public);
    }

    #[cfg(not(feature = "dag"))]
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

    #[test]
    fn test_requires_explicit_advertise_addr_for_seed_mode() {
        assert!(requires_explicit_advertise_addr(
            NodeMode::Seed,
            NodeRole::FullNode,
            false,
            false,
        ));
    }

    #[test]
    fn test_requires_explicit_advertise_addr_for_public_validator_with_seeds() {
        assert!(requires_explicit_advertise_addr(
            NodeMode::Public,
            NodeRole::Validator,
            true,
            false,
        ));
    }

    #[test]
    fn test_requires_explicit_advertise_addr_for_observer_accepting_operator() {
        assert!(requires_explicit_advertise_addr(
            NodeMode::Public,
            NodeRole::FullNode,
            false,
            true,
        ));
    }

    #[test]
    fn test_hidden_mode_never_requires_explicit_advertise_addr() {
        assert!(!requires_explicit_advertise_addr(
            NodeMode::Hidden,
            NodeRole::Validator,
            true,
            true,
        ));
    }

    #[test]
    fn test_outbound_only_public_observer_can_skip_advertise_addr() {
        assert!(!requires_explicit_advertise_addr(
            NodeMode::Public,
            NodeRole::FullNode,
            false,
            false,
        ));
    }

    #[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
    #[test]
    fn test_make_local_checkpoint_vote_binds_checkpoint_target() {
        use misaka_crypto::validator_sig::generate_validator_keypair;
        use misaka_dag::{DagCheckpoint, LocalDagValidator};
        use misaka_types::validator::{ValidatorIdentity, ValidatorPublicKey};

        let keypair = generate_validator_keypair();
        let identity = ValidatorIdentity {
            validator_id: keypair.public_key.to_canonical_id(),
            stake_weight: 1_000_000,
            public_key: ValidatorPublicKey {
                bytes: keypair.public_key.to_bytes(),
            },
            is_active: true,
        };
        let local = LocalDagValidator { identity, keypair };
        let checkpoint = DagCheckpoint {
            block_hash: [0xA1; 32],
            blue_score: 12,
            utxo_root: [0xB2; 32],
            total_spent_count: 4,
            total_applied_txs: 7,
            timestamp_ms: 1_700_000_000_000,
        };

        let vote = make_local_checkpoint_vote(&local, &checkpoint).unwrap();
        assert_eq!(vote.voter, local.identity.validator_id);
        assert_eq!(vote.target, checkpoint.validator_target());
        assert!(!vote.signature.bytes.is_empty());
    }

    #[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
    fn make_test_dag_state(
        validator_count: usize,
        local_validator: Option<misaka_dag::LocalDagValidator>,
        latest_checkpoint: Option<misaka_dag::DagCheckpoint>,
    ) -> misaka_dag::DagNodeState {
        use misaka_dag::dag_block::{DagBlockHeader, DAG_VERSION, ZERO_HASH};
        use misaka_dag::dag_store::ThreadSafeDagStore;
        use misaka_dag::reachability::ReachabilityStore;
        use misaka_dag::{DagMempool, DagStateManager, GhostDagEngine};
        use std::collections::HashSet;
        use std::path::PathBuf;
        use std::sync::Arc;

        let genesis_header = DagBlockHeader {
            version: DAG_VERSION,
            parents: vec![],
            timestamp_ms: 1_700_000_000_000,
            tx_root: ZERO_HASH,
            proposer_id: [0u8; 32],
            nonce: 0,
            blue_score: 0,
            bits: 0,
        };
        let genesis_hash = genesis_header.compute_hash();

        misaka_dag::DagNodeState {
            dag_store: Arc::new(ThreadSafeDagStore::new(genesis_hash, genesis_header)),
            ghostdag: GhostDagEngine::new(18, genesis_hash),
            state_manager: DagStateManager::new(HashSet::new(), HashSet::new()),
            utxo_set: misaka_storage::utxo_set::UtxoSet::new(32),
            virtual_state: misaka_dag::VirtualState::new(genesis_hash),
            ingestion_pipeline: misaka_dag::IngestionPipeline::new(
                [genesis_hash].into_iter().collect(),
            ),
            quarantined_blocks: HashSet::new(),
            mempool: DagMempool::new(32),
            chain_id: 31337,
            validator_count,
            known_validators: Vec::new(),
            proposer_id: [0xAB; 32],
            sr_index: 0,
            num_active_srs: 1,
            runtime_active_sr_validator_ids: Vec::new(),
            local_validator,
            genesis_hash,
            snapshot_path: PathBuf::from("/tmp/misaka-node-test-snapshot.json"),
            latest_checkpoint,
            latest_checkpoint_vote: None,
            latest_checkpoint_finality: None,
            checkpoint_vote_pool: std::collections::HashMap::new(),
            attestation_rpc_peers: Vec::new(),
            blocks_produced: 0,
            reachability: ReachabilityStore::new(genesis_hash),
            persistent_backend: None,
            faucet_cooldowns: std::collections::HashMap::new(),
            pending_transactions: std::collections::HashMap::new(),
        }
    }

    #[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
    fn make_test_validator(
        stake_weight: u128,
    ) -> (
        misaka_types::validator::ValidatorIdentity,
        misaka_crypto::validator_sig::ValidatorKeypair,
    ) {
        use misaka_crypto::validator_sig::generate_validator_keypair;
        use misaka_types::validator::{ValidatorIdentity, ValidatorPublicKey};

        let keypair = generate_validator_keypair();
        let identity = ValidatorIdentity {
            validator_id: keypair.public_key.to_canonical_id(),
            stake_weight,
            public_key: ValidatorPublicKey {
                bytes: keypair.public_key.to_bytes(),
            },
            is_active: true,
        };
        (identity, keypair)
    }

    #[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
    fn make_signed_checkpoint_vote(
        identity: &misaka_types::validator::ValidatorIdentity,
        keypair: &misaka_crypto::validator_sig::ValidatorKeypair,
        checkpoint: &misaka_dag::DagCheckpoint,
    ) -> misaka_types::validator::DagCheckpointVote {
        use misaka_crypto::validator_sig::validator_sign;
        use misaka_types::validator::{DagCheckpointVote, ValidatorSignature};

        let stub = DagCheckpointVote {
            voter: identity.validator_id,
            target: checkpoint.validator_target(),
            signature: ValidatorSignature { bytes: vec![] },
        };
        let sig = validator_sign(&stub.signing_bytes(), &keypair.secret_key).unwrap();
        DagCheckpointVote {
            signature: ValidatorSignature {
                bytes: sig.to_bytes(),
            },
            ..stub
        }
    }

    #[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
    fn make_finality_proof_for_checkpoint(
        checkpoint: &misaka_dag::DagCheckpoint,
        votes: Vec<misaka_types::validator::DagCheckpointVote>,
    ) -> misaka_types::validator::DagCheckpointFinalityProof {
        misaka_types::validator::DagCheckpointFinalityProof {
            target: checkpoint.validator_target(),
            commits: votes,
        }
    }

    #[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
    #[test]
    fn test_ingest_checkpoint_vote_forms_two_validator_local_quorum() {
        use misaka_dag::{DagCheckpoint, LocalDagValidator};

        let (local_identity, local_keypair) = make_test_validator(1_000_000);
        let local_validator = LocalDagValidator {
            identity: local_identity.clone(),
            keypair: local_keypair,
        };
        let (remote_identity, remote_keypair) = make_test_validator(1_000_000);
        let checkpoint = DagCheckpoint {
            block_hash: [0xC1; 32],
            blue_score: 42,
            utxo_root: [0xD2; 32],
            total_spent_count: 4,
            total_applied_txs: 9,
            timestamp_ms: 1_700_000_000_000,
        };

        let mut state = make_test_dag_state(2, Some(local_validator), Some(checkpoint.clone()));
        refresh_local_checkpoint_attestation(&mut state).unwrap();
        assert_eq!(state.known_validators.len(), 1);
        assert!(state.latest_checkpoint_finality.is_none());

        let remote_vote =
            make_signed_checkpoint_vote(&remote_identity, &remote_keypair, &checkpoint);
        ingest_checkpoint_vote(&mut state, remote_vote, Some(remote_identity)).unwrap();

        assert_eq!(state.known_validators.len(), 2);
        assert!(state.latest_checkpoint_finality.is_some());
        let proof = state.latest_checkpoint_finality.unwrap();
        assert_eq!(proof.target, checkpoint.validator_target());
        assert_eq!(proof.commits.len(), 2);
    }

    #[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
    #[test]
    fn test_ingest_checkpoint_vote_rejects_target_mismatch() {
        use misaka_dag::{DagCheckpoint, LocalDagValidator};

        let (local_identity, local_keypair) = make_test_validator(1_000_000);
        let local_validator = LocalDagValidator {
            identity: local_identity.clone(),
            keypair: local_keypair,
        };
        let (remote_identity, remote_keypair) = make_test_validator(1_000_000);
        let checkpoint = DagCheckpoint {
            block_hash: [0x91; 32],
            blue_score: 7,
            utxo_root: [0x82; 32],
            total_spent_count: 1,
            total_applied_txs: 2,
            timestamp_ms: 1_700_000_000_000,
        };
        let mut wrong_checkpoint = checkpoint.clone();
        wrong_checkpoint.blue_score += 1;

        let mut state = make_test_dag_state(2, Some(local_validator), Some(checkpoint));
        refresh_local_checkpoint_attestation(&mut state).unwrap();

        let wrong_vote =
            make_signed_checkpoint_vote(&remote_identity, &remote_keypair, &wrong_checkpoint);
        let err = ingest_checkpoint_vote(&mut state, wrong_vote, Some(remote_identity))
            .expect_err("mismatched checkpoint target should be rejected");
        assert!(err.to_string().contains("target mismatch"));
    }

    #[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
    #[test]
    fn test_prune_checkpoint_attestation_state_discards_stale_targets() {
        use misaka_dag::DagCheckpoint;

        let current_checkpoint = DagCheckpoint {
            block_hash: [0x21; 32],
            blue_score: 11,
            utxo_root: [0x31; 32],
            total_spent_count: 2,
            total_applied_txs: 3,
            timestamp_ms: 1_700_000_000_000,
        };
        let stale_checkpoint = DagCheckpoint {
            block_hash: [0x41; 32],
            blue_score: 9,
            utxo_root: [0x51; 32],
            total_spent_count: 1,
            total_applied_txs: 2,
            timestamp_ms: 1_699_999_999_000,
        };

        let (current_identity, current_keypair) = make_test_validator(1_000_000);
        let (stale_identity, stale_keypair) = make_test_validator(1_000_000);
        let current_vote =
            make_signed_checkpoint_vote(&current_identity, &current_keypair, &current_checkpoint);
        let stale_vote =
            make_signed_checkpoint_vote(&stale_identity, &stale_keypair, &stale_checkpoint);

        let mut state = make_test_dag_state(2, None, Some(current_checkpoint.clone()));
        state.latest_checkpoint_vote = Some(stale_vote.clone());
        state.latest_checkpoint_finality = Some(make_finality_proof_for_checkpoint(
            &stale_checkpoint,
            vec![stale_vote.clone()],
        ));
        state
            .checkpoint_vote_pool
            .insert(stale_checkpoint.validator_target(), vec![stale_vote]);
        state.checkpoint_vote_pool.insert(
            current_checkpoint.validator_target(),
            vec![current_vote.clone()],
        );

        prune_checkpoint_attestation_state(&mut state);

        assert_eq!(state.checkpoint_vote_pool.len(), 1);
        assert!(state
            .checkpoint_vote_pool
            .contains_key(&current_checkpoint.validator_target()));
        assert!(state.latest_checkpoint_vote.is_none());
        assert!(state.latest_checkpoint_finality.is_none());
        assert_eq!(
            state
                .checkpoint_vote_pool
                .get(&current_checkpoint.validator_target())
                .unwrap()
                .len(),
            1
        );
    }

    #[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
    #[test]
    fn test_prune_checkpoint_attestation_state_clears_when_checkpoint_missing() {
        use misaka_dag::DagCheckpoint;

        let checkpoint = DagCheckpoint {
            block_hash: [0x61; 32],
            blue_score: 4,
            utxo_root: [0x71; 32],
            total_spent_count: 1,
            total_applied_txs: 1,
            timestamp_ms: 1_700_000_000_000,
        };
        let (identity, keypair) = make_test_validator(1_000_000);
        let vote = make_signed_checkpoint_vote(&identity, &keypair, &checkpoint);

        let mut state = make_test_dag_state(1, None, None);
        state.latest_checkpoint_vote = Some(vote.clone());
        state.latest_checkpoint_finality = Some(make_finality_proof_for_checkpoint(
            &checkpoint,
            vec![vote.clone()],
        ));
        state
            .checkpoint_vote_pool
            .insert(checkpoint.validator_target(), vec![vote]);

        prune_checkpoint_attestation_state(&mut state);

        assert!(state.latest_checkpoint_vote.is_none());
        assert!(state.latest_checkpoint_finality.is_none());
        assert!(state.checkpoint_vote_pool.is_empty());
    }

    #[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
    #[test]
    fn test_checkpoint_rollover_blocked_by_pending_finality_for_validator() {
        use misaka_dag::{DagCheckpoint, LocalDagValidator};

        let (local_identity, local_keypair) = make_test_validator(1_000_000);
        let local_validator = LocalDagValidator {
            identity: local_identity,
            keypair: local_keypair,
        };
        let checkpoint = DagCheckpoint {
            block_hash: [0x71; 32],
            blue_score: 12,
            utxo_root: [0x72; 32],
            total_spent_count: 3,
            total_applied_txs: 4,
            timestamp_ms: 1_700_000_000_000,
        };

        let mut state = make_test_dag_state(2, Some(local_validator), Some(checkpoint));
        assert!(checkpoint_rollover_blocked_by_pending_finality(&state));

        refresh_local_checkpoint_attestation(&mut state).unwrap();
        let (remote_identity, remote_keypair) = make_test_validator(1_000_000);
        let remote_vote = make_signed_checkpoint_vote(
            &remote_identity,
            &remote_keypair,
            state.latest_checkpoint.as_ref().unwrap(),
        );
        ingest_checkpoint_vote(&mut state, remote_vote, Some(remote_identity)).unwrap();

        assert!(!checkpoint_rollover_blocked_by_pending_finality(&state));
    }

    #[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
    #[test]
    fn test_checkpoint_rollover_not_blocked_without_local_validator() {
        use misaka_dag::DagCheckpoint;

        let checkpoint = DagCheckpoint {
            block_hash: [0x81; 32],
            blue_score: 8,
            utxo_root: [0x82; 32],
            total_spent_count: 1,
            total_applied_txs: 2,
            timestamp_ms: 1_700_000_000_000,
        };
        let state = make_test_dag_state(2, None, Some(checkpoint));

        assert!(!checkpoint_rollover_blocked_by_pending_finality(&state));
    }

    #[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
    #[test]
    fn test_checkpoint_rollover_stays_blocked_until_finality_even_if_chain_advances() {
        use misaka_dag::dag_block::{DagBlockHeader, GhostDagData, DAG_VERSION, ZERO_HASH};
        use misaka_dag::DagCheckpoint;

        let (local_identity, local_keypair) = make_test_validator(1_000_000);
        let local_validator = misaka_dag::LocalDagValidator {
            identity: local_identity,
            keypair: local_keypair,
        };
        let checkpoint = DagCheckpoint {
            block_hash: [0x91; 32],
            blue_score: 12,
            utxo_root: [0x92; 32],
            total_spent_count: 1,
            total_applied_txs: 1,
            timestamp_ms: 1_700_000_000_000,
        };

        let state = make_test_dag_state(3, Some(local_validator), Some(checkpoint));
        assert!(checkpoint_rollover_blocked_by_pending_finality(&state));

        let header = DagBlockHeader {
            version: DAG_VERSION,
            parents: vec![state.genesis_hash],
            timestamp_ms: 1_700_000_000_100,
            tx_root: ZERO_HASH,
            proposer_id: [0xAB; 32],
            nonce: 1,
            blue_score: 13,
            bits: 0,
        };
        let block_hash = header.compute_hash();
        state
            .dag_store
            .insert_block(block_hash, header, Vec::new())
            .expect("test block inserted");
        state.dag_store.set_ghostdag(
            block_hash,
            GhostDagData {
                blue_score: 13,
                blue_work: 13,
                selected_parent: state.genesis_hash,
                mergeset_blues: vec![],
                mergeset_reds: vec![],
                blues_anticone_sizes: vec![],
            },
        );

        assert!(checkpoint_rollover_blocked_by_pending_finality(&state));
    }

    #[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
    #[test]
    fn test_normalize_dag_rpc_peers_adds_scheme_and_dedups() {
        let peers = normalize_dag_rpc_peers(&[
            "127.0.0.1:3001".to_string(),
            "http://127.0.0.1:3001/".to_string(),
            "https://example.com/rpc".to_string(),
            "".to_string(),
        ]);

        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0], "http://127.0.0.1:3001");
        assert_eq!(peers[1], "https://example.com/rpc");
    }

    #[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
    #[tokio::test]
    async fn test_gossip_checkpoint_vote_to_peers_posts_vote_payload() {
        use axum::{extract::State, routing::post, Json, Router};
        use serde_json::Value;
        use std::sync::Arc;
        use tokio::sync::Mutex;

        async fn handler(
            State(captured): State<Arc<Mutex<Vec<Value>>>>,
            Json(payload): Json<Value>,
        ) -> Json<Value> {
            captured.lock().await.push(payload);
            Json(serde_json::json!({
                "accepted": true,
                "target": { "blueScore": 42 }
            }))
        }

        let captured = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/api/submit_checkpoint_vote", post(handler))
            .with_state(captured.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("read test listener addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });

        let checkpoint = misaka_dag::DagCheckpoint {
            block_hash: [0x81; 32],
            blue_score: 42,
            utxo_root: [0x82; 32],
            total_spent_count: 2,
            total_applied_txs: 3,
            timestamp_ms: 1_700_000_000_000,
        };
        let (identity, keypair) = make_test_validator(1_000_000);
        let vote = make_signed_checkpoint_vote(&identity, &keypair, &checkpoint);

        gossip_checkpoint_vote_to_peers(
            vec![format!("http://{}", addr)],
            vote.clone(),
            identity.clone(),
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let payloads = captured.lock().await.clone();
        server.abort();

        assert_eq!(payloads.len(), 1);
        assert_eq!(
            payloads[0]["vote"]["target"]["blue_score"],
            serde_json::Value::from(42u64)
        );
        assert_eq!(
            payloads[0]["validator_identity"]["stake_weight"],
            serde_json::Value::from(1_000_000u64)
        );
    }

    #[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
    #[test]
    fn test_deterministic_dag_genesis_header_is_stable_per_chain_id() {
        let header_a1 = deterministic_dag_genesis_header(2);
        let header_a2 = deterministic_dag_genesis_header(2);
        let header_b = deterministic_dag_genesis_header(9);

        assert_eq!(header_a1.timestamp_ms, 0);
        assert_eq!(header_a1.parents, Vec::<[u8; 32]>::new());
        assert_eq!(header_a1.compute_hash(), header_a2.compute_hash());
        assert_ne!(header_a1.proposer_id, header_b.proposer_id);
        assert_ne!(header_a1.compute_hash(), header_b.compute_hash());
    }

    #[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
    #[tokio::test]
    async fn test_remote_vote_gossip_forms_live_local_quorum_when_checkpoint_matches() {
        use misaka_dag::{DagCheckpoint, LocalDagValidator};
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let _guard = env_lock();

        let checkpoint = DagCheckpoint {
            block_hash: [0x91; 32],
            blue_score: 77,
            utxo_root: [0x92; 32],
            total_spent_count: 5,
            total_applied_txs: 9,
            timestamp_ms: 1_700_000_000_000,
        };

        let (validator_a_identity, validator_a_keypair) = make_test_validator(1_000_000);
        let (validator_b_identity, validator_b_keypair) = make_test_validator(1_000_000);

        let local_validator_a = LocalDagValidator {
            identity: validator_a_identity.clone(),
            keypair: validator_a_keypair,
        };
        let local_validator_b = LocalDagValidator {
            identity: validator_b_identity.clone(),
            keypair: validator_b_keypair,
        };

        let mut state_b = make_test_dag_state(2, Some(local_validator_b), Some(checkpoint.clone()));
        refresh_local_checkpoint_attestation(&mut state_b).unwrap();
        assert!(state_b.latest_checkpoint_finality.is_none());

        let shared_state_b = Arc::new(RwLock::new(state_b));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test port");
        let addr = listener.local_addr().expect("read test addr");
        drop(listener);

        let server_state = shared_state_b.clone();
        let server = tokio::spawn(async move {
            crate::dag_rpc::run_dag_rpc_server_with_observation(
                server_state,
                None,
                None,
                None,
                None,
                Arc::new(RwLock::new(0)),
                None,
                addr,
                31337,
            )
            .await
            .expect("run dag rpc server");
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut state_a = make_test_dag_state(2, Some(local_validator_a), Some(checkpoint.clone()));
        state_a.attestation_rpc_peers = vec![format!("http://{}", addr)];
        refresh_local_checkpoint_attestation(&mut state_a).unwrap();
        let (vote, identity, peers) =
            local_vote_gossip_payload(&state_a).expect("local vote gossip payload");

        gossip_checkpoint_vote_to_peers(peers, vote, identity).await;
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;

        let client = reqwest::Client::new();
        let chain_info = client
            .post(format!("http://{}/api/get_chain_info", addr))
            .json(&serde_json::json!({}))
            .send()
            .await
            .expect("request chain info")
            .json::<serde_json::Value>()
            .await
            .expect("decode chain info");

        server.abort();

        assert_eq!(
            chain_info["validatorAttestation"]["currentCheckpointVotes"]["voteCount"],
            serde_json::Value::from(2u64)
        );
        assert_eq!(
            chain_info["validatorAttestation"]["currentCheckpointVotes"]["quorumReached"],
            serde_json::Value::Bool(true)
        );
        assert_eq!(
            chain_info["validatorAttestation"]["currentCheckpointStatus"]["bridgeReadiness"],
            serde_json::Value::String("ready".into())
        );
        assert_eq!(
            chain_info["validatorAttestation"]["currentCheckpointStatus"]
                ["explorerConfirmationLevel"],
            serde_json::Value::String("checkpointFinalized".into())
        );
    }

    #[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
    #[tokio::test]
    async fn test_discover_checkpoint_validators_from_rpc_peers_reads_local_validator_identity() {
        use misaka_dag::{DagCheckpoint, LocalDagValidator};
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let _guard = env_lock();

        let checkpoint = DagCheckpoint {
            block_hash: [0xA1; 32],
            blue_score: 21,
            utxo_root: [0xA2; 32],
            total_spent_count: 1,
            total_applied_txs: 2,
            timestamp_ms: 1_700_000_000_000,
        };

        let (identity, keypair) = make_test_validator(1_000_000);
        let shared_state = Arc::new(RwLock::new(make_test_dag_state(
            2,
            Some(LocalDagValidator {
                identity: identity.clone(),
                keypair,
            }),
            Some(checkpoint),
        )));

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind test port");
        let addr = listener.local_addr().expect("read test addr");
        drop(listener);

        let server_state = shared_state.clone();
        let server = tokio::spawn(async move {
            crate::dag_rpc::run_dag_rpc_server_with_observation(
                server_state,
                None,
                None,
                None,
                None,
                Arc::new(RwLock::new(0)),
                None,
                addr,
                31337,
            )
            .await
            .expect("run dag rpc server");
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let discovered =
            discover_checkpoint_validators_from_rpc_peers(&[format!("http://{}", addr)]).await;

        server.abort();

        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].validator_id, identity.validator_id);
        assert_eq!(discovered[0].stake_weight, identity.stake_weight);
        assert_eq!(discovered[0].public_key.bytes, identity.public_key.bytes);
    }

    // ─── Permissionless SR: OBSERVER dynamic-validator expansion ─────
    //
    // Verifies the Phase 8.5 gate: a validator that is NOT in the
    // genesis manifest but IS Active in the staking registry must be
    // recognized as a full validator, not OBSERVER.

    #[test]
    #[allow(deprecated)]
    fn dynamic_validator_not_observer() {
        use misaka_consensus::staking::{StakingConfig, StakingRegistry, ValidatorState};

        let config = StakingConfig {
            min_validator_stake: 10_000_000,
            max_active_validators: 10,
            ..StakingConfig::testnet()
        };
        let mut reg = StakingRegistry::new(config);
        let fp = [0xAB; 32];

        // Before any registration: not a dynamic validator.
        assert!(!is_dynamic_active_validator(&reg, &fp));

        // Register + activate.
        reg.register(
            fp,
            vec![0xAB; 1952],
            20_000_000,
            500,
            fp,
            0,
            fp,
            0,
            true, // solana_stake_verified — satisfies activate() OR-gate
            Some("sig".into()),
            false,
        )
        .expect("register");
        reg.update_score(&fp, 5000);

        // LOCKED is not enough — must be Active.
        assert_eq!(reg.get(&fp).unwrap().state, ValidatorState::Locked);
        assert!(
            !is_dynamic_active_validator(&reg, &fp),
            "LOCKED validator must not be treated as a dynamic validator"
        );

        reg.activate(&fp, 1).expect("activate");
        assert_eq!(reg.get(&fp).unwrap().state, ValidatorState::Active);

        // ACTIVE → now recognized as a dynamic validator (not OBSERVER).
        assert!(
            is_dynamic_active_validator(&reg, &fp),
            "ACTIVE registry validator must be recognized as non-OBSERVER",
        );

        // Different fingerprint → not a dynamic validator.
        assert!(!is_dynamic_active_validator(&reg, &[0xFF; 32]));
    }

    #[test]
    fn observer_returns_to_observer_after_exit() {
        use misaka_consensus::staking::{StakingConfig, StakingRegistry};

        let config = StakingConfig {
            min_validator_stake: 10_000_000,
            max_active_validators: 10,
            ..StakingConfig::testnet()
        };
        let mut reg = StakingRegistry::new(config);
        let fp = [0xCD; 32];

        // Bring the validator to Active.
        #[allow(deprecated)]
        reg.register(
            fp,
            vec![0xCD; 1952],
            20_000_000,
            500,
            fp,
            0,
            fp,
            0,
            true,
            Some("sig".into()),
            false,
        )
        .expect("register");
        reg.update_score(&fp, 5000);
        reg.activate(&fp, 1).expect("activate");
        assert!(is_dynamic_active_validator(&reg, &fp));

        // Exit — state goes EXITING, no longer counted as dynamic.
        reg.exit(&fp, 10).expect("exit");
        assert!(
            !is_dynamic_active_validator(&reg, &fp),
            "EXITING validator must NOT be treated as active dynamic validator — OBSERVER downgrade on exit"
        );
    }

    // ─── PR-B: uptime enforcement ─────────────────────────────────────

    /// Test the pure arithmetic helper: 50 proposed / 100 expected → 5000 bps.
    #[test]
    fn prb_uptime_calculated_correctly() {
        // Exact ratios.
        assert_eq!(compute_uptime_bps(50, 100), 5000);
        assert_eq!(compute_uptime_bps(100, 100), 10_000);
        assert_eq!(compute_uptime_bps(0, 100), 0);

        // Over-participation (leader wave imbalance, etc.) clamps to 10_000.
        assert_eq!(compute_uptime_bps(200, 100), 10_000);

        // Bootstrap / quiet epoch: expected == 0 → full credit.
        assert_eq!(compute_uptime_bps(0, 0), 10_000);
        assert_eq!(compute_uptime_bps(5, 0), 10_000);

        // Large values don't overflow (u128 internal arithmetic).
        let big = u64::MAX / 2;
        let result = compute_uptime_bps(big, big);
        assert_eq!(result, 10_000);
    }

    /// Test that `StakingRegistry::slash(Minor)` applies the 1% rate to
    /// a zero-uptime ACTIVE validator (the path PR-B's commit loop hits).
    #[test]
    #[allow(deprecated)]
    fn prb_zero_uptime_triggers_minor_slash() {
        use misaka_consensus::staking::{
            SlashSeverity, StakingConfig, StakingRegistry, ValidatorState,
        };

        let config = StakingConfig {
            min_validator_stake: 1_000,
            slash_minor_bps: 100, // 1%
            ..StakingConfig::testnet()
        };
        let mut reg = StakingRegistry::new(config);
        let id = [0xAA; 32];
        reg.register(
            id,
            vec![1; 1952],
            20_000_000, // well above min
            500,
            id,
            0,
            [0xAA; 32],
            0,
            true,
            Some("sig".into()),
            false,
        )
        .expect("register");
        reg.update_score(&id, 5000);
        reg.activate(&id, 1).expect("activate");
        assert_eq!(reg.get(&id).unwrap().state, ValidatorState::Active);

        // Simulate PR-B: zero proposed, epoch had blocks → slash Minor.
        reg.update_uptime(&id, compute_uptime_bps(0, /* expected = */ 100));
        assert_eq!(reg.get(&id).unwrap().uptime_bps, 0, "uptime set to 0");

        let stake_before = reg.get(&id).unwrap().stake_amount;
        let (slashed, _reporter) = reg.slash(&id, SlashSeverity::Minor, 2).expect("slash");
        let stake_after = reg.get(&id).unwrap().stake_amount;

        // 1% of 20_000_000 = 200_000 base units.
        assert_eq!(slashed, 200_000, "Minor slash = 1% of stake");
        assert_eq!(
            stake_before - stake_after,
            slashed,
            "stake_amount reduced by slashed amount"
        );
    }

    /// Test the clear-on-boundary semantic: the HashMap + counter are
    /// per-epoch; after clear, the next epoch starts from zero.
    #[test]
    fn prb_uptime_resets_each_epoch() {
        let mut propose_count: std::collections::HashMap<[u8; 32], u64> =
            std::collections::HashMap::new();
        let mut epoch_block_count: u64 = 0;

        let v1 = [0x01; 32];
        let v2 = [0x02; 32];

        // Epoch 1: v1 proposes 3, v2 proposes 7 → 10 total.
        for _ in 0..3 {
            *propose_count.entry(v1).or_insert(0) += 1;
            epoch_block_count += 1;
        }
        for _ in 0..7 {
            *propose_count.entry(v2).or_insert(0) += 1;
            epoch_block_count += 1;
        }

        let expected_e1 = epoch_block_count / 2; // 2 validators
        assert_eq!(expected_e1, 5);
        assert_eq!(compute_uptime_bps(3, expected_e1), 6000);
        assert_eq!(compute_uptime_bps(7, expected_e1), 10_000); // clamped

        // Boundary reset.
        propose_count.clear();
        epoch_block_count = 0;

        // Epoch 2: v1 only, 5 blocks.
        for _ in 0..5 {
            *propose_count.entry(v1).or_insert(0) += 1;
            epoch_block_count += 1;
        }
        assert_eq!(propose_count.get(&v1).copied(), Some(5));
        assert_eq!(
            propose_count.get(&v2).copied(),
            None,
            "epoch 1 tally was cleared"
        );
        assert_eq!(epoch_block_count, 5);

        // v2 was not heard in epoch 2 → zero_uptime candidate.
        let expected_e2 = epoch_block_count / 2;
        let v2_uptime = compute_uptime_bps(0, expected_e2);
        assert_eq!(v2_uptime, 0, "v2 must be at 0 uptime in epoch 2");
    }
}

// ════════════════════════════════════════════════════════════════
//  Phase 10 (Item 2): Smoke E2E stake-lifecycle tests
// ════════════════════════════════════════════════════════════════
//
// These tests exercise the full in-process stake lifecycle:
//   1. ValidatorStakeTx envelope construction (the shape the CLI emits)
//   2. UtxoExecutor::execute_committed commits it
//   3. StakingRegistry state transitions (LOCKED → ACTIVE → EXITING → UNLOCKED)
//   4. auto_activate_locked + settle_unlocks + SR21 + committee rebuild
//
// We skip the network / RPC / mempool layer and drive the executor
// directly. Subprocess-based multi-node tests live in
// `crates/misaka-test-cluster` (out of scope here). These are smoke
// tests: they prove the state machine, not throughput.

#[cfg(test)]
#[allow(deprecated)]
mod phase10_smoke {
    use super::*;
    use misaka_consensus::staking::{StakingConfig, StakingRegistry, ValidatorState};
    use misaka_crypto::validator_sig::ValidatorPqPublicKey;
    use misaka_pqc::pq_sign::{ml_dsa_sign_raw, MlDsaKeypair};
    use misaka_storage::utxo_set::UtxoSet;
    use misaka_types::intent::AppId;
    use misaka_types::utxo::{
        OutputRef, TxInput, TxOutput, TxType, UtxoTransaction, UTXO_TX_VERSION,
    };
    use misaka_types::validator_stake_tx::{
        RegisterParams, StakeInput, StakeMoreParams, StakeTxKind, StakeTxParams, ValidatorStakeTx,
    };

    fn smoke_staking_config() -> StakingConfig {
        // Tiny thresholds so fixture stake amounts (~11_000 base units)
        // satisfy min_validator_stake, and the unbonding test can settle
        // within a short epoch window.
        StakingConfig {
            min_validator_stake: 1_000,
            unbonding_epochs: 5,
            min_uptime_bps: 0,
            min_score: 0,
            ..StakingConfig::testnet()
        }
    }

    fn new_executor() -> crate::utxo_executor::UtxoExecutor {
        let app_id = AppId::new(2, [0u8; 32]);
        let mut ex = crate::utxo_executor::UtxoExecutor::with_utxo_set(UtxoSet::new(1000), app_id);
        // Feature gate is u64::MAX in FEATURE_ACTIVATIONS by default;
        // Phase 6 / Group 1's test override lets stake tx through.
        ex.enable_on_chain_staking_for_tests(0);
        ex
    }

    fn seed_utxo(ex: &mut crate::utxo_executor::UtxoExecutor, outref: OutputRef, amount: u64) {
        ex.utxo_set_mut()
            .add_output(
                outref,
                TxOutput {
                    amount,
                    address: [0x77; 32],
                    spending_pubkey: None,
                },
                0,
                false,
            )
            .expect("seed utxo");
    }

    fn sign_envelope(mut tx: ValidatorStakeTx, kp: &MlDsaKeypair) -> ValidatorStakeTx {
        tx.signature = vec![];
        let payload = tx.signing_payload();
        let sig = ml_dsa_sign_raw(&kp.secret_key, &payload).expect("sign envelope");
        tx.signature = sig.as_bytes().to_vec();
        tx
    }

    fn validator_id_of(kp: &MlDsaKeypair) -> [u8; 32] {
        ValidatorPqPublicKey::from_bytes(kp.public_key.as_bytes())
            .unwrap()
            .to_canonical_id()
    }

    fn make_register_envelope(
        kp: &MlDsaKeypair,
        vid: [u8; 32],
        stake_input_ref: (OutputRef, u64),
    ) -> ValidatorStakeTx {
        let (outref, input_amount) = stake_input_ref;
        sign_envelope(
            ValidatorStakeTx {
                kind: StakeTxKind::Register,
                validator_id: vid,
                stake_inputs: vec![StakeInput {
                    tx_hash: outref.tx_hash,
                    output_index: outref.output_index,
                    amount: input_amount,
                }],
                fee: 1_000,
                nonce: 0,
                memo: None,
                params: StakeTxParams::Register(RegisterParams {
                    consensus_pubkey: kp.public_key.as_bytes().to_vec(),
                    reward_address: [0x33; 32],
                    commission_bps: 500,
                    p2p_endpoint: Some("127.0.0.1:30333".into()),
                    moniker: None,
                }),
                signature: Vec::new(),
            },
            kp,
        )
    }

    fn make_stake_more_envelope(
        kp: &MlDsaKeypair,
        vid: [u8; 32],
        stake_input_ref: (OutputRef, u64),
        additional: u64,
    ) -> ValidatorStakeTx {
        let (outref, input_amount) = stake_input_ref;
        sign_envelope(
            ValidatorStakeTx {
                kind: StakeTxKind::StakeMore,
                validator_id: vid,
                stake_inputs: vec![StakeInput {
                    tx_hash: outref.tx_hash,
                    output_index: outref.output_index,
                    amount: input_amount,
                }],
                fee: 1_000,
                nonce: 1,
                memo: None,
                params: StakeTxParams::StakeMore(StakeMoreParams {
                    additional_amount: additional,
                }),
                signature: Vec::new(),
            },
            kp,
        )
    }

    fn make_begin_exit_envelope(kp: &MlDsaKeypair, vid: [u8; 32]) -> ValidatorStakeTx {
        sign_envelope(
            ValidatorStakeTx {
                kind: StakeTxKind::BeginExit,
                validator_id: vid,
                stake_inputs: Vec::new(),
                fee: 1_000,
                nonce: 2,
                memo: None,
                params: StakeTxParams::BeginExit,
                signature: Vec::new(),
            },
            kp,
        )
    }

    /// Wrap a `ValidatorStakeTx` in a `UtxoTransaction { tx_type: StakeDeposit }`
    /// with the receipt marker at outputs[0] and the given input seeded in
    /// the caller's UtxoSet.
    fn wrap_stake_deposit(
        envelope: &ValidatorStakeTx,
        input: &OutputRef,
        validator_id: [u8; 32],
    ) -> Vec<u8> {
        let tx = UtxoTransaction {
            version: UTXO_TX_VERSION,
            tx_type: TxType::StakeDeposit,
            inputs: vec![TxInput {
                utxo_refs: vec![input.clone()],
                proof: vec![0xAA; 16],
            }],
            outputs: vec![TxOutput {
                amount: 0,
                address: validator_id,
                spending_pubkey: None,
            }],
            fee: 1_000,
            extra: envelope.encode_for_extra().expect("encode extra"),
            expiry: 0,
        };
        borsh::to_vec(&tx).expect("borsh tx")
    }

    fn wrap_stake_withdraw(envelope: &ValidatorStakeTx, input: &OutputRef) -> Vec<u8> {
        let tx = UtxoTransaction {
            version: UTXO_TX_VERSION,
            tx_type: TxType::StakeWithdraw,
            inputs: vec![TxInput {
                utxo_refs: vec![input.clone()],
                proof: vec![0xBB; 16],
            }],
            outputs: vec![TxOutput {
                amount: 0,
                address: [0x22; 32],
                spending_pubkey: None,
            }],
            fee: 1_000,
            extra: envelope.encode_for_extra().expect("encode extra"),
            expiry: 0,
        };
        borsh::to_vec(&tx).expect("borsh tx")
    }

    // ─── Test 1: stake-register full lifecycle ────────────────────────

    #[test]
    fn phase10_stake_register_lifecycle() {
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_of(&kp);

        let mut ex = new_executor();
        let mut reg = StakingRegistry::new(smoke_staking_config());

        let input_ref = OutputRef {
            tx_hash: [0xFF; 32],
            output_index: 0,
        };
        seed_utxo(&mut ex, input_ref.clone(), 11_000);

        let env = make_register_envelope(&kp, vid, (input_ref.clone(), 11_000));
        let raw = wrap_stake_deposit(&env, &input_ref, vid);

        let result = ex.execute_committed(1, &[raw], None, Some(&mut reg), 0);
        assert_eq!(result.txs_accepted, 1, "register must be accepted");
        assert_eq!(result.txs_rejected, 0);

        // LOCKED with l1_stake_verified set.
        let account = reg.get(&vid).expect("registered");
        assert_eq!(account.state, ValidatorState::Locked);
        assert!(account.l1_stake_verified);
        assert_eq!(account.stake_amount, 11_000 - 1_000); // net

        // auto_activate_locked → ACTIVE.
        let activated = reg.auto_activate_locked(1);
        assert_eq!(activated, vec![vid]);
        assert_eq!(reg.get(&vid).unwrap().state, ValidatorState::Active);
    }

    // ─── Test 2: stake-more increases weight ──────────────────────────

    #[test]
    fn phase10_stake_more_increases_weight() {
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_of(&kp);
        let mut ex = new_executor();
        let mut reg = StakingRegistry::new(smoke_staking_config());

        // Register first.
        let reg_input = OutputRef {
            tx_hash: [0xFF; 32],
            output_index: 0,
        };
        seed_utxo(&mut ex, reg_input.clone(), 11_000);
        let reg_env = make_register_envelope(&kp, vid, (reg_input.clone(), 11_000));
        let r1 = ex.execute_committed(
            1,
            &[wrap_stake_deposit(&reg_env, &reg_input, vid)],
            None,
            Some(&mut reg),
            0,
        );
        assert_eq!(r1.txs_accepted, 1);
        let stake_before = reg.get(&vid).unwrap().stake_amount;

        // Activate so stake_more's state check (Locked|Active only) passes
        // for the ACTIVE path too.
        reg.auto_activate_locked(1);

        // StakeMore. Use a fresh input ref so it does not collide with the
        // already-consumed Register input.
        let more_input = OutputRef {
            tx_hash: [0xEE; 32],
            output_index: 0,
        };
        seed_utxo(&mut ex, more_input.clone(), 6_000);
        let more_env = make_stake_more_envelope(&kp, vid, (more_input.clone(), 6_000), 5_000);
        let r2 = ex.execute_committed(
            2,
            &[wrap_stake_deposit(&more_env, &more_input, vid)],
            None,
            Some(&mut reg),
            1,
        );
        assert_eq!(r2.txs_accepted, 1, "stake-more must be accepted");

        let stake_after = reg.get(&vid).unwrap().stake_amount;
        assert_eq!(
            stake_after,
            stake_before + 5_000,
            "stake_amount must increase by additional_amount"
        );
    }

    // ─── Test 3: begin-exit + settle_unlocks ──────────────────────────

    #[test]
    fn phase10_begin_exit_and_settle() {
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_of(&kp);
        let mut ex = new_executor();
        let mut reg = StakingRegistry::new(smoke_staking_config());

        // Register + activate so we can BeginExit.
        let reg_input = OutputRef {
            tx_hash: [0xFF; 32],
            output_index: 0,
        };
        seed_utxo(&mut ex, reg_input.clone(), 11_000);
        let reg_env = make_register_envelope(&kp, vid, (reg_input.clone(), 11_000));
        ex.execute_committed(
            1,
            &[wrap_stake_deposit(&reg_env, &reg_input, vid)],
            None,
            Some(&mut reg),
            0,
        );
        reg.auto_activate_locked(1);
        assert_eq!(reg.get(&vid).unwrap().state, ValidatorState::Active);

        // BeginExit.
        let exit_input = OutputRef {
            tx_hash: [0xCD; 32],
            output_index: 0,
        };
        seed_utxo(&mut ex, exit_input.clone(), 2_000);
        let exit_env = make_begin_exit_envelope(&kp, vid);
        let raw = wrap_stake_withdraw(&exit_env, &exit_input);
        let exit_epoch = 10u64;
        let r = ex.execute_committed(3, &[raw], None, Some(&mut reg), exit_epoch);
        assert_eq!(r.txs_accepted, 1, "begin-exit must be accepted");
        assert!(matches!(
            reg.get(&vid).unwrap().state,
            ValidatorState::Exiting { .. }
        ));

        // Before unbonding completes: settle_unlocks is a no-op.
        assert!(reg.settle_unlocks(exit_epoch + 1).is_empty());
        assert!(reg.settle_unlocks(exit_epoch + 4).is_empty());

        // At exit_epoch + unbonding_epochs (=5 in smoke config): settles.
        let settled = reg.settle_unlocks(exit_epoch + 5);
        assert_eq!(settled.len(), 1);
        assert_eq!(settled[0].0, vid);
        assert_eq!(reg.get(&vid).unwrap().state, ValidatorState::Unlocked);

        // Executor materializes the unlocked stake as a reward UTXO.
        let before_count = ex.utxo_set().len();
        ex.apply_settled_unlocks(&settled, exit_epoch + 5);
        assert!(
            ex.utxo_set().len() > before_count,
            "apply_settled_unlocks must create a reward UTXO"
        );

        // Second settle in the same epoch: idempotent no-op.
        assert!(reg.settle_unlocks(exit_epoch + 5).is_empty());
    }

    // ─── Test 4: feature gate closed ──────────────────────────────────

    #[test]
    fn phase10_stake_register_rejected_when_feature_inactive() {
        let kp = MlDsaKeypair::generate();
        let vid = validator_id_of(&kp);

        // NO enable_on_chain_staking_for_tests — simulates production default.
        let app_id = AppId::new(2, [0u8; 32]);
        let mut ex = crate::utxo_executor::UtxoExecutor::with_utxo_set(UtxoSet::new(1000), app_id);
        let mut reg = StakingRegistry::new(smoke_staking_config());

        let input_ref = OutputRef {
            tx_hash: [0xFF; 32],
            output_index: 0,
        };
        seed_utxo(&mut ex, input_ref.clone(), 11_000);

        let env = make_register_envelope(&kp, vid, (input_ref.clone(), 11_000));
        let raw = wrap_stake_deposit(&env, &input_ref, vid);

        let result = ex.execute_committed(1, &[raw], None, Some(&mut reg), 0);
        assert_eq!(
            result.txs_accepted, 0,
            "feature gate must reject before the registry is touched"
        );
        assert_eq!(result.txs_rejected, 1);
        assert!(
            reg.get(&vid).is_none(),
            "registry must be untouched when the gate rejects"
        );
    }

    // ─── Test 5: full epoch-boundary pipeline ─────────────────────────
    //
    // Exercises the ordering that the narwhal commit loop (Group 2 +
    // γ-5 + Phase 8 hot-reload) applies at an epoch boundary:
    //   1. settle_unlocks drops an EXITING validator past unbonding
    //   2. auto_activate_locked promotes a freshly-LOCKED validator
    //   3. SR21 election accepts the new ACTIVE set
    //   4. build_committee_from_sources produces the post-boundary committee
    //
    // The test checks membership shape — not proposer selection.

    #[test]
    fn phase10_full_epoch_boundary_pipeline() {
        let kp_new = MlDsaKeypair::generate();
        let vid_new = validator_id_of(&kp_new);

        let mut ex = new_executor();
        let mut reg = StakingRegistry::new(smoke_staking_config());

        // --- Seed a prior validator that's about to unlock -----------
        let kp_old = MlDsaKeypair::generate();
        let vid_old = validator_id_of(&kp_old);
        let old_input = OutputRef {
            tx_hash: [0x10; 32],
            output_index: 0,
        };
        seed_utxo(&mut ex, old_input.clone(), 11_000);
        ex.execute_committed(
            1,
            &[wrap_stake_deposit(
                &make_register_envelope(&kp_old, vid_old, (old_input.clone(), 11_000)),
                &old_input,
                vid_old,
            )],
            None,
            Some(&mut reg),
            0,
        );
        reg.auto_activate_locked(1);
        // Begin exit at epoch 10.
        let exit_input = OutputRef {
            tx_hash: [0x11; 32],
            output_index: 0,
        };
        seed_utxo(&mut ex, exit_input.clone(), 2_000);
        ex.execute_committed(
            2,
            &[wrap_stake_withdraw(
                &make_begin_exit_envelope(&kp_old, vid_old),
                &exit_input,
            )],
            None,
            Some(&mut reg),
            10,
        );
        assert!(matches!(
            reg.get(&vid_old).unwrap().state,
            ValidatorState::Exiting { .. }
        ));

        // --- Register a new validator (LOCKED) -----------------------
        let new_input = OutputRef {
            tx_hash: [0x20; 32],
            output_index: 0,
        };
        seed_utxo(&mut ex, new_input.clone(), 11_000);
        ex.execute_committed(
            3,
            &[wrap_stake_deposit(
                &make_register_envelope(&kp_new, vid_new, (new_input.clone(), 11_000)),
                &new_input,
                vid_new,
            )],
            None,
            Some(&mut reg),
            14,
        );
        assert_eq!(reg.get(&vid_new).unwrap().state, ValidatorState::Locked);

        // --- Epoch boundary at epoch 15 (exit_epoch=10 + unbonding=5) -
        let epoch = 15u64;

        // (a) settle_unlocks retires vid_old.
        let settled = reg.settle_unlocks(epoch);
        assert_eq!(settled.len(), 1);
        assert_eq!(settled[0].0, vid_old);
        ex.apply_settled_unlocks(&settled, epoch);
        assert_eq!(reg.get(&vid_old).unwrap().state, ValidatorState::Unlocked);

        // (b) auto_activate_locked promotes vid_new.
        let activated = reg.auto_activate_locked(epoch);
        assert_eq!(activated, vec![vid_new]);
        assert_eq!(reg.get(&vid_new).unwrap().state, ValidatorState::Active);

        // (c) SR21 projection + election pick up the post-boundary ACTIVE set.
        let identities = crate::sr21_election::registry_to_validator_identities(&reg);
        assert_eq!(
            identities.len(),
            1,
            "only vid_new is ACTIVE after the boundary"
        );
        assert_eq!(identities[0].validator_id, vid_new);
        let election = crate::sr21_election::run_election_with_min_stake(&identities, 0u128, epoch);
        assert_eq!(election.num_active, 1);
        assert_eq!(election.active_srs[0].validator_id, vid_new);

        // (d) build_committee_from_sources with an empty genesis — the
        //     committee is built solely from the dynamic-registry side.
        //     BFT constructor requires ≥1 authority and total_stake > 0,
        //     both satisfied here.
        //
        //     We cannot call build_committee_from_sources with a truly
        //     empty GenesisCommitteeManifest (the helper requires at
        //     least the BFT invariant to hold), so we stop after
        //     asserting the election result. The Phase 8 tests in
        //     genesis_committee cover the merge path itself.
        //     This test validates the ORDERING (settle → activate →
        //     election) and the state transitions end-to-end.
    }
}
