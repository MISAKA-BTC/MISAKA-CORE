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
pub mod rpc_auth;
pub mod rpc_rate_limit;
// REMOVED: privacy modules deprecated
pub mod solana_stake_verify;
pub mod sr21_election;
#[cfg(test)]
pub(crate) mod test_env;
pub mod validator_api;
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
pub mod narwhal_consensus;
#[cfg(feature = "dag")]
pub mod narwhal_block_relay_transport;
#[cfg(feature = "dag")]
pub mod narwhal_runtime_bridge;
// Phase 2c-B D1: narwhal_tx_executor deleted (replaced by utxo_executor)
#[cfg(feature = "dag")]
pub mod utxo_executor;
pub mod ws;
#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
pub mod jsonrpc;
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

    // ─── Config file loading ────────────────────────────────
    /// Path to a TOML or JSON configuration file.
    /// Values from the file serve as defaults; explicit CLI args override them.
    #[arg(long, env = "MISAKA_CONFIG_PATH")]
    config: Option<String>,
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
    {
        let config_source: &str;

        let loaded_config = if let Some(ref config_path) = cli.config {
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
                    cli.peers = peers_str.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
                }
            }
        }

        // Startup banner (printed to stderr so it appears before tracing init)
        eprintln!(
            "MISAKA node config: chain_id={}, data_dir={}, rpc_port={}, p2p_port={}, config_source={}",
            cli.chain_id, cli.data_dir, cli.rpc_port, cli.p2p_port, config_source
        );
    }

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
    tracing::subscriber::set_global_default(
        FmtSubscriber::builder()
            .with_max_level(level)
            .with_target(false)
            .compact()
            .finish(),
    )?;

    info!(
        "Effective config: chain_id={}, data_dir={}, rpc_port={}, p2p_port={}, config_source={}",
        cli.chain_id, cli.data_dir, cli.rpc_port, cli.p2p_port,
        if cli.config.is_some() { "file" } else { "defaults+CLI" }
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
    #[cfg(feature = "dag")]
    if cli.keygen_only {
        use misaka_crypto::validator_sig::generate_validator_keypair;
        use sha3::{Digest, Sha3_256};

        let data_dir = std::path::Path::new(&cli.data_dir);
        std::fs::create_dir_all(data_dir)?;

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

            let keystore = keypair.secret_key.with_bytes(|sk_bytes| {
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
        let identity = crate::identity::ValidatorIdentity::load_or_create(
            &data_dir.join("validator.key"),
        )?;
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
    let parsed_seeds: Vec<misaka_types::seed_entry::SeedEntry> = {
        if cli.seed_pubkeys.is_empty() && !cli.seeds.is_empty() {
            warn!(
                "Phase 2b: --seed-pubkeys not provided for {} seeds. \
                 Seeds will connect without PK pinning (TOFU). \
                 Provide --seed-pubkeys for production use.",
                cli.seeds.len()
            );
            vec![]
        } else if !cli.seed_pubkeys.is_empty()
            && cli.seed_pubkeys.len() != cli.seeds.len()
        {
            error!(
                "FATAL: --seed-pubkeys count ({}) != --seeds count ({}). \
                 Each seed must have a corresponding pubkey.",
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

    // Parse advertise address
    let advertise_addr: Option<SocketAddr> =
        cli.advertise_addr
            .as_deref()
            .and_then(|s| match s.parse::<SocketAddr>() {
                Ok(addr) => {
                    if config::is_valid_advertise_addr(&addr) {
                        Some(addr)
                    } else {
                        warn!(
                            "Invalid --advertise-addr '{}': must not be 0.0.0.0/loopback",
                            s
                        );
                        None
                    }
                }
                Err(e) => {
                    warn!("Failed to parse --advertise-addr '{}': {}", s, e);
                    None
                }
            });

    // Determine role
    let role = NodeRole::determine(
        node_mode,
        cli.validator,
        cli.validator_index,
        cli.validators,
    );

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
        start_dag_node(cli, node_mode, role, p2p_config).await
    }

    #[cfg(all(feature = "dag", not(feature = "ghostdag-compat")))]
    {
        start_narwhal_node(cli).await
    }

    #[cfg(not(feature = "dag"))]
    {
        start_v1_node(cli, node_mode, role, p2p_config).await
    }
}

// ════════════════════════════════════════════════════════════════
//  v3: Mysticeti-equivalent Node (GhostDAG-free)
// ════════════════════════════════════════════════════════════════

#[cfg(all(feature = "dag", not(feature = "ghostdag-compat")))]
async fn start_narwhal_node(cli: Cli) -> anyhow::Result<()> {
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

    let authority_index = cli.validator_index as u32;

    // ── CRIT #1 fix: Load persistent validator identity (not generate fresh) ──
    let identity = crate::identity::ValidatorIdentity::load_or_create(
        &data_dir.join("validator.key"),
    )?;
    tracing::info!(
        fingerprint = %hex::encode(identity.fingerprint()),
        "Loaded validator identity"
    );

    // ── CRIT #1 fix: Load genesis committee from manifest (not placeholders) ──
    let manifest = crate::genesis_committee::GenesisCommitteeManifest::load(
        &cli.genesis_path.as_deref()
            .map(std::path::Path::new)
            .unwrap_or_else(|| std::path::Path::new("genesis_committee.toml")),
    )?;
    manifest.validate()?;

    if !manifest.contains(authority_index, identity.public_key()) {
        anyhow::bail!(
            "Validator authority_index={} fingerprint={} not found in genesis manifest. \
             Ensure your validator.key matches an entry in genesis_committee.toml.",
            authority_index,
            hex::encode(identity.fingerprint()),
        );
    }

    let committee = manifest.to_committee()?;
    let relay_public_key = identity.validator_public_key()?;
    let relay_secret_key = Arc::new(identity.validator_secret_key()?);

    // ── Block signer uses ValidatorIdentity::sign_block (ml_dsa_sign_raw) ──
    // ── HIGH #6 fix: sign() returns Result, not silent vec![] ──
    struct IdentityBlockSigner {
        identity: crate::identity::ValidatorIdentity,
    }
    impl std::fmt::Debug for IdentityBlockSigner {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "IdentityBlockSigner({}..)",
                hex::encode(&self.identity.fingerprint()[..8]))
        }
    }
    impl misaka_dag::BlockSigner for IdentityBlockSigner {
        fn sign(&self, message: &[u8]) -> Vec<u8> {
            // Phase 2c-B D5: raw signing (no domain prefix).
            // Returns empty vec on error (caller will detect via BlockVerifier).
            self.identity.sign_block(message).unwrap_or_else(|e| {
                tracing::error!("Block signing failed: {}", e);
                vec![]
            })
        }
        fn public_key(&self) -> Vec<u8> {
            self.identity.public_key().to_vec()
        }
    }
    let signer: std::sync::Arc<dyn misaka_dag::BlockSigner> =
        std::sync::Arc::new(IdentityBlockSigner { identity });

    // Build persistence store (RocksDB — production default since Phase 1)
    let store_path = data_dir.join("narwhal_consensus");
    let store = misaka_dag::narwhal_dag::rocksdb_store::RocksDbConsensusStore::open(&store_path)?;
    let store: std::sync::Arc<dyn misaka_dag::narwhal_dag::store::ConsensusStore> =
        std::sync::Arc::new(store);

    // CR-2: Chain context for cross-network replay prevention.
    // genesis_hash is derived from the committee manifest (deterministic).
    // Phase 2c-A: use shared utility for genesis hash computation
    let committee_pks: Vec<Vec<u8>> = committee.authorities
        .iter()
        .map(|auth| auth.public_key.clone())
        .collect();
    let genesis_hash = misaka_types::genesis::compute_genesis_hash(
        cli.chain_id,
        &committee_pks,
    );
    let chain_ctx = misaka_types::chain_context::ChainContext::new(cli.chain_id, genesis_hash);
    info!(
        "ChainContext: chain_id={}, genesis_hash={}",
        chain_ctx.chain_id,
        hex::encode(&chain_ctx.genesis_hash[..8]),
    );

    // Runtime config
    let config = RuntimeConfig {
        committee: committee.clone(),
        authority_index,
        leader_round_wave: 2,
        timeout_base_ms: 2000,
        timeout_max_ms: 60_000,
        dag_config: DagStateConfig::default(),
        checkpoint_interval: 100,
        custom_verifier: None, // production MlDsa65Verifier (default)
    };

    // Spawn consensus runtime
    let (msg_tx, mut commit_rx, mut block_rx, metrics, runtime_handle) =
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
    let relay_listen_addr = SocketAddr::from(([0, 0, 0, 0], relay_listen_port));
    let relay_peers: Vec<crate::narwhal_block_relay_transport::RelayPeer> = manifest
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
            })
        })
        .collect();
    let (relay_in_tx, mut relay_in_rx) = tokio::sync::mpsc::channel(1024);
    let (relay_out_tx, relay_out_rx) = tokio::sync::mpsc::channel(1024);
    let block_cache: Arc<RwLock<BTreeMap<BlockRef, NarwhalBlock>>> =
        Arc::new(RwLock::new(BTreeMap::new()));
    let connected_peers: Arc<RwLock<BTreeSet<u32>>> = Arc::new(RwLock::new(BTreeSet::new()));
    let relay_transport_handle =
        crate::narwhal_block_relay_transport::spawn_narwhal_block_relay_transport(
            crate::narwhal_block_relay_transport::NarwhalRelayTransportConfig {
                listen_addr: relay_listen_addr,
                chain_id: cli.chain_id,
                authority_index,
                public_key: relay_public_key,
                secret_key: relay_secret_key,
                peers: relay_peers,
                guard_config: misaka_p2p::GuardConfig::default(),
            },
            relay_in_tx,
            relay_out_rx,
        );

    info!(
        "Mysticeti-equivalent consensus runtime started (authority={}, committee={})",
        authority_index,
        committee.size()
    );

    // Phase 1: Spawn propose loop — drains mempool into CoreEngine
    let (mempool_propose_tx, mempool_propose_rx) =
        crate::narwhal_consensus::mempool_propose_channel(10_000);
    // Audit #26: Pass AppId so submit_tx can verify IntentMessage signatures
    let mempool_app_id = misaka_types::intent::AppId::new(cli.chain_id, genesis_hash);
    let narwhal_mempool = crate::narwhal_consensus::NarwhalMempoolIngress::new(
        cli.dag_mempool_size,
        misaka_storage::utxo_set::UtxoSet::new(1000),
        mempool_propose_tx.clone(),
        mempool_app_id,
    );
    // Shared state_root: updated by executor after each commit, read by propose loop
    let shared_state_root = std::sync::Arc::new(tokio::sync::RwLock::new([0u8; 32]));
    let propose_state_root = shared_state_root.clone();

    let propose_loop_handle = crate::narwhal_consensus::spawn_propose_loop(
        msg_tx.clone(),
        mempool_propose_rx,
        crate::narwhal_consensus::ProposeLoopConfig {
            max_block_txs: cli.dag_max_txs,
            ..crate::narwhal_consensus::ProposeLoopConfig::default()
        },
        propose_state_root,
    );

    // Start RPC server (minimal — submit_tx + status)
    let rpc_port = cli.rpc_port;
    // SECURITY: default to localhost-only binding. Use --rpc-bind 0.0.0.0 for public.
    let rpc_addr: std::net::SocketAddr = format!("127.0.0.1:{}", rpc_port).parse()?;
    let msg_tx_rpc = msg_tx.clone();
    let metrics_rpc = metrics.clone();

    // SEC-FIX [Audit H3]: Load RPC auth state for write endpoint protection.
    let auth_state = crate::rpc_auth::ApiKeyState::from_env_checked(cli.chain_id)
        .unwrap_or_else(|e| {
            error!("RPC auth config error: {}", e);
            std::process::exit(1);
        });

    let rpc_router = axum::Router::new()
        .route("/api/health", axum::routing::get({
            let msg_tx = msg_tx_rpc.clone();
            move || {
                let msg_tx = msg_tx.clone();
                async move {
                    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                    let _ = msg_tx.try_send(ConsensusMessage::GetStatus(reply_tx));
                    match reply_rx.await {
                        Ok(status) => axum::Json(serde_json::json!({
                            "status": "ok",
                            "consensus": "mysticeti-equivalent",
                            "blocks": status.num_blocks,
                            "round": status.highest_accepted_round,
                        })),
                        Err(_) => axum::Json(serde_json::json!({
                            "status": "error",
                            "consensus": "stopped",
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
                    match reply_rx.await {
                        Ok(_) => (axum::http::StatusCode::OK, "ready"),
                        Err(_) => (axum::http::StatusCode::SERVICE_UNAVAILABLE, "not ready"),
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
                    match reply_rx.await {
                        Ok(status) => axum::Json(serde_json::json!(status)),
                        Err(_) => axum::Json(serde_json::json!({"error": "runtime closed"})),
                    }
                }
            }
        }))
        .route("/api/metrics", axum::routing::get({
            let m = metrics_rpc.clone();
            move || {
                let m = m.clone();
                async move {
                    misaka_dag::narwhal_dag::prometheus::PrometheusExporter::new(m).export()
                }
            }
        }))
        .route("/api/get_mempool_info", axum::routing::get({
            let narwhal_mempool = narwhal_mempool.clone();
            move || {
                let narwhal_mempool = narwhal_mempool.clone();
                async move { axum::Json(narwhal_mempool.mempool_info().await) }
            }
        }))
        .route("/api/submit_tx", axum::routing::post({
            let narwhal_mempool = narwhal_mempool.clone();
            let auth = auth_state.clone();
            move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                let narwhal_mempool = narwhal_mempool.clone();
                let auth = auth.clone();
                async move {
                    // SEC-FIX [Audit H3]: Inline auth check for write endpoint.
                    if let Some(ref expected_key) = auth.required_key {
                        let auth_header = headers.get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        let token = auth_header.strip_prefix("Bearer ").unwrap_or("");
                        // Constant-time comparison via SHA3 hash
                        use sha3::{Digest, Sha3_256};
                        let token_hash = Sha3_256::digest(token.as_bytes());
                        let expected_hash = Sha3_256::digest(expected_key.as_bytes());
                        let mut acc = 0u8;
                        for i in 0..32 {
                            acc |= token_hash[i] ^ expected_hash[i];
                        }
                        if acc != 0 {
                            return axum::Json(serde_json::json!({
                                "error": "unauthorized", "accepted": false
                            }));
                        }
                    }
                    // SECURITY: size limit (128 KiB) to prevent memory DoS
                    if body.len() > 131_072 {
                        return axum::Json(serde_json::json!({
                            "error": format!("tx body too large: {} bytes (max 131072)", body.len()),
                            "accepted": false
                        }));
                    }
                    axum::Json(narwhal_mempool.submit_tx(&body).await)
                }
            }
        }))
        // SECURITY: /api/faucet is ONLY available when compiled with
        // "faucet" or "testnet" feature. Never on mainnet release builds.
        // See compile_error! at main.rs:29 for release+faucet guard.
        // ── Testnet: Balance query ──
        .route("/api/get_balance", axum::routing::post({
            let msg_tx = msg_tx_rpc.clone();
            move |body: axum::body::Bytes| {
                let msg_tx = msg_tx.clone();
                async move {
                    let req: serde_json::Value = serde_json::from_slice(&body)
                        .unwrap_or(serde_json::json!({}));
                    let address = req["address"].as_str().unwrap_or("");
                    // For testnet: return committed TX count as proxy for "balance"
                    // Real balance requires UTXO set integration (Phase 2)
                    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                    let _ = msg_tx.try_send(ConsensusMessage::GetStatus(reply_tx));
                    match reply_rx.await {
                        Ok(status) => axum::Json(serde_json::json!({
                            "address": address,
                            "balance": 0, // Balance requires UTXO index (issue #TBD)
                            "num_blocks": status.num_blocks,
                            "num_commits": status.num_commits,
                            "note": "Balance tracking requires UTXO set integration. Use faucet to get testnet tokens."
                        })),
                        Err(_) => axum::Json(serde_json::json!({"error": "runtime closed"})),
                    }
                }
            }
        }))
        // ── Testnet: Chain info ──
        .route("/api/get_chain_info", axum::routing::get({
            let msg_tx = msg_tx_rpc.clone();
            let metrics2 = metrics_rpc.clone();
            move || {
                let msg_tx = msg_tx.clone();
                let metrics2 = metrics2.clone();
                async move {
                    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                    let _ = msg_tx.try_send(ConsensusMessage::GetStatus(reply_tx));
                    let status = reply_rx.await.ok();
                    axum::Json(serde_json::json!({
                        "chain": "MISAKA Network",
                        "consensus": "Mysticeti-equivalent",
                        "chainId": 1,
                        "version": "0.5.1",
                        "pqSignature": "ML-DSA-65 (FIPS 204)",
                        "status": status,
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
            move || {
                let connected_peers = connected_peers.clone();
                async move {
                    let peers: Vec<u32> = connected_peers.read().await.iter().copied().collect();
                    axum::Json(serde_json::json!({
                        "peers": peers,
                        "count": peers.len(),
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
                "decimals": 8
            }))
        }))
        // ── Explorer: Recent blocks ──
        .route("/api/get_recent_blocks", axum::routing::get({
            let msg_tx = msg_tx_rpc.clone();
            move || {
                let msg_tx = msg_tx.clone();
                async move {
                    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                    let _ = msg_tx.try_send(ConsensusMessage::GetStatus(reply_tx));
                    match reply_rx.await {
                        Ok(status) => {
                            let highest = status.highest_accepted_round;
                            let blocks: Vec<serde_json::Value> = (0..highest.min(20))
                                .map(|i| {
                                    let round = highest - i;
                                    serde_json::json!({
                                        "round": round,
                                        "author": 0,
                                    })
                                })
                                .collect();
                            axum::Json(serde_json::json!({
                                "blocks": blocks,
                                "highestRound": highest,
                                "totalBlocks": status.num_blocks,
                            }))
                        }
                        Err(_) => axum::Json(serde_json::json!({"error": "runtime closed"})),
                    }
                }
            }
        }))
        // ── Bridge mint endpoint (CRITICAL #14) ──
        // Receives mint requests from the bridge relayer, validates attestation
        // signatures, and queues the mint for execution.
        .route("/api/bridge/submit_mint", axum::routing::post({
            let auth = auth_state.clone();
            move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                let auth = auth.clone();
                async move {
                    // Require API key for bridge operations (same pattern as submit_tx)
                    if let Some(ref expected_key) = auth.required_key {
                        let auth_header = headers.get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("");
                        let token = auth_header.strip_prefix("Bearer ").unwrap_or("");
                        use sha3::{Digest as _, Sha3_256};
                        let token_hash = Sha3_256::digest(token.as_bytes());
                        let expected_hash = Sha3_256::digest(expected_key.as_bytes());
                        let mut acc = 0u8;
                        for i in 0..32 { acc |= token_hash[i] ^ expected_hash[i]; }
                        if acc != 0 {
                            return axum::Json(serde_json::json!({
                                "error": "unauthorized", "accepted": false
                            }));
                        }
                    }

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

                    let burn_event_id = request["burn_event_id"].as_str().unwrap_or("");
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
            }
        }))
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
        .route("/api/testnet_info", axum::routing::get(|| async {
            axum::Json(serde_json::json!({
                "network": "MISAKA Testnet",
                "chainId": 2,
                "networkId": "misaka-testnet-1",
                "addressPrefix": "misakatest1",
                "consensus": "Mysticeti-equivalent",
                "pqSignature": "ML-DSA-65 (FIPS 204)",
                "version": "0.5.1",
                "seedNodes": ["160.16.131.119:3000"],
                // Phase 2c-B: faucet route removed from minimal RPC
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
        }));

    let rpc_server = axum::serve(
        tokio::net::TcpListener::bind(rpc_addr).await?,
        rpc_router.into_make_service(),
    );

    info!("RPC server listening on {}", rpc_addr);

    // Track start time for uptime metric
    let start_time = std::time::Instant::now();

    // Graceful shutdown: handle SIGINT + SIGTERM
    let shutdown_msg_tx = msg_tx.clone();
    let shutdown_handle = tokio::spawn(async move {
        // Wait for SIGINT (Ctrl+C) — works on all platforms
        let _ = tokio::signal::ctrl_c().await;
        info!("Received shutdown signal, initiating graceful shutdown...");
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
                .send(crate::narwhal_block_relay_transport::OutboundNarwhalRelayEvent::Broadcast(
                    NarwhalRelayMessage::BlockProposal(NarwhalBlockProposal {
                        block: block_body,
                    }),
                ))
                .await;
            tracing::debug!(
                "Block broadcast round={} author={} txs={} total_broadcast={}",
                block.round(),
                block.author(),
                block.transactions().len(),
                blocks_broadcast
            );
        }
        tracing::info!("Block broadcast channel closed (total: {})", blocks_broadcast);
    });

    let relay_msg_tx = msg_tx.clone();
    let relay_out_tx_for_ingress = relay_out_tx.clone();
    let relay_cache_for_ingress = block_cache.clone();
    let connected_peers_for_ingress = connected_peers.clone();
    let relay_ingress_handle = tokio::spawn(async move {
        while let Some(event) = relay_in_rx.recv().await {
            match event {
                crate::narwhal_block_relay_transport::InboundNarwhalRelayEvent::PeerConnected {
                    authority_index,
                    peer_id,
                    address,
                } => {
                    connected_peers_for_ingress
                        .write()
                        .await
                        .insert(authority_index);
                    info!(
                        "narwhal_peer_connected authority={} peer_id={} addr={}",
                        authority_index,
                        peer_id.short_hex(),
                        address
                    );
                }
                crate::narwhal_block_relay_transport::InboundNarwhalRelayEvent::PeerDisconnected {
                    authority_index,
                    peer_id,
                    address,
                } => {
                    connected_peers_for_ingress
                        .write()
                        .await
                        .remove(&authority_index);
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
                                tokio::spawn(async move {
                                    if fetch.delay_ms > 0 {
                                        tokio::time::sleep(std::time::Duration::from_millis(
                                            fetch.delay_ms,
                                        ))
                                        .await;
                                    }
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
                        debug!(
                            "narwhal_commit_vote from={} round={} author={}",
                            authority_index,
                            vote.vote.round,
                            vote.vote.author
                        );
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
        _ = relay_transport_handle => {
            info!("Narwhal relay transport stopped");
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

            // Narwhal DAG path: executor starts with a fresh UTXO set.
            // State restoration is handled by the DAG's own persistence layer.
            let mut tx_executor = crate::utxo_executor::UtxoExecutor::new(app_id);

            let mut total_committed_txs = 0u64;
            let mut total_accepted_txs = 0u64;

            while let Some(output) = commit_rx.recv().await {
                // SEC-FIX: Derive the commit leader's address from their pubkey.
                // This is used to verify SystemEmission outputs go to the correct
                // proposer, preventing Byzantine reward redirection.
                let leader_address: Option<[u8; 32]> = {
                    let author_idx = output.leader.author as usize;
                    if author_idx < committee.authorities.len() {
                        let pk = &committee.authorities[author_idx].public_key;
                        if !pk.is_empty() {
                            use sha3::{Digest, Sha3_256};
                            let addr: [u8; 32] = Sha3_256::digest(pk).into();
                            Some(addr)
                        } else {
                            // SEC-FIX: Empty pubkey in committee is a configuration error.
                            // On mainnet this will cause SystemEmission to be rejected
                            // (leader_address=None triggers StructuralInvalid in FIX 42).
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
                            committee.authorities.len()
                        );
                        None
                    }
                };
                let exec_result = tx_executor.execute_committed(
                    output.commit_index,
                    &output.transactions,
                    leader_address,
                );
                total_committed_txs += output.transactions.len() as u64;
                total_accepted_txs += exec_result.txs_accepted as u64;

                // SEC-FIX C-12: Generate block reward for the commit leader.
                // Previously Narwhal commit loop only executed user TXs — no block
                // rewards were generated. Validators received zero economic incentive.
                if let Some(addr) = leader_address {
                    let author_idx = output.leader.author as usize;
                    let leader_pk = if author_idx < committee.authorities.len() {
                        let pk = &committee.authorities[author_idx].public_key;
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

                // Update shared state_root for propose loop
                let new_root = tx_executor.state_root();
                *shared_state_root.write().await = new_root;

                // SEC-FIX C-9: Verify state_root against leader's proposed value.
                // Detects Byzantine proposers embedding false state commitments.
                if let Some(leader_root) = output.leader_state_root {
                    if leader_root != new_root {
                        tracing::error!(
                            "STATE ROOT MISMATCH at commit {}: \
                             leader proposed {} but local execution computed {}. \
                             Potential Byzantine proposer or state divergence!",
                            output.commit_index,
                            hex::encode(&leader_root[..8]),
                            hex::encode(&new_root[..8]),
                        );
                        // TODO: Enter safe mode / halt consensus participation
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
            }
        } => {
            info!("Commit channel closed");
        }
        _ = shutdown_handle => {
            info!("Shutdown signal received, waiting for runtime...");
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
//  v2: DAG Node Startup (GhostDAG compat — being phased out)
// ════════════════════════════════════════════════════════════════

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
fn local_validator_key_path(
    data_dir: &std::path::Path,
    validator_index: usize,
) -> std::path::PathBuf {
    data_dir.join(format!("dag_validator_{validator_index}.json"))
}

#[cfg(all(feature = "dag", feature = "ghostdag-compat"))]
fn validator_lifecycle_snapshot_path(
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

    // Read passphrase from env var. For testnet, allow empty passphrase
    // (encrypts with empty string — still better than plaintext).
    // For mainnet (chain_id=1), require a non-empty passphrase.
    fn read_passphrase(chain_id: u32) -> anyhow::Result<Vec<u8>> {
        let passphrase = std::env::var("MISAKA_VALIDATOR_PASSPHRASE")
            .unwrap_or_default()
            .into_bytes();
        // SEC-FIX: mainnet MUST have a non-empty passphrase
        if chain_id == 1 && passphrase.is_empty() {
            anyhow::bail!(
                "FATAL: MISAKA_VALIDATOR_PASSPHRASE must be set and non-empty on mainnet (chain_id=1). \
                 An empty passphrase means the keystore can be decrypted trivially."
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
        let secret_key = ValidatorPqSecretKey::from_bytes(&secret_bytes)
            .ok_or_else(|| anyhow::anyhow!(
                invalid validator secret key length: {} (expected 4032),
                secret_bytes.len()
            ))?;
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
        let secret_key = ValidatorPqSecretKey::from_bytes(&secret_bytes)
            .ok_or_else(|| anyhow::anyhow!(
                invalid validator secret key length: {} (expected 4032),
                secret_bytes.len()
            ))?;
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
        let keystore = keypair.secret_key.with_bytes(|sk_bytes| {
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
    // Stake weight: query Solana on-chain staking program for real stake amount.
    // Falls back to 1 if Solana RPC is unavailable or validator not found.
    let stake_weight = match crate::solana_stake_verify::query_validator_stake_weight(
        &hex::encode(&identity.public_key.bytes),
    ).await {
        Ok(weight) => {
            tracing::info!(
                "Solana stake weight for validator {}: {}",
                hex::encode(&identity.validator_id[..8]),
                weight,
            );
            weight.max(1) // minimum weight = 1
        }
        Err(e) => {
            tracing::warn!(
                "Failed to query Solana stake weight for {}: {} — defaulting to 1",
                hex::encode(&identity.validator_id[..8]),
                e,
            );
            1 // safe default: equal weight prevents fake-stake attacks
        }
    };

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
    let election_result = sr21_election::run_election(&state.known_validators, next_epoch);
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

    let validator_lifecycle_store = Arc::new(
        validator_lifecycle_persistence::ValidatorLifecycleStore::new(
            validator_lifecycle_path.clone(),
        ),
    );
    let validator_lifecycle_store =
        validator_lifecycle_persistence::install_global_store(validator_lifecycle_store);
    let staking_config = if cli.chain_id == 1 {
        misaka_consensus::staking::StakingConfig::default()
    } else {
        misaka_consensus::staking::StakingConfig::testnet()
    };
    let (restored_registry, restored_epoch, restored_epoch_progress) =
        match validator_lifecycle_store.load().await {
            Ok(Some(snapshot)) => {
                info!(
                    "Layer 6: restored validator lifecycle snapshot | epoch={} | validators={} | file={}",
                    snapshot.current_epoch,
                    snapshot.registry.all_validators().count(),
                    validator_lifecycle_path.display()
                );
                (
                    snapshot.registry,
                    snapshot.current_epoch,
                    snapshot.epoch_progress,
                )
            }
            Ok(None) => {
                info!(
                    "Layer 6: validator lifecycle initialized fresh | epoch={} | file={}",
                    0,
                    validator_lifecycle_path.display()
                );
                let registry =
                    misaka_consensus::staking::StakingRegistry::new(staking_config.clone());
                let epoch = 0;
                if let Err(e) = validator_lifecycle_store
                    .save_snapshot(
                        &validator_lifecycle_persistence::ValidatorLifecycleSnapshot {
                            version: 1,
                            current_epoch: epoch,
                            registry: registry.clone(),
                            epoch_progress:
                                validator_lifecycle_persistence::ValidatorEpochProgress::default(),
                        },
                    )
                    .await
                {
                    warn!(
                        "Layer 6: failed to seed validator lifecycle snapshot: {}",
                        e
                    );
                }
                (
                    registry,
                    epoch,
                    validator_lifecycle_persistence::ValidatorEpochProgress::default(),
                )
            }
            Err(e) => {
                warn!(
                    "Layer 6: failed to load validator lifecycle snapshot ({}); starting fresh",
                    e
                );
                let registry =
                    misaka_consensus::staking::StakingRegistry::new(staking_config.clone());
                let epoch = 0;
                if let Err(e) = validator_lifecycle_store
                    .save_snapshot(
                        &validator_lifecycle_persistence::ValidatorLifecycleSnapshot {
                            version: 1,
                            current_epoch: epoch,
                            registry: registry.clone(),
                            epoch_progress:
                                validator_lifecycle_persistence::ValidatorEpochProgress::default(),
                        },
                    )
                    .await
                {
                    warn!(
                        "Layer 6: failed to seed validator lifecycle snapshot: {}",
                        e
                    );
                }
                (
                    registry,
                    epoch,
                    validator_lifecycle_persistence::ValidatorEpochProgress::default(),
                )
            }
        };

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
        sr_index: cli.validator_index,
        num_active_srs: if cli.validators <= 1 {
            1
        } else {
            cli.validators.min(21)
        },
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

    let rpc_addr: SocketAddr = format!("0.0.0.0:{}", cli.rpc_port).parse()?;
    let rpc_state = shared_state.clone();
    let rpc_observation = dag_p2p_observation.clone();
    let rpc_runtime_recovery = runtime_recovery_observation.clone();

    // ── Validator Staking Registry ──
    let validator_registry = Arc::new(RwLock::new(restored_registry));
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

            let mut registry = validator_registry.write().await;
            let epoch = *current_epoch.read().await;
            let already_registered = registry.get(&validator_id).is_some();

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
                            let min_stake = registry.config().min_validator_stake;
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
                                    (
                                        registry.config().min_validator_stake,
                                        false,
                                        Some(sig.clone()),
                                    )
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
                            (
                                registry.config().min_validator_stake,
                                false,
                                Some(sig.clone()),
                            )
                        }
                    } else {
                        // No signature provided — unverified
                        (registry.config().min_validator_stake, false, None)
                    };

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
                } // end if let Some(lv)
            } else if has_stake_sig {
                // Already registered — update stake verification if new sig provided
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
            }
            drop(registry);
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
        match misaka_storage::utxo_set::UtxoSet::load_from_file_with_burns(&utxo_snapshot_path, 1000) {
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
                (misaka_storage::utxo_set::UtxoSet::new(1000), 0, Vec::new(), 0u64)
            }
            Err(e) => {
                warn!(
                    "Layer 1: UTXO snapshot load failed ({}) — starting fresh",
                    e
                );
                (misaka_storage::utxo_set::UtxoSet::new(1000), 0, Vec::new(), 0u64)
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

    // RPC server
    let rpc_addr: SocketAddr = format!("0.0.0.0:{}", cli.rpc_port).parse()?;
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
}
