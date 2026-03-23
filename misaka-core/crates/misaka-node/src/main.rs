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

// ── P0-1: STARK STUB PHYSICAL EXCLUSION ──
// stark-stub is a development-only ZK placeholder. It MUST NEVER be linked
// into a production binary. This compile_error! makes it physically impossible
// to ship a release build with stub ZK backends.
#[cfg(all(not(debug_assertions), feature = "stark-stub"))]
compile_error!(
    "FATAL: 'stark-stub' feature MUST NOT be compiled in release mode. \
     This feature links placeholder ZK backends that skip real proof verification. \
     Production builds MUST use the real lattice ZKP pipeline. \
     Remove --features stark-stub from your build command."
);

// ── DAG mode: PRODUCTION DEFAULT ──
// The DAG consensus layer has graduated from experimental to default.
// The previous runtime guard (MISAKA_DAG_EXPERIMENTAL=1) has been removed.
//
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
pub mod metrics;
pub mod rpc_auth;
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
#[cfg(not(feature = "dag"))]
pub mod sync;
#[cfg(not(feature = "dag"))]
pub mod sync_relay_transport;

// ── v2 modules (DAG) ──
#[cfg(feature = "dag")]
pub mod dag_p2p_network;
#[cfg(feature = "dag")]
pub mod dag_p2p_surface;
#[cfg(feature = "dag")]
pub mod dag_p2p_transport;
#[cfg(feature = "dag")]
pub mod dag_rpc;

#[cfg(not(feature = "dag"))]
pub use misaka_execution::block_apply::{self, execute_block, rollback_last_block, BlockResult};

use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn, Level};
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

    /// Use the zero-knowledge block path for txs that carry `zk_proof`.
    /// When enabled, TXs with CompositeProof are routed through
    /// execute_block_zero_knowledge for full lattice ZKP verification.
    #[arg(long)]
    experimental_zk_path: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

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

    // Parse NodeMode
    let node_mode = NodeMode::from_str_loose(&cli.mode);

    // ── Runtime Defense-in-Depth: reject dev features on production networks ──
    // This is a SECOND layer after compile_error! guards above.
    // Catches edge cases where debug builds accidentally run against mainnet.
    {
        let is_mainnet = cli.chain_id == 1;
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

        if !dev_features_active.is_empty() {
            warn!(
                "⚠ Dev features active: {:?} — DO NOT use in production!",
                dev_features_active
            );
        }
        if cli.experimental_zk_path {
            info!("ZK block path ENABLED — txs with zk_proof will use CompositeProof verification");
        }
    }

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

    // ════════════════════════════════════════════════════════
    //  分岐: v1 (linear chain) vs v2 (DAG)
    // ════════════════════════════════════════════════════════

    #[cfg(feature = "dag")]
    {
        start_dag_node(cli, node_mode, role, p2p_config).await
    }

    #[cfg(not(feature = "dag"))]
    {
        start_v1_node(cli, node_mode, role, p2p_config).await
    }
}

// ════════════════════════════════════════════════════════════════
//  v2: DAG Node Startup
// ════════════════════════════════════════════════════════════════

#[cfg(feature = "dag")]
fn local_validator_key_path(
    data_dir: &std::path::Path,
    validator_index: usize,
) -> std::path::PathBuf {
    data_dir.join(format!("dag_validator_{validator_index}.json"))
}

#[cfg(feature = "dag")]
fn validator_lifecycle_snapshot_path(
    data_dir: &std::path::Path,
    chain_id: u32,
) -> std::path::PathBuf {
    data_dir.join(format!("validator_lifecycle_chain_{chain_id}.json"))
}

#[cfg(feature = "dag")]
fn load_or_create_local_dag_validator(
    data_dir: &std::path::Path,
    role: NodeRole,
    validator_index: usize,
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

    /// Read passphrase from env var. For testnet, allow empty passphrase
    /// (encrypts with empty string — still better than plaintext).
    /// For mainnet (chain_id=1), require a non-empty passphrase.
    fn read_passphrase() -> Vec<u8> {
        std::env::var("MISAKA_VALIDATOR_PASSPHRASE")
            .unwrap_or_default()
            .into_bytes()
    }

    let keypair_and_identity = if encrypted_path.exists() {
        // ── Load from encrypted keystore ──
        let passphrase = read_passphrase();
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
        let mut validator_id = [0u8; 20];
        if validator_id_vec.len() != 20 {
            anyhow::bail!(
                "invalid validator id length in '{}': expected 20, got {}",
                encrypted_path.display(),
                validator_id_vec.len()
            );
        }
        validator_id.copy_from_slice(&validator_id_vec);

        let public_key = ValidatorPqPublicKey::from_bytes(&hex::decode(&keystore.public_key_hex)?)
            .map_err(anyhow::Error::msg)?;

        let secret_key = ValidatorPqSecretKey {
            pq_sk: secret_bytes,
        };
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
        // ── Migrate plaintext → encrypted ──
        warn!(
            "Layer 2: ⚠ plaintext validator key detected at '{}' — migrating to encrypted format",
            plaintext_path.display()
        );

        let raw = std::fs::read_to_string(&plaintext_path)?;
        let persisted: LocalDagValidatorKeyFile = serde_json::from_str(&raw)?;

        let validator_id_vec = hex::decode(&persisted.validator_id_hex)?;
        let mut validator_id = [0u8; 20];
        if validator_id_vec.len() != 20 {
            anyhow::bail!("invalid validator id in plaintext key file");
        }
        validator_id.copy_from_slice(&validator_id_vec);

        let public_key = ValidatorPqPublicKey::from_bytes(&hex::decode(&persisted.public_key_hex)?)
            .map_err(anyhow::Error::msg)?;

        let secret_bytes = hex::decode(&persisted.secret_key_hex)?;
        let passphrase = read_passphrase();

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

        let secret_key = ValidatorPqSecretKey {
            pq_sk: secret_bytes,
        };
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
            validator_id: keypair.public_key.to_address(),
            stake_weight: 1_000_000,
            public_key: ValidatorPublicKey {
                bytes: keypair.public_key.to_bytes(),
            },
            is_active: true,
        };

        let passphrase = read_passphrase();
        let keystore = encrypt_keystore(
            &keypair.secret_key.pq_sk,
            &hex::encode(&identity.public_key.bytes),
            &hex::encode(identity.validator_id),
            identity.stake_weight,
            &passphrase,
        )
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

#[cfg(feature = "dag")]
fn normalize_experimental_validator_identity(
    identity: &misaka_types::validator::ValidatorIdentity,
) -> anyhow::Result<misaka_types::validator::ValidatorIdentity> {
    use misaka_crypto::validator_sig::ValidatorPqPublicKey;

    let public_key = ValidatorPqPublicKey::from_bytes(&identity.public_key.bytes)
        .map_err(|e| anyhow::anyhow!("invalid validator public key: {}", e))?;
    let expected_id = public_key.to_address();
    if expected_id != identity.validator_id {
        anyhow::bail!(
            "validator identity mismatch: derived={}, declared={}",
            hex::encode(expected_id),
            hex::encode(identity.validator_id)
        );
    }

    Ok(misaka_types::validator::ValidatorIdentity {
        stake_weight: 1,
        is_active: true,
        ..identity.clone()
    })
}

#[cfg(feature = "dag")]
pub(crate) fn dag_validator_set(
    state: &misaka_dag::DagNodeState,
) -> misaka_consensus::ValidatorSet {
    misaka_consensus::ValidatorSet::new(state.known_validators.clone())
}

#[cfg(feature = "dag")]
pub(crate) fn expected_dag_quorum_threshold(validator_count: usize) -> u128 {
    let total = validator_count.max(1) as u128;
    total * 2 / 3 + 1
}

#[cfg(feature = "dag")]
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

#[cfg(feature = "dag")]
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

#[cfg(feature = "dag")]
fn normalize_dag_rpc_peers(peers: &[String]) -> Vec<String> {
    let mut normalized = peers
        .iter()
        .filter_map(|peer| normalize_dag_rpc_peer(peer))
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

#[cfg(feature = "dag")]
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

#[cfg(feature = "dag")]
impl DagRpcValidatorIdentityWire {
    fn into_validator_identity(self) -> anyhow::Result<misaka_types::validator::ValidatorIdentity> {
        use misaka_types::validator::{ValidatorIdentity, ValidatorPublicKey};

        let validator_id_vec = hex::decode(&self.validator_id)?;
        if validator_id_vec.len() != 20 {
            anyhow::bail!(
                "invalid validator id length from RPC peer: expected 20 bytes, got {}",
                validator_id_vec.len()
            );
        }

        let mut validator_id = [0u8; 20];
        validator_id.copy_from_slice(&validator_id_vec);

        let public_key_bytes = hex::decode(&self.public_key_hex)?;
        let public_key = ValidatorPublicKey::from_bytes(&public_key_bytes)
            .map_err(|e| anyhow::anyhow!("invalid validator public key from RPC peer: {}", e))?;
        let stake_weight = self.stake_weight.parse::<u128>().map_err(|e| {
            anyhow::anyhow!("invalid validator stake weight from RPC peer: {}", e)
        })?;

        Ok(ValidatorIdentity {
            validator_id,
            stake_weight,
            public_key,
            is_active: self.is_active,
        })
    }
}

#[cfg(feature = "dag")]
#[derive(Debug, Default, serde::Deserialize)]
struct DagRpcValidatorAttestationWire {
    #[serde(rename = "localValidator")]
    local_validator: Option<DagRpcValidatorIdentityWire>,
    #[serde(rename = "knownValidators", default)]
    known_validators: Vec<DagRpcValidatorIdentityWire>,
}

#[cfg(feature = "dag")]
#[derive(Debug, Default, serde::Deserialize)]
struct DagRpcChainInfoWire {
    #[serde(rename = "validatorAttestation", default)]
    validator_attestation: DagRpcValidatorAttestationWire,
}

#[cfg(feature = "dag")]
fn validator_identity_matches(
    left: &misaka_types::validator::ValidatorIdentity,
    right: &misaka_types::validator::ValidatorIdentity,
) -> bool {
    left.validator_id == right.validator_id
        && left.stake_weight == right.stake_weight
        && left.is_active == right.is_active
        && left.public_key.bytes == right.public_key.bytes
}

#[cfg(feature = "dag")]
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

#[cfg(feature = "dag")]
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

    let mut discovered = BTreeMap::<[u8; 20], misaka_types::validator::ValidatorIdentity>::new();

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

#[cfg(feature = "dag")]
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

#[cfg(feature = "dag")]
fn maybe_spawn_local_vote_gossip(state: &misaka_dag::DagNodeState) {
    if let Some((vote, identity, peers)) = local_vote_gossip_payload(state) {
        tokio::spawn(async move {
            gossip_checkpoint_vote_to_peers(peers, vote, identity).await;
        });
    }
}

#[cfg(feature = "dag")]
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

#[cfg(feature = "dag")]
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

#[cfg(feature = "dag")]
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

#[cfg(feature = "dag")]
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

#[cfg(feature = "dag")]
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

#[cfg(feature = "dag")]
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

#[cfg(feature = "dag")]
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

#[cfg(feature = "dag")]
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

#[cfg(feature = "dag")]
async fn start_dag_node(
    cli: Cli,
    node_mode: NodeMode,
    role: NodeRole,
    _p2p_config: P2pConfig,
) -> anyhow::Result<()> {
    use misaka_dag::{
        dag_block::{DagBlockHeader, DAG_VERSION},
        dag_block_producer::run_dag_block_producer,
        dag_finality::FinalityManager,
        dag_store::ThreadSafeDagStore,
        load_runtime_snapshot, save_runtime_snapshot, DagMempool, DagNodeState, DagStateManager,
        DagStore, GhostDagEngine, UniformStakeProvider, ZERO_HASH,
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
    let reachability = misaka_dag::reachability::ReachabilityStore::new(genesis_hash);
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
        mempool,
        chain_id: cli.chain_id,
        validator_count: cli.validators,
        known_validators,
        proposer_id,
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
    };
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

    // ══════════════════════════════════════════════════════
    //  Layer 5: Network (DAG P2P)
    // ══════════════════════════════════════════════════════

    // ── 5a. Crash-Safe Recovery: WAL scan + rollback ──
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
                    info!("Layer 5: DAG recovery — WAL clean, no rollback needed");
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
    // pre-rollback checkpoint target.
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
                            if guard.local_validator.is_some() && guard.latest_checkpoint.is_some() {
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

    // Spawn the event loop
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
                transport_observation,
            )
            .await;
        });
        info!(
            "Layer 5: DAG P2P PQ-encrypted transport on {} | seeds={} (ML-KEM-768 + ChaCha20-Poly1305)",
            p2p_listen_addr,
            seed_count,
        );
    } else {
        // Non-validator: observation-only outbound consumer
        let _outbound_handle = tokio::spawn(async move {
            while let Some(event) = p2p_outbound_rx.recv().await {
                let target = event
                    .peer_id
                    .map(|id| hex::encode(&id[..4]))
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
            "10M MISAKA"
        } else {
            "10 MISAKA (testnet)"
        }
    );

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
    let _rpc_handle = tokio::spawn(async move {
        if let Err(e) = dag_rpc::run_dag_rpc_server_with_observation(
            rpc_state,
            Some(rpc_observation),
            Some(rpc_runtime_recovery),
            Some(rpc_registry),
            rpc_epoch,
            Some(rpc_epoch_progress),
            rpc_addr,
        )
        .await
        {
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
        info!(
            "Starting DAG block production loop (interval={}s, max_txs={})",
            cli.block_time, cli.dag_max_txs
        );

        // ── Finality monitoring task ──
        let finality_state = shared_state.clone();
        let runtime_recovery = runtime_recovery_observation.clone();
        let finality_interval = cli.dag_checkpoint_interval;
        tokio::spawn(async move {
            run_finality_monitor(finality_state, runtime_recovery, finality_interval).await;
        });

        // ── Block production (メインループ — ブロッキング) ──
        run_dag_block_producer(shared_state.clone(), cli.block_time, cli.dag_max_txs).await;
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
#[cfg(feature = "dag")]
async fn run_finality_monitor(
    state: Arc<RwLock<misaka_dag::DagNodeState>>,
    runtime_recovery: Arc<RwLock<dag_rpc::DagRuntimeRecoveryObservation>>,
    checkpoint_interval: u64,
) {
    use misaka_dag::dag_finality::FinalityManager;
    use misaka_dag::save_runtime_snapshot;
    use misaka_dag::DagStore;

    let initial_checkpoint = {
        let guard = state.read().await;
        guard.latest_checkpoint.clone()
    };
    let mut finality = FinalityManager::new(checkpoint_interval);
    if let Some(checkpoint) = initial_checkpoint {
        finality = finality.with_checkpoint(checkpoint);
    }
    let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(30));

    loop {
        ticker.tick().await;

        let mut guard = state.write().await;
        let snapshot = guard.dag_store.snapshot();
        let max_score = guard.dag_store.max_blue_score();
        let blocked_by_pending_finality = checkpoint_rollover_blocked_by_pending_finality(&guard);
        let should_advance_bucket = finality.should_checkpoint(max_score);
        let should_refresh_pending_target =
            blocked_by_pending_finality && guard.latest_checkpoint.is_some();

        if should_advance_bucket || should_refresh_pending_target {
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
                cp.blue_score, cp.total_applied_txs, cp.total_key_images,
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
        warn!("No valid advertise address — this node will NOT be discoverable. Use --advertise-addr <HOST:PORT>");
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
    let (utxo_set, restored_height) =
        match misaka_storage::utxo_set::UtxoSet::load_from_file(&utxo_snapshot_path, 1000) {
            Ok(Some(restored)) => {
                let h = restored.height;
                info!(
                    "Layer 1: restored UTXO snapshot | height={} | utxos={}",
                    h,
                    restored.len(),
                );
                (restored, h)
            }
            Ok(None) => {
                info!("Layer 1: no UTXO snapshot found — starting fresh");
                (misaka_storage::utxo_set::UtxoSet::new(1000), 0)
            }
            Err(e) => {
                warn!(
                    "Layer 1: UTXO snapshot load failed ({}) — starting fresh",
                    e
                );
                (misaka_storage::utxo_set::UtxoSet::new(1000), 0)
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
    }));

    // Parse peer addresses
    let static_peers: Vec<SocketAddr> = cli.peers.iter().filter_map(|s| s.parse().ok()).collect();

    // Start P2P
    let p2p = Arc::new(p2p_network::P2pNetwork::new(
        cli.chain_id,
        cli.name.clone(),
        p2p_config.clone(),
    ));
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

    #[cfg(feature = "dag")]
    #[test]
    fn test_make_local_checkpoint_vote_binds_checkpoint_target() {
        use misaka_crypto::validator_sig::generate_validator_keypair;
        use misaka_dag::{DagCheckpoint, LocalDagValidator};
        use misaka_types::validator::{ValidatorIdentity, ValidatorPublicKey};

        let keypair = generate_validator_keypair();
        let identity = ValidatorIdentity {
            validator_id: keypair.public_key.to_address(),
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
            total_key_images: 4,
            total_applied_txs: 7,
            timestamp_ms: 1_700_000_000_000,
        };

        let vote = make_local_checkpoint_vote(&local, &checkpoint).unwrap();
        assert_eq!(vote.voter, local.identity.validator_id);
        assert_eq!(vote.target, checkpoint.validator_target());
        assert!(!vote.signature.bytes.is_empty());
    }

    #[cfg(feature = "dag")]
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
            mempool: DagMempool::new(32),
            chain_id: 31337,
            validator_count,
            known_validators: Vec::new(),
            proposer_id: [0xAB; 32],
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
        }
    }

    #[cfg(feature = "dag")]
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
            validator_id: keypair.public_key.to_address(),
            stake_weight,
            public_key: ValidatorPublicKey {
                bytes: keypair.public_key.to_bytes(),
            },
            is_active: true,
        };
        (identity, keypair)
    }

    #[cfg(feature = "dag")]
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

    #[cfg(feature = "dag")]
    fn make_finality_proof_for_checkpoint(
        checkpoint: &misaka_dag::DagCheckpoint,
        votes: Vec<misaka_types::validator::DagCheckpointVote>,
    ) -> misaka_types::validator::DagCheckpointFinalityProof {
        misaka_types::validator::DagCheckpointFinalityProof {
            target: checkpoint.validator_target(),
            commits: votes,
        }
    }

    #[cfg(feature = "dag")]
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
            total_key_images: 4,
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

    #[cfg(feature = "dag")]
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
            total_key_images: 1,
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

    #[cfg(feature = "dag")]
    #[test]
    fn test_prune_checkpoint_attestation_state_discards_stale_targets() {
        use misaka_dag::DagCheckpoint;

        let current_checkpoint = DagCheckpoint {
            block_hash: [0x21; 32],
            blue_score: 11,
            utxo_root: [0x31; 32],
            total_key_images: 2,
            total_applied_txs: 3,
            timestamp_ms: 1_700_000_000_000,
        };
        let stale_checkpoint = DagCheckpoint {
            block_hash: [0x41; 32],
            blue_score: 9,
            utxo_root: [0x51; 32],
            total_key_images: 1,
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

    #[cfg(feature = "dag")]
    #[test]
    fn test_prune_checkpoint_attestation_state_clears_when_checkpoint_missing() {
        use misaka_dag::DagCheckpoint;

        let checkpoint = DagCheckpoint {
            block_hash: [0x61; 32],
            blue_score: 4,
            utxo_root: [0x71; 32],
            total_key_images: 1,
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

    #[cfg(feature = "dag")]
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
            total_key_images: 3,
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

    #[cfg(feature = "dag")]
    #[test]
    fn test_checkpoint_rollover_not_blocked_without_local_validator() {
        use misaka_dag::DagCheckpoint;

        let checkpoint = DagCheckpoint {
            block_hash: [0x81; 32],
            blue_score: 8,
            utxo_root: [0x82; 32],
            total_key_images: 1,
            total_applied_txs: 2,
            timestamp_ms: 1_700_000_000_000,
        };
        let state = make_test_dag_state(2, None, Some(checkpoint));

        assert!(!checkpoint_rollover_blocked_by_pending_finality(&state));
    }

    #[cfg(feature = "dag")]
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
            total_key_images: 1,
            total_applied_txs: 1,
            timestamp_ms: 1_700_000_000_000,
        };

        let mut state = make_test_dag_state(3, Some(local_validator), Some(checkpoint));
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

    #[cfg(feature = "dag")]
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

    #[cfg(feature = "dag")]
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
            total_key_images: 2,
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

    #[cfg(feature = "dag")]
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

    #[cfg(feature = "dag")]
    #[tokio::test]
    async fn test_remote_vote_gossip_forms_live_local_quorum_when_checkpoint_matches() {
        use misaka_dag::{DagCheckpoint, LocalDagValidator};
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let checkpoint = DagCheckpoint {
            block_hash: [0x91; 32],
            blue_score: 77,
            utxo_root: [0x92; 32],
            total_key_images: 5,
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
                Arc::new(RwLock::new(0)),
                None,
                addr,
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

    #[cfg(feature = "dag")]
    #[tokio::test]
    async fn test_discover_checkpoint_validators_from_rpc_peers_reads_local_validator_identity() {
        use misaka_dag::{DagCheckpoint, LocalDagValidator};
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let checkpoint = DagCheckpoint {
            block_hash: [0xA1; 32],
            blue_score: 21,
            utxo_root: [0xA2; 32],
            total_key_images: 1,
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
                Arc::new(RwLock::new(0)),
                None,
                addr,
            )
            .await
            .expect("run dag rpc server");
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let discovered = discover_checkpoint_validators_from_rpc_peers(&[format!(
            "http://{}",
            addr
        )])
        .await;

        server.abort();

        assert_eq!(discovered.len(), 1);
        assert_eq!(discovered[0].validator_id, identity.validator_id);
        assert_eq!(discovered[0].stake_weight, identity.stake_weight);
        assert_eq!(discovered[0].public_key.bytes, identity.public_key.bytes);
    }
}
