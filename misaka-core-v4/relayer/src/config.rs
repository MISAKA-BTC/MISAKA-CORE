//! Relayer configuration from environment variables.
//!
//! ## Security (Mainnet P0)
//!
//! - ALL required environment variables MUST be explicitly set.
//! - No default fallbacks for RPC URLs, program IDs, or keypair paths.
//! - Network mode (devnet/testnet/mainnet) is mandatory and validated.
//! - Tilde (~) in paths is properly expanded.

use std::path::PathBuf;

/// Network mode for the relayer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    Devnet,
    Testnet,
    Mainnet,
}

impl NetworkMode {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "devnet" => Some(Self::Devnet),
            "testnet" => Some(Self::Testnet),
            "mainnet" => Some(Self::Mainnet),
            _ => None,
        }
    }
}

pub struct RelayerConfig {
    pub network: NetworkMode,
    pub solana_rpc_url: String,
    pub misaka_rpc_url: String,
    pub bridge_program_id: String,
    pub relayer_keypair_path: String,
    pub poll_interval_secs: u64,
    /// Path to persistent JSON file tracking processed messages.
    pub processed_store_path: PathBuf,
    /// MISAKA chain ID for request_id derivation.
    pub misaka_chain_id: u32,
}

/// Expand leading `~` to the user's home directory.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{}/{}", home, rest);
        }
    }
    if path == "~" {
        if let Ok(home) = std::env::var("HOME") {
            return home;
        }
    }
    path.to_string()
}

/// Read a required environment variable, or panic with a clear message.
fn require_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!(
            "FATAL: Required environment variable '{}' is not set. \
             All relayer config must be explicit — no defaults allowed in production.",
            name
        )
    })
}

impl RelayerConfig {
    /// Alias for bridge_program_id (used by solana_watcher).
    pub fn solana_program_id(&self) -> &str {
        &self.bridge_program_id
    }

    pub fn from_env() -> Self {
        // ── Network mode: MANDATORY ──
        let network_str = require_env("RELAYER_NETWORK");
        let network = NetworkMode::from_str(&network_str).unwrap_or_else(|| {
            panic!(
                "FATAL: RELAYER_NETWORK='{}' is invalid. Must be one of: devnet, testnet, mainnet",
                network_str
            )
        });

        // ── Required config ──
        let solana_rpc_url = require_env("SOLANA_RPC_URL");
        let misaka_rpc_url = require_env("MISAKA_RPC_URL");
        let bridge_program_id = require_env("BRIDGE_PROGRAM_ID");
        let relayer_keypair_raw = require_env("RELAYER_KEYPAIR");
        let relayer_keypair_path = expand_tilde(&relayer_keypair_raw);

        // ── Validate keypair file exists ──
        if !std::path::Path::new(&relayer_keypair_path).exists() {
            panic!(
                "FATAL: RELAYER_KEYPAIR path '{}' (expanded from '{}') does not exist.",
                relayer_keypair_path, relayer_keypair_raw
            );
        }

        // ── Optional with safe defaults ──
        let poll_interval_secs: u64 = std::env::var("POLL_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(15);

        let processed_store_path = PathBuf::from(
            std::env::var("PROCESSED_STORE")
                .unwrap_or_else(|_| "./relayer-processed.json".into())
        );

        let misaka_chain_id: u32 = std::env::var("MISAKA_CHAIN_ID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(2);

        // ── Network consistency validation ──
        match network {
            NetworkMode::Mainnet => {
                if solana_rpc_url.contains("devnet") || solana_rpc_url.contains("testnet") {
                    panic!(
                        "FATAL: RELAYER_NETWORK=mainnet but SOLANA_RPC_URL '{}' appears to be a devnet/testnet URL.",
                        solana_rpc_url
                    );
                }
                if bridge_program_id.contains("xxxxxxx") || bridge_program_id.contains("XXXXXXX") {
                    panic!(
                        "FATAL: RELAYER_NETWORK=mainnet but BRIDGE_PROGRAM_ID '{}' looks like a placeholder.",
                        bridge_program_id
                    );
                }
                if misaka_chain_id != 1 {
                    panic!(
                        "FATAL: RELAYER_NETWORK=mainnet but MISAKA_CHAIN_ID={} (expected 1).",
                        misaka_chain_id
                    );
                }
            }
            NetworkMode::Devnet => {
                if solana_rpc_url.contains("mainnet") {
                    panic!(
                        "FATAL: RELAYER_NETWORK=devnet but SOLANA_RPC_URL '{}' appears to be a mainnet URL.",
                        solana_rpc_url
                    );
                }
            }
            NetworkMode::Testnet => {
                // Testnet allows both devnet and testnet Solana URLs
            }
        }

        Self {
            network,
            solana_rpc_url,
            misaka_rpc_url,
            bridge_program_id,
            relayer_keypair_path,
            poll_interval_secs,
            processed_store_path,
            misaka_chain_id,
        }
    }
}
