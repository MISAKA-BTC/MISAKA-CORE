//! Relayer configuration from environment variables.

use std::path::PathBuf;

pub struct RelayerConfig {
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

impl RelayerConfig {
    /// Alias for bridge_program_id (used by solana_watcher).
    pub fn solana_program_id(&self) -> &str {
        &self.bridge_program_id
    }

    pub fn from_env() -> Self {
        Self {
            solana_rpc_url: std::env::var("SOLANA_RPC_URL")
                .unwrap_or_else(|_| "https://api.devnet.solana.com".into()),
            misaka_rpc_url: std::env::var("MISAKA_RPC_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:3001".into()),
            bridge_program_id: std::env::var("BRIDGE_PROGRAM_ID")
                .unwrap_or_else(|_| "MBRDGxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx".into()),
            relayer_keypair_path: std::env::var("RELAYER_KEYPAIR")
                .unwrap_or_else(|_| "~/.config/solana/id.json".into()),
            poll_interval_secs: std::env::var("POLL_INTERVAL")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(15),
            processed_store_path: PathBuf::from(
                std::env::var("PROCESSED_STORE")
                    .unwrap_or_else(|_| "./relayer-processed.json".into())
            ),
            misaka_chain_id: std::env::var("MISAKA_CHAIN_ID")
                .ok().and_then(|s| s.parse().ok()).unwrap_or(2),
        }
    }
}
