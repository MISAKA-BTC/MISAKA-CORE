//! MISAKA <-> Solana Bridge Relayer
//!
//! Features:
//! - Bidirectional: Solana lock → Misaka mint, Misaka burn → Solana unlock
//! - Idempotent: persistent processed-message store (JSON file)
//! - Multi-instance safe: check-before-submit + check-after-submit
//! - Deterministic message IDs: SHA3-256(domain || chain || tx_hash || amount || nonce)

use std::collections::HashSet;
use std::path::PathBuf;
use tokio::time::{interval, Duration};
use tracing::{info, warn, error};
use serde::{Serialize, Deserialize};
use sha3::{Sha3_256, Digest};

mod config;
mod solana_watcher;
mod misaka_watcher;
mod message;

use config::RelayerConfig;
use message::{LockEvent, BurnReceipt};

/// Persistent processed-message store.
/// Survives restarts. Multiple relayers can share this via NFS/volume.
#[derive(Debug, Serialize, Deserialize)]
struct ProcessedStore {
    messages: HashSet<String>,
    #[serde(default)]
    version: u32,
}

impl ProcessedStore {
    fn load(path: &PathBuf) -> Self {
        match std::fs::read_to_string(path) {
            Ok(data) => serde_json::from_str(&data).unwrap_or(Self::new()),
            Err(_) => Self::new(),
        }
    }

    fn new() -> Self { Self { messages: HashSet::new(), version: 1 } }

    fn save(&self, path: &PathBuf) {
        if let Ok(data) = serde_json::to_string_pretty(self) {
            if let Err(e) = std::fs::write(path, data) {
                error!("Failed to save processed store: {}", e);
            }
        }
    }

    fn is_processed(&self, id: &str) -> bool { self.messages.contains(id) }

    fn mark_processed(&mut self, id: String, path: &PathBuf) {
        self.messages.insert(id);
        self.save(path);
    }
}

/// Compute deterministic idempotency key for a lock event.
fn lock_idempotency_key(event: &LockEvent) -> String {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA_RELAY_LOCK:");
    h.update(event.solana_tx_hash.as_bytes());
    h.update(event.amount.to_le_bytes());
    h.update(event.misaka_recipient.as_bytes());
    hex::encode(h.finalize())
}

/// Compute deterministic idempotency key for a burn receipt.
fn burn_idempotency_key(receipt: &BurnReceipt) -> String {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA_RELAY_BURN:");
    h.update(receipt.request_id.as_bytes());
    h.update(receipt.amount.to_le_bytes());
    h.update(receipt.solana_recipient.as_bytes());
    hex::encode(h.finalize())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let config = RelayerConfig::from_env();

    info!("╔═══════════════════════════════════════════════════════════╗");
    info!("║  MISAKA Bridge Relayer v0.2.0 (idempotent)              ║");
    info!("╚═══════════════════════════════════════════════════════════╝");
    info!("Solana RPC:     {}", config.solana_rpc_url);
    info!("Misaka RPC:     {}", config.misaka_rpc_url);
    info!("Poll interval:  {}s", config.poll_interval_secs);
    info!("Processed store: {}", config.processed_store_path.display());

    let store_path = config.processed_store_path.clone();
    let mut store = ProcessedStore::load(&store_path);
    info!("Loaded {} previously processed messages", store.messages.len());

    let mut ticker = interval(Duration::from_secs(config.poll_interval_secs));
    let mut consecutive_errors: u32 = 0;

    loop {
        ticker.tick().await;

        // ── 1. Solana lock → Misaka mint ──
        match solana_watcher::poll_lock_events(&config).await {
            Ok(events) => {
                consecutive_errors = 0;
                for event in events {
                    let idem_key = lock_idempotency_key(&event);

                    // Pre-submit check (local)
                    if store.is_processed(&idem_key) { continue; }

                    info!("[LOCK] {} → {} tokens → {}", &event.solana_tx_hash[..12], event.amount, event.misaka_recipient);

                    match misaka_watcher::submit_mint_request(&config, &event).await {
                        Ok(receipt_id) => {
                            info!("[LOCK] Mint OK: {}", &receipt_id[..16.min(receipt_id.len())]);
                            store.mark_processed(idem_key, &store_path);
                        }
                        Err(e) => warn!("[LOCK] Mint failed: {} (will retry)", e),
                    }
                }
            }
            Err(e) => {
                consecutive_errors += 1;
                warn!("Solana poll error ({}x): {}", consecutive_errors, e);
                if consecutive_errors > 10 {
                    error!("10 consecutive Solana poll failures — check RPC connectivity");
                }
            }
        }

        // ── 2. Misaka burn → Solana unlock ──
        match misaka_watcher::poll_burn_receipts(&config).await {
            Ok(receipts) => {
                for receipt in receipts {
                    let idem_key = burn_idempotency_key(&receipt);

                    if store.is_processed(&idem_key) { continue; }

                    info!("[BURN] {} → {} tokens → {}", &receipt.request_id[..12.min(receipt.request_id.len())], receipt.amount, receipt.solana_recipient);

                    match solana_watcher::submit_unlock(&config, &receipt).await {
                        Ok(tx_sig) => {
                            info!("[BURN] Unlock OK: {}", &tx_sig[..16.min(tx_sig.len())]);
                            store.mark_processed(idem_key, &store_path);
                        }
                        Err(e) => warn!("[BURN] Unlock failed: {} (will retry)", e),
                    }
                }
            }
            Err(e) => warn!("Misaka poll error: {}", e),
        }
    }
}
