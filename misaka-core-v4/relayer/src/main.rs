use tokio::time::{interval, Duration};
use tracing::{error, info, warn};
use sha3::{Digest, Sha3_256};

mod config;
mod solana_watcher;
mod misaka_watcher;
mod message;
mod store;
pub mod error;

use config::RelayerConfig;
use message::{BurnReceipt, LockEvent};
use store::{ClaimResult, SqliteProcessedStore};

fn lock_idempotency_key(event: &LockEvent) -> String {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA_RELAY_LOCK:");
    h.update(event.solana_tx_hash.as_bytes());
    h.update(event.amount.to_le_bytes());
    h.update(event.misaka_recipient.as_bytes());
    h.update(event.asset_id.as_bytes());
    hex::encode(h.finalize())
}

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
    let store_path = config.processed_store_path.with_extension("db");
    let store = SqliteProcessedStore::open(&store_path)?;

    info!("MISAKA Bridge Relayer starting");
    info!("Solana RPC: {}", config.solana_rpc_url);
    info!("Misaka RPC: {}", config.misaka_rpc_url);
    info!("Poll interval: {}s", config.poll_interval_secs);
    info!("Processed store: {}", store_path.display());

    let mut ticker = interval(Duration::from_secs(config.poll_interval_secs));
    let mut solana_errors: u32 = 0;
    let mut misaka_errors: u32 = 0;

    loop {
        ticker.tick().await;

        match solana_watcher::poll_lock_events(&config).await {
            Ok(events) => {
                solana_errors = 0;
                for event in events {
                    let idem_key = lock_idempotency_key(&event);
                    match store.try_claim(&idem_key, "lock", event.amount)? {
                        ClaimResult::AlreadyCompleted | ClaimResult::InProgress => continue,
                        ClaimResult::Claimed => {}
                    }

                    info!(
                        "[LOCK] {} -> {} -> {}",
                        &event.solana_tx_hash[..12.min(event.solana_tx_hash.len())],
                        event.amount,
                        event.misaka_recipient
                    );

                    match misaka_watcher::submit_mint_request(&config, &event).await {
                        Ok(receipt_id) => {
                            store.mark_completed(&idem_key, &receipt_id)?;
                            info!("[LOCK] Mint OK: {}", &receipt_id[..16.min(receipt_id.len())]);
                        }
                        Err(e) => {
                            store.mark_failed(&idem_key, &e.to_string())?;
                            warn!("[LOCK] Mint failed: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                solana_errors += 1;
                warn!("Solana poll error ({}x): {}", solana_errors, e);
                if solana_errors > 10 {
                    error!("More than 10 consecutive Solana poll failures");
                }
            }
        }

        match misaka_watcher::poll_burn_receipts(&config).await {
            Ok(receipts) => {
                misaka_errors = 0;
                for receipt in receipts {
                    let idem_key = burn_idempotency_key(&receipt);
                    match store.try_claim(&idem_key, "burn", receipt.amount)? {
                        ClaimResult::AlreadyCompleted | ClaimResult::InProgress => continue,
                        ClaimResult::Claimed => {}
                    }

                    info!(
                        "[BURN] {} -> {} -> {}",
                        &receipt.request_id[..12.min(receipt.request_id.len())],
                        receipt.amount,
                        receipt.solana_recipient
                    );

                    match solana_watcher::submit_unlock(&config, &receipt).await {
                        Ok(tx_sig) => {
                            store.mark_completed(&idem_key, &tx_sig)?;
                            info!("[BURN] Unlock OK: {}", &tx_sig[..16.min(tx_sig.len())]);
                        }
                        Err(e) => {
                            store.mark_failed(&idem_key, &e.to_string())?;
                            warn!("[BURN] Unlock failed: {}", e);
                        }
                    }
                }
            }
            Err(e) => {
                misaka_errors += 1;
                warn!("Misaka poll error ({}x): {}", misaka_errors, e);
                if misaka_errors > 10 {
                    error!("More than 10 consecutive Misaka poll failures");
                }
            }
        }
    }
}
