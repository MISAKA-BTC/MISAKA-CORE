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

    // SEC-FIX-4: from_env() returns Result instead of panicking.
    // On failure, log the structured error and exit cleanly so that
    // systemd/PM2 sees a proper exit code and the operator gets a
    // readable error message in the journal.
    let config = match RelayerConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            error!("{}", e);
            std::process::exit(1);
        }
    };
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

    // SEC-BRIDGE: Load persisted cursor for pagination.
    // This ensures we resume from the last processed signature after restart,
    // avoiding re-processing old events and the limit:20 ceiling.
    let mut last_lock_cursor: Option<String> = store.get_cursor("lock_cursor")
        .unwrap_or(None);
    if let Some(ref cursor) = last_lock_cursor {
        info!("Resuming lock poll from cursor: {}...", &cursor[..16.min(cursor.len())]);
    }

    // SEC-BRIDGE: Circuit breaker state — shared across poll iterations.
    let mut solana_consecutive_failures: u32 = 0;
    let mut bridge_paused = false;

    loop {
        ticker.tick().await;

        // SEC-BRIDGE: If circuit breaker tripped, wait for operator reset
        if bridge_paused {
            warn!("Bridge is PAUSED (circuit breaker). Set MISAKA_BRIDGE_RESUME=1 to resume.");
            if std::env::var("MISAKA_BRIDGE_RESUME").ok().as_deref() == Some("1") {
                info!("Bridge resumed by operator (MISAKA_BRIDGE_RESUME=1)");
                std::env::remove_var("MISAKA_BRIDGE_RESUME");
                bridge_paused = false;
                solana_consecutive_failures = 0;
            }
            continue;
        }

        match solana_watcher::poll_lock_events(
            &config,
            last_lock_cursor.as_deref(),
            &mut solana_consecutive_failures,
        ).await {
            Ok((events, new_cursor)) => {
                solana_errors = 0;

                // Persist cursor BEFORE processing events —
                // if we crash during processing, idempotency keys prevent
                // double-execution, and the cursor ensures we don't re-scan.
                if let Some(ref cursor) = new_cursor {
                    if last_lock_cursor.as_deref() != Some(cursor.as_str()) {
                        if let Err(e) = store.set_cursor("lock_cursor", cursor) {
                            warn!("Failed to persist lock cursor: {}", e);
                        }
                    }
                }
                last_lock_cursor = new_cursor;

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
                let msg = e.to_string();
                if msg.contains("CIRCUIT BREAKER") {
                    error!("{}", msg);
                    bridge_paused = true;
                    continue;
                }
                solana_errors += 1;
                warn!("Solana poll error ({}x): {}", solana_errors, e);
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
