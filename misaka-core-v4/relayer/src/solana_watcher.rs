//! Solana chain watcher — detects SPL Token Burns on Solana.
//!
//! # Architecture (Burn & Mint Model)
//!
//! - HTTP polling of `getSignaturesForAddress` for the MISAKA token mint
//! - Transaction parsing for SPL Token Burn instructions
//! - Burns are detected, verified, and queued for mint on MISAKA chain
//!
//! # Dependencies
//!
//! Uses raw JSON-RPC over HTTP (no solana-sdk dependency).

use crate::config::RelayerConfig;
use crate::message::BurnEvent;
use crate::message::BurnStatus;
use anyhow::{Context, Result, bail};
use sha3::{Digest, Sha3_256};
use tracing::{debug, error, info, warn};

/// SPL Token Program ID (full base58).
const SPL_TOKEN_PROGRAM_ID: &str = "TokenkegQEqKKXjqoMNiCeLi7q1HhiTtiMkDehESVQe";

/// Minimum slot depth below current finalized slot before we process an event.
const FINALITY_DEPTH: u64 = 32;

/// Maximum consecutive RPC failures before the bridge pauses.
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;

/// Poll Solana for new SPL Token Burn transactions.
///
/// Scans signatures for the MISAKA mint address, fetches each transaction,
/// and extracts burn events from SPL Token Burn instructions.
///
/// # Pagination
///
/// Uses `before` parameter with the last processed signature as cursor.
///
/// # Finality
///
/// Events are only returned if their slot is at least `FINALITY_DEPTH`
/// slots below the current finalized slot.
///
/// # Circuit Breaker
///
/// Tracks consecutive RPC failures. After `CIRCUIT_BREAKER_THRESHOLD`
/// failures, returns an error that signals the caller to pause polling.
pub async fn poll_burn_events(
    config: &RelayerConfig,
    last_signature: Option<&str>,
    consecutive_failures: &mut u32,
) -> Result<(Vec<BurnEvent>, Option<String>)> {
    let mint_address = &config.solana_misaka_mint;
    let solana_rpc_url = &config.solana_rpc_url;

    if mint_address.is_empty() || solana_rpc_url.is_empty() {
        debug!("Solana watcher: no mint_address or rpc_url configured, skipping");
        return Ok((vec![], None));
    }

    // ── Circuit breaker check ──
    if *consecutive_failures >= CIRCUIT_BREAKER_THRESHOLD {
        bail!(
            "CIRCUIT BREAKER: {} consecutive RPC failures — bridge paused. \
             Operator must investigate and restart.",
            consecutive_failures
        );
    }

    // ── Get current finalized slot for depth check ──
    let current_slot = match solana_rpc(
        solana_rpc_url,
        "getSlot",
        serde_json::json!([{"commitment": "finalized"}]),
    )
    .await
    {
        Ok(slot_val) => slot_val.as_u64().unwrap_or(0),
        Err(e) => {
            *consecutive_failures += 1;
            warn!(
                "Solana watcher: getSlot failed ({}/{}): {}",
                consecutive_failures, CIRCUIT_BREAKER_THRESHOLD, e
            );
            return Err(e);
        }
    };

    // ── 1. Get signatures for the MISAKA mint address ──
    // We query signatures for the mint address itself, which captures
    // all transactions that interact with this mint (including burns).
    let mut params = serde_json::json!({
        "limit": 20,
        "commitment": "finalized"
    });
    if let Some(before_sig) = last_signature {
        params["before"] = serde_json::Value::String(before_sig.to_string());
    }

    let sigs_result = solana_rpc(
        solana_rpc_url,
        "getSignaturesForAddress",
        serde_json::json!([mint_address, params]),
    )
    .await;

    let signatures = match sigs_result {
        Ok(serde_json::Value::Array(arr)) => {
            *consecutive_failures = 0;
            arr
        }
        Ok(_) => {
            *consecutive_failures = 0;
            debug!("Solana watcher: no signatures found");
            return Ok((vec![], last_signature.map(String::from)));
        }
        Err(e) => {
            *consecutive_failures += 1;
            error!(
                "Solana watcher: getSignaturesForAddress failed ({}/{}): {e}",
                consecutive_failures, CIRCUIT_BREAKER_THRESHOLD
            );
            return Err(e);
        }
    };

    // Track the newest signature for cursor advancement
    let newest_sig = signatures
        .first()
        .and_then(|s| s.get("signature"))
        .and_then(|s| s.as_str())
        .map(String::from);

    // ── 2. For each signature, fetch TX and parse for burn instructions ──
    let mut events = Vec::new();
    for sig_info in signatures.iter().take(20) {
        let sig = match sig_info.get("signature").and_then(|s| s.as_str()) {
            Some(s) => s,
            None => continue,
        };

        // Skip errored transactions
        if sig_info.get("err") != Some(&serde_json::Value::Null) {
            continue;
        }

        // ── Finality depth check ──
        let event_slot = sig_info.get("slot").and_then(|s| s.as_u64()).unwrap_or(0);
        if current_slot.saturating_sub(event_slot) < FINALITY_DEPTH {
            debug!(
                "Skipping sig {} — slot {} too recent (current={}, depth={})",
                &sig[..16.min(sig.len())],
                event_slot,
                current_slot,
                FINALITY_DEPTH
            );
            continue;
        }

        let tx_result = solana_rpc(
            solana_rpc_url,
            "getTransaction",
            serde_json::json!([
                sig,
                {
                    "encoding": "jsonParsed",
                    "commitment": "finalized",
                    "maxSupportedTransactionVersion": 0
                }
            ]),
        )
        .await;

        let tx = match tx_result {
            Ok(t) if !t.is_null() => t,
            _ => continue,
        };

        // Extract block_time
        let block_time = tx.get("blockTime").and_then(|t| t.as_i64()).unwrap_or(0);

        // Check transaction meta.err is null (double-check)
        if let Some(meta) = tx.get("meta") {
            if meta.get("err") != Some(&serde_json::Value::Null) {
                continue;
            }
        }

        // ── 3. Parse for SPL Token Burn instructions ──
        let burns = extract_burn_instructions(&tx, &config.solana_misaka_mint);
        for (burn_idx, (amount, wallet, mint)) in burns.iter().enumerate() {
            if *amount == 0 {
                warn!("Burn with zero amount in tx {}, skipping", sig);
                continue;
            }

            // Compute deterministic event ID: SHA3-256(tx_sig + burn_index)
            let event_id = {
                let mut h = Sha3_256::new();
                h.update(sig.as_bytes());
                h.update(&(burn_idx as u64).to_le_bytes());
                hex::encode(h.finalize())
            };

            info!(
                "Burn detected: sig={} amount={} wallet={} mint={} slot={} depth={}",
                &sig[..16.min(sig.len())],
                amount,
                &wallet[..16.min(wallet.len())],
                &mint[..16.min(mint.len())],
                event_slot,
                current_slot.saturating_sub(event_slot),
            );

            events.push(BurnEvent {
                id: event_id,
                solana_tx_signature: sig.to_string(),
                mint_address: mint.clone(),
                wallet_address: wallet.clone(),
                burn_amount_raw: *amount,
                slot: event_slot,
                block_time,
                status: BurnStatus::Detected,
            });
        }
    }

    let new_cursor = newest_sig.or_else(|| last_signature.map(String::from));
    Ok((events, new_cursor))
}

/// Extract all SPL Token Burn instructions from a parsed transaction.
///
/// Returns a list of (amount, wallet_owner, mint_address) tuples.
/// Only burns matching the expected mint are returned.
fn extract_burn_instructions(
    tx: &serde_json::Value,
    expected_mint: &str,
) -> Vec<(u64, String, String)> {
    let mut burns = Vec::new();

    // Check top-level instructions
    if let Some(instructions) = tx
        .get("transaction")
        .and_then(|t| t.get("message"))
        .and_then(|m| m.get("instructions"))
        .and_then(|i| i.as_array())
    {
        for ix in instructions {
            if let Some(burn) = parse_parsed_burn_instruction(ix, expected_mint) {
                burns.push(burn);
            }
        }
    }

    // Check inner instructions (from CPI calls)
    if let Some(inner_instructions) = tx
        .get("meta")
        .and_then(|m| m.get("innerInstructions"))
        .and_then(|i| i.as_array())
    {
        for inner_group in inner_instructions {
            if let Some(ixs) = inner_group.get("instructions").and_then(|i| i.as_array()) {
                for ix in ixs {
                    if let Some(burn) = parse_parsed_burn_instruction(ix, expected_mint) {
                        burns.push(burn);
                    }
                }
            }
        }
    }

    burns
}

/// Parse a single SPL Token Burn instruction from jsonParsed format.
///
/// The jsonParsed encoding for an SPL Token Burn looks like:
/// ```json
/// {
///   "program": "spl-token",
///   "programId": "TokenkegQEqKKXjqoMNiCeLi7q1HhiTtiMkDehESVQe",
///   "parsed": {
///     "type": "burn",
///     "info": {
///       "account": "<token_account>",
///       "mint": "<mint_address>",
///       "authority": "<owner_wallet>",
///       "amount": "<amount_string>"
///     }
///   }
/// }
/// ```
///
/// This ensures we only detect real SPL Token Program Burn instructions,
/// not transfers to dead addresses or other token operations.
fn parse_parsed_burn_instruction(
    ix: &serde_json::Value,
    expected_mint: &str,
) -> Option<(u64, String, String)> {
    // Verify it's the SPL Token Program
    let program_id = ix.get("programId").and_then(|p| p.as_str())?;
    if program_id != SPL_TOKEN_PROGRAM_ID {
        return None;
    }

    // Must be a parsed instruction with type "burn"
    let parsed = ix.get("parsed")?;
    let ix_type = parsed.get("type").and_then(|t| t.as_str())?;
    if ix_type != "burn" {
        return None;
    }

    let info = parsed.get("info")?;

    // Extract and verify mint
    let mint = info.get("mint").and_then(|m| m.as_str())?;
    if mint != expected_mint {
        return None;
    }

    // Extract amount
    let amount_str = info.get("amount").and_then(|a| a.as_str())?;
    let amount: u64 = amount_str.parse().ok()?;

    // Extract authority (wallet owner)
    let authority = info.get("authority").and_then(|a| a.as_str())?;

    Some((amount, authority.to_string(), mint.to_string()))
}

/// Solana JSON-RPC request helper.
async fn solana_rpc(
    rpc_url: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });

    let resp = http_post_json(rpc_url, &body)
        .await
        .context(format!("Solana RPC '{}' failed", method))?;

    if let Some(err) = resp.get("error") {
        bail!("Solana RPC error: {}", err);
    }

    Ok(resp
        .get("result")
        .cloned()
        .unwrap_or(serde_json::Value::Null))
}

/// HTTP POST with JSON body via reqwest (secure, with timeout).
async fn http_post_json(url: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("failed to build HTTP client")?;

    let resp = client
        .post(url)
        .json(body)
        .send()
        .await
        .context(format!("HTTP POST to {} failed", url))?;

    let status = resp.status();
    if !status.is_success() {
        let err_body = resp.text().await.unwrap_or_default();
        bail!(
            "Solana RPC HTTP {}: {}",
            status,
            &err_body[..200.min(err_body.len())]
        );
    }

    resp.json::<serde_json::Value>()
        .await
        .context("failed to parse Solana RPC JSON response")
}
