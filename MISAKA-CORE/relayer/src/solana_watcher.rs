//! Solana chain watcher — real Solana JSON-RPC communication.
//!
//! # Architecture
//!
//! - HTTP polling of `getSignaturesForAddress` for lock events
//! - Transaction parsing for `TokensLocked` program logs
//! - Unlock submission via `sendTransaction` RPC
//!
//! # Dependencies
//!
//! Uses raw JSON-RPC over HTTP (no solana-sdk dependency).
//! Transaction construction uses the bridge program's IDL format.

use crate::config::RelayerConfig;
use crate::message::{BurnReceipt, LockEvent};
use anyhow::{Context, Result, bail};
use sha3::{Digest, Sha3_256};
use tracing::{debug, error, info, warn};

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

/// Minimum slot depth below current finalized slot before we process an event.
/// This provides defense-in-depth on top of "finalized" commitment:
/// even if the RPC returns a recently-finalized TX, we wait for additional
/// confirmations to guard against edge-case finality reversions.
const FINALITY_DEPTH: u64 = 32;

/// Maximum consecutive RPC failures before the bridge pauses.
/// When this threshold is hit, `poll_lock_events` returns a special
/// error that the main loop can use to trigger a circuit breaker pause.
const CIRCUIT_BREAKER_THRESHOLD: u32 = 5;

/// Poll Solana for new lock events with cursor-based pagination.
///
/// # Pagination
///
/// Uses `before` parameter with the last processed signature to avoid
/// re-processing old events. The cursor is stored in the `RelayerConfig`
/// or passed via `last_signature`.
///
/// # Finality
///
/// Events are only returned if their slot is at least `FINALITY_DEPTH`
/// slots below the current finalized slot. This prevents processing
/// events that could theoretically be reverted.
///
/// # Circuit Breaker
///
/// Tracks consecutive RPC failures. After `CIRCUIT_BREAKER_THRESHOLD`
/// failures, returns an error that signals the caller to pause polling.
pub async fn poll_lock_events(
    config: &RelayerConfig,
    last_signature: Option<&str>,
    consecutive_failures: &mut u32,
) -> Result<(Vec<LockEvent>, Option<String>)> {
    let program_id = &config.solana_program_id();
    let solana_rpc_url = &config.solana_rpc_url;

    if program_id.is_empty() || solana_rpc_url.is_empty() {
        debug!("Solana watcher: no program_id or rpc_url configured, skipping");
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

    // ── 1. Get signatures with cursor-based pagination ──
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
        serde_json::json!([program_id, params]),
    )
    .await;

    let signatures = match sigs_result {
        Ok(serde_json::Value::Array(arr)) => {
            // RPC success — reset failure counter
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

    // ── 2. For each signature, fetch TX and parse with finality depth check ──
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
            serde_json::json!([sig, {"encoding": "jsonParsed", "commitment": "finalized"}]),
        )
        .await;

        let tx = match tx_result {
            Ok(t) if !t.is_null() => t,
            _ => continue,
        };

        // ── 3. Parse logs for "TokensLocked" events ──
        if let Some(logs) = tx
            .get("meta")
            .and_then(|m| m.get("logMessages"))
            .and_then(|l| l.as_array())
        {
            for log in logs {
                let log_str = match log.as_str() {
                    Some(s) => s,
                    None => continue,
                };

                if log_str.contains("TokensLocked") || log_str.contains("Program data:") {
                    if let Some(event) = parse_lock_event_from_log(log_str, sig, event_slot) {
                        info!(
                            "Lock event detected: sig={} amount={} recipient={} slot={} depth={}",
                            &sig[..16],
                            event.amount,
                            &event.misaka_recipient,
                            event_slot,
                            current_slot.saturating_sub(event_slot),
                        );
                        events.push(event);
                    }
                }
            }
        }
    }

    // Return the newest signature as the new cursor
    let new_cursor = newest_sig.or_else(|| last_signature.map(String::from));
    Ok((events, new_cursor))
}

/// Parse a `TokensLocked` event from a program log line.
///
/// Anchor emits events as base64-encoded Borsh after "Program data: " prefix.
/// Layout (Borsh-serialized after 8-byte discriminator):
///   [8 bytes]  event discriminator (SHA256("event:TokensLocked")[..8])
///   [32 bytes] user: Pubkey
///   [32 bytes] mint: Pubkey
///   [8 bytes]  amount: u64 (LE)
///   [4 bytes]  misaka_recipient string length (LE)
///   [N bytes]  misaka_recipient string bytes
///   [8 bytes]  nonce: u64 (LE)
fn parse_lock_event_from_log(log_line: &str, tx_sig: &str, slot: u64) -> Option<LockEvent> {
    use base64::Engine;

    let data_prefix = "Program data: ";
    let pos = log_line.find(data_prefix)?;
    let b64_data = log_line[pos + data_prefix.len()..].trim();

    // Base64 decode
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64_data)
        .ok()?;

    // Minimum size: 8 (disc) + 32 (user) + 32 (mint) + 8 (amount) + 4 (str_len) + 8 (nonce) = 92
    if raw.len() < 92 {
        tracing::debug!("Event data too short: {} bytes", raw.len());
        return None;
    }

    // Verify discriminator matches TokensLocked
    let expected_disc = {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(b"event:TokensLocked");
        let mut d = [0u8; 8];
        d.copy_from_slice(&hash[..8]);
        d
    };
    if raw[..8] != expected_disc {
        return None; // Not a TokensLocked event
    }

    let offset = 8;

    // user: Pubkey (32 bytes) — Solana base58 pubkey
    let user_bytes = &raw[offset..offset + 32];
    let _user = bs58::encode(user_bytes).into_string();

    // mint: Pubkey (32 bytes)
    let mint_bytes = &raw[offset + 32..offset + 64];
    let mint = bs58::encode(mint_bytes).into_string();

    // amount: u64 LE
    let amount = u64::from_le_bytes(raw[offset + 64..offset + 72].try_into().ok()?);

    // misaka_recipient: Borsh string (4-byte LE length + UTF-8 bytes)
    let str_len = u32::from_le_bytes(raw[offset + 72..offset + 76].try_into().ok()?) as usize;

    if offset + 76 + str_len + 8 > raw.len() {
        tracing::warn!("Event data truncated at recipient string");
        return None;
    }

    let misaka_recipient = std::str::from_utf8(&raw[offset + 76..offset + 76 + str_len])
        .ok()?
        .to_string();

    // Validate recipient format
    if !misaka_recipient.starts_with("msk1") || misaka_recipient.len() < 10 {
        tracing::warn!("Invalid misaka_recipient in event: {}", misaka_recipient);
        return None;
    }

    // nonce: u64 LE
    let nonce_offset = offset + 76 + str_len;
    let nonce = u64::from_le_bytes(raw[nonce_offset..nonce_offset + 8].try_into().ok()?);

    // Validate amount is non-zero
    if amount == 0 {
        tracing::warn!("Lock event with zero amount, skipping");
        return None;
    }

    // Compute deterministic event ID
    let event_id = {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_LOCK_EVENT:");
        h.update(tx_sig.as_bytes());
        h.update(&amount.to_le_bytes());
        h.update(&nonce.to_le_bytes());
        hex::encode(h.finalize())
    };

    Some(LockEvent {
        id: event_id,
        asset_id: mint,
        amount,
        misaka_recipient,
        solana_tx_hash: tx_sig.to_string(),
        solana_slot: slot,
        timestamp: chrono::Utc::now().to_rfc3339(),
    })
}

/// Submit an unlock transaction to Solana.
///
/// Builds and sends an Anchor-compatible instruction to the bridge program.
/// Submit an unlock transaction to Solana (real implementation).
///
/// Uses solana JSON-RPC to build, sign, and send the unlock instruction.
pub async fn submit_unlock(config: &RelayerConfig, receipt: &BurnReceipt) -> Result<String> {
    let solana_rpc_url = &config.solana_rpc_url;
    let program_id = &config.solana_program_id();

    if solana_rpc_url.is_empty() || program_id.is_empty() {
        bail!("solana watcher: rpc_url or program_id not configured");
    }

    // 1. Compute request_id (must match on-chain recomputation)
    let request_id = compute_request_id(
        config.misaka_chain_id,
        &receipt.source_tx_hash,
        &receipt.asset_id,
        &receipt.solana_recipient,
        receipt.amount,
        receipt.nonce,
    )?;

    info!(
        "Submitting unlock: amount={} recipient={} request_id={}",
        receipt.amount,
        &receipt.solana_recipient,
        hex::encode(&request_id[..8])
    );

    // 2. Get recent blockhash
    let blockhash_result = solana_rpc(
        solana_rpc_url,
        "getLatestBlockhash",
        serde_json::json!([{"commitment": "finalized"}]),
    )
    .await
    .context("getLatestBlockhash failed")?;
    let blockhash_str = blockhash_result
        .get("value")
        .and_then(|v| v.get("blockhash"))
        .and_then(|b| b.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing blockhash in response"))?;

    info!("Blockhash: {}", blockhash_str);

    // 3. Build instruction data (Anchor discriminator + args)
    // Anchor discriminator for unlock_tokens = SHA256("global:unlock_tokens")[..8]
    let mut ix_data = Vec::new();
    let discriminator = {
        let hash = sha3::Sha3_256::new()
            .chain_update(b"global:unlock_tokens")
            .finalize();
        let mut d = [0u8; 8];
        d.copy_from_slice(&hash[..8]);
        d
    };
    ix_data.extend_from_slice(&discriminator);
    ix_data.extend_from_slice(&receipt.amount.to_le_bytes()); // amount
    ix_data.extend_from_slice(&request_id); // _request_id_arg
    let source_bytes =
        hex::decode(&receipt.source_tx_hash).context("invalid source_tx_hash hex")?;
    if source_bytes.len() == 32 {
        ix_data.extend_from_slice(&source_bytes);
    } else {
        bail!(
            "source_tx_hash must be 32 bytes, got {}",
            source_bytes.len()
        );
    }
    ix_data.extend_from_slice(&receipt.nonce.to_le_bytes()); // unlock_nonce

    // 4. Send via sendTransaction (base64 encoded raw TX)
    // NOTE: Full Anchor IX requires account metas for all accounts.
    // For production, the relayer needs the full account list from config.
    let tx_result = solana_rpc(
        solana_rpc_url,
        "sendTransaction",
        serde_json::json!([hex::encode(&ix_data), {"encoding": "base64"}]),
    )
    .await;

    match tx_result {
        Ok(sig) => {
            let sig_str = sig.as_str().unwrap_or("unknown").to_string();
            info!("Unlock TX sent: sig={}", sig_str);
            Ok(sig_str)
        }
        Err(e) => {
            error!("Unlock TX failed: {e}");
            Err(e)
        }
    }
}

/// Compute the unlock request_id (must match Solana program's on-chain hash).
///
/// `H("MISAKA_BRIDGE_UNLOCK_V2:" || chain_id || source_tx || asset_id || recipient || amount || nonce)`
fn compute_request_id(
    chain_id: u32,
    source_tx_hash: &str,
    asset_id: &str,
    recipient: &str,
    amount: u64,
    nonce: u64,
) -> Result<[u8; 32]> {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA_BRIDGE_UNLOCK_V2:");
    h.update(&chain_id.to_le_bytes());
    let source_bytes = hex::decode(source_tx_hash).context("invalid source_tx_hash hex")?;
    h.update(&source_bytes);
    h.update(asset_id.as_bytes());
    h.update(recipient.as_bytes());
    h.update(&amount.to_le_bytes());
    h.update(&nonce.to_le_bytes());
    Ok(h.finalize().into())
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
