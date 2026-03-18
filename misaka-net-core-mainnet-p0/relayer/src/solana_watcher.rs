//! Solana chain watcher — polls lock events, submits unlock transactions.
//!
//! Initial version uses HTTP polling. Future: WebSocket subscription.

use crate::config::RelayerConfig;
use crate::message::{LockEvent, BurnReceipt};
use anyhow::Result;

/// Poll Solana for new lock events.
///
/// In production: parse program logs / account data for TokensLocked events.
/// Current: placeholder that queries Misaka node's bridge API.
pub async fn poll_lock_events(config: &RelayerConfig) -> Result<Vec<LockEvent>> {
    // TODO: Implement Solana RPC getSignaturesForAddress + getParsedTransaction
    // to extract TokensLocked events from the bridge program.
    //
    // For devnet testing, the Misaka node exposes /api/bridge/solana_locks
    // which simulates Solana lock event feed.

    let url = format!("{}/api/bridge/solana_locks", config.misaka_rpc_url);
    let body = serde_json::json!({});

    match http_post(&url, &body).await {
        Ok(resp) => {
            let events: Vec<LockEvent> = serde_json::from_value(
                resp.get("events").cloned().unwrap_or(serde_json::json!([]))
            ).unwrap_or_default();
            Ok(events)
        }
        Err(_) => Ok(vec![]), // No events or node unreachable
    }
}

/// Submit an unlock transaction to Solana.
///
/// In production: build and send an Anchor instruction to the bridge program.
/// Current: posts to Misaka node which logs the intent.
pub async fn submit_unlock(config: &RelayerConfig, receipt: &BurnReceipt) -> Result<String> {
    // TODO: Build Solana transaction:
    //   1. Load relayer keypair
    //   2. Build UnlockTokens instruction with:
    //      - amount: receipt.amount
    //      - request_id: receipt.request_id_bytes()
    //      - recipient_token_account: derive from receipt.solana_recipient
    //   3. Sign and send via Solana RPC
    //   4. Confirm and return signature

    let url = format!("{}/api/bridge/submit_unlock", config.misaka_rpc_url);
    let body = serde_json::json!({
        "receipt_id": receipt.id,
        "amount": receipt.amount,
        "solana_recipient": receipt.solana_recipient,
    });

    let resp = http_post(&url, &body).await?;
    let tx_sig = resp["txSignature"].as_str().unwrap_or("pending").to_string();
    Ok(tx_sig)
}

/// Minimal HTTP POST helper (no external HTTP client dependency).
async fn http_post(url: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
    let rest = url.strip_prefix("http://").unwrap_or(url);
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let path = format!("/{}", path);
    let (host, port) = authority.split_once(':')
        .map(|(h, p)| (h.to_string(), p.parse::<u16>().unwrap_or(3001)))
        .unwrap_or((authority.to_string(), 3001));

    let body_str = serde_json::to_string(body)?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host, port, body_str.len(), body_str,
    );

    let mut stream = tokio::net::TcpStream::connect(format!("{}:{}", host, port)).await?;
    tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes()).await?;

    let mut response = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut response).await?;

    let response_str = String::from_utf8_lossy(&response);
    let body_start = response_str.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    serde_json::from_str(&response_str[body_start..])
        .map_err(|e| anyhow::anyhow!("json parse: {}", e))
}
