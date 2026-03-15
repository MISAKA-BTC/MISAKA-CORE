//! Misaka chain watcher — polls burn receipts, submits mint requests.

use crate::config::RelayerConfig;
use crate::message::{LockEvent, BurnReceipt};
use anyhow::Result;

/// Submit a mint request to the Misaka node.
///
/// This tells the Misaka bridge module to mint wrapped tokens
/// after verifying the Solana lock event.
pub async fn submit_mint_request(config: &RelayerConfig, event: &LockEvent) -> Result<String> {
    let url = format!("{}/api/bridge/submit_mint", config.misaka_rpc_url);
    let body = serde_json::json!({
        "lock_event_id": event.id,
        "source_chain": 1, // Solana
        "amount": event.amount,
        "asset_id": event.asset_id,
        "misaka_recipient": event.misaka_recipient,
        "solana_tx_hash": event.solana_tx_hash,
    });

    let resp = http_post(&url, &body).await?;
    let receipt_id = resp["receiptId"].as_str().unwrap_or("pending").to_string();
    Ok(receipt_id)
}

/// Poll Misaka node for finalized burn receipts.
///
/// These are burns of wrapped assets that need to trigger
/// unlock on Solana.
pub async fn poll_burn_receipts(config: &RelayerConfig) -> Result<Vec<BurnReceipt>> {
    let url = format!("{}/api/bridge/burn_receipts", config.misaka_rpc_url);
    let body = serde_json::json!({ "status": "approved" });

    match http_post(&url, &body).await {
        Ok(resp) => {
            let receipts: Vec<BurnReceipt> = serde_json::from_value(
                resp.get("receipts").cloned().unwrap_or(serde_json::json!([]))
            ).unwrap_or_default();
            Ok(receipts)
        }
        Err(_) => Ok(vec![]),
    }
}

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
