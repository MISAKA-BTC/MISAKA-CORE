//! Misaka chain watcher — polls burn receipts, submits mint requests.

use crate::config::RelayerConfig;
use crate::message::{BurnReceipt, LockEvent};
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
    let receipt_id = resp["receiptId"]
        .as_str()
        .ok_or_else(|| {
            tracing::error!(
                "Mint response from {} missing 'receiptId' field: {:?}",
                url,
                resp
            );
            anyhow::anyhow!("mint response missing receiptId")
        })?
        .to_string();
    Ok(receipt_id)
}

/// Poll Misaka node for finalized burn receipts.
///
/// These are burns of wrapped assets that need to trigger
/// unlock on Solana.
pub async fn poll_burn_receipts(config: &RelayerConfig) -> Result<Vec<BurnReceipt>> {
    let url = format!("{}/api/bridge/burn_receipts", config.misaka_rpc_url);
    let body = serde_json::json!({ "status": "approved" });

    let resp = http_post(&url, &body).await?;
    let receipts: Vec<BurnReceipt> = serde_json::from_value(
        resp.get("receipts")
            .cloned()
            .unwrap_or(serde_json::json!([])),
    )
    .map_err(|e| {
        tracing::error!("Failed to parse burn receipts from {}: {}", url, e);
        anyhow::anyhow!("burn receipt parse error: {}", e)
    })?;
    Ok(receipts)
}

async fn http_post(url: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| anyhow::anyhow!("http client build: {e}"))?;

    let resp = client
        .post(url)
        .json(body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("http post to {}: {}", url, e))?;

    let status = resp.status();
    if !status.is_success() {
        let body_text = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "HTTP {} from {}: {}",
            status,
            url,
            &body_text[..200.min(body_text.len())]
        );
    }

    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| anyhow::anyhow!("json parse from {}: {}", url, e))
}
