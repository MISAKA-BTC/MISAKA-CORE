//! MISAKA chain interaction — submits mint requests for verified burns.
//!
//! In the Burn & Mint model, this module is responsible for:
//! - Submitting mint requests to the MISAKA chain after a Solana burn is verified
//! - The MISAKA chain mints wrapped tokens to the registered receive address

use crate::config::RelayerConfig;
use crate::store::BurnRequestRow;
use anyhow::Result;
use tracing::error;

/// Submit a mint request to the MISAKA chain for a verified burn.
///
/// Tells the MISAKA bridge module to mint wrapped tokens
/// corresponding to the burned SPL tokens on Solana.
pub async fn submit_mint_for_burn(
    config: &RelayerConfig,
    burn: &BurnRequestRow,
) -> Result<String> {
    let url = format!("{}/api/bridge/submit_mint", config.misaka_rpc_url);
    let body = serde_json::json!({
        "burn_event_id": burn.id,
        "source_chain": 1,  // Solana
        "amount": burn.burn_amount_raw,
        "mint_address": burn.mint_address,
        "misaka_recipient": burn.misaka_receive_address,
        "solana_tx_signature": burn.solana_tx_signature,
        "wallet_address": burn.wallet_address,
        "slot": burn.slot,
        "block_time": burn.block_time,
    });

    let resp = http_post(&url, &body).await?;
    let receipt_id = resp["receiptId"]
        .as_str()
        .ok_or_else(|| {
            error!(
                "Mint response from {} missing 'receiptId' field: {:?}",
                url, resp
            );
            anyhow::anyhow!("mint response missing receiptId")
        })?
        .to_string();
    Ok(receipt_id)
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
