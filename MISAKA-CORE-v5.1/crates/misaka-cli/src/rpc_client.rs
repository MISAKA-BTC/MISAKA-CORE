//! HTTP RPC client for querying the MISAKA node.
//!
//! Uses `reqwest` for proper HTTP handling (connection pooling,
//! timeout, status code validation). Replaces the previous
//! hand-rolled TCP socket + URL parser implementation.

use anyhow::{Context, Result};
use serde_json::Value;
use std::time::Duration;

/// Timeout for RPC requests.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum retries on transient errors.
const MAX_RETRIES: u32 = 2;

/// Delay between retries.
const RETRY_DELAY: Duration = Duration::from_millis(500);

/// RPC client backed by reqwest.
pub struct RpcClient {
    client: reqwest::Client,
    base_url: String,
}

impl RpcClient {
    /// Create a new RPC client.
    ///
    /// Validates the base URL at construction time.
    pub fn new(base_url: &str) -> Result<Self> {
        // Validate URL format
        let base_url = base_url.trim_end_matches('/').to_string();
        if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
            anyhow::bail!(
                "invalid RPC URL '{}': must start with http:// or https://",
                base_url
            );
        }

        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(4)
            .user_agent("misaka-cli/0.4.1")
            .build()
            .context("failed to build HTTP client")?;

        Ok(Self { client, base_url })
    }

    /// POST JSON to an endpoint path and return parsed response.
    ///
    /// Retries on transient errors (connection refused, timeout).
    /// Returns error on non-2xx status codes (fail-closed).
    pub async fn post_json(&self, path: &str, body: &Value) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let mut last_err = None;

        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                tokio::time::sleep(RETRY_DELAY).await;
            }

            match self.do_post(&url, body).await {
                Ok(val) => return Ok(val),
                Err(e) => {
                    let is_transient = e.to_string().contains("connection refused")
                        || e.to_string().contains("timed out")
                        || e.to_string().contains("connection reset");

                    if is_transient && attempt < MAX_RETRIES {
                        eprintln!(
                            "   ⚠ RPC attempt {} failed ({}), retrying...",
                            attempt + 1,
                            e
                        );
                        last_err = Some(e);
                        continue;
                    }
                    return Err(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("RPC failed after retries")))
    }

    async fn do_post(&self, url: &str, body: &Value) -> Result<Value> {
        let response = self
            .client
            .post(url)
            .json(body)
            .send()
            .await
            .with_context(|| format!("HTTP POST to {} failed", url))?;

        let status = response.status();
        if !status.is_success() {
            let body_text = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "RPC error: HTTP {} from {} — {}",
                status.as_u16(),
                url,
                &body_text[..body_text.len().min(200)]
            );
        }

        response
            .json::<Value>()
            .await
            .with_context(|| format!("failed to parse JSON response from {}", url))
    }
}

// ═══════════════════════════════════════════════════════════════
// Public query functions
// ═══════════════════════════════════════════════════════════════

pub async fn get_status(rpc_url: &str) -> Result<()> {
    let client = RpcClient::new(rpc_url)?;
    let resp = client
        .post_json("/api/get_chain_info", &serde_json::json!({}))
        .await?;

    println!("╔═══════════════════════════════════════════════╗");
    println!("║  MISAKA Node Status                          ║");
    println!("╚═══════════════════════════════════════════════╝");
    println!();
    println!(
        "  Network:     {}",
        resp["networkName"].as_str().unwrap_or("?")
    );
    println!(
        "  Version:     {}",
        resp["networkVersion"].as_str().unwrap_or("?")
    );
    println!("  Chain ID:    {}", resp["chainId"]);
    println!("  Height:      {}", resp["latestBlockHeight"]);
    println!("  Total TXs:   {}", resp["totalTransactions"]);
    println!("  Validators:  {}", resp["activeValidators"]);
    println!(
        "  Avg Block:   {:.1}s",
        resp["avgBlockTime"].as_f64().unwrap_or(0.0)
    );
    println!(
        "  TPS:         {:.1}",
        resp["tpsEstimate"].as_f64().unwrap_or(0.0)
    );
    println!(
        "  Health:      {}",
        resp["chainHealth"].as_str().unwrap_or("?")
    );
    println!(
        "  Finality:    {}",
        resp["finalityStatus"].as_str().unwrap_or("?")
    );

    Ok(())
}

pub async fn get_balance(rpc_url: &str, address: &str) -> Result<()> {
    let client = RpcClient::new(rpc_url)?;
    let resp = client
        .post_json(
            "/api/get_address_outputs",
            &serde_json::json!({
                "address": address
            }),
        )
        .await?;

    println!("Address: {}", address);
    println!();

    if let Some(note) = resp["privacyNote"].as_str() {
        println!("⚠  {}", note);
        println!();
    }

    match resp["balance"].as_u64() {
        Some(bal) => println!("  Balance: {} MISAKA", bal),
        None => println!("  Balance: [privacy-protected]"),
    }
    println!("  TX Count: {}", resp["txCount"]);

    if let Some(outputs) = resp["outputs"].as_array() {
        if !outputs.is_empty() {
            println!();
            println!("  Outputs ({}):", outputs.len());
            for o in outputs {
                let tx = o["txHash"].as_str().unwrap_or("?");
                let idx = &o["outputIndex"];
                print!("    {}..:{}", &tx[..tx.len().min(12)], idx);
                match o["amount"].as_u64() {
                    Some(a) => print!("  amount={}", a),
                    None => print!("  amount=[hidden]"),
                }
                println!();
            }
        }
    }

    Ok(())
}
