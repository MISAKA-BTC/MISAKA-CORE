//! Native HTTP client for MISAKA Node API.
//!
//! Feature-gated behind `native-rpc` — not available in WASM builds.
//! Chrome extension TypeScript code should use `fetch()` directly
//! with the types from `api_types` as the JSON schema reference.
//!
//! # Hardening (v5.2)
//!
//! - **Retry with backoff**: Transient errors (timeout, connection reset) are
//!   retried up to 2 times with exponential backoff.
//! - **HTTP status code handling**: Non-2xx responses are propagated as errors
//!   with status code context.
//! - **TX wait polling**: `wait_for_tx()` polls until a TX is confirmed or
//!   a timeout is reached — useful for CLI flows.
//! - **Pool tuning**: Idle connection pool sized for typical wallet usage.

use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;

use crate::api_types::*;

/// Maximum retries on transient network errors.
const MAX_RETRIES: u32 = 2;
/// Initial retry delay (doubles each retry).
const INITIAL_RETRY_DELAY: Duration = Duration::from_millis(500);

/// MISAKA Node RPC Client.
///
/// Wraps all wallet-relevant API endpoints with typed request/response pairs.
#[derive(Clone)]
pub struct NodeClient {
    client: reqwest::Client,
    base_url: String,
}

impl NodeClient {
    /// Create a new client pointing at a misaka-node or misaka-api server.
    ///
    /// ```rust,no_run
    /// # use misaka_wallet_core::rpc_client::NodeClient;
    /// let client = NodeClient::new("http://127.0.0.1:3001").expect("valid url");  // direct to node
    /// let client = NodeClient::new("http://127.0.0.1:4000").expect("valid url");  // via misaka-api
    /// ```
    pub fn new(base_url: &str) -> Result<Arc<Self>> {
        let base_url = base_url.trim_end_matches('/').to_string();
        if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
            anyhow::bail!("invalid RPC URL: must start with http:// or https://");
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .connect_timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(4)
            .user_agent("misaka-wallet-core/0.6.0")
            .build()
            .context("failed to build HTTP client")?;

        Ok(Arc::new(Self { client, base_url }))
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// POST with retry on transient errors.
    async fn post_with_retry<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &impl serde::Serialize,
    ) -> Result<T> {
        let url = self.url(path);
        let mut last_err = None;
        let mut delay = INITIAL_RETRY_DELAY;

        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                tokio::time::sleep(delay).await;
                delay *= 2;
            }

            match self.client.post(&url).json(body).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return resp.json::<T>().await.with_context(|| {
                            format!("failed to parse response from {}", path)
                        });
                    }
                    let body_text = resp.text().await.unwrap_or_default();
                    let err = anyhow::anyhow!(
                        "HTTP {} from {}: {}",
                        status.as_u16(),
                        path,
                        &body_text[..body_text.len().min(200)]
                    );
                    // Don't retry client errors (4xx)
                    if status.is_client_error() {
                        return Err(err);
                    }
                    last_err = Some(err);
                }
                Err(e) => {
                    let is_transient = e.is_timeout()
                        || e.is_connect()
                        || e.to_string().contains("connection reset");
                    if !is_transient || attempt >= MAX_RETRIES {
                        return Err(anyhow::anyhow!("request to {} failed: {}", path, e));
                    }
                    last_err = Some(anyhow::anyhow!("{}", e));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("request to {} failed after retries", path)))
    }

    /// GET with retry on transient errors.
    async fn get_with_retry<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T> {
        let url = self.url(path);
        let mut last_err = None;
        let mut delay = INITIAL_RETRY_DELAY;

        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                tokio::time::sleep(delay).await;
                delay *= 2;
            }

            match self.client.get(&url).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return resp.json::<T>().await.with_context(|| {
                            format!("failed to parse response from {}", path)
                        });
                    }
                    if status.is_client_error() {
                        let text = resp.text().await.unwrap_or_default();
                        return Err(anyhow::anyhow!("HTTP {} from {}: {}", status.as_u16(), path, text));
                    }
                    last_err = Some(anyhow::anyhow!("HTTP {} from {}", status.as_u16(), path));
                }
                Err(e) => {
                    let is_transient = e.is_timeout() || e.is_connect();
                    if !is_transient || attempt >= MAX_RETRIES {
                        return Err(anyhow::anyhow!("GET {} failed: {}", path, e));
                    }
                    last_err = Some(anyhow::anyhow!("{}", e));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("GET {} failed after retries", path)))
    }

    // ── Health ──

    pub async fn health(&self) -> Result<HealthResponse> {
        self.get_with_retry("/health").await
    }

    // ── Chain Info ──

    pub async fn chain_info(&self) -> Result<ChainInfo> {
        self.post_with_retry("/api/get_chain_info", &serde_json::json!({})).await
    }

    // ── Fee Estimate ──

    pub async fn fee_estimate(&self) -> Result<FeeEstimate> {
        self.get_with_retry("/api/fee_estimate").await
    }

    // ── Wallet UTXOs ──

    pub async fn get_utxos(&self, address: &str) -> Result<WalletUtxoResponse> {
        self.post_with_retry(
            "/api/get_utxos_by_address",
            &GetUtxosByAddressReq {
                address: address.to_string(),
            },
        )
        .await
    }

    /// Get the balance for an address (convenience wrapper).
    pub async fn balance(&self, address: &str) -> Result<u64> {
        let resp = self.get_utxos(address).await?;
        Ok(resp.balance)
    }

    // ── Decoy UTXOs (for ring signature transfers) ──

    pub async fn get_decoys(
        &self,
        amount: u64,
        count: usize,
        exclude_tx: &str,
        exclude_index: u32,
    ) -> Result<DecoyUtxoResponse> {
        self.post_with_retry(
            "/api/get_decoy_utxos",
            &GetDecoyUtxosReq {
                amount,
                count,
                exclude_tx_hash: exclude_tx.to_string(),
                exclude_output_index: exclude_index,
            },
        )
        .await
    }

    // ── Anonymity Set (for ZKP shielded transfers) ──

    pub async fn get_anonymity_set(
        &self,
        ring_size: usize,
        tx_hash: &str,
        output_index: u32,
    ) -> Result<AnonymitySetResponse> {
        self.post_with_retry(
            "/api/get_anonymity_set",
            &GetAnonymitySetReq {
                ring_size,
                tx_hash: tx_hash.to_string(),
                output_index,
            },
        )
        .await
    }

    // ── Submit Transaction ──

    pub async fn submit_tx(&self, tx_json: &serde_json::Value) -> Result<SubmitTxResponse> {
        self.post_with_retry("/api/submit_tx", tx_json).await
    }

    // ── Faucet ──

    pub async fn faucet(
        &self,
        address: &str,
        spending_pubkey: Option<&str>,
    ) -> Result<FaucetResponse> {
        self.post_with_retry(
            "/api/faucet",
            &FaucetReq {
                address: address.to_string(),
                spending_pubkey: spending_pubkey.map(|s| s.to_string()),
            },
        )
        .await
    }

    // ── TX Lookup ──

    pub async fn get_tx(&self, hash: &str) -> Result<serde_json::Value> {
        self.post_with_retry(
            "/api/get_tx_by_hash",
            &serde_json::json!({ "hash": hash }),
        )
        .await
    }

    // ── TX Wait (poll until confirmed or timeout) ──

    /// Poll for a transaction to appear on-chain. Returns the TX data
    /// once confirmed, or an error if the timeout is reached.
    ///
    /// Useful for CLI workflows: submit → wait → print result.
    pub async fn wait_for_tx(
        &self,
        hash: &str,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<serde_json::Value> {
        let start = std::time::Instant::now();
        loop {
            match self.get_tx(hash).await {
                Ok(data) => {
                    let status = data["status"].as_str().unwrap_or("");
                    if status == "confirmed" || status == "finalized" {
                        return Ok(data);
                    }
                }
                Err(_) => {} // TX not found yet
            }

            if start.elapsed() >= timeout {
                anyhow::bail!(
                    "timeout waiting for tx {} after {:?}",
                    &hash[..hash.len().min(16)],
                    timeout
                );
            }
            tokio::time::sleep(poll_interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_url() {
        let client = NodeClient::new("http://localhost:3001").expect("test: valid url");
        assert_eq!(client.url("/health"), "http://localhost:3001/health");
    }

    #[test]
    fn test_client_strips_trailing_slash() {
        let client = NodeClient::new("http://localhost:3001/").expect("test: valid url");
        assert_eq!(
            client.url("/api/submit_tx"),
            "http://localhost:3001/api/submit_tx"
        );
    }

    #[test]
    fn test_client_rejects_invalid_url() {
        let result = NodeClient::new("not-a-url");
        assert!(result.is_err());
    }

    #[test]
    fn test_client_accepts_https() {
        let result = NodeClient::new("https://rpc.misaka.network");
        assert!(result.is_ok());
    }
}
