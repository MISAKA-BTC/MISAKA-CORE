//! HTTP proxy client to a misaka-node RPC endpoint.
//!
//! All reads are forwarded to the upstream node. The API server
//! adds rate limiting, CORS, REST conventions, and (future) caching.
//!
//! # Hardening (v5.2)
//!
//! - **Request ID propagation**: Generates X-Request-Id for traceability.
//! - **Configurable timeout**: via `MISAKA_PROXY_TIMEOUT_SECS` env var.
//! - **Error classification**: Distinguishes timeout / connection / upstream errors.

use anyhow::{Context, Result};
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

/// Default upstream timeout (seconds). Override with MISAKA_PROXY_TIMEOUT_SECS.
const DEFAULT_TIMEOUT_SECS: u64 = 15;

#[derive(Clone)]
pub struct NodeProxy {
    client: reqwest::Client,
    base_url: String,
}

impl NodeProxy {
    pub fn new(node_rpc_url: &str) -> Result<Arc<Self>> {
        let base_url = node_rpc_url.trim_end_matches('/').to_string();
        let timeout_secs: u64 = std::env::var("MISAKA_PROXY_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_TIMEOUT_SECS);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .connect_timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(8)
            .user_agent("misaka-api/0.2.0")
            .build()
            .context("failed to build HTTP client")?;

        Ok(Arc::new(Self { client, base_url }))
    }

    /// Generate a short request ID for tracing.
    fn request_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros();
        format!("api-{:x}", ts & 0xFFFF_FFFF)
    }

    /// Forward a POST request to the upstream node.
    pub async fn post(&self, path: &str, body: &Value) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let req_id = Self::request_id();
        let resp = self
            .client
            .post(&url)
            .header("X-Request-Id", &req_id)
            .json(body)
            .send()
            .await
            .with_context(|| format!("[{}] POST {} failed", req_id, url))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "[{}] upstream {} returned {}: {}",
                req_id,
                path,
                status,
                &text[..text.len().min(300)]
            );
        }

        resp.json()
            .await
            .with_context(|| format!("[{}] failed to parse upstream JSON from {}", req_id, path))
    }

    /// Forward a GET request to the upstream node.
    pub async fn get(&self, path: &str) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let req_id = Self::request_id();
        let resp = self
            .client
            .get(&url)
            .header("X-Request-Id", &req_id)
            .send()
            .await
            .with_context(|| format!("[{}] GET {} failed", req_id, url))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "[{}] upstream {} returned {}: {}",
                req_id,
                path,
                status,
                &text[..text.len().min(300)]
            );
        }

        resp.json()
            .await
            .with_context(|| format!("[{}] failed to parse upstream JSON from {}", req_id, path))
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}
