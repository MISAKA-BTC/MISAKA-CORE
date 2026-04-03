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
use url::Url;

/// Default upstream timeout (seconds). Override with MISAKA_PROXY_TIMEOUT_SECS.
const DEFAULT_TIMEOUT_SECS: u64 = 15;

#[derive(Clone)]
pub struct NodeProxy {
    client: reqwest::Client,
    base_url: String,
    timeout_secs: u64,
}

impl NodeProxy {
    pub fn new(node_rpc_url: &str) -> Result<Arc<Self>> {
        let base_url = sanitize_base_url(node_rpc_url)?;
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

        Ok(Arc::new(Self {
            client,
            base_url,
            timeout_secs,
        }))
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

    pub fn timeout_secs(&self) -> u64 {
        self.timeout_secs
    }
}

fn sanitize_base_url(node_rpc_url: &str) -> Result<String> {
    let trimmed = node_rpc_url.trim();
    let url = Url::parse(trimmed).context("invalid upstream node URL")?;

    match url.scheme() {
        "http" | "https" => {}
        scheme => anyhow::bail!("unsupported upstream URL scheme: {}", scheme),
    }

    if !url.username().is_empty() || url.password().is_some() {
        anyhow::bail!("upstream URL must not contain embedded credentials");
    }

    if url.query().is_some() || url.fragment().is_some() {
        anyhow::bail!("upstream URL must not contain query or fragment");
    }

    if url.host_str().is_none() {
        anyhow::bail!("upstream URL must include a host");
    }

    let path = url.path().trim_end_matches('/');
    if !path.is_empty() && path != "/" {
        anyhow::bail!("upstream URL must not include a path");
    }

    Ok(format!(
        "{}://{}{}",
        url.scheme(),
        url.host_str().expect("validated host"),
        url.port()
            .map(|port| format!(":{}", port))
            .unwrap_or_default()
    ))
}

pub fn classify_upstream_error(err: &anyhow::Error) -> (&'static str, &'static str) {
    let text = err.to_string().to_ascii_lowercase();

    if text.contains("timed out") || text.contains("deadline has elapsed") {
        ("UPSTREAM_TIMEOUT", "upstream request timed out")
    } else if text.contains("parse upstream json")
        || text.contains("returned")
        || text.contains("invalid")
    {
        (
            "UPSTREAM_BAD_RESPONSE",
            "upstream returned an invalid response",
        )
    } else if text.contains("dns")
        || text.contains("connection")
        || text.contains("refused")
        || text.contains("unreachable")
        || text.contains("failed")
    {
        ("UPSTREAM_UNAVAILABLE", "upstream service unavailable")
    } else {
        ("UPSTREAM_ERROR", "upstream request failed")
    }
}

pub fn public_upstream_error(err: &anyhow::Error) -> serde_json::Value {
    let (code, message) = classify_upstream_error(err);
    serde_json::json!({
        "error": {
            "code": code,
            "message": message,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_http_url() {
        let url = sanitize_base_url("http://127.0.0.1:3001/").expect("valid url");
        assert_eq!(url, "http://127.0.0.1:3001");
    }

    #[test]
    fn rejects_embedded_credentials() {
        let err = sanitize_base_url("http://user:pass@127.0.0.1:3001")
            .expect_err("credentials must be rejected");
        assert!(err.to_string().contains("embedded credentials"));
    }

    #[test]
    fn rejects_query_and_fragment() {
        assert!(sanitize_base_url("http://127.0.0.1:3001?a=1").is_err());
        assert!(sanitize_base_url("http://127.0.0.1:3001/#frag").is_err());
    }

    #[test]
    fn rejects_path_segment() {
        let err = sanitize_base_url("http://127.0.0.1:3001/api")
            .expect_err("path segment must be rejected");
        assert!(err.to_string().contains("must not include a path"));
    }

    #[test]
    fn rejects_non_http_scheme() {
        let err = sanitize_base_url("ftp://127.0.0.1:3001").expect_err("scheme");
        assert!(err.to_string().contains("unsupported upstream URL scheme"));
    }

    #[test]
    fn classifies_timeout_error() {
        let err = anyhow::anyhow!("request timed out");
        assert_eq!(
            classify_upstream_error(&err),
            ("UPSTREAM_TIMEOUT", "upstream request timed out")
        );
    }

    #[test]
    fn classifies_connection_error() {
        let err = anyhow::anyhow!("connection refused");
        assert_eq!(
            classify_upstream_error(&err),
            ("UPSTREAM_UNAVAILABLE", "upstream service unavailable")
        );
    }
}
