//! Public Faucet API — queue-based, rate-limited, abuse-resistant.
//!
//! # Architecture
//!
//! ```text
//! HTTP POST /api/v1/faucet/request
//!       ↓ (validation + rate check)
//! FaucetQueue (tokio mpsc channel)
//!       ↓ (background worker)
//! Node RPC → submit_tx
//! ```
//!
//! The API endpoint validates and enqueues; the background worker
//! processes requests sequentially to avoid UTXO locking conflicts.
//!
//! # Rate Limiting
//!
//! Two independent limits:
//! - **Per-IP**: 1 request per `cooldown_secs` (default 24h).
//! - **Per-address**: 1 request per `cooldown_secs`.
//!
//! Both must pass for the request to be accepted.

use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};

use crate::AppState;
use tracing::warn;

// ═══════════════════════════════════════════════════════════════
//  Configuration
// ═══════════════════════════════════════════════════════════════

/// Faucet configuration.
#[derive(Debug, Clone)]
pub struct FaucetConfig {
    /// Drip amount in base units (default: 10 MISAKA = 10_000_000_000).
    /// MISAKA has 9 decimals: 1 MISAKA = 1_000_000_000 base units.
    pub drip_amount: u64,
    /// Cooldown between requests per IP/address (seconds).
    pub cooldown_secs: u64,
    /// Maximum queue depth.
    pub max_queue_depth: usize,
}

impl Default for FaucetConfig {
    fn default() -> Self {
        Self {
            drip_amount: 10_000_000_000, // 10 MISAKA (9 decimals)
            cooldown_secs: 86400, // 24 hours
            max_queue_depth: 100,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Rate Limiter (IP + Address)
// ═══════════════════════════════════════════════════════════════

#[derive(Clone)]
pub struct FaucetRateLimiter {
    ip_last: Arc<Mutex<HashMap<String, Instant>>>,
    addr_last: Arc<Mutex<HashMap<String, Instant>>>,
    cooldown: Duration,
}

impl FaucetRateLimiter {
    pub fn new(cooldown_secs: u64) -> Self {
        Self {
            ip_last: Arc::new(Mutex::new(HashMap::new())),
            addr_last: Arc::new(Mutex::new(HashMap::new())),
            cooldown: Duration::from_secs(cooldown_secs),
        }
    }

    /// Check if a request is allowed. Returns Ok(()) or Err(wait_seconds).
    pub async fn check(&self, ip: &str, address: &str) -> Result<(), u64> {
        let now = Instant::now();

        // Check IP
        {
            let mut map = self.ip_last.lock().await;
            if let Some(last) = map.get(ip) {
                let elapsed = now.duration_since(*last);
                if elapsed < self.cooldown {
                    let wait = (self.cooldown - elapsed).as_secs().max(1);
                    return Err(wait);
                }
            }
        }

        // Check address
        {
            let mut map = self.addr_last.lock().await;
            if let Some(last) = map.get(address) {
                let elapsed = now.duration_since(*last);
                if elapsed < self.cooldown {
                    let wait = (self.cooldown - elapsed).as_secs().max(1);
                    return Err(wait);
                }
            }
        }

        Ok(())
    }

    /// Record a successful request.
    pub async fn record(&self, ip: &str, address: &str) {
        let now = Instant::now();
        self.ip_last.lock().await.insert(ip.to_string(), now);
        self.addr_last.lock().await.insert(address.to_string(), now);
    }

    /// Periodic cleanup of expired entries.
    pub async fn cleanup(&self) {
        let cutoff = Instant::now() - self.cooldown * 2;
        self.ip_last.lock().await.retain(|_, v| *v > cutoff);
        self.addr_last.lock().await.retain(|_, v| *v > cutoff);
    }
}

// ═══════════════════════════════════════════════════════════════
//  Request / Response Types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Deserialize)]
pub struct FaucetRequest {
    pub address: String,
}

#[derive(Debug, Serialize)]
pub struct FaucetResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
    pub queue_position: Option<usize>,
}

// ═══════════════════════════════════════════════════════════════
//  Queue Item
// ═══════════════════════════════════════════════════════════════

#[derive(Debug)]
struct FaucetQueueItem {
    address: String,
    ip: String,
    /// Channel to send the result back to the HTTP handler.
    response_tx: tokio::sync::oneshot::Sender<FaucetWorkerResult>,
}

#[derive(Debug)]
enum FaucetWorkerResult {
    Success { tx_hash: String, amount: u64 },
    Failed { error: String },
}

// ═══════════════════════════════════════════════════════════════
//  Faucet State (shared between API handler and worker)
// ═══════════════════════════════════════════════════════════════

/// Shared faucet state — thread-safe, cloneable.
#[derive(Clone)]
pub struct FaucetState {
    rate_limiter: FaucetRateLimiter,
    queue_tx: mpsc::Sender<FaucetQueueItem>,
    queue_depth: Arc<Mutex<usize>>,
    config: FaucetConfig,
    proxy: Arc<crate::proxy::NodeProxy>,
}

impl FaucetState {
    /// Create a new faucet state and spawn the background worker.
    pub fn new(config: FaucetConfig, proxy: Arc<crate::proxy::NodeProxy>) -> Self {
        let (queue_tx, queue_rx) = mpsc::channel::<FaucetQueueItem>(config.max_queue_depth);
        let rate_limiter = FaucetRateLimiter::new(config.cooldown_secs);
        let queue_depth = Arc::new(Mutex::new(0usize));

        let state = Self {
            rate_limiter,
            queue_tx,
            queue_depth: queue_depth.clone(),
            config: config.clone(),
            proxy: proxy.clone(),
        };

        // Spawn background worker
        let worker_proxy = proxy;
        let worker_depth = queue_depth;
        let drip_amount = config.drip_amount;
        tokio::spawn(async move {
            faucet_worker(queue_rx, worker_proxy, worker_depth, drip_amount).await;
        });

        state
    }
}

/// Background worker — processes faucet requests sequentially.
async fn faucet_worker(
    mut rx: mpsc::Receiver<FaucetQueueItem>,
    proxy: Arc<crate::proxy::NodeProxy>,
    depth: Arc<Mutex<usize>>,
    drip_amount: u64,
) {
    while let Some(item) = rx.recv().await {
        let result = process_drip(&proxy, &item.address, drip_amount).await;
        {
            let mut d = depth.lock().await;
            *d = d.saturating_sub(1);
        }
        // Send result back (ignore if receiver dropped)
        let _ = item.response_tx.send(result);
    }
}

/// Process a single faucet drip via the node RPC.
async fn process_drip(
    proxy: &crate::proxy::NodeProxy,
    address: &str,
    amount: u64,
) -> FaucetWorkerResult {
    let body = serde_json::json!({
        "address": address,
        "amount": amount,
    });

    match proxy.post("/api/faucet", &body).await {
        Ok(resp) => {
            let success = resp["success"].as_bool().unwrap_or(false);
            if success {
                FaucetWorkerResult::Success {
                    tx_hash: resp["txHash"].as_str().unwrap_or("unknown").to_string(),
                    amount: resp["amount"].as_u64().unwrap_or(amount),
                }
            } else {
                FaucetWorkerResult::Failed {
                    error: resp["error"]
                        .as_str()
                        .unwrap_or("unknown error")
                        .to_string(),
                }
            }
        }
        Err(e) => FaucetWorkerResult::Failed {
            error: format!("node error: {}", e),
        },
    }
}

// ═══════════════════════════════════════════════════════════════
//  Router
// ═══════════════════════════════════════════════════════════════

pub fn router(faucet: FaucetState) -> Router {
    Router::new()
        .route("/api/v1/faucet/request", post(handle_faucet_request))
        .route("/api/v1/faucet/status", axum::routing::get(handle_faucet_status))
        .with_state(faucet)
}

// ═══════════════════════════════════════════════════════════════
//  Handlers
// ═══════════════════════════════════════════════════════════════

/// `POST /api/v1/faucet/request`
async fn handle_faucet_request(
    State(faucet): State<FaucetState>,
    maybe_addr: Option<ConnectInfo<SocketAddr>>,
    Json(req): Json<FaucetRequest>,
) -> (StatusCode, Json<FaucetResponse>) {
    // SEC-FIX-2: If ConnectInfo is unavailable, reject the request instead
    // of falling back to "unknown". Otherwise all users share one cooldown
    // bucket, making the faucet a global lock after a single request.
    let ip = match maybe_addr {
        Some(addr) => addr.0.ip().to_string(),
        None => {
            tracing::warn!("Faucet: ConnectInfo unavailable, rejecting request");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(FaucetResponse {
                    status: "error".into(),
                    tx_hash: None,
                    amount: None,
                    error: Some(
                        "server misconfiguration: cannot determine client IP".into(),
                    ),
                    retry_after: None,
                    queue_position: None,
                }),
            );
        }
    };

    // ── Validate address ──
    let address = req.address.trim();
    if !address.starts_with("msk1") {
        return (
            StatusCode::BAD_REQUEST,
            Json(FaucetResponse {
                status: "error".into(),
                tx_hash: None,
                amount: None,
                error: Some("address must start with msk1".into()),
                retry_after: None,
                queue_position: None,
            }),
        );
    }
    if address.len() < 10 || address.len() > 100 {
        return (
            StatusCode::BAD_REQUEST,
            Json(FaucetResponse {
                status: "error".into(),
                tx_hash: None,
                amount: None,
                error: Some("address length must be 10-100 characters".into()),
                retry_after: None,
                queue_position: None,
            }),
        );
    }

    // ── Rate limit check (IP + address) ──
    if let Err(wait) = faucet.rate_limiter.check(&ip, address).await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(FaucetResponse {
                status: "rate_limited".into(),
                tx_hash: None,
                amount: None,
                error: Some(format!("rate limited, retry after {}s", wait)),
                retry_after: Some(wait),
                queue_position: None,
            }),
        );
    }

    // ── Queue depth check ──
    let current_depth = {
        let d = faucet.queue_depth.lock().await;
        *d
    };
    if current_depth >= faucet.config.max_queue_depth {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(FaucetResponse {
                status: "queue_full".into(),
                tx_hash: None,
                amount: None,
                error: Some("faucet queue is full, try again later".into()),
                retry_after: Some(30),
                queue_position: None,
            }),
        );
    }

    // ── Enqueue ──
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    let item = FaucetQueueItem {
        address: address.to_string(),
        ip: ip.clone(),
        response_tx,
    };

    {
        let mut d = faucet.queue_depth.lock().await;
        *d += 1;
    }

    if faucet.queue_tx.send(item).await.is_err() {
        // SEC-FIX-9: Decrement depth on send failure — otherwise the counter
        // drifts upward and eventually blocks all future requests.
        {
            let mut d = faucet.queue_depth.lock().await;
            *d = d.saturating_sub(1);
        }
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(FaucetResponse {
                status: "error".into(),
                tx_hash: None,
                amount: None,
                error: Some("faucet worker not running".into()),
                retry_after: None,
                queue_position: None,
            }),
        );
    }

    // Record rate limit BEFORE waiting for result (prevent spam during processing)
    faucet.rate_limiter.record(&ip, address).await;

    // Wait for worker result (with timeout)
    let result = tokio::time::timeout(Duration::from_secs(30), response_rx).await;

    match result {
        Ok(Ok(FaucetWorkerResult::Success { tx_hash, amount })) => (
            StatusCode::OK,
            Json(FaucetResponse {
                status: "success".into(),
                tx_hash: Some(tx_hash),
                amount: Some(amount),
                error: None,
                retry_after: None,
                queue_position: None,
            }),
        ),
        Ok(Ok(FaucetWorkerResult::Failed { error })) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(FaucetResponse {
                status: "failed".into(),
                tx_hash: None,
                amount: None,
                error: Some(error),
                retry_after: None,
                queue_position: None,
            }),
        ),
        Ok(Err(_)) => {
            // SEC-FIX-9: Worker dropped the oneshot without processing.
            // The worker's recv loop decrements depth on normal processing,
            // but if the channel was dropped without recv, depth is stale.
            {
                let mut d = faucet.queue_depth.lock().await;
                *d = d.saturating_sub(1);
            }
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(FaucetResponse {
                    status: "error".into(),
                    tx_hash: None,
                    amount: None,
                    error: Some("worker channel dropped".into()),
                    retry_after: None,
                    queue_position: None,
                }),
            )
        }
        Err(_) => {
            // SEC-FIX-9: Timeout — the worker may still process the item
            // later and decrement, but if it never does, depth drifts.
            // We decrement here defensively; the worker's decrement will
            // saturate at 0 so no underflow occurs.
            {
                let mut d = faucet.queue_depth.lock().await;
                *d = d.saturating_sub(1);
            }
            (
                StatusCode::GATEWAY_TIMEOUT,
                Json(FaucetResponse {
                    status: "timeout".into(),
                    tx_hash: None,
                    amount: None,
                    error: Some("faucet request timed out (30s)".into()),
                    retry_after: Some(60),
                    queue_position: None,
                }),
            )
        }
    }
}

/// `GET /api/v1/faucet/status`
async fn handle_faucet_status(
    State(faucet): State<FaucetState>,
) -> Json<serde_json::Value> {
    let depth = *faucet.queue_depth.lock().await;
    Json(serde_json::json!({
        "queue_depth": depth,
        "max_queue_depth": faucet.config.max_queue_depth,
        "drip_amount": faucet.config.drip_amount,
        "cooldown_secs": faucet.config.cooldown_secs,
    }))
}
