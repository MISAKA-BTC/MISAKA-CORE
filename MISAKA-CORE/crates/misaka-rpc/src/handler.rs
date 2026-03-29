//! RPC request handler — unified handler for JSON-RPC, wRPC, and gRPC.
//!
//! Provides a single entry point for all RPC protocols with:
//! - Unified method dispatching
//! - Protocol-agnostic request/response types
//! - Middleware chain (auth → rate limit → validate → execute → log)
//! - Metrics collection per method

use crate::error::{RpcError, RpcResult};
use crate::auth::{TokenManager, MethodRateLimiter, AuthRole};
use crate::ops::RpcOp;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

/// Protocol-agnostic RPC request.
#[derive(Debug, Clone)]
pub struct RpcRequest {
    pub id: u64,
    pub method: String,
    pub params: serde_json::Value,
    pub protocol: RpcProtocol,
    pub client_id: String,
    pub client_addr: Option<String>,
    pub auth_token: Option<String>,
}

/// Protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcProtocol {
    JsonRpc,
    Wrpc,
    Grpc,
}

/// Protocol-agnostic RPC response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    pub id: u64,
    pub result: Option<serde_json::Value>,
    pub error: Option<RpcErrorResponse>,
    pub processing_time_ms: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcErrorResponse {
    pub code: i32,
    pub message: String,
}

/// Per-method execution metrics.
pub struct MethodMetrics {
    pub call_count: std::sync::atomic::AtomicU64,
    pub error_count: std::sync::atomic::AtomicU64,
    pub total_time_us: std::sync::atomic::AtomicU64,
    pub max_time_us: std::sync::atomic::AtomicU64,
}

impl MethodMetrics {
    fn new() -> Self {
        Self {
            call_count: std::sync::atomic::AtomicU64::new(0),
            error_count: std::sync::atomic::AtomicU64::new(0),
            total_time_us: std::sync::atomic::AtomicU64::new(0),
            max_time_us: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

/// RPC handler with full middleware pipeline.
pub struct RpcHandler {
    auth: Option<Arc<TokenManager>>,
    rate_limiter: MethodRateLimiter,
    metrics: parking_lot::RwLock<HashMap<String, Arc<MethodMetrics>>>,
    total_requests: std::sync::atomic::AtomicU64,
    total_errors: std::sync::atomic::AtomicU64,
    require_auth: bool,
    admin_methods: Vec<String>,
}

impl RpcHandler {
    pub fn new(require_auth: bool) -> Self {
        Self {
            auth: None,
            rate_limiter: MethodRateLimiter::new(),
            metrics: parking_lot::RwLock::new(HashMap::new()),
            total_requests: std::sync::atomic::AtomicU64::new(0),
            total_errors: std::sync::atomic::AtomicU64::new(0),
            require_auth,
            admin_methods: vec![
                "shutdown".into(), "addPeer".into(), "banPeer".into(),
                "unbanPeer".into(), "resolveFinalityConflict".into(),
            ],
        }
    }

    pub fn with_auth(mut self, token_manager: Arc<TokenManager>) -> Self {
        self.auth = Some(token_manager);
        self
    }

    /// Process an RPC request through the full middleware pipeline.
    pub fn handle(&self, request: RpcRequest) -> RpcResponse {
        let start = Instant::now();
        self.total_requests.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // 1. Authentication
        if let Err(e) = self.check_auth(&request) {
            return self.error_response(request.id, -32000, &e.to_string(), start);
        }

        // 2. Rate limiting
        if !self.rate_limiter.check(&request.method, &request.client_id) {
            return self.error_response(request.id, -32429, "rate limited", start);
        }

        // 3. Method validation
        if RpcOp::from_method(&request.method).is_none() {
            return self.error_response(request.id, -32601, &format!("method not found: {}", request.method), start);
        }

        // 4. Execute (placeholder — actual execution delegated to service_impl)
        let result = serde_json::json!({"message": "method dispatched"});

        // 5. Record metrics
        self.record_metrics(&request.method, start, false);

        RpcResponse {
            id: request.id,
            result: Some(result),
            error: None,
            processing_time_ms: start.elapsed().as_secs_f64() * 1000.0,
        }
    }

    fn check_auth(&self, request: &RpcRequest) -> RpcResult<()> {
        if !self.require_auth { return Ok(()); }

        // Admin methods always require auth
        if self.admin_methods.contains(&request.method) {
            let token = request.auth_token.as_deref()
                .ok_or(RpcError::Unauthorized("admin method requires authentication".into()))?;
            if let Some(ref auth) = self.auth {
                auth.check_authorization(token, &request.method)
                    .map_err(|e| RpcError::Unauthorized(e.to_string()))?;
            }
        }
        Ok(())
    }

    fn error_response(&self, id: u64, code: i32, message: &str, start: Instant) -> RpcResponse {
        self.total_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        RpcResponse {
            id,
            result: None,
            error: Some(RpcErrorResponse { code, message: message.to_string() }),
            processing_time_ms: start.elapsed().as_secs_f64() * 1000.0,
        }
    }

    fn record_metrics(&self, method: &str, start: Instant, is_error: bool) {
        let elapsed_us = start.elapsed().as_micros() as u64;
        let metrics = {
            let map = self.metrics.read();
            map.get(method).cloned()
        };
        let metrics = match metrics {
            Some(m) => m,
            None => {
                let m = Arc::new(MethodMetrics::new());
                self.metrics.write().insert(method.to_string(), m.clone());
                m
            }
        };
        metrics.call_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        metrics.total_time_us.fetch_add(elapsed_us, std::sync::atomic::Ordering::Relaxed);
        metrics.max_time_us.fetch_max(elapsed_us, std::sync::atomic::Ordering::Relaxed);
        if is_error {
            metrics.error_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    /// Get metrics snapshot for all methods.
    pub fn metrics_snapshot(&self) -> HashMap<String, MethodMetricsSnapshot> {
        let map = self.metrics.read();
        map.iter().map(|(method, m)| {
            let calls = m.call_count.load(std::sync::atomic::Ordering::Relaxed);
            let total_us = m.total_time_us.load(std::sync::atomic::Ordering::Relaxed);
            (method.clone(), MethodMetricsSnapshot {
                call_count: calls,
                error_count: m.error_count.load(std::sync::atomic::Ordering::Relaxed),
                avg_time_us: if calls > 0 { total_us / calls } else { 0 },
                max_time_us: m.max_time_us.load(std::sync::atomic::Ordering::Relaxed),
            })
        }).collect()
    }

    pub fn total_requests(&self) -> u64 { self.total_requests.load(std::sync::atomic::Ordering::Relaxed) }
    pub fn total_errors(&self) -> u64 { self.total_errors.load(std::sync::atomic::Ordering::Relaxed) }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodMetricsSnapshot {
    pub call_count: u64,
    pub error_count: u64,
    pub avg_time_us: u64,
    pub max_time_us: u64,
}
