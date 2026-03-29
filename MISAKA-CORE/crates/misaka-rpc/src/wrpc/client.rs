//! wRPC client: connects to a MISAKA node via WebSocket.

use super::message::*;
use super::encoding::Encoding;
use crate::error::{RpcError, RpcResult};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicBool, Ordering};
use parking_lot::Mutex;

/// wRPC client configuration.
#[derive(Debug, Clone)]
pub struct WrpcClientConfig {
    pub url: String,
    pub encoding: Encoding,
    pub reconnect_interval_ms: u64,
    pub max_reconnect_attempts: u32,
    pub request_timeout_ms: u64,
    pub max_pending_requests: usize,
}

impl Default for WrpcClientConfig {
    fn default() -> Self {
        Self {
            url: "ws://127.0.0.1:17110".to_string(),
            encoding: Encoding::Json,
            reconnect_interval_ms: 1000,
            max_reconnect_attempts: 10,
            request_timeout_ms: 30_000,
            max_pending_requests: 1000,
        }
    }
}

/// wRPC client state.
pub struct WrpcClient {
    config: WrpcClientConfig,
    next_id: AtomicU64,
    is_connected: AtomicBool,
    pending: Mutex<HashMap<u64, PendingRequest>>,
    subscriptions: Mutex<HashMap<u64, String>>,
}

struct PendingRequest {
    method: String,
    sent_at: std::time::Instant,
}

impl WrpcClient {
    pub fn new(config: WrpcClientConfig) -> Self {
        Self {
            config,
            next_id: AtomicU64::new(1),
            is_connected: AtomicBool::new(false),
            pending: Mutex::new(HashMap::new()),
            subscriptions: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new request with auto-incrementing ID.
    pub fn create_request(&self, method: &str, params: serde_json::Value) -> WrpcRequest {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.pending.lock().insert(id, PendingRequest {
            method: method.to_string(),
            sent_at: std::time::Instant::now(),
        });
        WrpcRequest { id, method: method.to_string(), params }
    }

    /// Handle a response.
    pub fn handle_response(&self, response: WrpcResponse) -> Option<String> {
        self.pending.lock().remove(&response.id).map(|r| r.method)
    }

    /// Subscribe to notifications.
    pub fn subscribe(&self, scope: &str) -> SubscriptionRequest {
        SubscriptionRequest {
            scope: scope.to_string(),
            params: None,
        }
    }

    /// Handle subscription acknowledgment.
    pub fn handle_subscription_ack(&self, ack: SubscriptionAck) {
        self.subscriptions.lock().insert(ack.listener_id, ack.scope);
    }

    pub fn is_connected(&self) -> bool { self.is_connected.load(Ordering::Relaxed) }
    pub fn pending_count(&self) -> usize { self.pending.lock().len() }
    pub fn subscription_count(&self) -> usize { self.subscriptions.lock().len() }

    /// Clean up timed-out requests.
    pub fn cleanup_timeouts(&self) -> Vec<u64> {
        let timeout = std::time::Duration::from_millis(self.config.request_timeout_ms);
        let mut pending = self.pending.lock();
        let timed_out: Vec<u64> = pending.iter()
            .filter(|(_, r)| r.sent_at.elapsed() > timeout)
            .map(|(id, _)| *id)
            .collect();
        for id in &timed_out {
            pending.remove(id);
        }
        timed_out
    }
}
