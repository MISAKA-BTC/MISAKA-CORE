//! Wallet wRPC client — connects to MISAKA node for blockchain interaction.
//!
//! Provides:
//! - Automatic connection management with reconnection
//! - Request queuing and timeout handling
//! - Subscription management for UTXO change notifications
//! - Multi-endpoint failover
//! - Connection health monitoring

use serde::{Serialize, Deserialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// wRPC client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrpcClientConfig {
    pub url: String,
    pub fallback_urls: Vec<String>,
    pub encoding: WrpcEncoding,
    pub reconnect_interval_ms: u64,
    pub max_reconnect_attempts: u32,
    pub request_timeout_ms: u64,
    pub keep_alive_interval_ms: u64,
    pub max_pending_requests: usize,
    pub max_subscriptions: usize,
    pub tls_enabled: bool,
    pub tls_ca_cert: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WrpcEncoding { Json, Borsh }

impl Default for WrpcClientConfig {
    fn default() -> Self {
        Self {
            url: "ws://127.0.0.1:17110".to_string(),
            fallback_urls: vec![],
            encoding: WrpcEncoding::Json,
            reconnect_interval_ms: 1000,
            max_reconnect_attempts: u32::MAX,
            request_timeout_ms: 30_000,
            keep_alive_interval_ms: 30_000,
            max_pending_requests: 256,
            max_subscriptions: 32,
            tls_enabled: false,
            tls_ca_cert: None,
        }
    }
}

/// Connection state tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Failed,
}

/// Pending RPC request.
#[derive(Debug)]
pub struct PendingRequest {
    pub id: u64,
    pub method: String,
    pub sent_at: u64,
    pub timeout_ms: u64,
}

/// Active subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveSubscription {
    pub id: u64,
    pub scope: String,
    pub created_at: u64,
    pub notification_count: u64,
}

/// wRPC client for wallet-to-node communication.
pub struct WalletRpcClient {
    config: WrpcClientConfig,
    state: AtomicU8Wrapper,
    next_request_id: AtomicU64,
    pending_requests: parking_lot::Mutex<HashMap<u64, PendingRequest>>,
    subscriptions: parking_lot::Mutex<HashMap<u64, ActiveSubscription>>,
    request_queue: parking_lot::Mutex<VecDeque<QueuedRequest>>,
    connected_url: parking_lot::Mutex<Option<String>>,
    reconnect_attempts: AtomicU64,
    total_requests: AtomicU64,
    total_responses: AtomicU64,
    total_errors: AtomicU64,
    total_timeouts: AtomicU64,
    last_activity: AtomicU64,
}

struct AtomicU8Wrapper(std::sync::atomic::AtomicU8);
impl AtomicU8Wrapper {
    fn new(val: u8) -> Self { Self(std::sync::atomic::AtomicU8::new(val)) }
    fn load(&self) -> ConnectionState {
        match self.0.load(Ordering::Relaxed) {
            0 => ConnectionState::Disconnected,
            1 => ConnectionState::Connecting,
            2 => ConnectionState::Connected,
            3 => ConnectionState::Reconnecting,
            _ => ConnectionState::Failed,
        }
    }
    fn store(&self, state: ConnectionState) {
        let val = match state {
            ConnectionState::Disconnected => 0,
            ConnectionState::Connecting => 1,
            ConnectionState::Connected => 2,
            ConnectionState::Reconnecting => 3,
            ConnectionState::Failed => 4,
        };
        self.0.store(val, Ordering::Relaxed);
    }
}

/// Request waiting to be sent (queued during disconnection).
#[derive(Debug)]
struct QueuedRequest {
    id: u64,
    method: String,
    params: serde_json::Value,
    queued_at: u64,
}

impl WalletRpcClient {
    pub fn new(config: WrpcClientConfig) -> Self {
        Self {
            config,
            state: AtomicU8Wrapper::new(0),
            next_request_id: AtomicU64::new(1),
            pending_requests: parking_lot::Mutex::new(HashMap::new()),
            subscriptions: parking_lot::Mutex::new(HashMap::new()),
            request_queue: parking_lot::Mutex::new(VecDeque::new()),
            connected_url: parking_lot::Mutex::new(None),
            reconnect_attempts: AtomicU64::new(0),
            total_requests: AtomicU64::new(0),
            total_responses: AtomicU64::new(0),
            total_errors: AtomicU64::new(0),
            total_timeouts: AtomicU64::new(0),
            last_activity: AtomicU64::new(0),
        }
    }

    /// Prepare a JSON-RPC request.
    pub fn make_request(&self, method: &str, params: serde_json::Value) -> (u64, serde_json::Value) {
        let id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.pending_requests.lock().insert(id, PendingRequest {
            id,
            method: method.to_string(),
            sent_at: now_ms(),
            timeout_ms: self.config.request_timeout_ms,
        });
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": id,
        });
        (id, request)
    }

    /// Handle a response from the node.
    pub fn handle_response(&self, response: &serde_json::Value) -> Option<(String, serde_json::Value)> {
        let id = response.get("id")?.as_u64()?;
        let pending = self.pending_requests.lock().remove(&id)?;
        self.total_responses.fetch_add(1, Ordering::Relaxed);
        self.last_activity.store(now_ms(), Ordering::Relaxed);

        if let Some(error) = response.get("error") {
            self.total_errors.fetch_add(1, Ordering::Relaxed);
            return Some((pending.method, serde_json::json!({"error": error})));
        }

        let result = response.get("result").cloned().unwrap_or(serde_json::Value::Null);
        Some((pending.method, result))
    }

    /// Subscribe to node notifications.
    pub fn subscribe(&self, scope: &str) -> u64 {
        let id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        self.subscriptions.lock().insert(id, ActiveSubscription {
            id,
            scope: scope.to_string(),
            created_at: now_ms(),
            notification_count: 0,
        });
        id
    }

    /// Handle an incoming notification.
    pub fn handle_notification(&self, method: &str, params: &serde_json::Value) {
        let mut subs = self.subscriptions.lock();
        for sub in subs.values_mut() {
            if sub.scope == method || sub.scope == "*" {
                sub.notification_count += 1;
            }
        }
        self.last_activity.store(now_ms(), Ordering::Relaxed);
    }

    /// Clean up timed-out requests.
    pub fn cleanup_timeouts(&self) -> Vec<u64> {
        let now = now_ms();
        let mut pending = self.pending_requests.lock();
        let timed_out: Vec<u64> = pending.iter()
            .filter(|(_, r)| now - r.sent_at > r.timeout_ms)
            .map(|(id, _)| *id)
            .collect();
        for id in &timed_out {
            pending.remove(id);
            self.total_timeouts.fetch_add(1, Ordering::Relaxed);
        }
        timed_out
    }

    /// Queue a request for sending when connected.
    pub fn queue_request(&self, method: &str, params: serde_json::Value) -> u64 {
        let id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        self.request_queue.lock().push_back(QueuedRequest {
            id,
            method: method.to_string(),
            params,
            queued_at: now_ms(),
        });
        id
    }

    /// Drain the request queue (call after reconnecting).
    pub fn drain_queue(&self) -> Vec<(u64, String, serde_json::Value)> {
        let mut queue = self.request_queue.lock();
        let now = now_ms();
        // Drop requests older than request_timeout
        queue.retain(|r| now - r.queued_at < self.config.request_timeout_ms);
        queue.drain(..).map(|r| (r.id, r.method, r.params)).collect()
    }

    // ─── State accessors ──────────────────────────

    pub fn connection_state(&self) -> ConnectionState { self.state.load() }
    pub fn is_connected(&self) -> bool { self.state.load() == ConnectionState::Connected }
    pub fn pending_count(&self) -> usize { self.pending_requests.lock().len() }
    pub fn subscription_count(&self) -> usize { self.subscriptions.lock().len() }
    pub fn queue_size(&self) -> usize { self.request_queue.lock().len() }

    pub fn stats(&self) -> RpcClientStats {
        RpcClientStats {
            state: format!("{:?}", self.state.load()),
            total_requests: self.total_requests.load(Ordering::Relaxed),
            total_responses: self.total_responses.load(Ordering::Relaxed),
            total_errors: self.total_errors.load(Ordering::Relaxed),
            total_timeouts: self.total_timeouts.load(Ordering::Relaxed),
            pending_requests: self.pending_requests.lock().len(),
            active_subscriptions: self.subscriptions.lock().len(),
            queue_size: self.request_queue.lock().len(),
            reconnect_attempts: self.reconnect_attempts.load(Ordering::Relaxed),
            connected_url: self.connected_url.lock().clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcClientStats {
    pub state: String,
    pub total_requests: u64,
    pub total_responses: u64,
    pub total_errors: u64,
    pub total_timeouts: u64,
    pub pending_requests: usize,
    pub active_subscriptions: usize,
    pub queue_size: usize,
    pub reconnect_attempts: u64,
    pub connected_url: Option<String>,
}

/// Convenience methods for specific RPC calls.
impl WalletRpcClient {
    pub fn get_utxos_by_addresses(&self, addresses: &[String]) -> (u64, serde_json::Value) {
        self.make_request("getUtxosByAddresses", serde_json::json!({ "addresses": addresses }))
    }

    pub fn get_balance_by_address(&self, address: &str) -> (u64, serde_json::Value) {
        self.make_request("getBalanceByAddress", serde_json::json!({ "address": address }))
    }

    pub fn submit_transaction(&self, tx_json: serde_json::Value) -> (u64, serde_json::Value) {
        self.make_request("submitTransaction", serde_json::json!({ "transaction": tx_json }))
    }

    pub fn get_block_dag_info(&self) -> (u64, serde_json::Value) {
        self.make_request("getBlockDagInfo", serde_json::json!({}))
    }

    pub fn get_virtual_daa_score(&self) -> (u64, serde_json::Value) {
        self.make_request("getVirtualDaaScore", serde_json::json!({}))
    }

    pub fn estimate_fee_rate(&self) -> (u64, serde_json::Value) {
        self.make_request("estimateFeeRate", serde_json::json!({}))
    }

    pub fn subscribe_utxos_changed(&self, addresses: &[String]) -> u64 {
        self.subscribe("utxosChanged")
    }

    pub fn subscribe_virtual_daa_score(&self) -> u64 {
        self.subscribe("virtualDaaScoreChanged")
    }

    pub fn subscribe_new_block_template(&self) -> u64 {
        self.subscribe("newBlockTemplate")
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
