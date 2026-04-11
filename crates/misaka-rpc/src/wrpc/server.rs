//! wRPC server: accepts WebSocket connections and dispatches requests.

use super::encoding::Encoding;
use super::message::*;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;

/// wRPC server configuration.
#[derive(Debug, Clone)]
pub struct WrpcServerConfig {
    pub listen_addr: SocketAddr,
    pub encoding: Encoding,
    pub max_connections: usize,
    pub max_subscriptions_per_client: usize,
    pub max_frame_size: usize,
    pub heartbeat_interval_ms: u64,
}

impl Default for WrpcServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:17110"
                .parse()
                .expect("invariant: literal \"0.0.0.0:17110\" must parse as SocketAddr"),
            encoding: Encoding::Json,
            max_connections: 1000,
            max_subscriptions_per_client: 256,
            max_frame_size: 4 * 1024 * 1024,
            heartbeat_interval_ms: 30_000,
        }
    }
}

/// Connected wRPC client.
pub struct WrpcClientSession {
    pub id: u64,
    pub addr: SocketAddr,
    pub encoding: Encoding,
    pub subscriptions: Vec<u64>,
    pub connected_at: std::time::Instant,
    pub last_activity: std::time::Instant,
    pub messages_sent: u64,
    pub messages_received: u64,
}

/// wRPC server state.
pub struct WrpcServer {
    config: WrpcServerConfig,
    clients: RwLock<HashMap<u64, WrpcClientSession>>,
    next_client_id: std::sync::atomic::AtomicU64,
    notification_tx: tokio::sync::broadcast::Sender<WrpcNotification>,
}

impl WrpcServer {
    pub fn new(config: WrpcServerConfig) -> Self {
        let (notification_tx, _) = tokio::sync::broadcast::channel(1024);
        Self {
            config,
            clients: RwLock::new(HashMap::new()),
            next_client_id: std::sync::atomic::AtomicU64::new(1),
            notification_tx,
        }
    }

    /// Subscribe to server-push notifications.
    pub fn subscribe_notifications(&self) -> tokio::sync::broadcast::Receiver<WrpcNotification> {
        self.notification_tx.subscribe()
    }

    pub fn register_client(&self, addr: SocketAddr, encoding: Encoding) -> Option<u64> {
        let mut clients = self.clients.write();
        if clients.len() >= self.config.max_connections {
            return None;
        }

        let id = self
            .next_client_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        clients.insert(
            id,
            WrpcClientSession {
                id,
                addr,
                encoding,
                subscriptions: Vec::new(),
                connected_at: std::time::Instant::now(),
                last_activity: std::time::Instant::now(),
                messages_sent: 0,
                messages_received: 0,
            },
        );
        Some(id)
    }

    pub fn remove_client(&self, id: u64) {
        self.clients.write().remove(&id);
    }

    pub fn client_count(&self) -> usize {
        self.clients.read().len()
    }

    /// Broadcast a notification to all subscribed clients.
    pub fn broadcast_notification(&self, notification: &WrpcNotification) -> usize {
        match self.notification_tx.send(notification.clone()) {
            Ok(n) => n,
            Err(_) => 0,
        }
    }

    /// Get client info.
    pub fn client_info(&self, id: u64) -> Option<ClientInfo> {
        self.clients.read().get(&id).map(|c| ClientInfo {
            id: c.id,
            addr: c.addr.to_string(),
            encoding: format!("{:?}", c.encoding),
            subscription_count: c.subscriptions.len(),
            connected_since: c.connected_at.elapsed().as_secs(),
        })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ClientInfo {
    pub id: u64,
    pub addr: String,
    pub encoding: String,
    pub subscription_count: usize,
    pub connected_since: u64,
}
