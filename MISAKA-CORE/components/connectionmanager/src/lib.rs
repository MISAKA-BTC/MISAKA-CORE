//! Connection manager: orchestrates P2P connections, handshakes,
//! and connection lifecycle management.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Connecting,
    Handshaking,
    Connected,
    Disconnecting,
    Disconnected,
    Failed,
}

/// Direction of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDirection {
    Inbound,
    Outbound,
}

/// Peer connection info.
#[derive(Debug, Clone)]
pub struct PeerConnection {
    pub id: u64,
    pub addr: SocketAddr,
    pub direction: ConnectionDirection,
    pub state: ConnectionState,
    pub connected_at: Instant,
    pub last_message_at: Option<Instant>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub latency_ms: Option<f64>,
    pub user_agent: Option<String>,
    pub protocol_version: Option<u32>,
}

/// Connection manager configuration.
#[derive(Debug, Clone)]
pub struct ConnectionManagerConfig {
    pub max_outbound: usize,
    pub max_inbound: usize,
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
    pub ping_interval: Duration,
    pub connect_timeout: Duration,
}

impl Default for ConnectionManagerConfig {
    fn default() -> Self {
        Self {
            max_outbound: 8,
            max_inbound: 117,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            ping_interval: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(30),
        }
    }
}

/// Manages active P2P connections.
pub struct ConnectionManager {
    config: ConnectionManagerConfig,
    connections: RwLock<HashMap<u64, PeerConnection>>,
    by_addr: RwLock<HashMap<SocketAddr, u64>>,
    next_id: std::sync::atomic::AtomicU64,
}

impl ConnectionManager {
    pub fn new(config: ConnectionManagerConfig) -> Self {
        Self {
            config,
            connections: RwLock::new(HashMap::new()),
            by_addr: RwLock::new(HashMap::new()),
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    /// Register a new connection.
    pub fn register(&self, addr: SocketAddr, direction: ConnectionDirection) -> Option<u64> {
        let connections = self.connections.read();
        let count = connections
            .values()
            .filter(|c| c.direction == direction && c.state == ConnectionState::Connected)
            .count();

        let limit = match direction {
            ConnectionDirection::Outbound => self.config.max_outbound,
            ConnectionDirection::Inbound => self.config.max_inbound,
        };

        if count >= limit {
            return None;
        }
        drop(connections);

        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let conn = PeerConnection {
            id,
            addr,
            direction,
            state: ConnectionState::Connecting,
            connected_at: Instant::now(),
            last_message_at: None,
            bytes_sent: 0,
            bytes_received: 0,
            messages_sent: 0,
            messages_received: 0,
            latency_ms: None,
            user_agent: None,
            protocol_version: None,
        };

        self.connections.write().insert(id, conn);
        self.by_addr.write().insert(addr, id);
        Some(id)
    }

    /// Update connection state.
    pub fn set_state(&self, id: u64, state: ConnectionState) {
        if let Some(conn) = self.connections.write().get_mut(&id) {
            conn.state = state;
        }
    }

    /// Remove a connection.
    pub fn remove(&self, id: u64) -> Option<PeerConnection> {
        let conn = self.connections.write().remove(&id);
        if let Some(ref c) = conn {
            self.by_addr.write().remove(&c.addr);
        }
        conn
    }

    /// Get connection by ID.
    pub fn get(&self, id: u64) -> Option<PeerConnection> {
        self.connections.read().get(&id).cloned()
    }

    /// Get connection by address.
    pub fn get_by_addr(&self, addr: &SocketAddr) -> Option<PeerConnection> {
        let by_addr = self.by_addr.read();
        by_addr
            .get(addr)
            .and_then(|id| self.connections.read().get(id).cloned())
    }

    /// Record bytes sent.
    pub fn record_sent(&self, id: u64, bytes: u64) {
        if let Some(conn) = self.connections.write().get_mut(&id) {
            conn.bytes_sent += bytes;
            conn.messages_sent += 1;
            conn.last_message_at = Some(Instant::now());
        }
    }

    /// Record bytes received.
    pub fn record_received(&self, id: u64, bytes: u64) {
        if let Some(conn) = self.connections.write().get_mut(&id) {
            conn.bytes_received += bytes;
            conn.messages_received += 1;
            conn.last_message_at = Some(Instant::now());
        }
    }

    /// Update latency measurement.
    pub fn update_latency(&self, id: u64, latency_ms: f64) {
        if let Some(conn) = self.connections.write().get_mut(&id) {
            conn.latency_ms = Some(latency_ms);
        }
    }

    /// Get idle connections that should be pinged or disconnected.
    pub fn idle_connections(&self) -> Vec<u64> {
        let connections = self.connections.read();
        connections
            .values()
            .filter(|c| {
                c.state == ConnectionState::Connected
                    && c.last_message_at
                        .map_or(true, |t| t.elapsed() > self.config.idle_timeout)
            })
            .map(|c| c.id)
            .collect()
    }

    /// Get all active connection infos.
    pub fn active_connections(&self) -> Vec<PeerConnection> {
        self.connections
            .read()
            .values()
            .filter(|c| c.state == ConnectionState::Connected)
            .cloned()
            .collect()
    }

    pub fn outbound_count(&self) -> usize {
        self.connections
            .read()
            .values()
            .filter(|c| {
                c.direction == ConnectionDirection::Outbound
                    && c.state == ConnectionState::Connected
            })
            .count()
    }

    pub fn inbound_count(&self) -> usize {
        self.connections
            .read()
            .values()
            .filter(|c| {
                c.direction == ConnectionDirection::Inbound && c.state == ConnectionState::Connected
            })
            .count()
    }

    pub fn total_connections(&self) -> usize {
        self.connections
            .read()
            .values()
            .filter(|c| c.state == ConnectionState::Connected)
            .count()
    }
}
