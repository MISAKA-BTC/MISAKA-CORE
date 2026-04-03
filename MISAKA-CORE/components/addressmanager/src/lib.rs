//! Address manager: maintains the set of known peer addresses
//! for P2P network discovery and connection management.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Address entry with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressEntry {
    pub addr: SocketAddr,
    pub source: AddressSource,
    pub last_connected: Option<u64>,
    pub last_attempt: Option<u64>,
    pub last_success: Option<u64>,
    pub connection_attempts: u32,
    pub connection_failures: u32,
    pub services: u64,
    pub is_banned: bool,
    pub ban_until: Option<u64>,
    pub user_agent: Option<String>,
    pub version: Option<u32>,
}

/// How we learned about this address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressSource {
    /// From DNS seeds.
    Dns,
    /// From peer address announcements.
    Peer,
    /// From manual configuration.
    Manual,
    /// From a previous session (persisted).
    Persisted,
    /// Inbound connection.
    Inbound,
}

/// Address manager configuration.
#[derive(Debug, Clone)]
pub struct AddressManagerConfig {
    pub max_addresses: usize,
    pub max_outbound: usize,
    pub max_inbound: usize,
    pub ban_duration: Duration,
    pub retry_interval: Duration,
    pub max_retries: u32,
    pub dns_seeds: Vec<String>,
}

impl Default for AddressManagerConfig {
    fn default() -> Self {
        Self {
            max_addresses: 10_000,
            max_outbound: 8,
            max_inbound: 117,
            ban_duration: Duration::from_secs(3600 * 24),
            retry_interval: Duration::from_secs(300),
            max_retries: 5,
            dns_seeds: vec![
                "seed1.misaka.network".to_string(),
                "seed2.misaka.network".to_string(),
            ],
        }
    }
}

/// Manages known peer addresses for the P2P network.
pub struct AddressManager {
    config: AddressManagerConfig,
    addresses: RwLock<HashMap<SocketAddr, AddressEntry>>,
    connected: RwLock<HashSet<SocketAddr>>,
    tried: RwLock<HashMap<SocketAddr, Instant>>,
}

impl AddressManager {
    pub fn new(config: AddressManagerConfig) -> Self {
        Self {
            config,
            addresses: RwLock::new(HashMap::new()),
            connected: RwLock::new(HashSet::new()),
            tried: RwLock::new(HashMap::new()),
        }
    }

    /// Add a new address to the pool.
    pub fn add_address(&self, addr: SocketAddr, source: AddressSource) -> bool {
        let mut addresses = self.addresses.write();
        if addresses.len() >= self.config.max_addresses {
            Self::evict_oldest(&mut addresses);
        }
        if addresses.contains_key(&addr) {
            return false;
        }
        addresses.insert(
            addr,
            AddressEntry {
                addr,
                source,
                last_connected: None,
                last_attempt: None,
                last_success: None,
                connection_attempts: 0,
                connection_failures: 0,
                services: 0,
                is_banned: false,
                ban_until: None,
                user_agent: None,
                version: None,
            },
        );
        true
    }

    /// Add multiple addresses.
    pub fn add_addresses(&self, addrs: &[SocketAddr], source: AddressSource) -> usize {
        addrs
            .iter()
            .filter(|a| self.add_address(**a, source))
            .count()
    }

    /// Mark an address as connected.
    pub fn mark_connected(&self, addr: &SocketAddr) {
        self.connected.write().insert(*addr);
        if let Some(entry) = self.addresses.write().get_mut(addr) {
            entry.last_connected = Some(now_secs());
            entry.last_success = Some(now_secs());
        }
    }

    /// Mark an address as disconnected.
    pub fn mark_disconnected(&self, addr: &SocketAddr) {
        self.connected.write().remove(addr);
    }

    /// Mark a connection attempt.
    pub fn mark_attempt(&self, addr: &SocketAddr) {
        self.tried.write().insert(*addr, Instant::now());
        if let Some(entry) = self.addresses.write().get_mut(addr) {
            entry.last_attempt = Some(now_secs());
            entry.connection_attempts += 1;
        }
    }

    /// Mark a connection failure.
    pub fn mark_failed(&self, addr: &SocketAddr) {
        if let Some(entry) = self.addresses.write().get_mut(addr) {
            entry.connection_failures += 1;
        }
    }

    /// Ban an address.
    pub fn ban(&self, addr: &SocketAddr) {
        if let Some(entry) = self.addresses.write().get_mut(addr) {
            entry.is_banned = true;
            entry.ban_until = Some(now_secs() + self.config.ban_duration.as_secs());
        }
        self.connected.write().remove(addr);
    }

    /// Unban an address.
    pub fn unban(&self, addr: &SocketAddr) {
        if let Some(entry) = self.addresses.write().get_mut(addr) {
            entry.is_banned = false;
            entry.ban_until = None;
            entry.connection_failures = 0;
        }
    }

    /// Check if an address is banned.
    pub fn is_banned(&self, addr: &SocketAddr) -> bool {
        self.addresses.read().get(addr).map_or(false, |e| {
            if !e.is_banned {
                return false;
            }
            if let Some(until) = e.ban_until {
                now_secs() < until
            } else {
                true
            }
        })
    }

    /// Select addresses for outbound connections.
    pub fn select_for_outbound(&self, count: usize) -> Vec<SocketAddr> {
        let addresses = self.addresses.read();
        let connected = self.connected.read();
        let tried = self.tried.read();

        let mut candidates: Vec<_> = addresses
            .values()
            .filter(|e| {
                !e.is_banned
                    && !connected.contains(&e.addr)
                    && e.connection_failures < self.config.max_retries
                    && !tried
                        .get(&e.addr)
                        .map_or(false, |t| t.elapsed() < self.config.retry_interval)
            })
            .collect();

        // Prefer addresses we've successfully connected to before
        candidates.sort_by(|a, b| {
            b.last_success
                .cmp(&a.last_success)
                .then(a.connection_failures.cmp(&b.connection_failures))
        });

        candidates.iter().take(count).map(|e| e.addr).collect()
    }

    /// Get all connected addresses.
    pub fn connected_addresses(&self) -> Vec<SocketAddr> {
        self.connected.read().iter().copied().collect()
    }

    /// Get the total number of known addresses.
    pub fn known_count(&self) -> usize {
        self.addresses.read().len()
    }

    /// Get the number of connected peers.
    pub fn connected_count(&self) -> usize {
        self.connected.read().len()
    }

    /// Get the number of banned addresses.
    pub fn banned_count(&self) -> usize {
        self.addresses
            .read()
            .values()
            .filter(|e| e.is_banned)
            .count()
    }

    /// Get random addresses for sharing with peers.
    pub fn get_addresses_for_sharing(&self, count: usize) -> Vec<SocketAddr> {
        let addresses = self.addresses.read();
        addresses
            .values()
            .filter(|e| !e.is_banned && e.last_success.is_some())
            .take(count)
            .map(|e| e.addr)
            .collect()
    }

    fn evict_oldest(addresses: &mut HashMap<SocketAddr, AddressEntry>) {
        // Remove addresses with most failures
        if let Some(worst) = addresses
            .values()
            .filter(|e| !e.is_banned)
            .max_by_key(|e| e.connection_failures)
            .map(|e| e.addr)
        {
            addresses.remove(&worst);
        }
    }

    /// Clean up expired bans and stale entries.
    pub fn cleanup(&self) -> usize {
        let mut addresses = self.addresses.write();
        let now = now_secs();
        let before = addresses.len();

        // Unban expired entries
        for entry in addresses.values_mut() {
            if entry.is_banned {
                if let Some(until) = entry.ban_until {
                    if now >= until {
                        entry.is_banned = false;
                        entry.ban_until = None;
                    }
                }
            }
        }

        // Remove stale entries (never connected, many failures)
        addresses.retain(|_, e| e.last_success.is_some() || e.connection_failures < 10);

        before - addresses.len()
    }
}

pub fn stores() {}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
