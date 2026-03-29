//! Sentry Bridge — persistent Validator↔Sentry connections.
//!
//! # Architecture
//!
//! ```text
//!                    Public Internet
//!                         │
//!        ┌────────────────┼────────────────┐
//!        │                │                │
//!   ┌────┴────┐     ┌────┴────┐     ┌────┴────┐
//!   │ Sentry A│     │ Sentry B│     │ Sentry C│
//!   └────┬────┘     └────┬────┘     └────┬────┘
//!        │                │                │
//!        └────────────────┼────────────────┘
//!                  PQ-Authenticated Links
//!                  (Validator dials OUT)
//!                         │
//!                  ┌──────┴──────┐
//!                  │  VALIDATOR  │
//!                  │ (NO listen) │
//!                  └─────────────┘
//! ```
//!
//! # Key Properties
//!
//! 1. **Validator never listens**: All connections are outbound from Validator.
//! 2. **PQ mutual auth**: Every link uses ML-KEM-768 + ML-DSA-65 handshake.
//! 3. **Persistent reconnect**: If a Sentry drops, Validator retries with backoff.
//! 4. **Health monitoring**: `ValidatorOperationalState` drives block production decisions.
//! 5. **IP scrubbing**: Validator never reveals its IP in peer records, Hello messages, or errors.
//! 6. **Relay priority**: Consensus-critical traffic (blocks, votes) is forwarded first.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::peer_id::PeerId;
use crate::validator_network::{
    check_validator_state, ValidatorNetworkConfig, ValidatorOperationalState,
};

// ═══════════════════════════════════════════════════════════════
//  Configuration
// ═══════════════════════════════════════════════════════════════

/// Configuration for a single Sentry endpoint.
#[derive(Debug, Clone)]
pub struct SentryEndpoint {
    /// PeerId of the sentry (derived from its PQ public key).
    pub peer_id: PeerId,
    /// TCP address to dial (e.g., "203.0.113.10:6690").
    pub address: SocketAddr,
    /// Human-readable label for logging.
    pub label: String,
    /// Priority: lower = higher priority for relay selection.
    pub priority: u8,
}

/// Sentry Bridge configuration.
#[derive(Debug, Clone)]
pub struct SentryBridgeConfig {
    /// List of sentry endpoints to maintain connections with.
    pub sentries: Vec<SentryEndpoint>,
    /// Minimum number of live sentries before entering degraded mode.
    pub min_live_sentries: usize,
    /// Base reconnect delay (exponential backoff).
    pub reconnect_base_delay: Duration,
    /// Maximum reconnect delay.
    pub reconnect_max_delay: Duration,
    /// How often to check sentry health.
    pub health_check_interval: Duration,
    /// How long to wait for a sentry to respond before considering it dead.
    pub liveness_timeout: Duration,
}

impl Default for SentryBridgeConfig {
    fn default() -> Self {
        Self {
            sentries: Vec::new(),
            min_live_sentries: 1,
            reconnect_base_delay: Duration::from_secs(2),
            reconnect_max_delay: Duration::from_secs(120),
            health_check_interval: Duration::from_secs(15),
            liveness_timeout: Duration::from_secs(10),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Sentry Connection State
// ═══════════════════════════════════════════════════════════════

/// Per-sentry connection tracking.
#[derive(Debug, Clone)]
pub struct SentryConnectionState {
    /// Sentry endpoint configuration.
    pub endpoint: SentryEndpoint,
    /// Current connection status.
    pub status: SentryStatus,
    /// Number of consecutive failed connection attempts.
    pub consecutive_failures: u32,
    /// When the last successful connection was established.
    pub last_connected: Option<Instant>,
    /// When the last connection attempt was made.
    pub last_attempt: Option<Instant>,
    /// When the last message was received from this sentry.
    pub last_activity: Option<Instant>,
    /// Total messages relayed through this sentry.
    pub relayed_messages: u64,
    /// Total bytes relayed through this sentry.
    pub relayed_bytes: u64,
}

/// Connection status for a sentry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SentryStatus {
    /// Not connected, will attempt to connect.
    Disconnected,
    /// Connection attempt in progress.
    Connecting,
    /// Connected and healthy.
    Connected,
    /// Connected but no recent activity (stale).
    Stale,
    /// Temporarily backed off due to repeated failures.
    ///
    /// SEC-M3 fix: stores absolute `Instant` when backoff expires (not relative ms).
    Backoff {
        /// The `Instant` after which a reconnection attempt is permitted.
        expires_at: Instant,
    },
}

impl SentryConnectionState {
    pub fn new(endpoint: SentryEndpoint) -> Self {
        Self {
            endpoint,
            status: SentryStatus::Disconnected,
            consecutive_failures: 0,
            last_connected: None,
            last_attempt: None,
            last_activity: None,
            relayed_messages: 0,
            relayed_bytes: 0,
        }
    }

    /// Compute the next backoff delay (exponential, capped).
    pub fn backoff_delay(&self, base: Duration, max: Duration) -> Duration {
        let exp = 2u64.saturating_pow(self.consecutive_failures.min(10));
        let delay = base.saturating_mul(exp as u32);
        delay.min(max)
    }

    /// Whether this sentry should be dialed now.
    pub fn should_dial(&self, now: Instant) -> bool {
        match self.status {
            SentryStatus::Disconnected => true,
            SentryStatus::Backoff { expires_at } => now >= expires_at,
            _ => false,
        }
    }

    /// Mark connection as established.
    pub fn on_connected(&mut self) {
        self.status = SentryStatus::Connected;
        self.consecutive_failures = 0;
        self.last_connected = Some(Instant::now());
        self.last_activity = Some(Instant::now());
    }

    /// Mark connection as failed.
    pub fn on_failed(&mut self, base: Duration, max: Duration) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let delay = self.backoff_delay(base, max);
        self.status = SentryStatus::Backoff {
            expires_at: Instant::now() + delay,
        };
        self.last_attempt = Some(Instant::now());
    }

    /// Mark connection as disconnected (was connected, now lost).
    pub fn on_disconnected(&mut self) {
        self.status = SentryStatus::Disconnected;
    }

    /// Record activity (message received).
    pub fn on_activity(&mut self, bytes: u64) {
        self.last_activity = Some(Instant::now());
        self.relayed_messages += 1;
        self.relayed_bytes += bytes;
    }

    /// Check if connection is stale (no recent activity).
    pub fn check_liveness(&mut self, timeout: Duration) {
        if self.status == SentryStatus::Connected {
            if let Some(last) = self.last_activity {
                if last.elapsed() > timeout {
                    self.status = SentryStatus::Stale;
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Sentry Bridge (runtime)
// ═══════════════════════════════════════════════════════════════

/// The Sentry Bridge manages all Validator↔Sentry connections.
///
/// This is the **single point of contact** between the hidden Validator
/// and the outside network. All inbound/outbound traffic flows through
/// the bridge's connected sentries.
pub struct SentryBridge {
    config: SentryBridgeConfig,
    /// Per-sentry connection state.
    sentries: HashMap<PeerId, SentryConnectionState>,
    /// Current operational state (Normal/Degraded/Isolated).
    operational_state: ValidatorOperationalState,
    /// Channel for sending outbound messages through sentries.
    #[allow(dead_code)]
    outbound_tx: mpsc::Sender<SentryOutbound>,
    /// Channel for receiving inbound messages from sentries.
    #[allow(dead_code)]
    inbound_tx: mpsc::Sender<SentryInbound>,
}

/// Message to send through a sentry.
#[derive(Debug)]
pub struct SentryOutbound {
    /// Target sentry PeerId (None = broadcast to all).
    pub target: Option<PeerId>,
    /// Message type for priority ordering.
    pub priority: MessagePriority,
    /// Serialized message payload.
    pub payload: Vec<u8>,
}

/// Message received from a sentry.
#[derive(Debug)]
pub struct SentryInbound {
    /// Which sentry forwarded this message.
    pub source_sentry: PeerId,
    /// Original sender PeerId (if known).
    pub original_peer: Option<PeerId>,
    /// Message payload.
    pub payload: Vec<u8>,
}

/// Message priority for relay ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessagePriority {
    /// Block proposals, finality votes — relay immediately.
    ConsensusHigh = 0,
    /// Block bodies, headers — relay with normal priority.
    ConsensusMedium = 1,
    /// Transaction broadcasts — relay with low priority.
    Gossip = 2,
    /// Peer discovery, sync status — relay last.
    Housekeeping = 3,
}

impl SentryBridge {
    /// Create a new bridge with the given configuration.
    pub fn new(
        config: SentryBridgeConfig,
    ) -> (Self, mpsc::Sender<SentryOutbound>, mpsc::Receiver<SentryInbound>) {
        let (outbound_tx, _outbound_rx) = mpsc::channel(256);
        let (inbound_tx, inbound_rx) = mpsc::channel(1024);

        let mut sentries = HashMap::new();
        for ep in &config.sentries {
            sentries.insert(ep.peer_id, SentryConnectionState::new(ep.clone()));
        }

        let operational_state = check_validator_state(
            0, // no sentries connected yet
            &ValidatorNetworkConfig {
                min_live_sentries: config.min_live_sentries,
                ..Default::default()
            },
        );

        let bridge = Self {
            config,
            sentries,
            operational_state,
            outbound_tx: outbound_tx.clone(),
            inbound_tx,
        };

        (bridge, outbound_tx, inbound_rx)
    }

    /// Get the current operational state.
    pub fn operational_state(&self) -> ValidatorOperationalState {
        self.operational_state
    }

    /// Count of currently connected sentries.
    pub fn live_sentry_count(&self) -> usize {
        self.sentries
            .values()
            .filter(|s| matches!(s.status, SentryStatus::Connected))
            .count()
    }

    /// Get a snapshot of all sentry states (for monitoring).
    pub fn sentry_states(&self) -> Vec<SentryStatusSnapshot> {
        self.sentries
            .values()
            .map(|s| SentryStatusSnapshot {
                peer_id: s.endpoint.peer_id,
                label: s.endpoint.label.clone(),
                address: s.endpoint.address,
                status: s.status,
                consecutive_failures: s.consecutive_failures,
                relayed_messages: s.relayed_messages,
                relayed_bytes: s.relayed_bytes,
            })
            .collect()
    }

    /// Update operational state based on current sentry connections.
    pub fn update_operational_state(&mut self) {
        let live = self.live_sentry_count();
        let val_config = ValidatorNetworkConfig {
            min_live_sentries: self.config.min_live_sentries,
            ..Default::default()
        };
        let new_state = check_validator_state(live, &val_config);

        if new_state != self.operational_state {
            match new_state {
                ValidatorOperationalState::Normal => {
                    info!(
                        "Validator operational: NORMAL ({} sentries)",
                        live
                    );
                }
                ValidatorOperationalState::Degraded {
                    live_sentries,
                    required,
                } => {
                    warn!(
                        "⚠ Validator DEGRADED: {}/{} sentries live",
                        live_sentries, required
                    );
                }
                ValidatorOperationalState::Isolated => {
                    error!("🚨 Validator ISOLATED: NO sentry connections. Block production HALTED.");
                }
            }
            self.operational_state = new_state;
        }
    }

    /// Check liveness of all sentries and update states.
    pub fn health_check(&mut self) {
        for state in self.sentries.values_mut() {
            state.check_liveness(self.config.liveness_timeout);
        }
        self.update_operational_state();
    }

    /// Record a sentry connection event.
    pub fn on_sentry_connected(&mut self, peer_id: &PeerId) {
        if let Some(state) = self.sentries.get_mut(peer_id) {
            state.on_connected();
            info!(
                "Sentry connected: {} ({})",
                state.endpoint.label,
                state.endpoint.address
            );
        }
        self.update_operational_state();
    }

    /// Record a sentry disconnection.
    pub fn on_sentry_disconnected(&mut self, peer_id: &PeerId) {
        if let Some(state) = self.sentries.get_mut(peer_id) {
            state.on_disconnected();
            warn!(
                "Sentry disconnected: {} ({})",
                state.endpoint.label,
                state.endpoint.address
            );
        }
        self.update_operational_state();
    }

    /// Record a failed connection attempt.
    pub fn on_sentry_failed(&mut self, peer_id: &PeerId) {
        if let Some(state) = self.sentries.get_mut(peer_id) {
            state.on_failed(
                self.config.reconnect_base_delay,
                self.config.reconnect_max_delay,
            );
            warn!(
                "Sentry connection failed: {} (attempt #{}, next retry in {:?})",
                state.endpoint.label,
                state.consecutive_failures,
                state.backoff_delay(
                    self.config.reconnect_base_delay,
                    self.config.reconnect_max_delay,
                )
            );
        }
        self.update_operational_state();
    }

    /// Record inbound message from a sentry.
    pub fn on_sentry_message(&mut self, peer_id: &PeerId, bytes: u64) {
        if let Some(state) = self.sentries.get_mut(peer_id) {
            state.on_activity(bytes);
        }
    }

    /// Select the best sentry to send a message through.
    ///
    /// Prefers: Connected > lowest priority number > most recent activity.
    pub fn select_relay_sentry(&self) -> Option<PeerId> {
        self.sentries
            .values()
            .filter(|s| matches!(s.status, SentryStatus::Connected))
            .min_by_key(|s| (s.endpoint.priority, std::cmp::Reverse(s.relayed_messages)))
            .map(|s| s.endpoint.peer_id)
    }

    /// Get sentries that need dial-out attempts.
    pub fn sentries_needing_dial(&self) -> Vec<SentryEndpoint> {
        let now = Instant::now();
        self.sentries
            .values()
            .filter(|s| s.should_dial(now))
            .map(|s| s.endpoint.clone())
            .collect()
    }

    /// Whether the validator should produce blocks in the current state.
    pub fn should_produce_blocks(&self) -> bool {
        !matches!(self.operational_state, ValidatorOperationalState::Isolated)
    }
}

/// Snapshot of a sentry's state for monitoring/RPC.
#[derive(Debug, Clone)]
pub struct SentryStatusSnapshot {
    pub peer_id: PeerId,
    pub label: String,
    pub address: SocketAddr,
    pub status: SentryStatus,
    pub consecutive_failures: u32,
    pub relayed_messages: u64,
    pub relayed_bytes: u64,
}

// ═══════════════════════════════════════════════════════════════
//  IP Scrubbing
// ═══════════════════════════════════════════════════════════════

/// Scrub all potentially identifying information from a P2P Hello message
/// when sent FROM a validator node.
///
/// Ensures the validator's IP, listen address, and node name are never
/// leaked to any peer (including sentries — defense in depth).
pub fn scrub_hello_for_validator(
    hello: &mut serde_json::Value,
    validator_alias: &str,
) {
    // Remove listen address
    hello["listen_addr"] = serde_json::Value::Null;
    // Use a generic name instead of hostname
    hello["node_name"] = serde_json::json!(validator_alias);
    // Force hidden mode
    hello["mode"] = serde_json::json!("hidden");
}

/// Scrub a peer record to remove validator-identifying information.
///
/// Called before a sentry forwards peer records to the public mesh.
pub fn scrub_peer_record_for_relay(
    record: &mut serde_json::Value,
    validator_peer_ids: &[PeerId],
) {
    // If the record's peer_id matches a known validator, remove the record entirely
    if let Some(pid_hex) = record["peer_id"].as_str() {
        let mut pid_bytes = [0u8; 32];
        if let Ok(bytes) = hex::decode(pid_hex) {
            if bytes.len() == 32 {
                pid_bytes.copy_from_slice(&bytes);
                let pid = PeerId(pid_bytes);
                if validator_peer_ids.contains(&pid) {
                    // Zero out the record — sentry should NOT relay it
                    *record = serde_json::json!(null);
                    return;
                }
            }
        }
    }

    // For non-validator records, scrub any private/reserved addresses
    if let Some(addrs) = record["addresses"].as_array_mut() {
        addrs.retain(|a| {
            let addr_str = a.as_str().unwrap_or("");
            !is_private_or_reserved(addr_str)
        });
    }
}

/// SEC-M4: Check if an address string points to a private/reserved IP.
///
/// Covers RFC 1918 (10/8, 172.16/12, 192.168/16), loopback (127/8),
/// link-local (169.254/16, fe80::/10), and IPv6 loopback (::1).
/// Falls back to string prefix matching if parsing fails.
fn is_private_or_reserved(addr_str: &str) -> bool {
    // Try to parse as SocketAddr first, then as raw IP
    let ip = addr_str
        .parse::<std::net::SocketAddr>()
        .map(|sa| sa.ip())
        .or_else(|_| addr_str.parse::<std::net::IpAddr>())
        .ok();

    match ip {
        Some(std::net::IpAddr::V4(v4)) => {
            let o = v4.octets();
            // 127.0.0.0/8
            o[0] == 127
            // 10.0.0.0/8
            || o[0] == 10
            // 192.168.0.0/16
            || (o[0] == 192 && o[1] == 168)
            // 172.16.0.0/12 (172.16.0.0 – 172.31.255.255)
            || (o[0] == 172 && (16..=31).contains(&o[1]))
            // 169.254.0.0/16 (link-local)
            || (o[0] == 169 && o[1] == 254)
            // 0.0.0.0
            || v4.is_unspecified()
        }
        Some(std::net::IpAddr::V6(v6)) => {
            v6.is_loopback()
                // fe80::/10 (link-local)
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                || v6.is_unspecified()
                // ::ffff:127.x.x.x (IPv4-mapped loopback)
                || v6.to_ipv4_mapped().map_or(false, |v4| v4.octets()[0] == 127)
        }
        None => {
            // Fallback: string-based (shouldn't happen for valid addresses)
            addr_str.starts_with("127.")
                || addr_str.starts_with("10.")
                || addr_str.starts_with("192.168.")
                || addr_str.starts_with("[::1]")
                || addr_str.starts_with("[fe80:")
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sentry_ep(id: u8, addr: &str) -> SentryEndpoint {
        SentryEndpoint {
            peer_id: PeerId([id; 32]),
            address: addr.parse().expect("test: valid addr"),
            label: format!("sentry-{}", id),
            priority: id,
        }
    }

    #[test]
    fn test_bridge_starts_isolated() {
        let config = SentryBridgeConfig {
            sentries: vec![sentry_ep(1, "1.2.3.4:6690"), sentry_ep(2, "5.6.7.8:6690")],
            min_live_sentries: 1,
            ..Default::default()
        };
        let (bridge, _, _) = SentryBridge::new(config);
        assert_eq!(bridge.live_sentry_count(), 0);
        assert!(matches!(
            bridge.operational_state(),
            ValidatorOperationalState::Isolated
        ));
        assert!(!bridge.should_produce_blocks());
    }

    #[test]
    fn test_bridge_becomes_normal_on_connect() {
        let config = SentryBridgeConfig {
            sentries: vec![sentry_ep(1, "1.2.3.4:6690")],
            min_live_sentries: 1,
            ..Default::default()
        };
        let (mut bridge, _, _) = SentryBridge::new(config);

        bridge.on_sentry_connected(&PeerId([1; 32]));
        assert_eq!(bridge.live_sentry_count(), 1);
        assert!(matches!(
            bridge.operational_state(),
            ValidatorOperationalState::Normal
        ));
        assert!(bridge.should_produce_blocks());
    }

    #[test]
    fn test_bridge_degraded_then_isolated() {
        let config = SentryBridgeConfig {
            sentries: vec![
                sentry_ep(1, "1.2.3.4:6690"),
                sentry_ep(2, "5.6.7.8:6690"),
            ],
            min_live_sentries: 2,
            ..Default::default()
        };
        let (mut bridge, _, _) = SentryBridge::new(config);

        bridge.on_sentry_connected(&PeerId([1; 32]));
        bridge.on_sentry_connected(&PeerId([2; 32]));
        assert!(matches!(
            bridge.operational_state(),
            ValidatorOperationalState::Normal
        ));

        // Lose one sentry → degraded
        bridge.on_sentry_disconnected(&PeerId([1; 32]));
        assert!(matches!(
            bridge.operational_state(),
            ValidatorOperationalState::Degraded { .. }
        ));
        assert!(bridge.should_produce_blocks()); // still producing

        // Lose all → isolated
        bridge.on_sentry_disconnected(&PeerId([2; 32]));
        assert!(matches!(
            bridge.operational_state(),
            ValidatorOperationalState::Isolated
        ));
        assert!(!bridge.should_produce_blocks()); // HALTED
    }

    #[test]
    fn test_backoff_exponential() {
        let mut state = SentryConnectionState::new(sentry_ep(1, "1.2.3.4:6690"));
        let base = Duration::from_secs(2);
        let max = Duration::from_secs(120);

        // Failure 1: 2s
        state.on_failed(base, max);
        assert_eq!(state.consecutive_failures, 1);

        // Failure 2: 4s
        state.on_failed(base, max);
        assert_eq!(state.consecutive_failures, 2);
        let delay = state.backoff_delay(base, max);
        assert!(delay >= Duration::from_secs(4));
        assert!(delay <= max);

        // Many failures: capped at max
        for _ in 0..20 {
            state.on_failed(base, max);
        }
        let delay = state.backoff_delay(base, max);
        assert_eq!(delay, max);
    }

    #[test]
    fn test_select_relay_sentry_prefers_priority() {
        let config = SentryBridgeConfig {
            sentries: vec![
                sentry_ep(2, "5.6.7.8:6690"),  // priority 2
                sentry_ep(1, "1.2.3.4:6690"),  // priority 1 (preferred)
            ],
            min_live_sentries: 1,
            ..Default::default()
        };
        let (mut bridge, _, _) = SentryBridge::new(config);

        bridge.on_sentry_connected(&PeerId([1; 32]));
        bridge.on_sentry_connected(&PeerId([2; 32]));

        let selected = bridge.select_relay_sentry();
        assert_eq!(selected, Some(PeerId([1; 32]))); // priority 1 wins
    }

    #[test]
    fn test_scrub_hello_removes_ip() {
        let mut hello = serde_json::json!({
            "chain_id": 2,
            "height": 100,
            "node_name": "my-secret-validator-hostname",
            "mode": "public",
            "listen_addr": "192.168.1.100:6690"
        });

        scrub_hello_for_validator(&mut hello, "validator-anon");

        assert_eq!(hello["listen_addr"], serde_json::Value::Null);
        assert_eq!(hello["node_name"], "validator-anon");
        assert_eq!(hello["mode"], "hidden");
    }

    #[test]
    fn test_scrub_peer_record_removes_validator() {
        let validator_pids = vec![PeerId([0xAA; 32])];

        // Record for a known validator → should be nulled
        let mut record = serde_json::json!({
            "peer_id": hex::encode([0xAA; 32]),
            "addresses": ["203.0.113.10:6690"],
        });
        scrub_peer_record_for_relay(&mut record, &validator_pids);
        assert!(record.is_null());

        // Record for a non-validator → kept, but private addrs removed
        let mut record2 = serde_json::json!({
            "peer_id": hex::encode([0xBB; 32]),
            "addresses": ["203.0.113.10:6690", "192.168.1.100:6690", "10.0.0.5:6690"],
        });
        scrub_peer_record_for_relay(&mut record2, &validator_pids);
        assert!(!record2.is_null());
        let addrs = record2["addresses"].as_array().expect("array");
        assert_eq!(addrs.len(), 1); // only public addr remains
        assert_eq!(addrs[0], "203.0.113.10:6690");
    }

    #[test]
    fn test_sentries_needing_dial() {
        let config = SentryBridgeConfig {
            sentries: vec![
                sentry_ep(1, "1.2.3.4:6690"),
                sentry_ep(2, "5.6.7.8:6690"),
            ],
            min_live_sentries: 1,
            ..Default::default()
        };
        let (mut bridge, _, _) = SentryBridge::new(config);

        // Both should need dialing initially
        let needs = bridge.sentries_needing_dial();
        assert_eq!(needs.len(), 2);

        // Connect one — only the other needs dialing
        bridge.on_sentry_connected(&PeerId([1; 32]));
        let needs = bridge.sentries_needing_dial();
        assert_eq!(needs.len(), 1);
        assert_eq!(needs[0].peer_id, PeerId([2; 32]));
    }

    #[test]
    fn test_sentry_states_snapshot() {
        let config = SentryBridgeConfig {
            sentries: vec![sentry_ep(1, "1.2.3.4:6690")],
            min_live_sentries: 1,
            ..Default::default()
        };
        let (mut bridge, _, _) = SentryBridge::new(config);

        bridge.on_sentry_connected(&PeerId([1; 32]));
        bridge.on_sentry_message(&PeerId([1; 32]), 1024);

        let states = bridge.sentry_states();
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].relayed_messages, 1);
        assert_eq!(states[0].relayed_bytes, 1024);
    }
}
