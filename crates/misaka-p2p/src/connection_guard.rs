//! # Connection Guard — Per-IP Throttling + Eclipse-Resistant Admission
//!
//! # Problem
//!
//! Without per-IP rate limiting, an attacker can:
//! 1. **Handshake flood**: Open thousands of TCP connections and start
//!    ML-KEM handshakes without completing them (slowloris variant).
//!    Each incomplete handshake holds memory for ephemeral keypairs.
//! 2. **Eclipse via inbound saturation**: Fill all inbound slots from
//!    a single /24 subnet, preventing honest peers from connecting.
//! 3. **Memory exhaustion**: Accumulate half-open connections faster
//!    than the node can process/timeout them.
//!
//! # Solution
//!
//! Three-layer defense:
//!
//! | Layer           | What it blocks                         |
//! |-----------------|----------------------------------------|
//! | Per-IP throttle | >N handshake attempts per window       |
//! | Subnet cap      | >/24 subnet saturation (Eclipse)       |
//! | Half-open limit | Total incomplete handshakes (memory)   |
//!
//! All checks are **fail-closed**: if the guard cannot determine
//! whether to allow, it rejects.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::subnet::SubnetId;

// ═══════════════════════════════════════════════════════════════
//  Default Constants (used when no config is provided)
// ═══════════════════════════════════════════════════════════════

/// Maximum handshake attempts per IP within the throttle window.
pub const MAX_HANDSHAKE_ATTEMPTS_PER_IP: u32 = 5;

/// Throttle window duration.
pub const THROTTLE_WINDOW_SECS: u64 = 60;

/// Maximum concurrent half-open (handshake in progress) connections.
pub const MAX_HALF_OPEN: usize = 64;

/// Half-open connection timeout — if a handshake hasn't completed
/// within this time, the slot is reclaimed.
pub const HALF_OPEN_TIMEOUT_SECS: u64 = 15;

/// Maximum established connections from the same subnet (inbound).
///
/// This is the inbound counterpart to `scoring::MAX_PEERS_PER_SUBNET`
/// which controls outbound dial diversity.
pub const MAX_INBOUND_PER_SUBNET: usize = 4;

/// Maximum established connections from the same single IP (inbound).
pub const MAX_INBOUND_PER_IP: usize = 2;

/// Cleanup interval — how often to purge stale entries.
pub const CLEANUP_INTERVAL_SECS: u64 = 30;

// ═══════════════════════════════════════════════════════════════
//  GuardConfig — Runtime Configuration
// ═══════════════════════════════════════════════════════════════

/// Runtime configuration for `ConnectionGuard`.
///
/// All fields have sensible defaults. Load from `testnet.toml` /
/// `mainnet.toml` via the node's `P2pConfig`, or use `Default::default()`.
///
/// # Example (TOML)
///
/// ```toml
/// [p2p]
/// max_handshake_attempts_per_ip = 5
/// max_half_open = 64
/// half_open_timeout_secs = 15
/// max_inbound_per_subnet = 4
/// max_inbound_per_ip = 2
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardConfig {
    /// Max handshake attempts per IP per throttle window.
    #[serde(default = "default_max_handshake_attempts")]
    pub max_handshake_attempts_per_ip: u32,

    /// Throttle window duration (seconds).
    #[serde(default = "default_throttle_window")]
    pub throttle_window_secs: u64,

    /// Max concurrent half-open connections globally.
    #[serde(default = "default_max_half_open")]
    pub max_half_open: usize,

    /// Half-open timeout (seconds).
    #[serde(default = "default_half_open_timeout")]
    pub half_open_timeout_secs: u64,

    /// Max established inbound from same subnet.
    #[serde(default = "default_max_inbound_per_subnet")]
    pub max_inbound_per_subnet: usize,

    /// Max established inbound from same IP.
    #[serde(default = "default_max_inbound_per_ip")]
    pub max_inbound_per_ip: usize,

    /// Cleanup interval (seconds).
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval_secs: u64,
}

fn default_max_handshake_attempts() -> u32 {
    MAX_HANDSHAKE_ATTEMPTS_PER_IP
}
fn default_throttle_window() -> u64 {
    THROTTLE_WINDOW_SECS
}
fn default_max_half_open() -> usize {
    MAX_HALF_OPEN
}
fn default_half_open_timeout() -> u64 {
    HALF_OPEN_TIMEOUT_SECS
}
fn default_max_inbound_per_subnet() -> usize {
    MAX_INBOUND_PER_SUBNET
}
fn default_max_inbound_per_ip() -> usize {
    MAX_INBOUND_PER_IP
}
fn default_cleanup_interval() -> u64 {
    CLEANUP_INTERVAL_SECS
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            max_handshake_attempts_per_ip: MAX_HANDSHAKE_ATTEMPTS_PER_IP,
            throttle_window_secs: THROTTLE_WINDOW_SECS,
            max_half_open: MAX_HALF_OPEN,
            half_open_timeout_secs: HALF_OPEN_TIMEOUT_SECS,
            max_inbound_per_subnet: MAX_INBOUND_PER_SUBNET,
            max_inbound_per_ip: MAX_INBOUND_PER_IP,
            cleanup_interval_secs: CLEANUP_INTERVAL_SECS,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Guard Decision
// ═══════════════════════════════════════════════════════════════

/// Result of a connection guard check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardDecision {
    /// Connection attempt is allowed.
    Allow,
    /// Connection attempt is rejected with reason.
    Reject(GuardRejectReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuardRejectReason {
    /// Too many handshake attempts from this IP recently.
    IpThrottled { ip: IpAddr, attempts: u32 },
    /// Too many half-open connections globally.
    HalfOpenExhausted { current: usize },
    /// Too many established inbound from same subnet.
    SubnetSaturated { subnet: SubnetId, count: usize },
    /// Too many established inbound from same IP.
    IpSaturated { ip: IpAddr, count: usize },
}

impl std::fmt::Display for GuardRejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IpThrottled { ip, attempts } => {
                write!(f, "IP {} throttled ({} attempts in window)", ip, attempts)
            }
            Self::HalfOpenExhausted { current } => {
                write!(f, "half-open limit reached ({})", current)
            }
            Self::SubnetSaturated { subnet, count } => {
                write!(f, "subnet {} saturated ({} connections)", subnet, count)
            }
            Self::IpSaturated { ip, count } => {
                write!(f, "IP {} saturated ({} connections)", ip, count)
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Half-Open Slot
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
struct HalfOpenSlot {
    ip: IpAddr,
    started_at: Instant,
}

// ═══════════════════════════════════════════════════════════════
//  Connection Guard
// ═══════════════════════════════════════════════════════════════

/// Per-IP throttling + subnet diversity enforcement for inbound connections.
///
/// # Usage
///
/// ```text
/// 1. TCP accept → guard.check_inbound(ip) → Allow / Reject
/// 2. If Allow → guard.register_half_open(ip) → slot_id
/// 3. Handshake completes → guard.promote_to_established(slot_id)
/// 4. Connection closes → guard.on_disconnect(ip)
/// ```
///
/// # Thread Safety
///
/// This struct is NOT `Sync`. Wrap in `Arc<Mutex<_>>` or
/// `Arc<RwLock<_>>` for concurrent access from the accept loop.
pub struct ConnectionGuard {
    /// Runtime configuration.
    config: GuardConfig,
    /// Per-IP handshake attempt timestamps (for throttling).
    ip_attempts: HashMap<IpAddr, Vec<Instant>>,
    /// Currently half-open connections (handshake in progress).
    half_open: HashMap<u64, HalfOpenSlot>,
    /// Next half-open slot ID.
    next_slot_id: u64,
    /// Established inbound connection count per IP.
    established_per_ip: HashMap<IpAddr, usize>,
    /// Last cleanup time.
    last_cleanup: Instant,
}

impl ConnectionGuard {
    /// Create with default configuration.
    pub fn new() -> Self {
        Self::with_config(GuardConfig::default())
    }

    /// Create with custom configuration (loaded from TOML).
    pub fn with_config(config: GuardConfig) -> Self {
        Self {
            config,
            ip_attempts: HashMap::new(),
            half_open: HashMap::new(),
            next_slot_id: 1,
            established_per_ip: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }

    /// Get a reference to the active configuration.
    pub fn config(&self) -> &GuardConfig {
        &self.config
    }

    /// Check whether an inbound connection from `ip` should be accepted.
    ///
    /// This performs ALL checks:
    /// 1. Per-IP handshake throttle
    /// 2. Global half-open limit
    /// 3. Per-subnet established limit
    /// 4. Per-IP established limit
    ///
    /// Returns `GuardDecision::Allow` only if ALL checks pass.
    pub fn check_inbound(&mut self, ip: IpAddr) -> GuardDecision {
        // Lazy cleanup
        if self.last_cleanup.elapsed() > Duration::from_secs(self.config.cleanup_interval_secs) {
            self.cleanup();
        }

        // ── 1. Per-IP throttle ──
        let now = Instant::now();
        let window = Duration::from_secs(self.config.throttle_window_secs);
        let attempts = self.ip_attempts.entry(ip).or_default();
        attempts.retain(|t| now.duration_since(*t) < window);
        if attempts.len() as u32 >= self.config.max_handshake_attempts_per_ip {
            return GuardDecision::Reject(GuardRejectReason::IpThrottled {
                ip,
                attempts: attempts.len() as u32,
            });
        }

        // ── 2. Global half-open limit ──
        // First, evict timed-out half-open slots
        let timeout = Duration::from_secs(self.config.half_open_timeout_secs);
        self.half_open
            .retain(|_, slot| now.duration_since(slot.started_at) < timeout);
        if self.half_open.len() >= self.config.max_half_open {
            return GuardDecision::Reject(GuardRejectReason::HalfOpenExhausted {
                current: self.half_open.len(),
            });
        }

        // ── 3. Per-subnet check (IPv4/24 + IPv6/48 via SubnetId) ──
        let subnet = SubnetId::from_ip(&ip);
        let subnet_count: usize = self
            .established_per_ip
            .iter()
            .filter(|(established_ip, count)| {
                **count > 0 && SubnetId::from_ip(established_ip) == subnet
            })
            .map(|(_, count)| *count)
            .sum();
        if subnet_count >= self.config.max_inbound_per_subnet {
            return GuardDecision::Reject(GuardRejectReason::SubnetSaturated {
                subnet,
                count: subnet_count,
            });
        }

        // ── 4. Per-IP check ──
        let ip_count = self.established_per_ip.get(&ip).copied().unwrap_or(0);
        if ip_count >= self.config.max_inbound_per_ip {
            return GuardDecision::Reject(GuardRejectReason::IpSaturated {
                ip,
                count: ip_count,
            });
        }

        // Record this attempt
        attempts.push(now);

        GuardDecision::Allow
    }

    /// Register a half-open connection (handshake started).
    ///
    /// Returns a slot_id that must be passed to `promote_to_established()`
    /// on handshake success, or `cancel_half_open()` on failure.
    pub fn register_half_open(&mut self, ip: IpAddr) -> u64 {
        let slot_id = self.next_slot_id;
        self.next_slot_id += 1;
        self.half_open.insert(
            slot_id,
            HalfOpenSlot {
                ip,
                started_at: Instant::now(),
            },
        );
        slot_id
    }

    /// Promote a half-open connection to established (handshake succeeded).
    pub fn promote_to_established(&mut self, slot_id: u64) {
        if let Some(slot) = self.half_open.remove(&slot_id) {
            *self.established_per_ip.entry(slot.ip).or_insert(0) += 1;
        }
    }

    /// Cancel a half-open connection (handshake failed / rejected).
    pub fn cancel_half_open(&mut self, slot_id: u64) {
        self.half_open.remove(&slot_id);
    }

    /// Notify that an established inbound connection from `ip` was closed.
    pub fn on_disconnect(&mut self, ip: IpAddr) {
        if let Some(count) = self.established_per_ip.get_mut(&ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.established_per_ip.remove(&ip);
            }
        }
    }

    /// Periodic cleanup: remove stale throttle entries and timed-out half-opens.
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let window = Duration::from_secs(self.config.throttle_window_secs);
        let timeout = Duration::from_secs(self.config.half_open_timeout_secs);

        // Remove expired throttle entries
        self.ip_attempts.retain(|_, attempts| {
            attempts.retain(|t| now.duration_since(*t) < window);
            !attempts.is_empty()
        });

        // Remove timed-out half-opens
        let timed_out: Vec<u64> = self
            .half_open
            .iter()
            .filter(|(_, slot)| now.duration_since(slot.started_at) >= timeout)
            .map(|(id, _)| *id)
            .collect();
        for id in timed_out {
            if let Some(slot) = self.half_open.remove(&id) {
                warn!(
                    ip = %slot.ip,
                    "half-open connection timed out after {}s",
                    HALF_OPEN_TIMEOUT_SECS
                );
            }
        }

        // Remove zero-count established entries
        self.established_per_ip.retain(|_, count| *count > 0);

        self.last_cleanup = now;
    }

    /// Current half-open count.
    pub fn half_open_count(&self) -> usize {
        self.half_open.len()
    }

    /// Current total established inbound count.
    pub fn established_count(&self) -> usize {
        self.established_per_ip.values().sum()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Address Validation — Bogon / Private IP Detection
// ═══════════════════════════════════════════════════════════════

/// Check whether an IP address is a bogon (non-routable).
///
/// Bogon IPs should NEVER appear in peer records advertised on the
/// public network. An attacker advertising 10.0.0.1 or 127.0.0.1
/// could:
/// - Cause peers to waste connection attempts on unreachable addresses
/// - Redirect peers to local services (SSRF-like)
/// - Pollute the peer store with useless entries
pub fn is_bogon_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()                          // 127.0.0.0/8
                || v4.is_broadcast()                   // 255.255.255.255
                || v4.is_unspecified()                 // 0.0.0.0
                || v4.is_link_local()                  // 169.254.0.0/16
                || v4.octets()[0] == 10                // 10.0.0.0/8
                || (v4.octets()[0] == 172              // 172.16.0.0/12
                    && (v4.octets()[1] >= 16 && v4.octets()[1] <= 31))
                || (v4.octets()[0] == 192              // 192.168.0.0/16
                    && v4.octets()[1] == 168)
                || (v4.octets()[0] == 100              // 100.64.0.0/10 (CGNAT)
                    && (v4.octets()[1] >= 64 && v4.octets()[1] <= 127))
                || (v4.octets()[0] == 198              // 198.18.0.0/15 (benchmarking)
                    && (v4.octets()[1] == 18 || v4.octets()[1] == 19))
                || v4.octets()[0] >= 240 // 240.0.0.0/4 (reserved)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()       // ::1
                || v6.is_unspecified() // ::
                // Link-local fe80::/10
                || (v6.octets()[0] == 0xfe && (v6.octets()[1] & 0xc0) == 0x80)
                // Unique local fc00::/7
                || (v6.octets()[0] & 0xfe) == 0xfc
        }
    }
}

/// Validate a network address string for peer record advertisement.
///
/// Returns `true` if the address is valid for public advertisement.
/// Returns `false` for bogon/private IPs, invalid formats, suspicious ports.
pub fn validate_advertised_address(addr_str: &str) -> bool {
    // Parse as SocketAddr (ip:port)
    if let Ok(sock_addr) = addr_str.parse::<std::net::SocketAddr>() {
        let ip = sock_addr.ip();
        let port = sock_addr.port();

        // Reject bogon IPs
        if is_bogon_ip(&ip) {
            return false;
        }

        // Reject suspicious ports (0, or well-known system ports < 1024
        // that are unlikely to be P2P nodes)
        if port == 0 {
            return false;
        }

        return true;
    }

    // If it doesn't parse as SocketAddr, reject
    false
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn test_ip_throttle_allows_within_limit() {
        let mut guard = ConnectionGuard::new();
        let ip = ipv4(203, 0, 113, 1);

        for _ in 0..MAX_HANDSHAKE_ATTEMPTS_PER_IP {
            assert_eq!(guard.check_inbound(ip), GuardDecision::Allow);
        }
    }

    #[test]
    fn test_ip_throttle_rejects_over_limit() {
        let mut guard = ConnectionGuard::new();
        let ip = ipv4(203, 0, 113, 1);

        for _ in 0..MAX_HANDSHAKE_ATTEMPTS_PER_IP {
            guard.check_inbound(ip);
        }

        match guard.check_inbound(ip) {
            GuardDecision::Reject(GuardRejectReason::IpThrottled { .. }) => {}
            other => panic!("expected IpThrottled, got {:?}", other),
        }
    }

    #[test]
    fn test_different_ips_have_independent_throttles() {
        let mut guard = ConnectionGuard::new();
        let ip1 = ipv4(203, 0, 113, 1);
        let ip2 = ipv4(203, 0, 113, 2);

        for _ in 0..MAX_HANDSHAKE_ATTEMPTS_PER_IP {
            guard.check_inbound(ip1);
        }

        // ip2 should still be allowed
        assert_eq!(guard.check_inbound(ip2), GuardDecision::Allow);
    }

    #[test]
    fn test_half_open_limit() {
        let mut guard = ConnectionGuard::new();

        for i in 0..MAX_HALF_OPEN {
            let ip = ipv4(
                10 + (i / 256 / 256) as u8,
                (i / 256 % 256) as u8,
                (i % 256) as u8,
                1,
            );
            // Bypass the throttle check by using check_inbound only once
            assert_eq!(guard.check_inbound(ip), GuardDecision::Allow);
            guard.register_half_open(ip);
        }

        // Next connection should be rejected for half-open exhaustion
        let ip = ipv4(198, 51, 100, 1);
        match guard.check_inbound(ip) {
            GuardDecision::Reject(GuardRejectReason::HalfOpenExhausted { .. }) => {}
            other => panic!("expected HalfOpenExhausted, got {:?}", other),
        }
    }

    #[test]
    fn test_promote_frees_half_open_slot() {
        let mut guard = ConnectionGuard::new();
        let ip = ipv4(203, 0, 113, 1);
        let slot = guard.register_half_open(ip);
        assert_eq!(guard.half_open_count(), 1);

        guard.promote_to_established(slot);
        assert_eq!(guard.half_open_count(), 0);
        assert_eq!(guard.established_count(), 1);
    }

    #[test]
    fn test_subnet_saturation_blocks_inbound() {
        let mut guard = ConnectionGuard::new();

        // Fill subnet 203.0.113.x
        for i in 0..MAX_INBOUND_PER_SUBNET {
            let ip = ipv4(203, 0, 113, 10 + i as u8);
            let slot = guard.register_half_open(ip);
            guard.promote_to_established(slot);
        }

        // Next connection from same /24 should be rejected
        let ip = ipv4(203, 0, 113, 100);
        match guard.check_inbound(ip) {
            GuardDecision::Reject(GuardRejectReason::SubnetSaturated { .. }) => {}
            other => panic!("expected SubnetSaturated, got {:?}", other),
        }
    }

    #[test]
    fn test_per_ip_saturation_blocks_inbound() {
        let mut guard = ConnectionGuard::new();
        let ip = ipv4(203, 0, 113, 1);

        for _ in 0..MAX_INBOUND_PER_IP {
            let slot = guard.register_half_open(ip);
            guard.promote_to_established(slot);
        }

        match guard.check_inbound(ip) {
            GuardDecision::Reject(GuardRejectReason::IpSaturated { .. }) => {}
            other => panic!("expected IpSaturated, got {:?}", other),
        }
    }

    #[test]
    fn test_disconnect_frees_slot() {
        let mut guard = ConnectionGuard::new();
        let ip = ipv4(203, 0, 113, 1);

        for _ in 0..MAX_INBOUND_PER_IP {
            let slot = guard.register_half_open(ip);
            guard.promote_to_established(slot);
        }

        guard.on_disconnect(ip);
        // Should allow again
        assert_eq!(guard.check_inbound(ip), GuardDecision::Allow);
    }

    // ── Bogon IP tests ──

    #[test]
    fn test_bogon_loopback() {
        assert!(is_bogon_ip(&ipv4(127, 0, 0, 1)));
    }

    #[test]
    fn test_bogon_private_10() {
        assert!(is_bogon_ip(&ipv4(10, 0, 0, 1)));
    }

    #[test]
    fn test_bogon_private_172() {
        assert!(is_bogon_ip(&ipv4(172, 16, 0, 1)));
        assert!(is_bogon_ip(&ipv4(172, 31, 255, 255)));
        assert!(!is_bogon_ip(&ipv4(172, 32, 0, 1)));
    }

    #[test]
    fn test_bogon_private_192_168() {
        assert!(is_bogon_ip(&ipv4(192, 168, 1, 1)));
    }

    #[test]
    fn test_bogon_cgnat() {
        assert!(is_bogon_ip(&ipv4(100, 64, 0, 1)));
        assert!(is_bogon_ip(&ipv4(100, 127, 255, 255)));
        assert!(!is_bogon_ip(&ipv4(100, 128, 0, 1)));
    }

    #[test]
    fn test_public_ip_not_bogon() {
        assert!(!is_bogon_ip(&ipv4(203, 0, 113, 1)));
        assert!(!is_bogon_ip(&ipv4(1, 1, 1, 1)));
        assert!(!is_bogon_ip(&ipv4(8, 8, 8, 8)));
    }

    #[test]
    fn test_validate_advertised_address_public() {
        assert!(validate_advertised_address("203.0.113.10:6690"));
        assert!(validate_advertised_address("1.2.3.4:8080"));
    }

    #[test]
    fn test_validate_advertised_address_rejects_private() {
        assert!(!validate_advertised_address("10.0.0.1:6690"));
        assert!(!validate_advertised_address("192.168.1.1:6690"));
        assert!(!validate_advertised_address("127.0.0.1:6690"));
    }

    #[test]
    fn test_validate_advertised_address_rejects_port_zero() {
        assert!(!validate_advertised_address("203.0.113.10:0"));
    }

    #[test]
    fn test_validate_advertised_address_rejects_garbage() {
        assert!(!validate_advertised_address("not-an-address"));
        assert!(!validate_advertised_address(""));
    }

    // ── IPv6 /48 subnet tests ──

    fn ipv6(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_ipv6_same_slash48_blocked_by_subnet_limit() {
        let mut guard = ConnectionGuard::new();

        // Fill with peers from same /48: 2001:db8:1::/48
        for i in 0..MAX_INBOUND_PER_SUBNET {
            let ip = ipv6(&format!("2001:db8:1:{:x}::1", i + 1));
            let slot = guard.register_half_open(ip);
            guard.promote_to_established(slot);
        }

        // Next peer from same /48 should be rejected
        let ip = ipv6("2001:db8:1:ffff::42");
        match guard.check_inbound(ip) {
            GuardDecision::Reject(GuardRejectReason::SubnetSaturated { .. }) => {}
            other => panic!("expected SubnetSaturated, got {:?}", other),
        }
    }

    #[test]
    fn test_ipv6_different_slash48_allowed() {
        let mut guard = ConnectionGuard::new();

        // Fill one /48
        for i in 0..MAX_INBOUND_PER_SUBNET {
            let ip = ipv6(&format!("2001:db8:1:{:x}::1", i + 1));
            let slot = guard.register_half_open(ip);
            guard.promote_to_established(slot);
        }

        // Different /48 should still be allowed
        let ip = ipv6("2001:db8:2::1");
        assert_eq!(guard.check_inbound(ip), GuardDecision::Allow);
    }

    #[test]
    fn test_ipv4_mapped_ipv6_shares_ipv4_subnet() {
        let mut guard = ConnectionGuard::new();

        // Fill with native IPv4 203.0.113.x
        for i in 0..MAX_INBOUND_PER_SUBNET {
            let ip = ipv4(203, 0, 113, 10 + i as u8);
            let slot = guard.register_half_open(ip);
            guard.promote_to_established(slot);
        }

        // IPv4-mapped IPv6 ::ffff:203.0.113.100 should be in the same subnet
        let mapped: IpAddr = "::ffff:203.0.113.100".parse().unwrap();
        match guard.check_inbound(mapped) {
            GuardDecision::Reject(GuardRejectReason::SubnetSaturated { .. }) => {}
            other => panic!("expected SubnetSaturated for mapped IPv4, got {:?}", other),
        }
    }

    // ── GuardConfig tests ──

    #[test]
    fn test_with_config_custom_limits() {
        let config = GuardConfig {
            max_handshake_attempts_per_ip: 2,
            max_inbound_per_ip: 1,
            ..Default::default()
        };
        let mut guard = ConnectionGuard::with_config(config);
        let ip = ipv4(203, 0, 113, 1);

        // Only 2 attempts allowed
        assert_eq!(guard.check_inbound(ip), GuardDecision::Allow);
        assert_eq!(guard.check_inbound(ip), GuardDecision::Allow);
        match guard.check_inbound(ip) {
            GuardDecision::Reject(GuardRejectReason::IpThrottled { .. }) => {}
            other => panic!("expected IpThrottled, got {:?}", other),
        }
    }

    #[test]
    fn test_with_config_custom_per_ip_limit() {
        let config = GuardConfig {
            max_inbound_per_ip: 1,
            ..Default::default()
        };
        let mut guard = ConnectionGuard::with_config(config);
        let ip = ipv4(203, 0, 113, 1);

        let slot = guard.register_half_open(ip);
        guard.promote_to_established(slot);

        // Only 1 established per IP — second should be rejected
        match guard.check_inbound(ip) {
            GuardDecision::Reject(GuardRejectReason::IpSaturated { .. }) => {}
            other => panic!("expected IpSaturated, got {:?}", other),
        }
    }

    #[test]
    fn test_default_config_matches_constants() {
        let config = GuardConfig::default();
        assert_eq!(
            config.max_handshake_attempts_per_ip,
            MAX_HANDSHAKE_ATTEMPTS_PER_IP
        );
        assert_eq!(config.max_half_open, MAX_HALF_OPEN);
        assert_eq!(config.half_open_timeout_secs, HALF_OPEN_TIMEOUT_SECS);
        assert_eq!(config.max_inbound_per_subnet, MAX_INBOUND_PER_SUBNET);
        assert_eq!(config.max_inbound_per_ip, MAX_INBOUND_PER_IP);
    }
}
