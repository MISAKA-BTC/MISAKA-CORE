//! Networking utilities: IP classification, peer scoring, ban management.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

/// Classify an IP address for security filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpClassification {
    /// Publicly routable address
    Public,
    /// Private/RFC1918 address
    Private,
    /// Loopback address
    Loopback,
    /// Link-local address
    LinkLocal,
    /// Bogon/reserved address that should never appear on public internet
    Bogon,
    /// Multicast address
    Multicast,
}

pub fn classify_ip(addr: &IpAddr) -> IpClassification {
    match addr {
        IpAddr::V4(ip) => classify_ipv4(ip),
        IpAddr::V6(ip) => classify_ipv6(ip),
    }
}

fn classify_ipv4(ip: &Ipv4Addr) -> IpClassification {
    if ip.is_loopback() {
        IpClassification::Loopback
    } else if ip.is_private() {
        IpClassification::Private
    } else if ip.is_link_local() {
        IpClassification::LinkLocal
    } else if ip.is_multicast() {
        IpClassification::Multicast
    } else if ip.is_broadcast() || ip.is_unspecified() || ip.is_documentation() {
        IpClassification::Bogon
    } else {
        let octets = ip.octets();
        // Additional bogon ranges
        if octets[0] == 0           // 0.0.0.0/8
            || octets[0] == 100 && (octets[1] & 0xC0) == 64  // 100.64.0.0/10 (CGN)
            || octets[0] == 192 && octets[1] == 0 && octets[2] == 0  // 192.0.0.0/24
            || octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) // 198.18.0.0/15
            || octets[0] == 240
        // 240.0.0.0/4 (reserved)
        {
            IpClassification::Bogon
        } else {
            IpClassification::Public
        }
    }
}

fn classify_ipv6(ip: &Ipv6Addr) -> IpClassification {
    if ip.is_loopback() {
        IpClassification::Loopback
    } else if ip.is_multicast() {
        IpClassification::Multicast
    } else if ip.is_unspecified() {
        IpClassification::Bogon
    } else {
        let segments = ip.segments();
        // fc00::/7 = unique local
        if (segments[0] & 0xFE00) == 0xFC00 {
            IpClassification::Private
        }
        // fe80::/10 = link local
        else if (segments[0] & 0xFFC0) == 0xFE80 {
            IpClassification::LinkLocal
        }
        // 2001:db8::/32 = documentation
        else if segments[0] == 0x2001 && segments[1] == 0x0db8 {
            IpClassification::Bogon
        }
        // ::ffff:0:0/96 = IPv4-mapped, classify the inner IPv4
        else if segments[0..5] == [0, 0, 0, 0, 0] && segments[5] == 0xFFFF {
            let inner = Ipv4Addr::new(
                (segments[6] >> 8) as u8,
                segments[6] as u8,
                (segments[7] >> 8) as u8,
                segments[7] as u8,
            );
            classify_ipv4(&inner)
        } else {
            IpClassification::Public
        }
    }
}

/// Returns true if the address should be rejected for P2P connections.
pub fn is_bogon(addr: &IpAddr) -> bool {
    matches!(
        classify_ip(addr),
        IpClassification::Bogon | IpClassification::Loopback | IpClassification::Multicast
    )
}

/// Peer reputation scoring.
#[derive(Debug, Clone)]
pub struct PeerScore {
    /// Current score (0.0 = bad, 1.0 = good)
    pub score: f64,
    /// Number of good actions
    pub good_actions: u64,
    /// Number of bad actions
    pub bad_actions: u64,
    /// Time of last score update
    pub last_update: Instant,
    /// Whether peer is currently banned
    pub banned: bool,
    /// Ban expiry time (if banned)
    pub ban_until: Option<Instant>,
}

impl Default for PeerScore {
    fn default() -> Self {
        Self {
            score: 0.5,
            good_actions: 0,
            bad_actions: 0,
            last_update: Instant::now(),
            banned: false,
            ban_until: None,
        }
    }
}

impl PeerScore {
    /// Record a positive action.
    pub fn record_good(&mut self, weight: f64) {
        self.good_actions += 1;
        self.score = (self.score + weight * 0.1).min(1.0);
        self.last_update = Instant::now();
    }

    /// Record a negative action.
    pub fn record_bad(&mut self, weight: f64) {
        self.bad_actions += 1;
        self.score = (self.score - weight * 0.15).max(0.0);
        self.last_update = Instant::now();
    }

    /// Apply time-based score decay toward neutral.
    pub fn decay(&mut self, elapsed: Duration) {
        let decay_factor = (-elapsed.as_secs_f64() / 3600.0).exp();
        self.score = 0.5 + (self.score - 0.5) * decay_factor;
        self.last_update = Instant::now();
    }

    /// Check if a ban has expired.
    pub fn check_ban_expiry(&mut self) -> bool {
        if self.banned {
            if let Some(until) = self.ban_until {
                if Instant::now() >= until {
                    self.banned = false;
                    self.ban_until = None;
                    self.score = 0.2; // Probationary score after ban
                    return true;
                }
            }
        }
        false
    }

    /// Ban this peer for a duration.
    pub fn ban(&mut self, duration: Duration) {
        self.banned = true;
        self.ban_until = Some(Instant::now() + duration);
        self.score = 0.0;
    }
}

/// Ban manager for tracking banned peers.
pub struct BanManager {
    bans: RwLock<HashMap<IpAddr, PeerScore>>,
    default_ban_duration: Duration,
    max_bans: usize,
}

impl BanManager {
    pub fn new(default_ban_duration: Duration, max_bans: usize) -> Self {
        Self {
            bans: RwLock::new(HashMap::new()),
            default_ban_duration,
            max_bans,
        }
    }

    pub fn ban(&self, addr: IpAddr, reason: &str) {
        let mut bans = self.bans.write();
        if bans.len() >= self.max_bans {
            // Evict expired bans
            bans.retain(|_, score| {
                if let Some(until) = score.ban_until {
                    Instant::now() < until
                } else {
                    false
                }
            });
        }
        let mut score = PeerScore::default();
        score.ban(self.default_ban_duration);
        tracing::warn!(
            "Banned peer {} for {:?}: {}",
            addr,
            self.default_ban_duration,
            reason
        );
        bans.insert(addr, score);
    }

    pub fn ban_with_duration(&self, addr: IpAddr, duration: Duration, reason: &str) {
        let mut bans = self.bans.write();
        let mut score = PeerScore::default();
        score.ban(duration);
        tracing::warn!("Banned peer {} for {:?}: {}", addr, duration, reason);
        bans.insert(addr, score);
    }

    pub fn is_banned(&self, addr: &IpAddr) -> bool {
        let bans = self.bans.read();
        if let Some(score) = bans.get(addr) {
            if score.banned {
                if let Some(until) = score.ban_until {
                    return Instant::now() < until;
                }
                return true;
            }
        }
        false
    }

    pub fn unban(&self, addr: &IpAddr) -> bool {
        self.bans.write().remove(addr).is_some()
    }

    pub fn banned_count(&self) -> usize {
        self.bans.read().values().filter(|s| s.banned).count()
    }

    pub fn cleanup_expired(&self) -> usize {
        let mut bans = self.bans.write();
        let before = bans.len();
        bans.retain(|_, score| {
            if let Some(until) = score.ban_until {
                Instant::now() < until
            } else {
                score.banned
            }
        });
        before - bans.len()
    }
}

/// Subnet-based connection limiter.
pub struct SubnetLimiter {
    /// Max connections per /16 subnet (IPv4)
    pub max_per_subnet_v4: usize,
    /// Max connections per /48 subnet (IPv6)
    pub max_per_subnet_v6: usize,
    counts: RwLock<HashMap<u64, usize>>,
}

impl SubnetLimiter {
    pub fn new(max_v4: usize, max_v6: usize) -> Self {
        Self {
            max_per_subnet_v4: max_v4,
            max_per_subnet_v6: max_v6,
            counts: RwLock::new(HashMap::new()),
        }
    }

    fn subnet_key(addr: &IpAddr) -> u64 {
        match addr {
            IpAddr::V4(ip) => {
                let o = ip.octets();
                ((o[0] as u64) << 8) | (o[1] as u64)
            }
            IpAddr::V6(ip) => {
                let s = ip.segments();
                ((s[0] as u64) << 32) | ((s[1] as u64) << 16) | (s[2] as u64) | 0x1_0000_0000_0000
            }
        }
    }

    pub fn try_add(&self, addr: &IpAddr) -> bool {
        let key = Self::subnet_key(addr);
        let max = match addr {
            IpAddr::V4(_) => self.max_per_subnet_v4,
            IpAddr::V6(_) => self.max_per_subnet_v6,
        };
        let mut counts = self.counts.write();
        let count = counts.entry(key).or_insert(0);
        if *count >= max {
            false
        } else {
            *count += 1;
            true
        }
    }

    pub fn remove(&self, addr: &IpAddr) {
        let key = Self::subnet_key(addr);
        let mut counts = self.counts.write();
        if let Some(count) = counts.get_mut(&key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_classification() {
        assert_eq!(
            classify_ip(&"8.8.8.8".parse().unwrap()),
            IpClassification::Public
        );
        assert_eq!(
            classify_ip(&"192.168.1.1".parse().unwrap()),
            IpClassification::Private
        );
        assert_eq!(
            classify_ip(&"127.0.0.1".parse().unwrap()),
            IpClassification::Loopback
        );
        assert_eq!(
            classify_ip(&"169.254.1.1".parse().unwrap()),
            IpClassification::LinkLocal
        );
        assert_eq!(
            classify_ip(&"240.0.0.1".parse().unwrap()),
            IpClassification::Bogon
        );
    }

    #[test]
    fn test_peer_score_decay() {
        let mut score = PeerScore::default();
        score.record_good(1.0);
        assert!(score.score > 0.5);
        score.record_bad(2.0);
        assert!(score.score < 0.6);
    }

    #[test]
    fn test_ban_manager() {
        let mgr = BanManager::new(Duration::from_secs(60), 1000);
        let addr: IpAddr = "1.2.3.4".parse().unwrap();
        mgr.ban(addr, "test");
        assert!(mgr.is_banned(&addr));
        mgr.unban(&addr);
        assert!(!mgr.is_banned(&addr));
    }

    #[test]
    fn test_subnet_limiter() {
        let limiter = SubnetLimiter::new(2, 2);
        let a1: IpAddr = "10.1.1.1".parse().unwrap();
        let a2: IpAddr = "10.1.2.2".parse().unwrap();
        let a3: IpAddr = "10.1.3.3".parse().unwrap();
        assert!(limiter.try_add(&a1));
        assert!(limiter.try_add(&a2));
        assert!(!limiter.try_add(&a3)); // Same /16, limit reached
        limiter.remove(&a1);
        assert!(limiter.try_add(&a3)); // Slot freed
    }
}
