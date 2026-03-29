//! # Subnet Identification — IPv4/24 + IPv6/48 Eclipse Resistance
//!
//! # Problem
//!
//! The previous implementation used `[u8; 3]` (the last 3 octets of any
//! IP address) as the subnet key. This was correct for IPv4 /24 but
//! completely wrong for native IPv6:
//!
//! - IPv6 addresses are 128 bits, allocated hierarchically
//! - A typical ISP assignment is a /48 prefix (first 6 bytes)
//! - Using the last 3 bytes groups unrelated addresses together
//!   while splitting related ones — the exact opposite of what
//!   Eclipse resistance requires
//!
//! # Solution: SubnetId
//!
//! A 6-byte identifier that extracts the correct network prefix:
//!
//! | IP Version | Prefix | Bytes Used | Rationale |
//! |-----------|--------|------------|-----------|
//! | IPv4      | /24    | 3 octets   | Standard ISP allocation ≈ /24 |
//! | IPv6      | /48    | 6 octets   | Standard site allocation (RFC 6177) |
//! | IPv4-mapped IPv6 | /24 | 3 octets | Decode to IPv4, use /24 |
//!
//! # Anti-Eclipse Properties
//!
//! An attacker controlling address space can only occupy
//! `MAX_PEERS_PER_SUBNET` connection slots per SubnetId.
//! Honest peers from diverse subnets fill the remaining slots.

use std::net::IpAddr;

// ═══════════════════════════════════════════════════════════════
//  SubnetId
// ═══════════════════════════════════════════════════════════════

/// A 6-byte subnet identifier for anti-Eclipse diversity enforcement.
///
/// # Layout
///
/// ```text
/// Byte 0: tag (0x04 = IPv4, 0x06 = IPv6)
/// Bytes 1-5: prefix bytes (zero-padded for IPv4)
///
/// IPv4 192.168.1.42  → [0x04, 192, 168, 1, 0, 0]
/// IPv6 2001:db8:1::1 → [0x06, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]
///                        tag   ─── /48 prefix (6 bytes) ───
/// ```
///
/// The tag byte prevents IPv4 `192.168.1.x` from colliding with
/// an IPv6 address whose /48 prefix happens to start with the
/// same bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubnetId([u8; 7]);

impl SubnetId {
    /// Extract the subnet identifier from an IP address.
    ///
    /// - IPv4: uses /24 prefix (first 3 octets)
    /// - IPv6: uses /48 prefix (first 6 octets)
    /// - IPv4-mapped IPv6 (::ffff:x.x.x.x): decoded to IPv4 /24
    pub fn from_ip(ip: &IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                Self([0x04, o[0], o[1], o[2], 0, 0, 0])
            }
            IpAddr::V6(v6) => {
                let o = v6.octets();

                // Detect IPv4-mapped IPv6 (::ffff:x.x.x.x)
                // Octets 0-9 are zero, octets 10-11 are 0xFF
                if o[..10] == [0; 10] && o[10] == 0xff && o[11] == 0xff {
                    // Extract the embedded IPv4 and use /24
                    Self([0x04, o[12], o[13], o[14], 0, 0, 0])
                } else {
                    // Native IPv6: use /48 prefix (first 6 octets)
                    Self([0x06, o[0], o[1], o[2], o[3], o[4], o[5]])
                }
            }
        }
    }

    /// Raw bytes for logging/serialization.
    pub fn as_bytes(&self) -> &[u8; 7] {
        &self.0
    }

    /// Short hex representation for logging.
    pub fn short_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Whether this is an IPv4-derived subnet.
    pub fn is_ipv4(&self) -> bool {
        self.0[0] == 0x04
    }

    /// Whether this is an IPv6-derived subnet.
    pub fn is_ipv6(&self) -> bool {
        self.0[0] == 0x06
    }
}

impl std::fmt::Display for SubnetId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_ipv4() {
            write!(f, "{}.{}.{}.0/24", self.0[1], self.0[2], self.0[3])
        } else {
            write!(
                f,
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}::/48",
                self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6]
            )
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ── IPv4 /24 tests ──

    #[test]
    fn test_ipv4_same_slash24_same_subnet() {
        let a: IpAddr = Ipv4Addr::new(192, 168, 1, 10).into();
        let b: IpAddr = Ipv4Addr::new(192, 168, 1, 200).into();
        assert_eq!(SubnetId::from_ip(&a), SubnetId::from_ip(&b));
    }

    #[test]
    fn test_ipv4_different_slash24_different_subnet() {
        let a: IpAddr = Ipv4Addr::new(192, 168, 1, 10).into();
        let b: IpAddr = Ipv4Addr::new(192, 168, 2, 10).into();
        assert_ne!(SubnetId::from_ip(&a), SubnetId::from_ip(&b));
    }

    #[test]
    fn test_ipv4_tag() {
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let sid = SubnetId::from_ip(&ip);
        assert!(sid.is_ipv4());
        assert!(!sid.is_ipv6());
    }

    // ── IPv6 /48 tests ──

    #[test]
    fn test_ipv6_same_slash48_same_subnet() {
        // 2001:0db8:0001:0001::1 and 2001:0db8:0001:ffff::42
        // Both share /48 prefix 2001:0db8:0001
        let a: IpAddr = "2001:db8:1:1::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:ffff::42".parse().unwrap();
        assert_eq!(SubnetId::from_ip(&a), SubnetId::from_ip(&b));
    }

    #[test]
    fn test_ipv6_different_slash48_different_subnet() {
        // 2001:0db8:0001::1 vs 2001:0db8:0002::1 (different /48)
        let a: IpAddr = "2001:db8:1::1".parse().unwrap();
        let b: IpAddr = "2001:db8:2::1".parse().unwrap();
        assert_ne!(SubnetId::from_ip(&a), SubnetId::from_ip(&b));
    }

    #[test]
    fn test_ipv6_tag() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let sid = SubnetId::from_ip(&ip);
        assert!(sid.is_ipv6());
        assert!(!sid.is_ipv4());
    }

    #[test]
    fn test_ipv6_slash48_extracts_first_6_octets() {
        // 2001:0db8:abcd:efgh::1
        // /48 = 2001:0db8:abcd
        let ip: IpAddr = "2001:db8:abcd:ef01::1".parse().unwrap();
        let sid = SubnetId::from_ip(&ip);
        // tag=0x06, then 0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd
        assert_eq!(sid.0[0], 0x06);
        assert_eq!(sid.0[1], 0x20);
        assert_eq!(sid.0[2], 0x01);
        assert_eq!(sid.0[3], 0x0d);
        assert_eq!(sid.0[4], 0xb8);
        assert_eq!(sid.0[5], 0xab);
        assert_eq!(sid.0[6], 0xcd);
    }

    // ── IPv4-mapped IPv6 tests ──

    #[test]
    fn test_ipv4_mapped_ipv6_decoded_to_ipv4_subnet() {
        // ::ffff:192.168.1.10 should map to the same subnet as 192.168.1.10
        let native: IpAddr = Ipv4Addr::new(192, 168, 1, 10).into();
        let mapped: IpAddr = "::ffff:192.168.1.10".parse().unwrap();
        assert_eq!(SubnetId::from_ip(&native), SubnetId::from_ip(&mapped));
    }

    #[test]
    fn test_ipv4_mapped_ipv6_is_tagged_as_ipv4() {
        let mapped: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        let sid = SubnetId::from_ip(&mapped);
        assert!(sid.is_ipv4(), "mapped IPv4 should be tagged as IPv4");
    }

    // ── Cross-protocol isolation ──

    #[test]
    fn test_ipv4_and_ipv6_never_collide() {
        // Even if an IPv6 /48 starts with the same bytes as an IPv4 /24,
        // the tag byte prevents collision
        let v4: IpAddr = Ipv4Addr::new(0x20, 0x01, 0x0d, 1).into();
        let v6: IpAddr = "2001:0d01::1".parse().unwrap();
        assert_ne!(
            SubnetId::from_ip(&v4),
            SubnetId::from_ip(&v6),
            "IPv4 and IPv6 must never share a SubnetId"
        );
    }

    // ── Display ──

    #[test]
    fn test_display_ipv4() {
        let ip: IpAddr = Ipv4Addr::new(203, 0, 113, 42).into();
        assert_eq!(SubnetId::from_ip(&ip).to_string(), "203.0.113.0/24");
    }

    #[test]
    fn test_display_ipv6() {
        let ip: IpAddr = "2001:db8:abcd::1".parse().unwrap();
        assert_eq!(SubnetId::from_ip(&ip).to_string(), "2001:0db8:abcd::/48");
    }

    // ── HashMap key ──

    #[test]
    fn test_subnet_id_as_hashmap_key() {
        use std::collections::HashMap;
        let mut map: HashMap<SubnetId, usize> = HashMap::new();
        let ip: IpAddr = Ipv4Addr::new(10, 0, 0, 1).into();
        let sid = SubnetId::from_ip(&ip);
        map.insert(sid, 42);
        assert_eq!(map.get(&sid), Some(&42));
    }
}
