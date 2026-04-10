//! # Peer Discovery — Bootstrap + Gossip with Signed Records
//!
//! # Protocol
//!
//! 1. Node connects to bootstrap nodes from config
//! 2. Sends GetPeers request
//! 3. Receives signed PeerRecords
//! 4. Validates and stores records
//! 5. Periodically gossips records to connected peers
//! 6. Periodically re-advertises own record
//!
//! # Anti-Spam
//!
//! - Records are verified before storage (ML-DSA-65 signature)
//! - Expired records are rejected
//! - Duplicate records are deduplicated by PeerId
//! - Gossip is rate-limited per peer
//! - Maximum peer store size is bounded

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tracing::{debug, warn};

use crate::peer_id::PeerId;
use crate::peer_record::{PeerRecord, PeerRecordError};

/// SEC-FIX-7: Maximum dial candidates from the same subnet.
///
/// An attacker controlling an address range (e.g., a /24 IPv4 or /48 IPv6)
/// can flood the peer store with records. Without subnet diversity in dial
/// selection, all outbound connections may go to attacker-controlled nodes
/// (Eclipse attack). This cap ensures outbound connections are spread
/// across diverse network prefixes.
pub const MAX_DIAL_CANDIDATES_PER_SUBNET: usize = 2;

/// Maximum age (seconds) for a peer record to be considered for dialing.
/// Records older than this are likely stale (node moved, restarted, etc.).
pub const MAX_RECORD_AGE_SECS: u64 = 3600 * 6; // 6 hours

/// Maximum peers in the peer store.
pub const MAX_PEER_STORE_SIZE: usize = 4096;

/// Gossip batch size (records per exchange).
pub const GOSSIP_BATCH_SIZE: usize = 16;

/// Minimum interval between gossip exchanges with the same peer.
pub const GOSSIP_COOLDOWN_SECS: u64 = 30;

/// Self-advertisement interval.
pub const SELF_ADVERTISE_INTERVAL_SECS: u64 = 300; // 5 minutes

// ═══════════════════════════════════════════════════════════════
//  Discovery Trait
// ═══════════════════════════════════════════════════════════════

/// Backend for peer discovery.
///
/// Designed for future extension (e.g., DHT backend).
pub trait DiscoveryBackend {
    /// Notification: a new peer has connected.
    fn on_connected_peer(&mut self, peer: PeerId);

    /// Notification: a peer has disconnected.
    fn on_disconnected_peer(&mut self, peer: PeerId);

    /// Ingest a peer record from the network.
    ///
    /// Returns Ok(true) if the record was new, Ok(false) if duplicate.
    fn ingest_peer_record(&mut self, record: PeerRecord) -> Result<bool, PeerRecordError>;

    /// Select peers to dial (not yet connected, sorted by priority).
    fn select_dial_candidates(&self, limit: usize) -> Vec<PeerRecord>;

    /// Get the next batch of records to gossip to a specific peer.
    fn next_gossip_batch(&self, peer: &PeerId, limit: usize) -> Vec<PeerRecord>;
}

// ═══════════════════════════════════════════════════════════════
//  Peer Store
// ═══════════════════════════════════════════════════════════════

/// In-memory store of verified peer records.
///
/// Only records that pass `PeerRecord::verify()` are admitted.
#[derive(Debug)]
pub struct PeerStore {
    /// Verified records indexed by PeerId.
    records: HashMap<PeerId, StoredRecord>,
    /// Connected peers (for filtering dial candidates).
    connected: std::collections::HashSet<PeerId>,
    /// Last gossip time per peer (rate limiting).
    last_gossip: HashMap<PeerId, Instant>,
    /// Our own chain_id (for chain-scoped validation).
    chain_id: u32,
}

#[derive(Debug, Clone)]
struct StoredRecord {
    record: PeerRecord,
    #[allow(dead_code)]
    added_at: Instant,
    dial_failures: u32,
    last_seen_connected: Option<Instant>,
}

impl PeerStore {
    pub fn new(chain_id: u32) -> Self {
        Self {
            records: HashMap::new(),
            connected: std::collections::HashSet::new(),
            last_gossip: HashMap::new(),
            chain_id,
        }
    }

    /// Number of stored records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Get a record by PeerId.
    pub fn get(&self, peer_id: &PeerId) -> Option<&PeerRecord> {
        self.records.get(peer_id).map(|s| &s.record)
    }

    /// Check if we have a record for this peer.
    pub fn contains(&self, peer_id: &PeerId) -> bool {
        self.records.contains_key(peer_id)
    }

    /// Remove expired records.
    pub fn evict_expired(&mut self) {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.records
            .retain(|_, stored| stored.record.expires_at_unix > now_unix);
    }

    /// Record a dial failure for a peer.
    pub fn record_dial_failure(&mut self, peer_id: &PeerId) {
        if let Some(stored) = self.records.get_mut(peer_id) {
            stored.dial_failures += 1;
        }
    }

    /// Record a successful connection.
    pub fn record_connection_success(&mut self, peer_id: &PeerId) {
        if let Some(stored) = self.records.get_mut(peer_id) {
            stored.last_seen_connected = Some(Instant::now());
            stored.dial_failures = 0; // Reset on success
        }
    }
}

impl DiscoveryBackend for PeerStore {
    fn on_connected_peer(&mut self, peer: PeerId) {
        self.connected.insert(peer);
        self.record_connection_success(&peer);
    }

    fn on_disconnected_peer(&mut self, peer: PeerId) {
        self.connected.remove(&peer);
    }

    fn ingest_peer_record(&mut self, record: PeerRecord) -> Result<bool, PeerRecordError> {
        // ── Chain ID check ──
        if record.chain_id != self.chain_id {
            return Err(PeerRecordError::PeerIdMismatch {
                declared: format!("chain_id={}", record.chain_id),
                derived: format!("expected chain_id={}", self.chain_id),
            });
        }

        // ── Verify signature + expiry ──
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        record.verify(now_unix)?;

        // ── SEC-DISC-BOGON: Reject records with non-routable addresses ──
        //
        // An attacker can advertise private/loopback IPs to:
        // 1. Cause peers to waste connections on unreachable addresses
        // 2. Redirect peers to local services (SSRF-like vector)
        // 3. Pollute the peer store with useless entries
        //
        // We validate ALL addresses in the record. If ANY address is
        // bogon, the entire record is rejected (fail-closed). A legitimate
        // node has no reason to advertise private IPs on the public network.
        for addr in &record.addresses {
            if !crate::connection_guard::validate_advertised_address(&addr.addr) {
                warn!(
                    peer_id = %record.peer_id.short_hex(),
                    addr = %addr.addr,
                    "SEC-DISC-BOGON: rejecting peer record with non-routable address"
                );
                return Ok(false);
            }
        }

        // ── Duplicate / update check ──
        if let Some(existing) = self.records.get(&record.peer_id) {
            if existing.record.issued_at_unix >= record.issued_at_unix {
                return Ok(false); // We already have a newer or equal record
            }
        }

        // ── Capacity check ──
        if self.records.len() >= MAX_PEER_STORE_SIZE && !self.records.contains_key(&record.peer_id)
        {
            // Evict the oldest record
            if let Some(oldest_id) = self
                .records
                .iter()
                .filter(|(id, _)| !self.connected.contains(id)) // Don't evict connected peers
                .min_by_key(|(_, s)| s.record.issued_at_unix)
                .map(|(id, _)| *id)
            {
                self.records.remove(&oldest_id);
            } else {
                // All peers are connected and store is full — reject
                warn!("Peer store full and all peers connected, rejecting new record");
                return Ok(false);
            }
        }

        let peer_id = record.peer_id;
        self.records.insert(
            peer_id,
            StoredRecord {
                record,
                added_at: Instant::now(),
                dial_failures: 0,
                last_seen_connected: None,
            },
        );

        debug!("Stored new peer record for {}", peer_id.short_hex());
        Ok(true)
    }

    fn select_dial_candidates(&self, limit: usize) -> Vec<PeerRecord> {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut candidates: Vec<&StoredRecord> = self
            .records
            .values()
            .filter(|s| {
                !self.connected.contains(&s.record.peer_id)
                    && s.dial_failures < 5
                    && !s.record.addresses.is_empty()
                    // SEC-FIX-7: Reject stale records
                    && now_unix.saturating_sub(s.record.issued_at_unix) < MAX_RECORD_AGE_SECS
            })
            .collect();

        // Sort: prefer fewer failures, then newer records
        candidates.sort_by(|a, b| {
            a.dial_failures
                .cmp(&b.dial_failures)
                .then_with(|| b.record.issued_at_unix.cmp(&a.record.issued_at_unix))
        });

        // SEC-FIX-7: Subnet-diverse selection.
        // Take at most MAX_DIAL_CANDIDATES_PER_SUBNET from each subnet.
        // This prevents an Eclipse attacker from filling all outbound slots
        // with nodes from one address range.
        use crate::subnet::SubnetId;
        let mut subnet_counts: std::collections::HashMap<SubnetId, usize> =
            std::collections::HashMap::new();
        let mut selected = Vec::with_capacity(limit);

        for stored in candidates {
            if selected.len() >= limit {
                break;
            }

            // Extract subnet from first address
            let subnet = stored
                .record
                .addresses
                .first()
                .and_then(|addr| {
                    // Parse "host:port" or "[host]:port" to extract IP
                    addr.addr
                        .rsplit_once(':')
                        .and_then(|(host, _)| {
                            let h = host.trim_start_matches('[').trim_end_matches(']');
                            h.parse::<std::net::IpAddr>().ok()
                        })
                        .map(|ip| SubnetId::from_ip(&ip))
                })
                .unwrap_or_else(|| {
                    // If we can't parse the address, use a unique "unknown" subnet
                    // that won't conflict with any real subnet.
                    SubnetId::from_ip(&std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
                });

            let count = subnet_counts.entry(subnet).or_insert(0);
            if *count >= MAX_DIAL_CANDIDATES_PER_SUBNET {
                continue; // Skip — too many from this subnet
            }
            *count += 1;
            selected.push(stored.record.clone());
        }

        selected
    }

    fn next_gossip_batch(&self, peer: &PeerId, limit: usize) -> Vec<PeerRecord> {
        // Rate limit gossip
        if let Some(last) = self.last_gossip.get(peer) {
            if last.elapsed() < Duration::from_secs(GOSSIP_COOLDOWN_SECS) {
                return Vec::new();
            }
        }

        // SEC-H3: Collect eligible records, then sort by a per-target-peer
        // deterministic hash to achieve pseudo-random selection.
        //
        // This ensures different peers receive different subsets of our known
        // records, improving network-wide record propagation coverage.
        // The hash rotates naturally as records are added/removed.
        let mut eligible: Vec<&StoredRecord> = self
            .records
            .values()
            .filter(|s| {
                s.record.peer_id != *peer
                    && !s.record.addresses.is_empty()
                    // Don't gossip validator records to non-sentry peers
                    && !s.record.roles.validator
            })
            .collect();

        // Deterministic shuffle: sort by H(target_peer || record_peer || issued_at)
        // This gives a different ordering per (target, record) pair and rotates
        // when records are refreshed (issued_at changes).
        eligible.sort_by_cached_key(|s| {
            use sha3::{Digest, Sha3_256};
            let mut h = Sha3_256::new();
            h.update(&peer.0);
            h.update(&s.record.peer_id.0);
            h.update(&s.record.issued_at_unix.to_le_bytes());
            let hash: [u8; 32] = h.finalize().into();
            // SAFETY: hash is 32 bytes, [..8] is always valid for 8-byte array
            let bytes: [u8; 8] = match hash[..8].try_into() {
                Ok(b) => b,
                Err(_) => [0u8; 8],
            };
            u64::from_le_bytes(bytes)
        });

        eligible
            .into_iter()
            .take(limit)
            .map(|s| s.record.clone())
            .collect()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_record::{CapabilityFlags, NetworkAddress, PeerRoles};
    use misaka_crypto::validator_sig::generate_validator_keypair;

    fn now_unix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn make_record(chain_id: u32) -> PeerRecord {
        let kp = generate_validator_keypair();
        PeerRecord::create_signed(
            &kp.public_key.to_bytes(),
            &kp.secret_key,
            vec![NetworkAddress {
                protocol: "tcp".into(),
                addr: "1.2.3.4:6690".into(),
            }],
            CapabilityFlags::RELAY,
            PeerRoles::full_node(),
            chain_id,
            "test".into(),
            0,
            now_unix(),
            3600,
        )
        .expect("create signed record")
    }

    #[test]
    fn test_peer_store_ingest_valid_record() {
        let mut store = PeerStore::new(2);
        let record = make_record(2);
        let result = store.ingest_peer_record(record);
        assert!(matches!(result, Ok(true)));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_peer_store_rejects_wrong_chain() {
        let mut store = PeerStore::new(2);
        let record = make_record(99); // wrong chain
        let result = store.ingest_peer_record(record);
        assert!(result.is_err());
    }

    #[test]
    fn test_peer_store_dedup_by_peer_id() {
        let mut store = PeerStore::new(2);
        let kp = generate_validator_keypair();
        let r1 = PeerRecord::create_signed(
            &kp.public_key.to_bytes(),
            &kp.secret_key,
            vec![],
            CapabilityFlags::RELAY,
            PeerRoles::full_node(),
            2,
            "test".into(),
            0,
            now_unix(),
            3600,
        )
        .expect("signed");
        let r2 = PeerRecord::create_signed(
            &kp.public_key.to_bytes(),
            &kp.secret_key,
            vec![],
            CapabilityFlags::RELAY,
            PeerRoles::full_node(),
            2,
            "test".into(),
            0,
            now_unix() - 10,
            3600, // older
        )
        .expect("signed");

        store.ingest_peer_record(r1).expect("first");
        let result = store.ingest_peer_record(r2).expect("second");
        assert!(!result, "older record should be rejected");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_dial_candidates_exclude_connected() {
        let mut store = PeerStore::new(2);
        let record = make_record(2);
        let pid = record.peer_id;
        store.ingest_peer_record(record).expect("ingest");
        store.on_connected_peer(pid);

        let candidates = store.select_dial_candidates(10);
        assert!(
            candidates.is_empty(),
            "connected peers should not be dial candidates"
        );
    }

    #[test]
    fn test_gossip_excludes_validator_records() {
        let mut store = PeerStore::new(2);
        let kp = generate_validator_keypair();
        let record = PeerRecord::create_signed(
            &kp.public_key.to_bytes(),
            &kp.secret_key,
            vec![NetworkAddress {
                protocol: "tcp".into(),
                addr: "1.2.3.4:6690".into(),
            }],
            CapabilityFlags::RELAY,
            PeerRoles::validator(), // validator role
            2,
            "test".into(),
            0,
            now_unix(),
            3600,
        )
        .expect("signed");
        store.ingest_peer_record(record).expect("ingest");

        let batch = store.next_gossip_batch(&PeerId::ZERO, 10);
        assert!(batch.is_empty(), "validator records should not be gossiped");
    }

    #[test]
    fn test_bogon_address_rejected() {
        let mut store = PeerStore::new(2);
        let kp = generate_validator_keypair();

        // Create a record with a private IP address
        let record = PeerRecord::create_signed(
            &kp.public_key.to_bytes(),
            &kp.secret_key,
            vec![NetworkAddress {
                protocol: "tcp".into(),
                addr: "10.0.0.1:6690".into(), // private IP!
            }],
            CapabilityFlags::RELAY,
            PeerRoles::full_node(),
            2,
            "test".into(),
            0,
            now_unix(),
            3600,
        )
        .expect("signed");

        // Should be rejected (returns Ok(false), not stored)
        let result = store.ingest_peer_record(record).expect("no error");
        assert!(!result, "records with private IPs must be rejected");
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn test_loopback_address_rejected() {
        let mut store = PeerStore::new(2);
        let kp = generate_validator_keypair();

        let record = PeerRecord::create_signed(
            &kp.public_key.to_bytes(),
            &kp.secret_key,
            vec![NetworkAddress {
                protocol: "tcp".into(),
                addr: "127.0.0.1:6690".into(), // loopback!
            }],
            CapabilityFlags::RELAY,
            PeerRoles::full_node(),
            2,
            "test".into(),
            0,
            now_unix(),
            3600,
        )
        .expect("signed");

        let result = store.ingest_peer_record(record).expect("no error");
        assert!(!result, "records with loopback IPs must be rejected");
    }

    // ── SEC-FIX-7 Tests: Subnet Diversity in Dial Selection ──

    #[test]
    fn test_dial_candidates_subnet_diversity() {
        let mut store = PeerStore::new(2);

        // Add 5 peers all from the same /24 subnet (1.2.3.x)
        for i in 0..5u8 {
            let kp = generate_validator_keypair();
            let record = PeerRecord::create_signed(
                &kp.public_key.to_bytes(),
                &kp.secret_key,
                vec![NetworkAddress {
                    protocol: "tcp".into(),
                    addr: format!("1.2.3.{}:6690", 10 + i),
                }],
                CapabilityFlags::RELAY,
                PeerRoles::full_node(),
                2,
                "test".into(),
                0,
                now_unix(),
                3600,
            )
            .expect("signed");
            store.ingest_peer_record(record).expect("ingest");
        }

        // Add 2 peers from a different subnet
        for i in 0..2u8 {
            let kp = generate_validator_keypair();
            let record = PeerRecord::create_signed(
                &kp.public_key.to_bytes(),
                &kp.secret_key,
                vec![NetworkAddress {
                    protocol: "tcp".into(),
                    addr: format!("5.6.7.{}:6690", 10 + i),
                }],
                CapabilityFlags::RELAY,
                PeerRoles::full_node(),
                2,
                "test".into(),
                0,
                now_unix(),
                3600,
            )
            .expect("signed");
            store.ingest_peer_record(record).expect("ingest");
        }

        assert_eq!(store.len(), 7);

        // Request 6 candidates — should get at most 2 from 1.2.3.0/24
        let candidates = store.select_dial_candidates(6);

        let same_subnet_count = candidates
            .iter()
            .filter(|r| r.addresses[0].addr.starts_with("1.2.3."))
            .count();

        assert!(
            same_subnet_count <= MAX_DIAL_CANDIDATES_PER_SUBNET,
            "got {} candidates from same subnet, max allowed is {}",
            same_subnet_count,
            MAX_DIAL_CANDIDATES_PER_SUBNET,
        );

        // Should include peers from the other subnet
        let other_subnet_count = candidates
            .iter()
            .filter(|r| r.addresses[0].addr.starts_with("5.6.7."))
            .count();
        assert!(
            other_subnet_count > 0,
            "should include peers from diverse subnets"
        );
    }

    #[test]
    fn test_stale_records_not_selected_for_dial() {
        let mut store = PeerStore::new(2);
        let kp = generate_validator_keypair();

        // Create a record that is already very old
        let old_time = now_unix().saturating_sub(MAX_RECORD_AGE_SECS + 100);
        let record = PeerRecord::create_signed(
            &kp.public_key.to_bytes(),
            &kp.secret_key,
            vec![NetworkAddress {
                protocol: "tcp".into(),
                addr: "1.2.3.4:6690".into(),
            }],
            CapabilityFlags::RELAY,
            PeerRoles::full_node(),
            2,
            "test".into(),
            0,
            old_time,
            // TTL long enough that it hasn't "expired" per the verify check
            MAX_RECORD_AGE_SECS * 2,
        )
        .expect("signed");
        store.ingest_peer_record(record).expect("ingest");

        let candidates = store.select_dial_candidates(10);
        assert!(
            candidates.is_empty(),
            "stale records must not be selected as dial candidates"
        );
    }
}
