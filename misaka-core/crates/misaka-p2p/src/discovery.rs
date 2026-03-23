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
        let mut candidates: Vec<&StoredRecord> = self
            .records
            .values()
            .filter(|s| {
                !self.connected.contains(&s.record.peer_id)
                    && s.dial_failures < 5
                    && !s.record.addresses.is_empty()
            })
            .collect();

        // Sort: prefer recently seen, fewer failures, newer records
        candidates.sort_by(|a, b| {
            a.dial_failures
                .cmp(&b.dial_failures)
                .then_with(|| b.record.issued_at_unix.cmp(&a.record.issued_at_unix))
        });

        candidates
            .into_iter()
            .take(limit)
            .map(|s| s.record.clone())
            .collect()
    }

    fn next_gossip_batch(&self, peer: &PeerId, limit: usize) -> Vec<PeerRecord> {
        // Rate limit gossip
        if let Some(last) = self.last_gossip.get(peer) {
            if last.elapsed() < Duration::from_secs(GOSSIP_COOLDOWN_SECS) {
                return Vec::new();
            }
        }

        // Select records to gossip (exclude the target peer's own record)
        self.records
            .values()
            .filter(|s| {
                s.record.peer_id != *peer
                    && !s.record.addresses.is_empty()
                    // Don't gossip validator records to non-sentry peers
                    && !s.record.roles.validator
            })
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
}
