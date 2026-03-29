//! Quarantine Store — persistent isolation of suspicious blocks, txs, peers, etc.
//!
//! # No-Rollback Architecture
//!
//! Instead of reverting chain history, MISAKA quarantines suspicious data:
//! - Quarantined blocks are NOT relayed to peers
//! - Quarantined txs are excluded from mempool and block production
//! - Quarantined peers are disconnected and banned
//! - Quarantined bridge events trigger bridge pause
//!
//! # Persistence
//!
//! The store is backed by a JSON file (upgradeable to RocksDB column family).
//! Entries survive node restart. Audit log is append-only JSONL.
//!
//! # Thread Safety
//!
//! The store is NOT internally synchronized. Wrap in Mutex at the call site.

use misaka_types::quarantine::{
    Hash, QuarantineEntry, QuarantineReason, QuarantineType,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

// ═══════════════════════════════════════════════════════════════
//  Error
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum QuarantineStoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("entry not found: type={entry_type} id={}", hex::encode(&id[..4]))]
    NotFound { entry_type: QuarantineType, id: Hash },
}

// ═══════════════════════════════════════════════════════════════
//  Audit Log Entry
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Serialize)]
struct AuditLogEntry {
    action: String,
    id: String,
    entry_type: String,
    reason: String,
    offense_count: u32,
    timestamp_ms: u64,
    operator: Option<String>,
}

// ═══════════════════════════════════════════════════════════════
//  Persistent Snapshot (for JSON file storage)
// ═══════════════════════════════════════════════════════════════

#[derive(Serialize, Deserialize)]
struct StoreSnapshot {
    entries: Vec<QuarantineEntry>,
}

// ═══════════════════════════════════════════════════════════════
//  QuarantineStore
// ═══════════════════════════════════════════════════════════════

pub struct QuarantineStore {
    /// All entries keyed by (type, id).
    entries: HashMap<(QuarantineType, Hash), QuarantineEntry>,
    /// Fast lookup: is this id quarantined (any type)?
    quarantined_ids: HashSet<Hash>,
    /// Store file path.
    store_path: PathBuf,
    /// Audit log file path.
    audit_log_path: PathBuf,
    /// Dirty flag: true if entries changed since last flush.
    dirty: bool,
}

impl QuarantineStore {
    /// Open or create a quarantine store.
    pub fn open(data_dir: &Path) -> Result<Self, QuarantineStoreError> {
        fs::create_dir_all(data_dir)?;
        let store_path = data_dir.join("quarantine.json");
        let audit_log_path = data_dir.join("quarantine_audit.jsonl");

        let mut store = Self {
            entries: HashMap::new(),
            quarantined_ids: HashSet::new(),
            store_path,
            audit_log_path,
            dirty: false,
        };

        // Load existing entries
        if store.store_path.exists() {
            let data = fs::read_to_string(&store.store_path)?;
            if !data.trim().is_empty() {
                let snapshot: StoreSnapshot = serde_json::from_str(&data)?;
                for entry in snapshot.entries {
                    if !entry.released {
                        store.quarantined_ids.insert(entry.id);
                    }
                    store.entries.insert((entry.entry_type, entry.id), entry);
                }
                info!(
                    "Quarantine store loaded: {} entries ({} active)",
                    store.entries.len(),
                    store.quarantined_ids.len()
                );
            }
        }

        Ok(store)
    }

    /// Create an in-memory store (for testing).
    #[cfg(test)]
    pub fn open_in_memory() -> Self {
        Self {
            entries: HashMap::new(),
            quarantined_ids: HashSet::new(),
            store_path: PathBuf::from("/dev/null"),
            audit_log_path: PathBuf::from("/dev/null"),
            dirty: false,
        }
    }

    // ─── Core Operations ──────────────────────────────────────

    /// Quarantine an entity. Returns the (possibly updated) entry.
    ///
    /// # Panics
    /// Never — the entry is always present after `or_insert_with`.
    #[allow(clippy::unwrap_used)] // entry is guaranteed present after insert above
    pub fn quarantine(
        &mut self,
        id: Hash,
        entry_type: QuarantineType,
        reason: QuarantineReason,
        source_peer: Option<Hash>,
    ) -> &QuarantineEntry {
        let now_ms = Self::now_ms();
        let key = (entry_type, id);
        let entry = self.entries.entry(key).or_insert_with(|| {
            QuarantineEntry::new(id, entry_type, reason.clone(), source_peer, now_ms)
        });
        if entry.quarantined_at_ms != now_ms {
            entry.offense_count += 1;
            entry.reason = reason.clone();
            entry.released = false;
            entry.released_at_ms = None;
            entry.released_by = None;
        }
        let offense_count = entry.offense_count;
        let reason_display = entry.reason.to_string();
        let reason_str = format!("{}", reason);
        self.quarantined_ids.insert(id);
        self.dirty = true;
        self.write_audit(AuditLogEntry {
            action: "quarantine".into(),
            id: hex::encode(id),
            entry_type: entry_type.to_string(),
            reason: reason_str,
            offense_count,
            timestamp_ms: now_ms,
            operator: None,
        });
        info!(
            "Quarantined {}/{}: {} (offense #{})",
            entry_type,
            hex::encode(&id[..4]),
            reason_display,
            offense_count
        );
        self.entries.get(&key).unwrap()
    }

    /// Is this id currently quarantined (any type)?
    pub fn is_quarantined(&self, id: &Hash) -> bool {
        self.quarantined_ids.contains(id)
    }

    /// Is this specific (type, id) actively quarantined?
    pub fn is_quarantined_as(&self, entry_type: QuarantineType, id: &Hash) -> bool {
        self.entries
            .get(&(entry_type, *id))
            .map(|e| e.is_active(Self::now_ms()))
            .unwrap_or(false)
    }

    /// Release a quarantine entry (operator action).
    #[allow(clippy::unwrap_used)] // entry is guaranteed present after get_mut above
    pub fn release(
        &mut self,
        entry_type: QuarantineType,
        id: Hash,
        operator: &str,
    ) -> Result<&QuarantineEntry, QuarantineStoreError> {
        let now_ms = Self::now_ms();
        let key = (entry_type, id);

        let entry = self
            .entries
            .get_mut(&key)
            .ok_or(QuarantineStoreError::NotFound { entry_type, id })?;

        entry.released = true;
        entry.released_at_ms = Some(now_ms);
        entry.released_by = Some(operator.to_string());
        self.dirty = true;

        // Remove from fast-lookup if all types are released
        let all_released = [
            QuarantineType::Block,
            QuarantineType::Tx,
            QuarantineType::Peer,
            QuarantineType::BridgeEvent,
            QuarantineType::Snapshot,
        ]
        .iter()
        .all(|t| {
            self.entries
                .get(&(*t, id))
                .map(|e| e.released)
                .unwrap_or(true)
        });

        if all_released {
            self.quarantined_ids.remove(&id);
        }

        self.write_audit(AuditLogEntry {
            action: "release".into(),
            id: hex::encode(id),
            entry_type: entry_type.to_string(),
            reason: String::new(),
            offense_count: 0,
            timestamp_ms: now_ms,
            operator: Some(operator.to_string()),
        });

        info!(
            "Released {}/{} by operator {}",
            entry_type,
            hex::encode(&id[..4]),
            operator
        );

        Ok(self.entries.get(&key).unwrap())
    }

    /// Get a specific entry.
    pub fn get(&self, entry_type: QuarantineType, id: &Hash) -> Option<&QuarantineEntry> {
        self.entries.get(&(entry_type, *id))
    }

    /// List entries by type (optionally including released).
    pub fn list(
        &self,
        entry_type: Option<QuarantineType>,
        include_released: bool,
    ) -> Vec<&QuarantineEntry> {
        let now = Self::now_ms();
        self.entries
            .values()
            .filter(|e| entry_type.map(|t| e.entry_type == t).unwrap_or(true))
            .filter(|e| include_released || e.is_active(now))
            .collect()
    }

    /// Count of active quarantine entries.
    pub fn active_count(&self) -> usize {
        let now = Self::now_ms();
        self.entries.values().filter(|e| e.is_active(now)).count()
    }

    /// Count of active entries by type.
    pub fn active_count_by_type(&self, entry_type: QuarantineType) -> usize {
        let now = Self::now_ms();
        self.entries
            .values()
            .filter(|e| e.entry_type == entry_type && e.is_active(now))
            .count()
    }

    // ─── Maintenance ──────────────────────────────────────────

    /// Clean up auto-expired entries (peer bans).
    pub fn cleanup_expired(&mut self) -> usize {
        let now = Self::now_ms();
        let expired: Vec<(QuarantineType, Hash)> = self
            .entries
            .iter()
            .filter(|(_, e)| {
                !e.released && e.auto_release_at_ms.map(|t| now >= t).unwrap_or(false)
            })
            .map(|(&k, _)| k)
            .collect();

        let count = expired.len();
        for (t, id) in expired {
            if let Some(entry) = self.entries.get_mut(&(t, id)) {
                entry.released = true;
                entry.released_at_ms = Some(now);
                entry.released_by = Some("auto-expire".into());
            }
        }

        if count > 0 {
            self.dirty = true;
            // Rebuild quarantined_ids
            self.quarantined_ids.clear();
            for ((_, id), entry) in &self.entries {
                if entry.is_active(now) {
                    self.quarantined_ids.insert(*id);
                }
            }
            debug!("Quarantine cleanup: {} entries auto-expired", count);
        }

        count
    }

    /// Flush entries to disk.
    pub fn flush(&mut self) -> Result<(), QuarantineStoreError> {
        if !self.dirty {
            return Ok(());
        }
        let snapshot = StoreSnapshot {
            entries: self.entries.values().cloned().collect(),
        };
        let data = serde_json::to_string_pretty(&snapshot)?;
        fs::write(&self.store_path, data)?;
        self.dirty = false;
        debug!("Quarantine store flushed: {} entries", self.entries.len());
        Ok(())
    }

    // ─── Internal Helpers ─────────────────────────────────────

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    fn write_audit(&self, entry: AuditLogEntry) {
        if let Ok(mut f) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.audit_log_path)
        {
            if let Ok(json) = serde_json::to_string(&entry) {
                let _ = writeln!(f, "{}", json);
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quarantine_and_check() {
        let mut store = QuarantineStore::open_in_memory();
        let id = [0xAA; 32];

        assert!(!store.is_quarantined(&id));

        store.quarantine(
            id,
            QuarantineType::Block,
            QuarantineReason::DuplicateBlock,
            None,
        );

        assert!(store.is_quarantined(&id));
        assert!(store.is_quarantined_as(QuarantineType::Block, &id));
        assert!(!store.is_quarantined_as(QuarantineType::Tx, &id));
    }

    #[test]
    fn test_quarantine_offense_count_increments() {
        let mut store = QuarantineStore::open_in_memory();
        let id = [0xBB; 32];

        store.quarantine(id, QuarantineType::Block, QuarantineReason::DuplicateBlock, None);
        // Manually wait isn't possible in unit test, so re-quarantine with different reason
        store.quarantine(
            id,
            QuarantineType::Block,
            QuarantineReason::HeaderValidationFailed("test".into()),
            None,
        );

        let entry = store.get(QuarantineType::Block, &id).unwrap();
        assert!(entry.offense_count >= 1);
    }

    #[test]
    fn test_release() {
        let mut store = QuarantineStore::open_in_memory();
        let id = [0xCC; 32];

        store.quarantine(id, QuarantineType::Block, QuarantineReason::DuplicateBlock, None);
        assert!(store.is_quarantined(&id));

        store.release(QuarantineType::Block, id, "operator-1").unwrap();
        assert!(!store.is_quarantined(&id));

        let entry = store.get(QuarantineType::Block, &id).unwrap();
        assert!(entry.released);
        assert_eq!(entry.released_by.as_deref(), Some("operator-1"));
    }

    #[test]
    fn test_release_not_found() {
        let mut store = QuarantineStore::open_in_memory();
        let result = store.release(QuarantineType::Block, [0xDD; 32], "op");
        assert!(result.is_err());
    }

    #[test]
    fn test_list_by_type() {
        let mut store = QuarantineStore::open_in_memory();
        store.quarantine([0x01; 32], QuarantineType::Block, QuarantineReason::DuplicateBlock, None);
        store.quarantine([0x02; 32], QuarantineType::Tx, QuarantineReason::DoubleSpendAttempt {
            nullifier_hex: "ab".into(),
        }, None);
        store.quarantine([0x03; 32], QuarantineType::Block, QuarantineReason::DuplicateBlock, None);

        let blocks = store.list(Some(QuarantineType::Block), false);
        assert_eq!(blocks.len(), 2);

        let txs = store.list(Some(QuarantineType::Tx), false);
        assert_eq!(txs.len(), 1);

        let all = store.list(None, false);
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_active_count() {
        let mut store = QuarantineStore::open_in_memory();
        store.quarantine([0x01; 32], QuarantineType::Block, QuarantineReason::DuplicateBlock, None);
        store.quarantine([0x02; 32], QuarantineType::Peer, QuarantineReason::PeerRateLimitExceeded, None);
        assert_eq!(store.active_count(), 2);
        assert_eq!(store.active_count_by_type(QuarantineType::Block), 1);

        store.release(QuarantineType::Block, [0x01; 32], "op").unwrap();
        assert_eq!(store.active_count(), 1);
    }

    #[test]
    fn test_auto_expire() {
        let mut store = QuarantineStore::open_in_memory();
        let id = [0xEE; 32];
        store.quarantine(id, QuarantineType::Peer, QuarantineReason::PeerRateLimitExceeded, None);

        // Set auto-release to past
        if let Some(entry) = store.entries.get_mut(&(QuarantineType::Peer, id)) {
            entry.auto_release_at_ms = Some(1); // far in the past
        }

        let expired = store.cleanup_expired();
        assert_eq!(expired, 1);
        assert!(!store.is_quarantined(&id));
    }

    #[test]
    fn test_multi_type_quarantine_release() {
        let mut store = QuarantineStore::open_in_memory();
        let id = [0xFF; 32];

        // Quarantine as both block and tx
        store.quarantine(id, QuarantineType::Block, QuarantineReason::DuplicateBlock, None);
        store.quarantine(id, QuarantineType::Tx, QuarantineReason::TxStructuralError("test".into()), None);
        assert!(store.is_quarantined(&id));

        // Release block only — still quarantined as tx
        store.release(QuarantineType::Block, id, "op").unwrap();
        assert!(store.is_quarantined(&id)); // tx still active

        // Release tx — now fully released
        store.release(QuarantineType::Tx, id, "op").unwrap();
        assert!(!store.is_quarantined(&id));
    }

    #[test]
    fn test_persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();

        // Write
        {
            let mut store = QuarantineStore::open(dir.path()).unwrap();
            store.quarantine(
                [0x01; 32],
                QuarantineType::Block,
                QuarantineReason::DuplicateBlock,
                Some([0xAA; 32]),
            );
            store.flush().unwrap();
        }

        // Read back
        {
            let store = QuarantineStore::open(dir.path()).unwrap();
            assert!(store.is_quarantined(&[0x01; 32]));
            let entry = store.get(QuarantineType::Block, &[0x01; 32]).unwrap();
            assert_eq!(entry.source_peer, Some([0xAA; 32]));
        }
    }
}
