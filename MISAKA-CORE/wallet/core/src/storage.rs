//! Wallet Storage — atomic writes, checksum validation, schema versioning.
//!
//! # Format
//!
//! The wallet file is a JSON document with an envelope:
//!
//! ```json
//! {
//!   "magic": "MISAKA_WALLET",
//!   "version": 2,
//!   "checksum": "sha256hex...",
//!   "payload": { ... wallet state ... }
//! }
//! ```
//!
//! # Integrity
//!
//! - `checksum` = SHA3-256 of the canonical JSON serialization of `payload`.
//! - On load, the checksum is recomputed and compared.
//! - If mismatch → file is corrupt → load from `.bak` backup.
//!
//! # Migration
//!
//! Each version bump has a migration function `vN_to_vN+1` that transforms
//! the payload JSON. Migrations are applied sequentially on load.
//!
//! # Atomic Writes
//!
//! Write to `.tmp` → fsync → rename to target. This prevents partial writes
//! on crash, because `rename()` is atomic on POSIX filesystems.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::path::{Path, PathBuf};

/// Current storage schema version.
pub const CURRENT_VERSION: u32 = 2;

/// Magic string for file identification.
const MAGIC: &str = "MISAKA_WALLET";

/// Storage envelope wrapping the wallet payload.
#[derive(Debug, Serialize, Deserialize)]
pub struct StorageEnvelope {
    /// Magic identifier.
    pub magic: String,
    /// Schema version.
    pub version: u32,
    /// SHA3-256 hex digest of the canonical `payload` JSON.
    pub checksum: String,
    /// The actual wallet state (version-dependent schema).
    pub payload: serde_json::Value,
}

/// Errors from storage operations.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid magic: expected '{expected}', got '{got}'")]
    InvalidMagic { expected: String, got: String },
    #[error("checksum mismatch: expected {expected}, computed {computed}")]
    ChecksumMismatch { expected: String, computed: String },
    #[error("unsupported version: {version} (max supported: {max})")]
    UnsupportedVersion { version: u32, max: u32 },
    #[error("migration failed: v{from} → v{to}: {reason}")]
    MigrationFailed { from: u32, to: u32, reason: String },
    #[error("backup also corrupt: {0}")]
    BackupCorrupt(String),
    #[error("no valid wallet file found at {0}")]
    NotFound(String),
}

// ═══════════════════════════════════════════════════════════════
//  Checksum
// ═══════════════════════════════════════════════════════════════

/// Compute SHA3-256 checksum of a JSON value (canonical serialization).
///
/// Uses recursive BTreeMap sorting to ensure deterministic key ordering.
/// This eliminates the serde_json HashMap key-order dependency.
fn compute_checksum(payload: &serde_json::Value) -> String {
    let canonical = canonicalize_json(payload);
    let canonical_str = serde_json::to_string(&canonical).unwrap_or_default();
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:wallet:checksum:v1:");
    h.update(canonical_str.as_bytes());
    let hash: [u8; 32] = h.finalize().into();
    hex::encode(hash)
}

/// Recursively canonicalize a JSON value by sorting all object keys.
///
/// This produces a deterministic JSON structure regardless of the
/// original HashMap iteration order, making the checksum stable
/// across serializer implementations and Rust versions.
fn canonicalize_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            // Convert to BTreeMap for sorted key order
            let sorted: std::collections::BTreeMap<String, serde_json::Value> = map
                .iter()
                .map(|(k, v)| (k.clone(), canonicalize_json(v)))
                .collect();
            serde_json::Value::Object(sorted.into_iter().collect())
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(canonicalize_json).collect())
        }
        other => other.clone(),
    }
}

/// Verify the checksum of a storage envelope.
fn verify_checksum(envelope: &StorageEnvelope) -> Result<(), StorageError> {
    let computed = compute_checksum(&envelope.payload);
    if computed != envelope.checksum {
        return Err(StorageError::ChecksumMismatch {
            expected: envelope.checksum.clone(),
            computed,
        });
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  Atomic File Operations
// ═══════════════════════════════════════════════════════════════

/// Write data atomically: write to .tmp → file fsync → rename → dir fsync.
///
/// The dir fsync ensures the rename is durable even if the OS crashes
/// immediately after rename() returns. Without it, the directory entry
/// may not be persisted on some filesystems (ext4 with default mount).
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), StorageError> {
    let tmp_path = path.with_extension("json.tmp");

    std::fs::write(&tmp_path, data)?;

    // File fsync — ensure data hits disk
    if let Ok(file) = std::fs::File::open(&tmp_path) {
        let _ = file.sync_all();
    }

    std::fs::rename(&tmp_path, path)?;

    // Dir fsync — ensure the rename (directory entry) is durable
    dir_fsync(path);

    Ok(())
}

/// Fsync the parent directory to ensure rename durability.
#[cfg(unix)]
fn dir_fsync(file_path: &Path) {
    if let Some(parent) = file_path.parent() {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

#[cfg(not(unix))]
fn dir_fsync(_file_path: &Path) {
    // Dir fsync is a Unix concept; on Windows, rename is already durable.
}

/// Backup path for a wallet file.
fn backup_path(path: &Path) -> PathBuf {
    path.with_extension("bak.json")
}

// ═══════════════════════════════════════════════════════════════
//  Migration Framework
// ═══════════════════════════════════════════════════════════════

/// Apply all necessary migrations to bring a payload from `from_version`
/// to `CURRENT_VERSION`.
fn migrate(
    mut payload: serde_json::Value,
    from_version: u32,
) -> Result<serde_json::Value, StorageError> {
    let mut v = from_version;

    while v < CURRENT_VERSION {
        payload = match v {
            1 => migrate_v1_to_v2(payload)?,
            _ => {
                return Err(StorageError::UnsupportedVersion {
                    version: v,
                    max: CURRENT_VERSION,
                })
            }
        };
        v += 1;
    }

    Ok(payload)
}

/// Migration: v1 → v2
///
/// Changes:
/// - Add `tx_tracker` field (empty tracker).
/// - Add `coin_selection_strategy` field (default: "largest_first").
/// - Rename `balance` → `cached_balance` for clarity.
fn migrate_v1_to_v2(mut payload: serde_json::Value) -> Result<serde_json::Value, StorageError> {
    // Add tx_tracker if missing
    if payload.get("tx_tracker").is_none() {
        payload["tx_tracker"] = serde_json::json!({
            "transactions": {},
            "utxo_locks": {},
            "lock_timeout_ms": 600000
        });
    }

    // Add coin_selection_strategy if missing
    if payload.get("coin_selection_strategy").is_none() {
        payload["coin_selection_strategy"] = serde_json::json!("largest_first");
    }

    // Rename balance → cached_balance (keep both for backward compat)
    if let Some(balance) = payload.get("balance").cloned() {
        payload["cached_balance"] = balance;
    }

    Ok(payload)
}

// ═══════════════════════════════════════════════════════════════
//  Public API
// ═══════════════════════════════════════════════════════════════

/// Save a wallet payload to disk with checksum and atomic write.
pub fn save_wallet(path: &Path, payload: &serde_json::Value) -> Result<(), StorageError> {
    let checksum = compute_checksum(payload);

    let envelope = StorageEnvelope {
        magic: MAGIC.to_string(),
        version: CURRENT_VERSION,
        checksum,
        payload: payload.clone(),
    };

    let json = serde_json::to_string_pretty(&envelope)?;

    // Backup existing file
    if path.exists() {
        let backup = backup_path(path);
        let _ = std::fs::copy(path, &backup);
    }

    atomic_write(path, json.as_bytes())?;

    Ok(())
}

/// Load a wallet payload from disk, verifying checksum and applying migrations.
///
/// If the primary file is corrupt, attempts to load from the backup.
pub fn load_wallet(path: &Path) -> Result<serde_json::Value, StorageError> {
    // Try primary file
    match load_wallet_inner(path) {
        Ok(payload) => return Ok(payload),
        Err(StorageError::ChecksumMismatch { .. }) | Err(StorageError::Json(_)) => {
            // Primary corrupt → try backup
            let backup = backup_path(path);
            if backup.exists() {
                match load_wallet_inner(&backup) {
                    Ok(payload) => {
                        // Backup is valid — restore it as primary
                        let json = std::fs::read(&backup)?;
                        atomic_write(path, &json)?;
                        return Ok(payload);
                    }
                    Err(e) => {
                        return Err(StorageError::BackupCorrupt(e.to_string()));
                    }
                }
            }
            return Err(StorageError::BackupCorrupt(
                "primary corrupt and no backup found".into(),
            ));
        }
        Err(StorageError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(StorageError::NotFound(path.display().to_string()));
        }
        Err(e) => return Err(e),
    }
}

/// Inner load logic (no backup fallback).
fn load_wallet_inner(path: &Path) -> Result<serde_json::Value, StorageError> {
    let json = std::fs::read_to_string(path)?;
    let envelope: StorageEnvelope = serde_json::from_str(&json)?;

    // Verify magic
    if envelope.magic != MAGIC {
        return Err(StorageError::InvalidMagic {
            expected: MAGIC.to_string(),
            got: envelope.magic,
        });
    }

    // Verify checksum
    verify_checksum(&envelope)?;

    // Version check
    if envelope.version > CURRENT_VERSION {
        return Err(StorageError::UnsupportedVersion {
            version: envelope.version,
            max: CURRENT_VERSION,
        });
    }

    // Apply migrations if needed
    let payload = if envelope.version < CURRENT_VERSION {
        migrate(envelope.payload, envelope.version)?
    } else {
        envelope.payload
    };

    Ok(payload)
}

/// Check if a wallet file exists and is valid (without loading the full payload).
pub fn probe_wallet(path: &Path) -> Result<u32, StorageError> {
    let json = std::fs::read_to_string(path)?;
    let envelope: StorageEnvelope = serde_json::from_str(&json)?;

    if envelope.magic != MAGIC {
        return Err(StorageError::InvalidMagic {
            expected: MAGIC.to_string(),
            got: envelope.magic,
        });
    }

    verify_checksum(&envelope)?;
    Ok(envelope.version)
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn test_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "misaka_storage_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("test: create dir");
        dir
    }

    fn sample_payload() -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "wallet_name": "test",
            "master_address": "msk1abc123",
            "balance": 1000,
            "utxos": []
        })
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = test_dir();
        let path = dir.join("wallet.json");
        let payload = sample_payload();

        save_wallet(&path, &payload).expect("save");
        let loaded = load_wallet(&path).expect("load");

        assert_eq!(loaded["wallet_name"], "test");
        assert_eq!(loaded["master_address"], "msk1abc123");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_checksum_detects_corruption() {
        let dir = test_dir();
        let path = dir.join("wallet.json");
        let payload = sample_payload();

        save_wallet(&path, &payload).expect("save");

        // Corrupt the file
        let mut json = fs::read_to_string(&path).expect("read");
        json = json.replace("msk1abc123", "msk1HACKED");
        fs::write(&path, &json).expect("write corrupt");

        let result = load_wallet(&path);
        assert!(matches!(
            result,
            Err(StorageError::ChecksumMismatch { .. }) | Err(StorageError::BackupCorrupt(_))
        ));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_backup_recovery() {
        let dir = test_dir();
        let path = dir.join("wallet.json");
        let payload = sample_payload();

        // Save twice to create backup
        save_wallet(&path, &payload).expect("save1");
        save_wallet(&path, &payload).expect("save2");

        // Corrupt primary
        fs::write(&path, "garbage data").expect("corrupt");

        // Load should recover from backup
        let loaded = load_wallet(&path).expect("load from backup");
        assert_eq!(loaded["wallet_name"], "test");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_migration_v1_to_v2() {
        let dir = test_dir();
        let path = dir.join("wallet.json");

        // Create a v1 envelope manually
        let payload = sample_payload();
        let checksum = compute_checksum(&payload);
        let envelope = StorageEnvelope {
            magic: MAGIC.to_string(),
            version: 1,
            checksum,
            payload,
        };
        let json = serde_json::to_string_pretty(&envelope).expect("serialize");
        fs::write(&path, &json).expect("write v1");

        // Load should auto-migrate to v2
        let loaded = load_wallet(&path).expect("load with migration");

        // v2 additions should be present
        assert!(loaded.get("tx_tracker").is_some());
        assert!(loaded.get("coin_selection_strategy").is_some());
        assert_eq!(loaded["coin_selection_strategy"], "largest_first");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_future_version_rejected() {
        let dir = test_dir();
        let path = dir.join("wallet.json");

        let payload = sample_payload();
        let checksum = compute_checksum(&payload);
        let envelope = StorageEnvelope {
            magic: MAGIC.to_string(),
            version: 999,
            checksum,
            payload,
        };
        let json = serde_json::to_string_pretty(&envelope).expect("serialize");
        fs::write(&path, &json).expect("write future");

        let result = load_wallet(&path);
        assert!(matches!(
            result,
            Err(StorageError::UnsupportedVersion { .. })
        ));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_invalid_magic_rejected() {
        let dir = test_dir();
        let path = dir.join("wallet.json");

        let envelope = serde_json::json!({
            "magic": "NOT_MISAKA",
            "version": 1,
            "checksum": "deadbeef",
            "payload": {}
        });
        fs::write(&path, serde_json::to_string(&envelope).expect("ser")).expect("write");

        let result = load_wallet(&path);
        assert!(matches!(result, Err(StorageError::InvalidMagic { .. })));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_probe_wallet() {
        let dir = test_dir();
        let path = dir.join("wallet.json");
        let payload = sample_payload();

        save_wallet(&path, &payload).expect("save");

        let version = probe_wallet(&path).expect("probe");
        assert_eq!(version, CURRENT_VERSION);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_not_found_error() {
        let result = load_wallet(Path::new("/nonexistent/wallet.json"));
        assert!(matches!(
            result,
            Err(StorageError::NotFound(_)) | Err(StorageError::Io(_))
        ));
    }

    #[test]
    fn test_checksum_deterministic() {
        let payload = sample_payload();
        let c1 = compute_checksum(&payload);
        let c2 = compute_checksum(&payload);
        assert_eq!(c1, c2, "checksum must be deterministic");
    }

    #[test]
    fn test_checksum_changes_with_data() {
        let p1 = serde_json::json!({"a": 1});
        let p2 = serde_json::json!({"a": 2});
        assert_ne!(
            compute_checksum(&p1),
            compute_checksum(&p2),
            "different data must produce different checksum"
        );
    }
}
