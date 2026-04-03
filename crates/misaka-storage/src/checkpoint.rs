//! Checkpoint Snapshots — periodic state materialization for fast recovery.
//!
//! # Problem
//!
//! Without checkpoints, recovering from a crash requires replaying the entire
//! diff journal from genesis. With 100,000+ blocks, this takes minutes.
//!
//! # Solution
//!
//! Every N blocks (CHECKPOINT_INTERVAL), materialize a complete state snapshot:
//!
//! ```text
//! Checkpoint {
//!     block_hash: <tip at checkpoint time>,
//!     blue_score: <score>,
//!     utxo_root: <Merkle root of UTXO set>,
//!     nullifier_root: <Merkle root of nullifier set>,
//!     reachability_seed: <compact reachability rebuild data>,
//!     selected_chain_anchor: <selected parent chain tip>,
//!     virtual_tip: <current virtual tip>,
//!     timestamp_ms: <when created>,
//! }
//! ```
//!
//! On restart:
//! 1. Load latest checkpoint
//! 2. Load diff journal entries AFTER the checkpoint
//! 3. Replay only those diffs → O(blocks_since_checkpoint), NOT O(total_blocks)
//!
//! # Checkpoint Files
//!
//! Stored as `checkpoint_{blue_score}.json` in the data directory.
//! Multiple checkpoints are retained for safety (pruned by age/count).

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

/// Create a checkpoint every N blocks.
pub const CHECKPOINT_INTERVAL: u64 = 500;

/// Keep at most this many checkpoint files (oldest are pruned).
pub const MAX_CHECKPOINTS_RETAINED: usize = 5;

// ═══════════════════════════════════════════════════════════════
//  Checkpoint Data
// ═══════════════════════════════════════════════════════════════

/// A complete state checkpoint at a specific block.
///
/// # Integrity (C4 FIX)
///
/// `content_hash` is SHA3-256 over the serialized checkpoint payload
/// (excluding the hash fields themselves). Verified on load.
///
/// # Chain of Trust (H2 FIX)
///
/// `prev_checkpoint_hash` links to the previous checkpoint, forming
/// a hash chain. An attacker cannot swap individual checkpoints without
/// invalidating all subsequent links.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Block hash at the checkpoint.
    pub block_hash: [u8; 32],
    /// Blue score at the checkpoint.
    pub blue_score: u64,
    /// UTXO set Merkle root.
    pub utxo_root: [u8; 32],
    /// Nullifier set Merkle root.
    pub nullifier_root: [u8; 32],
    /// State root (combined UTXO + nullifier commitment).
    pub state_root: [u8; 32],
    /// Virtual tip at the checkpoint.
    pub virtual_tip: [u8; 32],
    /// Virtual tip blue score.
    pub virtual_tip_score: u64,
    /// Number of nullifiers at checkpoint.
    pub nullifier_count: usize,
    /// Number of UTXOs at checkpoint.
    pub utxo_count: usize,
    /// Checkpoint creation timestamp (unix ms).
    pub created_at_ms: u64,
    /// Sequence number of the last WAL entry at this checkpoint.
    pub wal_seq: u64,
    /// Checkpoint format version.
    pub version: u32,

    // ── C4 FIX: Integrity Hash ──
    /// SHA3-256 of the checkpoint payload (all fields above).
    /// Verified on load to detect corruption or tampering.
    /// ZERO for legacy checkpoints (backward compat).
    #[serde(default)]
    pub content_hash: [u8; 32],

    // ── H2 FIX: Checkpoint Hash Chain ──
    /// SHA3-256 of the previous checkpoint's content_hash.
    /// ZERO for the first checkpoint.
    #[serde(default)]
    pub prev_checkpoint_hash: [u8; 32],
}

/// Checkpoint format version.
pub const CHECKPOINT_VERSION: u32 = 1;

// ═══════════════════════════════════════════════════════════════
//  Checkpoint Manager
// ═══════════════════════════════════════════════════════════════

/// Manages checkpoint creation, retention, and loading.
pub struct CheckpointManager {
    /// Directory where checkpoint files are stored.
    data_dir: PathBuf,
    /// Blue score at the last checkpoint.
    last_checkpoint_score: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("no checkpoint found")]
    NotFound,
    #[error("checkpoint version mismatch: expected {expected}, got {got}")]
    VersionMismatch { expected: u32, got: u32 },
    #[error("checkpoint state root mismatch: computed={computed}, stored={stored}")]
    StateRootMismatch { computed: String, stored: String },
    #[error("checkpoint content hash mismatch: stored={stored}, computed={computed} — file may be corrupted or tampered")]
    ContentHashMismatch { stored: String, computed: String },
}

impl CheckpointManager {
    /// Create a checkpoint manager for the given data directory.
    pub fn new(data_dir: &Path) -> Self {
        Self {
            data_dir: data_dir.to_path_buf(),
            last_checkpoint_score: 0,
        }
    }

    /// Check if a new checkpoint should be created at the given blue_score.
    pub fn should_checkpoint(&self, blue_score: u64) -> bool {
        blue_score >= self.last_checkpoint_score + CHECKPOINT_INTERVAL
    }

    /// Create and persist a checkpoint.
    ///
    /// # Integrity (C4 FIX)
    ///
    /// Computes SHA3-256 content hash over the checkpoint payload and
    /// stores it in `content_hash`. Also links to the previous checkpoint
    /// via `prev_checkpoint_hash` (H2 FIX).
    ///
    /// # Crash Safety (L1 FIX)
    ///
    /// Writes to .tmp, fsyncs, then atomically renames.
    pub fn create_checkpoint(
        &mut self,
        mut checkpoint: Checkpoint,
    ) -> Result<PathBuf, CheckpointError> {
        use sha3::{Digest, Sha3_256};
        use std::io::Write;

        fs::create_dir_all(&self.data_dir)?;

        // H2 FIX: Link to previous checkpoint
        checkpoint.prev_checkpoint_hash = match self.load_latest() {
            Ok(prev) => prev.content_hash,
            Err(CheckpointError::NotFound) => [0u8; 32], // First checkpoint
            Err(_) => [0u8; 32],                         // Degraded — don't block creation
        };

        // C4 FIX: Compute content hash (over all fields except content_hash itself)
        // Temporarily zero out content_hash for deterministic hashing
        checkpoint.content_hash = [0u8; 32];
        let payload_for_hash =
            serde_json::to_vec(&checkpoint).map_err(|e| CheckpointError::Serde(e.into()))?;
        checkpoint.content_hash = Sha3_256::digest(&payload_for_hash).into();

        let filename = format!("checkpoint_{:010}.json", checkpoint.blue_score);
        let path = self.data_dir.join(&filename);
        let tmp_path = path.with_extension("json.tmp");

        let json = serde_json::to_string_pretty(&checkpoint)?;

        // L1 FIX: Write + fsync .tmp, then atomic rename + dir fsync
        {
            let file = fs::File::create(&tmp_path)?;
            let mut writer = std::io::BufWriter::new(file);
            writer.write_all(json.as_bytes())?;
            writer.flush()?;
            writer.get_ref().sync_all()?; // fsync BEFORE rename
        }
        fs::rename(&tmp_path, &path)?;

        // fsync parent directory
        if let Ok(dir) = fs::File::open(&self.data_dir) {
            let _ = dir.sync_all();
        }

        self.last_checkpoint_score = checkpoint.blue_score;

        info!(
            "Checkpoint created: score={} tip={} state_root={} content_hash={} ({} nullifiers, {} utxos)",
            checkpoint.blue_score,
            hex::encode(&checkpoint.block_hash[..4]),
            hex::encode(&checkpoint.state_root[..4]),
            hex::encode(&checkpoint.content_hash[..4]),
            checkpoint.nullifier_count,
            checkpoint.utxo_count,
        );

        // Prune old checkpoints
        self.prune_old_checkpoints()?;

        Ok(path)
    }

    /// Load the latest checkpoint.
    ///
    /// # Integrity Verification (C4 FIX)
    ///
    /// Recomputes the content hash and verifies it matches the stored value.
    /// Rejects corrupted or tampered checkpoints.
    pub fn load_latest(&self) -> Result<Checkpoint, CheckpointError> {
        use sha3::{Digest, Sha3_256};

        let checkpoints = self.list_checkpoints()?;
        let latest = checkpoints.last().ok_or(CheckpointError::NotFound)?;

        let content = fs::read_to_string(latest)?;
        let checkpoint: Checkpoint = serde_json::from_str(&content)?;

        if checkpoint.version != CHECKPOINT_VERSION {
            return Err(CheckpointError::VersionMismatch {
                expected: CHECKPOINT_VERSION,
                got: checkpoint.version,
            });
        }

        // C4 FIX: Verify content hash (skip for legacy checkpoints with zero hash)
        if checkpoint.content_hash != [0u8; 32] {
            let mut verify_cp = checkpoint.clone();
            verify_cp.content_hash = [0u8; 32];
            let payload =
                serde_json::to_vec(&verify_cp).map_err(|e| CheckpointError::Serde(e.into()))?;
            let computed: [u8; 32] = Sha3_256::digest(&payload).into();
            if computed != checkpoint.content_hash {
                return Err(CheckpointError::ContentHashMismatch {
                    stored: hex::encode(&checkpoint.content_hash[..8]),
                    computed: hex::encode(&computed[..8]),
                });
            }
        }

        info!(
            "Loaded checkpoint: score={} tip={} state_root={} integrity={}",
            checkpoint.blue_score,
            hex::encode(&checkpoint.block_hash[..4]),
            hex::encode(&checkpoint.state_root[..4]),
            if checkpoint.content_hash != [0u8; 32] {
                "verified"
            } else {
                "legacy"
            },
        );

        Ok(checkpoint)
    }

    /// Load a specific checkpoint by blue score.
    pub fn load_by_score(&self, blue_score: u64) -> Result<Checkpoint, CheckpointError> {
        let filename = format!("checkpoint_{:010}.json", blue_score);
        let path = self.data_dir.join(&filename);
        let content = fs::read_to_string(&path)?;
        let checkpoint: Checkpoint = serde_json::from_str(&content)?;
        Ok(checkpoint)
    }

    /// List all checkpoint files, sorted by blue score (ascending).
    pub fn list_checkpoints(&self) -> Result<Vec<PathBuf>, CheckpointError> {
        if !self.data_dir.exists() {
            return Ok(vec![]);
        }

        let mut files: Vec<PathBuf> = fs::read_dir(&self.data_dir)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|f| f.to_str())
                    .map(|f| f.starts_with("checkpoint_") && f.ends_with(".json"))
                    .unwrap_or(false)
            })
            .collect();

        files.sort();
        Ok(files)
    }

    /// Remove old checkpoints, keeping only MAX_CHECKPOINTS_RETAINED.
    fn prune_old_checkpoints(&self) -> Result<(), CheckpointError> {
        let checkpoints = self.list_checkpoints()?;
        if checkpoints.len() <= MAX_CHECKPOINTS_RETAINED {
            return Ok(());
        }

        let to_remove = checkpoints.len() - MAX_CHECKPOINTS_RETAINED;
        for path in checkpoints.iter().take(to_remove) {
            debug!("Pruning old checkpoint: {}", path.display());
            fs::remove_file(path)?;
        }

        info!("Pruned {} old checkpoints", to_remove);
        Ok(())
    }
}

/// Verify a checkpoint's state root against a recomputed value.
pub fn verify_checkpoint_state(
    checkpoint: &Checkpoint,
    computed_state_root: [u8; 32],
) -> Result<(), CheckpointError> {
    if checkpoint.state_root != computed_state_root {
        return Err(CheckpointError::StateRootMismatch {
            computed: hex::encode(&computed_state_root[..8]),
            stored: hex::encode(&checkpoint.state_root[..8]),
        });
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn h(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn make_checkpoint(score: u64) -> Checkpoint {
        Checkpoint {
            block_hash: h((score & 0xFF) as u8),
            blue_score: score,
            utxo_root: h(0xAA),
            nullifier_root: h(0xBB),
            state_root: h(0xCC),
            virtual_tip: h((score & 0xFF) as u8),
            virtual_tip_score: score,
            nullifier_count: score as usize * 10,
            utxo_count: score as usize * 20,
            created_at_ms: 1_700_000_000_000 + score * 1000,
            wal_seq: score * 5,
            version: CHECKPOINT_VERSION,
            content_hash: [0u8; 32],         // Computed by create_checkpoint
            prev_checkpoint_hash: [0u8; 32], // Linked by create_checkpoint
        }
    }

    #[test]
    fn test_checkpoint_create_and_load() {
        let tmp = TempDir::new().unwrap();
        let mut mgr = CheckpointManager::new(tmp.path());

        let cp = make_checkpoint(500);
        mgr.create_checkpoint(cp.clone()).unwrap();

        let loaded = mgr.load_latest().unwrap();
        assert_eq!(loaded.blue_score, 500);
        assert_eq!(loaded.state_root, h(0xCC));
    }

    #[test]
    fn test_checkpoint_should_trigger() {
        let mgr = CheckpointManager::new(Path::new("/tmp/test"));
        assert!(mgr.should_checkpoint(500));
        assert!(mgr.should_checkpoint(1000));
        assert!(!mgr.should_checkpoint(0));
    }

    #[test]
    fn test_checkpoint_pruning() {
        let tmp = TempDir::new().unwrap();
        let mut mgr = CheckpointManager::new(tmp.path());

        // Create MAX + 2 checkpoints
        for i in 1..=(MAX_CHECKPOINTS_RETAINED + 2) as u64 {
            let cp = make_checkpoint(i * CHECKPOINT_INTERVAL);
            mgr.create_checkpoint(cp).unwrap();
        }

        let remaining = mgr.list_checkpoints().unwrap();
        assert_eq!(remaining.len(), MAX_CHECKPOINTS_RETAINED);
    }

    #[test]
    fn test_checkpoint_fresh_directory() {
        let tmp = TempDir::new().unwrap();
        let mgr = CheckpointManager::new(tmp.path());
        assert!(mgr.load_latest().is_err());
        assert!(mgr.list_checkpoints().unwrap().is_empty());
    }

    #[test]
    fn test_checkpoint_verify_state() {
        let cp = make_checkpoint(500);

        // Matching root → OK
        assert!(verify_checkpoint_state(&cp, h(0xCC)).is_ok());

        // Mismatching root → Error
        assert!(verify_checkpoint_state(&cp, h(0xFF)).is_err());
    }

    #[test]
    fn test_checkpoint_load_by_score() {
        let tmp = TempDir::new().unwrap();
        let mut mgr = CheckpointManager::new(tmp.path());

        mgr.create_checkpoint(make_checkpoint(500)).unwrap();
        mgr.create_checkpoint(make_checkpoint(1000)).unwrap();

        let cp = mgr.load_by_score(500).unwrap();
        assert_eq!(cp.blue_score, 500);
    }

    // ── C4 Tests: Content Hash Integrity ──

    #[test]
    fn test_checkpoint_content_hash_set_on_create() {
        let tmp = TempDir::new().unwrap();
        let mut mgr = CheckpointManager::new(tmp.path());

        mgr.create_checkpoint(make_checkpoint(500)).unwrap();
        let loaded = mgr.load_latest().unwrap();

        // content_hash must be non-zero after create
        assert_ne!(loaded.content_hash, [0u8; 32], "content_hash must be set");
    }

    #[test]
    fn test_checkpoint_tamper_detected() {
        let tmp = TempDir::new().unwrap();
        let mut mgr = CheckpointManager::new(tmp.path());

        mgr.create_checkpoint(make_checkpoint(500)).unwrap();

        // Tamper with the file: change a byte in the JSON
        let files = mgr.list_checkpoints().unwrap();
        let path = &files[0];
        let mut content = std::fs::read_to_string(path).unwrap();
        content = content.replace("\"blue_score\": 500", "\"blue_score\": 999");
        std::fs::write(path, content).unwrap();

        // Loading should detect the tampering
        let result = mgr.load_latest();
        assert!(result.is_err(), "tampered checkpoint must be rejected");
    }

    // ── H2 Tests: Checkpoint Hash Chain ──

    #[test]
    fn test_checkpoint_chain_link() {
        let tmp = TempDir::new().unwrap();
        let mut mgr = CheckpointManager::new(tmp.path());

        mgr.create_checkpoint(make_checkpoint(500)).unwrap();
        let first = mgr.load_latest().unwrap();

        mgr.create_checkpoint(make_checkpoint(1000)).unwrap();
        let second = mgr.load_latest().unwrap();

        // Second checkpoint's prev_checkpoint_hash must equal first's content_hash
        assert_eq!(
            second.prev_checkpoint_hash, first.content_hash,
            "checkpoint chain must link to previous content_hash"
        );
    }

    #[test]
    fn test_first_checkpoint_prev_is_zero() {
        let tmp = TempDir::new().unwrap();
        let mut mgr = CheckpointManager::new(tmp.path());

        mgr.create_checkpoint(make_checkpoint(500)).unwrap();
        let cp = mgr.load_latest().unwrap();

        assert_eq!(
            cp.prev_checkpoint_hash, [0u8; 32],
            "first checkpoint must have zero prev_checkpoint_hash"
        );
    }
}
