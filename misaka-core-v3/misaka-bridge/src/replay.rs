//! Replay protection — nullifier set for bridge requests.
//!
//! ## Production Safety (H1 audit fix)
//!
//! `VolatileReplayProtection` (in-memory HashSet) loses all state on restart.
//! Production MUST use `DurableReplayProtection` which persists to disk.
//!
//! The `ReplayBackend` trait allows pluggable storage backends.

use std::collections::HashSet;
use std::path::Path;

/// Replay protection backend trait.
///
/// Production implementations MUST persist state across restarts.
pub trait ReplayBackend: Send + Sync {
    fn is_used(&self, request_id: &[u8; 32]) -> bool;
    fn mark_used(&mut self, request_id: [u8; 32]) -> Result<(), String>;
    fn len(&self) -> usize;
}

/// In-memory replay protection — for testing only.
///
/// ⚠ ALL STATE IS LOST ON RESTART. Do NOT use in production.
pub struct VolatileReplayProtection {
    used_ids: HashSet<[u8; 32]>,
}

impl VolatileReplayProtection {
    pub fn new() -> Self { Self { used_ids: HashSet::new() } }
}

impl ReplayBackend for VolatileReplayProtection {
    fn is_used(&self, request_id: &[u8; 32]) -> bool {
        self.used_ids.contains(request_id)
    }
    fn mark_used(&mut self, request_id: [u8; 32]) -> Result<(), String> {
        self.used_ids.insert(request_id);
        Ok(())
    }
    fn len(&self) -> usize { self.used_ids.len() }
}

/// File-backed durable replay protection.
///
/// Each used request_id is appended to a flat file as 32 hex bytes + newline.
/// On construction, the file is loaded into memory for fast lookups.
/// On `mark_used`, the new ID is immediately appended (fsync'd).
///
/// This is simple but correct: survives restarts, crash-safe (append-only).
pub struct DurableReplayProtection {
    used_ids: HashSet<[u8; 32]>,
    file_path: std::path::PathBuf,
}

impl DurableReplayProtection {
    /// Load or create the replay protection file.
    pub fn open(path: &Path) -> Result<Self, String> {
        let mut used_ids = HashSet::new();

        if path.exists() {
            let content = std::fs::read_to_string(path)
                .map_err(|e| format!("failed to read replay file: {}", e))?;
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() { continue; }
                if line.len() != 64 {
                    return Err(format!("invalid replay file line (expected 64 hex chars): '{}'", line));
                }
                let bytes = hex::decode(line)
                    .map_err(|e| format!("invalid hex in replay file: {}", e))?;
                let id: [u8; 32] = bytes.try_into()
                    .map_err(|_| "invalid length in replay file".to_string())?;
                used_ids.insert(id);
            }
        }

        Ok(Self { used_ids, file_path: path.to_path_buf() })
    }
}

impl ReplayBackend for DurableReplayProtection {
    fn is_used(&self, request_id: &[u8; 32]) -> bool {
        self.used_ids.contains(request_id)
    }

    fn mark_used(&mut self, request_id: [u8; 32]) -> Result<(), String> {
        if self.used_ids.contains(&request_id) {
            return Ok(()); // idempotent
        }
        // Append to file FIRST (crash-safe: if append fails, state not updated)
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)
            .map_err(|e| format!("failed to open replay file for append: {}", e))?;
        writeln!(file, "{}", hex::encode(request_id))
            .map_err(|e| format!("failed to write to replay file: {}", e))?;
        file.sync_all()
            .map_err(|e| format!("failed to fsync replay file: {}", e))?;

        self.used_ids.insert(request_id);
        Ok(())
    }

    fn len(&self) -> usize { self.used_ids.len() }
}

/// Backward-compatible wrapper.
///
/// Delegates to a boxed `ReplayBackend`. The `BridgeModule` uses this.
pub struct ReplayProtection {
    backend: Box<dyn ReplayBackend>,
}

impl ReplayProtection {
    /// Create volatile (in-memory) replay protection.
    ///
    /// # Safety
    ///
    /// **TEST ONLY.** All state is lost on restart. Production code MUST
    /// use `ReplayProtection::durable()` which persists to disk.
    #[cfg(test)]
    pub fn new_volatile_for_test() -> Self {
        Self { backend: Box::new(VolatileReplayProtection::new()) }
    }

    /// Create durable (file-backed) replay protection. For production.
    pub fn durable(path: &Path) -> Result<Self, String> {
        Ok(Self { backend: Box::new(DurableReplayProtection::open(path)?) })
    }

    pub fn is_used(&self, request_id: &[u8; 32]) -> bool {
        self.backend.is_used(request_id)
    }

    pub fn mark_used(&mut self, request_id: [u8; 32]) -> Result<(), String> {
        self.backend.mark_used(request_id)
    }

    pub fn len(&self) -> usize { self.backend.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_volatile_replay_protection() {
        let mut rp = VolatileReplayProtection::new();
        let id = [0xAA; 32];
        assert!(!rp.is_used(&id));
        rp.mark_used(id).unwrap();
        assert!(rp.is_used(&id));
        assert_eq!(rp.len(), 1);
    }

    #[test]
    fn test_durable_replay_roundtrip() {
        let dir = std::env::temp_dir().join("misaka_replay_test");
        let _ = std::fs::remove_file(&dir);
        {
            let mut rp = DurableReplayProtection::open(&dir).unwrap();
            assert!(!rp.is_used(&[0xBB; 32]));
            rp.mark_used([0xBB; 32]).unwrap();
            rp.mark_used([0xCC; 32]).unwrap();
            assert_eq!(rp.len(), 2);
        }
        // Simulate restart — re-open
        {
            let rp = DurableReplayProtection::open(&dir).unwrap();
            assert!(rp.is_used(&[0xBB; 32]));
            assert!(rp.is_used(&[0xCC; 32]));
            assert!(!rp.is_used(&[0xDD; 32]));
            assert_eq!(rp.len(), 2);
        }
        let _ = std::fs::remove_file(&dir);
    }

    #[test]
    fn test_wrapper_volatile() {
        let mut rp = ReplayProtection::new_volatile_for_test();
        let id = [0xEE; 32];
        assert!(!rp.is_used(&id));
        rp.mark_used(id).unwrap();
        assert!(rp.is_used(&id));
    }
}
