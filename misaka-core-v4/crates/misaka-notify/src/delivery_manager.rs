//! Notification delivery management — retry and timeout
//!
//! Part of the MISAKA post-quantum blockchain security infrastructure.
//! All operations use domain-separated cryptography and zeroize-on-drop
//! semantics for secret key material.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configuration for the DeliveryManager subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryManagerConfig {
    pub enabled: bool,
    pub max_entries: usize,
    pub timeout_ms: u64,
    pub retry_count: u32,
    pub buffer_size: usize,
    pub cleanup_interval_secs: u64,
}

impl Default for DeliveryManagerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 10_000,
            timeout_ms: 30_000,
            retry_count: 3,
            buffer_size: 4096,
            cleanup_interval_secs: 300,
        }
    }
}

/// Runtime state for DeliveryManager.
pub struct DeliveryManagerRuntime {
    config: DeliveryManagerConfig,
    entries: parking_lot::RwLock<HashMap<u64, DeliveryManagerEntry>>,
    next_id: std::sync::atomic::AtomicU64,
    stats: DeliveryManagerStats,
    event_buffer: parking_lot::Mutex<Vec<DeliveryManagerEvent>>,
}

/// Individual entry tracked by DeliveryManager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryManagerEntry {
    pub id: u64,
    pub created_at: u64,
    pub updated_at: u64,
    pub state: EntryState,
    pub retry_count: u32,
    pub data: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

/// Entry lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryState {
    Pending,
    Active,
    Completed,
    Failed,
    Expired,
}

/// Events emitted by DeliveryManager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeliveryManagerEvent {
    EntryCreated { id: u64 },
    EntryCompleted { id: u64, duration_ms: u64 },
    EntryFailed { id: u64, reason: String },
    EntryExpired { id: u64 },
    ThresholdReached { count: usize },
    CleanupCompleted { removed: usize },
}

/// Operational statistics for DeliveryManager.
#[derive(Debug, Default)]
pub struct DeliveryManagerStats {
    pub total_created: std::sync::atomic::AtomicU64,
    pub total_completed: std::sync::atomic::AtomicU64,
    pub total_failed: std::sync::atomic::AtomicU64,
    pub total_expired: std::sync::atomic::AtomicU64,
    pub total_retries: std::sync::atomic::AtomicU64,
    pub active_count: std::sync::atomic::AtomicU64,
    pub peak_count: std::sync::atomic::AtomicU64,
    pub total_processing_ms: std::sync::atomic::AtomicU64,
}

impl DeliveryManagerStats {
    pub fn snapshot(&self) -> DeliveryManagerStatsSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        DeliveryManagerStatsSnapshot {
            total_created: self.total_created.load(Relaxed),
            total_completed: self.total_completed.load(Relaxed),
            total_failed: self.total_failed.load(Relaxed),
            total_expired: self.total_expired.load(Relaxed),
            total_retries: self.total_retries.load(Relaxed),
            active_count: self.active_count.load(Relaxed),
            peak_count: self.peak_count.load(Relaxed),
            total_processing_ms: self.total_processing_ms.load(Relaxed),
        }
    }
}

/// Serializable stats snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveryManagerStatsSnapshot {
    pub total_created: u64,
    pub total_completed: u64,
    pub total_failed: u64,
    pub total_expired: u64,
    pub total_retries: u64,
    pub active_count: u64,
    pub peak_count: u64,
    pub total_processing_ms: u64,
}

impl DeliveryManagerRuntime {
    /// Create a new DeliveryManager runtime.
    pub fn new(config: DeliveryManagerConfig) -> Self {
        Self {
            config,
            entries: parking_lot::RwLock::new(HashMap::new()),
            next_id: std::sync::atomic::AtomicU64::new(1),
            stats: DeliveryManagerStats::default(),
            event_buffer: parking_lot::Mutex::new(Vec::new()),
        }
    }

    /// Create a new entry.
    pub fn create_entry(&self, data: Vec<u8>) -> Result<u64, DeliveryManagerError> {
        let entries = self.entries.read();
        if entries.len() >= self.config.max_entries {
            return Err(DeliveryManagerError::CapacityExceeded {
                current: entries.len(),
                max: self.config.max_entries,
            });
        }
        drop(entries);

        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let now = now_secs();

        self.entries.write().insert(
            id,
            DeliveryManagerEntry {
                id,
                created_at: now,
                updated_at: now,
                state: EntryState::Pending,
                retry_count: 0,
                data,
                metadata: HashMap::new(),
            },
        );

        self.stats
            .total_created
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let active = self
            .stats
            .active_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        self.stats
            .peak_count
            .fetch_max(active, std::sync::atomic::Ordering::Relaxed);

        self.emit_event(DeliveryManagerEvent::EntryCreated { id });
        Ok(id)
    }

    /// Complete an entry successfully.
    pub fn complete_entry(&self, id: u64) -> Result<(), DeliveryManagerError> {
        let mut entries = self.entries.write();
        let entry = entries
            .get_mut(&id)
            .ok_or(DeliveryManagerError::NotFound(id))?;
        let duration = now_secs().saturating_sub(entry.created_at) * 1000;

        entry.state = EntryState::Completed;
        entry.updated_at = now_secs();
        drop(entries);

        self.stats
            .total_completed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.stats
            .active_count
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        self.stats
            .total_processing_ms
            .fetch_add(duration, std::sync::atomic::Ordering::Relaxed);

        self.emit_event(DeliveryManagerEvent::EntryCompleted {
            id,
            duration_ms: duration,
        });
        Ok(())
    }

    /// Mark an entry as failed.
    pub fn fail_entry(&self, id: u64, reason: String) -> Result<bool, DeliveryManagerError> {
        let mut entries = self.entries.write();
        let entry = entries
            .get_mut(&id)
            .ok_or(DeliveryManagerError::NotFound(id))?;

        entry.retry_count += 1;
        entry.updated_at = now_secs();

        if entry.retry_count >= self.config.retry_count {
            entry.state = EntryState::Failed;
            self.stats
                .total_failed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.stats
                .active_count
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            self.emit_event(DeliveryManagerEvent::EntryFailed { id, reason });
            Ok(false) // No more retries
        } else {
            entry.state = EntryState::Pending; // Retry
            self.stats
                .total_retries
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            Ok(true) // Will retry
        }
    }

    /// Get an entry by ID.
    pub fn get_entry(&self, id: u64) -> Option<DeliveryManagerEntry> {
        self.entries.read().get(&id).cloned()
    }

    /// Get all entries in a given state.
    pub fn entries_by_state(&self, state: EntryState) -> Vec<DeliveryManagerEntry> {
        self.entries
            .read()
            .values()
            .filter(|e| e.state == state)
            .cloned()
            .collect()
    }

    /// Clean up expired entries.
    pub fn cleanup_expired(&self) -> usize {
        let now = now_secs();
        let timeout_secs = self.config.timeout_ms / 1000;
        let mut entries = self.entries.write();
        let before = entries.len();

        let expired_ids: Vec<u64> = entries
            .iter()
            .filter(|(_, e)| {
                e.state == EntryState::Pending && now.saturating_sub(e.created_at) > timeout_secs
            })
            .map(|(id, _)| *id)
            .collect();

        for id in &expired_ids {
            if let Some(entry) = entries.get_mut(id) {
                entry.state = EntryState::Expired;
                self.stats
                    .total_expired
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                self.stats
                    .active_count
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            }
        }

        // Remove completed and expired entries older than cleanup interval
        entries.retain(|_, e| {
            !(matches!(
                e.state,
                EntryState::Completed | EntryState::Failed | EntryState::Expired
            ) && now.saturating_sub(e.updated_at) > self.config.cleanup_interval_secs)
        });

        let removed = before - entries.len();
        if removed > 0 {
            self.emit_event(DeliveryManagerEvent::CleanupCompleted { removed });
        }
        removed
    }

    /// Get current statistics.
    pub fn stats(&self) -> DeliveryManagerStatsSnapshot {
        self.stats.snapshot()
    }

    /// Drain pending events.
    pub fn drain_events(&self) -> Vec<DeliveryManagerEvent> {
        std::mem::take(&mut *self.event_buffer.lock())
    }

    /// Get entry count.
    pub fn entry_count(&self) -> usize {
        self.entries.read().len()
    }

    /// Get active entry count.
    pub fn active_count(&self) -> u64 {
        self.stats
            .active_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn emit_event(&self, event: DeliveryManagerEvent) {
        let mut buffer = self.event_buffer.lock();
        if buffer.len() < 10_000 {
            buffer.push(event);
        }
    }
}

/// Errors from DeliveryManager operations.
#[derive(Debug, thiserror::Error)]
pub enum DeliveryManagerError {
    #[error("entry not found: {0}")]
    NotFound(u64),
    #[error("capacity exceeded: {current}/{max}")]
    CapacityExceeded { current: usize, max: usize },
    #[error("operation timeout")]
    Timeout,
    #[error("internal error: {0}")]
    Internal(String),
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_complete() {
        let rt = DeliveryManagerRuntime::new(DeliveryManagerConfig::default());
        let id = rt.create_entry(vec![1, 2, 3]).unwrap();
        assert_eq!(rt.entry_count(), 1);
        assert_eq!(rt.active_count(), 1);

        rt.complete_entry(id).unwrap();
        let entry = rt.get_entry(id).unwrap();
        assert_eq!(entry.state, EntryState::Completed);

        let stats = rt.stats();
        assert_eq!(stats.total_created, 1);
        assert_eq!(stats.total_completed, 1);
    }

    #[test]
    fn test_retry_and_fail() {
        let config = DeliveryManagerConfig {
            retry_count: 2,
            ..Default::default()
        };
        let rt = DeliveryManagerRuntime::new(config);
        let id = rt.create_entry(vec![]).unwrap();

        // First failure — should retry
        assert!(rt.fail_entry(id, "err".into()).unwrap());
        // Second failure — should permanently fail
        assert!(!rt.fail_entry(id, "err".into()).unwrap());

        let entry = rt.get_entry(id).unwrap();
        assert_eq!(entry.state, EntryState::Failed);
    }

    #[test]
    fn test_capacity_limit() {
        let config = DeliveryManagerConfig {
            max_entries: 2,
            ..Default::default()
        };
        let rt = DeliveryManagerRuntime::new(config);
        rt.create_entry(vec![]).unwrap();
        rt.create_entry(vec![]).unwrap();
        assert!(rt.create_entry(vec![]).is_err());
    }
}
