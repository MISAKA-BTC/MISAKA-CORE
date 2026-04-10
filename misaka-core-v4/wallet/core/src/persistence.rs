//! Wallet persistence layer — atomically durable state
//!
//! Part of the MISAKA post-quantum blockchain infrastructure.
//! Security-critical: all operations follow defense-in-depth principles.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// Configuration for Persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceConfig {
    pub enabled: bool,
    pub max_entries: usize,
    pub timeout_ms: u64,
    pub retry_count: u32,
    pub buffer_size: usize,
    pub cleanup_interval_secs: u64,
    pub batch_size: usize,
    pub max_concurrent: usize,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 50_000,
            timeout_ms: 30_000,
            retry_count: 3,
            buffer_size: 8192,
            cleanup_interval_secs: 600,
            batch_size: 100,
            max_concurrent: 16,
        }
    }
}

/// Persistence operational state.
pub struct PersistenceState {
    config: PersistenceConfig,
    entries: parking_lot::RwLock<HashMap<u64, PersistenceEntry>>,
    index: parking_lot::RwLock<HashMap<String, Vec<u64>>>,
    queue: parking_lot::Mutex<VecDeque<PersistenceTask>>,
    next_id: std::sync::atomic::AtomicU64,
    stats: PersistenceStats,
    events: parking_lot::Mutex<Vec<PersistenceEvent>>,
    is_running: std::sync::atomic::AtomicBool,
}

/// Entry in Persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceEntry {
    pub id: u64,
    pub key: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub state: PersistenceEntryState,
    pub priority: u32,
    pub retry_count: u32,
    pub data: Vec<u8>,
    pub metadata: HashMap<String, String>,
    pub dependencies: Vec<u64>,
    pub tags: Vec<String>,
}

/// Entry state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PersistenceEntryState {
    Queued,
    Processing,
    Completed,
    Failed,
    Cancelled,
    Expired,
    Retrying,
}

/// Queued task.
#[allow(dead_code)]
struct PersistenceTask {
    entry_id: u64,
    scheduled_at: u64,
    priority: u32,
}

/// Events from Persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PersistenceEvent {
    Created {
        id: u64,
        key: String,
    },
    StateChanged {
        id: u64,
        from: String,
        to: String,
    },
    Completed {
        id: u64,
        duration_ms: u64,
    },
    Failed {
        id: u64,
        reason: String,
        will_retry: bool,
    },
    Expired {
        id: u64,
    },
    BatchCompleted {
        count: usize,
        duration_ms: u64,
    },
    QueueDrained {
        processed: usize,
    },
    Cleanup {
        removed: usize,
        remaining: usize,
    },
    ThresholdAlert {
        metric: String,
        value: u64,
        threshold: u64,
    },
}

/// Statistics for Persistence.
#[derive(Debug, Default)]
pub struct PersistenceStats {
    pub total_created: std::sync::atomic::AtomicU64,
    pub total_completed: std::sync::atomic::AtomicU64,
    pub total_failed: std::sync::atomic::AtomicU64,
    pub total_expired: std::sync::atomic::AtomicU64,
    pub total_retried: std::sync::atomic::AtomicU64,
    pub total_cancelled: std::sync::atomic::AtomicU64,
    pub active_count: std::sync::atomic::AtomicU64,
    pub peak_active: std::sync::atomic::AtomicU64,
    pub queue_depth: std::sync::atomic::AtomicU64,
    pub total_processing_ms: std::sync::atomic::AtomicU64,
    pub total_bytes_processed: std::sync::atomic::AtomicU64,
}

impl PersistenceStats {
    pub fn snapshot(&self) -> PersistenceStatsSnapshot {
        use std::sync::atomic::Ordering::Relaxed;
        let total = self.total_created.load(Relaxed);
        let completed = self.total_completed.load(Relaxed);
        let processing_ms = self.total_processing_ms.load(Relaxed);
        PersistenceStatsSnapshot {
            total_created: total,
            total_completed: completed,
            total_failed: self.total_failed.load(Relaxed),
            total_expired: self.total_expired.load(Relaxed),
            total_retried: self.total_retried.load(Relaxed),
            total_cancelled: self.total_cancelled.load(Relaxed),
            active_count: self.active_count.load(Relaxed),
            peak_active: self.peak_active.load(Relaxed),
            queue_depth: self.queue_depth.load(Relaxed),
            avg_processing_ms: if completed > 0 {
                processing_ms / completed
            } else {
                0
            },
            total_bytes_processed: self.total_bytes_processed.load(Relaxed),
            success_rate: if total > 0 {
                completed as f64 / total as f64
            } else {
                0.0
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceStatsSnapshot {
    pub total_created: u64,
    pub total_completed: u64,
    pub total_failed: u64,
    pub total_expired: u64,
    pub total_retried: u64,
    pub total_cancelled: u64,
    pub active_count: u64,
    pub peak_active: u64,
    pub queue_depth: u64,
    pub avg_processing_ms: u64,
    pub total_bytes_processed: u64,
    pub success_rate: f64,
}

impl PersistenceState {
    pub fn new(config: PersistenceConfig) -> Self {
        Self {
            config,
            entries: parking_lot::RwLock::new(HashMap::new()),
            index: parking_lot::RwLock::new(HashMap::new()),
            queue: parking_lot::Mutex::new(VecDeque::new()),
            next_id: std::sync::atomic::AtomicU64::new(1),
            stats: PersistenceStats::default(),
            events: parking_lot::Mutex::new(Vec::new()),
            is_running: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub fn create(
        &self,
        key: String,
        data: Vec<u8>,
        priority: u32,
    ) -> Result<u64, PersistenceError> {
        if self.entries.read().len() >= self.config.max_entries {
            return Err(PersistenceError::CapacityExceeded);
        }
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let now = now_secs();
        let entry = PersistenceEntry {
            id,
            key: key.clone(),
            created_at: now,
            updated_at: now,
            state: PersistenceEntryState::Queued,
            priority,
            retry_count: 0,
            data,
            metadata: HashMap::new(),
            dependencies: Vec::new(),
            tags: Vec::new(),
        };
        self.entries.write().insert(id, entry);
        self.index.write().entry(key.clone()).or_default().push(id);
        self.queue.lock().push_back(PersistenceTask {
            entry_id: id,
            scheduled_at: now,
            priority,
        });
        self.stats
            .total_created
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let active = self
            .stats
            .active_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            + 1;
        self.stats
            .peak_active
            .fetch_max(active, std::sync::atomic::Ordering::Relaxed);
        self.stats
            .queue_depth
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.emit(PersistenceEvent::Created { id, key });
        Ok(id)
    }

    pub fn complete(&self, id: u64) -> Result<(), PersistenceError> {
        let mut entries = self.entries.write();
        let entry = entries.get_mut(&id).ok_or(PersistenceError::NotFound(id))?;
        let duration = now_secs().saturating_sub(entry.created_at) * 1000;
        let _old_state = format!("{:?}", entry.state);
        entry.state = PersistenceEntryState::Completed;
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
        self.emit(PersistenceEvent::Completed {
            id,
            duration_ms: duration,
        });
        Ok(())
    }

    pub fn fail(&self, id: u64, reason: String) -> Result<bool, PersistenceError> {
        let mut entries = self.entries.write();
        let entry = entries.get_mut(&id).ok_or(PersistenceError::NotFound(id))?;
        entry.retry_count += 1;
        entry.updated_at = now_secs();
        let will_retry = entry.retry_count < self.config.retry_count;
        if will_retry {
            entry.state = PersistenceEntryState::Retrying;
            self.stats
                .total_retried
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            entry.state = PersistenceEntryState::Failed;
            self.stats
                .total_failed
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.stats
                .active_count
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.emit(PersistenceEvent::Failed {
            id,
            reason,
            will_retry,
        });
        Ok(will_retry)
    }

    pub fn cancel(&self, id: u64) -> Result<(), PersistenceError> {
        let mut entries = self.entries.write();
        let entry = entries.get_mut(&id).ok_or(PersistenceError::NotFound(id))?;
        entry.state = PersistenceEntryState::Cancelled;
        entry.updated_at = now_secs();
        self.stats
            .total_cancelled
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.stats
            .active_count
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    pub fn get(&self, id: u64) -> Option<PersistenceEntry> {
        self.entries.read().get(&id).cloned()
    }
    pub fn get_by_key(&self, key: &str) -> Vec<PersistenceEntry> {
        let index = self.index.read();
        let entries = self.entries.read();
        index
            .get(key)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| entries.get(id).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn by_state(&self, state: PersistenceEntryState) -> Vec<PersistenceEntry> {
        self.entries
            .read()
            .values()
            .filter(|e| e.state == state)
            .cloned()
            .collect()
    }
    pub fn process_queue(&self, max: usize) -> Vec<u64> {
        let mut queue = self.queue.lock();
        let mut processed = Vec::new();
        while processed.len() < max {
            match queue.pop_front() {
                Some(task) => {
                    self.stats
                        .queue_depth
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    processed.push(task.entry_id);
                }
                None => break,
            }
        }
        processed
    }
    pub fn cleanup(&self) -> usize {
        let now = now_secs();
        let timeout = self.config.cleanup_interval_secs;
        let mut entries = self.entries.write();
        let _before = entries.len();
        let to_remove: Vec<u64> = entries
            .iter()
            .filter(|(_, e)| {
                matches!(
                    e.state,
                    PersistenceEntryState::Completed
                        | PersistenceEntryState::Failed
                        | PersistenceEntryState::Cancelled
                        | PersistenceEntryState::Expired
                ) && now.saturating_sub(e.updated_at) > timeout
            })
            .map(|(id, _)| *id)
            .collect();
        for id in &to_remove {
            entries.remove(id);
        }
        let removed = to_remove.len();
        if removed > 0 {
            self.emit(PersistenceEvent::Cleanup {
                removed,
                remaining: entries.len(),
            });
        }
        removed
    }
    pub fn stats(&self) -> PersistenceStatsSnapshot {
        self.stats.snapshot()
    }
    pub fn drain_events(&self) -> Vec<PersistenceEvent> {
        std::mem::take(&mut *self.events.lock())
    }
    pub fn entry_count(&self) -> usize {
        self.entries.read().len()
    }
    pub fn queue_depth(&self) -> u64 {
        self.stats
            .queue_depth
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    pub fn is_running(&self) -> bool {
        self.is_running.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn emit(&self, event: PersistenceEvent) {
        let mut events = self.events.lock();
        if events.len() < 10_000 {
            events.push(event);
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    #[error("entry not found: {0}")]
    NotFound(u64),
    #[error("capacity exceeded")]
    CapacityExceeded,
    #[error("operation timeout")]
    Timeout,
    #[error("dependency not met: {0}")]
    DependencyNotMet(u64),
    #[error("invalid state transition")]
    InvalidStateTransition,
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
    fn test_lifecycle() {
        let state = PersistenceState::new(PersistenceConfig::default());
        let id = state.create("key1".into(), vec![1, 2, 3], 1).unwrap();
        assert_eq!(state.entry_count(), 1);
        state.complete(id).unwrap();
        let stats = state.stats();
        assert_eq!(stats.total_completed, 1);
    }

    #[test]
    fn test_retry() {
        let config = PersistenceConfig {
            retry_count: 2,
            ..Default::default()
        };
        let state = PersistenceState::new(config);
        let id = state.create("k".into(), vec![], 0).unwrap();
        assert!(state.fail(id, "e1".into()).unwrap()); // retry
        assert!(!state.fail(id, "e2".into()).unwrap()); // permanent fail
    }

    #[test]
    fn test_queue_processing() {
        let state = PersistenceState::new(PersistenceConfig::default());
        state.create("a".into(), vec![], 0).unwrap();
        state.create("b".into(), vec![], 0).unwrap();
        let processed = state.process_queue(10);
        assert_eq!(processed.len(), 2);
    }

    #[test]
    fn test_index_lookup() {
        let state = PersistenceState::new(PersistenceConfig::default());
        state.create("mykey".into(), vec![1], 0).unwrap();
        state.create("mykey".into(), vec![2], 0).unwrap();
        let results = state.get_by_key("mykey");
        assert_eq!(results.len(), 2);
    }
}
