//! Atomic counters and metrics aggregation.

use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};

/// Lock-free atomic counter with snapshot support.
#[derive(Debug, Default)]
pub struct AtomicCounter {
    value: AtomicU64,
}

impl AtomicCounter {
    pub const fn new(initial: u64) -> Self {
        Self {
            value: AtomicU64::new(initial),
        }
    }
    pub fn increment(&self) -> u64 {
        self.value.fetch_add(1, Ordering::Relaxed)
    }
    pub fn add(&self, n: u64) -> u64 {
        self.value.fetch_add(n, Ordering::Relaxed)
    }
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
    pub fn set(&self, val: u64) {
        self.value.store(val, Ordering::Relaxed);
    }
    pub fn reset(&self) -> u64 {
        self.value.swap(0, Ordering::Relaxed)
    }
}

/// Signed atomic gauge (can go up and down).
#[derive(Debug, Default)]
pub struct AtomicGauge {
    value: AtomicI64,
}

impl AtomicGauge {
    pub const fn new(initial: i64) -> Self {
        Self {
            value: AtomicI64::new(initial),
        }
    }
    pub fn increment(&self) -> i64 {
        self.value.fetch_add(1, Ordering::Relaxed)
    }
    pub fn decrement(&self) -> i64 {
        self.value.fetch_sub(1, Ordering::Relaxed)
    }
    pub fn add(&self, n: i64) -> i64 {
        self.value.fetch_add(n, Ordering::Relaxed)
    }
    pub fn get(&self) -> i64 {
        self.value.load(Ordering::Relaxed)
    }
    pub fn set(&self, val: i64) {
        self.value.store(val, Ordering::Relaxed);
    }
}

/// Snapshot of a set of counters for reporting.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CounterSnapshot {
    pub name: String,
    pub values: Vec<(String, u64)>,
    pub timestamp_ms: u64,
}

/// Collection of named counters for subsystem metrics.
pub struct CounterSet {
    name: String,
    counters: Vec<(String, AtomicCounter)>,
}

impl CounterSet {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            counters: Vec::new(),
        }
    }

    pub fn register(&mut self, counter_name: impl Into<String>) -> usize {
        let idx = self.counters.len();
        self.counters
            .push((counter_name.into(), AtomicCounter::new(0)));
        idx
    }

    pub fn increment(&self, idx: usize) {
        if let Some((_, counter)) = self.counters.get(idx) {
            counter.increment();
        }
    }

    pub fn add(&self, idx: usize, n: u64) {
        if let Some((_, counter)) = self.counters.get(idx) {
            counter.add(n);
        }
    }

    pub fn snapshot(&self) -> CounterSnapshot {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        CounterSnapshot {
            name: self.name.clone(),
            values: self
                .counters
                .iter()
                .map(|(n, c)| (n.clone(), c.get()))
                .collect(),
            timestamp_ms: now,
        }
    }
}

/// P2P bandwidth counter pair.
#[derive(Debug, Default)]
pub struct BandwidthCounters {
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub messages_sent: AtomicU64,
    pub messages_received: AtomicU64,
}

impl BandwidthCounters {
    pub fn record_send(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_receive(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
        self.messages_received.fetch_add(1, Ordering::Relaxed);
    }
}

/// Mining counters (Kaspa-compatible).
#[derive(Debug, Default)]
pub struct MiningCounters {
    pub blocks_submitted: AtomicU64,
    pub block_tx_counts: AtomicU64,
    pub tx_accepted: AtomicU64,
    pub tx_rejected: AtomicU64,
    pub orphans_added: AtomicU64,
    pub orphans_evicted: AtomicU64,
}

/// High-water-mark tracker.
#[derive(Debug)]
pub struct HighWaterMark {
    current: AtomicUsize,
    high: AtomicUsize,
}

impl HighWaterMark {
    pub fn new() -> Self {
        Self {
            current: AtomicUsize::new(0),
            high: AtomicUsize::new(0),
        }
    }
    pub fn update(&self, val: usize) {
        self.current.store(val, Ordering::Relaxed);
        self.high.fetch_max(val, Ordering::Relaxed);
    }
    pub fn current(&self) -> usize {
        self.current.load(Ordering::Relaxed)
    }
    pub fn high(&self) -> usize {
        self.high.load(Ordering::Relaxed)
    }
}

impl Default for HighWaterMark {
    fn default() -> Self {
        Self::new()
    }
}
