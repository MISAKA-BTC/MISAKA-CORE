//! Mining monitor: background tasks for mempool maintenance.

use crate::mempool::Mempool;
use std::time::Duration;

/// Mempool maintenance task: evict expired transactions, clean orphans.
pub struct MempoolMonitor {
    max_tx_age: Duration,
}

impl MempoolMonitor {
    pub fn new(max_tx_age_secs: u64) -> Self {
        Self {
            max_tx_age: Duration::from_secs(max_tx_age_secs),
        }
    }

    /// Run one maintenance cycle on the mempool.
    pub fn maintain(&self, _mempool: &mut Mempool) -> MaintenanceReport {
        let _now_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expired_count = 0;
        let _max_age = self.max_tx_age.as_secs();

        // Collect expired tx IDs
        let _expired: Vec<[u8; 32]> = Vec::new(); // TODO: collect expired tx IDs

        MaintenanceReport {
            expired_removed: expired_count,
            orphans_evicted: 0,
        }
    }
}

#[derive(Debug)]
pub struct MaintenanceReport {
    pub expired_removed: usize,
    pub orphans_evicted: usize,
}
