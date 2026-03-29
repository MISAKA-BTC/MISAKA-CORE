//! Data models for the mining subsystem.

pub mod candidate_tx;
pub mod frontier;
pub mod owner_txs;
pub mod topological_sort;
pub mod tx_insert;
pub mod tx_query;

use std::sync::atomic::{AtomicU64, Ordering};

/// Counters for mining operations.
#[derive(Debug, Default)]
pub struct MiningCounters {
    pub blocks_submitted: AtomicU64,
    pub block_tx_counts: AtomicU64,
    pub tx_accepted_count: AtomicU64,
    pub tx_rejected_count: AtomicU64,
    pub orphans_count: AtomicU64,
    pub orphans_evicted: AtomicU64,
    pub rbf_replacements: AtomicU64,
    pub template_builds: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
}

impl MiningCounters {
    pub fn snapshot(&self) -> MiningCountersSnapshot {
        MiningCountersSnapshot {
            blocks_submitted: self.blocks_submitted.load(Ordering::Relaxed),
            block_tx_counts: self.block_tx_counts.load(Ordering::Relaxed),
            tx_accepted_count: self.tx_accepted_count.load(Ordering::Relaxed),
            tx_rejected_count: self.tx_rejected_count.load(Ordering::Relaxed),
            orphans_count: self.orphans_count.load(Ordering::Relaxed),
            orphans_evicted: self.orphans_evicted.load(Ordering::Relaxed),
            rbf_replacements: self.rbf_replacements.load(Ordering::Relaxed),
            template_builds: self.template_builds.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MiningCountersSnapshot {
    pub blocks_submitted: u64,
    pub block_tx_counts: u64,
    pub tx_accepted_count: u64,
    pub tx_rejected_count: u64,
    pub orphans_count: u64,
    pub orphans_evicted: u64,
    pub rbf_replacements: u64,
    pub template_builds: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}
