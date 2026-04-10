// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Consensus metrics — Prometheus-style counters and gauges.
//!
//! Sui equivalent: consensus/core/metrics.rs (~400 lines)
//!
//! Provides in-process metrics that can be exposed via the node's
//! `/metrics` endpoint.

use std::sync::atomic::{AtomicU64, Ordering};

/// Consensus metrics.
///
/// All fields are atomic for lock-free access from the runtime.
pub struct ConsensusMetrics {
    // ── Block metrics ──
    /// Total blocks accepted into the DAG.
    pub blocks_accepted: AtomicU64,
    /// Total blocks rejected (invalid author, below eviction, etc).
    pub blocks_rejected: AtomicU64,
    /// Total blocks suspended (waiting for ancestors).
    pub blocks_suspended: AtomicU64,
    /// Total blocks unsuspended.
    pub blocks_unsuspended: AtomicU64,
    /// Total duplicate blocks received.
    pub blocks_duplicate: AtomicU64,
    /// Total equivocations detected.
    pub equivocations_detected: AtomicU64,

    // ── Round metrics ──
    /// Current consensus round.
    pub current_round: AtomicU64,
    /// Highest accepted block round.
    pub highest_accepted_round: AtomicU64,
    /// Total round timeouts.
    pub round_timeouts: AtomicU64,

    // ── Commit metrics ──
    /// Total commits (direct + indirect).
    pub commits_total: AtomicU64,
    /// Direct commits.
    pub commits_direct: AtomicU64,
    /// Indirect commits.
    pub commits_indirect: AtomicU64,
    /// Leaders skipped.
    pub leaders_skipped: AtomicU64,
    /// Total transactions committed.
    pub transactions_committed: AtomicU64,

    // ── Checkpoint metrics ──
    /// Total checkpoints finalized.
    pub checkpoints_finalized: AtomicU64,

    // ── DAG metrics ──
    /// Current number of blocks in memory.
    pub dag_size_blocks: AtomicU64,
    /// Current number of suspended blocks.
    pub dag_suspended_blocks: AtomicU64,
    /// Total blocks evicted by GC.
    pub dag_blocks_evicted: AtomicU64,

    // ── Sync metrics ──
    /// Sync fetches completed.
    pub sync_fetches_completed: AtomicU64,
    /// Sync fetches failed.
    pub sync_fetches_failed: AtomicU64,
    /// Blocks currently inflight (being fetched).
    pub sync_inflight: AtomicU64,

    // ── Persistence metrics ──
    /// WAL writes.
    pub wal_writes: AtomicU64,
    /// WAL write errors.
    pub wal_write_errors: AtomicU64,
    /// Checkpoints (snapshots) created.
    pub store_checkpoints: AtomicU64,

    // ── Proposal metrics ──
    /// Blocks proposed by this node.
    pub blocks_proposed: AtomicU64,
}

impl ConsensusMetrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self {
            blocks_accepted: AtomicU64::new(0),
            blocks_rejected: AtomicU64::new(0),
            blocks_suspended: AtomicU64::new(0),
            blocks_unsuspended: AtomicU64::new(0),
            blocks_duplicate: AtomicU64::new(0),
            equivocations_detected: AtomicU64::new(0),
            current_round: AtomicU64::new(0),
            highest_accepted_round: AtomicU64::new(0),
            round_timeouts: AtomicU64::new(0),
            commits_total: AtomicU64::new(0),
            commits_direct: AtomicU64::new(0),
            commits_indirect: AtomicU64::new(0),
            leaders_skipped: AtomicU64::new(0),
            transactions_committed: AtomicU64::new(0),
            checkpoints_finalized: AtomicU64::new(0),
            dag_size_blocks: AtomicU64::new(0),
            dag_suspended_blocks: AtomicU64::new(0),
            dag_blocks_evicted: AtomicU64::new(0),
            sync_fetches_completed: AtomicU64::new(0),
            sync_fetches_failed: AtomicU64::new(0),
            sync_inflight: AtomicU64::new(0),
            wal_writes: AtomicU64::new(0),
            wal_write_errors: AtomicU64::new(0),
            store_checkpoints: AtomicU64::new(0),
            blocks_proposed: AtomicU64::new(0),
        }
    }

    /// Increment a counter by 1.
    pub fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Set a gauge to a specific value.
    pub fn set(gauge: &AtomicU64, value: u64) {
        gauge.store(value, Ordering::Relaxed);
    }

    /// Get a counter/gauge value.
    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }

    /// Export all metrics as a Prometheus-compatible text format.
    pub fn to_prometheus(&self) -> String {
        let mut out = String::new();
        let metrics = [
            ("misaka_consensus_blocks_accepted", &self.blocks_accepted),
            ("misaka_consensus_blocks_rejected", &self.blocks_rejected),
            ("misaka_consensus_blocks_suspended", &self.blocks_suspended),
            (
                "misaka_consensus_blocks_unsuspended",
                &self.blocks_unsuspended,
            ),
            ("misaka_consensus_blocks_duplicate", &self.blocks_duplicate),
            (
                "misaka_consensus_equivocations",
                &self.equivocations_detected,
            ),
            ("misaka_consensus_current_round", &self.current_round),
            (
                "misaka_consensus_highest_round",
                &self.highest_accepted_round,
            ),
            ("misaka_consensus_round_timeouts", &self.round_timeouts),
            ("misaka_consensus_commits_total", &self.commits_total),
            ("misaka_consensus_commits_direct", &self.commits_direct),
            ("misaka_consensus_commits_indirect", &self.commits_indirect),
            ("misaka_consensus_leaders_skipped", &self.leaders_skipped),
            (
                "misaka_consensus_transactions_committed",
                &self.transactions_committed,
            ),
            (
                "misaka_consensus_checkpoints_finalized",
                &self.checkpoints_finalized,
            ),
            ("misaka_consensus_dag_blocks", &self.dag_size_blocks),
            ("misaka_consensus_dag_suspended", &self.dag_suspended_blocks),
            ("misaka_consensus_dag_evicted", &self.dag_blocks_evicted),
            (
                "misaka_consensus_sync_completed",
                &self.sync_fetches_completed,
            ),
            ("misaka_consensus_sync_failed", &self.sync_fetches_failed),
            ("misaka_consensus_sync_inflight", &self.sync_inflight),
            ("misaka_consensus_wal_writes", &self.wal_writes),
            ("misaka_consensus_wal_errors", &self.wal_write_errors),
            (
                "misaka_consensus_store_checkpoints",
                &self.store_checkpoints,
            ),
            ("misaka_consensus_blocks_proposed", &self.blocks_proposed),
        ];

        for (name, counter) in &metrics {
            out.push_str(&format!("{} {}\n", name, Self::get(counter)));
        }
        out
    }
}

impl Default for ConsensusMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_increment_and_export() {
        let m = ConsensusMetrics::new();
        ConsensusMetrics::inc(&m.blocks_accepted);
        ConsensusMetrics::inc(&m.blocks_accepted);
        ConsensusMetrics::inc(&m.commits_total);
        ConsensusMetrics::set(&m.current_round, 42);

        assert_eq!(ConsensusMetrics::get(&m.blocks_accepted), 2);
        assert_eq!(ConsensusMetrics::get(&m.commits_total), 1);
        assert_eq!(ConsensusMetrics::get(&m.current_round), 42);

        let prom = m.to_prometheus();
        assert!(prom.contains("misaka_consensus_blocks_accepted 2"));
        assert!(prom.contains("misaka_consensus_current_round 42"));
    }
}
