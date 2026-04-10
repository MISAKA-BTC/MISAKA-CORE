// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Production metrics — Prometheus-compatible export.
//!
//! Wraps `ConsensusMetrics` (atomic counters) with proper Prometheus
//! text format export, including HELP and TYPE annotations.
//!
//! ## Usage
//!
//! ```text
//! GET /metrics → PrometheusExporter::export()
//! ```

use super::metrics::ConsensusMetrics;
use std::sync::Arc;

/// Prometheus text format exporter.
pub struct PrometheusExporter {
    metrics: Arc<ConsensusMetrics>,
    /// Optional labels to add to all metrics.
    labels: Vec<(String, String)>,
}

impl PrometheusExporter {
    pub fn new(metrics: Arc<ConsensusMetrics>) -> Self {
        Self {
            metrics,
            labels: Vec::new(),
        }
    }

    /// Add a label to all metrics (e.g., authority="0", epoch="5").
    pub fn with_label(mut self, key: &str, value: &str) -> Self {
        self.labels.push((key.to_string(), value.to_string()));
        self
    }

    /// Format label string for Prometheus (empty string if no labels).
    fn label_str(&self) -> String {
        if self.labels.is_empty() {
            String::new()
        } else {
            let pairs: Vec<String> = self
                .labels
                .iter()
                .map(|(k, v)| format!("{}=\"{}\"", k, v))
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
    }

    /// Export all metrics in Prometheus text format.
    pub fn export(&self) -> String {
        let m = &self.metrics;
        let l = self.label_str();

        let mut out = String::with_capacity(4096);

        // Block metrics
        Self::write_counter(
            &mut out,
            "misaka_consensus_blocks_accepted_total",
            "Total blocks accepted into the DAG",
            &l,
            ConsensusMetrics::get(&m.blocks_accepted),
        );
        Self::write_counter(
            &mut out,
            "misaka_consensus_blocks_rejected_total",
            "Total blocks rejected",
            &l,
            ConsensusMetrics::get(&m.blocks_rejected),
        );
        Self::write_counter(
            &mut out,
            "misaka_consensus_blocks_suspended_total",
            "Total blocks suspended waiting for ancestors",
            &l,
            ConsensusMetrics::get(&m.blocks_suspended),
        );
        Self::write_counter(
            &mut out,
            "misaka_consensus_blocks_unsuspended_total",
            "Total blocks unsuspended after ancestors arrived",
            &l,
            ConsensusMetrics::get(&m.blocks_unsuspended),
        );
        Self::write_counter(
            &mut out,
            "misaka_consensus_blocks_duplicate_total",
            "Total duplicate blocks received",
            &l,
            ConsensusMetrics::get(&m.blocks_duplicate),
        );
        Self::write_counter(
            &mut out,
            "misaka_consensus_equivocations_total",
            "Total equivocations detected",
            &l,
            ConsensusMetrics::get(&m.equivocations_detected),
        );
        Self::write_counter(
            &mut out,
            "misaka_consensus_blocks_proposed_total",
            "Total blocks proposed by this node",
            &l,
            ConsensusMetrics::get(&m.blocks_proposed),
        );

        // Round metrics
        Self::write_gauge(
            &mut out,
            "misaka_consensus_current_round",
            "Current consensus round",
            &l,
            ConsensusMetrics::get(&m.current_round),
        );
        Self::write_gauge(
            &mut out,
            "misaka_consensus_highest_accepted_round",
            "Highest accepted block round",
            &l,
            ConsensusMetrics::get(&m.highest_accepted_round),
        );
        Self::write_counter(
            &mut out,
            "misaka_consensus_round_timeouts_total",
            "Total round timeouts",
            &l,
            ConsensusMetrics::get(&m.round_timeouts),
        );

        // Commit metrics
        Self::write_counter(
            &mut out,
            "misaka_consensus_commits_total",
            "Total commits (direct + indirect)",
            &l,
            ConsensusMetrics::get(&m.commits_total),
        );
        Self::write_counter(
            &mut out,
            "misaka_consensus_commits_direct_total",
            "Total direct commits",
            &l,
            ConsensusMetrics::get(&m.commits_direct),
        );
        Self::write_counter(
            &mut out,
            "misaka_consensus_commits_indirect_total",
            "Total indirect commits",
            &l,
            ConsensusMetrics::get(&m.commits_indirect),
        );
        Self::write_counter(
            &mut out,
            "misaka_consensus_leaders_skipped_total",
            "Total leaders skipped",
            &l,
            ConsensusMetrics::get(&m.leaders_skipped),
        );
        Self::write_counter(
            &mut out,
            "misaka_consensus_transactions_committed_total",
            "Total transactions committed",
            &l,
            ConsensusMetrics::get(&m.transactions_committed),
        );

        // Checkpoint metrics
        Self::write_counter(
            &mut out,
            "misaka_consensus_checkpoints_finalized_total",
            "Total checkpoints finalized",
            &l,
            ConsensusMetrics::get(&m.checkpoints_finalized),
        );

        // DAG metrics
        Self::write_gauge(
            &mut out,
            "misaka_consensus_dag_blocks",
            "Current number of blocks in memory",
            &l,
            ConsensusMetrics::get(&m.dag_size_blocks),
        );
        Self::write_gauge(
            &mut out,
            "misaka_consensus_dag_suspended_blocks",
            "Current number of suspended blocks",
            &l,
            ConsensusMetrics::get(&m.dag_suspended_blocks),
        );
        Self::write_counter(
            &mut out,
            "misaka_consensus_dag_blocks_evicted_total",
            "Total blocks evicted by GC",
            &l,
            ConsensusMetrics::get(&m.dag_blocks_evicted),
        );

        // Sync metrics
        Self::write_counter(
            &mut out,
            "misaka_consensus_sync_completed_total",
            "Total sync fetches completed",
            &l,
            ConsensusMetrics::get(&m.sync_fetches_completed),
        );
        Self::write_counter(
            &mut out,
            "misaka_consensus_sync_failed_total",
            "Total sync fetches failed",
            &l,
            ConsensusMetrics::get(&m.sync_fetches_failed),
        );
        Self::write_gauge(
            &mut out,
            "misaka_consensus_sync_inflight",
            "Blocks currently being fetched",
            &l,
            ConsensusMetrics::get(&m.sync_inflight),
        );

        // WAL metrics
        Self::write_counter(
            &mut out,
            "misaka_consensus_wal_writes_total",
            "Total WAL writes",
            &l,
            ConsensusMetrics::get(&m.wal_writes),
        );
        Self::write_counter(
            &mut out,
            "misaka_consensus_wal_errors_total",
            "Total WAL write errors",
            &l,
            ConsensusMetrics::get(&m.wal_write_errors),
        );
        Self::write_counter(
            &mut out,
            "misaka_consensus_store_checkpoints_total",
            "Total store checkpoints created",
            &l,
            ConsensusMetrics::get(&m.store_checkpoints),
        );

        out
    }

    fn write_counter(out: &mut String, name: &str, help: &str, labels: &str, value: u64) {
        out.push_str(&format!("# HELP {} {}\n", name, help));
        out.push_str(&format!("# TYPE {} counter\n", name));
        out.push_str(&format!("{}{} {}\n", name, labels, value));
    }

    fn write_gauge(out: &mut String, name: &str, help: &str, labels: &str, value: u64) {
        out.push_str(&format!("# HELP {} {}\n", name, help));
        out.push_str(&format!("# TYPE {} gauge\n", name));
        out.push_str(&format!("{}{} {}\n", name, labels, value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prometheus_export_format() {
        let metrics = Arc::new(ConsensusMetrics::new());
        ConsensusMetrics::inc(&metrics.blocks_accepted);
        ConsensusMetrics::inc(&metrics.blocks_accepted);
        ConsensusMetrics::set(&metrics.current_round, 42);
        ConsensusMetrics::inc(&metrics.commits_total);

        let exporter = PrometheusExporter::new(metrics)
            .with_label("authority", "0")
            .with_label("epoch", "5");

        let output = exporter.export();

        // Check HELP/TYPE annotations
        assert!(output.contains("# HELP misaka_consensus_blocks_accepted_total"));
        assert!(output.contains("# TYPE misaka_consensus_blocks_accepted_total counter"));
        assert!(output
            .contains("misaka_consensus_blocks_accepted_total{authority=\"0\",epoch=\"5\"} 2"));
        assert!(output.contains("# TYPE misaka_consensus_current_round gauge"));
        assert!(output.contains("misaka_consensus_current_round{authority=\"0\",epoch=\"5\"} 42"));
        assert!(output.contains("misaka_consensus_commits_total{authority=\"0\",epoch=\"5\"} 1"));
    }

    #[test]
    fn test_prometheus_no_labels() {
        let metrics = Arc::new(ConsensusMetrics::new());
        let exporter = PrometheusExporter::new(metrics);
        let output = exporter.export();
        assert!(output.contains("misaka_consensus_blocks_accepted_total 0"));
    }
}
