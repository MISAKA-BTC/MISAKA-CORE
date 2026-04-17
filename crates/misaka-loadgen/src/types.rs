// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

/// Load generation configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoadgenConfig {
    pub target_endpoints: Vec<String>,
    pub workload: Workload,
    pub duration_secs: u64,
    pub concurrency: usize,
    pub rate_limit_tps: Option<u64>,
    pub seed: u64,
    pub warmup_secs: u64,
    pub tx_count: Option<u64>,
}

impl Default for LoadgenConfig {
    fn default() -> Self {
        Self {
            target_endpoints: vec!["http://localhost:8080".into()],
            workload: Workload::SimpleTransfer {
                senders: 10,
                value_per_tx: 1,
            },
            duration_secs: 60,
            concurrency: 16,
            rate_limit_tps: None,
            seed: 42,
            warmup_secs: 5,
            tx_count: None,
        }
    }
}

/// Workload type.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Workload {
    SimpleTransfer { senders: usize, value_per_tx: u64 },
    Stress { tx_size_bytes: usize },
}

/// Latency histogram (percentile summary).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct LatencyHistogram {
    pub p50_ms: u64,
    pub p90_ms: u64,
    pub p99_ms: u64,
    pub p999_ms: u64,
    pub max_ms: u64,
    pub count: u64,
    pub samples: Vec<u64>,
}

impl LatencyHistogram {
    pub fn from_samples(mut samples: Vec<u64>) -> Self {
        if samples.is_empty() {
            return Self::default();
        }
        samples.sort_unstable();
        let n = samples.len();
        Self {
            p50_ms: samples[n / 2],
            p90_ms: samples[n * 90 / 100],
            p99_ms: samples[n * 99 / 100],
            p999_ms: samples[(n * 999 / 1000).min(n - 1)],
            max_ms: samples[n - 1],
            count: n as u64,
            samples,
        }
    }
}

/// ML-DSA-65 signature cost breakdown.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SignatureCostReport {
    pub avg_sign_us: u64,
    pub avg_sig_bytes: usize,
    pub bandwidth_share_pct: f64,
}

/// Full load generation report.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LoadgenReport {
    pub config: LoadgenConfig,
    pub started_at_epoch_ms: u64,
    pub elapsed_ms: u64,
    pub txs_submitted: u64,
    pub txs_accepted: u64,
    pub txs_rejected: u64,
    pub txs_timed_out: u64,
    pub submit_tps: f64,
    pub submit_latency: LatencyHistogram,
    pub signature_overhead: SignatureCostReport,
    pub bandwidth_used_bytes: u64,
    pub failures_by_reason: HashMap<String, u64>,
}

impl LoadgenReport {
    pub fn summary(&self) -> String {
        format!(
            "=== MISAKA LoadGen Report ===\n\
             Duration:     {:.1}s\n\
             Submitted:    {} txs\n\
             Accepted:     {} ({:.1}%)\n\
             Rejected:     {}\n\
             Timed out:    {}\n\
             Submit TPS:   {:.1}\n\
             Latency p50:  {}ms  p90: {}ms  p99: {}ms\n\
             Sig avg:      {}us  ({} bytes, {:.1}% bandwidth)\n\
             Bandwidth:    {:.1} KB\n\
             ============================",
            self.elapsed_ms as f64 / 1000.0,
            self.txs_submitted,
            self.txs_accepted,
            if self.txs_submitted > 0 {
                self.txs_accepted as f64 / self.txs_submitted as f64 * 100.0
            } else {
                0.0
            },
            self.txs_rejected,
            self.txs_timed_out,
            self.submit_tps,
            self.submit_latency.p50_ms,
            self.submit_latency.p90_ms,
            self.submit_latency.p99_ms,
            self.signature_overhead.avg_sign_us,
            self.signature_overhead.avg_sig_bytes,
            self.signature_overhead.bandwidth_share_pct,
            self.bandwidth_used_bytes as f64 / 1024.0,
        )
    }
}
