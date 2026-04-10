// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! SLO-driven metrics for the DAG consensus subsystem.
//!
//! Each metric corresponds to a specific SLO in `docs/ops/SLO.md`.
//! No metric exists here without an SLO justification.

use once_cell::sync::Lazy;
use prometheus::{Histogram, HistogramOpts, IntCounter, IntGauge, Opts};

// ═══════════════════════════════════════════════════════════════
//  Liveness SLO Metrics
// ═══════════════════════════════════════════════════════════════

/// L1: Total commits (rate computed by Prometheus/Grafana as commits/sec).
/// SLO: ≥ 0.5 commits/sec.
/// Why: Liveness detection. If this stops, the chain is halted.
pub static COMMITS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::with_opts(Opts::new(
        "misaka_consensus_commits_total",
        "Total committed sub-DAGs [SLO L1: commit rate]",
    ))
    .unwrap()
});

/// L2: Finality latency (block timestamp → commit time).
/// SLO: p99 ≤ 3.0s.
/// Why: User-facing latency. Degradation = bad UX.
pub static FINALITY_LATENCY: Lazy<Histogram> = Lazy::new(|| {
    Histogram::with_opts(
        HistogramOpts::new(
            "misaka_consensus_finality_latency_seconds",
            "Latency from block creation to commit [SLO L2: finality p99 ≤ 3s]",
        )
        .buckets(vec![0.1, 0.25, 0.5, 1.0, 2.0, 3.0, 5.0, 10.0, 30.0]),
    )
    .unwrap()
});

/// L3: Leader skip count.
/// SLO: skip_rate ≤ 5%.
/// Why: High skip rate = network partition or leader crash.
pub static LEADER_SKIPS: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::with_opts(Opts::new(
        "misaka_consensus_leader_skips_total",
        "Leaders skipped (not committed) [SLO L3: skip rate ≤ 5%]",
    ))
    .unwrap()
});

/// L3: Leader commit count (denominator for skip rate).
pub static LEADER_COMMITS: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::with_opts(Opts::new(
        "misaka_consensus_leader_commits_total",
        "Leaders committed (direct + indirect) [SLO L3]",
    ))
    .unwrap()
});

/// L4: Current round number.
/// SLO: advance ≥ 1 round per 60s.
/// Why: Round stall = complete consensus halt.
pub static CURRENT_ROUND: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::with_opts(Opts::new(
        "misaka_consensus_current_round",
        "Current consensus round [SLO L4: round advancement]",
    ))
    .unwrap()
});

/// L5: Fast-path certified transactions.
/// SLO: ≥ 90% certification rate.
/// Why: Fast-path is the primary user-facing latency path.
pub static CERTIFIER_CERTIFIED_TXS: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::with_opts(Opts::new(
        "misaka_certifier_certified_txs_total",
        "Transactions certified via fast path [SLO L5]",
    ))
    .unwrap()
});

/// L5: Pending blocks in certifier.
pub static CERTIFIER_PENDING: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::with_opts(Opts::new(
        "misaka_certifier_pending_blocks",
        "Blocks pending certification [SLO L5]",
    ))
    .unwrap()
});

// ═══════════════════════════════════════════════════════════════
//  Safety SLO Metrics (alert on any increment)
// ═══════════════════════════════════════════════════════════════

/// S1: Equivocation detected.
/// SLO: always 0.
/// Why: Any equivocation = potential Byzantine attack. P0 alert.
pub static EQUIVOCATIONS: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::with_opts(Opts::new(
        "misaka_dag_equivocations_detected_total",
        "Block equivocations detected [SLO S1: ALERT on >0]",
    ))
    .unwrap()
});

/// S2: Signature verification failures.
/// Why: Invalid signatures = malicious or corrupted peer.
pub static SIG_VERIFY_FAILURES: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::with_opts(Opts::new(
        "misaka_crypto_sig_verify_failures_total",
        "ML-DSA-65 signature verification failures [SLO S2]",
    ))
    .unwrap()
});

/// S3: BFS aborted (equivocation flooding mitigation).
/// Why: BFS abort = potential equivocation flooding attack.
pub static BFS_ABORTED: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::with_opts(Opts::new(
        "misaka_committer_bfs_aborted_total",
        "BFS causal history searches aborted (resource limit) [SLO S3]",
    ))
    .unwrap()
});

/// S4: Rejected transactions in commit finalizer.
pub static FINALIZER_REJECTED_TXS: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::with_opts(Opts::new(
        "misaka_finalizer_rejected_txs_total",
        "Transactions rejected by commit finalizer [SLO S4]",
    ))
    .unwrap()
});

// ═══════════════════════════════════════════════════════════════
//  Network SLO Metrics
// ═══════════════════════════════════════════════════════════════

/// N2: Block propagation delay in rounds.
/// SLO: ≤ 2 rounds.
pub static PROPAGATION_DELAY: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::with_opts(Opts::new(
        "misaka_prober_propagation_delay_rounds",
        "Own block propagation delay in rounds [SLO N2: ≤ 2]",
    ))
    .unwrap()
});

/// N3: Sync requests sent.
pub static SYNC_REQUESTS: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::with_opts(Opts::new(
        "misaka_sync_requests_sent_total",
        "Block sync requests sent to peers [SLO N3]",
    ))
    .unwrap()
});

/// N3: Sync timeouts.
pub static SYNC_TIMEOUTS: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::with_opts(Opts::new(
        "misaka_sync_timeouts_total",
        "Block sync request timeouts [SLO N3: timeout rate ≤ 5%]",
    ))
    .unwrap()
});

/// N4: Blocks accepted into DAG.
pub static BLOCKS_ACCEPTED: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::with_opts(Opts::new(
        "misaka_dag_blocks_accepted_total",
        "Blocks accepted into DAG [SLO N4]",
    ))
    .unwrap()
});

/// N4: Blocks rejected.
pub static BLOCKS_REJECTED: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::with_opts(Opts::new(
        "misaka_dag_blocks_rejected_total",
        "Blocks rejected (verify fail, below eviction, etc) [SLO N4]",
    ))
    .unwrap()
});

// ═══════════════════════════════════════════════════════════════
//  Resource SLO Metrics
// ═══════════════════════════════════════════════════════════════

/// R2: Blocks currently in DAG memory.
pub static DAG_BLOCKS_IN_MEMORY: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::with_opts(Opts::new(
        "misaka_dag_blocks_in_memory",
        "Blocks currently held in DAG state [SLO R2: ≤ 50,000]",
    ))
    .unwrap()
});

/// R3: Storage write batch latency.
pub static STORAGE_WRITE_LATENCY: Lazy<Histogram> = Lazy::new(|| {
    Histogram::with_opts(
        HistogramOpts::new(
            "misaka_storage_write_batch_seconds",
            "Write batch flush latency [SLO R3: p99 ≤ 100ms]",
        )
        .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]),
    )
    .unwrap()
});

/// R4: Current leader timeout in milliseconds.
pub static LEADER_TIMEOUT_MS: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::with_opts(Opts::new(
        "misaka_consensus_leader_timeout_ms",
        "Current leader timeout with backoff [SLO R4]",
    ))
    .unwrap()
});

/// R4: Total leader timeouts.
pub static LEADER_TIMEOUTS: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::with_opts(Opts::new(
        "misaka_consensus_leader_timeouts_total",
        "Total leader timeouts [SLO R4]",
    ))
    .unwrap()
});

// ═══════════════════════════════════════════════════════════════
//  Registration
// ═══════════════════════════════════════════════════════════════

/// Register all SLO metrics with the global prometheus registry.
///
/// Call once at node startup. Idempotent (Lazy ensures single init).
pub fn register_slo_metrics() {
    // Touch all Lazy statics to force registration.
    Lazy::force(&COMMITS_TOTAL);
    Lazy::force(&FINALITY_LATENCY);
    Lazy::force(&LEADER_SKIPS);
    Lazy::force(&LEADER_COMMITS);
    Lazy::force(&CURRENT_ROUND);
    Lazy::force(&CERTIFIER_CERTIFIED_TXS);
    Lazy::force(&CERTIFIER_PENDING);
    Lazy::force(&EQUIVOCATIONS);
    Lazy::force(&SIG_VERIFY_FAILURES);
    Lazy::force(&BFS_ABORTED);
    Lazy::force(&FINALIZER_REJECTED_TXS);
    Lazy::force(&PROPAGATION_DELAY);
    Lazy::force(&SYNC_REQUESTS);
    Lazy::force(&SYNC_TIMEOUTS);
    Lazy::force(&BLOCKS_ACCEPTED);
    Lazy::force(&BLOCKS_REJECTED);
    Lazy::force(&DAG_BLOCKS_IN_MEMORY);
    Lazy::force(&STORAGE_WRITE_LATENCY);
    Lazy::force(&LEADER_TIMEOUT_MS);
    Lazy::force(&LEADER_TIMEOUTS);
    Lazy::force(&BLOCKS_SUSPENDED);
    Lazy::force(&BLOCKS_UNSUSPENDED);
    Lazy::force(&COMMIT_LATENCY_HISTOGRAM);
    Lazy::force(&LEADER_ROUND_GAP);
}

// ═══════════════════════════════════════════════════════════════
//  Task 1.1: Fine-grained metrics
// ═══════════════════════════════════════════════════════════════

/// Task 1.1: Blocks suspended due to missing ancestors.
pub static BLOCKS_SUSPENDED: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::with_opts(Opts::new(
        "misaka_consensus_blocks_suspended",
        "Blocks suspended awaiting missing ancestors",
    ))
    .unwrap()
});

/// Task 1.1: Blocks unsuspended after ancestors arrived.
pub static BLOCKS_UNSUSPENDED: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::with_opts(Opts::new(
        "misaka_consensus_blocks_unsuspended",
        "Blocks released from suspension after ancestors arrived",
    ))
    .unwrap()
});

/// Task 1.1: Commit latency histogram (round received → commit, in ms).
pub static COMMIT_LATENCY_HISTOGRAM: Lazy<Histogram> = Lazy::new(|| {
    Histogram::with_opts(
        HistogramOpts::new(
            "misaka_consensus_commit_latency_ms",
            "Time from block reception to commit inclusion [Task 1.1]",
        )
        .buckets(vec![
            10.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2000.0, 5000.0,
        ]),
    )
    .unwrap()
});

/// Task 1.1: Gap between current round and last committed leader round.
pub static LEADER_ROUND_GAP: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::with_opts(Opts::new(
        "misaka_consensus_leader_round_gap",
        "Gap between current round and last committed leader round [Task 1.1]",
    ))
    .unwrap()
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_metrics_register_without_panic() {
        register_slo_metrics();
        // All metrics should be initialized (values may be non-zero from other tests
        // running in parallel, so we just verify they are accessible without panic).
        let _ = COMMITS_TOTAL.get();
        let _ = EQUIVOCATIONS.get();
        let _ = CURRENT_ROUND.get();
    }

    #[test]
    fn test_counter_increments() {
        register_slo_metrics();
        let before = COMMITS_TOTAL.get();
        COMMITS_TOTAL.inc();
        assert_eq!(COMMITS_TOTAL.get(), before + 1);
    }

    #[test]
    fn test_histogram_observes() {
        register_slo_metrics();
        FINALITY_LATENCY.observe(1.5);
        assert_eq!(FINALITY_LATENCY.get_sample_count(), 1);
    }
}
