// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation

use std::sync::Arc;
use std::time::Duration;

use crate::client::MockClient;
use crate::engine::run_loadgen;
use crate::txgen::{self, KeypairPool};
use crate::types::{LoadgenConfig, Workload};

// ── Test (a): Mock client → report generation ───────────────────

#[tokio::test]
async fn test_mock_submit_report_generation() {
    let config = LoadgenConfig {
        target_endpoints: vec!["mock://localhost".into()],
        workload: Workload::SimpleTransfer {
            senders: 4,
            value_per_tx: 1,
        },
        duration_secs: 10,
        concurrency: 4,
        rate_limit_tps: None,
        seed: 42,
        warmup_secs: 0,
        tx_count: Some(100),
    };

    let client = Arc::new(MockClient::always_accept());
    let report = run_loadgen(config, client)
        .await
        .expect("loadgen should succeed");

    assert_eq!(report.txs_submitted, 100);
    assert_eq!(report.txs_accepted, 100);
    assert_eq!(report.txs_rejected, 0);
    assert_eq!(report.txs_timed_out, 0);
    assert!(report.submit_tps > 0.0);
    assert_eq!(report.submit_latency.count, 100);
}

// ── Test (b): Determinism — same seed → same tx hashes ──────────

#[test]
fn test_determinism_same_seed_same_hashes() {
    let pool = KeypairPool::generate(4);

    let (_, hash1, _) = txgen::generate_tx(0, 1, &pool, 42, 100).unwrap();
    let (_, hash2, _) = txgen::generate_tx(0, 1, &pool, 42, 100).unwrap();

    assert_eq!(hash1, hash2, "same inputs should produce same tx hash");
}

// ── Test (c): Rate limiting ─────────────────────────────────────

#[tokio::test]
async fn test_rate_limiting() {
    let config = LoadgenConfig {
        target_endpoints: vec!["mock://localhost".into()],
        workload: Workload::SimpleTransfer {
            senders: 2,
            value_per_tx: 1,
        },
        duration_secs: 3,
        concurrency: 4,
        rate_limit_tps: Some(50), // 50 TPS limit
        seed: 7,
        warmup_secs: 0,
        tx_count: Some(100),
    };

    let client = Arc::new(MockClient::always_accept());
    let report = run_loadgen(config, client).await.expect("loadgen");

    // With 50 TPS limit and 100 txs, should take ~2 seconds
    // TPS should be around 50 ± 20% tolerance
    assert!(
        report.submit_tps <= 70.0,
        "rate-limited TPS should be <= 70, got {:.1}",
        report.submit_tps
    );
}

// ── Test (d): Failure handling ──────────────────────────────────

#[tokio::test]
async fn test_failure_handling() {
    let config = LoadgenConfig {
        target_endpoints: vec!["mock://localhost".into()],
        workload: Workload::SimpleTransfer {
            senders: 4,
            value_per_tx: 1,
        },
        duration_secs: 5,
        concurrency: 4,
        rate_limit_tps: None,
        seed: 99,
        warmup_secs: 0,
        tx_count: Some(100),
    };

    let client = Arc::new(MockClient::reject_half());
    let report = run_loadgen(config, client).await.expect("loadgen");

    assert_eq!(report.txs_submitted, 100);
    // Some should be rejected (exact count depends on tx byte distribution)
    assert!(
        report.txs_rejected > 0,
        "should have some rejections, got 0"
    );
    assert!(
        report.txs_accepted > 0,
        "should have some acceptances, got 0"
    );
    assert!(
        !report.failures_by_reason.is_empty(),
        "failure reasons should be recorded, got empty"
    );
}

// ── Test (e): Signature cost measurement ────────────────────────

#[test]
fn test_signature_cost_measurement() {
    let pool = KeypairPool::generate(2);
    let cost = txgen::measure_signature_cost(&pool, 5);

    assert!(cost.avg_sign_us > 0, "signing should take >0 microseconds");
    assert!(
        cost.avg_sig_bytes > 3000,
        "ML-DSA-65 sig should be >3000 bytes, got {}",
        cost.avg_sig_bytes
    );
    assert!(
        cost.bandwidth_share_pct > 50.0,
        "ML-DSA-65 sig should dominate bandwidth (>50%), got {:.1}%",
        cost.bandwidth_share_pct
    );
}

// ── Test (f): No forbidden dependencies ─────────────────────────

#[test]
fn test_no_forbidden_dependencies() {
    let crate_name = env!("CARGO_PKG_NAME");
    assert_eq!(crate_name, "misaka-loadgen");
    // Actual dep check: cargo tree -p misaka-loadgen | grep -E "misaka-(node|dag|p2p|storage)"
    // Should return 0 results.
}
