// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Load generation engine — orchestrates tx generation and submission.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::client::LoadgenClient;
use crate::error::LoadgenError;
use crate::txgen::{self, KeypairPool};
use crate::types::{LatencyHistogram, LoadgenConfig, LoadgenReport, SignatureCostReport, Workload};

/// Run load generation and return a report.
pub async fn run_loadgen<C: LoadgenClient + 'static>(
    config: LoadgenConfig,
    client: Arc<C>,
) -> Result<LoadgenReport, LoadgenError> {
    let senders = match &config.workload {
        Workload::SimpleTransfer { senders, .. } => *senders,
        Workload::Stress { .. } => 10,
    };
    let value = match &config.workload {
        Workload::SimpleTransfer { value_per_tx, .. } => *value_per_tx,
        Workload::Stress { .. } => 1,
    };

    // Warmup: generate keypairs
    info!("Warmup: generating {} keypairs...", senders);
    let pool = Arc::new(KeypairPool::generate(senders.max(2)));

    // Measure signature cost
    let sig_cost = txgen::measure_signature_cost(&pool, 10);
    info!(
        "ML-DSA-65 sign: {}us avg, {} bytes, {:.1}% bandwidth share",
        sig_cost.avg_sign_us, sig_cost.avg_sig_bytes, sig_cost.bandwidth_share_pct
    );

    let total_txs = config
        .tx_count
        .unwrap_or(config.rate_limit_tps.unwrap_or(1000) * config.duration_secs);

    let started_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let start = Instant::now();
    let deadline = start + Duration::from_secs(config.duration_secs);

    // Counters
    let submitted = Arc::new(AtomicU64::new(0));
    let accepted = Arc::new(AtomicU64::new(0));
    let rejected = Arc::new(AtomicU64::new(0));
    let timed_out = Arc::new(AtomicU64::new(0));
    let total_bytes = Arc::new(AtomicU64::new(0));

    let latencies: Arc<tokio::sync::Mutex<Vec<u64>>> =
        Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let failures: Arc<tokio::sync::Mutex<HashMap<String, u64>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));

    let semaphore = Arc::new(Semaphore::new(config.concurrency));
    let mut handles = Vec::new();

    // Rate limiter: simple token bucket
    let rate_interval = config
        .rate_limit_tps
        .map(|tps| Duration::from_micros(1_000_000 / tps.max(1)));

    for nonce in 0..total_txs {
        if Instant::now() >= deadline {
            break;
        }

        // Rate limiting
        if let Some(interval) = rate_interval {
            let expected = start + interval * (nonce as u32);
            let now = Instant::now();
            if expected > now {
                tokio::time::sleep(expected - now).await;
            }
        }

        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let pool = pool.clone();
        let submitted = submitted.clone();
        let accepted = accepted.clone();
        let rejected = rejected.clone();
        let timed_out = timed_out.clone();
        let total_bytes = total_bytes.clone();
        let latencies = latencies.clone();
        let failures = failures.clone();

        let handle = tokio::spawn(async move {
            let sender_idx = nonce as usize % pool.keypairs.len();
            let receiver_idx = (nonce as usize + 1) % pool.keypairs.len();

            let (tx_bytes, _tx_hash, _sign_us) =
                match txgen::generate_tx(sender_idx, receiver_idx, &pool, nonce, value) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("tx generation failed: {e}");
                        drop(permit);
                        return;
                    }
                };

            let tx_len = tx_bytes.len() as u64;
            submitted.fetch_add(1, Ordering::Relaxed);
            total_bytes.fetch_add(tx_len, Ordering::Relaxed);

            let submit_start = Instant::now();
            match tokio::time::timeout(Duration::from_secs(10), client.submit_tx(tx_bytes)).await {
                Ok(Ok(_)) => {
                    let latency_ms = submit_start.elapsed().as_millis() as u64;
                    accepted.fetch_add(1, Ordering::Relaxed);
                    latencies.lock().await.push(latency_ms);
                }
                Ok(Err(e)) => {
                    rejected.fetch_add(1, Ordering::Relaxed);
                    let reason = e.to_string();
                    *failures.lock().await.entry(reason).or_insert(0) += 1;
                }
                Err(_) => {
                    timed_out.fetch_add(1, Ordering::Relaxed);
                    *failures.lock().await.entry("timeout".into()).or_insert(0) += 1;
                }
            }

            drop(permit);
        });
        handles.push(handle);
    }

    // Wait for all tasks
    for h in handles {
        let _ = h.await;
    }

    let elapsed = start.elapsed();
    let elapsed_ms = elapsed.as_millis() as u64;
    let txs_submitted = submitted.load(Ordering::Relaxed);
    let txs_accepted = accepted.load(Ordering::Relaxed);
    let txs_rejected = rejected.load(Ordering::Relaxed);
    let txs_timed_out = timed_out.load(Ordering::Relaxed);
    let bandwidth = total_bytes.load(Ordering::Relaxed);

    let submit_tps = if elapsed_ms > 0 {
        txs_accepted as f64 / (elapsed_ms as f64 / 1000.0)
    } else {
        0.0
    };

    let latency_samples = latencies.lock().await.clone();
    let submit_latency = LatencyHistogram::from_samples(latency_samples);
    let failures_map = failures.lock().await.clone();

    Ok(LoadgenReport {
        config,
        started_at_epoch_ms: started_at,
        elapsed_ms,
        txs_submitted,
        txs_accepted,
        txs_rejected,
        txs_timed_out,
        submit_tps,
        submit_latency,
        signature_overhead: sig_cost,
        bandwidth_used_bytes: bandwidth,
        failures_by_reason: failures_map,
    })
}
