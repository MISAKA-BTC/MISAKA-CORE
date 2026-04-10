// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Dedicated rayon thread pool for ML-DSA-65 signature verification.
//!
//! Separate from the execution pool to prevent head-of-line blocking.
//! ML-DSA-65 has NO cryptographic batch verification (unlike Ed25519).
//! "Batch" here = rayon parallelism only. Speedup bounded by core count.

use once_cell::sync::OnceCell;
use rayon::ThreadPool;

static VERIFY_POOL: OnceCell<ThreadPool> = OnceCell::new();

/// Initialize the verify thread pool.
pub fn init_verify_pool(num_threads: usize) -> Result<(), String> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .thread_name(|i| format!("misaka-verify-{}", i))
        .build()
        .map_err(|e| e.to_string())?;
    VERIFY_POOL
        .set(pool)
        .map_err(|_| "already initialized".to_string())
}

/// Get the verify thread pool (lazy-initializes if needed).
pub fn verify_pool() -> &'static ThreadPool {
    VERIFY_POOL.get_or_init(|| {
        let n = (num_cpus::get() / 2).max(2).min(4);
        rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .thread_name(|i| format!("misaka-verify-{}", i))
            .build()
            .expect("verify pool")
    })
}
