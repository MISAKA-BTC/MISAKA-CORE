//! Global rayon thread pool for UTXO transaction validation.

use rayon::ThreadPool;
use std::sync::OnceLock;

static EXECUTION_POOL: OnceLock<ThreadPool> = OnceLock::new();

/// Initialize the execution thread pool with the given number of threads.
pub fn init_execution_pool(num_threads: usize) -> Result<(), String> {
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .thread_name(|i| format!("misaka-exec-{}", i))
        .build()
        .map_err(|e| e.to_string())?;
    EXECUTION_POOL
        .set(pool)
        .map_err(|_| "already initialized".to_string())
}

/// Get the execution thread pool (lazy-initializes if needed).
pub fn execution_pool() -> &'static ThreadPool {
    EXECUTION_POOL.get_or_init(|| {
        let n = num_cpus::get().min(8);
        rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .thread_name(|i| format!("misaka-exec-{}", i))
            .build()
            .expect("rayon pool")
    })
}
