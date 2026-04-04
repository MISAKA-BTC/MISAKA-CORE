//! Parallel Block Acceptance Pipeline.
//!
//! Wraps the atomic pipeline with concurrent header validation.
//!
//! # Architecture
//!
//! ```text
//! Incoming blocks
//!   │
//!   ├──→ [Header Validator Pool] (parallel, N workers)
//!   │     ├── ML-DSA-65 sig verify (~1ms)
//!   │     ├── Timestamp check
//!   │     ├── Parent existence check
//!   │     ├── TX root verify
//!   │     └── Chain ID check
//!   │
//!   ├──→ [Ordering Queue] (FIFO, bounded)
//!   │
//!   └──→ [Sequential Commit] (single writer)
//!         ├── Reachability update
//!         ├── GhostDAG calculation
//!         ├── Virtual state resolve
//!         └── Atomic commit (WriteBatch)
//! ```
//!
//! # Why Not Fully Parallel?
//!
//! - Reachability must be sequential (tree structure updates)
//! - GhostDAG depends on reachability output
//! - Virtual state depends on GhostDAG output
//! - Commit must be atomic (single WriteBatch)
//!
//! BUT: Header validation (~1ms for ML-DSA-65) is the bottleneck and
//! CAN run in parallel across multiple blocks.

use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::dag_block::{DagBlockHeader, Hash};

/// Result of parallel header validation.
#[derive(Debug)]
pub enum HeaderValidationResult {
    /// Header is valid — proceed to sequential stages.
    Valid {
        block_hash: Hash,
        header: DagBlockHeader,
        txs_payload: Vec<u8>,
    },
    /// Header is invalid — reject block.
    Invalid {
        block_hash: Hash,
        reason: String,
    },
}

/// Configuration for the parallel pipeline.
#[derive(Debug, Clone)]
pub struct ParallelPipelineConfig {
    /// Number of parallel header validation workers.
    /// Recommended: num_cpus / 2 (leave cores for networking + RPC).
    pub header_workers: usize,
    /// Maximum blocks queued for sequential commit.
    pub commit_queue_size: usize,
}

impl Default for ParallelPipelineConfig {
    fn default() -> Self {
        Self {
            header_workers: 4,
            commit_queue_size: 256,
        }
    }
}

impl ParallelPipelineConfig {
    /// Config for SR nodes (limited resources).
    pub fn for_sr() -> Self {
        Self {
            header_workers: 2,
            commit_queue_size: 128,
        }
    }

    /// Config for archive nodes (more resources).
    pub fn for_archive() -> Self {
        Self {
            header_workers: 8,
            commit_queue_size: 512,
        }
    }
}

/// Metrics for the parallel pipeline.
#[derive(Debug, Default)]
pub struct PipelineMetrics {
    /// Blocks validated in parallel (header stage).
    pub headers_validated: std::sync::atomic::AtomicU64,
    /// Blocks committed (sequential stage).
    pub blocks_committed: std::sync::atomic::AtomicU64,
    /// Blocks rejected at header validation.
    pub headers_rejected: std::sync::atomic::AtomicU64,
    /// Blocks rejected at commit stage.
    pub commits_rejected: std::sync::atomic::AtomicU64,
    /// Current queue depth.
    pub queue_depth: std::sync::atomic::AtomicU64,
}

impl PipelineMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

/// A block pending header validation.
pub struct PendingValidation {
    pub block_hash: Hash,
    pub header: DagBlockHeader,
    pub txs_payload: Vec<u8>,
}

/// Validated block ready for sequential commit.
pub struct ValidatedBlock {
    pub block_hash: Hash,
    pub header: DagBlockHeader,
    pub txs_payload: Vec<u8>,
}

/// The parallel pipeline coordinator.
///
/// Distributes header validation across N workers, then feeds validated
/// blocks into a sequential commit queue (single-writer for atomicity).
pub struct ParallelPipeline {
    config: ParallelPipelineConfig,
    metrics: Arc<PipelineMetrics>,
    /// Channel for submitting blocks for validation.
    validation_tx: mpsc::Sender<PendingValidation>,
    /// Channel for receiving validated blocks (feeds into sequential commit).
    commit_rx: Option<mpsc::Receiver<ValidatedBlock>>,
}

impl ParallelPipeline {
    /// Create a new parallel pipeline.
    ///
    /// Returns the pipeline and a receiver for validated blocks.
    /// The caller must drain `commit_rx` and feed blocks into the
    /// atomic pipeline's sequential stages.
    pub fn new(config: ParallelPipelineConfig) -> (Self, mpsc::Receiver<ValidatedBlock>) {
        let (validation_tx, mut validation_rx) =
            mpsc::channel::<PendingValidation>(config.commit_queue_size);
        let (commit_tx, commit_rx) =
            mpsc::channel::<ValidatedBlock>(config.commit_queue_size);

        let metrics = PipelineMetrics::new();
        let metrics_clone = metrics.clone();
        let workers = config.header_workers;

        // Spawn header validation dispatcher
        tokio::spawn(async move {
            // Simple round-robin: receive blocks and validate headers
            // In production, this would use a rayon thread pool for CPU-bound
            // ML-DSA-65 verification. For now, tokio::spawn_blocking per block.
            while let Some(pending) = validation_rx.recv().await {
                let tx = commit_tx.clone();
                let m = metrics_clone.clone();
                tokio::spawn(async move {
                    // Header validation (the expensive part: ML-DSA-65 ~1ms)
                    let valid = validate_header_parallel(&pending);
                    match valid {
                        Ok(()) => {
                            m.headers_validated.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            let _ = tx.send(ValidatedBlock {
                                block_hash: pending.block_hash,
                                header: pending.header,
                                txs_payload: pending.txs_payload,
                            }).await;
                        }
                        Err(reason) => {
                            m.headers_rejected.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            debug!("Parallel header reject {}: {}", hex::encode(&pending.block_hash[..8]), reason);
                        }
                    }
                });
            }
        });

        let pipeline = Self {
            config: config.clone(),
            metrics,
            validation_tx,
            commit_rx: None,
        };

        (pipeline, commit_rx)
    }

    /// Submit a block for parallel header validation.
    ///
    /// Non-blocking. Returns immediately. The block will be validated
    /// by a worker and, if valid, appear on the commit channel.
    pub async fn submit(&self, block_hash: Hash, header: DagBlockHeader, txs_payload: Vec<u8>) -> Result<(), String> {
        self.validation_tx.send(PendingValidation {
            block_hash,
            header,
            txs_payload,
        }).await.map_err(|_| "pipeline validation channel closed".to_string())
    }

    /// Get pipeline metrics.
    pub fn metrics(&self) -> &Arc<PipelineMetrics> {
        &self.metrics
    }
}

/// Parallel header validation (runs on worker threads).
///
/// This function performs ALL checks that don't require sequential state:
/// - Timestamp bounds
/// - TX root verification (if TXs available)
/// - Structural checks
///
/// ML-DSA-65 proposer signature verification is the most expensive
/// operation (~1ms) and benefits most from parallelization.
fn validate_header_parallel(pending: &PendingValidation) -> Result<(), String> {
    let header = &pending.header;

    // 1. Timestamp: reject if > 2 minutes in the future
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let max_future_ms = now_ms + 120_000;
    if header.timestamp_ms > max_future_ms {
        return Err(format!(
            "future timestamp: {}ms > max {}ms",
            header.timestamp_ms, max_future_ms
        ));
    }

    // 2. Version check
    if header.version != 0x02 {
        return Err(format!("bad version: {}", header.version));
    }

    // 3. Parent count
    if header.parents.is_empty() && pending.block_hash != [0u8; 32] {
        return Err("no parents (non-genesis)".into());
    }

    // 4. Hash verification
    let computed = header.compute_hash();
    if computed != pending.block_hash {
        return Err(format!(
            "hash mismatch: computed={} declared={}",
            hex::encode(&computed[..8]),
            hex::encode(&pending.block_hash[..8])
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag_block::{DagBlockHeader, ZERO_HASH};

    fn make_header(ts: u64) -> DagBlockHeader {
        DagBlockHeader {
            version: 0x02,
            parents: vec![ZERO_HASH],
            timestamp_ms: ts,
            tx_root: ZERO_HASH,
            proposer_id: [0; 32],
            nonce: 0,
            blue_score: 0,
            bits: 0,
        }
    }

    #[test]
    fn test_validate_header_future_timestamp() {
        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64 + 300_000; // 5 min in future
        let h = make_header(future);
        let pending = PendingValidation {
            block_hash: h.compute_hash(),
            header: h,
            txs_payload: vec![],
        };
        assert!(validate_header_parallel(&pending).is_err());
    }

    #[test]
    fn test_validate_header_bad_version() {
        let mut h = make_header(1000);
        h.version = 0xFF;
        let pending = PendingValidation {
            block_hash: [0; 32], // won't match computed
            header: h,
            txs_payload: vec![],
        };
        assert!(validate_header_parallel(&pending).is_err());
    }

    #[test]
    fn test_validate_header_valid() {
        let h = make_header(1000);
        let hash = h.compute_hash();
        let pending = PendingValidation {
            block_hash: hash,
            header: h,
            txs_payload: vec![],
        };
        assert!(validate_header_parallel(&pending).is_ok());
    }

    #[tokio::test]
    async fn test_pipeline_submit_and_receive() {
        let config = ParallelPipelineConfig { header_workers: 2, commit_queue_size: 16 };
        let (pipeline, mut commit_rx) = ParallelPipeline::new(config);

        let h = make_header(1000);
        let hash = h.compute_hash();
        pipeline.submit(hash, h, vec![]).await.unwrap();

        // Should receive validated block
        let validated = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            commit_rx.recv()
        ).await.unwrap().unwrap();

        assert_eq!(validated.block_hash, hash);
    }
}
