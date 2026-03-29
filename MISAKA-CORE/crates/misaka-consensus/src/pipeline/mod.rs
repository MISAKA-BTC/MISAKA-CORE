//! Consensus processing pipeline.
//!
//! Modeled after Kaspa's 4-stage pipeline, adapted for MISAKA's
//! PQC-native PoS architecture:
//!
//! 1. **HeaderProcessor** — validates header in isolation, runs GhostDAG
//! 2. **BodyProcessor** — validates transactions in context
//! 3. **VirtualProcessor** — maintains virtual state and UTXO set
//! 4. **PruningProcessor** — handles pruning and history compaction

pub mod header_processor;
pub mod body_processor;
pub mod virtual_processor;
pub mod pruning_processor;

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

/// Processing counters for monitoring.
#[derive(Default)]
pub struct ProcessingCounters {
    pub headers_processed: AtomicU64,
    pub bodies_processed: AtomicU64,
    pub virtual_updates: AtomicU64,
    pub pruning_rounds: AtomicU64,
    pub blocks_submitted: AtomicU64,
}

impl ProcessingCounters {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}
