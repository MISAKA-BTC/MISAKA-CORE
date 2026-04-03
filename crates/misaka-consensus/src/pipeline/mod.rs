//! Consensus processing pipeline (LEGACY — NOT ACTIVE IN DAG PATH).
//!
//! CRIT-5 STATUS: This module is Kaspa-inspired scaffolding that is NOT
//! called from the DAG block producer or validator. The active block
//! processing path goes through:
//!   block_producer.rs → execute_block() → validate_and_apply_block()
//!
//! This pipeline exists for future activation when MISAKA migrates to
//! a Kaspa-style 4-stage processing model. Until then, all code here
//! is effectively dead code.
//!
//! Original design:
//! 1. **HeaderProcessor** — validates header in isolation, runs GhostDAG
//! 2. **BodyProcessor** — validates transactions in context
//! 3. **VirtualProcessor** — maintains virtual state and UTXO set
//! 4. **PruningProcessor** — handles pruning and history compaction

pub mod body_processor;
pub mod header_processor;
pub mod pruning_processor;
pub mod virtual_processor;

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
