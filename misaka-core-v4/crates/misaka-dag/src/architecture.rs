//! DAG Three-Layer Architecture — Ordering, Execution, Storage.
//!
//! # Problem: Monolithic Coupling
//!
//! The original DAG implementation couples three distinct concerns:
//! - GhostDAG ordering (topology) reads TX contents to check nullifiers
//! - State manager (execution) calls storage directly during apply
//! - Persistence (storage) is tangled with validation logic
//!
//! This coupling creates:
//! - Non-determinism risk (storage timing affects ordering)
//! - Testing difficulty (can't test ordering without full storage)
//! - Reorg fragility (undo requires coordinating all three layers)
//!
//! # Solution: Strict Layer Separation
//!
//! ```text
//!  ┌─────────────────────────────────────────────────────────┐
//!  │                  Ordering Layer                          │
//!  │  (GhostDAG: pure topology → Vec<Hash> total order)      │
//!  │  Reads: block headers, parent links, reachability index  │
//!  │  Produces: deterministic total ordering of block hashes  │
//!  │  NEVER touches: TX contents, nullifiers, UTXO state      │
//!  └────────────────────────┬────────────────────────────────┘
//!                           │ Vec<Hash> (total order)
//!  ┌────────────────────────▼────────────────────────────────┐
//!  │                  Execution Layer                         │
//!  │  (State Manager: deterministic conflict resolution)      │
//!  │  Reads: total order + TX contents (from block store)     │
//!  │  Produces: StateDelta (nullifiers added, UTXOs created)  │
//!  │  NEVER touches: persistent storage directly              │
//!  └────────────────────────┬────────────────────────────────┘
//!                           │ StateDelta
//!  ┌────────────────────────▼────────────────────────────────┐
//!  │                  Storage Layer                           │
//!  │  (Persistent Store: atomic batch writes)                 │
//!  │  Receives: StateDelta from Execution Layer               │
//!  │  Performs: atomic DB write (nullifiers + UTXOs + indices) │
//!  │  NEVER touches: ordering logic or validation             │
//!  └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # Determinism Guarantee
//!
//! Given the same DAG topology:
//! 1. OrderingLayer always produces the same total order
//! 2. ExecutionLayer always produces the same StateDelta
//! 3. StorageLayer always produces the same persistent state
//!
//! No race conditions, no timing dependencies, no non-determinism.

use std::collections::HashSet;

/// Block hash type.
pub type Hash = [u8; 32];

// ═══════════════════════════════════════════════════════════════
//  Layer 1: Ordering (Pure Topology)
// ═══════════════════════════════════════════════════════════════

/// The Ordering Layer produces a deterministic total order from DAG topology.
///
/// # Contract
///
/// - Reads ONLY: block headers, parent links, blue scores, reachability index
/// - Produces: `Vec<Hash>` — the canonical total ordering of block hashes
/// - NEVER reads: transaction contents, nullifiers, UTXO state, amounts
///
/// # Determinism
///
/// `compute_total_order(tips)` is a PURE FUNCTION of the DAG topology.
/// Same topology → same output, regardless of call timing, thread scheduling,
/// or any external state.
pub trait OrderingLayer {
    type Error: std::fmt::Debug + std::fmt::Display;

    /// Compute the total order from current DAG tips.
    ///
    /// Returns block hashes in the canonical execution order.
    /// This is the ONLY output of the ordering layer.
    fn compute_total_order(&self, tips: &[Hash]) -> Result<Vec<Hash>, Self::Error>;

    /// Get the selected parent chain from a given block.
    fn selected_parent_chain(&self, from: &Hash) -> Result<Vec<Hash>, Self::Error>;

    /// Get a block's blue score (for finality/pruning decisions).
    fn blue_score(&self, block: &Hash) -> Option<u64>;
}

// ═══════════════════════════════════════════════════════════════
//  Layer 2: Execution (Deterministic State Transition)
// ═══════════════════════════════════════════════════════════════

/// The Execution Layer resolves conflicts and produces state deltas.
///
/// # Contract
///
/// - Receives: total order (from Ordering Layer) + TX contents (from block reader)
/// - Produces: `ExecutionResult` containing `StateDelta` for each block
/// - NEVER writes: to persistent storage directly
/// - NEVER reads: persistent storage (receives all inputs as parameters)
///
/// # Determinism
///
/// `execute_ordered_blocks(order, tx_reader)` is a PURE FUNCTION.
/// Given the same ordered blocks and the same transaction contents,
/// it ALWAYS produces the same execution result.
///
/// Nullifier conflicts are resolved by "first in total order wins" —
/// this is deterministic because the total order is deterministic.
pub trait ExecutionLayer {
    type Error: std::fmt::Debug + std::fmt::Display;

    /// Execute a sequence of ordered blocks, producing state deltas.
    ///
    /// # Arguments
    ///
    /// * `ordered_blocks` - Block hashes in total order (from OrderingLayer)
    /// * `tx_reader` - Read-only access to transaction contents
    /// * `known_nullifiers` - Already-spent nullifiers (from persistent state)
    ///
    /// # Returns
    ///
    /// One `BlockExecutionResult` per block, containing the state delta
    /// and per-TX conflict resolution results.
    fn execute_ordered_blocks(
        &self,
        ordered_blocks: &[Hash],
        tx_reader: &dyn BlockTxReader,
        known_nullifiers: &HashSet<Hash>,
    ) -> Result<Vec<BlockExecutionResult>, Self::Error>;
}

/// Read-only access to block transaction contents.
///
/// This trait is the ONLY way the Execution Layer accesses TX data.
/// It decouples execution from storage format.
pub trait BlockTxReader {
    /// Get sealed transactions for a block.
    fn get_block_txs(&self, block_hash: &Hash) -> Option<Vec<SealedTxRef>>;
}

/// Minimal TX reference for execution (no full TX parsing needed).
#[derive(Debug, Clone)]
pub struct SealedTxRef {
    pub tx_hash: Hash,
    pub nullifiers: Vec<Hash>,
    pub is_coinbase: bool,
    pub output_count: u32,
    pub output_addresses: Vec<[u8; 32]>,
}

/// Execution result for a single block.
#[derive(Debug, Clone)]
pub struct BlockExecutionResult {
    pub block_hash: Hash,
    pub delta: super::state_diff::StateDiff,
    pub applied_tx_count: usize,
    pub failed_tx_count: usize,
}

// ═══════════════════════════════════════════════════════════════
//  Layer 3: Storage (Atomic Persistence)
// ═══════════════════════════════════════════════════════════════

/// The Storage Layer persists state deltas atomically.
///
/// # Contract
///
/// - Receives: `StateDelta` from Execution Layer
/// - Performs: atomic batch write to persistent store
/// - NEVER performs: ordering logic, validation, conflict resolution
///
/// # Atomicity
///
/// `apply_delta()` MUST be atomic: either ALL changes are persisted,
/// or NONE are. Partial writes corrupt the state and are unrecoverable.
///
/// # Undo Support
///
/// `revert_delta()` MUST be the exact inverse of `apply_delta()`.
/// This is required for reorg support.
pub trait StorageLayer {
    type Error: std::fmt::Debug + std::fmt::Display;

    /// Atomically persist a state delta.
    ///
    /// After this returns Ok:
    /// - All nullifiers in delta are in the persistent nullifier set
    /// - All created UTXOs are in the persistent UTXO set
    /// - The state root has been updated
    fn apply_delta(&mut self, delta: &super::state_diff::StateDiff) -> Result<(), Self::Error>;

    /// Atomically revert a state delta (for reorgs).
    ///
    /// After this returns Ok:
    /// - All nullifiers in delta are removed from the persistent set
    /// - All created UTXOs are removed from the persistent set
    /// - The state root has been restored to pre-delta value
    fn revert_delta(&mut self, delta: &super::state_diff::StateDiff) -> Result<(), Self::Error>;

    /// Get current state root hash.
    fn state_root(&self) -> Hash;

    /// Check if a nullifier is already spent (persistent state).
    fn is_nullifier_spent(&self, nullifier: &Hash) -> bool;

    /// Get all spent nullifiers (for execution layer initialization).
    fn all_spent_nullifiers(&self) -> HashSet<Hash>;
}

// ═══════════════════════════════════════════════════════════════
//  Pipeline Orchestrator
// ═══════════════════════════════════════════════════════════════

/// Orchestrates the three layers into a single deterministic pipeline.
///
/// ```text
/// tips → [Ordering] → total_order → [Execution] → deltas → [Storage] → persisted
/// ```
///
/// # Determinism Proof
///
/// 1. `ordering.compute_total_order(tips)` is pure (same DAG → same order)
/// 2. `execution.execute_ordered_blocks(order, txs, nullifiers)` is pure
///    (same inputs → same deltas)
/// 3. `storage.apply_delta(delta)` is atomic (all-or-nothing)
///
/// Therefore: same DAG topology → same persistent state. QED.
pub struct DagPipeline<O, E, S>
where
    O: OrderingLayer,
    E: ExecutionLayer,
    S: StorageLayer,
{
    pub ordering: O,
    pub execution: E,
    pub storage: S,
}

/// Pipeline execution result.
#[derive(Debug)]
pub struct PipelineResult {
    pub total_order: Vec<Hash>,
    pub block_results: Vec<BlockExecutionResult>,
    pub new_state_root: Hash,
    pub total_applied: usize,
    pub total_failed: usize,
}

impl<O, E, S> DagPipeline<O, E, S>
where
    O: OrderingLayer,
    E: ExecutionLayer,
    S: StorageLayer,
{
    pub fn new(ordering: O, execution: E, storage: S) -> Self {
        Self { ordering, execution, storage }
    }

    /// Execute the full pipeline: Order → Execute → Store.
    ///
    /// This is the SINGLE entry point for DAG state advancement.
    /// No other code path should modify persistent state.
    pub fn advance(&mut self, tips: &[Hash], tx_reader: &dyn BlockTxReader)
        -> Result<PipelineResult, PipelineError>
    {
        // ── Layer 1: Ordering ──
        let total_order = self.ordering.compute_total_order(tips)
            .map_err(|e| PipelineError::Ordering(format!("{}", e)))?;

        // ── Layer 2: Execution ──
        let known_nullifiers = self.storage.all_spent_nullifiers();
        let block_results = self.execution.execute_ordered_blocks(
            &total_order, tx_reader, &known_nullifiers,
        ).map_err(|e| PipelineError::Execution(format!("{}", e)))?;

        // ── Layer 3: Storage (atomic per-block) ──
        let mut total_applied = 0usize;
        let mut total_failed = 0usize;

        for result in &block_results {
            self.storage.apply_delta(&result.delta)
                .map_err(|e| PipelineError::Storage(format!("{}", e)))?;
            total_applied += result.applied_tx_count;
            total_failed += result.failed_tx_count;
        }

        let new_state_root = self.storage.state_root();

        Ok(PipelineResult {
            total_order,
            block_results,
            new_state_root,
            total_applied,
            total_failed,
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("ordering: {0}")]
    Ordering(String),
    #[error("execution: {0}")]
    Execution(String),
    #[error("storage: {0}")]
    Storage(String),
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // Verify trait object safety (can be used as dyn Trait)
    fn _assert_ordering_object_safe(_: &dyn OrderingLayer<Error = String>) {}
    fn _assert_storage_object_safe(_: &dyn StorageLayer<Error = String>) {}
    fn _assert_block_reader_object_safe(_: &dyn BlockTxReader) {}

    #[test]
    fn test_sealed_tx_ref_nullifier_access() {
        let tx = SealedTxRef {
            tx_hash: [1; 32],
            nullifiers: vec![[0xAA; 32], [0xBB; 32]],
            is_coinbase: false,
            output_count: 2,
            output_addresses: vec![[0x11; 32], [0x22; 32]],
        };
        assert_eq!(tx.nullifiers.len(), 2);
        assert!(!tx.is_coinbase);
    }

    #[test]
    fn test_pipeline_error_display() {
        let e = PipelineError::Ordering("test".into());
        assert!(e.to_string().contains("ordering"));
    }
}
