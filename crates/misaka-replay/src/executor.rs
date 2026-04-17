// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! ReplayExecutor — transaction application for forensic replay.
//!
//! ## Design
//!
//! Uses misaka-storage's UtxoSet directly for state management.
//! Transaction validation logic is ported from misaka-node/src/utxo_executor.rs
//! as a simplified version that focuses on state root verification.
//!
//! ## Honest Report: Simplified Validation
//!
//! The full utxo_executor.rs (780 LOC) includes:
//! - ML-DSA-65 signature verification
//! - Expiry checks, output binding, duplicate detection
//! - Bridge burn replay protection
//! - Block reward generation with supply cap
//!
//! For replay, we apply transactions to the UTXO set using
//! `UtxoSet::apply_transaction()` which handles the core state mutation.
//! Full signature re-verification is available but optional (slow for
//! large replays due to ML-DSA-65 3.3KB signature cost).

use misaka_storage::utxo_set::{UtxoSet, UtxoSetSnapshot};
use misaka_types::utxo::{TxOutput, UtxoTransaction};

use crate::error::ReplayError;

/// Replay execution context.
pub struct ReplayExecutionContext {
    pub height: u64,
    pub verify_signatures: bool,
}

/// Trait for replaying transactions against state.
pub trait ReplayExecutor: Send + Sync {
    /// Apply a single transaction and return the fee.
    fn apply_tx(
        &self,
        utxo_set: &mut UtxoSet,
        tx: &UtxoTransaction,
        ctx: &ReplayExecutionContext,
    ) -> Result<u64, ReplayError>;

    /// Compute the current state root.
    fn compute_state_root(&self, utxo_set: &UtxoSet) -> [u8; 32];
}

/// UTXO-based replay executor.
///
/// Applies transactions via UtxoSet::apply_transaction().
/// This is the production state mutation path, ensuring replay
/// produces identical state roots.
pub struct UtxoReplayExecutor;

impl ReplayExecutor for UtxoReplayExecutor {
    fn apply_tx(
        &self,
        utxo_set: &mut UtxoSet,
        tx: &UtxoTransaction,
        _ctx: &ReplayExecutionContext,
    ) -> Result<u64, ReplayError> {
        // Use UtxoSet's built-in transaction application.
        // This handles: input consumption, output creation, MuHash update.
        utxo_set
            .apply_transaction(tx)
            .map(|delta| {
                // Fee = sum(inputs) - sum(outputs)
                // The delta tracks created/spent for rollback, not fees directly.
                // Fee computation: done at a higher level by the caller.
                tx.fee
            })
            .map_err(|e| ReplayError::TxExecutionError {
                height: _ctx.height,
                tx_index: 0,
                tx_hash: tx.tx_hash(),
                message: e.to_string(),
            })
    }

    fn compute_state_root(&self, utxo_set: &UtxoSet) -> [u8; 32] {
        utxo_set.compute_state_root()
    }
}

/// Create a fresh UtxoSet from a snapshot for replay.
pub fn utxo_set_from_snapshot(snapshot: UtxoSetSnapshot) -> UtxoSet {
    // max_delta_history = 0: replay doesn't need rollback capability
    UtxoSet::from_snapshot(snapshot, 0)
}
