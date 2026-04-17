// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! ReplayEngine — core forensic replay orchestrator.

use std::time::Instant;

use tracing::{info, warn};

use crate::error::{ReplayError, TxMismatch};
use crate::executor::{utxo_set_from_snapshot, ReplayExecutionContext, ReplayExecutor};
use crate::store::ReadOnlyStore;
use misaka_storage::utxo_set::UtxoSet;
use misaka_types::utxo::UtxoTransaction;

/// Replay configuration.
#[derive(Debug, Clone)]
pub struct ReplayConfig {
    /// Abort immediately on first state root mismatch.
    pub stop_on_first_mismatch: bool,
    /// Maximum transactions to replay (None = all).
    pub max_txs: Option<usize>,
    /// Enable ML-DSA-65 signature verification (slow but thorough).
    pub verify_signatures: bool,
    /// Verbose logging.
    pub verbose: bool,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            stop_on_first_mismatch: false,
            max_txs: None,
            verify_signatures: false,
            verbose: false,
        }
    }
}

/// Result of a replay run.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReplayResult {
    pub from_height: u64,
    pub to_height: u64,
    pub blocks_replayed: u64,
    pub txs_replayed: usize,
    pub mismatches: Vec<TxMismatch>,
    pub elapsed_ms: u64,
    pub final_state_root: [u8; 32],
}

impl ReplayResult {
    pub fn is_clean(&self) -> bool {
        self.mismatches.is_empty()
    }
}

/// Core replay engine.
pub struct ReplayEngine<S: ReadOnlyStore, E: ReplayExecutor> {
    store: S,
    executor: E,
    config: ReplayConfig,
}

impl<S: ReadOnlyStore, E: ReplayExecutor> ReplayEngine<S, E> {
    pub fn new(store: S, executor: E, config: ReplayConfig) -> Self {
        Self {
            store,
            executor,
            config,
        }
    }

    /// Replay a range of blocks [from, to] inclusive.
    pub fn replay_range(&self, from: u64, to: u64) -> Result<ReplayResult, ReplayError> {
        let start = Instant::now();
        let snapshot = self.store.get_snapshot()?;
        let mut utxo_set = utxo_set_from_snapshot(snapshot);

        let mut total_txs = 0usize;
        let mut mismatches = Vec::new();

        for height in from..=to {
            let block = self
                .store
                .get_block(height)?
                .ok_or(ReplayError::BlockNotFound(height))?;

            let ctx = ReplayExecutionContext {
                height,
                verify_signatures: self.config.verify_signatures,
            };

            // Deserialize and apply each transaction
            for (tx_idx, raw_tx) in block.transactions.iter().enumerate() {
                let tx: UtxoTransaction = borsh::from_slice(raw_tx).map_err(|e| {
                    ReplayError::DeserializationError(format!(
                        "height {height} tx {tx_idx}: {e}"
                    ))
                })?;

                let state_before = self.executor.compute_state_root(&utxo_set);

                match self.executor.apply_tx(&mut utxo_set, &tx, &ctx) {
                    Ok(_fee) => {}
                    Err(e) => {
                        if self.config.verbose {
                            warn!(
                                height,
                                tx_idx,
                                tx_hash = hex::encode(tx.tx_hash()),
                                "tx execution failed: {e}"
                            );
                        }
                    }
                }

                total_txs += 1;
                if let Some(max) = self.config.max_txs {
                    if total_txs >= max {
                        break;
                    }
                }
            }

            // Verify state root after block
            let actual_root = self.executor.compute_state_root(&utxo_set);
            if actual_root != block.expected_state_root {
                let mismatch = TxMismatch {
                    block_height: height,
                    tx_index: block.transactions.len(), // block-level mismatch
                    tx_hash: [0u8; 32],
                    expected_state_root: block.expected_state_root,
                    actual_state_root: actual_root,
                    error: Some("block state root mismatch".into()),
                };
                mismatches.push(mismatch);

                if self.config.stop_on_first_mismatch {
                    return Ok(ReplayResult {
                        from_height: from,
                        to_height: height,
                        blocks_replayed: height - from + 1,
                        txs_replayed: total_txs,
                        mismatches,
                        elapsed_ms: start.elapsed().as_millis() as u64,
                        final_state_root: actual_root,
                    });
                }
            }
        }

        Ok(ReplayResult {
            from_height: from,
            to_height: to,
            blocks_replayed: to - from + 1,
            txs_replayed: total_txs,
            mismatches,
            elapsed_ms: start.elapsed().as_millis() as u64,
            final_state_root: self.executor.compute_state_root(&utxo_set),
        })
    }

    /// Diagnose: find the first tx in a block that causes a state root mismatch.
    ///
    /// Replays the block tx-by-tx, checking state root after each tx.
    pub fn diagnose_block(&self, height: u64) -> Result<Option<TxMismatch>, ReplayError> {
        let snapshot = self.store.get_snapshot()?;
        let snap_height = snapshot.height;
        let mut utxo_set = utxo_set_from_snapshot(snapshot);

        // Replay all blocks before the target to get to the right state
        for h in (snap_height + 1)..height {
            if let Some(block) = self.store.get_block(h)? {
                let ctx = ReplayExecutionContext {
                    height: h,
                    verify_signatures: false,
                };
                for raw_tx in &block.transactions {
                    if let Ok(tx) = borsh::from_slice::<UtxoTransaction>(raw_tx) {
                        let _ = self.executor.apply_tx(&mut utxo_set, &tx, &ctx);
                    }
                }
            }
        }

        // Now replay the target block tx-by-tx
        let block = self
            .store
            .get_block(height)?
            .ok_or(ReplayError::BlockNotFound(height))?;

        let ctx = ReplayExecutionContext {
            height,
            verify_signatures: self.config.verify_signatures,
        };

        for (tx_idx, raw_tx) in block.transactions.iter().enumerate() {
            let tx: UtxoTransaction = borsh::from_slice(raw_tx).map_err(|e| {
                ReplayError::DeserializationError(format!("tx {tx_idx}: {e}"))
            })?;

            let root_before = self.executor.compute_state_root(&utxo_set);
            let apply_result = self.executor.apply_tx(&mut utxo_set, &tx, &ctx);
            let root_after = self.executor.compute_state_root(&utxo_set);

            // If we detect a problematic tx, report it
            if let Err(e) = &apply_result {
                return Ok(Some(TxMismatch {
                    block_height: height,
                    tx_index: tx_idx,
                    tx_hash: tx.tx_hash(),
                    expected_state_root: root_before,
                    actual_state_root: root_after,
                    error: Some(e.to_string()),
                }));
            }
        }

        // Check final state root
        let actual = self.executor.compute_state_root(&utxo_set);
        if actual != block.expected_state_root {
            // Mismatch but we couldn't pinpoint which tx — aggregate effect
            Ok(Some(TxMismatch {
                block_height: height,
                tx_index: block.transactions.len(),
                tx_hash: [0u8; 32],
                expected_state_root: block.expected_state_root,
                actual_state_root: actual,
                error: Some("aggregate mismatch after all txs".into()),
            }))
        } else {
            Ok(None)
        }
    }
}
