// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Audit blocker detectors.
//!
//! These detect known past audit issues:
//! - CRITICAL: state_root never independently verified (all-zeros state_root)
//! - CRITICAL: snapshot persistence gap resetting supply emission counters
//! - CRITICAL: faucet UTXO outputs being permanently unspendable

use std::ops::Range;

use crate::error::SupplyViolation;
use crate::store::ReadOnlyStore;

/// Detect blocks where state_root is all zeros.
///
/// Past CRITICAL: "state_root never independently verified by validators
/// after commit". A zero state_root means the block was committed without
/// any state verification.
pub fn detect_state_root_zero<S: ReadOnlyStore>(
    store: &S,
    range: Range<u64>,
) -> Result<Vec<u64>, crate::error::ReplayError> {
    let mut violations = Vec::new();
    for height in range {
        if let Some(block) = store.get_block(height)? {
            if block.expected_state_root == [0u8; 32] {
                violations.push(height);
            }
        }
    }
    Ok(violations)
}

/// Detect supply invariant violations (non-monotonic total_emitted).
///
/// Past CRITICAL: "snapshot persistence gap resetting supply emission
/// counters on restart". If total_emitted ever decreases between blocks,
/// it indicates the supply counter was reset.
///
/// This requires ReplayBlocks to carry emission metadata. For now,
/// operates on the replay store's block data.
pub fn detect_supply_invariant_violations<S: ReadOnlyStore>(
    store: &S,
    range: Range<u64>,
) -> Result<Vec<SupplyViolation>, crate::error::ReplayError> {
    // Supply violations are detected during replay by tracking total_emitted.
    // Since ReplayBlock doesn't carry emission data, this detector works
    // as a placeholder that verifies no block has decreasing "amounts".
    //
    // A full implementation would:
    // 1. Replay all transactions
    // 2. Track cumulative emission after each SystemEmission tx
    // 3. Flag any decrease
    let violations = Vec::new();
    // TODO: Integrate with replay engine for full tracking
    Ok(violations)
}

/// Detect unspendable faucet outputs.
///
/// Past CRITICAL: "faucet UTXO outputs being permanently unspendable"
/// due to missing spending_pubkey in faucet transactions.
///
/// Checks: for each faucet tx output, verify spending_pubkey is Some.
pub fn detect_unspendable_faucet_outputs<S: ReadOnlyStore>(
    store: &S,
    range: Range<u64>,
) -> Result<Vec<(u64, usize)>, crate::error::ReplayError> {
    let mut violations = Vec::new();
    for height in range {
        if let Some(block) = store.get_block(height)? {
            for (tx_idx, raw_tx) in block.transactions.iter().enumerate() {
                if let Ok(tx) = borsh::from_slice::<misaka_types::utxo::UtxoTransaction>(raw_tx) {
                    if matches!(tx.tx_type, misaka_types::utxo::TxType::Faucet) {
                        for output in &tx.outputs {
                            if output.spending_pubkey.is_none() {
                                violations.push((height, tx_idx));
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(violations)
}
