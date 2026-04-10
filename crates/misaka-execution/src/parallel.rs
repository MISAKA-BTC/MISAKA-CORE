// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! UTXO Parallel Execution Scheduler — Task 4.1
//!
//! Extracts parallelism from UTXO transactions by analyzing read/write sets.
//! Transactions with disjoint input/output sets can execute concurrently.
//!
//! # Design
//!
//! Unlike Sui's object-based parallelism, MISAKA uses UTXO inputs (consumed)
//! and outputs (created) as the conflict domain:
//!
//! - **Read set**: input OutPoints (UTXOs being consumed)
//! - **Write set**: output OutPoints (new UTXOs being created)
//! - **Conflict**: TX A's read set ∩ TX B's read set ≠ ∅ (same UTXO consumed twice)
//!   OR TX A's write set ∩ TX B's write set ≠ ∅ (same OutPoint created twice)
//!
//! Non-conflicting groups execute in parallel. Conflicting transactions fall back to serial.
//!
//! # Limitations
//!
//! - Ring signatures reference multiple UTXOs but only consume one (the real signer).
//!   We conservatively treat ALL ring members as reads → over-serializes but safe.
//! - Output OutPoints depend on tx_hash which includes all inputs → no pre-computation
//!   of write set is possible before execution. We only parallelize on read sets.

use crate::thread_pool::execution_pool;
use misaka_types::utxo::{OutputRef, UtxoTransaction};
use rayon::prelude::*;
use std::collections::{BTreeSet, HashSet};
use std::sync::Mutex;

/// Minimum group size to use rayon parallel execution; smaller groups run sequentially.
pub const PARALLEL_THRESHOLD: usize = 8;

/// Read/Write set for a single transaction.
#[derive(Debug, Clone)]
pub struct TxReadWriteSet {
    /// Input OutPoints (UTXOs consumed / referenced by ring).
    pub reads: BTreeSet<OutputRef>,
    /// Number of outputs (write count, not actual OutPoints since they depend on tx_hash).
    pub output_count: usize,
    /// Index in the original batch.
    pub batch_index: usize,
}

/// A group of non-conflicting transactions that can execute in parallel.
#[derive(Debug)]
pub struct ParallelGroup {
    /// Indices into the original transaction batch.
    pub tx_indices: Vec<usize>,
}

/// Result of scheduling a batch of transactions.
#[derive(Debug)]
pub struct ScheduleResult {
    /// Groups of non-conflicting transactions (execute each group in parallel).
    pub groups: Vec<ParallelGroup>,
    /// Total number of groups (= number of serial steps).
    pub serial_depth: usize,
    /// Maximum parallelism achieved in any single group.
    pub max_parallelism: usize,
}

/// Extract the read set (input OutPoints) from a transaction.
pub fn extract_read_set(tx: &UtxoTransaction) -> BTreeSet<OutputRef> {
    let mut reads = BTreeSet::new();
    for input in &tx.inputs {
        for outref in &input.utxo_refs {
            reads.insert(outref.clone());
        }
    }
    reads
}

/// Schedule a batch of transactions into parallel groups.
///
/// Uses a greedy coloring algorithm:
/// 1. For each TX, compute its read set
/// 2. Assign TX to the first group where no conflict exists
/// 3. If no group fits, create a new group
///
/// Complexity: O(N * G * R) where N = txs, G = groups, R = avg read set size.
/// For typical UTXO workloads (small rings, low conflict), G is small (1-3).
pub fn schedule_parallel(txs: &[UtxoTransaction]) -> ScheduleResult {
    if txs.is_empty() {
        return ScheduleResult {
            groups: vec![],
            serial_depth: 0,
            max_parallelism: 0,
        };
    }

    // Extract read sets
    let read_sets: Vec<BTreeSet<OutputRef>> = txs.iter().map(extract_read_set).collect();

    // Greedy group assignment
    let mut groups: Vec<ParallelGroup> = Vec::new();
    let mut group_reads: Vec<HashSet<OutputRef>> = Vec::new();

    for (i, reads) in read_sets.iter().enumerate() {
        let mut assigned = false;

        for (g_idx, g_reads) in group_reads.iter_mut().enumerate() {
            // Check for conflict: any read in common?
            let conflicts = reads.iter().any(|r| g_reads.contains(r));
            if !conflicts {
                // No conflict → add to this group
                groups[g_idx].tx_indices.push(i);
                g_reads.extend(reads.iter().cloned());
                assigned = true;
                break;
            }
        }

        if !assigned {
            // New group needed
            let mut new_reads = HashSet::new();
            new_reads.extend(reads.iter().cloned());
            group_reads.push(new_reads);
            groups.push(ParallelGroup {
                tx_indices: vec![i],
            });
        }
    }

    let max_parallelism = groups.iter().map(|g| g.tx_indices.len()).max().unwrap_or(0);
    let serial_depth = groups.len();

    ScheduleResult {
        groups,
        serial_depth,
        max_parallelism,
    }
}

/// Execute a scheduled batch using the provided executor function.
///
/// Each group is executed in parallel (via rayon) when the group size meets
/// [`PARALLEL_THRESHOLD`]; smaller groups run sequentially.
/// Groups themselves are executed serially (maintaining causal order).
///
/// Returns results in original batch order.
pub fn execute_scheduled<T, F>(
    schedule: &ScheduleResult,
    txs: &[UtxoTransaction],
    executor: F,
) -> Vec<T>
where
    T: Send + Default,
    F: Fn(usize, &UtxoTransaction) -> T + Send + Sync,
{
    let results: Vec<Mutex<Option<T>>> = (0..txs.len()).map(|_| Mutex::new(None)).collect();

    for group in &schedule.groups {
        if group.tx_indices.len() >= PARALLEL_THRESHOLD {
            // Large group: execute in parallel via rayon thread pool.
            execution_pool().install(|| {
                group.tx_indices.par_iter().for_each(|&idx| {
                    let result = executor(idx, &txs[idx]);
                    *results[idx].lock().unwrap() = Some(result);
                });
            });
        } else {
            // Small group: sequential execution.
            for &idx in &group.tx_indices {
                let result = executor(idx, &txs[idx]);
                *results[idx].lock().unwrap() = Some(result);
            }
        }
    }

    results
        .into_iter()
        .map(|r| r.into_inner().unwrap().unwrap_or_default())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_types::utxo::*;

    fn make_tx(input_refs: Vec<OutputRef>) -> UtxoTransaction {
        UtxoTransaction {
            version: UTXO_TX_VERSION,
            tx_type: TxType::TransparentTransfer,
            inputs: vec![TxInput {
                utxo_refs: input_refs,
                proof: vec![],
            }],
            outputs: vec![TxOutput {
                amount: 100,
                address: [0xCC; 32],
                spending_pubkey: None,
            }],
            fee: 10,
            extra: vec![],
            expiry: 0,
        }
    }

    fn outref(id: u8, idx: u32) -> OutputRef {
        OutputRef {
            tx_hash: [id; 32],
            output_index: idx,
        }
    }

    #[test]
    fn test_no_conflict_single_group() {
        // 3 TXs consuming different UTXOs → all parallel
        let txs = vec![
            make_tx(vec![outref(1, 0)]),
            make_tx(vec![outref(2, 0)]),
            make_tx(vec![outref(3, 0)]),
        ];

        let result = schedule_parallel(&txs);
        assert_eq!(result.serial_depth, 1, "no conflicts → 1 group");
        assert_eq!(result.max_parallelism, 3);
        assert_eq!(result.groups[0].tx_indices, vec![0, 1, 2]);
    }

    #[test]
    fn test_full_conflict_serial() {
        // 3 TXs all consuming the same UTXO → fully serial
        let shared = outref(1, 0);
        let txs = vec![
            make_tx(vec![shared.clone()]),
            make_tx(vec![shared.clone()]),
            make_tx(vec![shared]),
        ];

        let result = schedule_parallel(&txs);
        assert_eq!(result.serial_depth, 3, "full conflict → 3 groups");
        assert_eq!(result.max_parallelism, 1);
    }

    #[test]
    fn test_partial_conflict() {
        // TX0: consumes A
        // TX1: consumes B
        // TX2: consumes A (conflicts with TX0)
        // → Group 1: {TX0, TX1}, Group 2: {TX2}
        let txs = vec![
            make_tx(vec![outref(1, 0)]), // A
            make_tx(vec![outref(2, 0)]), // B
            make_tx(vec![outref(1, 0)]), // A again
        ];

        let result = schedule_parallel(&txs);
        assert_eq!(result.serial_depth, 2);
        assert_eq!(result.groups[0].tx_indices, vec![0, 1]);
        assert_eq!(result.groups[1].tx_indices, vec![2]);
    }

    #[test]
    fn test_empty_batch() {
        let result = schedule_parallel(&[]);
        assert_eq!(result.serial_depth, 0);
        assert_eq!(result.max_parallelism, 0);
    }

    #[test]
    fn test_execute_scheduled() {
        let txs = vec![
            make_tx(vec![outref(1, 0)]),
            make_tx(vec![outref(2, 0)]),
            make_tx(vec![outref(3, 0)]),
        ];
        let schedule = schedule_parallel(&txs);

        let results: Vec<usize> = execute_scheduled(&schedule, &txs, |idx, _tx| idx * 10);
        assert_eq!(results, vec![0, 10, 20]);
    }

    #[test]
    fn test_ring_members_as_reads() {
        // TX with ring of 4 members → all 4 are in read set
        let tx = make_tx(vec![outref(1, 0), outref(2, 0), outref(3, 0), outref(4, 0)]);
        let reads = extract_read_set(&tx);
        assert_eq!(reads.len(), 4);
    }
}
