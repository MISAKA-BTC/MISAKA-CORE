// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! WP11a: UTXO Transaction Dependency Graph — Analysis Only.
//!
//! This module implements Phase 11a of the MISAKA whitepaper: constructing a
//! dependency graph from linearized UTXO transactions and computing metrics
//! such as parallelism ratio, critical path length, and topological layers.
//!
//! **Phase 11a is analysis only** — no parallel execution is performed here.
//! The graph and metrics produced by this module feed into future phases
//! (11b+) that will schedule independent transaction waves for concurrent
//! execution.
//!
//! ## Algorithm
//!
//! Given a sequence of `TxReadWriteSet` entries (one per transaction in
//! linearized commit order), we perform O(n^2) pairwise conflict detection
//! to build a directed acyclic graph of dependencies. Three conflict kinds
//! are tracked: Read-After-Write, Write-After-Write, and Write-After-Read.

use std::collections::{HashSet, VecDeque};

// ═══════════════════════════════════════════════════════════
//  UTXO Reference
// ═══════════════════════════════════════════════════════════

/// A reference to a specific UTXO: the hash of the producing transaction
/// combined with the output index within that transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UtxoRef {
    /// BLAKE3 hash of the transaction that created this output.
    pub tx_hash: [u8; 32],
    /// Zero-based index of the output within the producing transaction.
    pub output_index: u32,
}

impl UtxoRef {
    pub fn new(tx_hash: [u8; 32], output_index: u32) -> Self {
        Self {
            tx_hash,
            output_index,
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Read/Write Set
// ═══════════════════════════════════════════════════════════

/// The read and write sets for a single transaction.
///
/// - `reads`: UTXOs consumed (spent) by this transaction.
/// - `writes`: UTXOs produced (created) by this transaction.
/// - `tx_index`: position in the linearized commit order.
#[derive(Clone, Debug)]
pub struct TxReadWriteSet {
    /// UTXOs consumed (inputs) — the "read set".
    pub reads: HashSet<UtxoRef>,
    /// UTXOs produced (outputs) — the "write set".
    pub writes: HashSet<UtxoRef>,
    /// Position in the linearized transaction sequence.
    pub tx_index: usize,
}

// ═══════════════════════════════════════════════════════════
//  Conflict Kind
// ═══════════════════════════════════════════════════════════

/// The kind of data dependency between two transactions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConflictKind {
    /// Transaction B reads a UTXO that transaction A writes (true dependency).
    ReadAfterWrite,
    /// Both transactions write (produce) UTXOs that collide — typically
    /// indicates duplicate output references.
    WriteAfterWrite,
    /// Transaction B writes a UTXO that transaction A reads, meaning B
    /// invalidates an input that A consumed.
    WriteAfterRead,
}

// ═══════════════════════════════════════════════════════════
//  Dependency Graph
// ═══════════════════════════════════════════════════════════

/// A directed acyclic graph of transaction dependencies.
///
/// Nodes are transactions (identified by their `tx_index`). Edges represent
/// data conflicts: an edge from A to B means B depends on A and must execute
/// after A.
pub struct TxDependencyGraph {
    /// Per-transaction read/write sets, ordered by `tx_index`.
    pub nodes: Vec<TxReadWriteSet>,
    /// All dependency edges: `(from, to, kind)`.
    pub edges: Vec<(usize, usize, ConflictKind)>,
    /// Forward adjacency list: `adjacency[i]` lists nodes that depend on `i`.
    pub adjacency: Vec<Vec<usize>>,
}

impl TxDependencyGraph {
    /// Build the dependency graph via O(n^2) pairwise conflict detection.
    ///
    /// For each pair `(i, j)` where `i < j` (i.e. `i` appears earlier in the
    /// linearized order), we check whether any of `j`'s reads overlap with
    /// `i`'s writes (RAW), any of `j`'s writes overlap with `i`'s writes
    /// (WAW), or any of `j`'s writes overlap with `i`'s reads (WAR).
    pub fn build(rw_sets: Vec<TxReadWriteSet>) -> Self {
        let n = rw_sets.len();
        let mut edges = Vec::new();
        let mut adjacency = vec![Vec::new(); n];

        for i in 0..n {
            for j in (i + 1)..n {
                // RAW: j reads something i writes
                for r in &rw_sets[j].reads {
                    if rw_sets[i].writes.contains(r) {
                        edges.push((i, j, ConflictKind::ReadAfterWrite));
                        adjacency[i].push(j);
                        break;
                    }
                }

                // WAW: both i and j write the same UTXO
                let has_raw = adjacency[i].last() == Some(&j);
                for w in &rw_sets[j].writes {
                    if rw_sets[i].writes.contains(w) {
                        edges.push((i, j, ConflictKind::WriteAfterWrite));
                        if !has_raw {
                            adjacency[i].push(j);
                        }
                        break;
                    }
                }

                // WAR: j writes something i reads
                let has_edge = adjacency[i].last() == Some(&j);
                for w in &rw_sets[j].writes {
                    if rw_sets[i].reads.contains(w) {
                        edges.push((i, j, ConflictKind::WriteAfterRead));
                        if !has_edge {
                            adjacency[i].push(j);
                        }
                        break;
                    }
                }
            }
        }

        Self {
            nodes: rw_sets,
            edges,
            adjacency,
        }
    }

    /// Total number of dependency edges.
    pub fn num_edges(&self) -> usize {
        self.edges.len()
    }

    /// Number of fully independent nodes (no incoming or outgoing edges).
    pub fn num_independent(&self) -> usize {
        let n = self.nodes.len();
        let mut has_edge = vec![false; n];
        for &(from, to, _) in &self.edges {
            has_edge[from] = true;
            has_edge[to] = true;
        }
        has_edge.iter().filter(|&&h| !h).count()
    }

    /// Parallelism ratio: greedy maximum independent set size / total nodes.
    ///
    /// A ratio of 1.0 means all transactions are independent (fully parallel).
    /// A ratio of 1/n means they form a single chain (fully sequential).
    ///
    /// Uses a greedy approximation: iterate in order, add a node to the
    /// independent set if none of its neighbors are already in the set.
    pub fn parallelism_ratio(&self) -> f64 {
        let n = self.nodes.len();
        if n == 0 {
            return 1.0;
        }

        // Build reverse adjacency for incoming edges
        let mut in_neighbors: Vec<HashSet<usize>> = vec![HashSet::new(); n];
        let mut out_neighbors: Vec<HashSet<usize>> = vec![HashSet::new(); n];
        for &(from, to, _) in &self.edges {
            out_neighbors[from].insert(to);
            in_neighbors[to].insert(from);
        }

        let mut in_set = vec![false; n];
        let mut count = 0usize;

        for i in 0..n {
            // Check that no neighbor (in or out) is already selected
            let conflict = in_neighbors[i].iter().any(|&nb| in_set[nb])
                || out_neighbors[i].iter().any(|&nb| in_set[nb]);
            if !conflict {
                in_set[i] = true;
                count += 1;
            }
        }

        count as f64 / n as f64
    }

    /// Critical path length — the longest path in the DAG via topological sort.
    ///
    /// Returns 0 for an empty graph. For a single node with no edges, returns 1.
    pub fn critical_path_length(&self) -> usize {
        let n = self.nodes.len();
        if n == 0 {
            return 0;
        }

        // dist[i] = longest path ending at node i
        let mut dist = vec![1usize; n];
        // Process in topological order (nodes are 0..n, edges go from lower to higher index)
        for j in 0..n {
            for &(from, to, _) in &self.edges {
                if to == j {
                    dist[j] = dist[j].max(dist[from] + 1);
                }
            }
        }

        dist.into_iter().max().unwrap_or(0)
    }

    /// Group transactions into topological layers (waves).
    ///
    /// Layer 0 contains all transactions with no incoming dependencies.
    /// Layer k contains transactions whose dependencies are all in layers < k.
    /// Transactions within the same layer can theoretically execute in parallel.
    pub fn topological_layers(&self) -> Vec<Vec<usize>> {
        let n = self.nodes.len();
        if n == 0 {
            return Vec::new();
        }

        // Compute in-degree
        let mut in_degree = vec![0usize; n];
        let mut reverse_adj: Vec<Vec<usize>> = vec![Vec::new(); n];
        for &(from, to, _) in &self.edges {
            // Deduplicate: only count unique adjacency edges
            if !reverse_adj[to].contains(&from) {
                reverse_adj[to].push(from);
            }
        }
        for i in 0..n {
            in_degree[i] = reverse_adj[i].len();
        }

        let mut layers = Vec::new();
        let mut queue: VecDeque<usize> = VecDeque::new();
        let mut remaining_in = in_degree.clone();

        // Seed with zero in-degree nodes
        for i in 0..n {
            if remaining_in[i] == 0 {
                queue.push_back(i);
            }
        }

        while !queue.is_empty() {
            let layer: Vec<usize> = queue.drain(..).collect();
            for &node in &layer {
                for &succ in &self.adjacency[node] {
                    remaining_in[succ] = remaining_in[succ].saturating_sub(1);
                    if remaining_in[succ] == 0 {
                        queue.push_back(succ);
                    }
                }
            }
            layers.push(layer);
        }

        layers
    }

    /// Check whether two transactions have a direct conflict edge.
    pub fn has_conflict(&self, a: usize, b: usize) -> bool {
        self.edges
            .iter()
            .any(|&(from, to, _)| (from == a && to == b) || (from == b && to == a))
    }
}

// ═══════════════════════════════════════════════════════════
//  UTXO R/W Set Extraction (placeholder)
// ═══════════════════════════════════════════════════════════

/// Extract a read/write set from a raw MISAKA transaction.
///
/// **Placeholder implementation** — real parsing requires `misaka-types`
/// integration with proper transaction deserialization. The current heuristic:
///
/// - The first 32 bytes of the transaction are treated as the transaction hash
///   and used to construct a single write (output 0).
/// - Remaining bytes are chunked into 36-byte input references (32-byte
///   tx_hash + 4-byte little-endian output_index) to form the read set.
///
/// Returns `None` if the transaction is too short (< 32 bytes).
pub fn extract_utxo_rw_set(tx: &[u8], tx_index: usize) -> Option<TxReadWriteSet> {
    if tx.len() < 32 {
        return None;
    }

    let mut tx_hash = [0u8; 32];
    tx_hash.copy_from_slice(&tx[..32]);

    // Write set: single output at index 0
    let mut writes = HashSet::new();
    writes.insert(UtxoRef::new(tx_hash, 0));

    // Read set: parse remaining bytes as 36-byte input references
    let mut reads = HashSet::new();
    let input_data = &tx[32..];
    let mut offset = 0;
    while offset + 36 <= input_data.len() {
        let mut ref_hash = [0u8; 32];
        ref_hash.copy_from_slice(&input_data[offset..offset + 32]);
        let idx_bytes: [u8; 4] = input_data[offset + 32..offset + 36].try_into().unwrap();
        let output_index = u32::from_le_bytes(idx_bytes);
        reads.insert(UtxoRef::new(ref_hash, output_index));
        offset += 36;
    }

    Some(TxReadWriteSet {
        reads,
        writes,
        tx_index,
    })
}

// ═══════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a TxReadWriteSet with explicit reads and writes.
    fn make_rw(
        tx_index: usize,
        reads: Vec<([u8; 32], u32)>,
        writes: Vec<([u8; 32], u32)>,
    ) -> TxReadWriteSet {
        TxReadWriteSet {
            reads: reads.into_iter().map(|(h, i)| UtxoRef::new(h, i)).collect(),
            writes: writes
                .into_iter()
                .map(|(h, i)| UtxoRef::new(h, i))
                .collect(),
            tx_index,
        }
    }

    /// Shorthand for a 32-byte hash with a single distinguishing byte.
    fn hash(b: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = b;
        h
    }

    // ─── Test: empty graph ────────────────────────────────────

    #[test]
    fn test_empty_graph() {
        let g = TxDependencyGraph::build(vec![]);
        assert_eq!(g.nodes.len(), 0);
        assert_eq!(g.num_edges(), 0);
        assert_eq!(g.num_independent(), 0);
        assert_eq!(g.critical_path_length(), 0);
        assert!(g.topological_layers().is_empty());
        assert!((g.parallelism_ratio() - 1.0).abs() < f64::EPSILON);
    }

    // ─── Test: fully independent transactions ─────────────────

    #[test]
    fn test_fully_independent() {
        // Four transactions, each with unique reads/writes — no conflicts.
        let sets = vec![
            make_rw(0, vec![], vec![(hash(1), 0)]),
            make_rw(1, vec![], vec![(hash(2), 0)]),
            make_rw(2, vec![], vec![(hash(3), 0)]),
            make_rw(3, vec![], vec![(hash(4), 0)]),
        ];
        let g = TxDependencyGraph::build(sets);

        assert_eq!(g.num_edges(), 0);
        assert_eq!(g.num_independent(), 4);
        assert!((g.parallelism_ratio() - 1.0).abs() < f64::EPSILON);
        assert_eq!(g.critical_path_length(), 1);

        let layers = g.topological_layers();
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].len(), 4);
    }

    // ─── Test: fully sequential chain ─────────────────────────

    #[test]
    fn test_fully_sequential() {
        // Chain: tx0 writes A, tx1 reads A writes B, tx2 reads B writes C
        let sets = vec![
            make_rw(0, vec![], vec![(hash(0xA0), 0)]),
            make_rw(1, vec![(hash(0xA0), 0)], vec![(hash(0xB0), 0)]),
            make_rw(2, vec![(hash(0xB0), 0)], vec![(hash(0xC0), 0)]),
        ];
        let g = TxDependencyGraph::build(sets);

        assert!(g.num_edges() >= 2); // 0->1, 1->2 (RAW edges)
        assert_eq!(g.num_independent(), 0);
        // Greedy MIS picks {tx0, tx2} (tx1 is skipped due to neighbor tx0),
        // giving ratio = 2/3 for a 3-node chain.
        assert!((g.parallelism_ratio() - 2.0 / 3.0).abs() < 0.01);
        assert_eq!(g.critical_path_length(), 3);

        let layers = g.topological_layers();
        assert_eq!(layers.len(), 3);
        assert_eq!(layers[0].len(), 1);
        assert_eq!(layers[1].len(), 1);
        assert_eq!(layers[2].len(), 1);
    }

    // ─── Test: diamond dependency ─────────────────────────────

    #[test]
    fn test_diamond_dependency() {
        //      tx0
        //     /   \
        //   tx1   tx2
        //     \   /
        //      tx3
        //
        // tx0 writes A and B
        // tx1 reads A, writes C
        // tx2 reads B, writes D
        // tx3 reads C and D
        let sets = vec![
            make_rw(0, vec![], vec![(hash(0xA0), 0), (hash(0xB0), 0)]),
            make_rw(1, vec![(hash(0xA0), 0)], vec![(hash(0xC0), 0)]),
            make_rw(2, vec![(hash(0xB0), 0)], vec![(hash(0xD0), 0)]),
            make_rw(3, vec![(hash(0xC0), 0), (hash(0xD0), 0)], vec![]),
        ];
        let g = TxDependencyGraph::build(sets);

        // Edges: 0->1, 0->2, 1->3, 2->3
        assert!(g.has_conflict(0, 1));
        assert!(g.has_conflict(0, 2));
        assert!(g.has_conflict(1, 3));
        assert!(g.has_conflict(2, 3));
        assert!(!g.has_conflict(1, 2)); // tx1 and tx2 are independent

        let layers = g.topological_layers();
        assert_eq!(layers.len(), 3); // layer0=[0], layer1=[1,2], layer2=[3]
        assert_eq!(layers[0], vec![0]);
        assert_eq!(layers[2], vec![3]);
        // Middle layer contains both 1 and 2 in some order
        let mut mid = layers[1].clone();
        mid.sort();
        assert_eq!(mid, vec![1, 2]);
    }

    // ─── Test: critical path ──────────────────────────────────

    #[test]
    fn test_critical_path() {
        // Two parallel chains:
        //   Chain A: tx0 -> tx1 -> tx2  (length 3)
        //   Chain B: tx3 -> tx4         (length 2)
        // Critical path = 3
        let sets = vec![
            make_rw(0, vec![], vec![(hash(1), 0)]),
            make_rw(1, vec![(hash(1), 0)], vec![(hash(2), 0)]),
            make_rw(2, vec![(hash(2), 0)], vec![(hash(3), 0)]),
            make_rw(3, vec![], vec![(hash(4), 0)]),
            make_rw(4, vec![(hash(4), 0)], vec![(hash(5), 0)]),
        ];
        let g = TxDependencyGraph::build(sets);

        assert_eq!(g.critical_path_length(), 3);

        let layers = g.topological_layers();
        // Layer 0: tx0, tx3 (both have no deps)
        // Layer 1: tx1, tx4
        // Layer 2: tx2
        assert_eq!(layers.len(), 3);
    }

    // ─── Test: topological layers ─────────────────────────────

    #[test]
    fn test_topological_layers() {
        // tx0: writes A
        // tx1: writes B (independent of tx0)
        // tx2: reads A and B (depends on tx0 and tx1)
        // tx3: reads A (depends on tx0 only)
        let sets = vec![
            make_rw(0, vec![], vec![(hash(0xA0), 0)]),
            make_rw(1, vec![], vec![(hash(0xB0), 0)]),
            make_rw(
                2,
                vec![(hash(0xA0), 0), (hash(0xB0), 0)],
                vec![(hash(0xC0), 0)],
            ),
            make_rw(3, vec![(hash(0xA0), 0)], vec![(hash(0xD0), 0)]),
        ];
        let g = TxDependencyGraph::build(sets);

        let layers = g.topological_layers();
        // Layer 0: tx0, tx1
        // Layer 1: tx2, tx3
        assert_eq!(layers.len(), 2);

        let mut l0 = layers[0].clone();
        l0.sort();
        assert_eq!(l0, vec![0, 1]);

        let mut l1 = layers[1].clone();
        l1.sort();
        assert_eq!(l1, vec![2, 3]);
    }

    // ─── Test: extract_utxo_rw_set placeholder ────────────────

    #[test]
    fn test_extract_utxo_rw_set_too_short() {
        assert!(extract_utxo_rw_set(&[0u8; 10], 0).is_none());
    }

    #[test]
    fn test_extract_utxo_rw_set_basic() {
        // 32-byte tx hash + one 36-byte input reference
        let mut tx = vec![0u8; 32 + 36];
        // tx hash = 0xAA repeated
        tx[..32].fill(0xAA);
        // Input ref: hash = 0xBB repeated, output_index = 1 (LE)
        tx[32..64].fill(0xBB);
        tx[64] = 1;
        tx[65] = 0;
        tx[66] = 0;
        tx[67] = 0;

        let rw = extract_utxo_rw_set(&tx, 7).unwrap();
        assert_eq!(rw.tx_index, 7);
        assert_eq!(rw.writes.len(), 1);
        assert_eq!(rw.reads.len(), 1);

        let write_ref = rw.writes.iter().next().unwrap();
        assert_eq!(write_ref.tx_hash, [0xAA; 32]);
        assert_eq!(write_ref.output_index, 0);

        let read_ref = rw.reads.iter().next().unwrap();
        assert_eq!(read_ref.tx_hash, [0xBB; 32]);
        assert_eq!(read_ref.output_index, 1);
    }

    // ─── Test: conflict kinds ─────────────────────────────────

    #[test]
    fn test_write_after_write_conflict() {
        // Both tx0 and tx1 produce the same UTXO
        let sets = vec![
            make_rw(0, vec![], vec![(hash(0xAA), 0)]),
            make_rw(1, vec![], vec![(hash(0xAA), 0)]),
        ];
        let g = TxDependencyGraph::build(sets);

        assert!(g.has_conflict(0, 1));
        let waw = g
            .edges
            .iter()
            .any(|&(_, _, k)| k == ConflictKind::WriteAfterWrite);
        assert!(waw, "expected WAW conflict");
    }

    #[test]
    fn test_write_after_read_conflict() {
        // tx0 reads X, tx1 writes X
        let sets = vec![
            make_rw(0, vec![(hash(0xCC), 0)], vec![(hash(0xDD), 0)]),
            make_rw(1, vec![], vec![(hash(0xCC), 0)]),
        ];
        let g = TxDependencyGraph::build(sets);

        assert!(g.has_conflict(0, 1));
        let war = g
            .edges
            .iter()
            .any(|&(_, _, k)| k == ConflictKind::WriteAfterRead);
        assert!(war, "expected WAR conflict");
    }
}
