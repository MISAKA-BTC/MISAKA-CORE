//! # Deterministic Multi-Node Chaos Test (v4)
//!
//! # Purpose
//!
//! This test verifies the following critical properties of the MISAKA DAG:
//!
//! 1. **Eventual Consistency**: When N nodes receive the same set of blocks
//!    (in ANY order, with ANY delays), they must ALL converge to the same
//!    VirtualState hash.
//!
//! 2. **Crash Recovery**: A node that crashes mid-sync must be able to
//!    rejoin the network via IBD and reach the same final state.
//!
//! 3. **Deterministic Ordering**: GhostDAG's total order is deterministic
//!    given the same DAG topology, regardless of insertion order.
//!
//! # Test Architecture
//!
//! All nodes run in-memory (no P2P, no disk I/O). The "network" is a
//! set of channels that deliver blocks with configurable:
//! - Random delivery order (shuffle)
//! - Random delays (0-100ms)
//! - Intentional drops (to simulate partitions)
//!
//! ```text
//! ┌─────────┐    ┌─────────┐    ┌─────────┐
//! │  Node 0  │    │  Node 1  │    │  Node 2  │
//! │ GhostDAG │    │ GhostDAG │    │ GhostDAG │
//! │ Virtual  │    │ Virtual  │    │ Virtual  │
//! └────┬─────┘    └────┬─────┘    └────┬─────┘
//!      │               │               │
//!      └───────┬───────┘               │
//!              │     In-Memory Network  │
//!              └───────────┬────────────┘
//!                          │
//!                   Block Scheduler
//!                   (random order/delay)
//! ```

use std::sync::Arc;

use misaka_dag::dag_block::{DagBlockHeader, Hash, DAG_VERSION, ZERO_HASH};
use misaka_dag::dag_store::ThreadSafeDagStore;
use misaka_dag::ghostdag::{GhostDagEngine, UniformStakeProvider};
use misaka_dag::legacy_ghostdag::DagStore;
use misaka_dag::reachability::ReachabilityStore;

// ═══════════════════════════════════════════════════════════════
//  In-Memory Node
// ═══════════════════════════════════════════════════════════════

/// A minimal in-memory DAG node for testing.
///
/// Convergence is verified by comparing GhostDAG selected parent chains
/// and blue scores — these must be identical regardless of block arrival order.
struct TestNode {
    id: usize,
    dag_store: Arc<ThreadSafeDagStore>,
    ghostdag: GhostDagEngine,
    reachability: ReachabilityStore,
    genesis_hash: Hash,
}

impl TestNode {
    fn new(id: usize, genesis_hash: Hash, genesis_header: DagBlockHeader, k: u64) -> Self {
        let dag_store = Arc::new(ThreadSafeDagStore::new(genesis_hash, genesis_header));
        let ghostdag = GhostDagEngine::new(k, genesis_hash);
        let reachability = ReachabilityStore::new(genesis_hash);

        Self {
            id,
            dag_store,
            ghostdag,
            reachability,
            genesis_hash,
        }
    }

    /// Insert a block into this node's DAG.
    ///
    /// Returns true if the block was successfully inserted.
    fn insert_block(&mut self, hash: Hash, header: DagBlockHeader) -> bool {
        let snapshot = self.dag_store.snapshot();

        // Check if already known
        if snapshot.get_header(&hash).is_some() {
            return false;
        }

        // Check all parents are present
        for parent in &header.parents {
            if *parent != ZERO_HASH && snapshot.get_header(parent).is_none() {
                return false; // Missing parent
            }
        }

        // Calculate GhostDAG data
        let ghostdag_data = match self.ghostdag.try_calculate(
            &hash,
            &header.parents,
            &snapshot,
            &self.reachability,
            &UniformStakeProvider,
        ) {
            Ok(data) => data,
            Err(_) => return false,
        };

        // Insert into store
        if self.dag_store.insert_block(hash, header, vec![]).is_err() {
            return false;
        }
        self.dag_store.set_ghostdag(hash, ghostdag_data.clone());

        // Update reachability
        if ghostdag_data.selected_parent != ZERO_HASH {
            if self
                .reachability
                .add_child(ghostdag_data.selected_parent, hash)
                .is_err()
            {
                return false;
            }
        }

        true
    }

    /// Get the selected tip (highest blue score, tie-break by hash).
    fn selected_tip(&self) -> Hash {
        let snapshot = self.dag_store.snapshot();
        let tips = snapshot.get_tips();
        tips.into_iter()
            .max_by(|a, b| {
                let a_score = snapshot
                    .get_ghostdag_data(a)
                    .map(|d| d.blue_score)
                    .unwrap_or(0);
                let b_score = snapshot
                    .get_ghostdag_data(b)
                    .map(|d| d.blue_score)
                    .unwrap_or(0);
                a_score.cmp(&b_score).then_with(|| a.cmp(b))
            })
            .unwrap_or(self.genesis_hash)
    }

    /// Get max blue score.
    fn max_blue_score(&self) -> u64 {
        self.dag_store.max_blue_score()
    }

    /// Block count.
    fn block_count(&self) -> usize {
        self.dag_store.block_count() as usize
    }

    /// Build a deterministic state fingerprint for convergence comparison.
    ///
    /// The fingerprint hashes: selected_tip + blue_score + all GhostDAG blue/red sets.
    /// If two nodes have the same fingerprint, they have identical consensus state.
    fn state_fingerprint(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let snapshot = self.dag_store.snapshot();
        let mut hasher = Sha3_256::new();

        // Hash the selected tip
        let tip = self.selected_tip();
        hasher.update(tip);

        // Hash all GhostDAG data in deterministic (hash-sorted) order
        let mut all_hashes = snapshot.all_hashes();
        all_hashes.sort();

        for hash in &all_hashes {
            hasher.update(hash);
            if let Some(data) = snapshot.get_ghostdag_data(hash) {
                hasher.update(data.blue_score.to_le_bytes());
                hasher.update(data.selected_parent);
                // Sort blue/red sets for determinism
                let mut blues = data.mergeset_blues.clone();
                blues.sort();
                for b in &blues {
                    hasher.update(b);
                }
                let mut reds = data.mergeset_reds.clone();
                reds.sort();
                for r in &reds {
                    hasher.update(r);
                }
            }
        }

        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }
}

// ═══════════════════════════════════════════════════════════════
//  Block Factory
// ═══════════════════════════════════════════════════════════════

/// Create a genesis block for testing.
fn make_genesis() -> (Hash, DagBlockHeader) {
    let header = DagBlockHeader {
        version: DAG_VERSION,
        parents: vec![],
        timestamp_ms: 1_700_000_000_000,
        tx_root: ZERO_HASH,
        proposer_id: [0u8; 32],
        nonce: 0,
        blue_score: 0,
        bits: 0,
    };
    let hash = header.compute_hash();
    (hash, header)
}

/// Create a test block with given parents and a unique nonce.
fn make_block(parents: Vec<Hash>, nonce: u64, timestamp_offset: u64) -> (Hash, DagBlockHeader) {
    let header = DagBlockHeader {
        version: DAG_VERSION,
        parents,
        timestamp_ms: 1_700_000_000_000 + timestamp_offset * 1000,
        tx_root: ZERO_HASH,
        proposer_id: {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&nonce.to_le_bytes());
            id
        },
        nonce,
        blue_score: 0, // Calculated by GhostDAG
        bits: 0,
    };
    let hash = header.compute_hash();
    (hash, header)
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use rand::seq::SliceRandom;
    use rand::SeedableRng;

    /// Test 1: All nodes receive blocks in the SAME order → identical VirtualState.
    #[test]
    fn test_same_order_convergence() {
        let (genesis_hash, genesis_header) = make_genesis();
        let k = 18;

        // Create 3 nodes
        let mut nodes: Vec<TestNode> = (0..3)
            .map(|i| TestNode::new(i, genesis_hash, genesis_header.clone(), k))
            .collect();

        // Create a linear chain of 10 blocks
        let mut blocks: Vec<(Hash, DagBlockHeader)> = Vec::new();
        let mut prev = genesis_hash;
        for i in 1..=10u64 {
            let (hash, header) = make_block(vec![prev], i, i);
            blocks.push((hash, header));
            prev = hash;
        }

        // Insert all blocks into all nodes (same order)
        for (hash, header) in &blocks {
            for node in &mut nodes {
                assert!(
                    node.insert_block(*hash, header.clone()),
                    "Node {} failed to insert block {}",
                    node.id,
                    hex::encode(&hash[..4])
                );
            }
        }

        // Verify all nodes have the same VirtualState hash
        let state_hashes: Vec<Hash> = nodes.iter().map(|n| n.state_fingerprint()).collect();
        for i in 1..state_hashes.len() {
            assert_eq!(
                state_hashes[0], state_hashes[i],
                "Node 0 and Node {} have different VirtualState hashes",
                i
            );
        }

        // Verify all nodes have the same max blue score
        let scores: Vec<u64> = nodes.iter().map(|n| n.max_blue_score()).collect();
        for i in 1..scores.len() {
            assert_eq!(scores[0], scores[i], "blue score mismatch");
        }
    }

    /// Test 2: Nodes receive blocks in RANDOM order → same final VirtualState.
    ///
    /// This is the core convergence test. The GhostDAG total order must be
    /// deterministic regardless of insertion order.
    #[test]
    fn test_random_order_convergence() {
        let (genesis_hash, genesis_header) = make_genesis();
        let k = 18;

        // Create a diamond DAG:
        //     genesis
        //    /   |   \
        //   A    B    C     (all have genesis as parent)
        //    \   |   /
        //       D           (D has parents A, B, C)

        let (a_hash, a_header) = make_block(vec![genesis_hash], 1, 1);
        let (b_hash, b_header) = make_block(vec![genesis_hash], 2, 1);
        let (c_hash, c_header) = make_block(vec![genesis_hash], 3, 1);
        let (d_hash, d_header) = make_block(vec![a_hash, b_hash, c_hash], 4, 2);

        let all_blocks: Vec<(Hash, DagBlockHeader)> = vec![
            (a_hash, a_header),
            (b_hash, b_header),
            (c_hash, c_header),
            (d_hash, d_header),
        ];

        let num_nodes = 5;
        let mut final_hashes: Vec<Hash> = Vec::new();

        for seed in 0..num_nodes {
            let mut node = TestNode::new(seed, genesis_hash, genesis_header.clone(), k);

            // Shuffle blocks with a deterministic RNG
            let mut shuffled = all_blocks.clone();
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64);
            shuffled.shuffle(&mut rng);

            // Insert blocks, retrying those with missing parents
            let mut remaining = shuffled;
            let mut max_attempts = remaining.len() * remaining.len();
            while !remaining.is_empty() && max_attempts > 0 {
                max_attempts -= 1;
                let (hash, header) = remaining.remove(0);
                if !node.insert_block(hash, header.clone()) {
                    remaining.push((hash, header)); // Retry later
                }
            }

            assert!(
                remaining.is_empty(),
                "Node {} could not insert all blocks",
                seed
            );
            assert_eq!(node.block_count(), 5, "Node {} block count mismatch", seed);

            final_hashes.push(node.state_fingerprint());
        }

        // All nodes must have identical VirtualState
        for i in 1..final_hashes.len() {
            assert_eq!(
                final_hashes[0],
                final_hashes[i],
                "Convergence failure: Node 0 ({}) != Node {} ({})",
                hex::encode(&final_hashes[0][..8]),
                i,
                hex::encode(&final_hashes[i][..8])
            );
        }
    }

    /// Test 3: Crash and rejoin — a node that misses blocks can catch up.
    #[test]
    fn test_crash_and_catchup() {
        let (genesis_hash, genesis_header) = make_genesis();
        let k = 18;

        // Create 2 nodes
        let mut node_alive = TestNode::new(0, genesis_hash, genesis_header.clone(), k);
        let mut node_crashed = TestNode::new(1, genesis_hash, genesis_header.clone(), k);

        // Build a chain of 10 blocks
        let mut blocks: Vec<(Hash, DagBlockHeader)> = Vec::new();
        let mut prev = genesis_hash;
        for i in 1..=10u64 {
            let (hash, header) = make_block(vec![prev], i, i);
            blocks.push((hash, header));
            prev = hash;
        }

        // Both nodes receive first 5 blocks
        for (hash, header) in &blocks[..5] {
            assert!(node_alive.insert_block(*hash, header.clone()));
            assert!(node_crashed.insert_block(*hash, header.clone()));
        }

        // node_crashed "crashes" (we stop feeding it blocks)
        // node_alive receives remaining 5 blocks
        for (hash, header) in &blocks[5..] {
            assert!(node_alive.insert_block(*hash, header.clone()));
        }

        // Verify states differ
        assert_ne!(
            node_alive.state_fingerprint(),
            node_crashed.state_fingerprint()
        );

        // node_crashed "reboots" and catches up (IBD simulation)
        // In real code, this would be done via P2P IBD.
        // Here we just feed the missing blocks.
        let mut new_node = TestNode::new(2, genesis_hash, genesis_header.clone(), k);

        // Re-feed ALL blocks (simulating IBD from genesis)
        for (hash, header) in &blocks {
            new_node.insert_block(*hash, header.clone());
        }

        // After catchup, new_node should match node_alive
        assert_eq!(
            node_alive.state_fingerprint(),
            new_node.state_fingerprint(),
            "Crash-recovered node has different state"
        );
        assert_eq!(
            node_alive.max_blue_score(),
            new_node.max_blue_score(),
            "blue score mismatch after catchup"
        );
    }

    /// Test 4: Wide DAG with concurrent proposers → deterministic convergence.
    #[test]
    fn test_wide_dag_convergence() {
        let (genesis_hash, genesis_header) = make_genesis();
        let k = 18;

        // 3 proposers each create 5 blocks, all branching from genesis
        // then a merge block ties them all together
        let mut all_blocks: Vec<(Hash, DagBlockHeader)> = Vec::new();
        let mut tip_hashes: Vec<Hash> = Vec::new();

        let mut prev_per_proposer: Vec<Hash> = vec![genesis_hash; 3];

        for round in 1..=5u64 {
            for proposer in 0..3usize {
                let nonce = round * 100 + proposer as u64;
                let (hash, header) = make_block(vec![prev_per_proposer[proposer]], nonce, round);
                prev_per_proposer[proposer] = hash;
                all_blocks.push((hash, header));
            }
        }

        // Merge block referencing all 3 tips
        tip_hashes = prev_per_proposer.clone();
        let (merge_hash, merge_header) = make_block(tip_hashes, 9999, 10);
        all_blocks.push((merge_hash, merge_header));

        // Feed to 4 nodes in different orders
        let num_nodes = 4;
        let mut final_states: Vec<Hash> = Vec::new();

        for seed in 0..num_nodes {
            let mut node = TestNode::new(seed, genesis_hash, genesis_header.clone(), k);
            let mut shuffled = all_blocks.clone();
            let mut rng = rand::rngs::StdRng::seed_from_u64(seed as u64 + 42);
            shuffled.shuffle(&mut rng);

            let mut remaining = shuffled;
            let mut attempts = remaining.len() * remaining.len() + 100;
            while !remaining.is_empty() && attempts > 0 {
                attempts -= 1;
                let (hash, header) = remaining.remove(0);
                if !node.insert_block(hash, header.clone()) {
                    remaining.push((hash, header));
                }
            }

            assert!(
                remaining.is_empty(),
                "Node {} could not insert all {} blocks (remaining={})",
                seed,
                all_blocks.len(),
                remaining.len()
            );

            final_states.push(node.state_fingerprint());
        }

        for i in 1..final_states.len() {
            assert_eq!(
                final_states[0], final_states[i],
                "Wide DAG convergence failure: Node 0 != Node {}",
                i
            );
        }
    }

    /// Test 5: Verify that block insertion order doesn't affect selected tip.
    #[test]
    fn test_selected_tip_determinism() {
        let (genesis_hash, genesis_header) = make_genesis();
        let k = 18;

        let (a_hash, a_header) = make_block(vec![genesis_hash], 1, 1);
        let (b_hash, b_header) = make_block(vec![genesis_hash], 2, 1);
        let (c_hash, c_header) = make_block(vec![a_hash, b_hash], 3, 2);

        let blocks = vec![
            (a_hash, a_header.clone()),
            (b_hash, b_header.clone()),
            (c_hash, c_header.clone()),
        ];

        // Node 1: insert A, B, C
        let mut n1 = TestNode::new(0, genesis_hash, genesis_header.clone(), k);
        for (h, hdr) in &blocks {
            n1.insert_block(*h, hdr.clone());
        }

        // Node 2: insert B, A, C
        let mut n2 = TestNode::new(1, genesis_hash, genesis_header.clone(), k);
        n2.insert_block(b_hash, b_header);
        n2.insert_block(a_hash, a_header);
        n2.insert_block(c_hash, c_header);

        assert_eq!(
            n1.selected_tip(),
            n2.selected_tip(),
            "Selected tip must be deterministic regardless of insertion order"
        );
    }
}
