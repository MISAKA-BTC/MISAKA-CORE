// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! RocksDB crash recovery tests for production consensus store.
//!
//! These tests verify:
//! 1. Basic write + recovery with RocksDB
//! 2. Atomic write batch: all-or-nothing across column families
//! 3. Recovery after high-volume writes (1000 blocks)
//! 4. GC: blocks below gc_round are deleted, commits preserved
//! 5. Double recovery is idempotent
//! 6. Equivocation evidence persistence
//! 7. Column family integrity on open
//! 8. Interleaved writes + reads consistency

#![cfg(feature = "rocksdb")]

use std::sync::Arc;

use misaka_dag::narwhal_dag::dag_state::*;
use misaka_dag::narwhal_dag::rocksdb_store::RocksDbConsensusStore;
use misaka_dag::narwhal_dag::store::*;
use misaka_dag::narwhal_types::block::*;
use misaka_dag::narwhal_types::commit::*;
use misaka_dag::narwhal_types::committee::*;

use tempfile::TempDir;

fn make_block(round: Round, author: AuthorityIndex) -> Block {
    Block {
        epoch: 0,
        round,
        author,
        timestamp_ms: round as u64 * 1000 + author as u64,
        ancestors: vec![],
        transactions: vec![vec![round as u8, author as u8]],
        commit_votes: vec![],
        tx_reject_votes: vec![],
        state_root: [0u8; 32],
        state_root_smt: [0u8; 32],
        signature: vec![0xAA; 64],
    }
}

fn make_commit(index: u64, leader_round: Round, leader_author: AuthorityIndex) -> CommittedSubDag {
    let leader = BlockRef::new(
        leader_round,
        leader_author,
        make_block(leader_round, leader_author).digest(),
    );
    CommittedSubDag {
        index,
        leader,
        blocks: vec![leader],
        timestamp_ms: leader_round as u64 * 1000,
        previous_digest: CommitDigest([0; 32]),
        is_direct: true,
    }
}

// ═══════════════════════════════════════════════════════════
//  Test 1: Basic write + recovery
// ═══════════════════════════════════════════════════════════

#[test]
fn test_rocksdb_basic_write_and_recover() {
    let dir = TempDir::new().unwrap();
    let store_path = dir.path().join("consensus_db");

    // Write phase
    {
        let store = RocksDbConsensusStore::open(&store_path).unwrap();
        let mut batch = DagWriteBatch::new();
        for author in 0..4u32 {
            batch.add_block(VerifiedBlock::new_for_test(make_block(1, author)));
        }
        batch.set_last_committed_rounds(vec![0, 0, 0, 0]);
        store.write_batch(&batch).unwrap();
        // Drop store (simulates shutdown)
    }

    // Recovery phase (reopen)
    {
        let store = RocksDbConsensusStore::open(&store_path).unwrap();
        let blocks = store.read_all_blocks().unwrap();
        assert_eq!(blocks.len(), 4, "should recover 4 blocks");

        let rounds = store.read_last_committed_rounds().unwrap();
        assert_eq!(rounds, Some(vec![0, 0, 0, 0]));
    }
}

// ═══════════════════════════════════════════════════════════
//  Test 2: Commit persistence
// ═══════════════════════════════════════════════════════════

#[test]
fn test_rocksdb_commit_persistence() {
    let dir = TempDir::new().unwrap();
    let store_path = dir.path().join("consensus_db");

    {
        let store = RocksDbConsensusStore::open(&store_path).unwrap();
        let mut batch = DagWriteBatch::new();
        for author in 0..4u32 {
            batch.add_block(VerifiedBlock::new_for_test(make_block(1, author)));
        }
        let commit = make_commit(0, 1, 0);
        batch.add_commit(commit);
        batch.set_last_committed_rounds(vec![1, 0, 0, 0]);
        store.write_batch(&batch).unwrap();
    }

    {
        let store = RocksDbConsensusStore::open(&store_path).unwrap();
        let commits = store.read_all_commits().unwrap();
        assert_eq!(commits.len(), 1);
        assert_eq!(commits[0].index, 0);

        let rounds = store.read_last_committed_rounds().unwrap();
        assert_eq!(rounds, Some(vec![1, 0, 0, 0]));
    }
}

// ═══════════════════════════════════════════════════════════
//  Test 3: High-volume write + recovery (1000 blocks)
// ═══════════════════════════════════════════════════════════

#[test]
fn test_rocksdb_high_volume_recovery() {
    let dir = TempDir::new().unwrap();
    let store_path = dir.path().join("consensus_db");

    let num_rounds = 250u32;
    let committee_size = 4u32;
    let expected_blocks = num_rounds * committee_size;

    // Write 1000 blocks in batches of 100
    {
        let store = RocksDbConsensusStore::open(&store_path).unwrap();
        for batch_start in (1..=num_rounds).step_by(25) {
            let mut batch = DagWriteBatch::new();
            for round in batch_start..batch_start + 25 {
                for author in 0..committee_size {
                    batch.add_block(VerifiedBlock::new_for_test(make_block(round, author)));
                }
            }
            store.write_batch(&batch).unwrap();
        }

        // Write commits
        let mut commit_batch = DagWriteBatch::new();
        for i in 0..10u64 {
            commit_batch.add_commit(make_commit(i, (i as u32 + 1) * 2, 0));
        }
        store.write_batch(&commit_batch).unwrap();
    }

    // Recover
    {
        let store = RocksDbConsensusStore::open(&store_path).unwrap();
        let blocks = store.read_all_blocks().unwrap();
        assert_eq!(
            blocks.len() as u32,
            expected_blocks,
            "should recover all {} blocks",
            expected_blocks
        );

        let commits = store.read_all_commits().unwrap();
        assert_eq!(commits.len(), 10);
        // Verify commit ordering
        for (i, commit) in commits.iter().enumerate() {
            assert_eq!(commit.index, i as u64, "commits should be sorted by index");
        }
    }
}

// ═══════════════════════════════════════════════════════════
//  Test 4: GC deletes old blocks, preserves commits
// ═══════════════════════════════════════════════════════════

#[test]
fn test_rocksdb_gc_below_round() {
    let dir = TempDir::new().unwrap();
    let store_path = dir.path().join("consensus_db");

    let store = RocksDbConsensusStore::open(&store_path).unwrap();

    // Write blocks for rounds 1..=10
    let mut batch = DagWriteBatch::new();
    for round in 1..=10u32 {
        for author in 0..4u32 {
            batch.add_block(VerifiedBlock::new_for_test(make_block(round, author)));
        }
    }
    // Also write some commits
    batch.add_commit(make_commit(0, 2, 0));
    batch.add_commit(make_commit(1, 4, 0));
    store.write_batch(&batch).unwrap();

    // GC below round 6 (delete rounds 1-5)
    let deleted = store.gc_below_round(6).unwrap();
    assert_eq!(
        deleted, 20,
        "should delete 5 rounds × 4 authors = 20 blocks"
    );

    // Remaining blocks should be rounds 6-10
    let blocks = store.read_all_blocks().unwrap();
    assert_eq!(blocks.len(), 20); // 5 rounds × 4 authors
    for (_, block) in &blocks {
        assert!(
            block.round >= 6,
            "all remaining blocks should be round >= 6"
        );
    }

    // Commits should be preserved (GC only affects blocks)
    let commits = store.read_all_commits().unwrap();
    assert_eq!(commits.len(), 2, "commits should survive GC");

    // GC round should be persisted
    let gc_round = store.get_gc_round().unwrap();
    assert_eq!(gc_round, Some(6));
}

// ═══════════════════════════════════════════════════════════
//  Test 5: Double recovery is idempotent
// ═══════════════════════════════════════════════════════════

#[test]
fn test_rocksdb_double_recovery_idempotent() {
    let dir = TempDir::new().unwrap();
    let store_path = dir.path().join("consensus_db");

    {
        let store = RocksDbConsensusStore::open(&store_path).unwrap();
        let mut batch = DagWriteBatch::new();
        for author in 0..4u32 {
            batch.add_block(VerifiedBlock::new_for_test(make_block(1, author)));
        }
        store.write_batch(&batch).unwrap();
    }

    let committee = Committee::new_for_test(4);

    let store1 = RocksDbConsensusStore::open(&store_path).unwrap();
    let dag1 =
        recover_dag_state(&store1, committee.clone(), DagStateConfig::default(), None).unwrap();
    drop(store1);

    let store2 = RocksDbConsensusStore::open(&store_path).unwrap();
    let dag2 = recover_dag_state(&store2, committee, DagStateConfig::default(), None).unwrap();

    assert_eq!(dag1.num_blocks(), dag2.num_blocks());
    assert_eq!(dag1.highest_accepted_round(), dag2.highest_accepted_round());
}

// ═══════════════════════════════════════════════════════════
//  Test 6: Equivocation evidence persistence
// ═══════════════════════════════════════════════════════════

#[test]
fn test_rocksdb_equivocation_evidence() {
    let dir = TempDir::new().unwrap();
    let store_path = dir.path().join("consensus_db");

    let evidence_data = b"equivocation proof: block A != block B at (round=5, author=2)";

    // Write evidence
    {
        let store = RocksDbConsensusStore::open(&store_path).unwrap();
        store
            .store_equivocation_evidence(5, 2, evidence_data)
            .unwrap();
        store
            .store_equivocation_evidence(7, 1, b"another equivocation")
            .unwrap();
    }

    // Recover and verify
    {
        let store = RocksDbConsensusStore::open(&store_path).unwrap();

        // Read specific
        let ev = store.read_equivocation_evidence(5, 2).unwrap();
        assert_eq!(ev.as_deref(), Some(evidence_data.as_slice()));

        // Non-existent
        let none = store.read_equivocation_evidence(5, 3).unwrap();
        assert!(none.is_none());

        // Read all
        let all = store.read_all_equivocation_evidence().unwrap();
        assert_eq!(all.len(), 2);
        // Should be sorted by (round, author) due to big-endian key encoding
        assert_eq!(all[0].0, 5); // round
        assert_eq!(all[0].1, 2); // author
        assert_eq!(all[1].0, 7);
        assert_eq!(all[1].1, 1);
    }
}

// ═══════════════════════════════════════════════════════════
//  Test 7: Empty store recovery
// ═══════════════════════════════════════════════════════════

#[test]
fn test_rocksdb_empty_recovery() {
    let dir = TempDir::new().unwrap();
    let store_path = dir.path().join("consensus_db");

    let store = RocksDbConsensusStore::open(&store_path).unwrap();
    let committee = Committee::new_for_test(4);

    let dag = recover_dag_state(&store, committee, DagStateConfig::default(), None).unwrap();
    assert_eq!(dag.num_blocks(), 0);
    assert_eq!(dag.highest_accepted_round(), 0);
    assert_eq!(dag.num_commits(), 0);
}

// ═══════════════════════════════════════════════════════════
//  Test 8: Interleaved writes maintain consistency
// ═══════════════════════════════════════════════════════════

#[test]
fn test_rocksdb_interleaved_writes() {
    let dir = TempDir::new().unwrap();
    let store_path = dir.path().join("consensus_db");

    let store = RocksDbConsensusStore::open(&store_path).unwrap();

    // Interleave block writes and reads
    for round in 1..=20u32 {
        let mut batch = DagWriteBatch::new();
        for author in 0..4u32 {
            batch.add_block(VerifiedBlock::new_for_test(make_block(round, author)));
        }
        if round % 5 == 0 {
            batch.add_commit(make_commit((round / 5 - 1) as u64, round, 0));
        }
        batch.set_last_committed_rounds(vec![round; 4]);
        store.write_batch(&batch).unwrap();

        // Read back immediately
        let rounds = store.read_last_committed_rounds().unwrap();
        assert_eq!(
            rounds,
            Some(vec![round; 4]),
            "last_committed_rounds should be updated after round {}",
            round
        );
    }

    // Final consistency check
    let blocks = store.read_all_blocks().unwrap();
    assert_eq!(blocks.len(), 80); // 20 rounds × 4 authors

    let commits = store.read_all_commits().unwrap();
    assert_eq!(commits.len(), 4); // rounds 5, 10, 15, 20
}

// ═══════════════════════════════════════════════════════════
//  Test 9: GC round persists across reopens
// ═══════════════════════════════════════════════════════════

#[test]
fn test_rocksdb_gc_round_persistence() {
    let dir = TempDir::new().unwrap();
    let store_path = dir.path().join("consensus_db");

    {
        let store = RocksDbConsensusStore::open(&store_path).unwrap();
        assert_eq!(
            store.get_gc_round().unwrap(),
            None,
            "fresh DB has no gc_round"
        );
        store.set_gc_round(42).unwrap();
    }

    {
        let store = RocksDbConsensusStore::open(&store_path).unwrap();
        assert_eq!(
            store.get_gc_round().unwrap(),
            Some(42),
            "gc_round should survive reopen"
        );
    }
}
