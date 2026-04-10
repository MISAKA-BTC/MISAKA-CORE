#![cfg(feature = "json-store-dev")]
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Crash recovery tests for Narwhal/Bullshark consensus.
//!
//! Simulates node crashes and restarts:
//! 1. Crash after block acceptance, before commit → recover blocks from WAL
//! 2. Crash after commit, before checkpoint → WAL has commits
//! 3. Crash after checkpoint → snapshot has state, WAL empty
//! 4. Crash mid-WAL-write → corrupt entry skipped
//! 5. Double recovery (idempotent)

use std::sync::Arc;

use misaka_dag::narwhal_dag::dag_state::*;
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
//  Test 1: Crash after block acceptance, before commit
// ═══════════════════════════════════════════════════════════

#[test]
fn test_crash_after_blocks_before_commit() {
    let dir = TempDir::new().unwrap();
    let store = JsonFileStore::new(dir.path().join("store")).unwrap();
    let committee = Committee::new_for_test(4);

    // Phase 1: Accept blocks, persist to WAL
    {
        let mut dag = DagState::new(committee.clone(), DagStateConfig::default());
        for round in 1..=3 {
            for author in 0..4u32 {
                let block = make_block(round, author);
                dag.accept_block(VerifiedBlock::new_for_test(block));
            }
        }
        // Persist
        let batch = dag.take_write_batch();
        assert!(!batch.is_empty());
        store.write_batch(&batch).unwrap();
        // CRASH here — no commits recorded
    }

    // Phase 2: Recover
    let recovered = recover_dag_state(&store, committee, DagStateConfig::default(), None).unwrap();
    assert_eq!(recovered.num_blocks(), 12); // 3 rounds × 4 authorities
    assert_eq!(recovered.highest_accepted_round(), 3);
    assert_eq!(recovered.num_commits(), 0); // no commits were persisted
}

// ═══════════════════════════════════════════════════════════
//  Test 2: Crash after commit
// ═══════════════════════════════════════════════════════════

#[test]
fn test_crash_after_commit() {
    let dir = TempDir::new().unwrap();
    let store = JsonFileStore::new(dir.path().join("store")).unwrap();
    let committee = Committee::new_for_test(4);

    // Phase 1: Accept blocks + create commits
    {
        let mut dag = DagState::new(committee.clone(), DagStateConfig::default());
        for author in 0..4u32 {
            let block = make_block(1, author);
            dag.accept_block(VerifiedBlock::new_for_test(block));
        }

        let commit = make_commit(0, 1, 0);
        dag.record_commit(commit);

        let batch = dag.take_write_batch();
        store.write_batch(&batch).unwrap();
        // CRASH
    }

    // Phase 2: Recover
    let recovered = recover_dag_state(&store, committee, DagStateConfig::default(), None).unwrap();
    assert_eq!(recovered.num_blocks(), 4);
    assert_eq!(recovered.num_commits(), 1);
    assert_eq!(recovered.last_commit_index(), Some(0));
}

// ═══════════════════════════════════════════════════════════
//  Test 3: Crash after checkpoint
// ═══════════════════════════════════════════════════════════

#[test]
fn test_crash_after_checkpoint() {
    let dir = TempDir::new().unwrap();
    let store = JsonFileStore::new(dir.path().join("store")).unwrap();
    let committee = Committee::new_for_test(4);

    // Phase 1: Build state, checkpoint, then add more
    let blocks_phase1: Vec<Block> = (0..4u32).map(|a| make_block(1, a)).collect();
    {
        let mut dag = DagState::new(committee.clone(), DagStateConfig::default());
        for block in &blocks_phase1 {
            dag.accept_block(VerifiedBlock::new_for_test(block.clone()));
        }

        // Write WAL
        let batch = dag.take_write_batch();
        store.write_batch(&batch).unwrap();

        // Checkpoint: snapshot + truncate WAL
        store
            .checkpoint(&blocks_phase1, &[], &[1, 1, 1, 1])
            .unwrap();
    }

    // Phase 2: Add more blocks after checkpoint (to WAL only)
    {
        let blocks_phase2: Vec<Block> = (0..4u32).map(|a| make_block(2, a)).collect();
        let mut batch = DagWriteBatch::new();
        for block in &blocks_phase2 {
            batch.add_block(VerifiedBlock::new_for_test(block.clone()));
        }
        store.write_batch(&batch).unwrap();
        // CRASH
    }

    // Phase 3: Recover — should have snapshot (4) + WAL (4) = 8 blocks
    let recovered = recover_dag_state(&store, committee, DagStateConfig::default(), None).unwrap();
    assert_eq!(recovered.num_blocks(), 8);
    assert_eq!(recovered.highest_accepted_round(), 2);
}

// ═══════════════════════════════════════════════════════════
//  Test 4: Corrupt WAL entry skipped
// ═══════════════════════════════════════════════════════════

#[test]
fn test_corrupt_wal_entry_skipped() {
    let dir = TempDir::new().unwrap();
    let wal_path = dir.path().join("test.wal");

    // Write valid entries + corrupt entry
    {
        use std::io::Write;
        let wal = WriteAheadLog::new(wal_path.clone());
        let mut batch = DagWriteBatch::new();
        batch.add_block(VerifiedBlock::new_for_test(make_block(1, 0)));
        wal.append_batch(&batch).unwrap();

        // Append corrupt line
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&wal_path)
            .unwrap();
        writeln!(
            file,
            "{{\"this is\": \"corrupt json that doesn't match WalEntry\"}}"
        )
        .unwrap();

        // Write another valid entry
        let mut batch2 = DagWriteBatch::new();
        batch2.add_block(VerifiedBlock::new_for_test(make_block(2, 0)));
        wal.append_batch(&batch2).unwrap();
    }

    // Replay — should skip corrupt entry and recover both valid blocks
    let wal = WriteAheadLog::new(wal_path);
    let (blocks, _, _) = wal.replay().unwrap();
    assert_eq!(
        blocks.len(),
        2,
        "should recover 2 valid blocks, skipping corrupt entry"
    );
    assert_eq!(blocks[0].round, 1);
    assert_eq!(blocks[1].round, 2);
}

// ═══════════════════════════════════════════════════════════
//  Test 5: Double recovery is idempotent
// ═══════════════════════════════════════════════════════════

#[test]
fn test_double_recovery_idempotent() {
    let dir = TempDir::new().unwrap();
    let store = JsonFileStore::new(dir.path().join("store")).unwrap();
    let committee = Committee::new_for_test(4);

    // Write blocks
    let mut batch = DagWriteBatch::new();
    for author in 0..4u32 {
        batch.add_block(VerifiedBlock::new_for_test(make_block(1, author)));
    }
    store.write_batch(&batch).unwrap();

    // Recover twice
    let dag1 = recover_dag_state(&store, committee.clone(), DagStateConfig::default(), None).unwrap();
    let dag2 = recover_dag_state(&store, committee, DagStateConfig::default(), None).unwrap();

    assert_eq!(dag1.num_blocks(), dag2.num_blocks());
    assert_eq!(dag1.highest_accepted_round(), dag2.highest_accepted_round());
}

// ═══════════════════════════════════════════════════════════
//  Test 6: WAL + snapshot composability
// ═══════════════════════════════════════════════════════════

#[test]
fn test_wal_snapshot_compose_correctly() {
    let dir = TempDir::new().unwrap();
    let store = JsonFileStore::new(dir.path().join("store")).unwrap();

    // Write 3 rounds to WAL
    for round in 1..=3 {
        let mut batch = DagWriteBatch::new();
        for author in 0..4u32 {
            batch.add_block(VerifiedBlock::new_for_test(make_block(round, author)));
        }
        store.write_batch(&batch).unwrap();
    }

    // Checkpoint rounds 1-2 (8 blocks)
    let checkpoint_blocks: Vec<Block> = (1..=2u32)
        .flat_map(|r| (0..4u32).map(move |a| make_block(r, a)))
        .collect();
    store
        .checkpoint(&checkpoint_blocks, &[], &[2, 2, 2, 2])
        .unwrap();

    // Write round 4 to WAL (post-checkpoint)
    let mut batch = DagWriteBatch::new();
    for author in 0..4u32 {
        batch.add_block(VerifiedBlock::new_for_test(make_block(4, author)));
    }
    store.write_batch(&batch).unwrap();

    // Recover: snapshot (8 blocks, rounds 1-2) + WAL (4 blocks, round 4)
    // Note: round 3 was in old WAL but truncated at checkpoint, so it's lost.
    // This is expected — checkpoint represents committed state.
    let blocks = store.read_all_blocks().unwrap();
    assert_eq!(blocks.len(), 12); // 8 snapshot + 4 WAL
}

// ═══════════════════════════════════════════════════════════
//  Test 7: Empty WAL recovery
// ═══════════════════════════════════════════════════════════

#[test]
fn test_empty_wal_recovery() {
    let dir = TempDir::new().unwrap();
    let store = JsonFileStore::new(dir.path().join("store")).unwrap();
    let committee = Committee::new_for_test(4);

    // No writes at all
    let dag = recover_dag_state(&store, committee, DagStateConfig::default(), None).unwrap();
    assert_eq!(dag.num_blocks(), 0);
    assert_eq!(dag.highest_accepted_round(), 0);
    assert_eq!(dag.num_commits(), 0);
}
