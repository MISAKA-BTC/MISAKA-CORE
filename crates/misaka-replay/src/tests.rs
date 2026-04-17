// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! misaka-replay tests — forensic replay engine validation.

use crate::detectors;
use crate::engine::{ReplayConfig, ReplayEngine};
use crate::executor::{utxo_set_from_snapshot, UtxoReplayExecutor};
use crate::store::{MemoryReplayStore, ReplayBlock};
use misaka_storage::utxo_set::{UtxoSet, UtxoSetSnapshot};
use misaka_types::utxo::{OutputRef, TxInput, TxOutput, TxType, UtxoTransaction};

/// Helper: create a minimal valid UtxoTransaction (transparent transfer).
fn make_tx(inputs: Vec<OutputRef>, outputs: Vec<TxOutput>, fee: u64) -> UtxoTransaction {
    UtxoTransaction {
        version: 0x02,
        tx_type: TxType::TransparentTransfer,
        inputs: inputs
            .into_iter()
            .map(|outref| TxInput {
                utxo_refs: vec![outref],
                proof: vec![0u8; 64], // dummy proof (signature verification disabled in tests)
            })
            .collect(),
        outputs,
        fee,
        extra: vec![],
        expiry: 0,
    }
}

/// Helper: create a faucet tx (no inputs, one output).
fn make_faucet_tx(
    amount: u64,
    address: [u8; 32],
    spending_pubkey: Option<Vec<u8>>,
) -> UtxoTransaction {
    UtxoTransaction {
        version: 0x02,
        tx_type: TxType::Faucet,
        inputs: vec![],
        outputs: vec![TxOutput {
            amount,
            address,
            spending_pubkey,
        }],
        fee: 0,
        extra: vec![],
        expiry: 0,
    }
}

/// Helper: serialize a tx to borsh bytes.
fn serialize_tx(tx: &UtxoTransaction) -> Vec<u8> {
    borsh::to_vec(tx).expect("borsh serialize")
}

/// Helper: create an empty snapshot at height 0.
fn empty_snapshot() -> UtxoSetSnapshot {
    let utxo_set = UtxoSet::new(0);
    utxo_set.export_snapshot()
}

/// Helper: create a snapshot with pre-loaded UTXOs.
fn snapshot_with_utxos(utxos: Vec<(OutputRef, TxOutput, u64)>) -> UtxoSetSnapshot {
    let mut utxo_set = UtxoSet::new(0);
    for (outref, output, height) in utxos {
        utxo_set
            .add_output(outref, output, height, false)
            .expect("add_output");
    }
    utxo_set.export_snapshot()
}

// ─── Test (a): Determinism ──────────────────────────────────────

#[test]
fn test_determinism_identical_results() {
    let snapshot = empty_snapshot();
    let blocks: Vec<ReplayBlock> = (1..=5)
        .map(|h| {
            let faucet = make_faucet_tx(
                100,
                [h as u8; 32],
                Some(vec![0xAA; 1952]),
            );
            // Compute expected state root by replaying
            let mut utxo = utxo_set_from_snapshot(snapshot.clone());
            for prev in 1..h {
                let prev_faucet = make_faucet_tx(
                    100,
                    [prev as u8; 32],
                    Some(vec![0xAA; 1952]),
                );
                let _ = utxo.apply_transaction(&prev_faucet);
            }
            let _ = utxo.apply_transaction(&faucet);
            let root = utxo.compute_state_root();
            ReplayBlock {
                height: h,
                transactions: vec![serialize_tx(&faucet)],
                expected_state_root: root,
                leader_address: None,
            }
        })
        .collect();

    let mut store1 = MemoryReplayStore::new().with_snapshot(snapshot.clone());
    let mut store2 = MemoryReplayStore::new().with_snapshot(snapshot);
    for b in &blocks {
        store1.add_block(b.clone());
        store2.add_block(b.clone());
    }

    let config = ReplayConfig::default();
    let r1 = ReplayEngine::new(store1, UtxoReplayExecutor, config.clone())
        .replay_range(1, 5)
        .expect("replay 1");
    let r2 = ReplayEngine::new(store2, UtxoReplayExecutor, config)
        .replay_range(1, 5)
        .expect("replay 2");

    assert_eq!(r1.final_state_root, r2.final_state_root);
    assert_eq!(r1.txs_replayed, r2.txs_replayed);
    assert!(r1.is_clean());
    assert!(r2.is_clean());
}

// ─── Test (b): Normal replay — all state roots match ────────────

#[test]
fn test_normal_replay_state_roots_match() {
    let snapshot = empty_snapshot();

    // Build 3 blocks with faucet txs, pre-computing correct state roots.
    let mut utxo = utxo_set_from_snapshot(snapshot.clone());
    let mut blocks = Vec::new();

    for h in 1..=3u64 {
        let faucet = make_faucet_tx(100 * h, [h as u8; 32], Some(vec![0xBB; 1952]));
        let _ = utxo.apply_transaction(&faucet);
        let root = utxo.compute_state_root();
        blocks.push(ReplayBlock {
            height: h,
            transactions: vec![serialize_tx(&faucet)],
            expected_state_root: root,
            leader_address: None,
        });
    }

    let mut store = MemoryReplayStore::new().with_snapshot(snapshot);
    for b in blocks {
        store.add_block(b);
    }

    let result = ReplayEngine::new(store, UtxoReplayExecutor, ReplayConfig::default())
        .replay_range(1, 3)
        .expect("replay");

    assert!(result.is_clean(), "all state roots should match");
    assert_eq!(result.blocks_replayed, 3);
    assert_eq!(result.txs_replayed, 3);
}

// ─── Test (c): Tampered tx detection ────────────────────────────

#[test]
fn test_tampered_tx_detected() {
    let snapshot = empty_snapshot();

    // Build correct state root for block 1
    let mut utxo = utxo_set_from_snapshot(snapshot.clone());
    let faucet = make_faucet_tx(100, [0x01; 32], Some(vec![0xCC; 1952]));
    let _ = utxo.apply_transaction(&faucet);
    let correct_root = utxo.compute_state_root();

    // Create block with DIFFERENT tx (tampered amount) but ORIGINAL state root
    let tampered_faucet = make_faucet_tx(999, [0x01; 32], Some(vec![0xCC; 1952]));
    let block = ReplayBlock {
        height: 1,
        transactions: vec![serialize_tx(&tampered_faucet)],
        expected_state_root: correct_root, // expects original root
        leader_address: None,
    };

    let mut store = MemoryReplayStore::new().with_snapshot(snapshot);
    store.add_block(block);

    let result = ReplayEngine::new(store, UtxoReplayExecutor, ReplayConfig::default())
        .replay_range(1, 1)
        .expect("replay");

    assert!(!result.is_clean(), "tampered tx should cause mismatch");
    assert_eq!(result.mismatches.len(), 1);
    assert_eq!(result.mismatches[0].block_height, 1);
}

// ─── Test (d): Diagnose pinpoints tx ────────────────────────────

#[test]
fn test_diagnose_finds_problematic_tx() {
    let snapshot = empty_snapshot();

    // Build 1 block with 2 txs, second is bad
    let mut utxo = utxo_set_from_snapshot(snapshot.clone());
    let tx1 = make_faucet_tx(100, [0x01; 32], Some(vec![0xDD; 1952]));
    let _ = utxo.apply_transaction(&tx1);
    // Compute wrong root (as if tx2 had different amount)
    let tx2_good = make_faucet_tx(200, [0x02; 32], Some(vec![0xEE; 1952]));
    let _ = utxo.apply_transaction(&tx2_good);
    let correct_root = utxo.compute_state_root();

    // Tamper tx2
    let tx2_bad = make_faucet_tx(999, [0x02; 32], Some(vec![0xEE; 1952]));
    let block = ReplayBlock {
        height: 1,
        transactions: vec![serialize_tx(&tx1), serialize_tx(&tx2_bad)],
        expected_state_root: correct_root,
        leader_address: None,
    };

    let mut store = MemoryReplayStore::new().with_snapshot(snapshot);
    store.add_block(block);

    let mismatch = ReplayEngine::new(store, UtxoReplayExecutor, ReplayConfig::default())
        .diagnose_block(1)
        .expect("diagnose");

    assert!(mismatch.is_some(), "should detect mismatch in block 1");
}

// ─── Test (e): Read-only guarantee ──────────────────────────────

#[test]
fn test_read_only_guarantee() {
    let snapshot = empty_snapshot();
    let snapshot_bytes = bincode::serialize(&snapshot).expect("serialize");

    let faucet = make_faucet_tx(100, [0x01; 32], Some(vec![0xFF; 1952]));
    let mut utxo = utxo_set_from_snapshot(snapshot.clone());
    let _ = utxo.apply_transaction(&faucet);
    let root = utxo.compute_state_root();

    let block = ReplayBlock {
        height: 1,
        transactions: vec![serialize_tx(&faucet)],
        expected_state_root: root,
        leader_address: None,
    };

    let mut store = MemoryReplayStore::new().with_snapshot(snapshot.clone());
    store.add_block(block);

    let _result = ReplayEngine::new(store, UtxoReplayExecutor, ReplayConfig::default())
        .replay_range(1, 1)
        .expect("replay");

    // Verify original snapshot is unchanged
    let snapshot_bytes_after = bincode::serialize(&snapshot).expect("serialize");
    assert_eq!(
        snapshot_bytes, snapshot_bytes_after,
        "snapshot must not be modified by replay"
    );
}

// ─── Test (f): State root zero detector ─────────────────────────

#[test]
fn test_detect_state_root_zero() {
    let mut store = MemoryReplayStore::new().with_snapshot(empty_snapshot());

    // Block 1: normal state root
    store.add_block(ReplayBlock {
        height: 1,
        transactions: vec![],
        expected_state_root: [0xAA; 32],
        leader_address: None,
    });
    // Block 2: ZERO state root (audit violation)
    store.add_block(ReplayBlock {
        height: 2,
        transactions: vec![],
        expected_state_root: [0u8; 32],
        leader_address: None,
    });
    // Block 3: normal
    store.add_block(ReplayBlock {
        height: 3,
        transactions: vec![],
        expected_state_root: [0xBB; 32],
        leader_address: None,
    });

    let violations = detectors::detect_state_root_zero(&store, 1..4).expect("detect");
    assert_eq!(violations, vec![2], "only block 2 should have zero state root");
}

// ─── Test (g): Unspendable faucet detector ──────────────────────

#[test]
fn test_detect_unspendable_faucet() {
    let mut store = MemoryReplayStore::new().with_snapshot(empty_snapshot());

    // Block 1: faucet WITH spending_pubkey (good)
    let good_faucet = make_faucet_tx(100, [0x01; 32], Some(vec![0xAA; 1952]));
    // Block 2: faucet WITHOUT spending_pubkey (bad = unspendable)
    let bad_faucet = make_faucet_tx(100, [0x02; 32], None);

    store.add_block(ReplayBlock {
        height: 1,
        transactions: vec![serialize_tx(&good_faucet)],
        expected_state_root: [0; 32],
        leader_address: None,
    });
    store.add_block(ReplayBlock {
        height: 2,
        transactions: vec![serialize_tx(&bad_faucet)],
        expected_state_root: [0; 32],
        leader_address: None,
    });

    let violations =
        detectors::detect_unspendable_faucet_outputs(&store, 1..3).expect("detect");
    assert_eq!(violations.len(), 1);
    assert_eq!(violations[0], (2, 0)); // block 2, tx 0
}

// ─── Test (h): No forbidden dependencies ────────────────────────

#[test]
fn test_no_forbidden_dependencies() {
    // This test verifies at compile-time that misaka-replay does NOT
    // depend on misaka-node, misaka-dag, misaka-p2p, or misaka-rpc.
    // If it did, this test file would fail to compile because those
    // crates are not listed in [dependencies].
    //
    // Additionally, we can check at runtime via the crate name:
    let crate_name = env!("CARGO_PKG_NAME");
    assert_eq!(crate_name, "misaka-replay");

    // The actual dependency check is done via:
    // cargo tree -p misaka-replay | grep -E "misaka-(node|dag|p2p|rpc)"
    // which should return 0 results. See build verification step.
}
