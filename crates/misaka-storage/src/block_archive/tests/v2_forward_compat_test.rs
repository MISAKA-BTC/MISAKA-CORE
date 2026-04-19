//! v2 forward compatibility tests for the block archive.
//!
//! The `cf_tx_body` column family stores transaction bodies as opaque bytes
//! (raw `&[u8]` passed directly to `WriteBatch::put_cf`). This test suite
//! verifies that:
//!
//! 1. The archive does NOT interpret tx body contents at storage time.
//! 2. Any borsh-encoded payload (v1 today, v2 after hard fork) round-trips.
//! 3. Mixed payload sizes (10 B up to 10 KiB) are preserved byte-for-byte.
//! 4. Same-key writes exhibit last-write-wins semantics (RocksDB default).
//!
//! These guarantees mean the archive schema does NOT need to change at the
//! v2.0 hard fork — existing v1 nodes will transparently store v2 tx bodies.

use crate::block_archive::{BlockArchive, BlockMetadata, TxRef};

/// Helper: open a fresh BlockArchive in a temp directory with txindex enabled.
fn open_archive(dir: &tempfile::TempDir) -> BlockArchive {
    BlockArchive::open(dir.path(), /* txindex */ true, /* prune */ None).expect("open archive")
}

/// Helper: commit fixture so we can put_tx (put_tx requires a prior commit).
fn put_dummy_commit(archive: &BlockArchive, commit_index: u64, tx_hashes: &[[u8; 32]]) {
    let leader_hash = [u8::try_from(commit_index % 255).unwrap_or(0); 32];
    let meta = BlockMetadata {
        hash: leader_hash,
        round: commit_index as u32,
        author: 0,
        timestamp_ms: 1_700_000_000_000 + commit_index,
        commit_index,
        tx_count: tx_hashes.len() as u32,
        state_root: [0u8; 32],
        block_refs: vec![],
    };
    let tx_refs: Vec<TxRef> = tx_hashes
        .iter()
        .enumerate()
        .map(|(i, h)| TxRef {
            tx_hash: *h,
            position: i as u32,
        })
        .collect();
    archive.put_commit(&meta, &tx_refs).expect("put_commit");
}

/// Test (a): a realistic v1 UTXO tx (borsh-encoded) round-trips via tx_body CF.
#[test]
fn v1_utxo_tx_opaque_roundtrip() {
    use misaka_types::utxo::{OutputRef, TxInput, TxOutput, TxType, UtxoTransaction};
    let dir = tempfile::tempdir().expect("tempdir");
    let archive = open_archive(&dir);

    // Build a v1 UTXO tx
    let tx = UtxoTransaction {
        version: 2,
        tx_type: TxType::TransparentTransfer,
        inputs: vec![TxInput {
            utxo_refs: vec![OutputRef {
                tx_hash: [1u8; 32],
                output_index: 0,
            }],
            proof: vec![0xAA; 64],
        }],
        outputs: vec![TxOutput {
            amount: 1_000_000,
            address: [2u8; 32],
            spending_pubkey: None,
        }],
        fee: 100,
        extra: vec![],
        expiry: 0,
    };
    let raw = borsh::to_vec(&tx).expect("borsh");
    let tx_hash = tx.tx_hash();
    let commit_idx = 1u64;
    let leader_hash = [1u8; 32];

    // Must register commit first (put_commit is prerequisite for put_tx)
    put_dummy_commit(&archive, commit_idx, &[tx_hash]);

    // Opaque store
    archive
        .put_tx(tx_hash, leader_hash, commit_idx, 0, &raw)
        .expect("put_tx");

    // Opaque retrieval
    let got = archive
        .get_tx_body(&tx_hash)
        .expect("get_tx_body")
        .expect("present");
    assert_eq!(got, raw, "byte-for-byte preservation of v1 tx");

    // Confirm the archive did NOT interpret the bytes — it's still a valid
    // borsh UtxoTransaction after round-trip.
    let decoded: UtxoTransaction = borsh::from_slice(&got).expect("decode");
    assert_eq!(decoded.fee, 100);
    assert_eq!(decoded.inputs.len(), 1);
    assert_eq!(decoded.outputs.len(), 1);
}

/// Test (b): a 100-byte arbitrary payload (simulating an unknown future
/// v2 tx encoding) round-trips exactly. Proves the archive is
/// version-agnostic at the storage layer.
#[test]
fn arbitrary_100_byte_opaque_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let archive = open_archive(&dir);

    // 100 deterministic bytes that are NOT a valid UtxoTransaction
    let payload: Vec<u8> = (0..100u8).collect();
    let tx_hash = [0x42u8; 32];

    put_dummy_commit(&archive, 1, &[tx_hash]);
    archive
        .put_tx(tx_hash, [1u8; 32], 1, 0, &payload)
        .expect("put_tx");

    let got = archive
        .get_tx_body(&tx_hash)
        .expect("get_tx_body")
        .expect("present");
    assert_eq!(got, payload, "100-byte opaque payload preserved exactly");
}

/// Test (c): mixed-size payloads (10 B, 1 KiB, 10 KiB) all round-trip.
#[test]
fn mixed_size_opaque_roundtrip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let archive = open_archive(&dir);

    let sizes = [10usize, 1024, 10_240];
    let mut commit_idx = 1u64;
    for (i, &size) in sizes.iter().enumerate() {
        let payload: Vec<u8> = (0..size).map(|n| (n % 251) as u8).collect();
        let mut tx_hash = [0u8; 32];
        tx_hash[0] = i as u8;

        put_dummy_commit(&archive, commit_idx, &[tx_hash]);
        archive
            .put_tx(tx_hash, [0xAA; 32], commit_idx, 0, &payload)
            .expect("put_tx");

        let got = archive
            .get_tx_body(&tx_hash)
            .expect("get_tx_body")
            .expect("present");
        assert_eq!(got.len(), size, "length preserved for {} bytes", size);
        assert_eq!(got, payload, "content preserved for {} bytes", size);
        commit_idx += 1;
    }
}

/// Test (d): same tx_hash with different bytes → last write wins.
#[test]
fn same_tx_hash_last_write_wins() {
    let dir = tempfile::tempdir().expect("tempdir");
    let archive = open_archive(&dir);

    let tx_hash = [0x77u8; 32];
    let first = vec![0xAA; 50];
    let second = vec![0xBB; 80];

    put_dummy_commit(&archive, 1, &[tx_hash]);

    // First write
    archive
        .put_tx(tx_hash, [1u8; 32], 1, 0, &first)
        .expect("put_tx first");
    let got1 = archive
        .get_tx_body(&tx_hash)
        .expect("get")
        .expect("present");
    assert_eq!(got1, first, "first write visible");

    // Second write to same key overwrites
    archive
        .put_tx(tx_hash, [1u8; 32], 1, 0, &second)
        .expect("put_tx second");
    let got2 = archive
        .get_tx_body(&tx_hash)
        .expect("get")
        .expect("present");
    assert_eq!(got2, second, "second write overrides first");
    assert_ne!(got2, first);
}
