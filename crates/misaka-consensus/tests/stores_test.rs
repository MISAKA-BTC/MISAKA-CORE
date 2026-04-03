use misaka_consensus::stores::ghostdag::*;
use misaka_consensus::stores::headers::*;
use misaka_consensus::stores::relations::*;
use misaka_consensus::stores::statuses::*;
use misaka_consensus::stores::utxo_diffs::*;

use misaka_consensus::stores::daa::*;
use misaka_consensus::stores::depth::*;
use misaka_database::prelude::*;
use std::sync::Arc;

fn temp_db() -> (tempfile::TempDir, Arc<DB>) {
    let dir = tempfile::tempdir().expect("tmp");
    let db = ConnBuilder::default().build(dir.path()).expect("open");
    (dir, Arc::new(db))
}

fn test_hash(n: u8) -> Hash {
    let mut h = [0u8; 32];
    h[0] = n;
    h
}

#[test]
fn test_ghostdag_store_roundtrip() {
    let (_dir, db) = temp_db();
    let store = DbGhostdagStore::new(db.clone(), 0, CachePolicy::Count(100));
    let hash = test_hash(1);
    let data = GhostdagData::new(
        10,
        100,
        test_hash(0),
        vec![test_hash(0)],
        vec![test_hash(2)],
        vec![(test_hash(0), 0)],
    );
    store.insert(hash, &data).expect("insert");
    assert_eq!(store.get_blue_score(&hash).expect("score"), 10);
    assert_eq!(store.get_blue_work(&hash).expect("work"), 100);
    assert_eq!(store.get_selected_parent(&hash).expect("sp"), test_hash(0));
    assert!(store.has(&hash).expect("has"));
    assert!(!store.has(&test_hash(99)).expect("!has"));
}

#[test]
fn test_ghostdag_batch_write() {
    let (_dir, db) = temp_db();
    let store = DbGhostdagStore::new(db.clone(), 0, CachePolicy::Count(100));
    let mut batch = rocksdb::WriteBatch::default();
    let h1 = test_hash(10);
    let h2 = test_hash(20);
    let d1 = GhostdagData::new(1, 1, ZERO_HASH, vec![], vec![], vec![]);
    let d2 = GhostdagData::new(2, 2, h1, vec![h1], vec![], vec![(h1, 0)]);
    store.insert_batch(&mut batch, h1, &d1).expect("b1");
    store.insert_batch(&mut batch, h2, &d2).expect("b2");
    db.write(batch).expect("commit");
    assert_eq!(store.get_blue_score(&h1).expect("s1"), 1);
    assert_eq!(store.get_blue_score(&h2).expect("s2"), 2);
}

#[test]
fn test_headers_store_roundtrip() {
    let (_dir, db) = temp_db();
    let store = DbHeadersStore::new(db.clone(), CachePolicy::Count(100), CachePolicy::Count(100));
    let hash = test_hash(5);
    let header = Header {
        hash,
        version: 1,
        parents: vec![test_hash(0)],
        hash_merkle_root: ZERO_HASH,
        accepted_id_merkle_root: ZERO_HASH,
        utxo_commitment: ZERO_HASH,
        timestamp: 1000,
        bits: 0x1d00ffff,
        nonce: 42,
        daa_score: 100,
        blue_work: 500,
        blue_score: 50,
        pruning_point: ZERO_HASH,
        pqc_signature: vec![1, 2, 3],
        proposer_pk: vec![4, 5, 6],
    };
    let mut batch = rocksdb::WriteBatch::default();
    store
        .insert_batch(&mut batch, hash, header.clone())
        .expect("insert");
    db.write(batch).expect("commit");
    assert_eq!(store.get_daa_score(hash).expect("daa"), 100);
    assert_eq!(store.get_timestamp(hash).expect("ts"), 1000);
    assert_eq!(store.get_bits(hash).expect("bits"), 0x1d00ffff);
    assert_eq!(store.get_blue_score(hash).expect("bs"), 50);
    assert!(store.has(hash).expect("has"));
}

#[test]
fn test_statuses_store() {
    let (_dir, db) = temp_db();
    let store = DbStatusesStore::new(db.clone(), CachePolicy::Count(100));
    let hash = test_hash(7);
    store.set(hash, BlockStatus::StatusHeaderOnly).expect("set");
    assert_eq!(store.get(hash).expect("get"), BlockStatus::StatusHeaderOnly);
    store.set(hash, BlockStatus::StatusUTXOValid).expect("set2");
    assert_eq!(store.get(hash).expect("get2"), BlockStatus::StatusUTXOValid);
}

#[test]
fn test_relations_store() {
    let (_dir, db) = temp_db();
    let store = DbRelationsStore::new(db.clone(), 0, CachePolicy::Count(100));
    let parent = test_hash(1);
    let child = test_hash(2);
    let mut batch = rocksdb::WriteBatch::default();
    // Insert parent with no parents
    store.insert_batch(&mut batch, parent, vec![]).expect("p");
    // Insert child with parent
    store
        .insert_batch(&mut batch, child, vec![parent])
        .expect("c");
    db.write(batch).expect("commit");
    assert_eq!(store.get_parents(child).expect("parents"), vec![parent]);
    assert_eq!(store.get_children(parent).expect("children"), vec![child]);
}

#[test]
fn test_utxo_diffs_store() {
    let (_dir, db) = temp_db();
    let store = DbUtxoDiffsStore::new(db.clone(), CachePolicy::Count(100));
    let hash = test_hash(3);
    let diff = UtxoDiff {
        added: vec![UtxoEntry {
            outpoint: Outpoint {
                transaction_id: test_hash(10),
                index: 0,
            },
            amount: 1000,
            script_public_key: vec![1, 2],
            block_daa_score: 5,
            is_coinbase: false,
        }],
        removed: vec![],
    };
    let mut batch = rocksdb::WriteBatch::default();
    store
        .insert_batch(&mut batch, hash, diff.clone())
        .expect("insert");
    db.write(batch).expect("commit");
    let got = store.get(hash).expect("get");
    assert_eq!(got.added.len(), 1);
    assert_eq!(got.added[0].amount, 1000);
}

#[test]
fn test_daa_store() {
    let (_dir, db) = temp_db();
    let store = DbDaaStore::new(db.clone(), CachePolicy::Count(100));
    let hash = test_hash(4);
    let mut batch = rocksdb::WriteBatch::default();
    store.insert_batch(&mut batch, hash, 12345).expect("insert");
    db.write(batch).expect("commit");
    assert_eq!(store.get(hash).expect("get"), 12345);
}

#[test]
fn test_depth_store() {
    let (_dir, db) = temp_db();
    let store = DbDepthStore::new(db.clone(), CachePolicy::Count(100));
    let hash = test_hash(6);
    let data = BlockDepthData {
        merge_depth_root: test_hash(1),
        finality_point: test_hash(2),
    };
    let mut batch = rocksdb::WriteBatch::default();
    store.insert_batch(&mut batch, hash, data).expect("insert");
    db.write(batch).expect("commit");
    let got = store.get(hash).expect("get");
    assert_eq!(got.merge_depth_root, test_hash(1));
    assert_eq!(got.finality_point, test_hash(2));
}
