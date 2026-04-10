use misaka_consensus::stores::acceptance_data::*;
use misaka_consensus::stores::block_transactions::*;
use misaka_consensus::stores::daa::*;
use misaka_consensus::stores::depth::*;
use misaka_consensus::stores::ghostdag::*;
use misaka_consensus::stores::headers::*;
use misaka_consensus::stores::pruning::*;
use misaka_consensus::stores::reachability::*;
use misaka_consensus::stores::relations::*;
use misaka_consensus::stores::selected_chain::*;
use misaka_consensus::stores::statuses::*;
use misaka_consensus::stores::tips::*;
use misaka_consensus::stores::utxo_diffs::*;
use misaka_consensus::stores::virtual_state::*;
use misaka_database::prelude::*;
use std::sync::Arc;

fn temp_db() -> (tempfile::TempDir, Arc<DB>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let db = ConnBuilder::default().build(dir.path()).expect("open db");
    (dir, Arc::new(db))
}

fn test_hash(n: u8) -> Hash {
    let mut h = [0u8; 32];
    h[0] = n;
    h
}

// ── GhostDAG Store ────────────────────────────────────────────

#[test]
fn test_ghostdag_store_roundtrip() {
    let (_d, db) = temp_db();
    let store = DbGhostdagStore::new(db, 0, CachePolicy::Count(100));
    let hash = test_hash(1);
    let data = GhostdagData::new(
        10,
        100,
        test_hash(0),
        vec![test_hash(0), test_hash(2)],
        vec![test_hash(3)],
        vec![(test_hash(0), 0), (test_hash(2), 1)],
    );

    store.insert(hash, &data).expect("insert");
    assert_eq!(store.get_blue_score(&hash).expect("score"), 10);
    assert_eq!(store.get_blue_work(&hash).expect("work"), 100);
    assert_eq!(
        store.get_selected_parent(&hash).expect("parent"),
        test_hash(0)
    );
    assert!(store.has(&hash).expect("has"));

    let full = store.get_data(&hash).expect("data");
    assert_eq!(full.mergeset_blues.len(), 2);
    assert_eq!(full.mergeset_reds.len(), 1);
}

#[test]
fn test_ghostdag_batch() {
    let (_d, db) = temp_db();
    let store = DbGhostdagStore::new(db.clone(), 0, CachePolicy::Count(100));
    let mut batch = rocksdb::WriteBatch::default();
    for i in 0u8..5 {
        let data = GhostdagData::new(i as u64, i as u128, test_hash(0), vec![], vec![], vec![]);
        store
            .insert_batch(&mut batch, test_hash(i + 10), &data)
            .expect("batch");
    }
    db.write(batch).expect("commit");
    assert_eq!(store.get_blue_score(&test_hash(12)).expect("score"), 2);
}

// ── Headers Store ─────────────────────────────────────────────

#[test]
fn test_headers_store_roundtrip() {
    let (_d, db) = temp_db();
    let store = DbHeadersStore::new(db.clone(), CachePolicy::Count(100), CachePolicy::Count(100));
    let hash = test_hash(1);
    let header = Header {
        hash,
        version: 1,
        parents: vec![test_hash(0)],
        hash_merkle_root: [0; 32],
        accepted_id_merkle_root: [0; 32],
        utxo_commitment: [0; 32],
        timestamp: 1000,
        bits: 0x1d00ffff,
        nonce: 42,
        daa_score: 5,
        blue_work: 50,
        blue_score: 5,
        pruning_point: [0; 32],
        pqc_signature: vec![1, 2, 3],
        proposer_pk: vec![4, 5, 6],
    };
    let mut batch = rocksdb::WriteBatch::default();
    store
        .insert_batch(&mut batch, hash, header.clone())
        .expect("insert");
    db.write(batch).expect("commit");

    assert_eq!(store.get_timestamp(hash).expect("ts"), 1000);
    assert_eq!(store.get_daa_score(hash).expect("daa"), 5);
    assert_eq!(store.get_bits(hash).expect("bits"), 0x1d00ffff);
    assert!(store.has(hash).expect("has"));

    let full = store.get_header(hash).expect("header");
    assert_eq!(full.nonce, 42);
    assert_eq!(full.pqc_signature, vec![1, 2, 3]);
}

// ── Statuses Store ────────────────────────────────────────────

#[test]
fn test_statuses_store() {
    let (_d, db) = temp_db();
    let store = DbStatusesStore::new(db, CachePolicy::Count(100));
    let hash = test_hash(1);
    store.set(hash, BlockStatus::StatusHeaderOnly).expect("set");
    assert_eq!(store.get(hash).expect("get"), BlockStatus::StatusHeaderOnly);
    store
        .set(hash, BlockStatus::StatusUTXOValid)
        .expect("update");
    assert_eq!(store.get(hash).expect("get"), BlockStatus::StatusUTXOValid);
}

// ── Relations Store ───────────────────────────────────────────

#[test]
fn test_relations_store() {
    let (_d, db) = temp_db();
    let store = DbRelationsStore::new(db.clone(), 0, CachePolicy::Count(100));
    let parent = test_hash(1);
    let child = test_hash(2);

    // Insert parent first (so children can be updated)
    let mut b = rocksdb::WriteBatch::default();
    store
        .insert_batch(&mut b, parent, vec![])
        .expect("insert parent");
    db.write(b).expect("commit");

    let mut b2 = rocksdb::WriteBatch::default();
    store
        .insert_batch(&mut b2, child, vec![parent])
        .expect("insert child");
    db.write(b2).expect("commit");

    let parents = store.get_parents(child).expect("parents");
    assert_eq!(parents, vec![parent]);
    let children = store.get_children(parent).expect("children");
    assert_eq!(children, vec![child]);
}

// ── Reachability Store ────────────────────────────────────────

#[test]
fn test_reachability_store() {
    let (_d, db) = temp_db();
    let store = DbReachabilityStore::new(db, CachePolicy::Count(100));
    let hash = test_hash(1);
    let data = ReachabilityData {
        interval: ReachabilityInterval { start: 0, end: 100 },
        parent: test_hash(0),
        children: vec![test_hash(2), test_hash(3)],
        future_covering_set: vec![test_hash(4)],
    };
    store.insert(hash, data).expect("insert");
    let interval = store.get_interval(hash).expect("interval");
    assert_eq!(interval.start, 0);
    assert_eq!(interval.end, 100);
    assert_eq!(store.get_children(hash).expect("children").len(), 2);
}

// ── Tips Store ────────────────────────────────────────────────

#[test]
fn test_tips_store() {
    let (_d, db) = temp_db();
    let mut store = DbTipsStore::new(db);
    store.init(&[test_hash(1)]).expect("init");
    let tips = store.get().expect("get");
    assert_eq!(tips.len(), 1);

    // Add tip that replaces parent
    let new_tips = store.add_tip(test_hash(2), &[test_hash(1)]).expect("add");
    assert_eq!(new_tips.len(), 1);
    assert_eq!(new_tips[0], test_hash(2));

    // Add another tip (fork)
    let forked = store.add_tip(test_hash(3), &[]).expect("add fork");
    assert_eq!(forked.len(), 2);
}

// ── UTXO Diffs Store ──────────────────────────────────────────

#[test]
fn test_utxo_diffs_store() {
    let (_d, db) = temp_db();
    let store = DbUtxoDiffsStore::new(db.clone(), CachePolicy::Count(100));
    let hash = test_hash(1);
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
    store.insert_batch(&mut batch, hash, diff).expect("insert");
    db.write(batch).expect("commit");
    let result = store.get(hash).expect("get");
    assert_eq!(result.added.len(), 1);
    assert_eq!(result.added[0].amount, 1000);
}

// ── Selected Chain Store ──────────────────────────────────────

#[test]
fn test_selected_chain_store() {
    let (_d, db) = temp_db();
    let mut store = DbSelectedChainStore::new(db.clone(), CachePolicy::Count(100));
    let mut batch = rocksdb::WriteBatch::default();
    store
        .apply_new_chain_block(&mut batch, 0, test_hash(1))
        .expect("apply");
    store
        .apply_new_chain_block(&mut batch, 1, test_hash(2))
        .expect("apply");
    db.write(batch).expect("commit");

    assert_eq!(store.get_by_index(0).expect("idx 0"), test_hash(1));
    assert_eq!(store.get_by_index(1).expect("idx 1"), test_hash(2));
    assert_eq!(store.get_by_hash(test_hash(2)).expect("hash"), 1);
    let (idx, hash) = store.get_tip().expect("tip");
    assert_eq!(idx, 1);
    assert_eq!(hash, test_hash(2));
}

// ── Block Transactions Store ──────────────────────────────────

#[test]
fn test_block_transactions_store() {
    let (_d, db) = temp_db();
    let store = DbBlockTransactionsStore::new(db.clone(), CachePolicy::Count(100));
    let hash = test_hash(1);
    let txs = vec![StoredTransaction {
        tx_id: test_hash(10),
        inputs: vec![],
        outputs: vec![StoredTxOutput {
            amount: 500,
            script_public_key: vec![],
        }],
        gas_budget: 0,
        gas_price: 0,
        is_coinbase: true,
        signature: vec![],
    }];
    let mut batch = rocksdb::WriteBatch::default();
    store.insert_batch(&mut batch, hash, txs).expect("insert");
    db.write(batch).expect("commit");
    let result = store.get(hash).expect("get");
    assert_eq!(result.len(), 1);
    assert!(result[0].is_coinbase);
}

// ── DAA Store ─────────────────────────────────────────────────

#[test]
fn test_daa_store() {
    let (_d, db) = temp_db();
    let store = DbDaaStore::new(db.clone(), CachePolicy::Count(100));
    let mut batch = rocksdb::WriteBatch::default();
    store
        .insert_batch(&mut batch, test_hash(1), 12345)
        .expect("insert");
    db.write(batch).expect("commit");
    assert_eq!(store.get(test_hash(1)).expect("get"), 12345);
}

// ── Depth Store ───────────────────────────────────────────────

#[test]
fn test_depth_store() {
    let (_d, db) = temp_db();
    let store = DbDepthStore::new(db.clone(), CachePolicy::Count(100));
    let mut batch = rocksdb::WriteBatch::default();
    store
        .insert_batch(
            &mut batch,
            test_hash(1),
            BlockDepthData {
                merge_depth_root: test_hash(0),
                finality_point: test_hash(0),
            },
        )
        .expect("insert");
    db.write(batch).expect("commit");
    let data = store.get(test_hash(1)).expect("get");
    assert_eq!(data.merge_depth_root, test_hash(0));
}

// ── Pruning Store ─────────────────────────────────────────────

#[test]
fn test_pruning_store() {
    let (_d, db) = temp_db();
    let mut store = DbPruningStore::new(db);
    store
        .set(&PruningPointInfo {
            pruning_point: test_hash(5),
            candidate: test_hash(10),
            index: 0,
        })
        .expect("set");
    let info = store.get().expect("get");
    assert_eq!(info.pruning_point, test_hash(5));
    assert_eq!(info.index, 0);
}

// ── Virtual State Store ───────────────────────────────────────

#[test]
fn test_virtual_state_store() {
    let (_d, db) = temp_db();
    let mut store = DbVirtualStateStore::new(db);
    let state = VirtualState {
        parents: vec![test_hash(1)],
        daa_score: 100,
        bits: 0x1d00ffff,
        past_median_time: 5000,
        ..Default::default()
    };
    store.set(&state).expect("set");
    let result = store.get().expect("get");
    assert_eq!(result.daa_score, 100);
    assert_eq!(result.parents.len(), 1);
}
