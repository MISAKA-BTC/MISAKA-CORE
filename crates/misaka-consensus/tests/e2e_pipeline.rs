use misaka_consensus::pipeline::header_processor::{HeaderProcessor, HeaderProcessorConfig};
use misaka_consensus::pipeline::virtual_processor::VirtualStateProcessor;
use misaka_consensus::stores::acceptance_data::DbAcceptanceDataStore;
use misaka_consensus::stores::block_transactions::DbBlockTransactionsStore;
use misaka_consensus::stores::ghostdag::{DbGhostdagStore, GhostdagData, Hash, ZERO_HASH};
use misaka_consensus::stores::headers::{DbHeadersStore, Header};
use misaka_consensus::stores::reachability::{
    DbReachabilityStore, ReachabilityData, ReachabilityInterval,
};
use misaka_consensus::stores::relations::DbRelationsStore;
use misaka_consensus::stores::selected_chain::DbSelectedChainStore;
use misaka_consensus::stores::statuses::{BlockStatus, DbStatusesStore, StatusesStoreReader};
use misaka_consensus::stores::tips::DbTipsStore;
use misaka_consensus::stores::utxo_diffs::DbUtxoDiffsStore;
use misaka_consensus::stores::virtual_state::{DbVirtualStateStore, VirtualStateStoreReader};
use misaka_consensus::ValidatorSet;
use misaka_database::prelude::*;
use parking_lot::RwLock;
use rocksdb::WriteBatch;
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

fn test_header(
    hash: Hash,
    parents: Vec<Hash>,
    daa_score: u64,
    nonce: u64,
    pruning_point: Hash,
) -> Header {
    Header {
        hash,
        version: 1,
        parents,
        hash_merkle_root: ZERO_HASH,
        accepted_id_merkle_root: ZERO_HASH,
        utxo_commitment: ZERO_HASH,
        timestamp: 1_700_000_000_000 + (daa_score * 100),
        bits: 0x207f_ffff,
        nonce,
        daa_score,
        blue_work: daa_score as u128,
        blue_score: daa_score,
        pruning_point,
        pqc_signature: vec![],
        proposer_pk: vec![],
    }
}

#[test]
fn test_e2e_genesis_to_two_blocks_current_pipeline() {
    let (_dir, db) = temp_db();
    let genesis_hash = test_hash(0xff);
    let block1_hash = test_hash(1);
    let block2_hash = test_hash(2);
    let cache = CachePolicy::Count(1_000);
    let compact = CachePolicy::Count(10_000);

    let ghostdag_store = DbGhostdagStore::new(db.clone(), 0, compact);
    let headers_store = DbHeadersStore::new(db.clone(), cache, compact);
    let relations_store = DbRelationsStore::new(db.clone(), 0, cache);
    let reachability_store = DbReachabilityStore::new(db.clone(), cache);
    let statuses_store = DbStatusesStore::new(db.clone(), compact);
    let block_txs_store = DbBlockTransactionsStore::new(db.clone(), cache);
    let utxo_diffs_store = DbUtxoDiffsStore::new(db.clone(), cache);
    let virtual_state_store = Arc::new(RwLock::new(DbVirtualStateStore::new(db.clone())));
    let acceptance_data_store = DbAcceptanceDataStore::new(db.clone(), cache);
    let selected_chain_store = Arc::new(RwLock::new(DbSelectedChainStore::new(db.clone(), cache)));
    let tips_store = Arc::new(RwLock::new(DbTipsStore::new(db.clone())));

    let header_processor = HeaderProcessor::new(
        HeaderProcessorConfig {
            genesis_hash,
            max_block_parents: 64,
            ghostdag_k: 18,
            target_time_per_block_ms: 100,
            max_block_level: 32,
            skip_proposer_validation: true, // E2E pipeline test (GhostDAG layer)
            chain_id: 0, // test chain
        },
        db.clone(),
        ghostdag_store.clone(),
        headers_store.clone(),
        relations_store.clone(),
        reachability_store.clone(),
        statuses_store.clone(),
        Arc::new(ValidatorSet::new(vec![])),
    );
    // D2: BodyProcessor deleted — body validation is now done via direct
    // status store updates in tests.
    let virtual_processor = VirtualStateProcessor::new(
        db.clone(),
        ghostdag_store.clone(),
        headers_store.clone(),
        statuses_store.clone(),
        utxo_diffs_store,
        virtual_state_store.clone(),
        acceptance_data_store,
        selected_chain_store.clone(),
        block_txs_store,
        tips_store.clone(),
    );

    let mut genesis_batch = WriteBatch::default();
    headers_store
        .insert_batch(
            &mut genesis_batch,
            genesis_hash,
            test_header(genesis_hash, Vec::new(), 0, 0, ZERO_HASH),
        )
        .expect("genesis header");
    ghostdag_store
        .insert_batch(
            &mut genesis_batch,
            genesis_hash,
            &GhostdagData::genesis_data(),
        )
        .expect("genesis ghostdag");
    statuses_store
        .set_batch(
            &mut genesis_batch,
            genesis_hash,
            BlockStatus::StatusUTXOValid,
        )
        .expect("genesis status");
    relations_store
        .insert_batch(&mut genesis_batch, genesis_hash, Vec::new())
        .expect("genesis relations");
    reachability_store
        .insert_batch(
            &mut genesis_batch,
            genesis_hash,
            ReachabilityData {
                interval: ReachabilityInterval {
                    start: 1,
                    end: u64::MAX / 2,
                },
                parent: ZERO_HASH,
                children: Vec::new(),
                future_covering_set: Vec::new(),
            },
        )
        .expect("genesis reachability");
    selected_chain_store
        .write()
        .apply_new_chain_block(&mut genesis_batch, 0, genesis_hash)
        .expect("selected chain genesis");
    db.write(genesis_batch).expect("commit genesis batch");
    tips_store
        .write()
        .init(&[genesis_hash])
        .expect("genesis tip init");

    let block1 = test_header(block1_hash, vec![genesis_hash], 1, 1, genesis_hash);
    let block2 = test_header(block2_hash, vec![block1_hash], 2, 2, genesis_hash);

    header_processor
        .process_header(&block1)
        .expect("block1 header");
    assert_eq!(
        statuses_store.get(block1_hash).expect("block1 status"),
        BlockStatus::StatusHeaderOnly
    );

    // D2: BodyProcessor deleted — set body status directly.
    {
        let mut batch = WriteBatch::default();
        statuses_store
            .set_batch(&mut batch, block1_hash, BlockStatus::StatusBodyValid)
            .expect("block1 body status");
        db.write(batch).expect("commit block1 body batch");
    }
    assert_eq!(
        statuses_store.get(block1_hash).expect("block1 body status"),
        BlockStatus::StatusBodyValid
    );

    virtual_processor
        .process_block(block1_hash)
        .expect("block1 virtual");
    assert_eq!(
        statuses_store
            .get(block1_hash)
            .expect("block1 virtual status"),
        BlockStatus::StatusUTXOValid
    );

    header_processor
        .process_header(&block2)
        .expect("block2 header");
    assert_eq!(
        statuses_store.get(block2_hash).expect("block2 status"),
        BlockStatus::StatusHeaderOnly
    );

    // D2: BodyProcessor deleted — set body status directly.
    {
        let mut batch = WriteBatch::default();
        statuses_store
            .set_batch(&mut batch, block2_hash, BlockStatus::StatusBodyValid)
            .expect("block2 body status");
        db.write(batch).expect("commit block2 body batch");
    }
    assert_eq!(
        statuses_store.get(block2_hash).expect("block2 body status"),
        BlockStatus::StatusBodyValid
    );

    virtual_processor
        .process_block(block2_hash)
        .expect("block2 virtual");
    assert_eq!(
        statuses_store
            .get(block2_hash)
            .expect("block2 virtual status"),
        BlockStatus::StatusUTXOValid
    );

    let tips = tips_store.read().get().expect("tips");
    assert_eq!(tips, vec![block2_hash]);

    let virtual_state = virtual_state_store.read().get().expect("virtual state");
    assert_eq!(virtual_state.parents, vec![block2_hash]);
    assert_eq!(virtual_state.ghostdag_data.selected_parent, block2_hash);
    assert_eq!(virtual_state.daa_score, 3);
}
