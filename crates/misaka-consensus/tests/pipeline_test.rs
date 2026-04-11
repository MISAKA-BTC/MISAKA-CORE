use misaka_consensus::pipeline::header_processor::*;

use misaka_consensus::stores::ghostdag::*;
use misaka_consensus::stores::headers::*;
use misaka_consensus::stores::reachability::*;
use misaka_consensus::stores::relations::*;
use misaka_consensus::stores::statuses::*;
use misaka_consensus::ValidatorSet;
use misaka_database::prelude::*;
use std::sync::Arc;

/// Empty validator set for GhostDAG pipeline tests.
/// These tests operate on the DAG ordering layer which uses
/// genesis-like headers (no proposer_pk). The validator set is
/// required by HeaderProcessor but not exercised in these tests
/// because all test blocks use empty proposer_pk with genesis_hash
/// or chain topology tests.
fn test_validator_set() -> Arc<ValidatorSet> {
    Arc::new(ValidatorSet::new(vec![]))
}

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

#[test]
fn test_header_processor_genesis() {
    let (_d, db) = temp_db();
    let genesis_hash = test_hash(0);

    let ghostdag_store = DbGhostdagStore::new(db.clone(), 0, CachePolicy::Count(100));
    let headers_store =
        DbHeadersStore::new(db.clone(), CachePolicy::Count(100), CachePolicy::Count(100));
    let relations_store = DbRelationsStore::new(db.clone(), 0, CachePolicy::Count(100));
    let reachability_store = DbReachabilityStore::new(db.clone(), CachePolicy::Count(100));
    let statuses_store = DbStatusesStore::new(db.clone(), CachePolicy::Count(100));

    // Init genesis in stores
    ghostdag_store
        .insert(genesis_hash, &GhostdagData::genesis_data())
        .expect("genesis ghostdag");
    statuses_store
        .set(genesis_hash, BlockStatus::StatusUTXOValid)
        .expect("genesis status");

    let config = HeaderProcessorConfig {
        genesis_hash,
        max_block_parents: 10,
        ghostdag_k: 18,
        target_time_per_block_ms: 1000,
        max_block_level: 255,
        skip_proposer_validation: true, // GhostDAG-layer test
        chain_id: 0, // test chain
    };

    let processor = HeaderProcessor::new(
        config,
        db.clone(),
        ghostdag_store.clone(),
        headers_store,
        relations_store,
        reachability_store,
        statuses_store.clone(),
        test_validator_set(),
    );

    // Process a block on top of genesis
    let header = Header {
        hash: test_hash(1),
        version: 1,
        parents: vec![genesis_hash],
        hash_merkle_root: [0; 32],
        accepted_id_merkle_root: [0; 32],
        utxo_commitment: [0; 32],
        timestamp: 1000,
        bits: 0x1d00ffff,
        nonce: 0,
        daa_score: 1,
        blue_work: 1,
        blue_score: 1,
        pruning_point: genesis_hash,
        pqc_signature: vec![],
        proposer_pk: vec![],
    };

    let gd = processor.process_header(&header).expect("process");
    assert_eq!(gd.selected_parent, genesis_hash);
    assert!(gd.blue_score > 0);

    // Verify block is stored
    assert!(statuses_store.has(test_hash(1)).expect("has"));
    assert_eq!(
        statuses_store.get(test_hash(1)).expect("get"),
        BlockStatus::StatusHeaderOnly
    );

    // Duplicate should fail
    assert!(processor.process_header(&header).is_err());
}

#[test]
fn test_header_processor_chain() {
    let (_d, db) = temp_db();
    let genesis_hash = test_hash(0);

    let ghostdag_store = DbGhostdagStore::new(db.clone(), 0, CachePolicy::Count(100));
    let headers_store =
        DbHeadersStore::new(db.clone(), CachePolicy::Count(100), CachePolicy::Count(100));
    let relations_store = DbRelationsStore::new(db.clone(), 0, CachePolicy::Count(100));
    let reachability_store = DbReachabilityStore::new(db.clone(), CachePolicy::Count(100));
    let statuses_store = DbStatusesStore::new(db.clone(), CachePolicy::Count(100));

    ghostdag_store
        .insert(genesis_hash, &GhostdagData::genesis_data())
        .expect("genesis");
    statuses_store
        .set(genesis_hash, BlockStatus::StatusUTXOValid)
        .expect("genesis status");

    let processor = HeaderProcessor::new(
        HeaderProcessorConfig {
            genesis_hash,
            max_block_parents: 10,
            ghostdag_k: 18,
            target_time_per_block_ms: 1000,
            max_block_level: 255,
            skip_proposer_validation: true,
            chain_id: 0,
        },
        db.clone(),
        ghostdag_store.clone(),
        headers_store,
        relations_store,
        reachability_store,
        statuses_store,
        test_validator_set(),
    );

    // Build a chain of 10 blocks
    let mut prev = genesis_hash;
    for i in 1u8..=10 {
        let header = Header {
            hash: test_hash(i),
            version: 1,
            parents: vec![prev],
            hash_merkle_root: [0; 32],
            accepted_id_merkle_root: [0; 32],
            utxo_commitment: [0; 32],
            timestamp: i as u64 * 1000,
            bits: 0x1d00ffff,
            nonce: 0,
            daa_score: i as u64,
            blue_work: i as u128,
            blue_score: i as u64,
            pruning_point: genesis_hash,
            pqc_signature: vec![],
            proposer_pk: vec![],
        };
        let gd = processor.process_header(&header).expect("process");
        assert_eq!(gd.selected_parent, prev);
        prev = test_hash(i);
    }

    // Verify blue scores increase
    let score_5 = ghostdag_store
        .get_blue_score(&test_hash(5))
        .expect("score 5");
    let score_10 = ghostdag_store
        .get_blue_score(&test_hash(10))
        .expect("score 10");
    assert!(score_10 > score_5);
}

#[test]
fn test_transaction_validator_isolation() {
    use misaka_consensus::processes::transaction_validator::TransactionValidator;
    use misaka_consensus::stores::block_transactions::*;

    let validator = TransactionValidator::new(100, 100, 10000, 50000, 100, 18);

    // Valid tx
    let tx = StoredTransaction {
        tx_id: test_hash(1),
        inputs: vec![StoredTxInput {
            previous_tx_id: test_hash(2),
            previous_index: 0,
            sig_script: vec![1],
        }],
        outputs: vec![StoredTxOutput {
            amount: 100,
            script_public_key: vec![1],
        }],
        gas_budget: 0,
        gas_price: 0,
        is_coinbase: false,
        signature: vec![],
    };
    assert!(validator.validate_tx_in_isolation(&tx).is_ok());

    // No inputs (non-coinbase) should fail
    let bad_tx = StoredTransaction {
        tx_id: test_hash(3),
        inputs: vec![],
        outputs: vec![StoredTxOutput {
            amount: 1,
            script_public_key: vec![],
        }],
        gas_budget: 0,
        gas_price: 0,
        is_coinbase: false,
        signature: vec![],
    };
    assert!(validator.validate_tx_in_isolation(&bad_tx).is_err());

    // Coinbase with no inputs is OK
    let cb_tx = StoredTransaction {
        tx_id: test_hash(4),
        inputs: vec![],
        outputs: vec![StoredTxOutput {
            amount: 1,
            script_public_key: vec![],
        }],
        gas_budget: 0,
        gas_price: 0,
        is_coinbase: true,
        signature: vec![],
    };
    assert!(validator.validate_tx_in_isolation(&cb_tx).is_ok());
}
