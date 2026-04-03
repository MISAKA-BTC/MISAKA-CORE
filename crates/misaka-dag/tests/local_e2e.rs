use misaka_dag::dag_block::DAG_VERSION;
use misaka_dag::dag_state_manager::ApplyStats;
use misaka_dag::reachability::ReachabilityStore;
use misaka_dag::{
    assemble_dag_block, build_ordered_block_data, load_runtime_snapshot, replay_ordered_state,
    save_runtime_snapshot, DagBlockHeader, DagStore, FinalityManager, GhostDagEngine,
    ThreadSafeDagStore, TxApplyStatus, UniformStakeProvider, VirtualBlock, ZERO_HASH,
};
use misaka_pqc::pq_ring::{Poly, SpendingKeypair};
use misaka_pqc::pq_sign::MlDsaKeypair;
use misaka_pqc::{materialize_zkmp_stub_tx, ZkmpInputWitness};
use misaka_types::utxo::{
    OutputRef, TxInput, TxOutput, TxType, UtxoTransaction, PROOF_SCHEME_DEPRECATED_LOGRING,
    UTXO_TX_VERSION_V3,
};
use misaka_types::validator::{
    DagCheckpointFinalityProof, DagCheckpointVote, ValidatorIdentity, ValidatorPublicKey,
    ValidatorSignature,
};

type Hash = [u8; 32];

fn make_genesis_header() -> DagBlockHeader {
    DagBlockHeader {
        version: DAG_VERSION,
        parents: vec![],
        timestamp_ms: 1_700_000_000_000,
        tx_root: ZERO_HASH,
        proposer_id: [0; 32],
        nonce: 0,
        blue_score: 0,
        bits: 0,
    }
}

fn make_output(amount: u64, tag: u8) -> TxOutput {
    TxOutput {
        amount,
        one_time_address: [tag; 32],
        pq_stealth: None,
        spending_pubkey: None,
    }
}

fn make_transfer_tx(key_image: [u8; 32], amount: u64, tag: u8) -> UtxoTransaction {
    UtxoTransaction {
        version: UTXO_TX_VERSION_V3,
        proof_scheme: PROOF_SCHEME_DEPRECATED_LOGRING,
        tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            utxo_refs: vec![
                OutputRef {
                    tx_hash: [tag; 32],
                    output_index: 0,
                },
                OutputRef {
                    tx_hash: [tag.wrapping_add(1); 32],
                    output_index: 1,
                },
                OutputRef {
                    tx_hash: [tag.wrapping_add(2); 32],
                    output_index: 2,
                },
                OutputRef {
                    tx_hash: [tag.wrapping_add(3); 32],
                    output_index: 3,
                },
            ],
            proof: vec![tag; 96],
            key_image,
            ki_proof: vec![tag; 48],
        }],
        outputs: vec![make_output(amount, tag)],
        fee: 10,
        extra: vec![tag],
        zk_proof: None,
    }
}

fn make_zkmp_materialized_transfer_tx(
    amount: u64,
    tag: u8,
    shared_wallet: &SpendingKeypair,
    shared_one_time_address: [u8; 32],
) -> ([u8; 32], UtxoTransaction) {
    let mut ring_pubkeys = vec![shared_wallet.public_poly.clone()];
    ring_pubkeys.extend((0..3).map(|_| {
        SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key)
            .unwrap()
            .public_poly
    }));
    let utxo_refs: Vec<OutputRef> = ring_pubkeys
        .iter()
        .enumerate()
        .map(|(idx, _)| OutputRef {
            tx_hash: [tag.wrapping_add(idx as u8); 32],
            output_index: idx as u32,
        })
        .collect();
    let ring_pubkeys = vec![ring_pubkeys.into_iter().collect::<Vec<Poly>>()];
    let mut tx = UtxoTransaction {
        version: UTXO_TX_VERSION_V3,
        proof_scheme: PROOF_SCHEME_DEPRECATED_LOGRING,
        tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            utxo_refs,
            proof: vec![tag; 96],
            key_image: [tag; 32],
            ki_proof: vec![tag; 48],
        }],
        outputs: vec![make_output(amount, tag)],
        fee: 10,
        extra: vec![tag],
        zk_proof: None,
    };
    let witness = ZkmpInputWitness {
        secret_poly: shared_wallet.secret_poly.clone(),
        spent_one_time_address: shared_one_time_address,
    };
    let (_, statement, build) =
        materialize_zkmp_stub_tx(&mut tx, &[amount + 10], &ring_pubkeys, &[witness]).unwrap();

    assert_eq!(
        statement.target_spend_identifier_label,
        "canonicalNullifier"
    );
    assert!(tx.zk_proof.is_some());

    (build.target_nullifiers[0], tx)
}

#[test]
fn test_parallel_conflict_replay_and_checkpoint() {
    let genesis_hash: Hash = [0x01; 32];
    let dag_store = ThreadSafeDagStore::new(genesis_hash, make_genesis_header());
    let ghostdag = GhostDagEngine::new(18, genesis_hash);
    let mut reachability = ReachabilityStore::new(genesis_hash);
    let stake = UniformStakeProvider;

    let shared_ki = [0x55; 32];
    let tx_a = make_transfer_tx(shared_ki, 500, 0xA1);
    let tx_b = make_transfer_tx(shared_ki, 700, 0xB1);

    let mut block_a = assemble_dag_block(
        &[genesis_hash],
        vec![tx_a.clone()],
        [0x0A; 32],
        1_700_000_001_000,
        misaka_dag::daa::INITIAL_BITS,
    );
    let a_hash = block_a.hash();
    dag_store
        .insert_block(a_hash, block_a.header.clone(), block_a.transactions.clone())
        .unwrap();
    let mut snapshot = dag_store.snapshot();
    let sp = ghostdag.select_parent_public(&block_a.header.parents, &snapshot);
    reachability.add_child(sp, a_hash).unwrap();
    let a_data = ghostdag
        .try_calculate(
            &a_hash,
            &block_a.header.parents,
            &snapshot,
            &reachability,
            &stake,
        )
        .unwrap();
    snapshot.set_ghostdag_data(a_hash, a_data.clone());
    dag_store.set_ghostdag(a_hash, a_data);

    let mut block_b = assemble_dag_block(
        &[genesis_hash],
        vec![tx_b.clone()],
        [0x0B; 32],
        1_700_000_001_100,
        misaka_dag::daa::INITIAL_BITS,
    );
    let b_hash = block_b.hash();
    dag_store
        .insert_block(b_hash, block_b.header.clone(), block_b.transactions.clone())
        .unwrap();
    let mut snapshot = dag_store.snapshot();
    let sp = ghostdag.select_parent_public(&block_b.header.parents, &snapshot);
    reachability.add_child(sp, b_hash).unwrap();
    let b_data = ghostdag
        .try_calculate(
            &b_hash,
            &block_b.header.parents,
            &snapshot,
            &reachability,
            &stake,
        )
        .unwrap();
    snapshot.set_ghostdag_data(b_hash, b_data.clone());
    dag_store.set_ghostdag(b_hash, b_data);

    let mut block_c = assemble_dag_block(
        &[a_hash, b_hash],
        vec![],
        [0x0C; 32],
        1_700_000_002_000,
        misaka_dag::daa::INITIAL_BITS,
    );
    let c_hash = block_c.hash();
    dag_store
        .insert_block(c_hash, block_c.header.clone(), block_c.transactions.clone())
        .unwrap();
    let mut snapshot = dag_store.snapshot();
    let sp = ghostdag.select_parent_public(&block_c.header.parents, &snapshot);
    reachability.add_child(sp, c_hash).unwrap();
    let c_data = ghostdag
        .try_calculate(
            &c_hash,
            &block_c.header.parents,
            &snapshot,
            &reachability,
            &stake,
        )
        .unwrap();
    snapshot.set_ghostdag_data(c_hash, c_data.clone());
    dag_store.set_ghostdag(c_hash, c_data);

    let snapshot = dag_store.snapshot();
    let total_order = ghostdag.get_total_ordering(&snapshot);
    assert_eq!(total_order.first(), Some(&genesis_hash));
    assert!(total_order.contains(&a_hash));
    assert!(total_order.contains(&b_hash));
    assert!(total_order.contains(&c_hash));

    let ordered_data = build_ordered_block_data(&total_order, &dag_store);
    assert_eq!(ordered_data.len(), total_order.len());

    let conflict_order: Vec<[u8; 32]> = ordered_data
        .iter()
        .flat_map(|block| block.transactions.iter())
        .filter(|tx| tx.key_images.contains(&shared_ki))
        .map(|tx| tx.tx_hash)
        .collect();
    assert_eq!(conflict_order.len(), 2);
    let winner_hash = conflict_order[0];
    let loser_hash = conflict_order[1];
    assert_ne!(winner_hash, loser_hash);

    let replay = replay_ordered_state(&ordered_data, 32).unwrap();
    let results = replay.results;

    assert_eq!(results.len(), 2);
    assert!(results.iter().any(|result| {
        result.tx_hash == winner_hash && matches!(result.status, TxApplyStatus::Applied)
    }));
    assert!(results.iter().any(|result| {
        result.tx_hash == loser_hash
            && matches!(
                result.status,
                TxApplyStatus::FailedKeyImageConflict {
                    conflicting_key_image,
                    prior_tx_hash,
                } if conflicting_key_image == shared_ki && prior_tx_hash == winner_hash
            )
    }));

    assert!(replay.spent_key_images.contains(&shared_ki));
    assert_eq!(replay.state_manager.stats.txs_applied, 1);
    assert_eq!(replay.state_manager.stats.txs_failed_ki_conflict, 1);
    assert_eq!(replay.utxo_set.len(), 1);
    assert!(replay.utxo_set.is_key_image_spent(&shared_ki));
    let state_root = replay.utxo_set.compute_state_root();
    assert_ne!(state_root, [0; 32]);

    let checkpoint_tip = snapshot
        .get_tips()
        .into_iter()
        .max_by_key(|hash| {
            snapshot
                .get_ghostdag_data(hash)
                .map(|data| data.blue_score)
                .unwrap_or(0)
        })
        .unwrap();
    let checkpoint_score = snapshot
        .get_ghostdag_data(&checkpoint_tip)
        .unwrap()
        .blue_score;

    assert_eq!(checkpoint_tip, c_hash);
    assert_eq!(VirtualBlock::blue_score(&snapshot), checkpoint_score + 1);

    let mut finality = FinalityManager::new(1);
    assert!(finality.should_checkpoint(checkpoint_score));
    let checkpoint = finality.create_checkpoint(
        checkpoint_tip,
        checkpoint_score,
        state_root,
        1,
        replay.state_manager.stats.txs_applied,
    );

    assert_eq!(checkpoint.block_hash, c_hash);
    assert_eq!(checkpoint.total_key_images, 1);
    assert_eq!(checkpoint.total_applied_txs, 1);
    assert_eq!(replay.utxo_set.height, 3);
}

#[test]
fn test_snapshot_restore_preserves_checkpoint_and_state_root() {
    let genesis_hash: Hash = [0x11; 32];
    let dag_store = ThreadSafeDagStore::new(genesis_hash, make_genesis_header());
    let ghostdag = GhostDagEngine::new(18, genesis_hash);
    let mut reachability = ReachabilityStore::new(genesis_hash);
    let stake = UniformStakeProvider;

    let shared_ki = [0x66; 32];
    let tx_a = make_transfer_tx(shared_ki, 900, 0xC1);
    let tx_b = make_transfer_tx(shared_ki, 1200, 0xD1);

    let mut block_a = assemble_dag_block(
        &[genesis_hash],
        vec![tx_a.clone()],
        [0x1A; 32],
        1_700_000_101_000,
        misaka_dag::daa::INITIAL_BITS,
    );
    let a_hash = block_a.hash();
    dag_store
        .insert_block(a_hash, block_a.header.clone(), block_a.transactions.clone())
        .unwrap();
    let mut snapshot = dag_store.snapshot();
    let sp = ghostdag.select_parent_public(&block_a.header.parents, &snapshot);
    reachability.add_child(sp, a_hash).unwrap();
    let a_data = ghostdag
        .try_calculate(
            &a_hash,
            &block_a.header.parents,
            &snapshot,
            &reachability,
            &stake,
        )
        .unwrap();
    snapshot.set_ghostdag_data(a_hash, a_data.clone());
    dag_store.set_ghostdag(a_hash, a_data);

    let mut block_b = assemble_dag_block(
        &[genesis_hash],
        vec![tx_b.clone()],
        [0x1B; 32],
        1_700_000_101_100,
        misaka_dag::daa::INITIAL_BITS,
    );
    let b_hash = block_b.hash();
    dag_store
        .insert_block(b_hash, block_b.header.clone(), block_b.transactions.clone())
        .unwrap();
    let mut snapshot = dag_store.snapshot();
    let sp = ghostdag.select_parent_public(&block_b.header.parents, &snapshot);
    reachability.add_child(sp, b_hash).unwrap();
    let b_data = ghostdag
        .try_calculate(
            &b_hash,
            &block_b.header.parents,
            &snapshot,
            &reachability,
            &stake,
        )
        .unwrap();
    snapshot.set_ghostdag_data(b_hash, b_data.clone());
    dag_store.set_ghostdag(b_hash, b_data);

    let mut block_c = assemble_dag_block(
        &[a_hash, b_hash],
        vec![],
        [0x1C; 32],
        1_700_000_102_000,
        misaka_dag::daa::INITIAL_BITS,
    );
    let c_hash = block_c.hash();
    dag_store
        .insert_block(c_hash, block_c.header.clone(), block_c.transactions.clone())
        .unwrap();
    let mut snapshot = dag_store.snapshot();
    let sp = ghostdag.select_parent_public(&block_c.header.parents, &snapshot);
    reachability.add_child(sp, c_hash).unwrap();
    let c_data = ghostdag
        .try_calculate(
            &c_hash,
            &block_c.header.parents,
            &snapshot,
            &reachability,
            &stake,
        )
        .unwrap();
    snapshot.set_ghostdag_data(c_hash, c_data.clone());
    dag_store.set_ghostdag(c_hash, c_data);

    let snapshot = dag_store.snapshot();
    let total_order = ghostdag.get_total_ordering(&snapshot);
    let ordered_data = build_ordered_block_data(&total_order, &dag_store);
    let replay = replay_ordered_state(&ordered_data, 32).unwrap();
    let state_root_before = replay.utxo_set.compute_state_root();

    let checkpoint_tip = snapshot
        .get_tips()
        .into_iter()
        .max_by_key(|hash| {
            snapshot
                .get_ghostdag_data(hash)
                .map(|data| data.blue_score)
                .unwrap_or(0)
        })
        .unwrap();
    let checkpoint_score = snapshot
        .get_ghostdag_data(&checkpoint_tip)
        .unwrap()
        .blue_score;
    let mut finality = FinalityManager::new(1);
    let checkpoint = finality.create_checkpoint(
        checkpoint_tip,
        checkpoint_score,
        state_root_before,
        replay.spent_key_images.len() as u64,
        replay.state_manager.stats.txs_applied,
    );

    let base = std::env::temp_dir().join(format!(
        "misaka-dag-restore-{}.json",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    save_runtime_snapshot(
        &base,
        &dag_store,
        &replay.utxo_set,
        &replay.state_manager.stats,
        Some(&checkpoint),
        &[],
        None,
        None,
        &std::collections::HashMap::new(),
    )
    .unwrap();

    let restored = load_runtime_snapshot(&base, 32).unwrap().unwrap();
    let restored_checkpoint = restored.latest_checkpoint.expect("checkpoint restored");
    let state_root_after = restored.utxo_set.compute_state_root();

    assert_eq!(restored.genesis_hash, genesis_hash);
    assert_eq!(restored.dag_store.block_count(), dag_store.block_count());
    assert_eq!(state_root_after, state_root_before);
    assert_eq!(state_root_after, restored_checkpoint.utxo_root);
    assert_eq!(restored_checkpoint.block_hash, c_hash);
    assert_eq!(restored_checkpoint.blue_score, checkpoint_score);
    assert_eq!(restored_checkpoint.total_key_images, 1);
    assert_eq!(restored_checkpoint.total_applied_txs, 1);
    assert_eq!(restored.state_manager.stats.txs_applied, 1);
    assert_eq!(restored.state_manager.stats.txs_failed_ki_conflict, 1);
    assert!(restored.utxo_set.is_key_image_spent(&shared_ki));
    assert_eq!(restored.utxo_set.height, 3);

    let _ = std::fs::remove_file(base);
}

#[test]
fn test_snapshot_restore_preserves_validator_attestation_metadata() {
    let genesis_hash: Hash = [0x77; 32];
    let dag_store = ThreadSafeDagStore::new(genesis_hash, make_genesis_header());
    let utxo_set = misaka_storage::utxo_set::UtxoSet::new(32);
    let checkpoint = misaka_dag::DagCheckpoint {
        block_hash: [0xA1; 32],
        blue_score: 11,
        utxo_root: [0xB2; 32],
        total_key_images: 2,
        total_applied_txs: 3,
        timestamp_ms: 1_700_000_000_000,
    };
    let validator = ValidatorIdentity {
        validator_id: [0x11; 32],
        stake_weight: 1,
        public_key: ValidatorPublicKey {
            bytes: vec![0x55; 1952],
        },
        is_active: true,
    };
    let vote = DagCheckpointVote {
        voter: validator.validator_id,
        target: checkpoint.validator_target(),
        signature: ValidatorSignature {
            bytes: vec![0x66; 3309],
        },
    };
    let finality = DagCheckpointFinalityProof {
        target: checkpoint.validator_target(),
        commits: vec![vote.clone()],
    };
    let mut vote_pool = std::collections::HashMap::new();
    vote_pool.insert(checkpoint.validator_target(), vec![vote.clone()]);

    let base = std::env::temp_dir().join(format!(
        "misaka-dag-attestation-{}.json",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));

    save_runtime_snapshot(
        &base,
        &dag_store,
        &utxo_set,
        &ApplyStats::default(),
        Some(&checkpoint),
        std::slice::from_ref(&validator),
        Some(&vote),
        Some(&finality),
        &vote_pool,
    )
    .unwrap();

    let restored = load_runtime_snapshot(&base, 32).unwrap().unwrap();
    let restored_checkpoint = restored.latest_checkpoint.expect("checkpoint restored");
    assert_eq!(restored_checkpoint.block_hash, checkpoint.block_hash);
    assert_eq!(restored_checkpoint.blue_score, checkpoint.blue_score);
    assert_eq!(restored_checkpoint.utxo_root, checkpoint.utxo_root);
    assert_eq!(restored.known_validators.len(), 1);
    assert_eq!(
        restored.known_validators[0].validator_id,
        validator.validator_id
    );
    assert_eq!(
        restored
            .latest_checkpoint_vote
            .as_ref()
            .map(|vote| vote.voter),
        Some(validator.validator_id)
    );
    assert_eq!(
        restored
            .latest_checkpoint_finality
            .as_ref()
            .map(|proof| proof.commits.len()),
        Some(1)
    );
    assert_eq!(
        restored
            .checkpoint_vote_pool
            .get(&checkpoint.validator_target())
            .map(|votes| votes.len()),
        Some(1)
    );

    let _ = std::fs::remove_file(base);
}

#[test]
fn test_zkmp_materialized_parallel_conflict_replay_and_checkpoint() {
    let genesis_hash: Hash = [0x21; 32];
    let dag_store = ThreadSafeDagStore::new(genesis_hash, make_genesis_header());
    let ghostdag = GhostDagEngine::new(18, genesis_hash);
    let mut reachability = ReachabilityStore::new(genesis_hash);
    let stake = UniformStakeProvider;

    let shared_wallet = SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key).unwrap();
    let shared_one_time_address = [0x77; 32];
    let (shared_nullifier, tx_a) =
        make_zkmp_materialized_transfer_tx(500, 0xE1, &shared_wallet, shared_one_time_address);
    let (shared_nullifier_b, tx_b) =
        make_zkmp_materialized_transfer_tx(700, 0xF1, &shared_wallet, shared_one_time_address);
    assert_eq!(shared_nullifier, shared_nullifier_b);
    assert_eq!(tx_a.inputs[0].key_image, shared_nullifier);
    assert_eq!(tx_b.inputs[0].key_image, shared_nullifier);

    let mut block_a = assemble_dag_block(
        &[genesis_hash],
        vec![tx_a.clone()],
        [0x2A; 32],
        1_700_000_201_000,
        misaka_dag::daa::INITIAL_BITS,
    );
    let a_hash = block_a.hash();
    dag_store
        .insert_block(a_hash, block_a.header.clone(), block_a.transactions.clone())
        .unwrap();
    let mut snapshot = dag_store.snapshot();
    let sp = ghostdag.select_parent_public(&block_a.header.parents, &snapshot);
    reachability.add_child(sp, a_hash).unwrap();
    let a_data = ghostdag
        .try_calculate(
            &a_hash,
            &block_a.header.parents,
            &snapshot,
            &reachability,
            &stake,
        )
        .unwrap();
    snapshot.set_ghostdag_data(a_hash, a_data.clone());
    dag_store.set_ghostdag(a_hash, a_data);

    let mut block_b = assemble_dag_block(
        &[genesis_hash],
        vec![tx_b.clone()],
        [0x2B; 32],
        1_700_000_201_100,
        misaka_dag::daa::INITIAL_BITS,
    );
    let b_hash = block_b.hash();
    dag_store
        .insert_block(b_hash, block_b.header.clone(), block_b.transactions.clone())
        .unwrap();
    let mut snapshot = dag_store.snapshot();
    let sp = ghostdag.select_parent_public(&block_b.header.parents, &snapshot);
    reachability.add_child(sp, b_hash).unwrap();
    let b_data = ghostdag
        .try_calculate(
            &b_hash,
            &block_b.header.parents,
            &snapshot,
            &reachability,
            &stake,
        )
        .unwrap();
    snapshot.set_ghostdag_data(b_hash, b_data.clone());
    dag_store.set_ghostdag(b_hash, b_data);

    let mut block_c = assemble_dag_block(
        &[a_hash, b_hash],
        vec![],
        [0x2C; 32],
        1_700_000_202_000,
        misaka_dag::daa::INITIAL_BITS,
    );
    let c_hash = block_c.hash();
    dag_store
        .insert_block(c_hash, block_c.header.clone(), block_c.transactions.clone())
        .unwrap();
    let mut snapshot = dag_store.snapshot();
    let sp = ghostdag.select_parent_public(&block_c.header.parents, &snapshot);
    reachability.add_child(sp, c_hash).unwrap();
    let c_data = ghostdag
        .try_calculate(
            &c_hash,
            &block_c.header.parents,
            &snapshot,
            &reachability,
            &stake,
        )
        .unwrap();
    snapshot.set_ghostdag_data(c_hash, c_data.clone());
    dag_store.set_ghostdag(c_hash, c_data);

    let snapshot = dag_store.snapshot();
    let total_order = ghostdag.get_total_ordering(&snapshot);
    let ordered_data = build_ordered_block_data(&total_order, &dag_store);

    let conflict_order: Vec<[u8; 32]> = ordered_data
        .iter()
        .flat_map(|block| block.transactions.iter())
        .filter(|tx| tx.key_images.contains(&shared_nullifier))
        .map(|tx| tx.tx_hash)
        .collect();
    assert_eq!(conflict_order.len(), 2);

    let replay = replay_ordered_state(&ordered_data, 32).unwrap();
    assert!(replay.spent_key_images.contains(&shared_nullifier));
    assert!(replay.utxo_set.is_key_image_spent(&shared_nullifier));
    assert_eq!(replay.state_manager.stats.txs_applied, 1);
    assert_eq!(replay.state_manager.stats.txs_failed_ki_conflict, 1);
    assert!(replay.results.iter().any(|result| {
        result.tx_hash == conflict_order[0] && matches!(result.status, TxApplyStatus::Applied)
    }));
    assert!(replay.results.iter().any(|result| {
        result.tx_hash == conflict_order[1]
            && matches!(
                result.status,
                TxApplyStatus::FailedKeyImageConflict {
                    conflicting_key_image,
                    prior_tx_hash,
                } if conflicting_key_image == shared_nullifier && prior_tx_hash == conflict_order[0]
            )
    }));

    let checkpoint_tip = snapshot
        .get_tips()
        .into_iter()
        .max_by_key(|hash| {
            snapshot
                .get_ghostdag_data(hash)
                .map(|data| data.blue_score)
                .unwrap_or(0)
        })
        .unwrap();
    let checkpoint_score = snapshot
        .get_ghostdag_data(&checkpoint_tip)
        .unwrap()
        .blue_score;
    let mut finality = FinalityManager::new(1);
    let checkpoint = finality.create_checkpoint(
        checkpoint_tip,
        checkpoint_score,
        replay.utxo_set.compute_state_root(),
        replay.spent_key_images.len() as u64,
        replay.state_manager.stats.txs_applied,
    );

    assert_eq!(checkpoint.block_hash, c_hash);
    assert_eq!(checkpoint.total_key_images, 1);
}
