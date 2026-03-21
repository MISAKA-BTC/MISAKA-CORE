#![cfg(feature = "stark-stub")]

use misaka_consensus::{
    resolve_tx_with_backend_family, validate_and_apply_block,
    validate_and_apply_block_zero_knowledge, BlockCandidate,
};
use misaka_pqc::{
    materialize_zkmp_stub_tx, MlDsaKeypair, PrivacyBackendFamily, SpendingKeypair, ZkmpInputWitness,
};
use misaka_storage::utxo_set::UtxoSet;
use misaka_types::utxo::{
    OutputRef, RingInput, TxOutput, TxType, UtxoTransaction, RING_SCHEME_LOGRING,
    UTXO_TX_VERSION_V3,
};

fn wallet() -> SpendingKeypair {
    SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key).unwrap()
}

fn add_ring_member(
    utxo_set: &mut UtxoSet,
    tx_byte: u8,
    amount: u64,
) -> (OutputRef, SpendingKeypair) {
    let spending = wallet();
    let outref = OutputRef {
        tx_hash: [tx_byte; 32],
        output_index: 0,
    };
    let output = TxOutput {
        amount,
        one_time_address: [tx_byte; 32],
        pq_stealth: None,
        spending_pubkey: Some(spending.public_poly.to_bytes()),
    };
    utxo_set.add_output(outref.clone(), output, 0).unwrap();
    utxo_set.register_spending_key(outref.clone(), spending.public_poly.to_bytes());
    (outref, spending)
}

fn build_zk_candidate() -> (UtxoSet, UtxoTransaction, [u8; 32]) {
    let mut utxo_set = UtxoSet::new(64);
    let ring_members_with_wallets: Vec<(OutputRef, SpendingKeypair)> = (1u8..=4)
        .map(|id| add_ring_member(&mut utxo_set, id, 10_000))
        .collect();
    let ring_members: Vec<OutputRef> = ring_members_with_wallets
        .iter()
        .map(|(outref, _)| outref.clone())
        .collect();
    let ring_pubkeys = ring_members_with_wallets
        .iter()
        .map(|(_, wallet)| wallet.public_poly.clone())
        .collect::<Vec<_>>();
    let signer_wallet = &ring_members_with_wallets[0].1;

    let recipient = wallet();
    let change = wallet();

    let mut tx = UtxoTransaction {
        version: UTXO_TX_VERSION_V3,
        ring_scheme: RING_SCHEME_LOGRING,
        tx_type: TxType::Transfer,
        inputs: vec![RingInput {
            ring_members,
            ring_signature: vec![],
            key_image: [0x44; 32],
            ki_proof: vec![],
        }],
        outputs: vec![
            TxOutput {
                amount: 7_000,
                one_time_address: [0xAA; 32],
                pq_stealth: None,
                spending_pubkey: Some(recipient.public_poly.to_bytes()),
            },
            TxOutput {
                amount: 2_900,
                one_time_address: [0xBB; 32],
                pq_stealth: None,
                spending_pubkey: Some(change.public_poly.to_bytes()),
            },
        ],
        fee: 100,
        extra: vec![],
        zk_proof: None,
    };

    let (_, _, build) = materialize_zkmp_stub_tx(
        &mut tx,
        &[10_000],
        &[ring_pubkeys],
        &[ZkmpInputWitness {
            secret_poly: signer_wallet.secret_poly.clone(),
            spent_one_time_address: [1u8; 32],
        }],
    )
    .unwrap();

    (utxo_set, tx, build.target_nullifiers[0])
}

#[test]
fn test_explicit_zero_knowledge_block_path_accepts_stub_proof() {
    let (mut utxo_set, tx, target_nullifier) = build_zk_candidate();
    let vtx = resolve_tx_with_backend_family(&tx, &utxo_set, PrivacyBackendFamily::ZeroKnowledge)
        .unwrap();
    let block = BlockCandidate {
        height: 1,
        slot: 1,
        parent_hash: [0u8; 32],
        transactions: vec![vtx],
        proposer_signature: None,
    };

    validate_and_apply_block_zero_knowledge(&block, &mut utxo_set, None).unwrap();
    assert_eq!(utxo_set.height, 1);
    assert!(utxo_set.has_key_image(&target_nullifier));
    assert_eq!(utxo_set.len(), 6);
}

#[test]
fn test_default_ring_path_rejects_same_tx_without_ring_signature() {
    let (mut utxo_set, tx, _) = build_zk_candidate();
    let vtx = resolve_tx_with_backend_family(&tx, &utxo_set, PrivacyBackendFamily::ZeroKnowledge)
        .unwrap();
    let block = BlockCandidate {
        height: 1,
        slot: 1,
        parent_hash: [0u8; 32],
        transactions: vec![vtx],
        proposer_signature: None,
    };

    let err = validate_and_apply_block(&block, &mut utxo_set, None)
        .unwrap_err()
        .to_string();
    assert!(err.contains("ring sig"));
}
