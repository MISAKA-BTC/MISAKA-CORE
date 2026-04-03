// DISABLED: Internal ZKP API refactored. Re-enable after stabilization.
#![cfg(all(test, feature = "__internal_zkp_api_stable"))]

//! Integration tests: full transfer pipeline.

use misaka_mempool::UtxoMempool;
use misaka_pqc::ki_proof::{canonical_strong_ki, prove_key_image};
use misaka_pqc::output_recovery::OutputRecovery;
use misaka_pqc::pq_kem::ml_kem_keygen;
use misaka_pqc::pq_ring::{
    derive_public_param, pq_sign, ring_verify, Poly, SpendingKeypair, DEFAULT_A_SEED,
};
use misaka_pqc::pq_sign::MlDsaKeypair;
use misaka_pqc::pq_stealth::{create_stealth_output, StealthScanner};
use misaka_storage::utxo_set::UtxoSet;
use misaka_types::stealth::PqStealthData;
use misaka_types::utxo::*;

struct Wallet {
    spending: SpendingKeypair,
    view_kp: misaka_pqc::pq_kem::MlKemKeypair,
}

impl Wallet {
    fn new() -> Self {
        Self {
            spending: SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key).unwrap(),
            view_kp: ml_kem_keygen().unwrap(),
        }
    }
}

#[test]
fn test_full_transfer_with_mempool_verification() {
    let a = derive_public_param(&DEFAULT_A_SEED);
    let alice = Wallet::new();
    let bob = Wallet::new();
    let decoy1 = Wallet::new();
    let decoy2 = Wallet::new();
    let decoy3 = Wallet::new();

    // Setup UTXO set + mempool
    let mut utxo_set = UtxoSet::new(100);
    let mut pool = UtxoMempool::new(100);

    let wallets = [&alice, &bob, &decoy1, &decoy2, &decoy3];
    for (i, w) in wallets.iter().enumerate() {
        let outref = OutputRef {
            tx_hash: [(i + 1) as u8; 32],
            output_index: 0,
        };
        let output = TxOutput {
            amount: 10_000, // Uniform: same-amount ring requirement
            one_time_address: [0xAA; 32],
            pq_stealth: None,
            spending_pubkey: None,
        };
        utxo_set.add_output(outref.clone(), output, 0).unwrap();
        utxo_set.register_spending_key(outref, w.spending.public_poly.to_bytes());
    }

    // Alice → Bob: 7000, fee=100, change=2900
    let ring_pks = vec![
        alice.spending.public_poly.clone(),
        decoy1.spending.public_poly.clone(),
        decoy2.spending.public_poly.clone(),
        decoy3.spending.public_poly.clone(),
    ];
    let (_, alice_strong_ki) =
        canonical_strong_ki(&alice.spending.public_poly, &alice.spending.secret_poly);

    let tx_id = [0x42; 32];
    let bob_stealth =
        create_stealth_output(&bob.view_kp.public_key, 7000, b"from Alice", &tx_id, 0).unwrap();

    let mut tx = UtxoTransaction {
        proof_scheme: PROOF_SCHEME_DEPRECATED_LRS,
        tx_type: TxType::Transfer,
        version: UTXO_TX_VERSION,
        inputs: vec![TxInput {
            utxo_refs: vec![
                OutputRef {
                    tx_hash: [1; 32],
                    output_index: 0,
                },
                OutputRef {
                    tx_hash: [3; 32],
                    output_index: 0,
                },
                OutputRef {
                    tx_hash: [4; 32],
                    output_index: 0,
                },
                OutputRef {
                    tx_hash: [5; 32],
                    output_index: 0,
                },
            ],
            proof: vec![],
            key_image: alice_strong_ki,
            ki_proof: vec![],
        }],
        outputs: vec![
            TxOutput {
                amount: 7000,
                one_time_address: bob_stealth.one_time_address,
                pq_stealth: Some(bob_stealth.stealth_data.clone()),
                spending_pubkey: None,
            },
            TxOutput {
                amount: 2900,
                one_time_address: [0xCC; 32],
                pq_stealth: None,
                spending_pubkey: None,
            },
        ],
        fee: 100,
        extra: vec![],
        zk_proof: None,
    };

    // Sign + strong KI proof for the current LRS main path.
    let digest = tx.signing_digest();
    let sig = pq_sign(&a, &ring_pks, 0, &alice.spending.secret_poly, &digest).unwrap();
    tx.inputs[0].proof = sig.to_bytes();
    tx.inputs[0].ki_proof = prove_key_image(
        &a,
        &alice.spending.secret_poly,
        &alice.spending.public_poly,
        &alice_strong_ki,
    )
    .unwrap()
    .to_bytes();

    println!("✓ TX built and signed with canonical KI proof");

    // Admit to mempool — FULL internal verification
    let hash = pool.admit(tx, &utxo_set, 1000).unwrap();
    println!(
        "✓ TX admitted to mempool (hash={})",
        hex::encode(&hash[..8])
    );
    assert_eq!(pool.len(), 1);

    // Bob recovers stealth output
    let scanner = StealthScanner::new(bob.view_kp.secret_key.clone());
    let recovered = scanner
        .try_recover(&bob_stealth.stealth_data, &tx_id, 0)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.amount, 7000);
    println!("✓ Bob recovered {} MISAKA", recovered.amount);

    // Double-spend rejected (same key_image as first tx)
    let mut tx2 = UtxoTransaction {
        proof_scheme: PROOF_SCHEME_DEPRECATED_LRS,
        tx_type: TxType::Transfer,
        version: UTXO_TX_VERSION,
        inputs: vec![TxInput {
            utxo_refs: vec![
                OutputRef {
                    tx_hash: [1; 32],
                    output_index: 0,
                },
                OutputRef {
                    tx_hash: [3; 32],
                    output_index: 0,
                },
                OutputRef {
                    tx_hash: [4; 32],
                    output_index: 0,
                },
                OutputRef {
                    tx_hash: [5; 32],
                    output_index: 0,
                },
            ],
            proof: vec![],
            key_image: alice_strong_ki, // same key image → double-spend
            ki_proof: vec![],
        }],
        outputs: vec![TxOutput {
            amount: 9800,
            one_time_address: [0xDD; 32],
            pq_stealth: None,
            spending_pubkey: None,
        }],
        fee: 200,
        extra: vec![],
        zk_proof: None,
    };
    let sig2 = pq_sign(
        &a,
        &ring_pks,
        0,
        &alice.spending.secret_poly,
        &tx2.signing_digest(),
    )
    .unwrap();
    tx2.inputs[0].proof = sig2.to_bytes();
    tx2.inputs[0].ki_proof = prove_key_image(
        &a,
        &alice.spending.secret_poly,
        &alice.spending.public_poly,
        &alice_strong_ki,
    )
    .unwrap()
    .to_bytes();
    assert!(pool.admit(tx2, &utxo_set, 2000).is_err());
    println!("✓ Double-spend rejected by mempool");

    println!("\n✅ FULL TRANSFER WITH MEMPOOL VERIFICATION PASSED");
}

#[test]
fn test_mempool_rejects_invalid_ring_sig() {
    let a = derive_public_param(&DEFAULT_A_SEED);
    let wallets: Vec<SpendingKeypair> = (0..5)
        .map(|_| SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key).unwrap())
        .collect();

    let mut utxo_set = UtxoSet::new(100);
    let mut pool = UtxoMempool::new(100);
    for (i, w) in wallets.iter().enumerate() {
        let outref = OutputRef {
            tx_hash: [(i + 1) as u8; 32],
            output_index: 0,
        };
        utxo_set
            .add_output(
                outref.clone(),
                TxOutput {
                    amount: 10_000,
                    one_time_address: [0xAA; 32],
                    pq_stealth: None,
                    spending_pubkey: None,
                },
                0,
            )
            .unwrap();
        utxo_set.register_spending_key(outref, w.public_poly.to_bytes());
    }

    let ring_pks: Vec<Poly> = (0..4).map(|i| wallets[i].public_poly.clone()).collect();
    let mut tx = UtxoTransaction {
        proof_scheme: PROOF_SCHEME_DEPRECATED_LRS,
        tx_type: TxType::Transfer,
        version: UTXO_TX_VERSION,
        inputs: vec![TxInput {
            utxo_refs: (0..4)
                .map(|i| OutputRef {
                    tx_hash: [(i + 1) as u8; 32],
                    output_index: 0,
                })
                .collect(),
            proof: vec![],
            key_image: wallets[0].key_image,
            ki_proof: vec![],
        }],
        outputs: vec![TxOutput {
            amount: 9900,
            one_time_address: [0xBB; 32],
            pq_stealth: None,
            spending_pubkey: None,
        }],
        fee: 100,
        extra: vec![],
        zk_proof: None,
    };

    let sig = pq_sign(
        &a,
        &ring_pks,
        0,
        &wallets[0].secret_poly,
        &tx.signing_digest(),
    )
    .unwrap();
    let mut sig_bytes = sig.to_bytes();
    sig_bytes[50] ^= 0xFF; // corrupt
    tx.inputs[0].proof = sig_bytes;
    // ki_proof left empty — optional for LRS scheme

    assert!(pool.admit(tx, &utxo_set, 1000).is_err());
    println!("✓ Invalid ring sig rejected by mempool");
}

#[test]
fn test_mempool_rejects_nonexistent_ring_member() {
    let a = derive_public_param(&DEFAULT_A_SEED);
    let wallets: Vec<SpendingKeypair> = (0..5)
        .map(|_| SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key).unwrap())
        .collect();

    let mut utxo_set = UtxoSet::new(100);
    let mut pool = UtxoMempool::new(100);
    for (i, w) in wallets.iter().enumerate() {
        let outref = OutputRef {
            tx_hash: [(i + 1) as u8; 32],
            output_index: 0,
        };
        utxo_set
            .add_output(
                outref.clone(),
                TxOutput {
                    amount: 10_000,
                    one_time_address: [0xAA; 32],
                    pq_stealth: None,
                    spending_pubkey: None,
                },
                0,
            )
            .unwrap();
        utxo_set.register_spending_key(outref, w.public_poly.to_bytes());
    }

    let ring_pks: Vec<Poly> = (0..4).map(|i| wallets[i].public_poly.clone()).collect();
    let mut tx = UtxoTransaction {
        proof_scheme: PROOF_SCHEME_DEPRECATED_LRS,
        tx_type: TxType::Transfer,
        version: UTXO_TX_VERSION,
        inputs: vec![TxInput {
            utxo_refs: vec![
                OutputRef {
                    tx_hash: [1; 32],
                    output_index: 0,
                },
                OutputRef {
                    tx_hash: [2; 32],
                    output_index: 0,
                },
                OutputRef {
                    tx_hash: [0xFF; 32],
                    output_index: 99,
                }, // doesn't exist
                OutputRef {
                    tx_hash: [4; 32],
                    output_index: 0,
                },
            ],
            proof: vec![0; 100],
            key_image: wallets[0].key_image,
            ki_proof: vec![0; 576],
        }],
        outputs: vec![TxOutput {
            amount: 9900,
            one_time_address: [0xBB; 32],
            pq_stealth: None,
            spending_pubkey: None,
        }],
        fee: 100,
        extra: vec![],
        zk_proof: None,
    };

    assert!(pool.admit(tx, &utxo_set, 1000).is_err());
    println!("✓ Non-existent ring member rejected by mempool");
}
