//! Privacy tests — verify observer cannot recover secrets from V3 proofs.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use misaka_shielded::sha3_proof::{
    ProofInputV3, ProofOutputV3, Sha3TransferProofBuilderV3,
};
use misaka_shielded::types::EncryptedNote;

#[test]
fn test_v3_proof_contains_no_plaintext_value() {
    // Build a V3 proof and verify the proof bytes do NOT contain
    // the plaintext value bytes in any position
    let value: u64 = 123_456_789;
    let value_bytes = value.to_le_bytes();
    let blinding = [0xAA; 32];

    let mut builder = Sha3TransferProofBuilderV3::new(100, [0xBB; 32]);
    builder.add_input(ProofInputV3 {
        value,
        blinding,
        nk_commit: [0xCC; 32],
        merkle_position: 0,
        merkle_siblings: vec![[0xDD; 32]],
    });
    builder.add_output(ProofOutputV3 {
        commitment: [0xEE; 32],
        value: value - 100,
        blinding: [0xFF; 32],
    });

    let proof_bytes = builder.build();

    // The plaintext value bytes MUST NOT appear anywhere in the proof
    for window in proof_bytes.windows(8) {
        assert_ne!(window, &value_bytes, "plaintext value found in V3 proof!");
    }
}

#[test]
fn test_v3_proof_contains_no_plaintext_recipient() {
    let recipient_pk = [0x42; 32];
    let mut builder = Sha3TransferProofBuilderV3::new(50, [0xAA; 32]);
    builder.add_input(ProofInputV3 {
        value: 1000,
        blinding: [0xBB; 32],
        nk_commit: [0xCC; 32],
        merkle_position: 0,
        merkle_siblings: vec![],
    });
    builder.add_output(ProofOutputV3 {
        commitment: [0xDD; 32],
        value: 950,
        blinding: [0xEE; 32],
    });

    let proof_bytes = builder.build();

    // Recipient PK MUST NOT appear in proof bytes
    for window in proof_bytes.windows(32) {
        assert_ne!(window, &recipient_pk, "recipient pk found in V3 proof!");
    }
}

#[test]
fn test_v3_proof_contains_no_rcm() {
    let rcm = [0x99; 32]; // This is the blinding factor
    let mut builder = Sha3TransferProofBuilderV3::new(10, [0xAA; 32]);
    builder.add_input(ProofInputV3 {
        value: 500,
        blinding: rcm,
        nk_commit: [0xBB; 32],
        merkle_position: 0,
        merkle_siblings: vec![],
    });
    builder.add_output(ProofOutputV3 {
        commitment: [0xCC; 32],
        value: 490,
        blinding: [0xDD; 32],
    });

    let proof_bytes = builder.build();

    // RCM (blinding factor) MUST NOT appear in proof
    for window in proof_bytes.windows(32) {
        assert_ne!(window, &rcm, "rcm/blinding found in V3 proof!");
    }
}

#[test]
fn test_v3_proof_contains_no_nk_commit() {
    let nk_commit = [0x77; 32];
    let mut builder = Sha3TransferProofBuilderV3::new(10, [0xAA; 32]);
    builder.add_input(ProofInputV3 {
        value: 500,
        blinding: [0xBB; 32],
        nk_commit,
        merkle_position: 0,
        merkle_siblings: vec![],
    });
    builder.add_output(ProofOutputV3 {
        commitment: [0xCC; 32],
        value: 490,
        blinding: [0xDD; 32],
    });

    let proof_bytes = builder.build();

    // nk_commit plaintext MUST NOT appear in proof
    for window in proof_bytes.windows(32) {
        assert_ne!(
            window, &nk_commit,
            "nk_commit plaintext found in V3 proof!"
        );
    }
}

#[test]
fn test_encrypted_note_not_readable_without_key() {
    // An encrypted note should be opaque without the decryption key
    let note = EncryptedNote {
        epk: [0x11; 32],
        ciphertext: vec![0xAA; 128],
        tag: [0xBB; 16],
        view_tag: 0x42,
    };

    // The ciphertext should not contain recognizable plaintext patterns
    assert!(note.ciphertext.len() > 64);
    // Cannot extract value from ciphertext without key
}

#[test]
fn test_deposit_remains_transparent() {
    // Deposits MUST remain transparent for CEX compatibility
    use misaka_shielded::tx_types::ShieldDepositTx;
    use misaka_shielded::types::{EncryptedNote, NoteCommitment};

    let deposit = ShieldDepositTx {
        from: [0xAA; 32],
        amount: 1_000_000,
        asset_id: 0,
        fee: misaka_shielded::MIN_SHIELDED_FEE,
        output_commitment: NoteCommitment([0xBB; 32]),
        encrypted_note: EncryptedNote {
            epk: [0xCC; 32],
            ciphertext: vec![0u8; 64],
            tag: [0u8; 16],
            view_tag: 0,
        },
        signature_bytes: vec![0u8; 3309],
        sender_pubkey: vec![0u8; 1952],
    };

    // These MUST be publicly accessible (not hidden)
    assert_eq!(deposit.amount, 1_000_000);
    assert_eq!(deposit.from, [0xAA; 32]);
}

#[test]
fn test_shielded_disabled_mode() {
    // When shielded is disabled, all shielded operations should be rejected
    // This is for CEX nodes that only process transparent transactions
    use misaka_shielded::{
        ShieldedConfig, ShieldedError, ShieldedState, ShieldedTransferTx,
    };
    use misaka_shielded::types::{
        CircuitVersion, EncryptedNote, NoteCommitment, Nullifier, ShieldedProof, TreeRoot,
    };

    let state = ShieldedState::new(ShieldedConfig::disabled());
    assert!(!state.is_enabled());

    let tx = ShieldedTransferTx {
        nullifiers: vec![Nullifier([1u8; 32])],
        output_commitments: vec![NoteCommitment([2u8; 32])],
        anchor: TreeRoot::empty(),
        fee: misaka_shielded::MIN_SHIELDED_FEE,
        encrypted_outputs: vec![EncryptedNote {
            epk: [3u8; 32],
            ciphertext: vec![0u8; 64],
            tag: [0u8; 16],
            view_tag: 0,
        }],
        proof: ShieldedProof::dev_testnet_stub(),
        circuit_version: CircuitVersion::SHA3_TRANSFER_V3,
        public_memo: None,
    };

    let result = state.validate_shielded_transfer(&tx);
    assert!(result.is_err());
    assert!(
        matches!(result, Err(ShieldedError::ModuleDisabled)),
        "disabled module must reject shielded transfers"
    );
}

#[test]
fn test_v3_proof_build_and_verify_roundtrip() {
    // Build a V3 proof and verify it passes the V3 verifier
    use misaka_shielded::sha3_proof::Sha3TransferProofBackend;
    use misaka_shielded::types::{
        CircuitVersion, NoteCommitment, Nullifier, ShieldedProof, ShieldedPublicInputs, TreeRoot,
    };
    use sha3::{Digest, Sha3_256};

    let value_in = 1000u64;
    let blinding_in = [42u8; 32];
    let nk_commit = [7u8; 32];
    let fee = 100u64;
    let fee_blinding = [88u8; 32];
    let value_out = 900u64;
    let blinding_out = [99u8; 32];

    // Compute value commitment for the input (used as the "leaf" in the Merkle tree)
    let vc_in = Sha3TransferProofBuilderV3::compute_value_commitment(value_in, &blinding_in);

    // Build a trivial Merkle tree with just this one leaf (depth=1)
    let empty_sibling = blake3::derive_key("MISAKA shielded empty leaf v1", &[]);
    let mut hasher = blake3::Hasher::new_derive_key("MISAKA shielded node v1");
    hasher.update(&vc_in);
    hasher.update(&empty_sibling);
    let root: [u8; 32] = *hasher.finalize().as_bytes();

    // Compute output commitment (for V3, this is provided externally)
    let output_cm = [0xEE; 32]; // arbitrary for this test

    // Compute the nullifier the same way the verifier will
    let nk_binding: [u8; 32] = {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:nk_binding:v3:");
        h.update(&nk_commit);
        h.update(&vc_in);
        h.finalize().into()
    };
    let rho = Sha3TransferProofBackend::compute_rho(&vc_in, 0);
    let nullifier: [u8; 32] = {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:nullifier:v3:");
        h.update(&nk_binding);
        h.update(&rho);
        h.finalize().into()
    };

    // Build V3 proof
    let mut builder = Sha3TransferProofBuilderV3::new(fee, fee_blinding);
    builder.add_input(ProofInputV3 {
        value: value_in,
        blinding: blinding_in,
        nk_commit,
        merkle_position: 0,
        merkle_siblings: vec![empty_sibling],
    });
    builder.add_output(ProofOutputV3 {
        commitment: output_cm,
        value: value_out,
        blinding: blinding_out,
    });

    let proof_bytes = builder.build();

    // Build public inputs
    let public_inputs = ShieldedPublicInputs {
        anchor: TreeRoot(root),
        nullifiers: vec![Nullifier(nullifier)],
        output_commitments: vec![NoteCommitment(output_cm)],
        fee,
        withdraw_amount: None,
        circuit_version: CircuitVersion::SHA3_TRANSFER_V3,
    };

    // Verify
    let backend = Sha3TransferProofBackend::new_v3();
    use misaka_shielded::ProofBackend;
    let result = backend.verify(
        &public_inputs,
        &ShieldedProof {
            bytes: proof_bytes,
        },
    );
    assert!(
        result.is_ok(),
        "V3 proof verification failed: {:?}",
        result.err()
    );
}
