//! Shielded Module — Integration Tests
//!
//! # テストシナリオ
//!
//! 1. `test_deposit_apply`       — ShieldDeposit を apply して tree が更新されること
//! 2. `test_withdraw_apply`      — ShieldWithdraw を apply して nullifier が記録されること
//! 3. `test_double_spend_rejected` — 同一 nullifier の二重消費が拒否されること
//! 4. `test_module_disabled`     — transparent-only モードが shielded tx を拒否すること
//! 5. `test_cex_flow`            — transparent → deposit → withdraw → transparent の経路
//! 6. `test_nullifier_reservation` — mempool reservation の排他制御
//! 7. `test_anchor_validation`   — 無効な anchor が拒否されること
//! 8. `test_payment_proof`       — PaymentProof の生成と検証
//! 9. `test_note_encrypt_decrypt` — EncryptedNote の暗号化と復号
//! 10. `test_view_tag_fast_reject` — 自分宛でない note が view tag で高速棄却されること

#![allow(clippy::expect_used, clippy::unwrap_used)]

use misaka_shielded::{
    sha3_proof::{ProofInput, ProofOutput},
    types::Note,
    CircuitVersion, EncryptedNote, IncomingViewKey, NoteCommitment, NoteScanner, Nullifier,
    NullifierKey, PaymentProof, ScannedBlock, ScannedNote, Sha3TransferProofBackend,
    Sha3TransferProofBuilder, ShieldDepositTx, ShieldWithdrawTx, ShieldedConfig, ShieldedError,
    ShieldedProof, ShieldedState, ShieldedTransferTx, TreeRoot, MIN_SHIELDED_FEE,
};

// ─── Fixtures ─────────────────────────────────────────────────────────────────

fn make_state() -> ShieldedState {
    let mut s = ShieldedState::new(ShieldedConfig::testnet());
    s.register_stub_backend_for_testnet().expect("testnet stub");
    s
}

fn make_deposit_with_commitment(
    output_commitment: NoteCommitment,
    note_byte: u8,
    amount: u64,
) -> ShieldDepositTx {
    use misaka_pqc::pq_sign::MlDsaKeypair;
    use sha3::{Digest, Sha3_256};

    // 1. ML-DSA-65 キーペア生成
    let kp = MlDsaKeypair::generate();
    let pubkey_bytes = kp.public_key.as_bytes().to_vec();

    // 2. pubkey → from address 導出
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:address:v1:");
    h.update(&pubkey_bytes);
    let hash = h.finalize();
    let mut from = [0u8; 32];
    from.copy_from_slice(&hash);

    // 3. tx 構築 (署名前)
    let mut tx = ShieldDepositTx {
        from,
        amount,
        asset_id: 0,
        fee: MIN_SHIELDED_FEE,
        output_commitment,
        encrypted_note: EncryptedNote {
            epk: [note_byte; 32],
            ciphertext: vec![note_byte; 64],
            tag: [0u8; 16],
            view_tag: 0,
        },
        signature_bytes: vec![], // placeholder
        sender_pubkey: pubkey_bytes,
    };

    // 4. signing payload → ML-DSA-65 署名
    let payload = tx.signing_payload();
    let sig = misaka_pqc::ml_dsa_sign(&kp.secret_key, &payload).expect("sign ok");
    tx.signature_bytes = sig.as_bytes().to_vec();

    tx
}

fn make_deposit(cm_byte: u8, amount: u64) -> ShieldDepositTx {
    make_deposit_with_commitment(NoteCommitment([cm_byte; 32]), cm_byte, amount)
}

fn make_stub_withdraw(
    nf_byte: u8,
    amount: u64,
    anchor: TreeRoot,
    recipient: [u8; 32],
) -> ShieldWithdrawTx {
    ShieldWithdrawTx {
        nullifiers: vec![Nullifier([nf_byte; 32])],
        anchor,
        withdraw_amount: amount,
        withdraw_recipient: recipient,
        fee: MIN_SHIELDED_FEE,
        proof: ShieldedProof::dev_testnet_stub(),
        circuit_version: CircuitVersion::STUB_V1,
    }
}

fn make_withdraw(nf_byte: u8, amount: u64) -> ShieldWithdrawTx {
    make_stub_withdraw(nf_byte, amount, TreeRoot::empty(), [9u8; 32])
}

// ─── 1. ShieldDeposit apply ───────────────────────────────────────────────────

#[test]
fn test_deposit_apply() {
    let mut state = make_state();

    let tx = make_deposit(42, 5_000_000);
    let (ws, receipt) = state
        .apply_deposit(&tx, [0u8; 32], 1)
        .expect("apply_deposit");

    // commitment が tree に追加された
    assert_eq!(state.commitment_count(), 1);
    assert_eq!(receipt.positions, vec![0u64]);
    assert_eq!(ws.commitments.len(), 1);
    assert_eq!(ws.commitments[0].1, NoteCommitment([42u8; 32]));

    // transparent debit 情報が含まれる
    let debit = ws.transparent_debit.expect("should have debit");
    assert_eq!(debit.amount, 5_000_000);
    assert_eq!(debit.fee, MIN_SHIELDED_FEE);

    // root が変化した
    assert_ne!(receipt.new_root, TreeRoot::empty());
}

// ─── 2. ShieldWithdraw apply ──────────────────────────────────────────────────

#[test]
fn test_withdraw_apply() {
    let mut state = make_state();

    let tx = make_withdraw(55, 2_000_000);
    let (ws, receipt) = state
        .apply_withdraw(&tx, [0u8; 32], 1)
        .expect("apply_withdraw");

    // nullifier が confirmed に記録された
    assert_eq!(state.nullifier_count(), 1);
    assert!(state.is_nullifier_spent(&Nullifier([55u8; 32])));

    // transparent credit 情報
    let credit = ws.transparent_credit.expect("should have credit");
    assert_eq!(credit.amount, 2_000_000);
    assert_eq!(credit.recipient, [9u8; 32]);

    assert_eq!(receipt.nullifiers_spent.len(), 1);
}

// ─── 3. Double-spend 拒否 ─────────────────────────────────────────────────────

#[test]
fn test_double_spend_rejected() {
    let mut state = make_state();

    // 1回目は成功
    state
        .apply_withdraw(&make_withdraw(77, 1_000_000), [0u8; 32], 1)
        .expect("first withdraw ok");

    // 2回目は同じ nullifier → 拒否
    let err = state
        .validate_withdraw(&make_withdraw(77, 1_000_000))
        .expect_err("should reject double spend");
    assert!(matches!(err, ShieldedError::NullifierAlreadySpent(_)));
}

// ─── 4. disabled module ───────────────────────────────────────────────────────

#[test]
fn test_module_disabled_rejects_all() {
    let state = ShieldedState::new(ShieldedConfig::disabled());

    assert!(matches!(
        state.validate_deposit(&make_deposit(1, 1_000_000)),
        Err(ShieldedError::ModuleDisabled)
    ));
    assert!(matches!(
        state.validate_withdraw(&make_withdraw(1, 500_000)),
        Err(ShieldedError::ModuleDisabled)
    ));
}

// ─── 5. CEX Flow: transparent → deposit → withdraw → transparent ─────────────
//
// MISAKAのCEX統合の標準経路をシミュレート:
//   transparent (send to self) → ShieldDeposit → ShieldWithdraw → transparent
//
// CEX は transparent 側のみを見れば入出金を確認できる。

#[test]
fn test_cex_flow() {
    use misaka_pqc::pq_sign::MlDsaKeypair;
    use sha3::{Digest, Sha3_256};

    let mut state = make_state();
    let cex_addr = [0xCEu8; 32];

    // Step 1: ユーザーが shielded pool に預ける (ShieldDeposit)
    // ML-DSA-65 キーペア生成 → 署名付き deposit
    let kp = MlDsaKeypair::generate();
    let pubkey_bytes = kp.public_key.as_bytes().to_vec();
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:address:v1:");
    h.update(&pubkey_bytes);
    let hash = h.finalize();
    let mut user_addr = [0u8; 32];
    user_addr.copy_from_slice(&hash);

    let mut deposit_tx = ShieldDepositTx {
        from: user_addr,
        amount: 10_000_000,
        asset_id: 0,
        fee: MIN_SHIELDED_FEE,
        output_commitment: NoteCommitment([0xD1u8; 32]),
        encrypted_note: EncryptedNote {
            epk: [0u8; 32],
            ciphertext: vec![0u8; 64],
            tag: [0u8; 16],
            view_tag: 0,
        },
        signature_bytes: vec![],
        sender_pubkey: pubkey_bytes,
    };
    let payload = deposit_tx.signing_payload();
    let sig = misaka_pqc::ml_dsa_sign(&kp.secret_key, &payload).expect("sign ok");
    deposit_tx.signature_bytes = sig.as_bytes().to_vec();

    let (deposit_ws, deposit_receipt) = state
        .apply_deposit(&deposit_tx, [1u8; 32], 100)
        .expect("deposit ok");

    // transparent 側で debit が発生する
    assert!(deposit_ws.transparent_debit.is_some());
    assert_eq!(
        deposit_ws.transparent_debit.as_ref().unwrap().from,
        user_addr
    );

    // Step 2: ユーザーが shielded pool から CEX アドレスへ出金 (ShieldWithdraw)
    let withdraw_tx = make_stub_withdraw(
        0xE1,
        9_000_000, // fee 引き後
        deposit_receipt.new_root,
        cex_addr,
    );
    let (withdraw_ws, _) = state
        .apply_withdraw(&withdraw_tx, [2u8; 32], 101)
        .expect("withdraw ok");

    // transparent 側で CEX への credit が発生する
    let credit = withdraw_ws.transparent_credit.as_ref().expect("credit");
    assert_eq!(credit.recipient, cex_addr);
    assert_eq!(credit.amount, 9_000_000);

    // CEX は transparent explorer で credit を確認できる
    // shielded pool の内部は見えないが、入金確認には transparent のみで十分
    println!("✅ CEX flow validated:");
    println!("   amount:       {} base units", credit.amount);
}

#[test]
fn test_real_sha3_transfer_apply() {
    let mut state = ShieldedState::new(ShieldedConfig::default());
    state.register_sha3_backend();

    let input_value = 10_000_000u64;
    let output_value = input_value - MIN_SHIELDED_FEE;
    let nk_commit = [0x71u8; 32];
    let input_rcm = [0x52u8; 32];
    let output_rcm = [0x99u8; 32];
    let recipient_pk = [0x55u8; 32];

    let input_commitment = NoteCommitment(Sha3TransferProofBackend::compute_commitment(
        input_value,
        0,
        &nk_commit,
        &input_rcm,
    ));
    let deposit_tx = make_deposit_with_commitment(input_commitment, 0xD4, input_value);
    let (_, deposit_receipt) = state
        .apply_deposit(&deposit_tx, [0x11u8; 32], 100)
        .expect("deposit ok");

    let witness = state.merkle_witness(0).expect("witness");
    let auth_path = witness.auth_path.clone();
    assert_eq!(
        deposit_receipt.new_root.0,
        Sha3TransferProofBackend::recompute_merkle_root(
            input_commitment.as_bytes(),
            witness.position as u32,
            &auth_path
        )
    );

    let mut builder = Sha3TransferProofBuilder::new(MIN_SHIELDED_FEE);
    builder.add_input(ProofInput {
        position: witness.position as u32,
        merkle_siblings: auth_path,
        value: input_value,
        asset_id: 0,
        rcm: input_rcm,
        nk_commit,
    });
    builder.add_output(ProofOutput {
        value: output_value,
        asset_id: 0,
        recipient_pk,
        rcm: output_rcm,
    });
    let (proof, nullifiers, commitments) = builder.build().expect("proof build");

    let transfer_tx = ShieldedTransferTx {
        nullifiers: nullifiers.clone(),
        output_commitments: commitments.clone(),
        anchor: deposit_receipt.new_root,
        fee: MIN_SHIELDED_FEE,
        encrypted_outputs: vec![EncryptedNote {
            epk: [0x22u8; 32],
            ciphertext: vec![0x44u8; 64],
            tag: [0u8; 16],
            view_tag: 0,
        }],
        proof,
        circuit_version: CircuitVersion::SHA3_TRANSFER_V2,
        public_memo: Some(b"sha3 transfer integration".to_vec()),
    };

    state
        .validate_shielded_transfer(&transfer_tx)
        .expect("validate transfer");
    let (write_set, receipt) = state
        .apply_shielded_transfer(&transfer_tx, [0x22u8; 32], 101)
        .expect("apply transfer");

    assert_eq!(receipt.nullifiers_spent, nullifiers);
    assert_eq!(receipt.commitments_added, commitments);
    assert_eq!(receipt.positions, vec![1u64]);
    assert_eq!(write_set.commitments.len(), 1);
    assert_eq!(write_set.encrypted_notes.len(), 1);
    assert!(write_set.transparent_credit.is_none());
    assert!(write_set.transparent_debit.is_none());
    assert_eq!(state.commitment_count(), 2);
    assert_eq!(state.nullifier_count(), 1);
}

// ─── 6. Nullifier reservation ────────────────────────────────────────────────

#[test]
fn test_nullifier_reservation_exclusive() {
    let mut state = make_state();
    let nf = Nullifier([0x42u8; 32]);
    let tx1 = [1u8; 32];
    let tx2 = [2u8; 32];

    // tx1 が先に予約
    state
        .reserve_nullifiers(&[nf], tx1)
        .expect("tx1 reserve ok");
    assert!(state.is_nullifier_reserved(&nf));

    // tx2 は同じ nullifier を予約できない
    assert!(state.reserve_nullifiers(&[nf], tx2).is_err());

    // tx1 が evict されたら tx2 が予約できる
    state.release_nullifier_reservation(&tx1);
    assert!(!state.is_nullifier_reserved(&nf));
    state
        .reserve_nullifiers(&[nf], tx2)
        .expect("tx2 reserve after release ok");
}

// ─── 7. Anchor validation ────────────────────────────────────────────────────

#[test]
fn test_invalid_anchor_rejected() {
    let state = make_state();

    // 存在しない root を anchor にした withdraw → 拒否
    let invalid_anchor = TreeRoot([0xFF; 32]);
    let tx = make_stub_withdraw(1, 1_000_000, invalid_anchor, [9u8; 32]);

    assert!(matches!(
        state.validate_withdraw(&tx),
        Err(ShieldedError::InvalidAnchor(_))
    ));
}

#[test]
fn test_empty_tree_anchor_valid() {
    let state = make_state();
    // 空の木の root は常に有効
    let empty_root = TreeRoot::empty();
    assert!(state.is_valid_anchor(&empty_root));
}

// ─── 8. PaymentProof ─────────────────────────────────────────────────────────

#[test]
fn test_payment_proof_create_verify() {
    let ivk = IncomingViewKey([0x11u8; 32]);
    let cm = NoteCommitment([0x22u8; 32]);
    let note = Note {
        value: 500_000,
        asset_id: 0,
        recipient_pk: [0u8; 32],
        rcm: [0u8; 32],
        memo: Some(b"Invoice #42".to_vec()),
    };
    let sn = ScannedNote {
        note: Some(note),
        position: 3,
        commitment: cm,
        tx_hash: [0xABu8; 32],
        block_height: 200,
        spent: false,
    };

    // proof 生成
    let proof =
        PaymentProof::from_scanned_note(&sn, &ivk, 1_700_000_000_000).expect("proof created");

    assert_eq!(proof.amount, 500_000);
    assert_eq!(proof.block_height, 200);

    // 正しい ivk で検証 → OK
    assert!(proof.verify(&ivk, &cm));

    // 異なる ivk → NG
    let wrong_ivk = IncomingViewKey([0x99u8; 32]);
    assert!(!proof.verify(&wrong_ivk, &cm));

    // 異なる commitment → NG
    let wrong_cm = NoteCommitment([0x33u8; 32]);
    assert!(!proof.verify(&ivk, &wrong_cm));
}

// ─── 9. EncryptedNote 暗号化・復号 ───────────────────────────────────────────

#[test]
fn test_note_encrypt_decrypt_roundtrip() {
    let ivk = [0xA1u8; 32];
    let epk_secret = [0xB2u8; 32];
    let note = Note {
        value: 1_234_567,
        asset_id: 0,
        recipient_pk: [0xC3u8; 32],
        rcm: [0xD4u8; 32],
        memo: Some(b"test memo".to_vec()),
    };

    let enc = EncryptedNote::encrypt(&note, &ivk, &epk_secret).expect("encrypt ok");

    // 正しい ivk で復号
    let decrypted = enc.try_decrypt(&ivk).expect("decrypt ok");
    assert_eq!(decrypted.value, 1_234_567);
    assert_eq!(decrypted.asset_id, 0);
    assert_eq!(decrypted.recipient_pk, [0xC3u8; 32]);
    assert_eq!(decrypted.memo, Some(b"test memo".to_vec()));
}

#[test]
fn test_note_encrypt_wrong_key_fails() {
    let ivk = [0xA1u8; 32];
    let wrong_ivk = [0x00u8; 32];
    let epk_secret = [0xB2u8; 32];
    let note = Note {
        value: 100,
        asset_id: 0,
        recipient_pk: [0u8; 32],
        rcm: [0u8; 32],
        memo: None,
    };

    let enc = EncryptedNote::encrypt(&note, &ivk, &epk_secret).expect("encrypt ok");
    // 別の ivk では復号できない（view tag か AEAD で弾かれる）
    assert!(enc.try_decrypt(&wrong_ivk).is_err());
}

// ─── 10. view tag 高速棄却 ────────────────────────────────────────────────────

#[test]
fn test_view_tag_fast_reject() {
    let ivk = IncomingViewKey([0xA1u8; 32]);
    let nk = NullifierKey([0xB2u8; 32]);
    let mut scanner = NoteScanner::new(ivk.clone(), nk);

    let epk_secret = [0xC3u8; 32];
    let correct_note = Note {
        value: 1_000,
        asset_id: 0,
        recipient_pk: [0u8; 32],
        rcm: [0u8; 32],
        memo: None,
    };

    // 自分宛の note を作成
    let enc =
        EncryptedNote::encrypt(&correct_note, ivk.as_bytes(), &epk_secret).expect("encrypt ok");

    // 別の epk を持つ note（自分宛でない）
    let other_enc = EncryptedNote {
        epk: [0xFFu8; 32], // 無関係の epk
        ciphertext: vec![0u8; 64],
        tag: [0u8; 16],
        view_tag: 0xFF, // 高確率でミスマッチ
    };

    let block = ScannedBlock {
        height: 1,
        encrypted_notes: vec![(0, enc, [1u8; 32]), (1, other_enc, [2u8; 32])],
        spent_nullifiers: vec![],
    };

    let found = scanner.scan_block(&block);
    // 自分宛の note だけ検出される（1件）
    assert_eq!(found.len(), 1);
    assert_eq!(scanner.shielded_balance(), 1_000);

    // view tag miss が記録される
    assert!(scanner.stats.view_tag_misses >= 1);
    assert!(scanner.stats.view_tag_hits >= 1);
}

// ─── 11. 複数 deposit → root 変化 ────────────────────────────────────────────

#[test]
fn test_multiple_deposits_update_root() {
    let mut state = make_state();

    let roots: Vec<_> = (1u8..=5)
        .map(|i| {
            let tx = make_deposit(i, 1_000_000);
            let (ws, _) = state.apply_deposit(&tx, [i; 32], i as u64).expect("ok");
            ws.new_root
        })
        .collect();

    // 各 deposit で root が変化する
    let unique_roots: std::collections::HashSet<_> = roots.iter().collect();
    assert_eq!(unique_roots.len(), 5, "all roots should be unique");
    assert_eq!(state.commitment_count(), 5);
}

// ─── 12. on_block_finalized → anchor 履歴 ────────────────────────────────────

#[test]
fn test_anchor_history_after_deposits() {
    let mut state = make_state();

    // block 1: deposit
    let tx1 = make_deposit(1, 1_000_000);
    state.apply_deposit(&tx1, [0u8; 32], 1).expect("ok");
    state.on_block_finalized(1);
    let root1 = state.current_root();

    // block 2: deposit
    let tx2 = make_deposit(2, 1_000_000);
    state.apply_deposit(&tx2, [1u8; 32], 2).expect("ok");
    state.on_block_finalized(2);
    let root2 = state.current_root();

    // 両方の root が anchor として有効
    assert!(state.is_valid_anchor(&root1));
    assert!(state.is_valid_anchor(&root2));
    assert_ne!(root1, root2);
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
// (hex encoding via std::fmt or hex crate where needed)
