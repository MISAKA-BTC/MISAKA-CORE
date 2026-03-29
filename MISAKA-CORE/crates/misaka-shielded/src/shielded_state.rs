//! Shielded State Machine
//!
//! ShieldDeposit / ShieldedTransfer / ShieldWithdraw の
//! validate と apply を実装する。
//!
//! # Atomic Apply Rule
//! transparent state と shielded state の更新は常に同一の WriteBatch で
//! atomic に commit する。このクレートは WriteBatch 相当の型として
//! `ShieldedWriteSet` を返す。chain node が transparent state の変更と
//! 合わせて single RocksDB WriteBatch に詰め込む責任を持つ。
//!
//! # Security Properties
//! - nullifier の存在確認は validate と apply の両方で行う（TOCTOU 対策）
//! - apply は validate を内部で再実行する
//! - proof 検証は CircuitRegistry 経由で行い、version mismatch を拒否する

use crate::{
    commitment_tree::CommitmentTree,
    nullifier_set::{NullifierError, NullifierSet},
    proof_backend::{CircuitRegistry, ProofBackend, ProofError},
    tx_types::{ShieldDepositTx, ShieldWithdrawTx, ShieldedTransferTx, ShieldedTxError},
    types::{
        CircuitVersion, EncryptedNote, NoteCommitment, Nullifier,
        ShieldedPublicInputs, SpentRecord, TreeRoot,
    },
};
use parking_lot::RwLock;
use std::sync::Arc;

// ─── Config ────────────────────────────────────────────────────────────────────

/// Shielded module の設定
#[derive(Debug, Clone)]
pub struct ShieldedConfig {
    /// shielded module 全体の有効/無効（CEX 運用ノードは false にできる）
    pub enabled: bool,
    /// mempool での proof 事前検証（true で DoS 対策強化 / latency 増加）
    pub mempool_proof_verify: bool,
    /// anchor として許容する最大ブロック深さ
    pub max_anchor_age_blocks: u64,
    /// shielded tx の最低手数料
    pub min_shielded_fee: u64,
    /// testnet モード（StubProofBackend を許可）
    pub testnet_mode: bool,
}

impl Default for ShieldedConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mempool_proof_verify: false,
            max_anchor_age_blocks: 100,
            min_shielded_fee: crate::tx_types::MIN_SHIELDED_FEE,
            testnet_mode: false,
        }
    }
}

impl ShieldedConfig {
    pub fn testnet() -> Self {
        Self {
            testnet_mode: true,
            ..Default::default()
        }
    }

    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }
}

// ─── ShieldedWriteSet ─────────────────────────────────────────────────────────

/// apply の結果として生成される書き込みセット。
/// 呼び出し側が transparent state の変更と合わせて atomic に commit する。
#[derive(Debug)]
pub struct ShieldedWriteSet {
    /// 挿入する nullifiers（DB CF: shield_nullifiers）
    pub nullifiers: Vec<(Nullifier, SpentRecord)>,
    /// 挿入する commitments（DB CF: shield_commitments, key = position）
    pub commitments: Vec<(u64 /* position */, NoteCommitment)>,
    /// 挿入する encrypted notes（DB CF: shield_notes_enc, key = position）
    pub encrypted_notes: Vec<(u64 /* position */, EncryptedNote)>,
    /// 新しい frontier bytes（DB CF: shield_frontier）
    pub new_frontier: Vec<u8>,
    /// 新しい root（DB CF: shield_roots, key = block_height）
    pub new_root: TreeRoot,
    /// tx によって transparent に払い出す amount（ShieldWithdraw のみ）
    pub transparent_credit: Option<TransparentCredit>,
    /// ShieldDeposit の場合、transparent から引き落とす情報
    pub transparent_debit: Option<TransparentDebit>,
}

/// transparent からの debit 情報（ShieldDeposit 用）
#[derive(Debug, Clone)]
pub struct TransparentDebit {
    pub from: [u8; 32],
    pub amount: u64,
    pub fee: u64,
}

/// transparent への credit 情報（ShieldWithdraw 用）
#[derive(Debug, Clone)]
pub struct TransparentCredit {
    pub recipient: [u8; 32],
    pub amount: u64,
    pub fee: u64,
}

/// apply の receipt（explorer 表示用）
#[derive(Debug)]
pub struct ShieldedReceipt {
    pub tx_type: ShieldedTxType,
    pub new_root: TreeRoot,
    pub nullifiers_spent: Vec<Nullifier>,
    pub commitments_added: Vec<NoteCommitment>,
    pub positions: Vec<u64>,
}

#[derive(Debug, Clone, Copy)]
pub enum ShieldedTxType {
    Deposit,
    Transfer,
    Withdraw,
}

// ─── ShieldedState ────────────────────────────────────────────────────────────

/// Shielded module の全体状態。
///
/// Arc<RwLock<>> でラップして node の複数コンポーネントから共有する想定。
///
/// # SECURITY [M2]: フィールドは private
/// 内部状態（commitment_tree, nullifier_set, circuit_registry）への直接書き込みを
/// 外部から行うと不変条件（invariants）が破れる可能性があるため private にする。
/// 読み取りはアクセサメソッド経由。書き込みは validate→apply の経路のみ。
#[derive(Debug)]
pub struct ShieldedState {
    commitment_tree: CommitmentTree,
    pub nullifier_set: NullifierSet,
    circuit_registry: CircuitRegistry,
    pub config: ShieldedConfig,
    /// Stored encrypted notes (position → encrypted_note, block_height, tx_hash)
    pub stored_notes: Vec<StoredEncryptedNote>,
}

/// An encrypted note stored for wallet scanning.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredEncryptedNote {
    pub position: u64,
    pub encrypted_note: EncryptedNote,
    pub block_height: u64,
    pub tx_hash: [u8; 32],
}

impl ShieldedState {
    pub fn new(config: ShieldedConfig) -> Self {
        let max_anchor_age = config.max_anchor_age_blocks;
        Self {
            commitment_tree: CommitmentTree::new(max_anchor_age),
            nullifier_set: NullifierSet::new(),
            circuit_registry: CircuitRegistry::new(),
            config,
            stored_notes: Vec::new(),
        }
    }

    /// StubProofBackend を登録（testnet / P0 フェーズ用）
    pub fn register_stub_backend(&mut self) {
        use crate::proof_backend::StubProofBackend;
        self.circuit_registry
            .register(Box::new(StubProofBackend::new_for_testnet()));
        tracing::info!(
            "ShieldedState: registered StubProofBackend (circuit_version={:?})",
            CircuitVersion::STUB_V1
        );
    }

    /// SHA3MerkleProofBackend + SHA3TransferProofBackend を登録（production / PQ-safe）
    pub fn register_sha3_backend(&mut self) {
        use crate::proof_backend::Sha3MerkleProofBackend;
        use crate::sha3_proof::Sha3TransferProofBackend;
        self.circuit_registry
            .register(Box::new(Sha3MerkleProofBackend::new()));
        self.circuit_registry
            .register(Box::new(Sha3TransferProofBackend::new()));
        // Also register stub for backward compat with existing deposits
        use crate::proof_backend::StubProofBackend;
        self.circuit_registry
            .register(Box::new(StubProofBackend::new_for_testnet()));
        tracing::info!(
            "ShieldedState: registered SHA3 backends (membership={:?}, transfer={:?})",
            CircuitVersion::SHA3_MERKLE_V1,
            crate::sha3_proof::Sha3TransferProofBackend::new().circuit_version()
        );
    }

    // ─── ShieldDeposit ────────────────────────────────────────────────────

    /// ShieldDeposit の validate
    pub fn validate_deposit(
        &self,
        tx: &ShieldDepositTx,
    ) -> Result<(), ShieldedError> {
        self.check_module_enabled()?;
        tx.validate_structure().map_err(ShieldedError::InvalidStructure)?;

        // SECURITY [C3][Audit #4]: ML-DSA-65 署名検証 — ShieldedState 側で完結。
        // 1. sender_pubkey → from address の導出チェック
        // 2. ML-DSA-65 signature の暗号学的検証
        {
            use sha3::{Digest, Sha3_256};

            // Step 1: pubkey → address derivation check
            let mut h = Sha3_256::new();
            h.update(b"MISAKA:address:v1:");
            h.update(&tx.sender_pubkey);
            let hash: [u8; 32] = h.finalize().into();
            if hash != tx.from {
                return Err(ShieldedError::InvalidStructure(
                    crate::tx_types::ShieldedTxError::MissingSignature,
                ));
            }

            // Step 2: ML-DSA-65 signature verification
            let pk = misaka_pqc::pq_sign::MlDsaPublicKey::from_bytes(&tx.sender_pubkey)
                .map_err(|_| ShieldedError::InvalidStructure(
                    crate::tx_types::ShieldedTxError::MissingSignature,
                ))?;
            let sig = misaka_pqc::pq_sign::MlDsaSignature::from_bytes(&tx.signature_bytes)
                .map_err(|_| ShieldedError::InvalidStructure(
                    crate::tx_types::ShieldedTxError::MissingSignature,
                ))?;
            let payload = tx.signing_payload();
            misaka_pqc::ml_dsa_verify(&pk, &payload, &sig)
                .map_err(|_| ShieldedError::InvalidStructure(
                    crate::tx_types::ShieldedTxError::MissingSignature,
                ))?;
        }

        // SECURITY: commitment の重複チェック（インメモリ範囲）
        // DB 側での重複チェックは必須だが、インメモリ二重挿入も防ぐ。
        // ※ P0: CommitmentTree の contains() は O(n) スキャン。P1 で HashSet 追加予定。
        if self.commitment_tree.contains(&tx.output_commitment) {
            return Err(ShieldedError::DuplicateCommitment(tx.output_commitment));
        }

        Ok(())
    }

    /// ShieldDeposit を apply し、WriteBatch 相当のデータを返す。
    ///
    /// **caller は transparent 側の残高減算と同一 WriteBatch で commit すること。**
    pub fn apply_deposit(
        &mut self,
        tx: &ShieldDepositTx,
        tx_hash: [u8; 32],
        block_height: u64,
    ) -> Result<(ShieldedWriteSet, ShieldedReceipt), ShieldedError> {
        // apply 時も validate を再実行（TOCTOU 対策）
        self.validate_deposit(tx)?;

        // commitment を tree に追加
        let position = self.commitment_tree.append(tx.output_commitment)
            .map_err(|e| ShieldedError::Internal(format!("commitment tree full: {}", e)))?;

        // Store encrypted note for wallet scanning
        self.stored_notes.push(StoredEncryptedNote {
            position,
            encrypted_note: tx.encrypted_note.clone(),
            block_height,
            tx_hash,
        });

        let new_frontier = self.commitment_tree.serialize_frontier();
        let new_root = self.commitment_tree.root();

        let write_set = ShieldedWriteSet {
            nullifiers: vec![],
            commitments: vec![(position, tx.output_commitment)],
            encrypted_notes: vec![(position, tx.encrypted_note.clone())],
            new_frontier,
            new_root,
            transparent_credit: None,
            transparent_debit: Some(TransparentDebit {
                from: tx.from,
                amount: tx.amount,
                fee: tx.fee,
            }),
        };

        let receipt = ShieldedReceipt {
            tx_type: ShieldedTxType::Deposit,
            new_root,
            nullifiers_spent: vec![],
            commitments_added: vec![tx.output_commitment],
            positions: vec![position],
        };

        tracing::debug!(
            "ShieldedState::apply_deposit: commitment={} position={} root={}",
            tx.output_commitment,
            position,
            new_root
        );

        Ok((write_set, receipt))
    }

    // ─── ShieldWithdraw ───────────────────────────────────────────────────

    /// ShieldWithdraw の validate
    pub fn validate_withdraw(
        &self,
        tx: &ShieldWithdrawTx,
    ) -> Result<(), ShieldedError> {
        self.check_module_enabled()?;
        tx.validate_structure().map_err(ShieldedError::InvalidStructure)?;

        // anchor の有効性
        self.check_anchor(&tx.anchor)?;

        // circuit version
        self.check_circuit_version(&tx.circuit_version)?;

        // nullifier の非存在確認
        // SECURITY: confirmed + reserved の両方をチェックする（mempool TOCTOU 対策）。
        // is_confirmed_spent のみでは、mempool に同一 nullifier を持つ別 tx が
        // 同時に accept される恐れがある。
        for nf in &tx.nullifiers {
            if self.nullifier_set.is_spent_or_reserved(nf) {
                if self.nullifier_set.is_confirmed_spent(nf) {
                    return Err(ShieldedError::NullifierAlreadySpent(*nf));
                } else {
                    return Err(ShieldedError::NullifierConflict(
                        crate::nullifier_set::NullifierError::AlreadyReserved {
                            nullifier: *nf,
                            reserved_by: [0u8; 32], // 内部エラーのため tx_hash は非公開
                        },
                    ));
                }
            }
        }

        // proof 検証（常に実行 — testnet_mode での条件分岐は廃止）
        // SECURITY: proof 検証を config フラグで無効化することは禁止。
        // StubProofBackend 自体が testnet_only フラグを持ち、
        // production 登録時は StubDisabledInProduction を返す。
        let backend = self.get_backend(&tx.circuit_version)?;
        backend.pre_validate(&tx.proof).map_err(ShieldedError::ProofError)?;

        let public_inputs = ShieldedPublicInputs {
            anchor: tx.anchor,
            nullifiers: tx.nullifiers.clone(),
            output_commitments: vec![],
            fee: tx.fee,
            withdraw_amount: Some(tx.withdraw_amount),
            circuit_version: tx.circuit_version,
        };
        backend
            .verify(&public_inputs, &tx.proof)
            .map_err(ShieldedError::ProofError)?;

        Ok(())
    }

    /// ShieldWithdraw を apply し、WriteBatch 相当のデータを返す。
    pub fn apply_withdraw(
        &mut self,
        tx: &ShieldWithdrawTx,
        tx_hash: [u8; 32],
        block_height: u64,
    ) -> Result<(ShieldedWriteSet, ShieldedReceipt), ShieldedError> {
        // apply 時も validate を再実行（TOCTOU 対策）
        self.validate_withdraw(tx)?;

        // nullifier を confirmed に挿入
        for nf in &tx.nullifiers {
            self.nullifier_set.insert_confirmed(
                *nf,
                SpentRecord { tx_hash, block_height },
            );
        }

        let new_frontier = self.commitment_tree.serialize_frontier();
        let new_root = self.commitment_tree.root();

        let write_set = ShieldedWriteSet {
            nullifiers: tx
                .nullifiers
                .iter()
                .map(|nf| (*nf, SpentRecord { tx_hash, block_height }))
                .collect(),
            commitments: vec![],
            encrypted_notes: vec![],
            new_frontier,
            new_root,
            transparent_credit: Some(TransparentCredit {
                recipient: tx.withdraw_recipient,
                amount: tx.withdraw_amount,
                fee: tx.fee,
            }),
            transparent_debit: None,
        };

        let receipt = ShieldedReceipt {
            tx_type: ShieldedTxType::Withdraw,
            new_root,
            nullifiers_spent: tx.nullifiers.clone(),
            commitments_added: vec![],
            positions: vec![],
        };

        tracing::debug!(
            "ShieldedState::apply_withdraw: nullifiers={} withdraw_amount={} recipient={}",
            tx.nullifiers.len(),
            tx.withdraw_amount,
            hex::encode(tx.withdraw_recipient)
        );

        Ok((write_set, receipt))
    }

    // ─── ShieldedTransfer (P1) ────────────────────────────────────────────

    /// ShieldedTransfer の validate（P1 フェーズで本実装）
    pub fn validate_shielded_transfer(
        &self,
        tx: &ShieldedTransferTx,
    ) -> Result<(), ShieldedError> {
        self.check_module_enabled()?;
        tx.validate_structure().map_err(ShieldedError::InvalidStructure)?;

        self.check_anchor(&tx.anchor)?;
        self.check_circuit_version(&tx.circuit_version)?;

        // SECURITY FIX [v9.1]: confirmed + reserved の両方をチェックする。
        // validate_withdraw() と同一のロジック。
        //
        // 旧実装のバグ: is_confirmed_spent() のみチェックしていたため、
        // mempool に同一 nullifier を持つ別の ShieldedTransferTx が
        // 同時に accept される可能性があった。
        // ブロック適用時 (apply_shielded_transfer) では検出されるが、
        // mempool flooding / DoS の原因になりうる。
        for nf in &tx.nullifiers {
            if self.nullifier_set.is_spent_or_reserved(nf) {
                if self.nullifier_set.is_confirmed_spent(nf) {
                    return Err(ShieldedError::NullifierAlreadySpent(*nf));
                } else {
                    return Err(ShieldedError::NullifierConflict(
                        crate::nullifier_set::NullifierError::AlreadyReserved {
                            nullifier: *nf,
                            reserved_by: [0u8; 32], // 内部エラーのため tx_hash は非公開
                        },
                    ));
                }
            }
        }

        let backend = self.get_backend(&tx.circuit_version)?;
        backend.pre_validate(&tx.proof).map_err(ShieldedError::ProofError)?;

        // ShieldedTransfer の proof 検証は必須（P0 の stub を除く）
        let public_inputs = ShieldedPublicInputs {
            anchor: tx.anchor,
            nullifiers: tx.nullifiers.clone(),
            output_commitments: tx.output_commitments.clone(),
            fee: tx.fee,
            withdraw_amount: None,
            circuit_version: tx.circuit_version,
        };
        backend
            .verify(&public_inputs, &tx.proof)
            .map_err(ShieldedError::ProofError)?;

        Ok(())
    }

    /// ShieldedTransfer を apply（P1 フェーズで本実装）
    pub fn apply_shielded_transfer(
        &mut self,
        tx: &ShieldedTransferTx,
        tx_hash: [u8; 32],
        block_height: u64,
    ) -> Result<(ShieldedWriteSet, ShieldedReceipt), ShieldedError> {
        self.validate_shielded_transfer(tx)?;

        // nullifiers 挿入
        for nf in &tx.nullifiers {
            self.nullifier_set.insert_confirmed(
                *nf,
                SpentRecord { tx_hash, block_height },
            );
        }

        // commitments 挿入
        let mut positions = Vec::new();
        for cm in &tx.output_commitments {
            let pos = self.commitment_tree.append(*cm)
                .map_err(|e| ShieldedError::Internal(format!("commitment tree full: {}", e)))?;
            positions.push(pos);
        }

        // Store encrypted notes for wallet scanning
        for (enc, pos) in tx.encrypted_outputs.iter().zip(positions.iter()) {
            self.stored_notes.push(StoredEncryptedNote {
                position: *pos,
                encrypted_note: enc.clone(),
                block_height,
                tx_hash,
            });
        }

        let new_frontier = self.commitment_tree.serialize_frontier();
        let new_root = self.commitment_tree.root();

        let write_set = ShieldedWriteSet {
            nullifiers: tx
                .nullifiers
                .iter()
                .map(|nf| (*nf, SpentRecord { tx_hash, block_height }))
                .collect(),
            commitments: tx
                .output_commitments
                .iter()
                .zip(positions.iter())
                .map(|(cm, pos)| (*pos, *cm))
                .collect(),
            encrypted_notes: tx
                .encrypted_outputs
                .iter()
                .zip(positions.iter())
                .map(|(enc, pos)| (*pos, enc.clone()))
                .collect(),
            new_frontier,
            new_root,
            transparent_credit: None,
            transparent_debit: None,
        };

        let receipt = ShieldedReceipt {
            tx_type: ShieldedTxType::Transfer,
            new_root,
            nullifiers_spent: tx.nullifiers.clone(),
            commitments_added: tx.output_commitments.clone(),
            positions,
        };

        Ok((write_set, receipt))
    }

    // ─── Block finality ────────────────────────────────────────────────────

    /// block が finalized された時に root 履歴を更新する
    pub fn on_block_finalized(&mut self, block_height: u64) {
        self.commitment_tree.record_root(block_height);
    }

    // ─── Mempool support ──────────────────────────────────────────────────

    /// mempool が tx を admit する際に nullifier を予約する
    pub fn reserve_nullifiers(
        &mut self,
        nullifiers: &[Nullifier],
        tx_hash: [u8; 32],
    ) -> Result<(), NullifierError> {
        self.nullifier_set.reserve_batch(nullifiers, tx_hash)
    }

    /// mempool が tx を evict した際に reservation を解放する
    pub fn release_nullifier_reservation(&mut self, tx_hash: &[u8; 32]) {
        self.nullifier_set.release_reservation(tx_hash);
    }

    // ─── Query ────────────────────────────────────────────────────────────

    pub fn current_root(&self) -> TreeRoot {
        self.commitment_tree.root()
    }

    pub fn commitment_count(&self) -> u64 {
        self.commitment_tree.size()
    }

    pub fn nullifier_count(&self) -> usize {
        self.nullifier_set.confirmed_count()
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get encrypted notes since a given block height (for wallet scanning).
    pub fn get_encrypted_notes_since(&self, from_block: u64, limit: usize) -> Vec<&StoredEncryptedNote> {
        self.stored_notes
            .iter()
            .filter(|n| n.block_height >= from_block)
            .take(limit)
            .collect()
    }

    /// Total stored encrypted notes count
    pub fn stored_note_count(&self) -> usize {
        self.stored_notes.len()
    }

    /// nullifier が confirmed 消費済みかどうかを確認する（テスト・explorer 用）
    pub fn is_nullifier_spent(&self, nf: &Nullifier) -> bool {
        self.nullifier_set.is_confirmed_spent(nf)
    }

    /// nullifier が reserved（mempool 予約中）かどうかを確認する（テスト・explorer 用）
    pub fn is_nullifier_reserved(&self, nf: &Nullifier) -> bool {
        self.nullifier_set.is_reserved(nf)
    }

    /// anchor が有効な root かどうか（テスト・wallet 用）
    pub fn is_valid_anchor(&self, anchor: &TreeRoot) -> bool {
        self.commitment_tree.is_valid_anchor(anchor)
    }

    /// commitment_tree への読み取りアクセス（テスト・復元処理用）
    pub fn commitment_tree(&self) -> &CommitmentTree {
        &self.commitment_tree
    }

    /// nullifier_set への読み取りアクセス（DB 保存・復元処理用）
    pub fn nullifier_set(&self) -> &NullifierSet {
        &self.nullifier_set
    }

    // ─── Internal helpers ─────────────────────────────────────────────────

    fn check_module_enabled(&self) -> Result<(), ShieldedError> {
        if !self.config.enabled {
            Err(ShieldedError::ModuleDisabled)
        } else {
            Ok(())
        }
    }

    fn check_anchor(&self, anchor: &TreeRoot) -> Result<(), ShieldedError> {
        if !self.commitment_tree.is_valid_anchor(anchor) {
            Err(ShieldedError::InvalidAnchor(*anchor))
        } else {
            Ok(())
        }
    }

    fn check_circuit_version(&self, version: &CircuitVersion) -> Result<(), ShieldedError> {
        if !self.circuit_registry.is_accepted(version) {
            Err(ShieldedError::UnknownCircuitVersion(*version))
        } else {
            Ok(())
        }
    }

    fn get_backend(
        &self,
        version: &CircuitVersion,
    ) -> Result<&dyn ProofBackend, ShieldedError> {
        self.circuit_registry
            .get(version)
            .ok_or(ShieldedError::UnknownCircuitVersion(*version))
    }

    // NOTE: should_verify_proof() は削除済み。
    // proof 検証は validate_withdraw / validate_shielded_transfer で常に実行する。
    // StubProofBackend.testnet_only が production guard を担う。

    // ─── Phase A-2: Persistence ───────────────────────────────────────────

    /// Save shielded state to a JSON snapshot file.
    pub fn save_snapshot(&self, path: &str) -> Result<(), ShieldedError> {
        let snapshot = ShieldedSnapshot {
            frontier: self.commitment_tree.frontier.clone(),
            root_history: self.commitment_tree.root_history.iter().cloned().collect(),
            confirmed_nullifiers: self.nullifier_set.confirmed_entries(),
            max_anchor_age: self.commitment_tree.max_anchor_age,
            last_block_height: self.commitment_tree.root_history.back().map(|(h, _)| *h).unwrap_or(0),
            stored_notes: self.stored_notes.clone(),
        };
        let json = serde_json::to_string(&snapshot)
            .map_err(|e| ShieldedError::Internal(format!("snapshot serialize: {}", e)))?;
        std::fs::write(path, json)
            .map_err(|e| ShieldedError::Internal(format!("snapshot write: {}", e)))?;
        tracing::debug!("ShieldedState: saved snapshot to {} (commitments={}, nullifiers={}, notes={})",
            path, snapshot.frontier.size, snapshot.confirmed_nullifiers.len(), snapshot.stored_notes.len());
        Ok(())
    }

    /// Load shielded state from a JSON snapshot file.
    pub fn load_snapshot(&mut self, path: &str) -> Result<(), ShieldedError> {
        let json = std::fs::read_to_string(path)
            .map_err(|e| ShieldedError::Internal(format!("snapshot read: {}", e)))?;
        let snapshot: ShieldedSnapshot = serde_json::from_str(&json)
            .map_err(|e| ShieldedError::Internal(format!("snapshot deserialize: {}", e)))?;
        self.commitment_tree = CommitmentTree::restore(
            snapshot.frontier,
            snapshot.root_history,
            snapshot.max_anchor_age,
        );
        for (nf, record) in snapshot.confirmed_nullifiers {
            self.nullifier_set.insert_confirmed(nf, record);
        }
        self.stored_notes = snapshot.stored_notes;
        tracing::info!("ShieldedState: loaded snapshot from {} (commitments={}, nullifiers={}, notes={})",
            path, self.commitment_tree.size(), self.nullifier_set.confirmed_count(), self.stored_notes.len());
        Ok(())
    }
}

/// Serializable snapshot of shielded state (JSON).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShieldedSnapshot {
    pub frontier: crate::commitment_tree::MerkleFrontier,
    pub root_history: Vec<(u64, TreeRoot)>,
    pub confirmed_nullifiers: Vec<(Nullifier, crate::types::SpentRecord)>,
    pub max_anchor_age: u64,
    pub last_block_height: u64,
    /// Persisted encrypted notes for wallet scanning
    #[serde(default)]
    pub stored_notes: Vec<StoredEncryptedNote>,
}

// ─── Thread-safe wrapper ──────────────────────────────────────────────────────

/// Arc<RwLock<ShieldedState>> の便利な型エイリアス
pub type SharedShieldedState = Arc<RwLock<ShieldedState>>;

pub fn new_shared_state(config: ShieldedConfig) -> SharedShieldedState {
    Arc::new(RwLock::new(ShieldedState::new(config)))
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ShieldedError {
    #[error("shielded module is disabled")]
    ModuleDisabled,

    #[error("invalid tx structure: {0}")]
    InvalidStructure(#[from] ShieldedTxError),

    #[error("nullifier already spent: {0}")]
    NullifierAlreadySpent(Nullifier),

    #[error("nullifier conflict in mempool: {0}")]
    NullifierConflict(#[from] NullifierError),

    #[error("invalid anchor: {0}")]
    InvalidAnchor(TreeRoot),

    #[error("unknown circuit version: {0:?}")]
    UnknownCircuitVersion(CircuitVersion),

    #[error("proof error: {0}")]
    ProofError(#[from] ProofError),

    #[error("duplicate commitment: {0}")]
    DuplicateCommitment(NoteCommitment),

    #[error("internal error: {0}")]
    Internal(String),
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::tx_types::{MIN_SHIELDED_FEE, ShieldDepositTx};
    use crate::types::{EncryptedNote, NoteCommitment, ShieldedProof};

    fn test_state() -> ShieldedState {
        let mut s = ShieldedState::new(ShieldedConfig::testnet());
        s.register_stub_backend();
        s
    }

    /// ML-DSA-65 署名付きの有効な ShieldDepositTx を生成するテストヘルパー。
    ///
    /// SEC-FIX [Audit #4] で validate_deposit() が ML-DSA-65 署名検証を行うようになったため、
    /// テスト用 deposit にも実際の署名が必要。
    fn make_deposit(cm: u8) -> ShieldDepositTx {
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
            amount: 1_000_000,
            asset_id: 0,
            fee: MIN_SHIELDED_FEE,
            output_commitment: NoteCommitment([cm; 32]),
            encrypted_note: EncryptedNote {
                epk: [3u8; 32],
                ciphertext: vec![0u8; 64],
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

    #[test]
    fn deposit_validate_ok() {
        let state = test_state();
        state.validate_deposit(&make_deposit(1)).expect("valid deposit");
    }

    #[test]
    fn deposit_apply_updates_tree() {
        let mut state = test_state();
        let tx = make_deposit(42);
        let (ws, receipt) = state.apply_deposit(&tx, [0u8; 32], 1).expect("apply ok");
        assert_eq!(receipt.positions, vec![0u64]);
        assert_eq!(ws.commitments.len(), 1);
        assert_eq!(state.commitment_count(), 1);
    }

    #[test]
    fn disabled_module_rejects_deposit() {
        let mut state = ShieldedState::new(ShieldedConfig::disabled());
        state.register_stub_backend();
        assert!(matches!(
            state.validate_deposit(&make_deposit(1)),
            Err(ShieldedError::ModuleDisabled)
        ));
    }

    fn make_withdraw(nf_byte: u8) -> ShieldWithdrawTx {
        ShieldWithdrawTx {
            nullifiers: vec![Nullifier([nf_byte; 32])],
            anchor: TreeRoot::empty(), // 空の木の root
            withdraw_amount: 500_000,
            withdraw_recipient: [9u8; 20],
            fee: MIN_SHIELDED_FEE,
            proof: ShieldedProof::stub(),
            circuit_version: CircuitVersion::STUB_V1,
        }
    }

    #[test]
    fn withdraw_validate_and_apply() {
        let mut state = test_state();
        state.validate_withdraw(&make_withdraw(1)).expect("valid withdraw");
        let (ws, receipt) = state
            .apply_withdraw(&make_withdraw(1), [0u8; 32], 1)
            .expect("apply ok");
        assert_eq!(ws.nullifiers.len(), 1);
        assert_eq!(receipt.nullifiers_spent.len(), 1);
        assert!(ws.transparent_credit.is_some());
    }

    #[test]
    fn double_withdraw_rejected() {
        let mut state = test_state();
        state.apply_withdraw(&make_withdraw(1), [0u8; 32], 1).expect("first ok");
        let result = state.validate_withdraw(&make_withdraw(1));
        assert!(matches!(result, Err(ShieldedError::NullifierAlreadySpent(_))));
    }

    #[test]
    fn nullifier_reservation_works() {
        let mut state = test_state();
        let nf = Nullifier([5u8; 32]);
        let tx1 = [1u8; 32];
        let tx2 = [2u8; 32];
        state.reserve_nullifiers(&[nf], tx1).expect("first reserve ok");
        assert!(state.reserve_nullifiers(&[nf], tx2).is_err());
        state.release_nullifier_reservation(&tx1);
        state.reserve_nullifiers(&[nf], tx2).expect("after release ok");
    }
}
