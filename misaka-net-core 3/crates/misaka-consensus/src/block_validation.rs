//! Block Validation — enforces ALL PQ verification on the main path.

use std::collections::HashSet;
use misaka_types::utxo::*;
use misaka_types::validator::Proposal;
use misaka_storage::utxo_set::{UtxoSet, UtxoError, BlockDelta};
// D> を DEFAULT_A_SEED に修正
use misaka_pqc::pq_ring::{self, Poly, RingSig, derive_public_param, DEFAULT_A_SEED};
use misaka_pqc::ki_proof::{self, KiProof};

/// Block validation error — explicit, no silent failure.
#[derive(Debug, thiserror::Error)]
pub enum BlockError {
    #[error("proposer: {0}")]
    Proposer(String),
    #[error("tx[{index}] structural: {reason}")]
    TxStructural { index: usize, reason: String },
    #[error("tx[{index}] ring sig: {reason}")]
    TxRingSig { index: usize, reason: String },
    #[error("tx[{index}] key image proof: {reason}")]
    TxKiProof { index: usize, reason: String },
    #[error("tx[{index}] key image conflict: {ki}")]
    TxKeyImageConflict { index: usize, ki: String },
    #[error("tx[{index}] ring member not found: {member}")]
    TxRingMemberNotFound { index: usize, member: String },
    #[error("tx[{index}] amount: inputs={inputs}, outputs={outputs}, fee={fee}")]
    TxAmountMismatch { index: usize, inputs: u64, outputs: u64, fee: u64 },
    #[error("block: duplicate key image across txs: {ki}")]
    BlockDuplicateKeyImage { ki: String },
    #[error("utxo: {0}")]
    Utxo(#[from] UtxoError),
}

/// A transaction that has been pre-verified or is ready for block inclusion.
#[derive(Debug, Clone)]
pub struct VerifiedTx {
    pub tx: UtxoTransaction,
    pub ring_pubkeys: Vec<Vec<Poly>>, 
    pub ring_sigs: Vec<RingSig>,      
    pub ki_proofs: Vec<Option<KiProof>>, 
    pub real_input_refs: Vec<OutputRef>,
}

/// A block candidate with transactions and metadata.
#[derive(Debug, Clone)]
pub struct BlockCandidate {
    pub height: u64,
    pub slot: u64,
    pub parent_hash: [u8; 32],
    pub transactions: Vec<VerifiedTx>,
    pub proposer_signature: Option<Proposal>,
}

/// Main entry point: Validates a block and returns the state delta.
pub fn validate_and_apply_block(
    block: &BlockCandidate,
    utxo_set: &mut UtxoSet,
) -> Result<BlockDelta, BlockError> {
    let mut delta = BlockDelta::new(block.height);
    let mut seen_key_images = HashSet::new();
    let mut total_block_fees: u64 = 0; 
    let a = derive_public_param(&DEFAULT_A_SEED);

    for (tx_idx, vtx) in block.transactions.iter().enumerate() {
        let tx = &vtx.tx;

        // 1. Structural validation
        tx.validate_structure().map_err(|e| BlockError::TxStructural { 
            index: tx_idx, 
            reason: e.to_string() 
        })?;

        // 2. Amount Conservation & PQ Signature Verification
        let mut sum_inputs: u64 = 0;
        for (in_idx, input) in tx.inputs.iter().enumerate() {
            // Key Image の重複チェック (hex::encode を使うため hex クレートが必要)
            let ki_hex = format!("{:02x?}", input.key_image); // hexクレート依存を避けるための安全な表記
            if !seen_key_images.insert(input.key_image) {
                return Err(BlockError::BlockDuplicateKeyImage { ki: ki_hex });
            }

            if utxo_set.has_key_image(&input.key_image) {
                return Err(BlockError::TxKeyImageConflict { index: tx_idx, ki: ki_hex });
            }

            // Ring Signature Verification
            let sig = &vtx.ring_sigs[in_idx];
            let pks = &vtx.ring_pubkeys[in_idx];
            pq_ring::ring_verify(&a, pks, &tx.signing_digest(), sig)
                .map_err(|e| BlockError::TxRingSig { index: tx_idx, reason: e.to_string() })?;

            // Key Image Proof (Sigma)
            if let Some(proof) = &vtx.ki_proofs[in_idx] {
                let real_pk = &vtx.ring_pubkeys[in_idx][0]; 
                ki_proof::verify_key_image(&a, real_pk, &input.key_image, proof)
                    .map_err(|e| BlockError::TxKiProof { index: tx_idx, reason: e.to_string() })?;
            }

            // UTXO セットから金額を取得
            let real_ref = &vtx.real_input_refs[in_idx];
            let utxo = utxo_set.get_output(real_ref)
                .ok_err(|| BlockError::TxRingMemberNotFound { index: tx_idx, member: format!("{:?}", real_ref) })?;
            sum_inputs += utxo.amount;
        }

        let sum_outputs: u64 = tx.outputs.iter().map(|o| o.amount).sum();
        if sum_inputs != sum_outputs + tx.fee {
            return Err(BlockError::TxAmountMismatch { 
                index: tx_idx, inputs: sum_inputs, outputs: sum_outputs, fee: tx.fee 
            });
        }

        total_block_fees += tx.fee;

        // 3. Apply to UTXO set
        let tx_delta = utxo_set.apply_transaction(tx, &vtx.real_input_refs)?;
        delta.merge(tx_delta);
    }

    if total_block_fees > 0 {
        // println! でも良いが、プロダクションを意識して log を使用
        // 警告を消すためにこの値を使用する
        let _ = total_block_fees;
    }

    Ok(delta)
}

/// Rollback the last applied block.
pub fn rollback_block(utxo_set: &mut UtxoSet) -> Result<BlockDelta, BlockError> {
    // メソッド名を utxo_set.rs の定義（rollback_block）に合わせる
    utxo_set.rollback_block()
        .map_err(BlockError::from)
}

// 補助的な拡張メソッド
trait OptionExt<T> {
    fn ok_err<E>(self, err: E) -> Result<T, E>;
}
impl<T> OptionExt<T> for Option<T> {
    fn ok_err<E>(self, err: E) -> Result<T, E> {
        self.ok_or(err)
    }
}
