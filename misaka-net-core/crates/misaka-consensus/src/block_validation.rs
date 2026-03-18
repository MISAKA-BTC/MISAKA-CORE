//! Block Validation — scheme-aware PQ verification.
//!
//! Dispatch order:
//! 1. **LogRing** (0x03) — system default, O(log n)
//! 2. **LRS** (0x01) — legacy, O(n)
//! 3. **ChipmunkRing** (0x02) — opt-in research, feature-gated

use std::collections::HashSet;
use misaka_types::utxo::*;
use misaka_types::validator::Proposal;
use misaka_storage::utxo_set::{UtxoSet, UtxoError, BlockDelta};
use misaka_pqc::pq_ring::{self, Poly, RingSig, derive_public_param, DEFAULT_A_SEED};
use misaka_pqc::ki_proof::{self, KiProof};
use misaka_pqc::logring::{LogRingSignature, logring_verify};

#[cfg(feature = "chipmunk")]
use misaka_pqc::chipmunk::{ChipmunkSig, ChipmunkKiProof, chipmunk_ring_verify, chipmunk_verify_ki};

/// Block validation error.
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
    #[error("tx[{index}] unsupported ring scheme: 0x{scheme:02x}")]
    TxUnsupportedScheme { index: usize, scheme: u8 },
    #[error("tx[{index}] logring link_tag mismatch")]
    TxLinkTagMismatch { index: usize },
    #[error("block: duplicate key image across txs: {ki}")]
    BlockDuplicateKeyImage { ki: String },
    #[error("utxo: {0}")]
    Utxo(#[from] UtxoError),
}

/// Pre-verified transaction (includes parsed crypto objects).
#[derive(Debug, Clone)]
pub struct VerifiedTx {
    pub tx: UtxoTransaction,
    pub ring_pubkeys: Vec<Vec<Poly>>,
    pub ring_sigs: Vec<RingSig>,
    pub ki_proofs: Vec<Option<KiProof>>,
    pub real_input_refs: Vec<OutputRef>,
}

/// Block candidate.
#[derive(Debug, Clone)]
pub struct BlockCandidate {
    pub height: u64,
    pub slot: u64,
    pub parent_hash: [u8; 32],
    pub transactions: Vec<VerifiedTx>,
    pub proposer_signature: Option<Proposal>,
}

/// Validate and apply a block. Dispatches ring sig verification per TX scheme.
///
/// Scheme dispatch order:
/// 1. LogRing (0x03) — default, verified via Merkle + Σ-protocol
/// 2. LRS (0x01) — legacy, verified via hash-chain Σ-protocol
/// 3. ChipmunkRing (0x02) — feature-gated
pub fn validate_and_apply_block(
    block: &BlockCandidate,
    utxo_set: &mut UtxoSet,
) -> Result<BlockDelta, BlockError> {
    let mut delta = BlockDelta::new(block.height);
    let mut seen_key_images = HashSet::new();
    let a = derive_public_param(&DEFAULT_A_SEED);

    for (tx_idx, vtx) in block.transactions.iter().enumerate() {
        let tx = &vtx.tx;

        // 1. Structural validation (handles v1, v2, v3)
        tx.validate_structure().map_err(|e| BlockError::TxStructural {
            index: tx_idx, reason: e.to_string(),
        })?;

        // 2. Per-input verification
        let mut sum_inputs: u64 = 0;
        for (in_idx, input) in tx.inputs.iter().enumerate() {
            let ki_hex = hex::encode(input.key_image);

            // Duplicate KI / link_tag within block
            if !seen_key_images.insert(input.key_image) {
                return Err(BlockError::BlockDuplicateKeyImage { ki: ki_hex });
            }
            // Already spent on chain
            if utxo_set.has_key_image(&input.key_image) {
                return Err(BlockError::TxKeyImageConflict { index: tx_idx, ki: ki_hex });
            }

            // Dispatch ring sig + KI proof verification by scheme
            let pks = &vtx.ring_pubkeys[in_idx];
            let digest = tx.signing_digest();

            match tx.ring_scheme {
                // ═══ LogRing — SYSTEM DEFAULT ═══
                RING_SCHEME_LOGRING => {
                    // Parse LogRing signature from raw bytes
                    let lr_sig = LogRingSignature::from_bytes(&input.ring_signature)
                        .map_err(|e| BlockError::TxRingSig {
                            index: tx_idx, reason: format!("logring parse: {e}"),
                        })?;

                    // Verify LogRing signature
                    logring_verify(&a, pks, &digest, &lr_sig)
                        .map_err(|e| BlockError::TxRingSig {
                            index: tx_idx, reason: format!("logring verify: {e}"),
                        })?;

                    // key_image field must match link_tag in LogRing
                    if input.key_image != lr_sig.link_tag {
                        return Err(BlockError::TxLinkTagMismatch { index: tx_idx });
                    }
                }

                // ═══ LRS — Legacy ═══
                RING_SCHEME_LRS => {
                    let sig = &vtx.ring_sigs[in_idx];
                    pq_ring::ring_verify(&a, pks, &digest, sig)
                        .map_err(|e| BlockError::TxRingSig { index: tx_idx, reason: e.to_string() })?;

                    // LRS KI proof
                    if let Some(proof) = &vtx.ki_proofs[in_idx] {
                        let real_pk = &pks[0];
                        ki_proof::verify_key_image(&a, real_pk, &input.key_image, proof)
                            .map_err(|e| BlockError::TxKiProof { index: tx_idx, reason: e.to_string() })?;
                    }
                }

                // ═══ ChipmunkRing — Feature-gated ═══
                #[cfg(feature = "chipmunk")]
                RING_SCHEME_CHIPMUNK => {
                    let cr_sig = ChipmunkSig::from_bytes(&input.ring_signature, pks.len())
                        .map_err(|e| BlockError::TxRingSig { index: tx_idx, reason: e.to_string() })?;
                    chipmunk_ring_verify(&a, pks, &digest, &cr_sig)
                        .map_err(|e| BlockError::TxRingSig { index: tx_idx, reason: e.to_string() })?;

                    if !input.ki_proof.is_empty() {
                        let cr_proof = ChipmunkKiProof::from_bytes(&input.ki_proof)
                            .map_err(|e| BlockError::TxKiProof { index: tx_idx, reason: e.to_string() })?;
                        let real_pk = &pks[0];
                        chipmunk_verify_ki(&a, real_pk, &input.key_image, &cr_proof)
                            .map_err(|e| BlockError::TxKiProof { index: tx_idx, reason: e.to_string() })?;
                    }
                }

                other => {
                    return Err(BlockError::TxUnsupportedScheme { index: tx_idx, scheme: other });
                }
            }

            // Get input amount from UTXO set
            let real_ref = &vtx.real_input_refs[in_idx];
            let output = utxo_set.get_output(real_ref)
                .ok_or_else(|| BlockError::TxRingMemberNotFound {
                    index: tx_idx, member: format!("{:?}", real_ref),
                })?;
            sum_inputs += output.amount;
        }

        // 3. Amount conservation
        let sum_outputs: u64 = tx.outputs.iter().map(|o| o.amount).sum();
        if sum_inputs != sum_outputs + tx.fee {
            return Err(BlockError::TxAmountMismatch {
                index: tx_idx, inputs: sum_inputs, outputs: sum_outputs, fee: tx.fee,
            });
        }

        // 4. Apply transaction to UTXO set
        let tx_delta = utxo_set.apply_transaction(tx, &vtx.real_input_refs)?;
        delta.merge(tx_delta);
    }

    Ok(delta)
}

/// Rollback the last applied block.
pub fn rollback_block(utxo_set: &mut UtxoSet) -> Result<BlockDelta, BlockError> {
    utxo_set.rollback_block().map_err(BlockError::from)
}
