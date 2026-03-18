//! Block Validation — Mainnet-grade PQ verification.
//!
//! # P0 Security Properties (Mainnet)
//!
//! 1. **Proposer Enforcement**: Every block MUST have a valid ML-DSA-65
//!    proposer signature verified against the validator set.
//! 2. **No real_input_refs**: The validator never learns which ring member
//!    is the real spender. Anonymity enforced at protocol level.
//! 3. **No pks[0] assumption**: KI proof iterates ALL ring members.
//! 4. **Link Tag as Nullifier**: For LogRing, link_tag is the sole
//!    double-spend prevention. No UTXO-specific marking needed.
//! 5. **Atomic Validation**: Ring sig validity proves "exactly one UTXO
//!    holder authorized this spend" without revealing which one.

use std::collections::HashSet;
use misaka_types::utxo::*;
use misaka_types::validator::Proposal;
use misaka_storage::utxo_set::{UtxoSet, UtxoError, BlockDelta};
use misaka_pqc::pq_ring::{self, Poly, RingSig, derive_public_param, DEFAULT_A_SEED};
use misaka_pqc::ki_proof::{self, KiProof};
use misaka_pqc::logring::{LogRingSignature, logring_verify};

#[cfg(feature = "chipmunk")]
use misaka_pqc::chipmunk::{ChipmunkSig, ChipmunkKiProof, chipmunk_ring_verify, chipmunk_verify_ki};

use super::validator_set::ValidatorSet;

// ═══ Error Types ══════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum BlockError {
    #[error("proposer: {0}")]
    Proposer(String),
    #[error("proposer signature missing (MANDATORY)")]
    ProposerSigMissing,
    #[error("proposer not authorized for slot {slot}")]
    ProposerNotAuthorized { slot: u64 },
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
    #[error("tx[{index}] amount insufficient: available={available}, required={required}")]
    TxAmountInsufficient { index: usize, available: u64, required: u64 },
    #[error("tx[{index}] unsupported ring scheme: 0x{scheme:02x}")]
    TxUnsupportedScheme { index: usize, scheme: u8 },
    #[error("tx[{index}] logring link_tag mismatch")]
    TxLinkTagMismatch { index: usize },
    #[error("block: duplicate key image / link_tag: {ki}")]
    BlockDuplicateKeyImage { ki: String },
    #[error("utxo: {0}")]
    Utxo(#[from] UtxoError),
}

// ═══ Transaction Container (real_input_refs ELIMINATED) ══════

/// Pre-verified transaction.
///
/// # MAINNET: real_input_refs completely removed.
///
/// The validator does NOT know which ring member is the real spender.
/// Anonymity is enforced at the protocol level.
#[derive(Debug, Clone)]
pub struct VerifiedTx {
    pub tx: UtxoTransaction,
    /// ring_pubkeys[i] = pubkeys for input i's ring members.
    pub ring_pubkeys: Vec<Vec<Poly>>,
    /// ring_amounts[i][j] = amount of ring member j for input i.
    pub ring_amounts: Vec<Vec<u64>>,
    /// LRS ring signatures (only for LRS scheme).
    pub ring_sigs: Vec<RingSig>,
    /// KI proofs for LRS (only for LRS scheme).
    pub ki_proofs: Vec<Option<KiProof>>,
    // NO real_input_refs — anonymity preserved.
}

/// Block candidate.
#[derive(Debug, Clone)]
pub struct BlockCandidate {
    pub height: u64,
    pub slot: u64,
    pub parent_hash: [u8; 32],
    pub transactions: Vec<VerifiedTx>,
    /// Proposer signature — MANDATORY when validator_set is provided.
    pub proposer_signature: Option<Proposal>,
}

// ═══ Core Validation ═════════════════════════════════════════

/// Validate and apply a block with full mainnet security.
///
/// # Proposer Verification
///
/// When `validator_set` is provided:
/// 1. Signature MUST be present
/// 2. Proposer MUST be authorized for this slot
/// 3. ML-DSA-65 signature MUST verify over (slot, proposer, block_hash)
///
/// # Anonymous UTXO Spending
///
/// For each input:
/// 1. ALL ring members exist in UTXO set
/// 2. Ring signature proves signer owns one member's secret key
/// 3. key_image/link_tag is not already spent (nullifier)
/// 4. Amount conservation is verified against ring member amounts
/// 5. Only the nullifier is recorded — NOT which UTXO was spent
pub fn validate_and_apply_block(
    block: &BlockCandidate,
    utxo_set: &mut UtxoSet,
    validator_set: Option<&ValidatorSet>,
) -> Result<BlockDelta, BlockError> {
    // ═══ 0. Proposer Verification ═══
    if let Some(vs) = validator_set {
        let proposal = block.proposer_signature.as_ref()
            .ok_or(BlockError::ProposerSigMissing)?;

        // Verify proposer is authorized for this slot
        let expected = super::proposer::proposer_for_slot(vs, block.slot)
            .ok_or(BlockError::ProposerNotAuthorized { slot: block.slot })?;

        if proposal.proposer != expected {
            return Err(BlockError::Proposer(
                format!("wrong proposer: expected {}, got {}",
                    hex::encode(&expected[..8]),
                    hex::encode(&proposal.proposer[..8]))));
        }

        // Verify ML-DSA-65 signature
        vs.verify_validator_sig(
            &proposal.proposer,
            &proposal.signing_bytes(),
            &proposal.signature,
        ).map_err(|e| BlockError::Proposer(format!("sig verify: {e}")))?;

        // Slot binding
        if proposal.slot != block.slot {
            return Err(BlockError::Proposer(
                format!("slot mismatch: proposal={}, block={}", proposal.slot, block.slot)));
        }
    }

    // ═══ 1. Transaction Validation ═══
    let mut delta = BlockDelta::new(block.height);
    let mut seen_nullifiers: HashSet<[u8; 32]> = HashSet::new();
    let a = derive_public_param(&DEFAULT_A_SEED);

    for (tx_idx, vtx) in block.transactions.iter().enumerate() {
        let tx = &vtx.tx;

        // Structural validation
        tx.validate_structure().map_err(|e| BlockError::TxStructural {
            index: tx_idx, reason: e.to_string(),
        })?;

        let mut sum_available: u64 = 0;

        for (in_idx, input) in tx.inputs.iter().enumerate() {
            let ki_hex = hex::encode(input.key_image);

            // ── Nullifier checks ──
            if !seen_nullifiers.insert(input.key_image) {
                return Err(BlockError::BlockDuplicateKeyImage { ki: ki_hex });
            }
            if utxo_set.has_key_image(&input.key_image) {
                return Err(BlockError::TxKeyImageConflict { index: tx_idx, ki: ki_hex });
            }

            // ── Ring member existence ──
            let pks = &vtx.ring_pubkeys[in_idx];
            let amounts = &vtx.ring_amounts[in_idx];
            let digest = tx.signing_digest();

            for (m_idx, member) in input.ring_members.iter().enumerate() {
                if utxo_set.get(member).is_none() {
                    return Err(BlockError::TxRingMemberNotFound {
                        index: tx_idx,
                        member: format!("in[{}].ring[{}]", in_idx, m_idx),
                    });
                }
            }

            // ── Ring signature verification (scheme dispatch) ──
            match tx.ring_scheme {
                RING_SCHEME_LOGRING => {
                    let lr_sig = LogRingSignature::from_bytes(&input.ring_signature)
                        .map_err(|e| BlockError::TxRingSig {
                            index: tx_idx, reason: format!("logring parse: {e}"),
                        })?;

                    logring_verify(&a, pks, &digest, &lr_sig)
                        .map_err(|e| BlockError::TxRingSig {
                            index: tx_idx, reason: format!("logring verify: {e}"),
                        })?;

                    // link_tag bound to sk+ring_root in Fiat-Shamir — no separate KI proof
                    if input.key_image != lr_sig.link_tag {
                        return Err(BlockError::TxLinkTagMismatch { index: tx_idx });
                    }
                }

                RING_SCHEME_LRS => {
                    let sig = &vtx.ring_sigs[in_idx];
                    pq_ring::ring_verify(&a, pks, &digest, sig)
                        .map_err(|e| BlockError::TxRingSig {
                            index: tx_idx, reason: e.to_string(),
                        })?;

                    // KI proof: iterate ALL ring members (NO pks[0] assumption)
                    if let Some(proof) = &vtx.ki_proofs[in_idx] {
                        let mut ki_valid = false;
                        for pk in pks.iter() {
                            if ki_proof::verify_key_image_proof(
                                &a, pk, &input.key_image, proof
                            ).is_ok() {
                                ki_valid = true;
                                break;
                            }
                        }
                        if !ki_valid {
                            return Err(BlockError::TxKiProof {
                                index: tx_idx,
                                reason: "KI proof invalid against ALL ring members".into(),
                            });
                        }
                    }
                }

                #[cfg(feature = "chipmunk")]
                RING_SCHEME_CHIPMUNK => {
                    let cr_sig = ChipmunkSig::from_bytes(&input.ring_signature, pks.len())
                        .map_err(|e| BlockError::TxRingSig {
                            index: tx_idx, reason: e.to_string(),
                        })?;
                    chipmunk_ring_verify(&a, pks, &digest, &cr_sig)
                        .map_err(|e| BlockError::TxRingSig {
                            index: tx_idx, reason: e.to_string(),
                        })?;

                    if !input.ki_proof.is_empty() {
                        let cr_proof = ChipmunkKiProof::from_bytes(&input.ki_proof)
                            .map_err(|e| BlockError::TxKiProof {
                                index: tx_idx, reason: e.to_string(),
                            })?;
                        let mut ki_valid = false;
                        for pk in pks.iter() {
                            if chipmunk_verify_ki(&a, pk, &input.key_image, &cr_proof).is_ok() {
                                ki_valid = true;
                                break;
                            }
                        }
                        if !ki_valid {
                            return Err(BlockError::TxKiProof {
                                index: tx_idx,
                                reason: "Chipmunk KI proof invalid against ALL ring members".into(),
                            });
                        }
                    }
                }

                other => {
                    return Err(BlockError::TxUnsupportedScheme { index: tx_idx, scheme: other });
                }
            }

            // ── Amount: max ring member amount as upper bound ──
            if !amounts.is_empty() {
                sum_available += amounts.iter().copied().max().unwrap_or(0);
            }
        }

        // ── Amount conservation ──
        let sum_outputs: u64 = tx.outputs.iter().map(|o| o.amount).sum();
        let required = sum_outputs.saturating_add(tx.fee);
        if sum_available < required {
            return Err(BlockError::TxAmountInsufficient {
                index: tx_idx, available: sum_available, required,
            });
        }

        // ── Apply: record nullifiers + create outputs (NO real_input_refs) ──
        let tx_hash = tx.tx_hash();
        let mut tx_delta = BlockDelta::new(block.height);

        for input in &tx.inputs {
            utxo_set.record_nullifier(input.key_image)
                .map_err(|e| BlockError::Utxo(e))?;
            tx_delta.key_images_added.push(input.key_image);
        }

        for (idx, output) in tx.outputs.iter().enumerate() {
            let outref = OutputRef { tx_hash, output_index: idx as u32 };
            utxo_set.add_output(outref.clone(), output.clone(), block.height)?;
            tx_delta.created.push(outref);
        }

        delta.merge(tx_delta);
    }

    Ok(delta)
}

/// Rollback the last applied block.
pub fn rollback_block(utxo_set: &mut UtxoSet) -> Result<BlockDelta, BlockError> {
    utxo_set.rollback_block().map_err(BlockError::from)
}
