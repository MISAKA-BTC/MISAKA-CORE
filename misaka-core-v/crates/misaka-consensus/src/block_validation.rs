//! Block Validation — Mainnet P0 grade.
//!
//! # Security Properties
//!
//! 1. **Proposer Enforcement**: ML-DSA-65 sig MANDATORY, block_hash binding
//! 2. **No real_input_refs**: Anonymity at protocol level
//! 3. **No pks[0] assumption**: KI proof iterates ALL ring members
//! 4. **Same-Amount Ring**: All members must have equal amounts (Item 3 fix)
//! 5. **Block Hash Binding**: proposal.block_hash == canonical hash (Item 2 fix)

use std::collections::HashSet;
use sha3::{Sha3_256, Digest};
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
    #[error("proposer block_hash mismatch: proposal={proposal}, computed={computed}")]
    ProposerBlockHashMismatch { proposal: String, computed: String },
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
    #[error("tx[{index}] ring amounts not uniform: input[{input}] has amounts {amounts:?}")]
    TxRingAmountsNotUniform { index: usize, input: usize, amounts: Vec<u64> },
    #[error("tx[{index}] amount mismatch: inputs={inputs}, outputs+fee={required}")]
    TxAmountMismatch { index: usize, inputs: u64, required: u64 },
    #[error("tx[{index}] unsupported ring scheme: 0x{scheme:02x}")]
    TxUnsupportedScheme { index: usize, scheme: u8 },
    #[error("tx[{index}] logring link_tag mismatch")]
    TxLinkTagMismatch { index: usize },
    #[error("block: duplicate nullifier: {ki}")]
    BlockDuplicateKeyImage { ki: String },
    #[error("utxo: {0}")]
    Utxo(#[from] UtxoError),
}

// ═══ Canonical Block Hash ════════════════════════════════════

/// Compute the canonical block hash for proposer signature binding.
///
/// `H("MISAKA_BLOCK_V1:" || height_le || slot_le || parent_hash || tx_root)`
///
/// `tx_root` = SHA3-256 of all tx signing digests concatenated.
pub fn canonical_block_hash(block: &BlockCandidate) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA_BLOCK_V1:");
    h.update(&block.height.to_le_bytes());
    h.update(&block.slot.to_le_bytes());
    h.update(&block.parent_hash);

    // TX root: hash of all tx digests
    let mut tx_h = Sha3_256::new();
    for vtx in &block.transactions {
        tx_h.update(&vtx.tx.signing_digest());
    }
    h.update(&tx_h.finalize());

    h.finalize().into()
}

// ═══ Transaction Container ══════════════════════════════════

/// Scheme-aware ring proof — eliminates dummy RingSig values.
///
/// Each variant carries exactly the data needed for that scheme's verification.
/// The validator MUST `match` this enum, ensuring compile-time exhaustiveness
/// when new schemes are added.
#[derive(Debug, Clone)]
pub enum VerifiedRingProof {
    /// LRS-v1: parsed RingSig + mandatory KiProof.
    Lrs {
        sig: RingSig,
        ki_proof: Option<KiProof>,
    },
    /// LogRing-v1: raw bytes (parsed lazily by block_validation).
    LogRing {
        raw_sig: Vec<u8>,
    },
    /// ChipmunkRing: raw bytes (parsed lazily by block_validation).
    #[cfg(feature = "chipmunk")]
    Chipmunk {
        raw_sig: Vec<u8>,
        raw_ki_proof: Vec<u8>,
    },
}

/// Pre-verified transaction. NO real_input_refs.
#[derive(Debug, Clone)]
pub struct VerifiedTx {
    pub tx: UtxoTransaction,
    /// ring_pubkeys[i] = pubkeys for input i's ring members.
    pub ring_pubkeys: Vec<Vec<Poly>>,
    /// ring_amounts[i][j] = amount of ring member j for input i.
    /// MUST be uniform (all equal) per same-amount ring rule.
    pub ring_amounts: Vec<Vec<u64>>,
    /// Per-input ring proofs, typed by scheme.
    pub ring_proofs: Vec<VerifiedRingProof>,
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

/// Maximum transactions per block (DoS protection).
pub const MAX_TXS_PER_BLOCK: usize = 256;

pub fn validate_and_apply_block(
    block: &BlockCandidate,
    utxo_set: &mut UtxoSet,
    validator_set: Option<&ValidatorSet>,
) -> Result<BlockDelta, BlockError> {
    // ═══ 0a. Structural bounds ═══
    if block.transactions.len() > MAX_TXS_PER_BLOCK {
        return Err(BlockError::TxStructural {
            index: 0,
            reason: format!("block has {} txs, max is {}", block.transactions.len(), MAX_TXS_PER_BLOCK),
        });
    }

    // ═══ 0b. Height monotonicity ═══
    if block.height > 0 && block.height != utxo_set.height + 1 {
        return Err(BlockError::Proposer(
            format!("height mismatch: block={}, expected={}", block.height, utxo_set.height + 1),
        ));
    }

    // ═══ 0c. Proposer Verification + Block Hash Binding ═══
    if let Some(vs) = validator_set {
        let proposal = block.proposer_signature.as_ref()
            .ok_or(BlockError::ProposerSigMissing)?;

        // 0a. Proposer authorization for slot
        let expected = super::proposer::proposer_for_slot(vs, block.slot)
            .ok_or(BlockError::ProposerNotAuthorized { slot: block.slot })?;

        if proposal.proposer != expected {
            return Err(BlockError::Proposer(
                format!("wrong proposer for slot {}", block.slot)));
        }

        // 0b. Slot binding
        if proposal.slot != block.slot {
            return Err(BlockError::Proposer(
                format!("slot mismatch: proposal={}, block={}", proposal.slot, block.slot)));
        }

        // 0c. Block hash binding (Item 2 FIX)
        let computed_hash = canonical_block_hash(block);
        if proposal.block_hash != computed_hash {
            return Err(BlockError::ProposerBlockHashMismatch {
                proposal: hex::encode(&proposal.block_hash[..8]),
                computed: hex::encode(&computed_hash[..8]),
            });
        }

        // 0d. ML-DSA-65 signature verification
        vs.verify_validator_sig(
            &proposal.proposer,
            &proposal.signing_bytes(),
            &proposal.signature,
        ).map_err(|e| BlockError::Proposer(format!("sig verify: {e}")))?;
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

        let mut sum_input_amount: u64 = 0;

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

            // ── Same-Amount Ring Enforcement (Item 3 FIX) ──
            //
            // ALL ring members MUST have the same amount.
            // This eliminates the "max(ring_amounts)" vulnerability
            // where a high-value decoy inflates spendable amount.
            //
            // In a same-amount ring, the spend amount is unambiguous:
            // the signer's UTXO has the same amount as every decoy.
            if !amounts.is_empty() {
                let ring_amount = amounts[0];
                for (j, &amt) in amounts.iter().enumerate().skip(1) {
                    if amt != ring_amount {
                        return Err(BlockError::TxRingAmountsNotUniform {
                            index: tx_idx,
                            input: in_idx,
                            amounts: amounts.clone(),
                        });
                    }
                }
                sum_input_amount = sum_input_amount.checked_add(ring_amount)
                    .ok_or_else(|| BlockError::TxAmountMismatch {
                        index: tx_idx, inputs: u64::MAX, required: 0,
                    })?;
            }

            // ── Ring signature verification ──
            match &vtx.ring_proofs[in_idx] {
                VerifiedRingProof::LogRing { raw_sig } => {
                    let lr_sig = LogRingSignature::from_bytes(raw_sig)
                        .map_err(|e| BlockError::TxRingSig {
                            index: tx_idx, reason: format!("logring parse: {e}"),
                        })?;

                    logring_verify(&a, pks, &digest, &lr_sig)
                        .map_err(|e| BlockError::TxRingSig {
                            index: tx_idx, reason: format!("logring verify: {e}"),
                        })?;

                    if input.key_image != lr_sig.link_tag {
                        return Err(BlockError::TxLinkTagMismatch { index: tx_idx });
                    }
                }

                VerifiedRingProof::Lrs { sig, ki_proof } => {
                    pq_ring::ring_verify(&a, pks, &digest, sig)
                        .map_err(|e| BlockError::TxRingSig {
                            index: tx_idx, reason: e.to_string(),
                        })?;

                    // KI proof: MANDATORY for LRS scheme (SEC-003 fix).
                    let proof = ki_proof.as_ref()
                        .ok_or(BlockError::TxKiProof {
                            index: tx_idx,
                            reason: "KI proof is REQUIRED for LRS scheme but was None".into(),
                        })?;
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

                #[cfg(feature = "chipmunk")]
                VerifiedRingProof::Chipmunk { raw_sig, raw_ki_proof } => {
                    let cr_sig = ChipmunkSig::from_bytes(raw_sig, pks.len())
                        .map_err(|e| BlockError::TxRingSig {
                            index: tx_idx, reason: e.to_string(),
                        })?;
                    chipmunk_ring_verify(&a, pks, &digest, &cr_sig)
                        .map_err(|e| BlockError::TxRingSig {
                            index: tx_idx, reason: e.to_string(),
                        })?;

                    if !raw_ki_proof.is_empty() {
                        let cr_proof = ChipmunkKiProof::from_bytes(raw_ki_proof)
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
                                reason: "Chipmunk KI proof invalid".into(),
                            });
                        }
                    }
                }
            }
        }

        // ── Exact Amount Conservation (same-amount ring: sum is deterministic) ──
        let sum_outputs: u64 = tx.outputs.iter()
            .try_fold(0u64, |acc, o| acc.checked_add(o.amount))
            .ok_or_else(|| BlockError::TxAmountMismatch {
                index: tx_idx, inputs: sum_input_amount, required: u64::MAX,
            })?;
        let required = sum_outputs.checked_add(tx.fee)
            .ok_or_else(|| BlockError::TxAmountMismatch {
                index: tx_idx, inputs: sum_input_amount, required: u64::MAX,
            })?;
        if sum_input_amount != required {
            return Err(BlockError::TxAmountMismatch {
                index: tx_idx, inputs: sum_input_amount, required,
            });
        }

        // ── Apply: nullifiers + outputs + spending keys ──
        let tx_hash = tx.tx_hash();
        let mut tx_delta = BlockDelta::new(block.height);

        for input in &tx.inputs {
            utxo_set.record_nullifier(input.key_image)
                .map_err(BlockError::Utxo)?;
            tx_delta.key_images_added.push(input.key_image);
        }

        for (idx, output) in tx.outputs.iter().enumerate() {
            let outref = OutputRef { tx_hash, output_index: idx as u32 };
            utxo_set.add_output(outref.clone(), output.clone(), block.height)?;

            // Phase 1.2 fix: Auto-register spending pubkey so this UTXO can be
            // used as a ring member in future transactions.
            if let Some(ref spk_bytes) = output.spending_pubkey {
                utxo_set.register_spending_key(outref.clone(), spk_bytes.clone());
            }

            tx_delta.created.push(outref);
        }

        delta.merge(tx_delta);
    }

    // Update UTXO set height and store delta for rollback support
    utxo_set.apply_block(delta.clone())
        .map_err(|e| BlockError::Utxo(e))?;

    Ok(delta)
}

/// Rollback the last applied block.
pub fn rollback_block(utxo_set: &mut UtxoSet) -> Result<BlockDelta, BlockError> {
    utxo_set.rollback_block().map_err(BlockError::from)
}
