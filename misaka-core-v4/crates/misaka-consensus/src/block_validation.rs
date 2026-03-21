//! Block Validation — Mainnet P0 grade.
//!
//! # Security Properties
//!
//! 1. **Proposer Enforcement**: ML-DSA-65 sig MANDATORY, block_hash binding
//! 2. **No real_input_refs**: Anonymity at protocol level
//! 3. **No pks[0] assumption**: KI proof iterates ALL ring members
//! 4. **Same-Amount Ring**: All members must have equal amounts (Item 3 fix)
//! 5. **Block Hash Binding**: proposal.block_hash == canonical hash (Item 2 fix)

use misaka_pqc::ki_proof::KiProof;
use misaka_pqc::pq_ring::{derive_public_param, Poly, RingSig, DEFAULT_A_SEED};
#[cfg(feature = "stark-stub")]
use misaka_pqc::verify_zero_knowledge_tx_with_statement;
use misaka_pqc::{
    select_privacy_backend, validate_public_statement, verify_ring_family_input,
    PrivacyBackendPreference, RingFamilyVerifyError, RingFamilyVerifyInput,
    TransactionPrivacyConstraints, TransactionPublicStatement,
};
use misaka_storage::utxo_set::{BlockDelta, UtxoError, UtxoSet};
use misaka_types::utxo::*;
use misaka_types::validator::Proposal;
use sha3::{Digest, Sha3_256};
use std::collections::HashSet;

use super::validation_pipeline::validate_resolved_privacy_constraints;
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
    TxRingAmountsNotUniform {
        index: usize,
        input: usize,
        amounts: Vec<u64>,
    },
    #[error("tx[{index}] amount mismatch: inputs={inputs}, outputs+fee={required}")]
    TxAmountMismatch {
        index: usize,
        inputs: u64,
        required: u64,
    },
    #[error("tx[{index}] privacy constraints mismatch: {reason}")]
    TxPrivacyConstraints { index: usize, reason: String },
    #[error("tx[{index}] public statement mismatch: {reason}")]
    TxPublicStatement { index: usize, reason: String },
    #[error("tx[{index}] zero-knowledge proof: {reason}")]
    TxZeroKnowledge { index: usize, reason: String },
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
    LogRing { raw_sig: Vec<u8> },
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
    /// Optional common privacy statement derived from resolved inputs.
    ///
    /// This does not replace scheme-specific verification. It exists so the
    /// current LogRing path and a future ZKP path can talk about the same
    /// transaction-level statement.
    pub privacy_constraints: Option<TransactionPrivacyConstraints>,
    /// Public statement built from resolved rings and tx bindings.
    ///
    /// This is the future-facing seam for ZK membership/nullifier proofs.
    pub privacy_statement: Option<TransactionPublicStatement>,
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
    validate_and_apply_block_with_backend(
        block,
        utxo_set,
        validator_set,
        PrivacyBackendPreference::RingSignature,
    )
}

#[cfg(feature = "stark-stub")]
pub fn validate_and_apply_block_zero_knowledge(
    block: &BlockCandidate,
    utxo_set: &mut UtxoSet,
    validator_set: Option<&ValidatorSet>,
) -> Result<BlockDelta, BlockError> {
    validate_and_apply_block_with_backend(
        block,
        utxo_set,
        validator_set,
        PrivacyBackendPreference::ZeroKnowledge,
    )
}

fn validate_and_apply_block_with_backend(
    block: &BlockCandidate,
    utxo_set: &mut UtxoSet,
    validator_set: Option<&ValidatorSet>,
    backend_preference: PrivacyBackendPreference,
) -> Result<BlockDelta, BlockError> {
    // ═══ 0a. Structural bounds ═══
    if block.transactions.len() > MAX_TXS_PER_BLOCK {
        return Err(BlockError::TxStructural {
            index: 0,
            reason: format!(
                "block has {} txs, max is {}",
                block.transactions.len(),
                MAX_TXS_PER_BLOCK
            ),
        });
    }

    // ═══ 0b. Height monotonicity ═══
    if block.height > 0 && block.height != utxo_set.height + 1 {
        return Err(BlockError::Proposer(format!(
            "height mismatch: block={}, expected={}",
            block.height,
            utxo_set.height + 1
        )));
    }

    // ═══ 0c. Proposer Verification + Block Hash Binding ═══
    if let Some(vs) = validator_set {
        let proposal = block
            .proposer_signature
            .as_ref()
            .ok_or(BlockError::ProposerSigMissing)?;

        // 0a. Proposer authorization for slot
        let expected = super::proposer::proposer_for_slot(vs, block.slot)
            .ok_or(BlockError::ProposerNotAuthorized { slot: block.slot })?;

        if proposal.proposer != expected {
            return Err(BlockError::Proposer(format!(
                "wrong proposer for slot {}",
                block.slot
            )));
        }

        // 0b. Slot binding
        if proposal.slot != block.slot {
            return Err(BlockError::Proposer(format!(
                "slot mismatch: proposal={}, block={}",
                proposal.slot, block.slot
            )));
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
        )
        .map_err(|e| BlockError::Proposer(format!("sig verify: {e}")))?;
    }

    // ═══ 1. Transaction Validation ═══
    let mut delta = BlockDelta::new(block.height);
    let mut seen_nullifiers: HashSet<[u8; 32]> = HashSet::new();
    let a = derive_public_param(&DEFAULT_A_SEED);

    for (tx_idx, vtx) in block.transactions.iter().enumerate() {
        let tx = &vtx.tx;
        let selected_backend = select_privacy_backend(tx, backend_preference).map_err(|e| {
            BlockError::TxStructural {
                index: tx_idx,
                reason: format!("backend selection failed: {e}"),
            }
        })?;

        // Structural validation
        tx.validate_structure()
            .map_err(|e| BlockError::TxStructural {
                index: tx_idx,
                reason: e.to_string(),
            })?;

        let mut sum_input_amount: u64 = 0;

        for (in_idx, input) in tx.inputs.iter().enumerate() {
            let ki_hex = hex::encode(input.key_image);

            // ── Nullifier checks ──
            if !seen_nullifiers.insert(input.key_image) {
                return Err(BlockError::BlockDuplicateKeyImage { ki: ki_hex });
            }
            if utxo_set.has_key_image(&input.key_image) {
                return Err(BlockError::TxKeyImageConflict {
                    index: tx_idx,
                    ki: ki_hex,
                });
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
                sum_input_amount = sum_input_amount.checked_add(ring_amount).ok_or_else(|| {
                    BlockError::TxAmountMismatch {
                        index: tx_idx,
                        inputs: u64::MAX,
                        required: 0,
                    }
                })?;
            }

            if selected_backend.backend_family == misaka_pqc::PrivacyBackendFamily::RingSignature {
                let (raw_sig, raw_ki_proof) = match &vtx.ring_proofs[in_idx] {
                    VerifiedRingProof::LogRing { raw_sig } => (raw_sig.clone(), Vec::new()),
                    VerifiedRingProof::Lrs { sig, ki_proof } => (
                        sig.to_bytes(),
                        ki_proof
                            .as_ref()
                            .map(|proof| proof.to_bytes())
                            .unwrap_or_default(),
                    ),
                    #[cfg(feature = "chipmunk")]
                    VerifiedRingProof::Chipmunk {
                        raw_sig,
                        raw_ki_proof,
                    } => (raw_sig.clone(), raw_ki_proof.clone()),
                };

                let verify = RingFamilyVerifyInput {
                    a_param: &a,
                    ring_pubkeys: pks,
                    signing_digest: &digest,
                    input_key_image: &input.key_image,
                    raw_ring_signature: &raw_sig,
                    raw_ki_proof: &raw_ki_proof,
                };

                verify_ring_family_input(&selected_backend, tx, in_idx, &verify).map_err(|e| {
                    match e {
                        RingFamilyVerifyError::ProofParse(reason) => BlockError::TxRingSig {
                            index: tx_idx,
                            reason,
                        },
                        RingFamilyVerifyError::SignatureInvalid(reason) => BlockError::TxRingSig {
                            index: tx_idx,
                            reason,
                        },
                        RingFamilyVerifyError::SpendIdentifierMismatch(_) => {
                            BlockError::TxLinkTagMismatch { index: tx_idx }
                        }
                        RingFamilyVerifyError::MissingKeyImageProof => BlockError::TxKiProof {
                            index: tx_idx,
                            reason: "KI proof is REQUIRED for this backend but was None".into(),
                        },
                        RingFamilyVerifyError::KeyImageProofInvalid(reason) => {
                            BlockError::TxKiProof {
                                index: tx_idx,
                                reason,
                            }
                        }
                        RingFamilyVerifyError::WrongBackendFamily(family) => {
                            BlockError::TxRingSig {
                                index: tx_idx,
                                reason: format!(
                                    "wrong backend family for block validation: {:?}",
                                    family
                                ),
                            }
                        }
                        RingFamilyVerifyError::UnsupportedScheme(scheme) => {
                            BlockError::TxUnsupportedScheme {
                                index: tx_idx,
                                scheme,
                            }
                        }
                    }
                })?;
            }
        }

        // ── Exact Amount Conservation (same-amount ring: sum is deterministic) ──
        let sum_outputs: u64 = tx
            .outputs
            .iter()
            .try_fold(0u64, |acc, o| acc.checked_add(o.amount))
            .ok_or_else(|| BlockError::TxAmountMismatch {
                index: tx_idx,
                inputs: sum_input_amount,
                required: u64::MAX,
            })?;
        let required =
            sum_outputs
                .checked_add(tx.fee)
                .ok_or_else(|| BlockError::TxAmountMismatch {
                    index: tx_idx,
                    inputs: sum_input_amount,
                    required: u64::MAX,
                })?;
        if sum_input_amount != required {
            return Err(BlockError::TxAmountMismatch {
                index: tx_idx,
                inputs: sum_input_amount,
                required,
            });
        }

        if let Some(ref constraints) = vtx.privacy_constraints {
            validate_resolved_privacy_constraints(
                constraints,
                tx,
                sum_input_amount,
                sum_outputs,
                selected_backend.backend_family,
            )
            .map_err(|e| BlockError::TxPrivacyConstraints {
                index: tx_idx,
                reason: e.to_string(),
            })?;
            if let Some(ref statement) = vtx.privacy_statement {
                validate_public_statement(
                    statement,
                    tx,
                    constraints,
                    selected_backend.backend_family,
                )
                .map_err(|e| BlockError::TxPublicStatement {
                    index: tx_idx,
                    reason: e.to_string(),
                })?;
            }
            if selected_backend.backend_family == misaka_pqc::PrivacyBackendFamily::ZeroKnowledge {
                #[cfg(feature = "stark-stub")]
                {
                    let statement = vtx.privacy_statement.as_ref().ok_or_else(|| {
                        BlockError::TxZeroKnowledge {
                            index: tx_idx,
                            reason: "zero-knowledge path requires public statement".into(),
                        }
                    })?;
                    verify_zero_knowledge_tx_with_statement(
                        &selected_backend,
                        tx,
                        constraints,
                        statement,
                    )
                    .map_err(|e| BlockError::TxZeroKnowledge {
                        index: tx_idx,
                        reason: e.to_string(),
                    })?;
                }
                #[cfg(not(feature = "stark-stub"))]
                return Err(BlockError::TxZeroKnowledge {
                    index: tx_idx,
                    reason: "zero-knowledge backend unavailable without stark-stub feature".into(),
                });
            }
        } else if selected_backend.backend_family == misaka_pqc::PrivacyBackendFamily::ZeroKnowledge
        {
            return Err(BlockError::TxZeroKnowledge {
                index: tx_idx,
                reason: "zero-knowledge path requires resolved privacy constraints".into(),
            });
        }

        // ── Apply: nullifiers + outputs + spending keys ──
        let tx_hash = tx.tx_hash();
        let mut tx_delta = BlockDelta::new(block.height);

        for input in &tx.inputs {
            utxo_set
                .record_nullifier(input.key_image)
                .map_err(BlockError::Utxo)?;
            tx_delta.key_images_added.push(input.key_image);
        }

        for (idx, output) in tx.outputs.iter().enumerate() {
            let outref = OutputRef {
                tx_hash,
                output_index: idx as u32,
            };
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
    utxo_set
        .apply_block(delta.clone())
        .map_err(|e| BlockError::Utxo(e))?;

    Ok(delta)
}

/// Rollback the last applied block.
pub fn rollback_block(utxo_set: &mut UtxoSet) -> Result<BlockDelta, BlockError> {
    utxo_set.rollback_block().map_err(BlockError::from)
}
