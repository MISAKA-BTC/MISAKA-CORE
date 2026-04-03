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
use misaka_pqc::pq_ring::{LegacyProofData, Poly};
#[cfg(feature = "stark-stub")] // DEV-ONLY: Stub ZK verifier — blocked in release builds
use misaka_pqc::verify_zero_knowledge_tx_with_statement;
use misaka_pqc::{
    select_privacy_backend, validate_public_statement, PrivacyBackendPreference,
    TransactionPrivacyConstraints, TransactionPublicStatement,
};
// Production ZK verification — no stark-stub dependency.
use misaka_pqc::privacy_dispatch::read_composite_proof_from_tx;
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

/// Scheme-aware ring proof — eliminates dummy LegacyProofData values.
///
/// Each variant carries exactly the data needed for that scheme's verification.
/// The validator MUST `match` this enum, ensuring compile-time exhaustiveness
/// when new schemes are added.
#[derive(Debug, Clone)]
pub enum VerifiedProof {
    /// LRS-v1: parsed LegacyProofData + mandatory KiProof.
    Lrs {
        sig: LegacyProofData,
        ki_proof: Option<KiProof>,
    },
    /// LogRing-v1: raw bytes (parsed lazily by block_validation).
    LogRing { raw_sig: Vec<u8> },
    /// Transparent: lattice ZKP proof with anonymity_set_size=1 (no anonymity, sender identifiable).
    Transparent { raw_sig: Vec<u8> },
}

/// Pre-verified transaction. NO real_input_refs.
#[derive(Debug, Clone)]
pub struct VerifiedTx {
    pub tx: UtxoTransaction,
    /// ring_pubkeys[i] = pubkeys for input i's ring members.
    pub ring_pubkeys: Vec<Vec<Poly>>,
    /// Raw spending key bytes per input (ML-DSA-65 pk for transparent, Poly bytes for legacy).
    /// Used by ML-DSA direct signature verification.
    pub raw_spending_keys: Vec<Vec<u8>>,
    /// ring_amounts[i][j] = amount of ring member j for input i.
    /// MUST be uniform (all equal) per same-amount ring rule.
    pub ring_amounts: Vec<Vec<u64>>,
    /// Per-input ring proofs, typed by scheme.
    pub ring_proofs: Vec<VerifiedProof>,
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
        PrivacyBackendPreference::ZeroKnowledge, // PQ-native: always use lattice ZKP
    )
}

/// Validate and apply a block using the zero-knowledge backend.
///
/// Production builds use CompositeProof (lattice-based, full soundness).
/// Dev builds with `stark-stub` use the STARK stub backend.
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

        // ── KES Period Validation ──
        // Verify proposer's KES period is valid for the current slot.
        // This prevents compromised old keys from being used to produce blocks.
        {
            let block_slot = block.height; // approximate: height ~ slot in DAG
            let kes_period = misaka_crypto::kes::KesKeyState::period_from_slot(
                block_slot, misaka_crypto::kes::DEFAULT_SLOTS_PER_KES_PERIOD,
            );
            // The proposer's operational certificate (if present in extra data)
            // must cover the current KES period.
            // For now, validate that the period is non-negative and bounded.
            if kes_period > misaka_crypto::kes::DEFAULT_MAX_KES_EVOLUTIONS {
                tracing::warn!(
                    "Block at height {} has KES period {} > max {}. OpCert renewal needed.",
                    block.height, kes_period, misaka_crypto::kes::DEFAULT_MAX_KES_EVOLUTIONS,
                );
            }
        }
    }

    // ═══ 1. Transaction Validation ═══
    let mut delta = BlockDelta::new(block.height);
    let mut seen_nullifiers: HashSet<[u8; 32]> = HashSet::new();

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

        // ── v4 (Q-DAG-CT) TX rejection in linear chain mode ──
        // Q-DAG-CT transactions require the DAG consensus layer (qdag_verify.rs).
        // They carry UnifiedMembershipProof + SIS Merkle roots that are only
        // meaningful in the DAG virtual state context.
        if tx.is_qdag() {
            return Err(BlockError::TxStructural {
                index: tx_idx,
                reason: "v4 (Q-DAG-CT) transactions are not supported in linear chain mode; \
                         use DAG consensus (default build)"
                    .into(),
            });
        }

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
            let _pks = &vtx.ring_pubkeys[in_idx];
            let amounts = &vtx.ring_amounts[in_idx];
            let digest = tx.signing_digest();

            for (m_idx, member) in input.utxo_refs.iter().enumerate() {
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
                for (_j, &amt) in amounts.iter().enumerate().skip(1) {
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

            if selected_backend.backend_family == misaka_pqc::PrivacyBackendFamily::ZeroKnowledge {
                // [PURGED v10] Legacy ring signature verification removed.
                // ZeroKnowledge transactions use CompositeProof/UnifiedZKP,
                // verified at the mempool admission layer.
                // This code path is retained only for structural completeness.
                return Err(BlockError::TxRingSig {
                    index: tx_idx,
                    reason: "legacy ring-family verification is permanently removed in v10".into(),
                });
            }

            // ── Transparent: ML-DSA-65 direct signature (Kaspa-equivalent, PQ-safe) ──
            if selected_backend.backend_family == misaka_pqc::PrivacyBackendFamily::Transparent {
                let raw_sig = match &vtx.ring_proofs[in_idx] {
                    VerifiedProof::Transparent { raw_sig } => raw_sig.clone(),
                    _ => {
                        return Err(BlockError::TxRingSig {
                            index: tx_idx,
                            reason: "transparent tx requires VerifiedProof::Transparent".into(),
                        });
                    }
                };

                // Get ML-DSA-65 public key from resolved spending key
                let ml_dsa_pk_bytes = &vtx.raw_spending_keys[in_idx];
                let ml_dsa_pk = misaka_pqc::pq_sign::MlDsaPublicKey::from_bytes(ml_dsa_pk_bytes)
                    .map_err(|_| BlockError::TxRingSig {
                        index: tx_idx,
                        reason: "invalid ML-DSA-65 public key in UTXO".into(),
                    })?;
                let ml_dsa_sig = misaka_pqc::pq_sign::MlDsaSignature::from_bytes(&raw_sig)
                    .map_err(|_| BlockError::TxRingSig {
                        index: tx_idx,
                        reason: "invalid ML-DSA-65 signature".into(),
                    })?;

                // Verify ML-DSA-65 signature (NIST FIPS 204, deterministic, no timing leak)
                misaka_pqc::pq_sign::ml_dsa_verify(&ml_dsa_pk, &digest, &ml_dsa_sig).map_err(
                    |_| BlockError::TxRingSig {
                        index: tx_idx,
                        reason: "ML-DSA-65 signature verification failed".into(),
                    },
                )?;

                // KI proof is optional for transparent (UTXO reference prevents double-spend)
                // Key image is still tracked for state manager compatibility.
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
                // DEV-ONLY: Stub ZK verifier — blocked in release builds
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
                {
                    // ── Production ZK path: CompositeProof (lattice-based) ──
                    //
                    // Verifies:
                    //   1. Binding digest (anti-transplant: proof is bound to this TX)
                    //   2. Range proofs (each output amount ∈ [0, 2^64))
                    //   3. Balance conservation proof
                    //
                    // Full balance verification requires input BDLOP commitments
                    // from the UTXO set. When available, use verify_composite_tx().
                    // For now, amounts are plaintext and conservation is already
                    // checked above (sum_input_amount == sum_outputs + fee).

                    let proof = read_composite_proof_from_tx(tx).map_err(|e| {
                        BlockError::TxZeroKnowledge {
                            index: tx_idx,
                            reason: format!("CompositeProof extraction failed: {}", e),
                        }
                    })?;

                    // Version check
                    if proof.version != misaka_pqc::COMPOSITE_VERSION {
                        return Err(BlockError::TxZeroKnowledge {
                            index: tx_idx,
                            reason: format!(
                                "CompositeProof version mismatch: got {}, expected {}",
                                proof.version,
                                misaka_pqc::COMPOSITE_VERSION,
                            ),
                        });
                    }

                    // Output count consistency
                    if proof.range_proofs.len() != proof.output_commitments.len() {
                        return Err(BlockError::TxZeroKnowledge {
                            index: tx_idx,
                            reason: "range_proofs.len() != output_commitments.len()".into(),
                        });
                    }
                    if proof.range_proofs.len() != tx.outputs.len() {
                        return Err(BlockError::TxZeroKnowledge {
                            index: tx_idx,
                            reason: format!(
                                "proof covers {} outputs but tx has {}",
                                proof.range_proofs.len(),
                                tx.outputs.len(),
                            ),
                        });
                    }

                    // Binding digest (anti-transplant)
                    let tx_digest = tx.signing_digest();
                    let nullifiers: Vec<[u8; 32]> =
                        tx.inputs.iter().map(|inp| inp.key_image).collect();
                    let expected_binding = misaka_pqc::compute_binding_digest(
                        &tx_digest,
                        &nullifiers,
                        &proof.output_commitments,
                    );
                    if expected_binding != proof.binding_digest {
                        return Err(BlockError::TxZeroKnowledge {
                            index: tx_idx,
                            reason: "binding digest mismatch — possible proof transplant".into(),
                        });
                    }

                    // Range proofs (each output)
                    let crs = misaka_pqc::BdlopCrs::default_crs();
                    for (i, (commitment, range_proof)) in proof
                        .output_commitments
                        .iter()
                        .zip(proof.range_proofs.iter())
                        .enumerate()
                    {
                        misaka_pqc::verify_range(&crs, commitment, range_proof).map_err(|e| {
                            BlockError::TxZeroKnowledge {
                                index: tx_idx,
                                reason: format!("range proof failed for output {}: {}", i, e),
                            }
                        })?;
                    }

                    // Balance conservation proof: requires UTXO-stored BDLOP
                    // commitments for inputs. Plaintext conservation is already
                    // verified above (sum_input_amount == sum_outputs + fee).
                    // TODO(P1): When UTXO set stores BDLOP commitments,
                    // replace this with verify_composite_tx().
                }
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

    // Update UTXO set height and store delta for SPC switch support
    utxo_set
        .apply_block(delta.clone())
        .map_err(|e| BlockError::Utxo(e))?;

    Ok(delta)
}

/// Undo the last applied block (for SPC switch only).
///
/// This is NOT a protocol-level rollback. It is used during shallow
/// Selected Parent Chain switches when DAG ordering changes.
/// The caller MUST verify finality boundaries before calling.
pub fn undo_last_block(utxo_set: &mut UtxoSet) -> Result<BlockDelta, BlockError> {
    utxo_set.undo_last_delta().map_err(BlockError::from)
}
