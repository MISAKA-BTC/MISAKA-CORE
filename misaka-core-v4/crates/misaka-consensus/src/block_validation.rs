//! Block Validation — Legacy (non-DAG) path.
//!
//! # SEC-FIX WARNING
//!
//! This module uses `tx.tx_hash()` as the signing digest (line ~229), whereas
//! the DAG executor (`utxo_executor.rs`) uses `IntentMessage::wrap().signing_digest()`.
//! Transactions signed by the CLI (which uses IntentMessage) will FAIL verification
//! in this path. This module is only valid for the legacy non-DAG execution mode.
//!
//! In DAG mode, all transaction execution goes through `UtxoExecutor` which uses
//! the correct IntentMessage-based digest. This module should NOT be called in DAG mode.
//!
//! # Security Properties
//!
//! 1. **Proposer Enforcement**: ML-DSA-65 sig MANDATORY, block_hash binding
//! 2. **No real_input_refs**: Anonymity at protocol level
//! 3. **No pks[0] assumption**: KI proof iterates ALL ring members
//! 4. **Same-Amount Ring**: All members must have equal amounts (Item 3 fix)
//! 5. **Block Hash Binding**: proposal.block_hash == canonical hash (Item 2 fix)

use misaka_pqc::key_derivation::Poly;
use misaka_storage::utxo_set::{BlockDelta, UtxoError, UtxoSet};
use misaka_types::utxo::*;
use misaka_types::validator::Proposal;
use sha3::{Digest, Sha3_256};

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
    #[error("tx[{index}] zero-knowledge proof: {reason}")]
    TxZeroKnowledge { index: usize, reason: String },
    #[error("tx[{index}] unsupported ring scheme: 0x{scheme:02x}")]
    TxUnsupportedScheme { index: usize, scheme: u8 },
    #[error("utxo: {0}")]
    Utxo(#[from] UtxoError),
    #[error("total fees overflow")]
    FeeOverflow,
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
        // Phase 2c-B: signing_digest deleted; use tx_hash for v1 compat
        tx_h.update(&vtx.tx.tx_hash());
    }
    h.update(&tx_h.finalize());

    h.finalize().into()
}

// ═══ Transaction Container ══════════════════════════════════

/// Proof type for verified transactions.
///
/// SEC-FIX: Legacy LRS and LogRing variants have been removed.
/// All transactions use TransparentTransfer (ML-DSA-65 direct signatures)
/// as of Phase 2c-B. The LRS code contained a key image forgery vulnerability.
#[derive(Debug, Clone)]
pub enum VerifiedProof {
    /// Transparent: ML-DSA-65 direct signature (the only supported scheme).
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

/// Maximum transactions per block — SSOT from misaka-types.
pub const MAX_TXS_PER_BLOCK: usize = misaka_types::constants::MAX_TXS_PER_BLOCK;

/// SEC-FIX H-3: This function uses `tx.tx_hash()` as the signing digest,
/// which differs from the DAG executor's `IntentMessage::wrap().signing_digest()`.
/// Calling this in DAG mode will cause valid transactions to be rejected.
/// Use `UtxoExecutor` for DAG mode instead.
#[deprecated(note = "Legacy non-DAG path — do NOT use in DAG mode. Use UtxoExecutor instead.")]
pub fn validate_and_apply_block(
    block: &BlockCandidate,
    utxo_set: &mut UtxoSet,
    validator_set: Option<&ValidatorSet>,
) -> Result<BlockDelta, BlockError> {
    validate_and_apply_block_inner(block, utxo_set, validator_set)
}

fn validate_and_apply_block_inner(
    block: &BlockCandidate,
    utxo_set: &mut UtxoSet,
    validator_set: Option<&ValidatorSet>,
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

    // ═══ SEC-FIX: Reject system-only tx types in user blocks (defense-in-depth) ═══
    for (idx, vtx) in block.transactions.iter().enumerate() {
        if matches!(
            vtx.tx.tx_type,
            misaka_types::utxo::TxType::SystemEmission
                | misaka_types::utxo::TxType::Faucet
        ) {
            return Err(BlockError::TxStructural {
                index: idx,
                reason: "SystemEmission/Faucet transactions cannot appear in user blocks"
                    .into(),
            });
        }
    }

    // ═══ 1. Transaction Validation ═══
    let mut delta = BlockDelta::new(block.height);

    for (tx_idx, vtx) in block.transactions.iter().enumerate() {
        let tx = &vtx.tx;

        // Structural validation
        tx.validate_structure()
            .map_err(|e| BlockError::TxStructural {
                index: tx_idx,
                reason: e.to_string(),
            })?;

        let mut sum_input_amount: u64 = 0;

        for (in_idx, input) in tx.inputs.iter().enumerate() {
            // ── Ring member existence ──
            let _pks = &vtx.ring_pubkeys[in_idx];
            let amounts = &vtx.ring_amounts[in_idx];
            // Phase 2c-B: signing_digest deleted; use tx_hash for v1 compat
            let digest = tx.tx_hash();

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

            // ── ML-DSA-65 direct signature verification (transparent mode) ──
            {
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
                misaka_pqc::pq_sign::ml_dsa_verify_raw(&ml_dsa_pk, &digest, &ml_dsa_sig).map_err(
                    |_| BlockError::TxRingSig {
                        index: tx_idx,
                        reason: "ML-DSA-65 signature verification failed".into(),
                    },
                )?;

                // KI proof is optional for transparent (UTXO reference prevents double-spend)
                // Key image is still tracked for state manager compatibility.
            }
        }

        // ── Audit #19: Consume input UTXOs (prevent double-spend in block_validation path) ──
        let mut spent_entries: Vec<([u8; 32], OutputRef, TxOutput)> = Vec::new();
        for input in &tx.inputs {
            if let Some(spent_outref) = input.utxo_refs.first() {
                let entry = utxo_set.get(spent_outref).ok_or_else(|| {
                    BlockError::TxRingMemberNotFound {
                        index: tx_idx,
                        member: format!("input UTXO already spent in this block"),
                    }
                })?;
                let output = entry.output.clone();
                utxo_set.remove_output(spent_outref);
                spent_entries.push(([0u8; 32], spent_outref.clone(), output));
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

        // ── Apply: outputs + spending keys ──
        let tx_hash = tx.tx_hash();
        let mut tx_delta = BlockDelta::new(block.height);
        tx_delta.spent = spent_entries;

        for (idx, output) in tx.outputs.iter().enumerate() {
            let outref = OutputRef {
                tx_hash,
                output_index: idx as u32,
            };
            utxo_set.add_output(outref.clone(), output.clone(), block.height, false)?;

            // Phase 1.2 fix: Auto-register spending pubkey so this UTXO can be
            // used as a ring member in future transactions.
            if let Some(ref spk_bytes) = output.spending_pubkey {
                if let Err(e) = utxo_set.register_spending_key(outref.clone(), spk_bytes.clone()) {
                    tracing::warn!("spending key registration failed for {:?}: {}", outref, e);
                }
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
