//! Transaction Resolution — build VerifiedTx from raw UtxoTransaction + UtxoSet.
//!
//! # DEPRECATION NOTICE (v4)
//!
//! This module handles v1/v2/v3 (ML-DSA signature) transactions only.
//! v4 (Q-DAG-CT) transactions use `VerifiedTransactionEnvelope` from
//! `misaka_pqc::verified_envelope` and bypass this module entirely.
//! This module will be removed once v1/v2/v3 transaction support is sunset.
//!
//! # Purpose
//!
//! This module bridges the gap between the mempool (which stores raw
//! `UtxoTransaction`) and the consensus layer (which requires `VerifiedTx`
//! with resolved ring pubkeys, amounts, parsed signatures, and KI proofs).
//!
//! The block producer calls `resolve_tx()` for each transaction when
//! constructing a `BlockCandidate`, ensuring all transactions pass through
//! `validate_and_apply_block()` — the single consensus validation path.
//!
//! # Architecture Invariant
//!
//! ```text
//! Mempool (verified admission)
//!   → block_producer collects top-by-fee
//!   → resolve_tx() builds VerifiedTx for each    ← THIS MODULE
//!   → BlockCandidate assembled
//!   → execute_block() / validate_and_apply_block()  ← SINGLE VALIDATION PATH
//!   → state committed atomically
//! ```

// Phase 2c-B D4: ring re-export removed; use direct path
use misaka_pqc::key_derivation::Poly;
use misaka_storage::utxo_set::UtxoSet;
use misaka_types::utxo::UtxoTransaction;

use crate::block_validation::{VerifiedProof, VerifiedTx};

/// Error during transaction resolution.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("input[{index}] ring member {member} not found in UTXO set")]
    RingMemberNotFound { index: usize, member: String },
    #[error("input[{index}] ring member has no spending pubkey")]
    NoSpendingKey { index: usize },
    #[error("input[{index}] spending pubkey parse error: {reason}")]
    PubkeyParse { index: usize, reason: String },
    #[error("input[{index}] ML-DSA signature parse error: {reason}")]
    RingSigParse { index: usize, reason: String },
    #[error("input[{index}] KI proof parse error: {reason}")]
    KiProofParse { index: usize, reason: String },
    #[error("input[{index}] UTXO amount lookup failed for ring member {member}")]
    AmountLookup { index: usize, member: String },
    #[error("input[{index}]: {reason}")]
    InvalidRingSize { index: usize, reason: String },
}

/// Resolve a raw `UtxoTransaction` into a `VerifiedTx` by looking up
/// ring member public keys and amounts from the UTXO set.
///
/// This does NOT perform cryptographic verification — that is the job of
/// `validate_and_apply_block()`. This function only gathers the data
/// needed for verification.
///
/// # Arguments
///
/// * `tx` - Raw transaction from mempool
/// * `utxo_set` - Current UTXO set for ring member resolution
///
/// # Returns
///
/// A `VerifiedTx` ready to be included in a `BlockCandidate`.
pub fn resolve_tx(tx: &UtxoTransaction, utxo_set: &UtxoSet) -> Result<VerifiedTx, ResolveError> {
    let mut ring_pubkeys_all = Vec::with_capacity(tx.inputs.len());
    let mut ring_amounts_all = Vec::with_capacity(tx.inputs.len());
    let mut ring_proofs = Vec::with_capacity(tx.inputs.len());
    let mut raw_spending_keys_all: Vec<Vec<u8>> = Vec::with_capacity(tx.inputs.len());

    for (i, input) in tx.inputs.iter().enumerate() {
        // ── Resolve ring member public keys ──
        let mut pks = Vec::with_capacity(input.utxo_refs.len());
        let mut amounts = Vec::with_capacity(input.utxo_refs.len());
        // Phase 34 (H-2 fix): Collect raw spending keys for ALL ring members,
        // not just the last one. For transparent mode (anonymity_set_size=1)
        // there's only one member, but this code must be correct for any ring size.
        let mut raw_pk_bytes_per_member: Vec<Vec<u8>> = Vec::new();

        for (_m_idx, member) in input.utxo_refs.iter().enumerate() {
            let entry = utxo_set
                .get(member)
                .ok_or_else(|| ResolveError::RingMemberNotFound {
                    index: i,
                    member: format!(
                        "{}:{}",
                        hex::encode(&member.tx_hash[..8]),
                        member.output_index
                    ),
                })?;

            let pk_bytes = utxo_set
                .get_spending_key(member)
                .ok_or(ResolveError::NoSpendingKey { index: i })?;

            // D4b: privacy fields deleted — all TXs use transparent (ML-DSA-65).
            // Store raw pk bytes, skip Poly parse.
            raw_pk_bytes_per_member.push(pk_bytes.to_vec());
            // Push a placeholder Poly (not used in ML-DSA verify path)
            pks.push(Poly::zero());
            amounts.push(entry.output.amount);
        }

        ring_pubkeys_all.push(pks);
        ring_amounts_all.push(amounts);

        // SEC-FIX: Enforce ring_size=1 in transparent mode.
        // Without this check, only the first member's key is used for signature
        // verification, allowing other ring members to spend without verification.
        if raw_pk_bytes_per_member.len() != 1 {
            return Err(ResolveError::InvalidRingSize {
                index: i,
                reason: format!(
                    "transparent mode requires exactly 1 ring member, got {}",
                    raw_pk_bytes_per_member.len()
                ),
            });
        }
        raw_spending_keys_all.push(raw_pk_bytes_per_member[0].clone());

        // ── Build transparent proof ──
        // D4b: privacy fields deleted — all TXs are transparent (ML-DSA-65 direct sig).
        let proof = VerifiedProof::Transparent {
            raw_sig: input.proof.clone(),
        };
        ring_proofs.push(proof);
    }

    Ok(VerifiedTx {
        tx: tx.clone(),
        ring_pubkeys: ring_pubkeys_all,
        raw_spending_keys: raw_spending_keys_all,
        ring_amounts: ring_amounts_all,
        ring_proofs,
    })
}
