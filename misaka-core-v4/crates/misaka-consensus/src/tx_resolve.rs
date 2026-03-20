//! Transaction Resolution — build VerifiedTx from raw UtxoTransaction + UtxoSet.
//!
//! # DEPRECATION NOTICE (v4)
//!
//! This module handles v1/v2/v3 (ring signature) transactions only.
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

use misaka_pqc::ki_proof::KiProof;
use misaka_pqc::packing;
use misaka_pqc::pq_ring::{derive_public_param, Poly, RingSig, DEFAULT_A_SEED};
use misaka_pqc::PrivacyBackendFamily;
use misaka_pqc::TransactionPrivacyConstraints;
use misaka_pqc::TransactionPublicStatement;
use misaka_storage::utxo_set::UtxoSet;
#[cfg(feature = "chipmunk")]
use misaka_types::utxo::RING_SCHEME_CHIPMUNK;
use misaka_types::utxo::{UtxoTransaction, RING_SCHEME_LOGRING, RING_SCHEME_LRS};

use crate::block_validation::{VerifiedRingProof, VerifiedTx};

/// Error during transaction resolution.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("input[{index}] ring member {member} not found in UTXO set")]
    RingMemberNotFound { index: usize, member: String },
    #[error("input[{index}] ring member has no spending pubkey")]
    NoSpendingKey { index: usize },
    #[error("input[{index}] spending pubkey parse error: {reason}")]
    PubkeyParse { index: usize, reason: String },
    #[error("input[{index}] ring signature parse error: {reason}")]
    RingSigParse { index: usize, reason: String },
    #[error("input[{index}] KI proof parse error: {reason}")]
    KiProofParse { index: usize, reason: String },
    #[error("input[{index}] UTXO amount lookup failed for ring member {member}")]
    AmountLookup { index: usize, member: String },
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
    resolve_tx_with_backend_family(tx, utxo_set, PrivacyBackendFamily::RingSignature)
}

pub fn resolve_tx_with_backend_family(
    tx: &UtxoTransaction,
    utxo_set: &UtxoSet,
    backend_family: PrivacyBackendFamily,
) -> Result<VerifiedTx, ResolveError> {
    let mut ring_pubkeys_all = Vec::with_capacity(tx.inputs.len());
    let mut ring_amounts_all = Vec::with_capacity(tx.inputs.len());
    let mut ring_proofs = Vec::with_capacity(tx.inputs.len());

    for (i, input) in tx.inputs.iter().enumerate() {
        // ── Resolve ring member public keys ──
        let mut pks = Vec::with_capacity(input.ring_members.len());
        let mut amounts = Vec::with_capacity(input.ring_members.len());

        for (m_idx, member) in input.ring_members.iter().enumerate() {
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
            let poly = Poly::from_bytes(pk_bytes).map_err(|e| ResolveError::PubkeyParse {
                index: i,
                reason: e.to_string(),
            })?;
            pks.push(poly);
            amounts.push(entry.output.amount);
        }

        ring_pubkeys_all.push(pks);
        ring_amounts_all.push(amounts);

        // ── Build scheme-typed ring proof ──
        let proof = match tx.ring_scheme {
            RING_SCHEME_LRS => {
                let ring_size = input.ring_members.len();
                let sig = parse_ring_sig(&input.ring_signature, ring_size, i)?;
                let ki_proof = if !input.ki_proof.is_empty() {
                    Some(KiProof::from_bytes(&input.ki_proof).map_err(|e| {
                        ResolveError::KiProofParse {
                            index: i,
                            reason: e.to_string(),
                        }
                    })?)
                } else {
                    None
                };
                VerifiedRingProof::Lrs { sig, ki_proof }
            }
            RING_SCHEME_LOGRING => VerifiedRingProof::LogRing {
                raw_sig: input.ring_signature.clone(),
            },
            #[cfg(feature = "chipmunk")]
            RING_SCHEME_CHIPMUNK => VerifiedRingProof::Chipmunk {
                raw_sig: input.ring_signature.clone(),
                raw_ki_proof: input.ki_proof.clone(),
            },
            other => {
                return Err(ResolveError::RingSigParse {
                    index: i,
                    reason: format!("unsupported ring scheme: 0x{:02x}", other),
                });
            }
        };
        ring_proofs.push(proof);
    }

    let privacy_constraints =
        resolved_same_amount_inputs(&ring_amounts_all).and_then(|input_amounts| {
            TransactionPrivacyConstraints::from_tx_and_input_amounts_for_backend(
                tx,
                &input_amounts,
                backend_family,
            )
            .ok()
        });
    let privacy_statement = privacy_constraints.as_ref().and_then(|constraints| {
        TransactionPublicStatement::from_constraints_and_resolved_rings(
            tx,
            constraints,
            &ring_pubkeys_all,
            backend_family,
        )
        .ok()
    });

    Ok(VerifiedTx {
        tx: tx.clone(),
        ring_pubkeys: ring_pubkeys_all,
        ring_amounts: ring_amounts_all,
        ring_proofs,
        privacy_constraints,
        privacy_statement,
    })
}

/// Parse a ring signature from raw bytes, trying multiple formats.
fn parse_ring_sig(raw: &[u8], ring_size: usize, input_idx: usize) -> Result<RingSig, ResolveError> {
    // Try v2 (compact) first, then v0 (raw), then direct
    if let Ok(sig) = packing::unpack_ring_sig_v2(raw, ring_size) {
        return Ok(sig);
    }
    if let Ok(sig) = packing::unpack_ring_sig(raw, ring_size) {
        return Ok(sig);
    }
    RingSig::from_bytes(raw, ring_size).map_err(|e| ResolveError::RingSigParse {
        index: input_idx,
        reason: e.to_string(),
    })
}

fn resolved_same_amount_inputs(ring_amounts: &[Vec<u64>]) -> Option<Vec<u64>> {
    let mut input_amounts = Vec::with_capacity(ring_amounts.len());
    for amounts in ring_amounts {
        let first = *amounts.first()?;
        if amounts.iter().any(|amt| *amt != first) {
            return None;
        }
        input_amounts.push(first);
    }
    Some(input_amounts)
}
