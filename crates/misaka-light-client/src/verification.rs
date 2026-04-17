// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Core verification logic — ported from misaka-consensus (~80 LOC).
//!
//! Does NOT depend on misaka-consensus (which pulls rocksdb/tokenomics).
//! Uses misaka-crypto for ML-DSA-65 verification directly.
//!
//! Formula: quorum = (total_stake * 2) / 3 + 1
//!          (same as misaka-consensus/validator_set.rs:45)

use std::collections::HashSet;

use misaka_crypto::validator_sig::{
    validator_verify, ValidatorPqPublicKey, ValidatorPqSignature,
};
use misaka_types::validator::{
    CommitteeVote, EpochTransitionProof, ValidatorId, ValidatorIdentity, ValidatorSignature,
};

use crate::error::LightClientError;

/// Compute total stake for a committee (saturating to prevent u128 overflow).
pub fn total_stake(committee: &[ValidatorIdentity]) -> u128 {
    committee
        .iter()
        .filter(|v| v.is_active)
        .map(|v| v.stake_weight)
        .fold(0u128, |acc, w| acc.saturating_add(w))
}

/// BFT quorum threshold: `(total * 2) / 3 + 1`.
///
/// Mirrors `misaka_consensus::validator_set::ValidatorSet::quorum_threshold`.
/// SEC-FIX NM-4: Avoids `(total * 2)` overflow via split arithmetic.
pub fn quorum_threshold(committee: &[ValidatorIdentity]) -> u128 {
    let total = total_stake(committee);
    let two_thirds = total / 3 * 2 + (total % 3) * 2 / 3;
    two_thirds + 1
}

/// Compute committee hash (same algorithm as ValidatorSet::set_hash).
///
/// Sorted by validator_id, then SHA3-256 of concatenated fields.
pub fn committee_hash(committee: &[ValidatorIdentity]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut sorted = committee.to_vec();
    sorted.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));
    let mut buf = Vec::new();
    for v in &sorted {
        buf.extend_from_slice(&v.validator_id);
        buf.extend_from_slice(&v.stake_weight.to_le_bytes());
        buf.extend_from_slice(&v.public_key.bytes);
        buf.push(v.is_active as u8);
    }
    let hash = Sha3_256::digest(&buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

/// Find a validator by ID and return its identity.
fn find_validator<'a>(
    committee: &'a [ValidatorIdentity],
    id: &ValidatorId,
) -> Result<&'a ValidatorIdentity, LightClientError> {
    committee
        .iter()
        .find(|v| v.validator_id == *id && v.is_active)
        .ok_or_else(|| LightClientError::UnknownVoter(hex::encode(id)))
}

/// Verify a single ML-DSA-65 validator signature.
fn verify_sig(
    vi: &ValidatorIdentity,
    message: &[u8],
    sig: &ValidatorSignature,
) -> Result<(), LightClientError> {
    let pk = ValidatorPqPublicKey::from_bytes(&vi.public_key.bytes)
        .map_err(|e| LightClientError::SignatureVerificationFailed(e.to_string()))?;
    let pq_sig = ValidatorPqSignature::from_bytes(&sig.bytes)
        .map_err(|e| LightClientError::SignatureVerificationFailed(e.to_string()))?;
    validator_verify(message, &pq_sig, &pk)
        .map_err(|e| LightClientError::SignatureVerificationFailed(e.to_string()))
}

/// Verify committee votes and return accumulated stake.
///
/// Ported from `misaka_consensus::committee::verify_committee_votes`.
/// Each vote is ML-DSA-65 verified — NO stub verifiers.
pub fn verify_committee_votes(
    committee: &[ValidatorIdentity],
    votes: &[CommitteeVote],
    expected_slot: u64,
    expected_block_hash: &[u8; 32],
    expected_epoch: u64,
    expected_chain_id: u32,
) -> Result<u128, LightClientError> {
    let mut seen = HashSet::new();
    let mut total: u128 = 0;

    for v in votes {
        if v.slot != expected_slot {
            return Err(LightClientError::SlotMismatch);
        }
        if v.block_hash != *expected_block_hash {
            return Err(LightClientError::BlockHashMismatch);
        }
        if v.epoch != expected_epoch {
            return Err(LightClientError::EpochMismatch {
                expected: expected_epoch,
                got: v.epoch,
            });
        }
        if v.chain_id != expected_chain_id {
            return Err(LightClientError::ChainIdMismatch {
                expected: expected_chain_id,
                got: v.chain_id,
            });
        }
        if !seen.insert(v.voter) {
            return Err(LightClientError::DuplicateVote(hex::encode(v.voter)));
        }

        let vi = find_validator(committee, &v.voter)?;
        verify_sig(vi, &v.signing_bytes(), &v.signature)?;
        total = total
            .checked_add(vi.stake_weight)
            .ok_or_else(|| {
                LightClientError::SignatureVerificationFailed("stake overflow".into())
            })?;
    }
    Ok(total)
}

/// Verify an epoch transition proof.
///
/// Checks that 2f+1 of the outgoing committee signed the transition
/// to the new committee.
pub fn verify_epoch_transition(
    outgoing_committee: &[ValidatorIdentity],
    proof: &EpochTransitionProof,
) -> Result<(), LightClientError> {
    if outgoing_committee.is_empty() {
        return Err(LightClientError::EmptyCommittee);
    }

    // Verify committee hash matches
    let computed = committee_hash(&proof.new_committee);
    if computed != proof.new_committee_hash {
        return Err(LightClientError::CommitteeHashMismatch);
    }

    let threshold = quorum_threshold(outgoing_committee);
    let signing_bytes = EpochTransitionProof::signing_bytes(
        proof.old_epoch,
        proof.new_epoch,
        &proof.new_committee_hash,
    );

    let mut seen = HashSet::new();
    let mut accumulated: u128 = 0;

    for vote in &proof.transition_votes {
        if !seen.insert(vote.voter) {
            return Err(LightClientError::DuplicateVote(hex::encode(vote.voter)));
        }
        let vi = find_validator(outgoing_committee, &vote.voter)?;
        verify_sig(vi, &signing_bytes, &vote.signature)?;
        accumulated = accumulated.saturating_add(vi.stake_weight);
    }

    if accumulated < threshold {
        return Err(LightClientError::QuorumNotReached {
            got: accumulated,
            need: threshold,
        });
    }
    Ok(())
}
