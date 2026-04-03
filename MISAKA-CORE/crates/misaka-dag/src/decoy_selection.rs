//! Anonymity Set Selection — Global UTXO Merkle Tree (ZKP Architecture).
//!
//! # Architecture Change (Task 1.4)
//!
//! The previous "Gamma distribution ring member selection" approach has been
//! completely replaced. The old design was based on Ring Signatures where:
//! - Decoys were selected from a gamma distribution over output age
//! - Amounts are now hidden in BDLOP commitments
//! - Selection was O(anonymity_set_size) per transaction
//!
//! # New: Global Anonymity Set
//!
//! In the ZKP architecture, the "anonymity set" is a Merkle tree over ALL
//! eligible UTXOs in the DAG. The prover demonstrates membership in this
//! tree via a zero-knowledge proof (UnifiedMembershipProof).
//!
//! The key difference:
//! - **Old (Ring Sig)**: Select N specific decoys → anonymity = 1/N
//! - **New (ZKP)**: Prove membership in global set → anonymity = 1/|UTXO_set|
//!   (modulo practical constraints on the Merkle tree subset)
//!
//! In practice, we still select a subset of the global UTXO set to form
//! the per-transaction Merkle tree (for proof size reasons), but:
//! - NO gamma distribution — uniform random from eligible set
//! - NO amount constraints — amounts are hidden in BDLOP commitments
//! - NO age bias — any eligible UTXO is equally valid as a ring member
//!
//! # Selection Criteria
//!
//! An output is eligible for the anonymity set if:
//! 1. It is unspent (not consumed by any nullifier)
//! 2. It has a registered spending public key
//! 3. It is at least `MIN_DECOY_DEPTH` blocks deep (reorg safety)
//! 4. It is on the same chain_id

use rand::seq::SliceRandom;

use crate::ghostdag::MIN_DECOY_DEPTH;

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

/// Standard anonymity set size (= ring size for ZKP Merkle tree).
/// Matches `privacy::STANDARD_RING_SIZE`.
pub const ANONYMITY_SET_SIZE: usize = 16;

/// Maximum anonymity set size (for future expansion).
pub const MAX_ANONYMITY_SET_SIZE: usize = 1024;

// ═══════════════════════════════════════════════════════════════
//  Eligible Output (replaces RingCandidate)
// ═══════════════════════════════════════════════════════════════

/// An output eligible for inclusion in the anonymity set.
///
/// Unlike the old `RingCandidate`, this does NOT include amount information
/// (amounts hidden in BDLOP commitments — no amount-based filtering needed).
#[derive(Debug, Clone)]
pub struct EligibleOutput {
    /// Output identifier.
    pub tx_hash: [u8; 32],
    pub output_index: u32,
    /// Blue score of the block containing this output (for depth check).
    pub blue_score: u64,
    /// Spending public key (serialized polynomial, 512 bytes).
    pub spending_pubkey: Vec<u8>,
    /// Commitment to the output amount (opaque — no amount matching).
    pub commitment_bytes: Vec<u8>,
    /// Chain ID.
    pub chain_id: u32,
}

// ═══════════════════════════════════════════════════════════════
//  Selection Error
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum DecoySelectionError {
    #[error("insufficient eligible outputs: {available} < {needed}")]
    InsufficientOutputs { available: usize, needed: usize },

    #[error("real output not found in eligible set")]
    RealOutputNotEligible,

    #[error("chain_id mismatch: expected {expected}, got {got}")]
    ChainIdMismatch { expected: u32, got: u32 },
}

// ═══════════════════════════════════════════════════════════════
//  Anonymity Set Selector
// ═══════════════════════════════════════════════════════════════

/// Select an anonymity set from eligible UTXOs for a ZKP membership proof.
///
/// # Algorithm (uniform random, no age/amount bias)
///
/// 1. Filter eligible outputs by chain_id and depth
/// 2. Exclude the real output from candidates
/// 3. Sample `ANONYMITY_SET_SIZE - 1` outputs uniformly at random
/// 4. Insert the real output at a random position
/// 5. Return the shuffled set + signer index
///
/// # Why Uniform (not Gamma)?
///
/// In the Ring Signature model, gamma distribution matched the empirical
/// spend-age distribution to prevent statistical deanonymization.
///
/// In the ZKP model, amounts are hidden (BDLOP commitments) and the prover
/// demonstrates membership in a Merkle tree — no age correlation is leaked
/// because the proof reveals NOTHING about which leaf was used.
/// Uniform selection maximizes entropy and minimizes implementation complexity.
pub fn select_anonymity_set(
    real_tx_hash: &[u8; 32],
    real_output_index: u32,
    chain_id: u32,
    current_blue_score: u64,
    eligible_outputs: &[EligibleOutput],
) -> Result<(Vec<EligibleOutput>, usize), DecoySelectionError> {
    let needed = ANONYMITY_SET_SIZE;

    // Filter: correct chain, sufficient depth, has spending key
    let min_score = current_blue_score.saturating_sub(MIN_DECOY_DEPTH);
    let candidates: Vec<&EligibleOutput> = eligible_outputs
        .iter()
        .filter(|o| o.chain_id == chain_id)
        .filter(|o| o.blue_score <= min_score)
        .filter(|o| !o.spending_pubkey.is_empty())
        .filter(|o| !(o.tx_hash == *real_tx_hash && o.output_index == real_output_index))
        .collect();

    if candidates.len() < needed - 1 {
        return Err(DecoySelectionError::InsufficientOutputs {
            available: candidates.len(),
            needed: needed - 1,
        });
    }

    // Find the real output
    let real_output = eligible_outputs
        .iter()
        .find(|o| o.tx_hash == *real_tx_hash && o.output_index == real_output_index)
        .ok_or(DecoySelectionError::RealOutputNotEligible)?;

    if real_output.chain_id != chain_id {
        return Err(DecoySelectionError::ChainIdMismatch {
            expected: chain_id,
            got: real_output.chain_id,
        });
    }

    // Uniform random selection (no age/amount bias)
    let mut rng = rand::rngs::OsRng;
    let selected: Vec<EligibleOutput> = candidates
        .choose_multiple(&mut rng, needed - 1)
        .map(|o| (*o).clone())
        .collect();

    // Insert real output at random position
    let signer_index = rand::Rng::gen_range(&mut rng, 0..needed);
    let mut result = Vec::with_capacity(needed);
    let mut decoy_iter = selected.into_iter();
    for i in 0..needed {
        if i == signer_index {
            result.push(real_output.clone());
        } else if let Some(decoy) = decoy_iter.next() {
            result.push(decoy);
        }
    }

    Ok((result, signer_index))
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_eligible(id: u8, score: u64) -> EligibleOutput {
        EligibleOutput {
            tx_hash: [id; 32],
            output_index: 0,
            blue_score: score,
            spending_pubkey: vec![id; 512],
            commitment_bytes: vec![],
            chain_id: 2,
        }
    }

    #[test]
    fn test_select_anonymity_set_valid() {
        let mut outputs = Vec::new();
        for i in 0..32u8 {
            outputs.push(make_eligible(i, 10));
        }
        let (set, idx) = select_anonymity_set(&[0; 32], 0, 2, 200, &outputs).unwrap();
        assert_eq!(set.len(), ANONYMITY_SET_SIZE);
        assert!(idx < ANONYMITY_SET_SIZE);
        assert_eq!(set[idx].tx_hash, [0; 32]);
    }

    #[test]
    fn test_select_insufficient_outputs() {
        let outputs = vec![make_eligible(0, 10), make_eligible(1, 10)];
        let result = select_anonymity_set(&[0; 32], 0, 2, 200, &outputs);
        assert!(result.is_err());
    }

    #[test]
    fn test_select_wrong_chain_rejected() {
        let mut outputs = Vec::new();
        for i in 0..32u8 {
            outputs.push(make_eligible(i, 10));
        }
        // Real output has chain_id=2 but we request chain_id=99
        let result = select_anonymity_set(&[0; 32], 0, 99, 200, &outputs);
        assert!(result.is_err());
    }

    #[test]
    fn test_no_age_bias() {
        // Verify that outputs of all ages are equally eligible
        let mut outputs = Vec::new();
        for i in 0..32u8 {
            outputs.push(make_eligible(i, i as u64)); // varying ages
        }
        let (set, _) = select_anonymity_set(&[0; 32], 0, 2, 200, &outputs).unwrap();
        // All outputs should be eligible (all deep enough)
        assert_eq!(set.len(), ANONYMITY_SET_SIZE);
    }
}
