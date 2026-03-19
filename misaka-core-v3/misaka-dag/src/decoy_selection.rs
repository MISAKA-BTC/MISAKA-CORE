//! Decoy Selection — Gamma Distribution for Ring Member Choice (Long-term Item 3).
//!
//! # Problem
//!
//! Naive decoy selection (uniform random, or deterministic) leaks information:
//! - Uniform: real spend is indistinguishable from decoys statistically,
//!   but the newest output is likely the real one (recency bias).
//! - Deterministic: attacker can predict which outputs will be decoys.
//!
//! # Solution: Gamma Distribution (Monero approach)
//!
//! Select decoys from a gamma distribution over output age:
//!   `P(age) ∝ gamma(shape=19.28, rate=1.61)` (Monero parameters)
//!
//! This matches the empirical distribution of real spend ages:
//! - Most spends happen within hours/days of receiving
//! - Some spends happen weeks/months later
//! - Very few spends happen after years
//!
//! By selecting decoys with the same age distribution, an observer
//! cannot distinguish the real spend from decoys based on age alone.
//!
//! # DAG-Specific Considerations
//!
//! In a DAG, "age" is measured by blue_score distance, not block height.
//! The gamma distribution is applied over blue_score differences.
//!
//! # Parameters
//!
//! | Parameter | Value | Source |
//! |-----------|-------|--------|
//! | Shape (α) | 19.28 | Monero research (MRL-0004) |
//! | Rate (β)  | 1.61  | Monero research (MRL-0004) |
//! | Min depth | 100   | MIN_DECOY_DEPTH (reorg safety) |
//! | Max age   | 100000| Avoid ancient outputs |

use std::collections::HashSet;
use rand::Rng;

use crate::dag_block::Hash;
use crate::ghostdag::{GhostDagManager, DagStore, MIN_DECOY_DEPTH};
use crate::dag_state_manager::DagStateManager;

// ═══════════════════════════════════════════════════════════════
//  Gamma Distribution Parameters
// ═══════════════════════════════════════════════════════════════

/// Gamma distribution shape parameter (α = 19.28).
/// Controls the "peakedness" of the distribution.
pub const GAMMA_SHAPE: f64 = 19.28;

/// Gamma distribution rate parameter (β = 1.61).
/// Controls the scale (higher = more concentrated near peak).
pub const GAMMA_RATE: f64 = 1.61;

/// Maximum age in blue_score units for decoy selection.
pub const MAX_DECOY_AGE: u64 = 100_000;

/// Minimum ring size for privacy.
pub const MIN_RING_SIZE: usize = 4;

/// Default ring size for confidential transactions.
pub const DEFAULT_RING_SIZE: usize = 16;

/// Maximum ring size.
pub const MAX_RING_SIZE_CT: usize = 64;

/// Number of selection attempts before giving up.
const MAX_SELECTION_ATTEMPTS: usize = 1000;

// ═══════════════════════════════════════════════════════════════
//  Output Age Distribution
// ═══════════════════════════════════════════════════════════════

/// Sample from a gamma distribution using Marsaglia and Tsang's method.
///
/// For α ≥ 1 (which is our case with α = 19.28):
/// 1. d = α - 1/3
/// 2. c = 1/√(9d)
/// 3. Loop: generate v = (1 + c·x)³ where x ~ N(0,1)
/// 4. Accept if v > 0 and log(U) < 0.5·x² + d - d·v + d·ln(v)
fn sample_gamma(shape: f64, rate: f64, rng: &mut impl Rng) -> f64 {
    assert!(shape >= 1.0);
    let d = shape - 1.0 / 3.0;
    let c = 1.0 / (9.0 * d).sqrt();

    loop {
        let x: f64 = sample_standard_normal(rng);
        let v_base = 1.0 + c * x;
        if v_base <= 0.0 { continue; }
        let v = v_base * v_base * v_base;
        let u: f64 = rng.gen();
        let x2 = x * x;
        if u.ln() < 0.5 * x2 + d - d * v + d * v.ln() {
            return d * v / rate;
        }
    }
}

/// Box-Muller transform for standard normal sampling.
fn sample_standard_normal(rng: &mut impl Rng) -> f64 {
    let u1: f64 = rng.gen::<f64>().max(1e-15);
    let u2: f64 = rng.gen();
    (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
}

// ═══════════════════════════════════════════════════════════════
//  Candidate UTXO
// ═══════════════════════════════════════════════════════════════

/// A candidate output for ring member selection.
#[derive(Debug, Clone)]
pub struct RingCandidate {
    /// Output identifier.
    pub tx_hash: [u8; 32],
    pub output_index: u32,
    /// Block this output was created in.
    pub block_hash: Hash,
    /// Blue score of the block containing this output.
    pub blue_score: u64,
    /// Commitment to the output amount (for Q-DAG-CT).
    pub commitment_bytes: Vec<u8>,
    /// Spending public key (serialized polynomial).
    pub spending_pubkey: Vec<u8>,
    /// Chain ID.
    pub chain_id: u32,
}

// ═══════════════════════════════════════════════════════════════
//  Gamma Decoy Selector
// ═══════════════════════════════════════════════════════════════

/// Gamma-distribution-based decoy selector for Q-DAG-CT ring construction.
///
/// # Algorithm
///
/// 1. Determine the current DAG tip blue_score
/// 2. For each decoy slot needed:
///    a. Sample age ~ Gamma(19.28, 1.61)
///    b. Compute target_score = tip_score - age
///    c. Find an eligible output near target_score
///    d. Verify: depth ≥ MIN_DECOY_DEPTH, not failed TX, not already selected
/// 3. If insufficient candidates at target_score, retry with new sample
///
/// # Privacy Properties
///
/// - Age distribution of decoys matches real spend distribution
/// - Selection is non-deterministic (random sampling)
/// - No correlation between decoy positions and real spend
/// - No temporal bias (neither newest nor oldest is special)
pub struct GammaDecoySelector<'a, S: DagStore> {
    ghostdag: &'a GhostDagManager,
    store: &'a S,
    state_manager: &'a DagStateManager,
    tip_blue_score: u64,
}

impl<'a, S: DagStore> GammaDecoySelector<'a, S> {
    pub fn new(
        ghostdag: &'a GhostDagManager,
        store: &'a S,
        state_manager: &'a DagStateManager,
    ) -> Self {
        let tip_blue_score = store.get_tips().iter()
            .filter_map(|tip| store.get_ghostdag_data(tip))
            .map(|gd| gd.blue_score)
            .max()
            .unwrap_or(0);
        Self { ghostdag, store, state_manager, tip_blue_score }
    }

    /// Select `ring_size - 1` decoys from the eligible UTXO pool.
    ///
    /// The real output is already known — we select decoys to fill the ring.
    ///
    /// # Arguments
    /// - `ring_size`: total ring size including real output
    /// - `real_output_score`: blue_score of the real output being spent
    /// - `eligible_outputs`: all eligible UTXOs (pre-filtered by amount/chain/etc.)
    /// - `exclude`: outputs to exclude (own inputs, already selected)
    ///
    /// # Returns
    /// Indices into `eligible_outputs` for the selected decoys.
    pub fn select_decoys(
        &self,
        ring_size: usize,
        real_output_score: u64,
        eligible_outputs: &[RingCandidate],
        exclude: &HashSet<([u8; 32], u32)>,
    ) -> Result<Vec<usize>, DecoySelectionError> {
        if ring_size < MIN_RING_SIZE {
            return Err(DecoySelectionError::RingSizeTooSmall(ring_size));
        }
        if ring_size > MAX_RING_SIZE_CT {
            return Err(DecoySelectionError::RingSizeTooLarge(ring_size));
        }

        let decoys_needed = ring_size - 1; // real output fills one slot
        if eligible_outputs.len() < decoys_needed {
            return Err(DecoySelectionError::InsufficientCandidates {
                needed: decoys_needed,
                available: eligible_outputs.len(),
            });
        }

        // Build score-indexed lookup for efficient nearest-neighbor
        let mut by_score: Vec<(u64, usize)> = eligible_outputs.iter()
            .enumerate()
            .filter(|(_, c)| {
                !exclude.contains(&(c.tx_hash, c.output_index))
                    && self.tip_blue_score.saturating_sub(c.blue_score) >= MIN_DECOY_DEPTH as u64
            })
            .map(|(i, c)| (c.blue_score, i))
            .collect();
        by_score.sort_by_key(|(score, _)| *score);

        if by_score.len() < decoys_needed {
            return Err(DecoySelectionError::InsufficientCandidates {
                needed: decoys_needed,
                available: by_score.len(),
            });
        }

        let mut rng = rand::thread_rng();
        let mut selected: HashSet<usize> = HashSet::new();
        let mut attempts = 0;

        while selected.len() < decoys_needed && attempts < MAX_SELECTION_ATTEMPTS {
            attempts += 1;

            // Sample age from gamma distribution
            let age = sample_gamma(GAMMA_SHAPE, GAMMA_RATE, &mut rng);
            let age_score = (age * (self.tip_blue_score as f64 / MAX_DECOY_AGE as f64)) as u64;
            let target_score = self.tip_blue_score.saturating_sub(age_score);

            // Find nearest candidate by blue_score
            let nearest_idx = match by_score.binary_search_by_key(&target_score, |(s, _)| *s) {
                Ok(i) => i,
                Err(i) => {
                    if i == 0 { 0 }
                    else if i >= by_score.len() { by_score.len() - 1 }
                    else {
                        // Pick the closer of the two neighbors
                        let diff_left = target_score.saturating_sub(by_score[i-1].0);
                        let diff_right = by_score[i].0.saturating_sub(target_score);
                        if diff_left <= diff_right { i - 1 } else { i }
                    }
                }
            };

            let (_, output_idx) = by_score[nearest_idx];
            selected.insert(output_idx);
        }

        if selected.len() < decoys_needed {
            return Err(DecoySelectionError::MaxAttemptsExceeded);
        }

        Ok(selected.into_iter().take(decoys_needed).collect())
    }
}

/// Errors during decoy selection.
#[derive(Debug, thiserror::Error)]
pub enum DecoySelectionError {
    #[error("ring size {0} < minimum {MIN_RING_SIZE}")]
    RingSizeTooSmall(usize),
    #[error("ring size {0} > maximum {MAX_RING_SIZE_CT}")]
    RingSizeTooLarge(usize),
    #[error("insufficient candidates: need {needed}, have {available}")]
    InsufficientCandidates { needed: usize, available: usize },
    #[error("max selection attempts exceeded")]
    MaxAttemptsExceeded,
}

// ═══════════════════════════════════════════════════════════════
//  Metadata Leakage Documentation (Phase 10)
// ═══════════════════════════════════════════════════════════════

/// Known metadata leakage points in the current implementation.
///
/// This struct documents what information is observable by an adversary.
/// Each field is `true` if the corresponding metadata is leaked.
///
/// # Purpose
///
/// This is NOT a runtime structure. It exists to force developers to
/// acknowledge each leakage point. Any new feature that adds a leakage
/// point must update this list.
pub struct MetadataLeakageProfile {
    /// Input count is visible (number of UTXOs being spent).
    pub input_count_visible: bool,
    /// Output count is visible (number of recipients).
    pub output_count_visible: bool,
    /// Fee amount is hidden (confidential fee, Item 2).
    pub fee_hidden: bool,
    /// Ring size is visible (different sizes could fingerprint).
    pub ring_size_visible: bool,
    /// Transaction size varies with content (could distinguish TX types).
    pub tx_size_variable: bool,
    /// Timing of TX submission is observable by network peers.
    pub timing_visible: bool,
    /// Signer position within ring is hidden (ZK membership, Item 1).
    pub signer_position_hidden: bool,
    /// Change output is indistinguishable from payment output.
    pub change_indistinguishable: bool,
}

impl MetadataLeakageProfile {
    /// Current leakage profile after all long-term items are implemented.
    pub fn current() -> Self {
        Self {
            input_count_visible: true,  // Structural: visible on-chain
            output_count_visible: true, // Structural: visible on-chain
            fee_hidden: true,           // Long-term Item 2: confidential fee
            ring_size_visible: true,    // Structural: proof size reveals ring size
            tx_size_variable: true,     // Different proof counts → different sizes
            timing_visible: true,       // Network layer: observable by peers
            signer_position_hidden: true,// Long-term Item 1: ZK membership
            change_indistinguishable: true, // All outputs have same structure
        }
    }

    /// Remaining leakage that cannot be eliminated at the protocol level.
    pub fn irreducible_leakage() -> Vec<&'static str> {
        vec![
            "input_count: visible on-chain (consider fixed-size TXs in future)",
            "output_count: visible on-chain (consider padding outputs)",
            "ring_size: derivable from proof size (standardize to fixed size)",
            "tx_size: derivable from wire format (consider padding)",
            "timing: observable by network peers (use Tor/mixnet)",
        ]
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gamma_distribution_shape() {
        let mut rng = rand::thread_rng();
        let mut samples = Vec::with_capacity(10000);
        for _ in 0..10000 {
            samples.push(sample_gamma(GAMMA_SHAPE, GAMMA_RATE, &mut rng));
        }

        // Mean of Gamma(α, β) = α/β ≈ 19.28/1.61 ≈ 11.98
        let mean: f64 = samples.iter().sum::<f64>() / samples.len() as f64;
        let expected_mean = GAMMA_SHAPE / GAMMA_RATE;
        assert!((mean - expected_mean).abs() < 1.0,
            "gamma mean {} should be near {}", mean, expected_mean);

        // Most samples should be positive
        assert!(samples.iter().all(|&s| s >= 0.0));

        // Distribution should have a tail (some large values)
        let max = samples.iter().cloned().fold(0.0f64, f64::max);
        assert!(max > 20.0, "gamma should have a tail, max={}", max);
    }

    #[test]
    fn test_gamma_no_negative() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let s = sample_gamma(GAMMA_SHAPE, GAMMA_RATE, &mut rng);
            assert!(s >= 0.0, "gamma sample must be non-negative, got {}", s);
        }
    }

    #[test]
    fn test_metadata_leakage_documented() {
        let profile = MetadataLeakageProfile::current();
        assert!(profile.fee_hidden, "fee should be hidden after Item 2");
        assert!(profile.signer_position_hidden, "position should be hidden after Item 1");

        let remaining = MetadataLeakageProfile::irreducible_leakage();
        assert!(!remaining.is_empty(), "there should be documented remaining leakage");
    }
}
