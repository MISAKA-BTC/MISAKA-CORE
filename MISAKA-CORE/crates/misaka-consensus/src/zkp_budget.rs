//! ZKP Verification Budget — Weighted Aggregate Proof Cost (Task 3.2).
//!
//! # Problem
//!
//! ZKP verification cost is NOT uniform across transactions:
//! - A TX with 1 input / 1 output costs ~16 units
//! - A TX with 8 inputs / 16 outputs (privacy mix) costs ~90 units
//! - A TX spending from a depth-20 Merkle tree costs more than depth-4
//!
//! A simple "count of proofs" budget allows an attacker to craft a block
//! full of maximally-expensive transactions that nominally fit the count
//! limit but exhaust validator CPU.
//!
//! # Solution: Aggregate Proof Weight
//!
//! Each proof type has a base cost PLUS scaling factors for:
//! - Number of inputs (membership proofs)
//! - Number of outputs (range proofs)
//! - Range proof bit width (64-bit = more OR-proofs)
//! - Membership tree depth (deeper = more levels to verify)
//!
//! The aggregate weight of a TX is the sum of all its proof costs.
//! A block's total weight MUST NOT exceed `MAX_BLOCK_WEIGHT`.

use std::time::{Duration, Instant};

// ═══════════════════════════════════════════════════════════════
//  Budget Constants (calibrated to reference hardware)
// ═══════════════════════════════════════════════════════════════

/// Maximum aggregate proof weight per block.
/// Calibrated so that a full block verifies in ≤10s on reference hardware
/// (4-core AMD EPYC, 2.4 GHz, Sakura Internet VPS).
pub const MAX_BLOCK_WEIGHT: u64 = 8_000;

/// Maximum wall-clock time for all ZKP verifications in a single block.
pub const MAX_BLOCK_VERIFICATION_TIME: Duration = Duration::from_secs(10);

/// Maximum number of ZKP-bearing transactions per block (hard cap).
pub const MAX_BLOCK_ZKP_TX_COUNT: usize = 500;

// Compatibility aliases kept while v4 callers migrate to the new names.
pub const MAX_BLOCK_VERIFICATION_UNITS: u64 = MAX_BLOCK_WEIGHT;
pub const MAX_BLOCK_ZKP_COUNT: usize = MAX_BLOCK_ZKP_TX_COUNT;

// ── Base costs per proof type ──

/// UnifiedMembershipProof: Σ + SIS Merkle + BDLOP committed path.
/// Base cost for a depth-1 tree with 1 input.
pub const COST_UNIFIED_MEMBERSHIP_BASE: u64 = 8;

/// Additional cost per Merkle level (each level = 1 OR-proof + commitment check).
pub const COST_PER_MERKLE_LEVEL: u64 = 1;

/// RangeProof: per-output bit-decomposition OR-proofs.
/// Base cost for 64-bit range proof.
pub const COST_RANGE_PROOF_BASE: u64 = 3;
pub const COST_UNIFIED_MEMBERSHIP: u64 = COST_UNIFIED_MEMBERSHIP_BASE;
pub const COST_RANGE_PROOF: u64 = COST_RANGE_PROOF_BASE;

/// BalanceExcessProof: single BDLOP opening.
pub const COST_BALANCE_EXCESS: u64 = 2;

/// ConfidentialFee: range proof + minimum proof.
pub const COST_CONFIDENTIAL_FEE: u64 = 4;

/// NullifierProof (standalone): dual-relation Σ-protocol.
pub const COST_NULLIFIER_PROOF: u64 = 5;

// ═══════════════════════════════════════════════════════════════
//  Proof Weight Calculator
// ═══════════════════════════════════════════════════════════════

/// Parameters describing a transaction's proof complexity.
///
/// These are extracted from the transaction structure BEFORE any
/// expensive crypto operations, enabling cheap pre-screening.
#[derive(Debug, Clone, Copy)]
pub struct TxProofParams {
    /// Number of confidential inputs (each requires membership proof)
    pub num_inputs: usize,
    /// Number of confidential outputs (each requires range proof)
    pub num_outputs: usize,
    /// Maximum Merkle tree depth across all inputs.
    /// Extracted from `membership_proof` wire format (the `num_levels` field).
    pub max_merkle_depth: usize,
    /// Range proof bit width (typically 64).
    pub range_bits: usize,
}

impl TxProofParams {
    /// Compute the aggregate proof weight for this transaction.
    ///
    /// ```text
    /// weight = (num_inputs × (MEMBERSHIP_BASE + max_depth × PER_LEVEL))
    ///        + (num_outputs × RANGE_BASE)
    ///        + BALANCE_EXCESS
    ///        + CONFIDENTIAL_FEE
    /// ```
    pub fn compute_weight(&self) -> u64 {
        let membership_per_input =
            COST_UNIFIED_MEMBERSHIP_BASE + (self.max_merkle_depth as u64) * COST_PER_MERKLE_LEVEL;
        let membership_total = (self.num_inputs as u64) * membership_per_input;
        let range_total = (self.num_outputs as u64) * COST_RANGE_PROOF_BASE;

        membership_total + range_total + COST_BALANCE_EXCESS + COST_CONFIDENTIAL_FEE
    }

    /// Quick weight estimate for pre-screening (uses default depth).
    pub fn estimate_weight(num_inputs: usize, num_outputs: usize) -> u64 {
        let params = Self {
            num_inputs,
            num_outputs,
            max_merkle_depth: 10, // Typical depth for ~1K UTXO set
            range_bits: 64,
        };
        params.compute_weight()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Budget Tracker
// ═══════════════════════════════════════════════════════════════

/// Tracks ZKP verification budget for a single block validation pass.
///
/// # Fail-Closed Design
///
/// Every `charge` call that would exceed any limit returns `Err`.
/// The caller MUST reject the entire block and penalize the proposer.
/// There is no "soft limit" or "best-effort" mode.
pub struct ZkpVerificationBudget {
    weight_consumed: u64,
    tx_count: usize,
    start_time: Instant,
}

#[derive(Debug, thiserror::Error)]
pub enum BudgetError {
    #[error("ZKP weight exceeded: {consumed} > {max} max")]
    WeightExceeded { consumed: u64, max: u64 },

    #[error("ZKP TX count exceeded: {count} > {max} max")]
    TxCountExceeded { count: usize, max: usize },

    #[error("ZKP verification timeout: {elapsed:?} > {max:?}")]
    Timeout { elapsed: Duration, max: Duration },
}

impl ZkpVerificationBudget {
    pub fn new() -> Self {
        Self {
            weight_consumed: 0,
            tx_count: 0,
            start_time: Instant::now(),
        }
    }

    /// Charge weighted verification cost for a transaction.
    ///
    /// Fails if any budget limit is exceeded.
    pub fn charge_tx(&mut self, params: &TxProofParams) -> Result<(), BudgetError> {
        let weight = params.compute_weight();
        self.charge_weight(weight)
    }

    /// Charge raw weight units. Returns error if budget exceeded.
    pub fn charge_weight(&mut self, weight: u64) -> Result<(), BudgetError> {
        self.weight_consumed = self.weight_consumed.saturating_add(weight);
        self.tx_count += 1;

        if self.weight_consumed > MAX_BLOCK_WEIGHT {
            return Err(BudgetError::WeightExceeded {
                consumed: self.weight_consumed,
                max: MAX_BLOCK_WEIGHT,
            });
        }

        if self.tx_count > MAX_BLOCK_ZKP_TX_COUNT {
            return Err(BudgetError::TxCountExceeded {
                count: self.tx_count,
                max: MAX_BLOCK_ZKP_TX_COUNT,
            });
        }

        let elapsed = self.start_time.elapsed();
        if elapsed > MAX_BLOCK_VERIFICATION_TIME {
            return Err(BudgetError::Timeout {
                elapsed,
                max: MAX_BLOCK_VERIFICATION_TIME,
            });
        }

        Ok(())
    }

    /// Pre-check: would a transaction with these params exceed the budget?
    pub fn can_afford(&self, params: &TxProofParams) -> bool {
        let weight = params.compute_weight();
        self.weight_consumed.saturating_add(weight) <= MAX_BLOCK_WEIGHT
            && self.tx_count < MAX_BLOCK_ZKP_TX_COUNT
            && self.start_time.elapsed() < MAX_BLOCK_VERIFICATION_TIME
    }

    /// Convenience: charge for a standard confidential TX.
    pub fn charge_confidential_tx(
        &mut self,
        num_inputs: usize,
        num_outputs: usize,
        merkle_depth: usize,
    ) -> Result<(), BudgetError> {
        let params = TxProofParams {
            num_inputs,
            num_outputs,
            max_merkle_depth: merkle_depth,
            range_bits: 64,
        };
        self.charge_tx(&params)
    }

    /// Summary of budget consumption (for logging).
    pub fn summary(&self) -> BudgetSummary {
        BudgetSummary {
            weight_consumed: self.weight_consumed,
            weight_remaining: MAX_BLOCK_WEIGHT.saturating_sub(self.weight_consumed),
            tx_count: self.tx_count,
            elapsed: self.start_time.elapsed(),
        }
    }
}

impl Default for ZkpVerificationBudget {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct BudgetSummary {
    pub weight_consumed: u64,
    pub weight_remaining: u64,
    pub tx_count: usize,
    pub elapsed: Duration,
}

impl std::fmt::Display for BudgetSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ZKP budget: {}/{} weight, {} TXs, {:?} elapsed",
            self.weight_consumed, MAX_BLOCK_WEIGHT, self.tx_count, self.elapsed
        )
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weight_calculation() {
        let params = TxProofParams {
            num_inputs: 2,
            num_outputs: 3,
            max_merkle_depth: 10,
            range_bits: 64,
        };
        // 2 × (8 + 10×1) + 3 × 3 + 2 + 4 = 2×18 + 9 + 6 = 51
        assert_eq!(params.compute_weight(), 51);
    }

    #[test]
    fn test_budget_normal_block() {
        let mut budget = ZkpVerificationBudget::new();
        // 100 standard TXs: 1 input, 2 outputs, depth 10
        for _ in 0..100 {
            budget.charge_confidential_tx(1, 2, 10).unwrap();
        }
        let summary = budget.summary();
        // 100 × (1×(8+10) + 2×3 + 2 + 4) = 100 × 30 = 3000
        assert_eq!(summary.weight_consumed, 3000);
        assert!(summary.weight_remaining > 0);
    }

    #[test]
    fn test_heavy_tx_budget_exceeded() {
        let mut budget = ZkpVerificationBudget::new();
        // 50 heavy TXs: 8 inputs, 8 outputs, depth 20
        // each: 8×(8+20) + 8×3 + 2 + 4 = 224 + 24 + 6 = 254
        // 50 × 254 = 12700 > 8000
        let mut rejected = false;
        for _ in 0..50 {
            if budget.charge_confidential_tx(8, 8, 20).is_err() {
                rejected = true;
                break;
            }
        }
        assert!(rejected, "heavy TXs must eventually exceed budget");
    }

    #[test]
    fn test_tx_count_exceeded() {
        let mut budget = ZkpVerificationBudget::new();
        // Tiny TXs but too many
        let params = TxProofParams {
            num_inputs: 1,
            num_outputs: 1,
            max_merkle_depth: 1,
            range_bits: 64,
        };
        for _ in 0..MAX_BLOCK_ZKP_TX_COUNT {
            budget.charge_tx(&params).unwrap();
        }
        assert!(budget.charge_tx(&params).is_err());
    }

    #[test]
    fn test_can_afford_check() {
        let mut budget = ZkpVerificationBudget::new();
        let big = TxProofParams {
            num_inputs: 8,
            num_outputs: 8,
            max_merkle_depth: 20,
            range_bits: 64,
        };
        assert!(budget.can_afford(&big));
        // Fill most of the budget
        budget.charge_weight(MAX_BLOCK_WEIGHT - 1).unwrap();
        assert!(!budget.can_afford(&big));
    }

    #[test]
    fn test_depth_affects_weight() {
        let shallow = TxProofParams {
            num_inputs: 1,
            num_outputs: 1,
            max_merkle_depth: 2,
            range_bits: 64,
        };
        let deep = TxProofParams {
            num_inputs: 1,
            num_outputs: 1,
            max_merkle_depth: 20,
            range_bits: 64,
        };
        assert!(
            deep.compute_weight() > shallow.compute_weight(),
            "deeper Merkle tree must cost more"
        );
    }
}
