//! ZKP Verification Budget — CPU DoS protection (Task 4.2).
//!
//! # Problem
//!
//! ZKP verification (UnifiedMembershipProof) is computationally expensive:
//! - Σ-protocol verification: O(1) per input (polynomial multiplication)
//! - SIS Merkle membership: O(depth) per input
//! - Range proof: O(bits) per output
//! - Balance excess proof: O(1) per transaction
//!
//! An attacker can craft blocks with many valid but expensive-to-verify
//! transactions to exhaust validator CPU resources (block validation DoS).
//!
//! # Solution: Verification Budget
//!
//! Each block has a fixed ZKP verification budget measured in "verification units".
//! Each proof type consumes a known number of units. If a block exceeds the
//! budget, it is rejected immediately and the proposer peer is penalized.
//!
//! # Unit Costs (calibrated to ~100ms total verification on reference hardware)
//!
//! | Proof Type               | Units | Rationale                              |
//! |--------------------------|------:|----------------------------------------|
//! | UnifiedMembershipProof   |    10 | Σ + SIS Merkle + BDLOP committed path  |
//! | RangeProof (per output)  |     3 | 64-bit OR-proof decomposition          |
//! | BalanceExcessProof       |     2 | Single BDLOP opening                   |
//! | NullifierProof           |     5 | Dual-relation Σ-protocol               |

use std::time::{Duration, Instant};

// ═══════════════════════════════════════════════════════════════
//  Budget Constants
// ═══════════════════════════════════════════════════════════════

/// Maximum verification units per block.
/// With ~200 txs × 1 input × 10 units = 2000 units at standard load.
/// Budget of 5000 allows burst capacity while preventing abuse.
pub const MAX_BLOCK_VERIFICATION_UNITS: u64 = 5_000;

/// Maximum wall-clock time for all ZKP verifications in a single block.
/// If exceeded, remaining transactions are skipped and the block is rejected.
pub const MAX_BLOCK_VERIFICATION_TIME: Duration = Duration::from_secs(10);

/// Maximum number of ZKP verifications per block (hard cap on proof count).
pub const MAX_BLOCK_ZKP_COUNT: usize = 500;

// ── Per-proof unit costs ──

pub const COST_UNIFIED_MEMBERSHIP: u64 = 10;
pub const COST_RANGE_PROOF: u64 = 3;
pub const COST_BALANCE_EXCESS: u64 = 2;
pub const COST_NULLIFIER_PROOF: u64 = 5;

// ═══════════════════════════════════════════════════════════════
//  Budget Tracker
// ═══════════════════════════════════════════════════════════════

/// Tracks ZKP verification budget for a single block validation pass.
///
/// # Usage
///
/// ```ignore
/// let mut budget = ZkpVerificationBudget::new();
///
/// for tx in block.transactions() {
///     for input in tx.inputs() {
///         budget.charge(COST_UNIFIED_MEMBERSHIP)?;
///     }
///     for output in tx.outputs() {
///         budget.charge(COST_RANGE_PROOF)?;
///     }
///     budget.charge(COST_BALANCE_EXCESS)?;
/// }
/// ```
pub struct ZkpVerificationBudget {
    units_consumed: u64,
    proofs_verified: usize,
    start_time: Instant,
}

#[derive(Debug, thiserror::Error)]
pub enum BudgetError {
    #[error("ZKP verification budget exceeded: {consumed} units > {max} max")]
    UnitsExceeded { consumed: u64, max: u64 },

    #[error("ZKP verification count exceeded: {count} proofs > {max} max")]
    CountExceeded { count: usize, max: usize },

    #[error("ZKP verification timeout: {elapsed:?} > {max:?}")]
    Timeout { elapsed: Duration, max: Duration },
}

impl ZkpVerificationBudget {
    pub fn new() -> Self {
        Self {
            units_consumed: 0,
            proofs_verified: 0,
            start_time: Instant::now(),
        }
    }

    /// Charge verification units. Returns error if budget exceeded.
    pub fn charge(&mut self, units: u64) -> Result<(), BudgetError> {
        self.units_consumed = self.units_consumed.saturating_add(units);
        self.proofs_verified += 1;

        if self.units_consumed > MAX_BLOCK_VERIFICATION_UNITS {
            return Err(BudgetError::UnitsExceeded {
                consumed: self.units_consumed,
                max: MAX_BLOCK_VERIFICATION_UNITS,
            });
        }

        if self.proofs_verified > MAX_BLOCK_ZKP_COUNT {
            return Err(BudgetError::CountExceeded {
                count: self.proofs_verified,
                max: MAX_BLOCK_ZKP_COUNT,
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

    /// Charge units for a complete confidential transaction.
    ///
    /// Computes: (inputs × membership) + (outputs × range) + balance
    pub fn charge_confidential_tx(
        &mut self,
        num_inputs: usize,
        num_outputs: usize,
    ) -> Result<(), BudgetError> {
        let tx_cost = (num_inputs as u64) * COST_UNIFIED_MEMBERSHIP
            + (num_outputs as u64) * COST_RANGE_PROOF
            + COST_BALANCE_EXCESS;
        self.charge(tx_cost)
    }

    /// Pre-check: would a transaction of this size exceed the remaining budget?
    /// Returns false if it would exceed — caller should reject the block.
    pub fn can_afford(&self, units: u64) -> bool {
        self.units_consumed.saturating_add(units) <= MAX_BLOCK_VERIFICATION_UNITS
            && self.proofs_verified < MAX_BLOCK_ZKP_COUNT
            && self.start_time.elapsed() < MAX_BLOCK_VERIFICATION_TIME
    }

    /// Pre-check for a confidential transaction.
    pub fn can_afford_tx(&self, num_inputs: usize, num_outputs: usize) -> bool {
        let tx_cost = (num_inputs as u64) * COST_UNIFIED_MEMBERSHIP
            + (num_outputs as u64) * COST_RANGE_PROOF
            + COST_BALANCE_EXCESS;
        self.can_afford(tx_cost)
    }

    /// Summary of budget consumption (for logging).
    pub fn summary(&self) -> BudgetSummary {
        BudgetSummary {
            units_consumed: self.units_consumed,
            units_remaining: MAX_BLOCK_VERIFICATION_UNITS.saturating_sub(self.units_consumed),
            proofs_verified: self.proofs_verified,
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
    pub units_consumed: u64,
    pub units_remaining: u64,
    pub proofs_verified: usize,
    pub elapsed: Duration,
}

impl std::fmt::Display for BudgetSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ZKP budget: {}/{} units, {} proofs, {:?} elapsed",
            self.units_consumed,
            MAX_BLOCK_VERIFICATION_UNITS,
            self.proofs_verified,
            self.elapsed
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
    fn test_budget_normal_block() {
        let mut budget = ZkpVerificationBudget::new();
        // Simulate a block with 100 transactions, 1 input + 2 outputs each
        for _ in 0..100 {
            budget.charge_confidential_tx(1, 2).unwrap();
        }
        let summary = budget.summary();
        // 100 × (10 + 6 + 2) = 1800 units
        assert_eq!(summary.units_consumed, 1800);
        assert!(summary.units_remaining > 0);
    }

    #[test]
    fn test_budget_exceeded_rejects() {
        let mut budget = ZkpVerificationBudget::new();
        // Try to process 400 transactions with 2 inputs each
        // 400 × (20 + 6 + 2) = 11200 > 5000
        let mut rejected = false;
        for _ in 0..400 {
            if budget.charge_confidential_tx(2, 2).is_err() {
                rejected = true;
                break;
            }
        }
        assert!(rejected, "budget must eventually reject");
    }

    #[test]
    fn test_budget_count_exceeded() {
        let mut budget = ZkpVerificationBudget::new();
        // charge 1 unit each time, but exceed proof count
        for _ in 0..MAX_BLOCK_ZKP_COUNT {
            budget.charge(1).unwrap();
        }
        assert!(budget.charge(1).is_err());
    }

    #[test]
    fn test_can_afford_check() {
        let mut budget = ZkpVerificationBudget::new();
        assert!(budget.can_afford(MAX_BLOCK_VERIFICATION_UNITS));
        budget.charge(MAX_BLOCK_VERIFICATION_UNITS - 1).unwrap();
        assert!(budget.can_afford(1));
        assert!(!budget.can_afford(2));
    }

    #[test]
    fn test_can_afford_tx() {
        let budget = ZkpVerificationBudget::new();
        // 1 input + 2 outputs = 10 + 6 + 2 = 18 units
        assert!(budget.can_afford_tx(1, 2));
    }
}
