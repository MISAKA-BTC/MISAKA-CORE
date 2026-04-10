//! Runtime invariant checking — catches logic bugs before they become exploits.
//!
//! Invariants are boolean conditions that MUST hold at specific program points.
//! When an invariant is violated:
//! 1. The violation is logged with full context
//! 2. A security alert is raised
//! 3. The operation is aborted safely
//! 4. Peer may be banned if the violation came from network input

use std::sync::atomic::{AtomicU64, Ordering};

static VIOLATIONS_COUNT: AtomicU64 = AtomicU64::new(0);
static CHECKS_COUNT: AtomicU64 = AtomicU64::new(0);

/// Check a consensus invariant. Returns Err on violation.
pub fn check_invariant(
    condition: bool,
    category: InvariantCategory,
    message: &str,
    context: &str,
) -> Result<(), InvariantViolation> {
    CHECKS_COUNT.fetch_add(1, Ordering::Relaxed);
    if !condition {
        VIOLATIONS_COUNT.fetch_add(1, Ordering::Relaxed);
        let violation = InvariantViolation {
            category,
            message: message.to_string(),
            context: context.to_string(),
            count: VIOLATIONS_COUNT.load(Ordering::Relaxed),
        };
        tracing::error!(
            "INVARIANT VIOLATION [{}]: {} — {}",
            category.as_str(),
            message,
            context
        );
        Err(violation)
    } else {
        Ok(())
    }
}

/// Categories of invariants for routing alerts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvariantCategory {
    /// Total supply must never exceed maximum.
    SupplyConservation,
    /// UTXO inputs must match or exceed outputs.
    BalanceConservation,
    /// Signatures must be valid before state mutation.
    SignatureValidity,
    /// Block ordering must respect DAG topology.
    DagTopology,
    /// Timestamps must be monotonically consistent.
    TimestampMonotonicity,
    /// State root must match computed state.
    StateRootIntegrity,
    /// SpendTag must not be double-spent.
    SpendTagUniqueness,
    /// Script execution must terminate.
    ScriptTermination,
    /// Merkle proof must be valid.
    MerkleIntegrity,
    /// Key material must be properly zeroized.
    KeyZeroization,
}

impl InvariantCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SupplyConservation => "SUPPLY_CONSERVATION",
            Self::BalanceConservation => "BALANCE_CONSERVATION",
            Self::SignatureValidity => "SIGNATURE_VALIDITY",
            Self::DagTopology => "DAG_TOPOLOGY",
            Self::TimestampMonotonicity => "TIMESTAMP_MONOTONICITY",
            Self::StateRootIntegrity => "STATE_ROOT_INTEGRITY",
            Self::SpendTagUniqueness => "NULLIFIER_UNIQUENESS",
            Self::ScriptTermination => "SCRIPT_TERMINATION",
            Self::MerkleIntegrity => "MERKLE_INTEGRITY",
            Self::KeyZeroization => "KEY_ZEROIZATION",
        }
    }

    pub fn severity(&self) -> Severity {
        match self {
            Self::SupplyConservation | Self::BalanceConservation | Self::SpendTagUniqueness => {
                Severity::Critical
            }
            Self::SignatureValidity | Self::StateRootIntegrity | Self::MerkleIntegrity => {
                Severity::High
            }
            Self::DagTopology | Self::TimestampMonotonicity | Self::ScriptTermination => {
                Severity::Medium
            }
            Self::KeyZeroization => Severity::Low,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, thiserror::Error)]
#[error("invariant violation [{category}]: {message} — {context}")]
pub struct InvariantViolation {
    pub category: InvariantCategory,
    pub message: String,
    pub context: String,
    pub count: u64,
}

impl std::fmt::Display for InvariantCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Supply conservation check.
pub fn check_supply_conservation(
    total_inputs: u64,
    total_outputs: u64,
    expected_fee: u64,
) -> Result<(), InvariantViolation> {
    check_invariant(
        total_inputs >= total_outputs,
        InvariantCategory::BalanceConservation,
        &format!("inputs ({}) < outputs ({})", total_inputs, total_outputs),
        "transaction validation",
    )?;
    check_invariant(
        total_inputs - total_outputs == expected_fee,
        InvariantCategory::BalanceConservation,
        &format!(
            "fee mismatch: {} != {}",
            total_inputs - total_outputs,
            expected_fee
        ),
        "fee validation",
    )
}

/// Block reward conservation check.
pub fn check_block_reward(
    coinbase_amount: u64,
    max_reward: u64,
    total_fees: u64,
) -> Result<(), InvariantViolation> {
    check_invariant(
        coinbase_amount <= max_reward + total_fees,
        InvariantCategory::SupplyConservation,
        &format!(
            "coinbase {} > reward {} + fees {}",
            coinbase_amount, max_reward, total_fees
        ),
        "coinbase validation",
    )
}

/// Get violation statistics.
pub fn violation_stats() -> (u64, u64) {
    (
        VIOLATIONS_COUNT.load(Ordering::Relaxed),
        CHECKS_COUNT.load(Ordering::Relaxed),
    )
}
