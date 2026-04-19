//! Execution cost model types.
//!
//! E1: Type definitions. E2: Parameter values frozen.
//! The cost model is consensus-critical: all validators MUST use
//! identical parameters.

use borsh::{BorshDeserialize, BorshSerialize};

/// Execution units: CPU steps + memory units.
///
/// Every script invocation is bounded by an ExUnits budget.
/// Exceeding the budget causes script failure (Phase 2 error).
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct ExUnits {
    /// CPU steps consumed.
    pub cpu: u64,
    /// Memory units consumed.
    pub mem: u64,
}

impl ExUnits {
    /// Zero budget.
    pub const ZERO: Self = Self { cpu: 0, mem: 0 };

    pub fn zero() -> Self {
        Self::ZERO
    }

    pub fn is_zero(&self) -> bool {
        self.cpu == 0 && self.mem == 0
    }

    /// Add two ExUnits (saturating).
    pub fn saturating_add(&self, other: &Self) -> Self {
        Self {
            cpu: self.cpu.saturating_add(other.cpu),
            mem: self.mem.saturating_add(other.mem),
        }
    }

    /// Check if self fits within the budget.
    pub fn fits_within(&self, budget: &Self) -> bool {
        self.cpu <= budget.cpu && self.mem <= budget.mem
    }
}

/// Block-level and transaction-level execution budget limits.
#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct ExBudgetParams {
    /// Maximum ExUnits a single transaction may consume.
    pub max_tx_ex_units: ExUnits,
    /// Maximum ExUnits a single block may consume.
    pub max_block_ex_units: ExUnits,
    /// Collateral percentage (basis points). E.g., 15000 = 150%.
    pub collateral_percentage: u32,
    /// Maximum collateral inputs per transaction.
    pub max_collateral_inputs: u32,
    /// Maximum serialized value size in bytes.
    pub max_value_size_bytes: u32,
    /// Maximum serialized transaction size in bytes.
    pub max_tx_size_bytes: u32,
}

/// Per-opcode cost entry.
///
/// Costs can be per-call (fixed) and per-byte (proportional to data size).
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct OpcodeCost {
    /// CPU cost per invocation (fixed component).
    pub cpu_per_call: u64,
    /// CPU cost per byte of input data (variable component).
    pub cpu_per_byte: u64,
    /// Memory cost per invocation (fixed component).
    pub mem_per_call: u64,
    /// Memory cost per byte of input data (variable component).
    pub mem_per_byte: u64,
}

/// Full cost model for a script VM version.
#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct CostModel {
    /// Cost model identifier (for governance parameter updates).
    pub model_id: u32,
    /// VM version this model applies to (1 = V1).
    pub vm_version: u8,
    /// Per-opcode costs: Vec of (opcode_u16, cost) pairs.
    /// Sorted by opcode for deterministic borsh encoding.
    pub opcode_costs: Vec<(u16, OpcodeCost)>,
    /// Budget parameters.
    pub params: ExBudgetParams,
}

impl CostModel {
    /// Look up the cost for a given opcode.
    pub fn lookup(&self, opcode: u16) -> Option<&OpcodeCost> {
        self.opcode_costs
            .iter()
            .find(|(op, _)| *op == opcode)
            .map(|(_, cost)| cost)
    }
}
