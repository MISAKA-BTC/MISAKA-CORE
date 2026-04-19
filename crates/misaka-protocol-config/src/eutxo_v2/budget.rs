//! ExBudget V1 (v2.0 hard fork launch values).
//! FROZEN — changing these requires governance protocol parameter update.

use misaka_types::eutxo::cost_model::{ExBudgetParams, ExUnits};

/// Per-transaction execution budget.
pub const MAX_TX_EX_UNITS: ExUnits = ExUnits {
    cpu: 5_000_000_000,
    mem: 10_000_000,
};

/// Per-block execution budget (10× per-tx).
pub const MAX_BLOCK_EX_UNITS: ExUnits = ExUnits {
    cpu: 50_000_000_000,
    mem: 100_000_000,
};

/// Construct the V1 budget parameters.
pub fn budget_v1() -> ExBudgetParams {
    ExBudgetParams {
        max_tx_ex_units: MAX_TX_EX_UNITS,
        max_block_ex_units: MAX_BLOCK_EX_UNITS,
        collateral_percentage: 15_000, // 150%
        max_collateral_inputs: 3,
        max_value_size_bytes: 5_000,
        max_tx_size_bytes: 16_384,
    }
}
