//! Fee formula V1 coefficients.
//! Formula: fee_plrz = a + b*tx_size + c*cpu + d*mem
//! All coefficients in plrz to avoid rounding loss.

use super::units::*;
use misaka_types::eutxo::cost_model::ExUnits;

/// Base fee per transaction: 100,000 ulrz = 0.0001 MISAKA.
pub const FEE_BASE_PLRZ: u128 = 100_000 * PLRZ_PER_ULRZ;

/// Fee per byte of tx size: 50 ulrz/byte.
pub const FEE_PER_BYTE_PLRZ: u128 = 50 * PLRZ_PER_ULRZ;

/// Fee per CPU step: 60 nlrz/step = 0.06 ulrz/step.
pub const FEE_PER_CPU_STEP_PLRZ: u128 = 60 * PLRZ_PER_NLRZ;

/// Fee per memory unit: 70 plrz/unit.
pub const FEE_PER_MEM_UNIT_PLRZ: u128 = 70;

/// Compute the minimum fee in ulrz for a given tx.
///
/// All intermediate computation uses u128 plrz to avoid overflow / rounding.
/// Final ulrz is rounded UP (ceiling) so undersized fees are rejected cleanly.
pub fn calculate_min_fee_ulrz(tx_size_bytes: usize, total_ex_units: ExUnits) -> u64 {
    let size_term = FEE_PER_BYTE_PLRZ.saturating_mul(tx_size_bytes as u128);
    let cpu_term = FEE_PER_CPU_STEP_PLRZ.saturating_mul(total_ex_units.cpu as u128);
    let mem_term = FEE_PER_MEM_UNIT_PLRZ.saturating_mul(total_ex_units.mem as u128);
    let total_plrz = FEE_BASE_PLRZ
        .saturating_add(size_term)
        .saturating_add(cpu_term)
        .saturating_add(mem_term);
    // Ceiling division to ulrz
    let total_ulrz = (total_plrz + PLRZ_PER_ULRZ - 1) / PLRZ_PER_ULRZ;
    total_ulrz.min(u64::MAX as u128) as u64
}
