//! Fee calculation helpers.

use misaka_protocol_config::eutxo_v2::fees::calculate_min_fee_ulrz;
use misaka_types::eutxo::tx_v2::UtxoTransactionV2;

/// Compute the minimum fee for a tx using its declared ExUnits.
pub fn compute_min_fee(tx: &UtxoTransactionV2) -> u64 {
    let size = borsh::to_vec(tx).map(|v| v.len()).unwrap_or(0);
    let declared = tx.declared_total_ex_units();
    calculate_min_fee_ulrz(size, declared)
}
