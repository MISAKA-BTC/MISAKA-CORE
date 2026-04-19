//! Collateral auto-selection.

use crate::error::SdkError;
use misaka_protocol_config::eutxo_v2::budget::budget_v1;
use misaka_types::eutxo::collateral::{CollateralInput, CollateralReturn};
use misaka_types::eutxo::value::AssetValue;
use misaka_types::utxo::OutputRef;

/// Auto-select collateral inputs covering 150% of fee.
/// Input: available UTXOs as (outref, amount) pairs.
/// Returns selected inputs + optional change output.
pub fn auto_select_collateral(
    available: &[(OutputRef, u64)],
    fee: u64,
    change_address: [u8; 32],
) -> Result<(Vec<CollateralInput>, Option<CollateralReturn>), SdkError> {
    let params = budget_v1();
    let required: u64 =
        ((fee as u128).saturating_mul(params.collateral_percentage as u128) / 10_000) as u64;

    // Greedy: sort by amount descending
    let mut sorted: Vec<(OutputRef, u64)> = available.to_vec();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));

    let mut selected = Vec::new();
    let mut total: u64 = 0;
    for (outref, amount) in &sorted {
        if total >= required {
            break;
        }
        if selected.len() >= params.max_collateral_inputs as usize {
            return Err(SdkError::TooManyCollateralInputs(selected.len()));
        }
        selected.push(CollateralInput {
            outref: outref.clone(),
        });
        total = total.saturating_add(*amount);
    }

    if total < required {
        return Err(SdkError::InsufficientCollateral {
            required,
            available: total,
        });
    }

    let change = if total > required {
        Some(CollateralReturn {
            address: change_address,
            value: AssetValue::mlp_only(total - required),
        })
    } else {
        None
    };

    Ok((selected, change))
}
