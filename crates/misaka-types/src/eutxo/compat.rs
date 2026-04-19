//! Legacy (v1) ↔ v2 transaction compatibility layer.
//!
//! Allows legacy UtxoTransaction to be lifted to UtxoTransactionV2
//! for unified processing in the E4 executor.

use super::collateral::CollateralReturn;
use super::datum::DatumOrHash;
use super::tx_v2::*;
use super::validity::ValidityInterval;
use super::value::AssetValue;
use super::witness::WitnessKindV2;
use crate::utxo::{OutputRef, UtxoTransaction};

/// Lift a legacy v1 transaction to v2 format.
///
/// The resulting v2 transaction has:
/// - All inputs as Signature witnesses (ML-DSA-65 proof from v1)
/// - All outputs as pure MLP (no native assets, no datum, no script_ref)
/// - No reference inputs, collateral, mint, redeemers, or auxiliary data
/// - validity_interval derived from the expiry field
pub fn lift_legacy_to_v2(tx: &UtxoTransaction) -> UtxoTransactionV2 {
    let inputs: Vec<TxInputV2> = tx
        .inputs
        .iter()
        .map(|inp| {
            let outref = inp.utxo_refs.first().cloned().unwrap_or(OutputRef {
                tx_hash: [0u8; 32],
                output_index: 0,
            });
            TxInputV2 {
                outref,
                witness: WitnessKindV2::Signature(inp.proof.clone()),
            }
        })
        .collect();

    let outputs: Vec<TxOutputV2> = tx
        .outputs
        .iter()
        .map(|out| TxOutputV2 {
            address: out.address,
            value: AssetValue::mlp_only(out.amount),
            spending_pubkey: out.spending_pubkey.clone(),
            datum: None,
            script_ref: None,
        })
        .collect();

    let validity_interval = if tx.expiry > 0 {
        ValidityInterval {
            valid_from: None,
            valid_to: Some(tx.expiry),
        }
    } else {
        ValidityInterval::default()
    };

    UtxoTransactionV2 {
        version: 2,
        network_id: 0,
        tx_type: tx.tx_type,
        inputs,
        outputs,
        fee: tx.fee,
        validity_interval,
        mint: vec![],
        required_signers: vec![],
        reference_inputs: vec![],
        collateral_inputs: vec![],
        collateral_return: None,
        total_collateral: None,
        network_params_hash: None,
        aux_data_hash: None,
        extra_redeemers: vec![],
        auxiliary_data: None,
    }
}

/// Attempt to decode a transaction as either v1 (legacy) or v2.
///
/// Tries v2 first (version byte == 2), then falls back to v1 (version byte <= 1).
pub fn decode_tx_compat(bytes: &[u8]) -> Result<TxCompat, String> {
    // Peek at version byte
    if bytes.is_empty() {
        return Err("empty tx bytes".into());
    }
    let version = bytes[0];
    if version == EUTXO_TX_VERSION {
        borsh::from_slice::<UtxoTransactionV2>(bytes)
            .map(TxCompat::V2)
            .map_err(|e| format!("v2 decode failed: {}", e))
    } else {
        borsh::from_slice::<UtxoTransaction>(bytes)
            .map(TxCompat::V1)
            .map_err(|e| format!("v1 decode failed: {}", e))
    }
}

/// Compat wrapper: either a v1 or v2 transaction.
#[derive(Debug, Clone)]
pub enum TxCompat {
    V1(UtxoTransaction),
    V2(UtxoTransactionV2),
}
