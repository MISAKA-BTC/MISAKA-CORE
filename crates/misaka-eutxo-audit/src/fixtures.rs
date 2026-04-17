//! Shared test fixtures for integration / fuzz / bench.

use misaka_storage::utxo_set::UtxoSet;
use misaka_types::eutxo::cost_model::ExUnits;
use misaka_types::eutxo::redeemer::{Redeemer, RedeemerPurpose};
use misaka_types::eutxo::tx_v2::{TxInputV2, TxOutputV2, UtxoTransactionV2};
use misaka_types::eutxo::validity::ValidityInterval;
use misaka_types::eutxo::value::AssetValue;
use misaka_types::eutxo::witness::WitnessKindV2;
use misaka_types::utxo::{OutputRef, TxOutput, TxType};

pub fn fresh_utxo_set() -> UtxoSet {
    UtxoSet::new(36)
}

pub fn prefund_utxo(us: &mut UtxoSet, outref: OutputRef, amount: u64, addr: [u8; 32]) {
    let out = TxOutput {
        amount,
        address: addr,
        spending_pubkey: Some(vec![0xAA; 64]),
    };
    us.add_output(outref, out, 1, false).expect("add_output");
}

pub fn zero_redeemer() -> Redeemer {
    Redeemer {
        purpose: RedeemerPurpose::Spend(0),
        data: vec![],
        ex_units: ExUnits::ZERO,
    }
}

pub fn simple_v2_tx(input: OutputRef, fee: u64, output_amount: u64) -> UtxoTransactionV2 {
    UtxoTransactionV2 {
        version: 2,
        network_id: 0,
        tx_type: TxType::TransparentTransfer,
        inputs: vec![TxInputV2 {
            outref: input,
            witness: WitnessKindV2::Signature(vec![0xBB; 64]),
        }],
        outputs: vec![TxOutputV2 {
            address: [3u8; 32],
            value: AssetValue::mlp_only(output_amount),
            spending_pubkey: None,
            datum: None,
            script_ref: None,
        }],
        fee,
        validity_interval: ValidityInterval::default(),
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
