//! validate_structural fuzz tests.

#[cfg(test)]
mod tests {
    use misaka_types::eutxo::tx_v2::*;
    use misaka_types::eutxo::validate::validate_structural;
    use misaka_types::eutxo::validity::ValidityInterval;
    use misaka_types::eutxo::value::AssetValue;
    use misaka_types::eutxo::witness::WitnessKindV2;
    use misaka_types::utxo::{OutputRef, TxType};
    use proptest::prelude::*;

    fn arb_bytes32() -> impl Strategy<Value = [u8; 32]> {
        any::<[u8; 32]>()
    }

    fn arb_outref() -> impl Strategy<Value = OutputRef> {
        (arb_bytes32(), any::<u32>()).prop_map(|(h, i)| OutputRef {
            tx_hash: h,
            output_index: i,
        })
    }

    fn arb_input() -> impl Strategy<Value = TxInputV2> {
        (arb_outref(), prop::collection::vec(any::<u8>(), 0..128)).prop_map(
            |(outref, sig)| TxInputV2 {
                outref,
                witness: WitnessKindV2::Signature(sig),
            },
        )
    }

    fn arb_output() -> impl Strategy<Value = TxOutputV2> {
        (arb_bytes32(), any::<u64>()).prop_map(|(addr, amt)| TxOutputV2 {
            address: addr,
            value: AssetValue::mlp_only(amt),
            spending_pubkey: None,
            datum: None,
            script_ref: None,
        })
    }

    fn arb_tx() -> impl Strategy<Value = UtxoTransactionV2> {
        (
            prop::collection::vec(arb_input(), 0..70),
            prop::collection::vec(arb_output(), 0..70),
            any::<u64>(),
            any::<Option<u64>>(),
            any::<Option<u64>>(),
        )
            .prop_map(|(inputs, outputs, fee, vf, vt)| UtxoTransactionV2 {
                version: 2,
                network_id: 0,
                tx_type: TxType::TransparentTransfer,
                inputs,
                outputs,
                fee,
                validity_interval: ValidityInterval {
                    valid_from: vf,
                    valid_to: vt,
                },
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
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn structural_never_panics(tx in arb_tx()) {
            let _ = validate_structural(&tx);
        }

        #[test]
        fn valid_tx_round_trips(tx in arb_tx()) {
            if validate_structural(&tx).is_ok() {
                let bytes = borsh::to_vec(&tx).expect("serialize");
                let decoded: UtxoTransactionV2 =
                    borsh::from_slice(&bytes).expect("deserialize");
                prop_assert_eq!(tx, decoded);
            }
        }

        #[test]
        fn oversized_inputs_rejected(
            inputs in prop::collection::vec(arb_input(), 65..100),
            outputs in prop::collection::vec(arb_output(), 0..10),
        ) {
            let tx = UtxoTransactionV2 {
                version: 2,
                network_id: 0,
                tx_type: TxType::TransparentTransfer,
                inputs,
                outputs,
                fee: 100_000,
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
            };
            prop_assert!(validate_structural(&tx).is_err());
        }

        #[test]
        fn wrong_version_rejected(version in 0u8..100) {
            if version == 2 { return Ok(()); }
            let tx = UtxoTransactionV2 {
                version,
                network_id: 0,
                tx_type: TxType::TransparentTransfer,
                inputs: vec![],
                outputs: vec![],
                fee: 0,
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
            };
            prop_assert!(validate_structural(&tx).is_err());
        }
    }
}
