//! Script VM fuzz tests. Goal: never panic, always deterministic, always bounded.

#[cfg(test)]
mod tests {
    use misaka_txscript::v2_eutxo::{
        budget::BudgetTracker, context::ScriptContext, engine::V1ScriptVm,
    };
    use misaka_types::eutxo::cost_model::ExUnits;
    use misaka_types::eutxo::redeemer::{Redeemer, RedeemerPurpose};
    use misaka_types::eutxo::tx_v2::*;
    use misaka_types::eutxo::validity::ValidityInterval;
    use misaka_types::eutxo::value::AssetValue;
    use misaka_types::utxo::{OutputRef, TxType};
    use proptest::prelude::*;

    fn fixture_tx() -> UtxoTransactionV2 {
        UtxoTransactionV2 {
            version: 2,
            network_id: 0,
            tx_type: TxType::TransparentTransfer,
            inputs: vec![TxInputV2 {
                outref: OutputRef { tx_hash: [1u8; 32], output_index: 0 },
                witness: misaka_types::eutxo::witness::WitnessKindV2::Signature(vec![]),
            }],
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
        }
    }

    fn fixture_output() -> TxOutputV2 {
        TxOutputV2 {
            address: [1u8; 32],
            value: AssetValue::mlp_only(100),
            spending_pubkey: None,
            datum: None,
            script_ref: None,
        }
    }

    fn fixture_redeemer() -> Redeemer {
        Redeemer {
            purpose: RedeemerPurpose::Spend(0),
            data: vec![],
            ex_units: ExUnits::ZERO,
        }
    }

    fn arb_bytecode() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(0u8..=0xFFu8, 0..100)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn vm_never_panics(bc in arb_bytecode()) {
            let tx = fixture_tx();
            let outputs = vec![fixture_output()];
            let ctx = ScriptContext {
                tx: &tx,
                spending_input_index: 0,
                resolved_reference_outputs: &[],
                resolved_spending_outputs: &outputs,
            };
            let redeemer = fixture_redeemer();
            let limit = ExUnits { cpu: 1_000_000_000, mem: 1_000_000 };
            let mut budget = BudgetTracker::new(limit);
            let mut vm = V1ScriptVm::new(&ctx, &redeemer, None, &mut budget);
            let _ = vm.execute(&bc);
        }

        #[test]
        fn vm_deterministic(bc in arb_bytecode()) {
            let tx = fixture_tx();
            let outputs = vec![fixture_output()];
            let ctx = ScriptContext {
                tx: &tx,
                spending_input_index: 0,
                resolved_reference_outputs: &[],
                resolved_spending_outputs: &outputs,
            };
            let redeemer = fixture_redeemer();
            let limit = ExUnits { cpu: 1_000_000_000, mem: 1_000_000 };

            let mut results = Vec::with_capacity(3);
            for _ in 0..3 {
                let mut b = BudgetTracker::new(limit);
                let mut vm = V1ScriptVm::new(&ctx, &redeemer, None, &mut b);
                let r = vm.execute(&bc);
                results.push((r, b.spent));
            }
            let first = &results[0];
            for r in &results[1..] {
                prop_assert_eq!(&r.0, &first.0);
                prop_assert_eq!(r.1, first.1);
            }
        }

        #[test]
        fn vm_respects_budget(bc in arb_bytecode(), cpu_limit in 0u64..100_000_000u64) {
            let tx = fixture_tx();
            let outputs = vec![fixture_output()];
            let ctx = ScriptContext {
                tx: &tx,
                spending_input_index: 0,
                resolved_reference_outputs: &[],
                resolved_spending_outputs: &outputs,
            };
            let redeemer = fixture_redeemer();
            let limit = ExUnits { cpu: cpu_limit, mem: 1_000_000 };
            let mut budget = BudgetTracker::new(limit);
            let mut vm = V1ScriptVm::new(&ctx, &redeemer, None, &mut budget);
            let _ = vm.execute(&bc);
            prop_assert!(budget.spent.cpu <= cpu_limit);
        }
    }
}
