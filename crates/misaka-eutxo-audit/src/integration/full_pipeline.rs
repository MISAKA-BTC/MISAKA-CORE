//! Full pipeline tests at cross-crate API level.
//!
//! Since misaka-node exposes the executor only as a binary target, we test
//! the consensus-critical building blocks that ARE cross-crate accessible:
//!   - validate_structural (E1)
//!   - UtxoSet add/remove + MuHash state_root (E5)
//!   - Script VM evaluation (E3)
//!   - TxBuilder (E7 SDK)

#[cfg(test)]
mod tests {
    use crate::fixtures::*;
    use misaka_types::eutxo::validate::validate_structural;
    use misaka_types::utxo::OutputRef;

    #[test]
    fn structural_validation_accepts_minimal_tx() {
        let outref = OutputRef { tx_hash: [1u8; 32], output_index: 0 };
        let tx = simple_v2_tx(outref, 200_000, 9_800_000);
        assert!(validate_structural(&tx).is_ok());
    }

    #[test]
    fn utxo_set_roundtrip_changes_state_root() {
        let mut us = fresh_utxo_set();
        let outref = OutputRef { tx_hash: [1u8; 32], output_index: 0 };
        prefund_utxo(&mut us, outref.clone(), 1_000_000, [2u8; 32]);
        let root_with = us.compute_state_root();

        us.remove_output(&outref);
        let root_empty = us.compute_state_root();

        assert_ne!(root_with, root_empty);
    }

    #[test]
    fn state_root_deterministic_replay() {
        fn build() -> [u8; 32] {
            let mut us = fresh_utxo_set();
            for i in 0u8..10 {
                let outref = OutputRef { tx_hash: [i + 1; 32], output_index: 0 };
                prefund_utxo(&mut us, outref, 1_000_000 * (i as u64 + 1), [(i + 10); 32]);
            }
            us.compute_state_root()
        }
        assert_eq!(build(), build(), "state_root must be deterministic");
    }

    /// v1.0 hard-fork parallel SMT: the v4 state root (derived
    /// from the parallel `SparseMerkleTree` inside `UtxoSet`,
    /// wrapped under `"MISAKA:state_root:v4:"`) MUST be
    /// deterministic across replays — same invariant as v3.
    /// This pins the migration-window determinism contract from
    /// the replay/audit side. See
    /// `docs/design/v100_smt_migration.md`.
    #[test]
    fn state_root_v4_deterministic_replay() {
        fn build() -> [u8; 32] {
            let mut us = fresh_utxo_set();
            for i in 0u8..10 {
                let outref = OutputRef { tx_hash: [i + 1; 32], output_index: 0 };
                prefund_utxo(&mut us, outref, 1_000_000 * (i as u64 + 1), [(i + 10); 32]);
            }
            us.compute_state_root_v4()
        }
        assert_eq!(build(), build(), "state_root_v4 must be deterministic");
    }

    /// v3 vs v4 domain separation audit: on the same UTXO set,
    /// the two commitments MUST differ so no cross-labelled
    /// replay can pass verification.
    #[test]
    fn state_root_v3_v4_are_domain_separated() {
        let mut us = fresh_utxo_set();
        let outref = OutputRef { tx_hash: [1u8; 32], output_index: 0 };
        prefund_utxo(&mut us, outref, 1_000_000, [2u8; 32]);
        assert_ne!(us.compute_state_root(), us.compute_state_root_v4());
    }

    #[test]
    fn script_vm_evaluates_op_true() {
        use misaka_txscript::v2_eutxo::{
            budget::BudgetTracker, context::ScriptContext, engine::V1ScriptVm,
        };
        use misaka_types::eutxo::cost_model::ExUnits;
        use misaka_types::eutxo::redeemer::{Redeemer, RedeemerPurpose};
        use misaka_types::eutxo::tx_v2::TxOutputV2;
        use misaka_types::eutxo::value::AssetValue;

        let outref = OutputRef { tx_hash: [1u8; 32], output_index: 0 };
        let tx = simple_v2_tx(outref, 200_000, 9_800_000);
        let outputs = vec![TxOutputV2 {
            address: [1u8; 32],
            value: AssetValue::mlp_only(100),
            spending_pubkey: None,
            datum: None,
            script_ref: None,
        }];
        let ctx = ScriptContext {
            tx: &tx,
            spending_input_index: 0,
            resolved_reference_outputs: &[],
            resolved_spending_outputs: &outputs,
        };
        let redeemer = Redeemer {
            purpose: RedeemerPurpose::Spend(0),
            data: vec![],
            ex_units: ExUnits::ZERO,
        };
        let mut budget = BudgetTracker::new(ExUnits { cpu: 1_000_000, mem: 1_000_000 });
        let mut vm = V1ScriptVm::new(&ctx, &redeemer, None, &mut budget);
        assert!(vm.execute(&[0x51]).expect("OP_TRUE"));
    }

    #[test]
    fn tx_builder_produces_valid_v2_tx() {
        use misaka_sdk::{AssetValue, TxBuilder};
        use misaka_types::utxo::TxType;
        let outref = OutputRef { tx_hash: [1u8; 32], output_index: 0 };
        let tx = TxBuilder::new(0, TxType::TransparentTransfer)
            .add_input(outref, vec![0xAA; 64])
            .add_output([2u8; 32], AssetValue::mlp_only(900_000))
            .set_fee(100_000)
            .build()
            .expect("build");
        assert_eq!(tx.version, 2);
        assert!(validate_structural(&tx).is_ok());
    }
}
