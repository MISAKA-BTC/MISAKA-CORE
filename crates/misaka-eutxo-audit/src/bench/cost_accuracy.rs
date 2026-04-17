//! Measure actual wall-clock time per opcode and compare to E2 declared costs.
//!
//! Generates a markdown report at `docs/audit/COST_MODEL_VALIDATION.md`.
//! Human review decides if re-freeze is needed.

use misaka_protocol_config::eutxo_v2::cost_model::{cost_model_v1, cost_model_v1_hash};
use std::time::Instant;

pub struct OpcodeTiming {
    pub opcode: u16,
    pub mnemonic: &'static str,
    pub declared_cpu: u64,
    pub measured_ns: u128,
    pub ratio: f64,
}

/// Run a microbenchmark for the given opcode and return median ns.
fn measure_op(bytecode: &[u8], iterations: u32) -> u128 {
    use misaka_txscript::v2_eutxo::{
        budget::BudgetTracker, context::ScriptContext, engine::V1ScriptVm,
    };
    use misaka_types::eutxo::cost_model::ExUnits;
    use misaka_types::eutxo::redeemer::{Redeemer, RedeemerPurpose};
    use misaka_types::eutxo::tx_v2::*;
    use misaka_types::eutxo::validity::ValidityInterval;
    use misaka_types::eutxo::value::AssetValue;
    use misaka_types::eutxo::witness::WitnessKindV2;
    use misaka_types::utxo::{OutputRef, TxType};

    let tx = UtxoTransactionV2 {
        version: 2,
        network_id: 0,
        tx_type: TxType::TransparentTransfer,
        inputs: vec![TxInputV2 {
            outref: OutputRef {
                tx_hash: [1u8; 32],
                output_index: 0,
            },
            witness: WitnessKindV2::Signature(vec![]),
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
    };
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

    // Warmup
    for _ in 0..100 {
        let mut b = BudgetTracker::new(ExUnits { cpu: u64::MAX, mem: u64::MAX });
        let mut vm = V1ScriptVm::new(&ctx, &redeemer, None, &mut b);
        let _ = vm.execute(bytecode);
    }

    let start = Instant::now();
    for _ in 0..iterations {
        let mut b = BudgetTracker::new(ExUnits { cpu: u64::MAX, mem: u64::MAX });
        let mut vm = V1ScriptVm::new(&ctx, &redeemer, None, &mut b);
        let _ = vm.execute(bytecode);
    }
    let elapsed = start.elapsed();
    elapsed.as_nanos() / iterations as u128
}

/// Benchmark a curated set of single-opcode bytecodes.
pub fn collect_timings() -> Vec<OpcodeTiming> {
    let model = cost_model_v1();
    let iters = 10_000u32;

    let cases: &[(u16, &str, &[u8])] = &[
        (0x51, "OP_TRUE", &[0x51]),
        (0x00, "OP_FALSE", &[0x00]),
        (0x93, "OP_ADD (1+1)", &[0x51, 0x51, 0x93]),
        (0x94, "OP_SUB (2-1)", &[0x52, 0x51, 0x94]),
        (0x87, "OP_EQUAL (1,1)", &[0x51, 0x51, 0x87]),
        (0x88, "OP_EQUALVERIFY (1,1)", &[0x51, 0x51, 0x88]),
        (0x69, "OP_VERIFY", &[0x51, 0x69]),
        (0x75, "OP_DROP", &[0x51, 0x75]),
        (0x76, "OP_DUP", &[0x51, 0x76]),
        (0x7C, "OP_SWAP", &[0x51, 0x52, 0x7C]),
        (0x9A, "OP_BOOLAND", &[0x51, 0x51, 0x9A]),
        (0x9B, "OP_BOOLOR", &[0x51, 0x00, 0x9B]),
    ];

    let mut timings = Vec::with_capacity(cases.len());
    for (opcode, mnemonic, bc) in cases {
        let measured_ns = measure_op(bc, iters);
        let declared_cpu = model.lookup(*opcode).map(|c| c.cpu_per_call).unwrap_or(0);
        let ratio = if declared_cpu > 0 {
            measured_ns as f64 / declared_cpu as f64
        } else {
            0.0
        };
        timings.push(OpcodeTiming {
            opcode: *opcode,
            mnemonic,
            declared_cpu,
            measured_ns,
            ratio,
        });
    }
    timings
}

/// Format timings as a markdown report.
pub fn format_report(timings: &[OpcodeTiming]) -> String {
    let mut s = String::new();
    s.push_str("# Cost Model Validation Report\n\n");
    s.push_str(&format!(
        "Cost model V1 hash: `{}`\n\n",
        hex::encode(cost_model_v1_hash())
    ));
    s.push_str("## Per-opcode Measurements\n\n");
    s.push_str("| Opcode | Mnemonic | Declared cpu | Measured ns | Ratio (ns/cpu) |\n");
    s.push_str("|--------|----------|--------------|-------------|----------------|\n");
    for t in timings {
        s.push_str(&format!(
            "| {:#06x} | {} | {} | {} | {:.4} |\n",
            t.opcode, t.mnemonic, t.declared_cpu, t.measured_ns, t.ratio
        ));
    }
    s.push_str("\n## Interpretation\n\n");
    s.push_str("- Target: 1 cpu_step ≈ 1 ns (calibration reference).\n");
    s.push_str("- Ratio 0.5–2.0: acceptable; declared cost proportional to measured.\n");
    s.push_str("- Ratio > 2.0: declared cost too low → submitter underpays. Candidate for re-freeze.\n");
    s.push_str("- Ratio < 0.5: declared cost too high → submitter overpays. Low priority.\n\n");
    s.push_str("## Review Decision\n\n");
    s.push_str("Human reviewer determines whether any opcode's ratio justifies a pre-launch re-freeze.\n");
    s.push_str("If yes: update `cost_model_v1_table` in misaka-protocol-config, re-run lock_in tests,\n");
    s.push_str("and the new `cost_model_v1_hash` becomes the v2.0 launch value.\n");
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_measure_op_true() {
        let timings = collect_timings();
        assert!(!timings.is_empty(), "should measure at least one opcode");
        // OP_TRUE measurement should be small but positive
        let op_true = timings.iter().find(|t| t.opcode == 0x51).expect("OP_TRUE");
        assert!(op_true.measured_ns > 0);
        assert!(op_true.declared_cpu > 0);
    }

    #[test]
    fn format_report_contains_table() {
        let timings = collect_timings();
        let report = format_report(&timings);
        assert!(report.contains("# Cost Model Validation Report"));
        assert!(report.contains("OP_TRUE"));
        assert!(report.contains("Declared cpu"));
    }
}
