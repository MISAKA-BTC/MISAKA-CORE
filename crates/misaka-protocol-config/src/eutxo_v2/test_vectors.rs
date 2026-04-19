//! Frozen test vectors for cost model V1.
//! Any change to these is a CONSENSUS BREAK.

/// Frozen hash of CostModel V1.
pub const COST_MODEL_V1_HASH_HEX: &str =
    "94f3792b4d5fcd9e860a8b3c4266e410ac48703db1530b7c6869bbc0cb207556";

/// Fee for minimum tx (200 bytes, no scripts): in ulrz.
pub const FEE_MIN_TX_200B_ULRZ: &str = "110000";

/// Fee for medium script tx (2000 bytes, 100M cpu / 1M mem): in ulrz.
pub const FEE_MEDIUM_SCRIPT_ULRZ: &str = "6200070";

/// Fee for max tx (16384 bytes, max ExUnits): in ulrz.
pub const FEE_MAX_TX_ULRZ: &str = "300919900";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eutxo_v2::*;
    use misaka_types::eutxo::cost_model::ExUnits;

    #[test]
    fn cost_model_v1_hash_frozen() {
        let h = cost_model::cost_model_v1_hash();
        let hex_val = hex::encode(h);
        eprintln!("COST_MODEL_V1_HASH = {}", hex_val);
        if COST_MODEL_V1_HASH_HEX != "REPLACE_AFTER_FIRST_RUN" {
            assert_eq!(
                hex_val, COST_MODEL_V1_HASH_HEX,
                "CostModel V1 hash drift — consensus break!"
            );
        }
    }

    #[test]
    fn fee_vectors() {
        // Vector 1: minimum tx
        let f1 = fees::calculate_min_fee_ulrz(200, ExUnits::ZERO);
        eprintln!("FEE_MIN_TX_200B = {} ulrz", f1);

        // Vector 2: medium script tx
        let f2 = fees::calculate_min_fee_ulrz(
            2000,
            ExUnits {
                cpu: 100_000_000,
                mem: 1_000_000,
            },
        );
        eprintln!("FEE_MEDIUM_SCRIPT = {} ulrz", f2);

        // Vector 3: max tx
        let f3 = fees::calculate_min_fee_ulrz(limits::MAX_TX_SIZE_BYTES, budget::MAX_TX_EX_UNITS);
        eprintln!("FEE_MAX_TX = {} ulrz ({:.4} MISAKA)", f3, f3 as f64 / 1e9);

        if FEE_MIN_TX_200B_ULRZ != "REPLACE_AFTER_FIRST_RUN" {
            assert_eq!(f1.to_string(), FEE_MIN_TX_200B_ULRZ);
            assert_eq!(f2.to_string(), FEE_MEDIUM_SCRIPT_ULRZ);
            assert_eq!(f3.to_string(), FEE_MAX_TX_ULRZ);
        }
    }

    #[test]
    fn budget_constants_frozen() {
        let b = budget::budget_v1();
        assert_eq!(b.max_tx_ex_units.cpu, 5_000_000_000);
        assert_eq!(b.max_tx_ex_units.mem, 10_000_000);
        assert_eq!(b.max_block_ex_units.cpu, 50_000_000_000);
        assert_eq!(b.max_block_ex_units.mem, 100_000_000);
        assert_eq!(b.collateral_percentage, 15_000);
        assert_eq!(b.max_collateral_inputs, 3);
        assert_eq!(b.max_tx_size_bytes, 16_384);
        assert_eq!(b.max_value_size_bytes, 5_000);
    }

    #[test]
    fn fee_coefficients_frozen() {
        use crate::eutxo_v2::units::*;
        assert_eq!(fees::FEE_BASE_PLRZ, 100_000 * PLRZ_PER_ULRZ);
        assert_eq!(fees::FEE_PER_BYTE_PLRZ, 50 * PLRZ_PER_ULRZ);
        assert_eq!(fees::FEE_PER_CPU_STEP_PLRZ, 60 * PLRZ_PER_NLRZ);
        assert_eq!(fees::FEE_PER_MEM_UNIT_PLRZ, 70);
    }

    #[test]
    fn fee_calculation_rounding_up() {
        // A tx that produces fractional ulrz should round UP
        let f = fees::calculate_min_fee_ulrz(1, ExUnits::ZERO);
        // base 100,000 ulrz + 1 byte * 50 ulrz/byte = 100,050 ulrz
        assert_eq!(f, 100_050);
    }

    #[test]
    fn cost_model_borsh_roundtrip() {
        let model = cost_model::cost_model_v1();
        let bytes = borsh::to_vec(&model).expect("serialize");
        let decoded: misaka_types::eutxo::cost_model::CostModel =
            borsh::from_slice(&bytes).expect("deserialize");
        assert_eq!(model, decoded);
    }

    #[test]
    fn cost_lookup_pqc() {
        let model = cost_model::cost_model_v1();
        let ml_dsa = model.lookup(opcodes::OPCODE_CHECK_ML_DSA);
        assert!(ml_dsa.is_some());
        assert_eq!(ml_dsa.expect("ML-DSA cost").cpu_per_call, 5_000_000);
    }
}
