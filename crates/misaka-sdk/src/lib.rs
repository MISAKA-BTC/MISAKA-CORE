//! MISAKA eUTXO client SDK.
//!
//! Provides:
//! - `TxBuilder` — fluent API for v2 tx construction
//! - `ScriptBuilder` — DSL for validator / mint policy bytecode
//! - `templates` — pre-built scripts (multisig / timelock / nft / pqc gate)
//! - signing helpers (ML-DSA-65)
//! - fee / collateral auto-selection

pub mod error;
pub mod script_builder;
pub mod templates;
pub mod tx_builder;

pub use error::SdkError;
pub use script_builder::ScriptBuilder;
pub use tx_builder::collateral::auto_select_collateral;
pub use tx_builder::fee::compute_min_fee;
pub use tx_builder::signing::{compute_signing_digest, generate_keypair, sign_input};
pub use tx_builder::TxBuilder;

// Re-export commonly used misaka-types for convenience
pub use misaka_types::eutxo::cost_model::ExUnits;
pub use misaka_types::eutxo::datum::{DatumOrHash, InlineDatum};
pub use misaka_types::eutxo::script::{
    ScriptBytecode, ScriptSource, ScriptVmVersion, VersionedScript,
};
pub use misaka_types::eutxo::value::{AssetId, AssetName, AssetValue};

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_types::utxo::{OutputRef, TxType};

    fn or(tag: u8) -> OutputRef {
        OutputRef {
            tx_hash: [tag; 32],
            output_index: 0,
        }
    }

    // ── TxBuilder tests ──

    #[test]
    fn test_build_requires_fee() {
        let result = TxBuilder::new(0, TxType::TransparentTransfer).build();
        assert!(matches!(result, Err(SdkError::FeeNotSet)));
    }

    #[test]
    fn test_simple_transfer() {
        let tx = TxBuilder::new(0, TxType::TransparentTransfer)
            .add_input(or(1), vec![0xAA; 64])
            .add_output([2u8; 32], AssetValue::mlp_only(900_000))
            .set_fee(100_000)
            .build();
        // Note: value imbalance (input amount unknown until resolved),
        // so validate_structural is purely structural and passes.
        assert!(tx.is_ok(), "simple transfer should build: {:?}", tx.err());
        let tx = tx.expect("build");
        assert_eq!(tx.version, 2);
        assert_eq!(tx.fee, 100_000);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
    }

    #[test]
    fn test_reference_input() {
        let tx = TxBuilder::new(0, TxType::TransparentTransfer)
            .add_input(or(1), vec![0xAA; 64])
            .add_reference_input(or(5))
            .add_output([2u8; 32], AssetValue::mlp_only(900_000))
            .set_fee(100_000)
            .build()
            .expect("build");
        assert_eq!(tx.reference_inputs.len(), 1);
    }

    #[test]
    fn test_declared_total_ex_units_zero_for_pubkey_tx() {
        let tx = TxBuilder::new(0, TxType::TransparentTransfer)
            .add_input(or(1), vec![0xAA; 64])
            .add_output([2u8; 32], AssetValue::mlp_only(900_000))
            .set_fee(100_000)
            .build()
            .expect("build");
        assert_eq!(tx.declared_total_ex_units(), ExUnits::ZERO);
    }

    #[test]
    fn test_script_input_ex_units() {
        let script = ScriptSource::Inline(VersionedScript {
            vm_version: ScriptVmVersion::V1,
            bytecode: ScriptBytecode(vec![0x51]),
        });
        let ex = ExUnits {
            cpu: 10_000,
            mem: 500,
        };
        let tx = TxBuilder::new(0, TxType::TransparentTransfer)
            .add_script_input(or(1), script, vec![1, 2, 3], None, ex)
            .add_output([2u8; 32], AssetValue::mlp_only(100))
            .add_collateral(or(9))
            .set_fee(200_000)
            .build()
            .expect("script tx build");
        assert_eq!(tx.declared_total_ex_units(), ex);
    }

    #[test]
    fn test_fee_estimation_converges() {
        let b = TxBuilder::new(0, TxType::TransparentTransfer)
            .add_input(or(1), vec![0xAA; 64])
            .add_output([2u8; 32], AssetValue::mlp_only(900_000));
        let fee = b.estimate_fee().expect("estimate");
        assert!(
            fee >= 100_000,
            "minimum fee should be at least base 100k ulrz"
        );
    }

    // ── ScriptBuilder tests ──

    #[test]
    fn test_script_builder_op_true() {
        let s = ScriptBuilder::new().op_true().build();
        assert_eq!(s.bytecode.0, vec![0x51]);
    }

    #[test]
    fn test_script_builder_chained() {
        let b = ScriptBuilder::new()
            .push_datum()
            .check_req_signer()
            .verify()
            .op_true();
        assert_eq!(b.bytecode(), &[0xC0, 0xC4, 0x69, 0x51]);
    }

    #[test]
    fn test_script_builder_hex() {
        let b = ScriptBuilder::new().op_true();
        assert_eq!(b.bytecode_hex(), "51");
    }

    // ── Template tests ──

    #[test]
    fn test_template_single_owner() {
        let s = templates::single_owner_validator();
        assert_eq!(s.bytecode.0, templates::SINGLE_OWNER_BYTECODE);
    }

    #[test]
    fn test_template_timelock() {
        let s = templates::timelock_before_validator();
        assert_eq!(s.bytecode.0, templates::TIMELOCK_BEFORE_BYTECODE);
    }

    #[test]
    fn test_template_nft_mint() {
        let s = templates::nft_mint_policy();
        assert_eq!(s.bytecode.0, templates::nft_mint::NFT_MINT_BYTECODE);
    }

    #[test]
    fn test_template_pqc_gate() {
        let s = templates::pqc_signature_gate();
        assert_eq!(s.bytecode.0, templates::PQC_GATE_BYTECODE);
    }

    // ── Signing tests ──

    #[test]
    fn test_generate_keypair() {
        let kp = generate_keypair();
        assert!(!kp.public_key.to_bytes().is_empty());
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let kp = generate_keypair();
        let tx = TxBuilder::new(0, TxType::TransparentTransfer)
            .add_input(or(1), vec![0xAA; 64])
            .add_output([2u8; 32], AssetValue::mlp_only(900_000))
            .set_fee(100_000)
            .build()
            .expect("build");
        let sig = sign_input(&tx, 0, &kp.secret_key).expect("sign");
        // Verify round-trip
        let digest = compute_signing_digest(&tx, 0);
        let sig_obj = misaka_pqc::pq_sign::MlDsaSignature::from_bytes(&sig).expect("sig parse");
        let result = misaka_pqc::pq_sign::ml_dsa_verify_raw(&kp.public_key, &digest, &sig_obj);
        assert!(result.is_ok(), "signature should verify");
    }

    #[test]
    fn test_signing_digest_deterministic() {
        let tx = TxBuilder::new(0, TxType::TransparentTransfer)
            .add_input(or(1), vec![0xAA; 64])
            .add_output([2u8; 32], AssetValue::mlp_only(900_000))
            .set_fee(100_000)
            .build()
            .expect("build");
        let d1 = compute_signing_digest(&tx, 0);
        let d2 = compute_signing_digest(&tx, 0);
        assert_eq!(d1, d2);
    }

    // ── Collateral tests ──

    #[test]
    fn test_collateral_sufficient() {
        let avail = vec![(or(1), 200_000), (or(2), 100_000)];
        let (selected, change) =
            auto_select_collateral(&avail, 100_000, [9u8; 32]).expect("select");
        assert_eq!(selected.len(), 1);
        // Required = 100_000 * 150% = 150_000. 200_000 selected → change = 50_000.
        assert!(change.is_some());
        assert_eq!(change.expect("change").value.mlp, 50_000);
    }

    #[test]
    fn test_collateral_insufficient() {
        let avail = vec![(or(1), 10_000)];
        let result = auto_select_collateral(&avail, 100_000, [9u8; 32]);
        assert!(matches!(
            result,
            Err(SdkError::InsufficientCollateral { .. })
        ));
    }

    #[test]
    fn test_collateral_exact_match() {
        // Required = 100k * 150% = 150k. Provide exactly 150k.
        let avail = vec![(or(1), 150_000)];
        let (selected, change) =
            auto_select_collateral(&avail, 100_000, [9u8; 32]).expect("select");
        assert_eq!(selected.len(), 1);
        assert!(change.is_none(), "exact match should have no change");
    }
}
