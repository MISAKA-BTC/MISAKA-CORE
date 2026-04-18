//! Frozen wire-format test vectors. v2.0 hard fork depends on these hex values.
//! Any change to these constants is a CONSENSUS BREAK.

/// Borsh-encoded empty v2 transaction.
pub const EMPTY_V2_TX_HEX: &str =
    "02000600000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
/// Borsh-encoded v2 transaction with one native asset.
pub const V2_NATIVE_ASSET_TX_HEX: &str =
    "020006010000000101010101010101010101010101010101010101010101010101010101010101000000000040000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa010000000202020202020202020202020202020202020202020202020202020202020202e803000000000000010000000303030303030303030303030303030303030303030303030303030303030303040000005553444df4010000000000000000006400000000000000000000000000000000000000000000000000000000000000000000";
/// SHA3-256 hash of a V1 VersionedScript containing OP_TRUE.
pub const VERSIONED_SCRIPT_V1_HASH_HEX: &str =
    "1e8ae0b0dea1ec9351fb36da04414913526c0ac20a0a6a304a9c8e6d5600bdf7";
/// tx_hash of the empty v2 transaction.
pub const EMPTY_V2_TX_HASH_HEX: &str =
    "10490918aeeda92e7e8a6b8a142cc38cf44549cd24310a8e246fd2bd9ef06f90";

#[cfg(test)]
mod lock_in {
    use super::*;
    use crate::eutxo::script::*;
    use crate::eutxo::tx_v2::*;
    use crate::eutxo::validity::*;
    use crate::eutxo::value::*;
    use crate::utxo::{OutputRef, TxType};
    use std::collections::BTreeMap;

    fn make_empty_v2_tx() -> UtxoTransactionV2 {
        UtxoTransactionV2 {
            version: 2,
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
        }
    }

    fn make_native_asset_v2_tx() -> UtxoTransactionV2 {
        UtxoTransactionV2 {
            version: 2,
            network_id: 0,
            tx_type: TxType::TransparentTransfer,
            inputs: vec![TxInputV2 {
                outref: OutputRef {
                    tx_hash: [1u8; 32],
                    output_index: 0,
                },
                witness: crate::eutxo::witness::WitnessKindV2::Signature(vec![0xAA; 64]),
            }],
            outputs: vec![TxOutputV2 {
                address: [2u8; 32],
                value: AssetValue {
                    mlp: 1000,
                    native_assets: BTreeMap::from([(
                        AssetId {
                            policy: [3u8; 32],
                            asset_name: AssetName(b"USDM".to_vec()),
                        },
                        500u64,
                    )]),
                },
                spending_pubkey: None,
                datum: None,
                script_ref: None,
            }],
            fee: 100,
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

    #[test]
    fn lock_in_empty_v2_tx() {
        let tx = make_empty_v2_tx();
        let encoded = borsh::to_vec(&tx).expect("borsh encode empty v2 tx");
        let hex_val = hex::encode(&encoded);
        let hash_hex = hex::encode(tx.tx_hash());
        eprintln!("EMPTY_V2_TX_HEX     = {}", hex_val);
        eprintln!("EMPTY_V2_TX_HASH_HEX = {}", hash_hex);

        if EMPTY_V2_TX_HEX != "REPLACE_AFTER_FIRST_RUN" {
            assert_eq!(hex_val, EMPTY_V2_TX_HEX, "empty v2 tx wire format changed");
            assert_eq!(hash_hex, EMPTY_V2_TX_HASH_HEX, "empty v2 tx hash changed");
        }
    }

    #[test]
    fn lock_in_native_asset_v2_tx() {
        let tx = make_native_asset_v2_tx();
        let encoded = borsh::to_vec(&tx).expect("borsh encode native asset v2 tx");
        let hex_val = hex::encode(&encoded);
        eprintln!("V2_NATIVE_ASSET_TX_HEX = {}", hex_val);

        if V2_NATIVE_ASSET_TX_HEX != "REPLACE_AFTER_FIRST_RUN" {
            assert_eq!(
                hex_val, V2_NATIVE_ASSET_TX_HEX,
                "native asset v2 tx wire format changed"
            );
        }
    }

    #[test]
    fn lock_in_versioned_script_hash() {
        let s = VersionedScript {
            vm_version: ScriptVmVersion::V1,
            bytecode: ScriptBytecode(vec![0x51]),
        };
        let hash_hex = hex::encode(s.hash());
        eprintln!("VERSIONED_SCRIPT_V1_HASH_HEX = {}", hash_hex);

        if VERSIONED_SCRIPT_V1_HASH_HEX != "REPLACE_AFTER_FIRST_RUN" {
            assert_eq!(
                hash_hex, VERSIONED_SCRIPT_V1_HASH_HEX,
                "script hash changed"
            );
        }
    }

    #[test]
    fn borsh_roundtrip_empty_v2() {
        let tx = make_empty_v2_tx();
        let encoded = borsh::to_vec(&tx).expect("encode");
        let decoded: UtxoTransactionV2 = borsh::from_slice(&encoded).expect("decode");
        assert_eq!(tx, decoded);
    }

    #[test]
    fn borsh_roundtrip_native_asset_v2() {
        let tx = make_native_asset_v2_tx();
        let encoded = borsh::to_vec(&tx).expect("encode");
        let decoded: UtxoTransactionV2 = borsh::from_slice(&encoded).expect("decode");
        assert_eq!(tx, decoded);
    }

    #[test]
    fn legacy_decode_not_broken() {
        use crate::utxo::UtxoTransaction;
        let legacy = UtxoTransaction {
            version: 2,
            tx_type: TxType::TransparentTransfer,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            extra: vec![],
            expiry: 0,
        };
        let encoded = borsh::to_vec(&legacy).expect("encode legacy");
        let decoded: UtxoTransaction = borsh::from_slice(&encoded).expect("decode legacy");
        assert_eq!(legacy.fee, decoded.fee);
    }

    #[test]
    fn validate_empty_v2_passes() {
        let tx = make_empty_v2_tx();
        assert!(crate::eutxo::validate::validate_structural(&tx).is_ok());
    }

    #[test]
    fn validate_rejects_wrong_version() {
        let mut tx = make_empty_v2_tx();
        tx.version = 1;
        assert!(crate::eutxo::validate::validate_structural(&tx).is_err());
    }
}
