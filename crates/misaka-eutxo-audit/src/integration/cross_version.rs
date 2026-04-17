//! v1 / v2 type compatibility tests.

#[cfg(test)]
mod tests {
    use misaka_storage::eutxo_state::extended_output::ExtendedOutput;
    use misaka_types::eutxo::tx_v2::TxOutputV2;
    use misaka_types::eutxo::value::AssetValue;
    use misaka_types::utxo::TxOutput;

    #[test]
    fn v1_output_lifts_to_extended() {
        let v1 = TxOutput {
            amount: 1_000_000,
            address: [1u8; 32],
            spending_pubkey: Some(vec![0xAA; 64]),
        };
        let ext = ExtendedOutput::from_v1(&v1);
        assert!(!ext.has_v2_features());
        assert_eq!(ext.value.mlp, 1_000_000);
    }

    #[test]
    fn extended_roundtrips_to_v1() {
        let v1 = TxOutput {
            amount: 2_500_000,
            address: [9u8; 32],
            spending_pubkey: Some(vec![0xBB; 64]),
        };
        let ext = ExtendedOutput::from_v1(&v1);
        let back = ext.try_to_v1().expect("round-trip");
        assert_eq!(back.amount, v1.amount);
        assert_eq!(back.address, v1.address);
        assert_eq!(back.spending_pubkey, v1.spending_pubkey);
    }

    #[test]
    fn v2_output_lifts_to_extended() {
        let v2 = TxOutputV2 {
            address: [7u8; 32],
            value: AssetValue::mlp_only(1_500_000),
            spending_pubkey: None,
            datum: None,
            script_ref: None,
        };
        let ext = ExtendedOutput::from_v2(&v2);
        assert!(!ext.has_v2_features());
        assert_eq!(ext.value.mlp, 1_500_000);
    }

    #[test]
    fn v2_with_datum_cannot_downgrade_to_v1() {
        use misaka_types::eutxo::datum::{DatumOrHash, InlineDatum};
        let ext = ExtendedOutput {
            address: [7u8; 32],
            value: AssetValue::mlp_only(1_000_000),
            spending_pubkey: None,
            datum: Some(DatumOrHash::Inline(InlineDatum(b"data".to_vec()))),
            script_ref: None,
        };
        assert!(ext.has_v2_features());
        assert!(ext.try_to_v1().is_none());
    }
}
