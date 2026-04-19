//! eUTXO v5 state commitment: datum + script_ref in UTXO element bytes.
//! Feature-gated behind `eutxo-v1-state`. Activated at v2.0 hard fork.

pub mod domain;
pub mod element_v5;
pub mod extended_output;

pub use element_v5::utxo_element_bytes_v5;
pub use extended_output::ExtendedOutput;

/// v5 state_root computation.
pub fn compute_state_root_v5(muhash_digest: [u8; 32], height: u64) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(domain::STATE_ROOT_V5);
    h.update(height.to_le_bytes());
    h.update(muhash_digest);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utxo_set::UtxoSet;
    use element_v5::*;
    use misaka_muhash::MuHash;
    use misaka_types::eutxo::datum::{DatumOrHash, InlineDatum};
    use misaka_types::eutxo::script::{ScriptBytecode, ScriptVmVersion, VersionedScript};
    use misaka_types::eutxo::value::AssetValue;
    use misaka_types::utxo::{OutputRef, TxOutput};
    use std::collections::BTreeMap;

    fn make_v1_output() -> TxOutput {
        TxOutput {
            amount: 1_000_000,
            address: [1u8; 32],
            spending_pubkey: Some(vec![0xAA; 64]),
        }
    }

    fn make_outref() -> OutputRef {
        OutputRef {
            tx_hash: [2u8; 32],
            output_index: 0,
        }
    }

    #[test]
    fn test_v1_lift_roundtrip() {
        let v1 = make_v1_output();
        let ext = ExtendedOutput::from_v1(&v1);
        assert!(!ext.has_v2_features());
        let back = ext.try_to_v1().expect("round-trip");
        assert_eq!(back.amount, v1.amount);
        assert_eq!(back.address, v1.address);
    }

    #[test]
    fn test_v5_element_deterministic() {
        let outref = make_outref();
        let ext = ExtendedOutput::from_v1(&make_v1_output());
        let a = utxo_element_bytes_v5(&outref, &ext, 100);
        let b = utxo_element_bytes_v5(&outref, &ext, 100);
        assert_eq!(a, b);
    }

    #[test]
    fn test_v5_element_differs_from_v4() {
        let outref = make_outref();
        let v1 = make_v1_output();
        let v4_elem = crate::utxo_set::utxo_element_bytes_v4_pub(&outref, &v1, 100);
        let ext = ExtendedOutput::from_v1(&v1);
        let v5_elem = utxo_element_bytes_v5(&outref, &ext, 100);
        assert_ne!(
            v4_elem, v5_elem,
            "v5 must differ from v4 (different domain)"
        );
    }

    #[test]
    fn test_datum_changes_element() {
        let outref = make_outref();
        let ext_none = ExtendedOutput {
            datum: None,
            ..ExtendedOutput::from_v1(&make_v1_output())
        };
        let ext_inline = ExtendedOutput {
            datum: Some(DatumOrHash::Inline(InlineDatum(b"hello".to_vec()))),
            ..ExtendedOutput::from_v1(&make_v1_output())
        };
        let a = utxo_element_bytes_v5(&outref, &ext_none, 100);
        let b = utxo_element_bytes_v5(&outref, &ext_inline, 100);
        assert_ne!(a, b);
    }

    #[test]
    fn test_script_ref_changes_element() {
        let outref = make_outref();
        let ext_none = ExtendedOutput::from_v1(&make_v1_output());
        let ext_script = ExtendedOutput {
            script_ref: Some(VersionedScript {
                vm_version: ScriptVmVersion::V1,
                bytecode: ScriptBytecode(vec![0x51]),
            }),
            ..ExtendedOutput::from_v1(&make_v1_output())
        };
        let a = utxo_element_bytes_v5(&outref, &ext_none, 100);
        let b = utxo_element_bytes_v5(&outref, &ext_script, 100);
        assert_ne!(a, b);
    }

    #[test]
    fn test_v5_state_root_differs_from_v4() {
        let mut us = UtxoSet::new(36);
        let outref = make_outref();
        let v1 = make_v1_output();
        us.add_output(outref.clone(), v1.clone(), 1, false)
            .expect("add");
        let v4_root = us.compute_state_root();

        // Recompute v5 from scratch
        let ext = ExtendedOutput::from_v1(&v1);
        let mut mh = MuHash::new();
        mh.add_element(&utxo_element_bytes_v5(&outref, &ext, 1));
        let v5_root = compute_state_root_v5(mh.finalize(), 1);

        assert_ne!(v4_root, v5_root, "v5 state_root must differ from v4");
    }

    #[test]
    fn test_v5_order_independence() {
        let or1 = OutputRef {
            tx_hash: [1u8; 32],
            output_index: 0,
        };
        let or2 = OutputRef {
            tx_hash: [2u8; 32],
            output_index: 0,
        };
        let ext1 = ExtendedOutput::from_v1(&TxOutput {
            amount: 100,
            address: [1u8; 32],
            spending_pubkey: None,
        });
        let ext2 = ExtendedOutput::from_v1(&TxOutput {
            amount: 200,
            address: [2u8; 32],
            spending_pubkey: None,
        });

        // Order 1
        let mut mh1 = MuHash::new();
        mh1.add_element(&utxo_element_bytes_v5(&or1, &ext1, 1));
        mh1.add_element(&utxo_element_bytes_v5(&or2, &ext2, 1));

        // Order 2
        let mut mh2 = MuHash::new();
        mh2.add_element(&utxo_element_bytes_v5(&or2, &ext2, 1));
        mh2.add_element(&utxo_element_bytes_v5(&or1, &ext1, 1));

        let r1 = compute_state_root_v5(mh1.finalize(), 1);
        let r2 = compute_state_root_v5(mh2.finalize(), 1);
        assert_eq!(r1, r2, "v5 must be order-independent");
    }

    // ── Frozen test vectors (lock-in after first run) ──
    const EMPTY_V5_ROOT_HEX: &str =
        "d6010d0b3bcb671d52772d4ae5b0096d6677fd2ce1c3361688813094c0a33915";
    const V1_LIFTED_V5_ROOT_HEX: &str =
        "bc3187c07d5aa0ecf39e2a6cac4cc6e8970bb4f6420b1288e6ebc36ec9edf64e";

    #[test]
    fn lock_v5_state_root_vectors() {
        // Empty
        let mh_empty = MuHash::new();
        let r_empty = compute_state_root_v5(mh_empty.finalize(), 0);
        eprintln!("EMPTY_V5_ROOT = {}", hex::encode(r_empty));

        // 1 v1 UTXO lifted
        let outref = make_outref();
        let ext = ExtendedOutput::from_v1(&make_v1_output());
        let mut mh1 = MuHash::new();
        mh1.add_element(&utxo_element_bytes_v5(&outref, &ext, 1));
        let r_v1 = compute_state_root_v5(mh1.finalize(), 1);
        eprintln!("V1_LIFTED_V5_ROOT = {}", hex::encode(r_v1));

        if EMPTY_V5_ROOT_HEX != "REPLACE_AFTER_FIRST_RUN" {
            assert_eq!(
                hex::encode(r_empty),
                EMPTY_V5_ROOT_HEX,
                "empty v5 root changed"
            );
            assert_eq!(
                hex::encode(r_v1),
                V1_LIFTED_V5_ROOT_HEX,
                "v1 lifted v5 root changed"
            );
        }
    }
}
