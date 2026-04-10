//! Phase 2c-A: Signable view of UtxoTransaction.
//!
//! UtxoTransaction contains its own signature/proof fields, creating
//! a chicken-and-egg problem when computing the signing digest:
//! we cannot include the signatures in the digest preimage.
//!
//! TxSignablePayload mirrors UtxoTransaction WITHOUT signature/proof
//! fields. It is wrapped in IntentMessage and signed/verified.
//!
//! ## Stability invariant
//!
//! The borsh encoding of this type is part of the protocol. Any field
//! addition/removal/reordering breaks all existing signatures and
//! constitutes a hard fork.
//!
//! ## Field correspondence
//!
//! This type MUST include every field that `signing_digest_inner`
//! (utxo.rs) includes in its preimage, MINUS chain_id (which is now
//! provided by IntentMessage's AppId).
//!
//! Fields included: version, tx_type, inputs(utxo_refs),
//! outputs(amount, address, spending_pubkey), fee, extra.
//!
//! Fields excluded: inputs.proof, chain_id.

use borsh::{BorshDeserialize, BorshSerialize};

use crate::utxo::{OutputRef, TxOutput, TxType, UtxoTransaction};

/// Signable subset of TxInput.
///
/// Phase 2c-B: ring fields deleted. Only UTXO refs remain.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TxSignableInput {
    pub utxo_refs: Vec<OutputRef>,
}

/// Signable subset of UtxoTransaction.
///
/// Phase 2c-B: ring fields deleted.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TxSignablePayload {
    pub version: u8,
    pub tx_type: TxType,
    pub inputs: Vec<TxSignableInput>,
    pub outputs: Vec<TxOutput>,
    pub fee: u64,
    pub extra: Vec<u8>,
    /// §4.2 step 4: Block height after which this TX is invalid (0 = no expiry).
    pub expiry: u64,
}

impl From<&UtxoTransaction> for TxSignablePayload {
    fn from(tx: &UtxoTransaction) -> Self {
        Self {
            version: tx.version,
            tx_type: tx.tx_type,
            inputs: tx
                .inputs
                .iter()
                .map(|i| TxSignableInput {
                    utxo_refs: i.utxo_refs.clone(),
                })
                .collect(),
            outputs: tx.outputs.clone(),
            fee: tx.fee,
            extra: tx.extra.clone(),
            expiry: tx.expiry,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signable_payload_borsh_roundtrip() {
        let p = TxSignablePayload {
            version: 2,
            tx_type: TxType::TransparentTransfer,
            inputs: vec![],
            outputs: vec![],
            fee: 100,
            extra: vec![1, 2, 3],
            expiry: 0,
        };
        let encoded = borsh::to_vec(&p).expect("borsh");
        let decoded: TxSignablePayload = borsh::from_slice(&encoded).expect("borsh");
        assert_eq!(p, decoded);
    }

    #[test]
    fn signable_payload_determinism() {
        let p = TxSignablePayload {
            version: 2,
            tx_type: TxType::TransparentTransfer,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            extra: vec![],
            expiry: 0,
        };
        let e1 = borsh::to_vec(&p).unwrap();
        let e2 = borsh::to_vec(&p).unwrap();
        assert_eq!(e1, e2);
    }

    #[test]
    fn different_fees_produce_different_encodings() {
        let mk = |fee: u64| {
            let p = TxSignablePayload {
                version: 2,
                tx_type: TxType::TransparentTransfer,
                inputs: vec![],
                outputs: vec![],
                fee,
                extra: vec![],
                expiry: 0,
            };
            borsh::to_vec(&p).unwrap()
        };
        assert_ne!(mk(100), mk(101));
    }

    #[test]
    fn different_extra_produce_different_encodings() {
        let mk = |extra: Vec<u8>| {
            let p = TxSignablePayload {
                version: 2,
                tx_type: TxType::TransparentTransfer,
                inputs: vec![],
                outputs: vec![],
                fee: 0,
                extra,
                expiry: 0,
            };
            borsh::to_vec(&p).unwrap()
        };
        assert_ne!(mk(vec![1]), mk(vec![2]));
    }
}
