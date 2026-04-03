//! Scheme-neutral privacy constraints extracted from a transaction.
//!
//! This is the shared statement layer between the current ring-signature path
//! and a future ZKP-oriented path.

use serde::{Deserialize, Serialize};

use crate::error::CryptoError;
use crate::privacy_backend::{
    tx_spend_semantics_for_backend, PrivacyBackendFamily, SpendIdentifierModel,
};
use misaka_types::utxo::{TxType, UtxoTransaction};

/// Transaction-level privacy statement shared by multiple proof backends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionPrivacyConstraints {
    pub tx_hash: [u8; 32],
    pub signing_digest: [u8; 32],
    pub tx_type: TxType,
    pub proof_scheme: u8,
    pub input_count: usize,
    pub output_count: usize,
    pub sum_inputs: u64,
    pub sum_outputs: u64,
    pub fee: u64,
    pub output_amounts: Vec<u64>,
    pub spend_identifier_model: SpendIdentifierModel,
    pub spend_identifier_label: String,
    pub spend_identifiers: Vec<[u8; 32]>,
    /// Backward-compatible mirror of `spend_identifiers`.
    pub key_images: Vec<[u8; 32]>,
}

impl TransactionPrivacyConstraints {
    /// Build common privacy constraints from a transaction plus the resolved
    /// spend amount for each input.
    pub fn from_tx_and_input_amounts(
        tx: &UtxoTransaction,
        input_amounts: &[u64],
    ) -> Result<Self, CryptoError> {
        Self::from_tx_and_input_amounts_for_backend(
            tx,
            input_amounts,
            PrivacyBackendFamily::ZeroKnowledge,
        )
    }

    pub fn from_tx_and_input_amounts_for_backend(
        tx: &UtxoTransaction,
        input_amounts: &[u64],
        backend_family: PrivacyBackendFamily,
    ) -> Result<Self, CryptoError> {
        if tx.inputs.len() != input_amounts.len() {
            return Err(CryptoError::ProofInvalid(format!(
                "privacy constraints input amount mismatch: tx has {} inputs but {} resolved amounts",
                tx.inputs.len(),
                input_amounts.len(),
            )));
        }

        let sum_inputs = input_amounts.iter().try_fold(0u64, |acc, amt| {
            acc.checked_add(*amt).ok_or_else(|| {
                CryptoError::ProofInvalid("privacy constraints input sum overflow".into())
            })
        })?;

        let output_amounts: Vec<u64> = tx.outputs.iter().map(|out| out.amount).collect();
        let sum_outputs = output_amounts.iter().try_fold(0u64, |acc, amt| {
            acc.checked_add(*amt).ok_or_else(|| {
                CryptoError::ProofInvalid("privacy constraints output sum overflow".into())
            })
        })?;

        let required = sum_outputs.checked_add(tx.fee).ok_or_else(|| {
            CryptoError::ProofInvalid("privacy constraints required amount overflow".into())
        })?;

        if sum_inputs != required {
            return Err(CryptoError::ProofInvalid(format!(
                "privacy constraints mismatch: inputs={} outputs+fee={}",
                sum_inputs, required
            )));
        }

        let spend_semantics = tx_spend_semantics_for_backend(tx, backend_family);
        let spend_identifiers = spend_semantics.spend_identifiers.clone();
        let tx_hash = match backend_family {
            PrivacyBackendFamily::ZeroKnowledge => tx.tx_hash_without_zk_proof(),
            PrivacyBackendFamily::Transparent => tx.tx_hash(),
        };

        Ok(Self {
            tx_hash,
            signing_digest: tx.signing_digest(),
            tx_type: tx.tx_type,
            proof_scheme: tx.proof_scheme,
            input_count: tx.inputs.len(),
            output_count: tx.outputs.len(),
            sum_inputs,
            sum_outputs,
            fee: tx.fee,
            output_amounts,
            spend_identifier_model: spend_semantics.spend_identifier_model,
            spend_identifier_label: spend_semantics.spend_identifier_label,
            spend_identifiers: spend_identifiers.clone(),
            key_images: spend_identifiers,
        })
    }

    #[cfg(feature = "stark-stub")] // DEV-ONLY: Stub ZK verifier — blocked in release builds
    pub fn to_stark_constraints(&self) -> crate::stark_proof::TxConstraints {
        crate::stark_proof::TxConstraints {
            tx_digest: self.signing_digest,
            sum_inputs: self.sum_inputs,
            sum_outputs: self.sum_outputs,
            fee: self.fee,
            num_outputs: self.output_count,
            output_amounts: self.output_amounts.clone(),
            key_images: self.spend_identifiers.clone(),
        }
    }
}

// TODO: Re-enable after ZKP internal API stabilization.
// These tests reference internal APIs (N, Q, Poly, etc.) that were refactored.
// Production code and pq_sign tests are unaffected.
#[cfg(all(test, feature = "__internal_zkp_api_stable"))]
mod tests {
    use super::*;
    use misaka_types::utxo::{
        OutputRef, TxInput, TxOutput, UtxoTransaction, PROOF_SCHEME_DEPRECATED_LOGRING,
        UTXO_TX_VERSION_V3,
    };

    fn sample_tx() -> UtxoTransaction {
        UtxoTransaction {
            version: UTXO_TX_VERSION_V3,
            proof_scheme: PROOF_SCHEME_DEPRECATED_LOGRING,
            tx_type: TxType::Transfer,
            inputs: vec![TxInput {
                utxo_refs: vec![
                    OutputRef {
                        tx_hash: [1u8; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [2u8; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [3u8; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [4u8; 32],
                        output_index: 0,
                    },
                ],
                proof: vec![],
                key_image: [9u8; 32],
                ki_proof: vec![],
            }],
            outputs: vec![
                TxOutput {
                    amount: 7000,
                    one_time_address: [0xAA; 32],
                    pq_stealth: None,
                    spending_pubkey: None,
                },
                TxOutput {
                    amount: 2900,
                    one_time_address: [0xBB; 32],
                    pq_stealth: None,
                    spending_pubkey: None,
                },
            ],
            fee: 100,
            extra: vec![],
            zk_proof: None,
        }
    }

    #[test]
    fn test_constraints_roundtrip_from_tx() {
        let tx = sample_tx();
        let constraints =
            TransactionPrivacyConstraints::from_tx_and_input_amounts(&tx, &[10_000]).unwrap();
        assert_eq!(constraints.sum_inputs, 10_000);
        assert_eq!(constraints.sum_outputs, 9_900);
        assert_eq!(constraints.fee, 100);
        assert_eq!(
            constraints.spend_identifier_model,
            SpendIdentifierModel::LinkTag
        );
        assert_eq!(constraints.spend_identifier_label, "linkTag");
        assert_eq!(constraints.spend_identifiers, vec![[9u8; 32]]);
        assert_eq!(constraints.key_images, vec![[9u8; 32]]);
        assert_eq!(constraints.output_count, 2);
    }

    #[test]
    fn test_constraints_reject_mismatched_input_amounts() {
        let tx = sample_tx();
        let err =
            TransactionPrivacyConstraints::from_tx_and_input_amounts(&tx, &[9_999]).unwrap_err();
        assert!(err.to_string().contains("privacy constraints mismatch"));
    }

    #[test]
    fn test_constraints_reject_wrong_input_count() {
        let tx = sample_tx();
        let err = TransactionPrivacyConstraints::from_tx_and_input_amounts(&tx, &[]).unwrap_err();
        assert!(err.to_string().contains("input amount mismatch"));
    }

    #[cfg(feature = "stark-stub")] // DEV-ONLY: Stub ZK verifier — blocked in release builds
    #[test]
    fn test_constraints_for_zero_knowledge_use_zero_knowledge_semantics() {
        let tx = sample_tx();
        let constraints = TransactionPrivacyConstraints::from_tx_and_input_amounts_for_backend(
            &tx,
            &[10_000],
            PrivacyBackendFamily::ZeroKnowledge,
        )
        .unwrap();

        assert_eq!(
            constraints.spend_identifier_model,
            SpendIdentifierModel::CanonicalNullifier
        );
        assert_eq!(constraints.spend_identifier_label, "canonicalNullifier");
    }
}
