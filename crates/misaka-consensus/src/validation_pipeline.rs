//! Validation pipeline metadata and shared stage helpers.
//!
//! This module does not change the current main path. Its job is to make the
//! block/tx validation order explicit and to centralize the shared
//! "resolved-statement consistency" checks that apply to both lattice ZKP
//! and ZeroKnowledge families.

use misaka_pqc::{
    tx_spend_semantics_for_backend, PrivacyBackendFamily, TransactionPrivacyConstraints,
};
use misaka_types::utxo::UtxoTransaction;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockValidationStage {
    Structural,
    NullifierConflict,
    RingMemberResolution,
    SameAmountRing,
    RingFamilyProof,
    AmountConservation,
    PrivacyStatementConsistency,
    ZeroKnowledgeProof,
    StateApply,
}

impl BlockValidationStage {
    pub const fn label(self) -> &'static str {
        match self {
            BlockValidationStage::Structural => "structural",
            BlockValidationStage::NullifierConflict => "nullifier_conflict",
            BlockValidationStage::RingMemberResolution => "ring_member_resolution",
            BlockValidationStage::SameAmountRing => "same_amount_ring",
            BlockValidationStage::RingFamilyProof => "ring_family_proof",
            BlockValidationStage::AmountConservation => "amount_conservation",
            BlockValidationStage::PrivacyStatementConsistency => "privacy_statement_consistency",
            BlockValidationStage::ZeroKnowledgeProof => "zero_knowledge_proof",
            BlockValidationStage::StateApply => "state_apply",
        }
    }
}

const LEGACY_PIPELINE: &[BlockValidationStage] = &[
    BlockValidationStage::Structural,
    BlockValidationStage::NullifierConflict,
    BlockValidationStage::RingMemberResolution,
    BlockValidationStage::SameAmountRing,
    BlockValidationStage::RingFamilyProof,
    BlockValidationStage::AmountConservation,
    BlockValidationStage::PrivacyStatementConsistency,
    BlockValidationStage::StateApply,
];

const ZERO_KNOWLEDGE_PIPELINE: &[BlockValidationStage] = &[
    BlockValidationStage::Structural,
    BlockValidationStage::NullifierConflict,
    BlockValidationStage::RingMemberResolution,
    BlockValidationStage::SameAmountRing,
    BlockValidationStage::RingFamilyProof,
    BlockValidationStage::AmountConservation,
    BlockValidationStage::PrivacyStatementConsistency,
    BlockValidationStage::ZeroKnowledgeProof,
    BlockValidationStage::StateApply,
];

pub const fn block_validation_pipeline(
    backend_family: PrivacyBackendFamily,
) -> &'static [BlockValidationStage] {
    match backend_family {
        // v10: all privacy transactions use ZeroKnowledge (ring sigs fully removed)
        PrivacyBackendFamily::ZeroKnowledge => ZERO_KNOWLEDGE_PIPELINE,
        PrivacyBackendFamily::Transparent => LEGACY_PIPELINE,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrivacyConstraintStageError {
    #[error("tx_hash mismatch")]
    TxHashMismatch,
    #[error("signing_digest mismatch")]
    SigningDigestMismatch,
    #[error("tx_type mismatch: constraints={constraints:?} tx={tx:?}")]
    TxTypeMismatch {
        constraints: misaka_types::utxo::TxType,
        tx: misaka_types::utxo::TxType,
    },
    #[error("proof_scheme mismatch: constraints=0x{constraints:02x} tx=0x{tx:02x}")]
    RingSchemeMismatch { constraints: u8, tx: u8 },
    #[error("input_count mismatch: constraints={constraints} tx={tx}")]
    InputCountMismatch { constraints: usize, tx: usize },
    #[error("output_count mismatch: constraints={constraints} tx={tx}")]
    OutputCountMismatch { constraints: usize, tx: usize },
    #[error("sum_inputs mismatch: constraints={constraints} resolved={resolved}")]
    SumInputsMismatch { constraints: u64, resolved: u64 },
    #[error("sum_outputs mismatch: constraints={constraints} resolved={resolved}")]
    SumOutputsMismatch { constraints: u64, resolved: u64 },
    #[error("fee mismatch: constraints={constraints} tx={tx}")]
    FeeMismatch { constraints: u64, tx: u64 },
    #[error("output_amounts mismatch")]
    OutputAmountsMismatch,
    #[error("spend_identifier_model mismatch: constraints={constraints:?} tx={tx:?}")]
    SpendIdentifierModelMismatch {
        constraints: misaka_pqc::SpendIdentifierModel,
        tx: misaka_pqc::SpendIdentifierModel,
    },
    #[error("spend_identifier_label mismatch")]
    SpendIdentifierLabelMismatch,
    #[error("spend_identifiers mismatch")]
    SpendIdentifiersMismatch,
    #[error("key_images mismatch")]
    KeyImagesMismatch,
}

pub fn validate_resolved_privacy_constraints(
    constraints: &TransactionPrivacyConstraints,
    tx: &UtxoTransaction,
    sum_input_amount: u64,
    sum_outputs: u64,
    backend_family: PrivacyBackendFamily,
) -> Result<(), PrivacyConstraintStageError> {
    let expected_tx_hash = match backend_family {
        PrivacyBackendFamily::ZeroKnowledge => tx.tx_hash_without_zk_proof(),
        PrivacyBackendFamily::Transparent => tx.tx_hash(),
    };
    if constraints.tx_hash != expected_tx_hash {
        return Err(PrivacyConstraintStageError::TxHashMismatch);
    }
    if constraints.signing_digest != tx.signing_digest() {
        return Err(PrivacyConstraintStageError::SigningDigestMismatch);
    }
    if constraints.tx_type != tx.tx_type {
        return Err(PrivacyConstraintStageError::TxTypeMismatch {
            constraints: constraints.tx_type,
            tx: tx.tx_type,
        });
    }
    if constraints.proof_scheme != tx.proof_scheme {
        return Err(PrivacyConstraintStageError::RingSchemeMismatch {
            constraints: constraints.proof_scheme,
            tx: tx.proof_scheme,
        });
    }
    if constraints.input_count != tx.inputs.len() {
        return Err(PrivacyConstraintStageError::InputCountMismatch {
            constraints: constraints.input_count,
            tx: tx.inputs.len(),
        });
    }
    if constraints.output_count != tx.outputs.len() {
        return Err(PrivacyConstraintStageError::OutputCountMismatch {
            constraints: constraints.output_count,
            tx: tx.outputs.len(),
        });
    }
    if constraints.sum_inputs != sum_input_amount {
        return Err(PrivacyConstraintStageError::SumInputsMismatch {
            constraints: constraints.sum_inputs,
            resolved: sum_input_amount,
        });
    }
    if constraints.sum_outputs != sum_outputs {
        return Err(PrivacyConstraintStageError::SumOutputsMismatch {
            constraints: constraints.sum_outputs,
            resolved: sum_outputs,
        });
    }
    if constraints.fee != tx.fee {
        return Err(PrivacyConstraintStageError::FeeMismatch {
            constraints: constraints.fee,
            tx: tx.fee,
        });
    }

    let expected_output_amounts: Vec<u64> = tx.outputs.iter().map(|o| o.amount).collect();
    if constraints.output_amounts != expected_output_amounts {
        return Err(PrivacyConstraintStageError::OutputAmountsMismatch);
    }

    let expected_spend_semantics = tx_spend_semantics_for_backend(tx, backend_family);
    if constraints.spend_identifier_model != expected_spend_semantics.spend_identifier_model {
        return Err(PrivacyConstraintStageError::SpendIdentifierModelMismatch {
            constraints: constraints.spend_identifier_model,
            tx: expected_spend_semantics.spend_identifier_model,
        });
    }
    if constraints.spend_identifier_label != expected_spend_semantics.spend_identifier_label {
        return Err(PrivacyConstraintStageError::SpendIdentifierLabelMismatch);
    }

    let expected_key_images: Vec<[u8; 32]> = tx.inputs.iter().map(|inp| inp.key_image).collect();
    if constraints.spend_identifiers != expected_key_images {
        return Err(PrivacyConstraintStageError::SpendIdentifiersMismatch);
    }
    if constraints.key_images != expected_key_images {
        return Err(PrivacyConstraintStageError::KeyImagesMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_pqc::PrivacyBackendFamily;
    use misaka_types::utxo::{
        OutputRef, TxInput, TxOutput, TxType, UtxoTransaction, PROOF_SCHEME_DEPRECATED_LOGRING,
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
    fn legacy_pipeline_has_no_zk_stage() {
        let stages = block_validation_pipeline(PrivacyBackendFamily::Transparent);
        assert_eq!(stages.first(), Some(&BlockValidationStage::Structural));
        assert_eq!(stages.last(), Some(&BlockValidationStage::StateApply));
        assert!(
            !stages.contains(&BlockValidationStage::ZeroKnowledgeProof),
            "ring path should not include explicit ZK proof stage"
        );
    }

    #[test]
    fn zero_knowledge_pipeline_inserts_zk_after_constraints() {
        let stages = block_validation_pipeline(PrivacyBackendFamily::ZeroKnowledge);
        assert_eq!(
            stages,
            &[
                BlockValidationStage::Structural,
                BlockValidationStage::NullifierConflict,
                BlockValidationStage::RingMemberResolution,
                BlockValidationStage::SameAmountRing,
                BlockValidationStage::RingFamilyProof,
                BlockValidationStage::AmountConservation,
                BlockValidationStage::PrivacyStatementConsistency,
                BlockValidationStage::ZeroKnowledgeProof,
                BlockValidationStage::StateApply,
            ]
        );
    }

    #[test]
    fn matching_constraints_pass_for_ring_path() {
        let tx = sample_tx();
        let constraints =
            misaka_pqc::TransactionPrivacyConstraints::from_tx_and_input_amounts(&tx, &[10_000])
                .unwrap();
        validate_resolved_privacy_constraints(
            &constraints,
            &tx,
            10_000,
            9_900,
            PrivacyBackendFamily::ZeroKnowledge,
        )
        .unwrap();
    }

    #[test]
    fn mismatched_tx_type_is_rejected() {
        let tx = sample_tx();
        let mut constraints =
            misaka_pqc::TransactionPrivacyConstraints::from_tx_and_input_amounts(&tx, &[10_000])
                .unwrap();
        constraints.tx_type = TxType::Faucet;

        let err = validate_resolved_privacy_constraints(
            &constraints,
            &tx,
            10_000,
            9_900,
            PrivacyBackendFamily::ZeroKnowledge,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            PrivacyConstraintStageError::TxTypeMismatch { .. }
        ));
    }
}
