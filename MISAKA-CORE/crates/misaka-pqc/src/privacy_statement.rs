//! Public transaction statement for future ZK-oriented privacy backends.
//!
//! This does not replace the current ring-signature path. It lifts the
//! transaction-level statement and resolved membership targets into a
//! first-class object so future `membership + nullifier + tx binding` proofs
//! can plug into the current runtime without redefining the whole tx model.

use crate::error::CryptoError;
use crate::pq_ring::Poly;
use crate::{
    target_spend_semantics_for_backend, NullifierWitnessBindingModel, PrivacyBackendFamily,
    SpendIdentifierModel, TransactionPrivacyConstraints,
};
use misaka_types::utxo::{TxType, UtxoTransaction};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

pub const MEMBERSHIP_TARGET_DST: &[u8] = b"MISAKA_RING_TARGET_V1:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum MembershipTargetModel {
    RingCommitmentV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InputMembershipTarget {
    pub target_model: MembershipTargetModel,
    pub target_label: String,
    pub target_root: [u8; 32],
    pub member_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionPublicStatement {
    pub tx_hash: [u8; 32],
    pub signing_digest: [u8; 32],
    pub tx_type: TxType,
    pub proof_scheme: u8,
    pub backend_family: PrivacyBackendFamily,
    pub input_count: usize,
    pub output_count: usize,
    pub sum_inputs: u64,
    pub sum_outputs: u64,
    pub fee: u64,
    pub output_amounts: Vec<u64>,
    pub spend_identifier_model: SpendIdentifierModel,
    pub spend_identifier_label: String,
    pub public_nullifiers: Vec<[u8; 32]>,
    pub target_spend_identifier_model: SpendIdentifierModel,
    pub target_spend_identifier_label: String,
    pub nullifier_witness_binding_model: NullifierWitnessBindingModel,
    pub nullifier_witness_binding_label: String,
    pub membership_targets: Vec<InputMembershipTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PublicStatementError {
    #[error("ring count mismatch: constraints={constraints} resolved={resolved}")]
    RingCountMismatch { constraints: usize, resolved: usize },
    #[error("tx_hash mismatch")]
    TxHashMismatch,
    #[error("signing_digest mismatch")]
    SigningDigestMismatch,
    #[error("tx_type mismatch: statement={statement:?} tx={tx:?}")]
    TxTypeMismatch { statement: TxType, tx: TxType },
    #[error("proof_scheme mismatch: statement=0x{statement:02x} tx=0x{tx:02x}")]
    RingSchemeMismatch { statement: u8, tx: u8 },
    #[error("backend_family mismatch: statement={statement:?} expected={expected:?}")]
    BackendFamilyMismatch {
        statement: PrivacyBackendFamily,
        expected: PrivacyBackendFamily,
    },
    #[error("input_count mismatch: statement={statement} tx={tx}")]
    InputCountMismatch { statement: usize, tx: usize },
    #[error("output_count mismatch: statement={statement} tx={tx}")]
    OutputCountMismatch { statement: usize, tx: usize },
    #[error("sum_inputs mismatch: statement={statement} constraints={constraints}")]
    SumInputsMismatch { statement: u64, constraints: u64 },
    #[error("sum_outputs mismatch: statement={statement} constraints={constraints}")]
    SumOutputsMismatch { statement: u64, constraints: u64 },
    #[error("fee mismatch: statement={statement} tx={tx}")]
    FeeMismatch { statement: u64, tx: u64 },
    #[error("output_amounts mismatch")]
    OutputAmountsMismatch,
    #[error(
        "spend_identifier_model mismatch: statement={statement:?} constraints={constraints:?}"
    )]
    SpendIdentifierModelMismatch {
        statement: SpendIdentifierModel,
        constraints: SpendIdentifierModel,
    },
    #[error("spend_identifier_label mismatch")]
    SpendIdentifierLabelMismatch,
    #[error("public_nullifiers mismatch")]
    PublicNullifiersMismatch,
    #[error(
        "target_spend_identifier_model mismatch: statement={statement:?} expected={expected:?}"
    )]
    TargetSpendIdentifierModelMismatch {
        statement: SpendIdentifierModel,
        expected: SpendIdentifierModel,
    },
    #[error("target_spend_identifier_label mismatch")]
    TargetSpendIdentifierLabelMismatch,
    #[error(
        "nullifier_witness_binding_model mismatch: statement={statement:?} expected={expected:?}"
    )]
    NullifierWitnessBindingModelMismatch {
        statement: NullifierWitnessBindingModel,
        expected: NullifierWitnessBindingModel,
    },
    #[error("nullifier_witness_binding_label mismatch")]
    NullifierWitnessBindingLabelMismatch,
    #[error("membership_targets count mismatch: statement={statement} tx_inputs={tx_inputs}")]
    MembershipTargetCountMismatch { statement: usize, tx_inputs: usize },
}

pub fn compute_membership_target(ring_pubkeys: &[Poly]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(MEMBERSHIP_TARGET_DST);
    h.update((ring_pubkeys.len() as u32).to_le_bytes());
    for pk in ring_pubkeys {
        h.update(pk.to_bytes());
    }
    h.finalize().into()
}

pub fn build_membership_targets(ring_pubkeys: &[Vec<Poly>]) -> Vec<InputMembershipTarget> {
    ring_pubkeys
        .iter()
        .map(|ring| InputMembershipTarget {
            target_model: MembershipTargetModel::RingCommitmentV1,
            target_label: "ringCommitment".to_string(),
            target_root: compute_membership_target(ring),
            member_count: ring.len(),
        })
        .collect()
}

impl TransactionPublicStatement {
    pub fn from_constraints_and_resolved_rings(
        tx: &UtxoTransaction,
        constraints: &TransactionPrivacyConstraints,
        ring_pubkeys: &[Vec<Poly>],
        backend_family: PrivacyBackendFamily,
    ) -> Result<Self, CryptoError> {
        if constraints.input_count != ring_pubkeys.len() {
            return Err(CryptoError::ProofInvalid(format!(
                "public statement ring count mismatch: constraints={} resolved={}",
                constraints.input_count,
                ring_pubkeys.len()
            )));
        }

        let target_spend_semantics = target_spend_semantics_for_backend(backend_family);

        Ok(Self {
            tx_hash: constraints.tx_hash,
            signing_digest: constraints.signing_digest,
            tx_type: tx.tx_type,
            proof_scheme: tx.proof_scheme,
            backend_family,
            input_count: tx.inputs.len(),
            output_count: tx.outputs.len(),
            sum_inputs: constraints.sum_inputs,
            sum_outputs: constraints.sum_outputs,
            fee: tx.fee,
            output_amounts: tx.outputs.iter().map(|o| o.amount).collect(),
            spend_identifier_model: constraints.spend_identifier_model,
            spend_identifier_label: constraints.spend_identifier_label.clone(),
            public_nullifiers: constraints.spend_identifiers.clone(),
            target_spend_identifier_model: target_spend_semantics.target_spend_identifier_model,
            target_spend_identifier_label: target_spend_semantics
                .target_spend_identifier_label
                .to_string(),
            nullifier_witness_binding_model: target_spend_semantics.nullifier_witness_binding_model,
            nullifier_witness_binding_label: target_spend_semantics
                .nullifier_witness_binding_label
                .to_string(),
            membership_targets: build_membership_targets(ring_pubkeys),
        })
    }
}

pub fn validate_public_statement(
    statement: &TransactionPublicStatement,
    tx: &UtxoTransaction,
    constraints: &TransactionPrivacyConstraints,
    expected_backend_family: PrivacyBackendFamily,
) -> Result<(), PublicStatementError> {
    let expected_tx_hash = match expected_backend_family {
        PrivacyBackendFamily::ZeroKnowledge => tx.tx_hash_without_zk_proof(),
        PrivacyBackendFamily::Transparent => tx.tx_hash(),
    };
    if statement.tx_hash != constraints.tx_hash || statement.tx_hash != expected_tx_hash {
        return Err(PublicStatementError::TxHashMismatch);
    }
    if statement.signing_digest != constraints.signing_digest {
        return Err(PublicStatementError::SigningDigestMismatch);
    }
    if statement.tx_type != tx.tx_type {
        return Err(PublicStatementError::TxTypeMismatch {
            statement: statement.tx_type,
            tx: tx.tx_type,
        });
    }
    if statement.proof_scheme != tx.proof_scheme {
        return Err(PublicStatementError::RingSchemeMismatch {
            statement: statement.proof_scheme,
            tx: tx.proof_scheme,
        });
    }
    if statement.backend_family != expected_backend_family {
        return Err(PublicStatementError::BackendFamilyMismatch {
            statement: statement.backend_family,
            expected: expected_backend_family,
        });
    }
    if statement.input_count != tx.inputs.len() {
        return Err(PublicStatementError::InputCountMismatch {
            statement: statement.input_count,
            tx: tx.inputs.len(),
        });
    }
    if statement.output_count != tx.outputs.len() {
        return Err(PublicStatementError::OutputCountMismatch {
            statement: statement.output_count,
            tx: tx.outputs.len(),
        });
    }
    if statement.sum_inputs != constraints.sum_inputs {
        return Err(PublicStatementError::SumInputsMismatch {
            statement: statement.sum_inputs,
            constraints: constraints.sum_inputs,
        });
    }
    if statement.sum_outputs != constraints.sum_outputs {
        return Err(PublicStatementError::SumOutputsMismatch {
            statement: statement.sum_outputs,
            constraints: constraints.sum_outputs,
        });
    }
    if statement.fee != tx.fee {
        return Err(PublicStatementError::FeeMismatch {
            statement: statement.fee,
            tx: tx.fee,
        });
    }
    let expected_output_amounts: Vec<u64> = tx.outputs.iter().map(|o| o.amount).collect();
    if statement.output_amounts != expected_output_amounts {
        return Err(PublicStatementError::OutputAmountsMismatch);
    }
    if statement.spend_identifier_model != constraints.spend_identifier_model {
        return Err(PublicStatementError::SpendIdentifierModelMismatch {
            statement: statement.spend_identifier_model,
            constraints: constraints.spend_identifier_model,
        });
    }
    if statement.spend_identifier_label != constraints.spend_identifier_label {
        return Err(PublicStatementError::SpendIdentifierLabelMismatch);
    }
    if statement.public_nullifiers != constraints.spend_identifiers {
        return Err(PublicStatementError::PublicNullifiersMismatch);
    }
    let target_spend_semantics = target_spend_semantics_for_backend(expected_backend_family);
    if statement.target_spend_identifier_model
        != target_spend_semantics.target_spend_identifier_model
    {
        return Err(PublicStatementError::TargetSpendIdentifierModelMismatch {
            statement: statement.target_spend_identifier_model,
            expected: target_spend_semantics.target_spend_identifier_model,
        });
    }
    if statement.target_spend_identifier_label
        != target_spend_semantics.target_spend_identifier_label
    {
        return Err(PublicStatementError::TargetSpendIdentifierLabelMismatch);
    }
    if statement.nullifier_witness_binding_model
        != target_spend_semantics.nullifier_witness_binding_model
    {
        return Err(PublicStatementError::NullifierWitnessBindingModelMismatch {
            statement: statement.nullifier_witness_binding_model,
            expected: target_spend_semantics.nullifier_witness_binding_model,
        });
    }
    if statement.nullifier_witness_binding_label
        != target_spend_semantics.nullifier_witness_binding_label
    {
        return Err(PublicStatementError::NullifierWitnessBindingLabelMismatch);
    }
    if statement.membership_targets.len() != tx.inputs.len() {
        return Err(PublicStatementError::MembershipTargetCountMismatch {
            statement: statement.membership_targets.len(),
            tx_inputs: tx.inputs.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_constraints::TransactionPrivacyConstraints;
    use misaka_types::utxo::{
        OutputRef, TxInput, TxOutput, UtxoTransaction, PROOF_SCHEME_DEPRECATED_LOGRING, UTXO_TX_VERSION_V3,
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
                ],
                proof: vec![0xAA; 32],
                key_image: [9u8; 32],
                ki_proof: vec![0xBB; 32],
            }],
            outputs: vec![TxOutput {
                amount: 9_900,
                one_time_address: [3u8; 32],
                pq_stealth: None,
                spending_pubkey: None,
            }],
            fee: 100,
            extra: vec![],
            zk_proof: None,
        }
    }

    #[test]
    fn test_compute_membership_target_deterministic() {
        let mut one = Poly::zero();
        one.coeffs[0] = 1;
        let ring = vec![Poly::zero(), one];
        let a = compute_membership_target(&ring);
        let b = compute_membership_target(&ring);
        assert_eq!(a, b);
    }

    #[test]
    fn test_public_statement_builds_from_constraints_and_rings() {
        let tx = sample_tx();
        let constraints = TransactionPrivacyConstraints::from_tx_and_input_amounts_for_backend(
            &tx,
            &[10_000],
            PrivacyBackendFamily::ZeroKnowledge,
        )
        .unwrap();
        let mut one = Poly::zero();
        one.coeffs[0] = 1;
        let rings = vec![vec![Poly::zero(), one]];
        let statement = TransactionPublicStatement::from_constraints_and_resolved_rings(
            &tx,
            &constraints,
            &rings,
            PrivacyBackendFamily::ZeroKnowledge,
        )
        .unwrap();

        assert_eq!(statement.public_nullifiers, vec![[9u8; 32]]);
        assert_eq!(
            statement.target_spend_identifier_model,
            SpendIdentifierModel::CanonicalNullifier
        );
        assert_eq!(
            statement.target_spend_identifier_label,
            "canonicalNullifier"
        );
        assert_eq!(
            statement.nullifier_witness_binding_model,
            NullifierWitnessBindingModel::WitnessOneTimeAddress
        );
        assert_eq!(
            statement.nullifier_witness_binding_label,
            "witnessOneTimeAddress"
        );
        assert_eq!(statement.membership_targets.len(), 1);
        assert_eq!(
            statement.membership_targets[0].target_model,
            MembershipTargetModel::RingCommitmentV1
        );
    }

    #[test]
    fn test_validate_public_statement_accepts_matching_inputs() {
        let tx = sample_tx();
        let constraints = TransactionPrivacyConstraints::from_tx_and_input_amounts_for_backend(
            &tx,
            &[10_000],
            PrivacyBackendFamily::ZeroKnowledge,
        )
        .unwrap();
        let mut one = Poly::zero();
        one.coeffs[0] = 1;
        let rings = vec![vec![Poly::zero(), one]];
        let statement = TransactionPublicStatement::from_constraints_and_resolved_rings(
            &tx,
            &constraints,
            &rings,
            PrivacyBackendFamily::ZeroKnowledge,
        )
        .unwrap();

        validate_public_statement(
            &statement,
            &tx,
            &constraints,
            PrivacyBackendFamily::ZeroKnowledge,
        )
        .unwrap();
    }

    #[test]
    fn test_validate_public_statement_rejects_backend_family_mismatch() {
        let tx = sample_tx();
        let constraints = TransactionPrivacyConstraints::from_tx_and_input_amounts_for_backend(
            &tx,
            &[10_000],
            PrivacyBackendFamily::ZeroKnowledge,
        )
        .unwrap();
        let mut one = Poly::zero();
        one.coeffs[0] = 1;
        let rings = vec![vec![Poly::zero(), one]];
        let statement = TransactionPublicStatement::from_constraints_and_resolved_rings(
            &tx,
            &constraints,
            &rings,
            PrivacyBackendFamily::ZeroKnowledge,
        )
        .unwrap();

        let err = validate_public_statement(
            &statement,
            &tx,
            &constraints,
            PrivacyBackendFamily::ZeroKnowledge,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PublicStatementError::BackendFamilyMismatch { .. }
        ));
    }

    #[test]
    fn test_validate_public_statement_rejects_target_spend_identifier_model_mismatch() {
        let tx = sample_tx();
        let constraints = TransactionPrivacyConstraints::from_tx_and_input_amounts_for_backend(
            &tx,
            &[10_000],
            PrivacyBackendFamily::ZeroKnowledge,
        )
        .unwrap();
        let mut one = Poly::zero();
        one.coeffs[0] = 1;
        let rings = vec![vec![Poly::zero(), one]];
        let mut statement = TransactionPublicStatement::from_constraints_and_resolved_rings(
            &tx,
            &constraints,
            &rings,
            PrivacyBackendFamily::ZeroKnowledge,
        )
        .unwrap();
        statement.target_spend_identifier_model = SpendIdentifierModel::LinkTag;

        let err = validate_public_statement(
            &statement,
            &tx,
            &constraints,
            PrivacyBackendFamily::ZeroKnowledge,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            PublicStatementError::TargetSpendIdentifierModelMismatch { .. }
        ));
    }
}
