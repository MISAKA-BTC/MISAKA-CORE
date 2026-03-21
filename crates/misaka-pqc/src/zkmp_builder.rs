#![cfg(feature = "stark-stub")]

//! ZKMP builder seam for the target privacy path.
//!
//! This does not replace the current runtime path yet. It provides the first
//! builder-level API that produces:
//!
//! - target canonical nullifiers
//! - a proof carrier
//! - a binding digest over public statement + target nullifiers
//!
//! The current proof implementation still uses the `stark-stub` backend. The
//! important step here is the builder shape: nullifier generation and proof
//! generation happen together from the same witness bundle.

use crate::canonical_key_image_bound;
use crate::error::CryptoError;
use crate::pq_ring::Poly;
use crate::privacy_backend::{
    zero_knowledge_stub_backend, NullifierWitnessBindingModel, PrivacyBackendFamily,
    SpendIdentifierModel,
};
use crate::privacy_constraints::TransactionPrivacyConstraints;
use crate::privacy_dispatch::read_zero_knowledge_proof_from_tx;
use crate::privacy_statement::{MembershipTargetModel, TransactionPublicStatement};
use crate::stark_proof::{stark_prove, stark_verify, StarkProof, TxConstraints};
use misaka_types::utxo::{UtxoTransaction, ZeroKnowledgeProofCarrier};
use sha3::{Digest, Sha3_256};

pub const DST_ZKMP_BINDING_V1: &[u8] = b"MISAKA_ZKMP_BINDING_V1:";

#[derive(Debug, Clone)]
pub struct ZkmpInputWitness {
    pub secret_poly: Poly,
    pub spent_one_time_address: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct ZkmpBuildResult {
    pub target_nullifiers: Vec<[u8; 32]>,
    pub binding_digest: [u8; 32],
    pub proof: StarkProof,
    pub carrier: ZeroKnowledgeProofCarrier,
}

fn membership_target_tag(model: MembershipTargetModel) -> u8 {
    match model {
        MembershipTargetModel::RingCommitmentV1 => 1,
    }
}

fn validate_zkmp_target_statement(
    constraints: &TransactionPrivacyConstraints,
    statement: &TransactionPublicStatement,
    witness_len: usize,
) -> Result<(), CryptoError> {
    if statement.backend_family != PrivacyBackendFamily::ZeroKnowledge {
        return Err(CryptoError::RingSignatureInvalid(format!(
            "ZKMP builder expects zeroKnowledge public statement, got {:?}",
            statement.backend_family
        )));
    }
    if statement.target_spend_identifier_model != SpendIdentifierModel::CanonicalNullifier {
        return Err(CryptoError::RingSignatureInvalid(format!(
            "ZKMP builder expects CanonicalNullifier target, got {:?}",
            statement.target_spend_identifier_model
        )));
    }
    if statement.nullifier_witness_binding_model
        != NullifierWitnessBindingModel::WitnessOneTimeAddress
    {
        return Err(CryptoError::RingSignatureInvalid(format!(
            "ZKMP builder expects witnessOneTimeAddress binding, got {:?}",
            statement.nullifier_witness_binding_model
        )));
    }
    if constraints.input_count != witness_len {
        return Err(CryptoError::RingSignatureInvalid(format!(
            "ZKMP witness count mismatch: constraints={} witness={}",
            constraints.input_count, witness_len
        )));
    }
    if statement.membership_targets.len() != witness_len {
        return Err(CryptoError::RingSignatureInvalid(format!(
            "ZKMP membership target count mismatch: statement={} witness={}",
            statement.membership_targets.len(),
            witness_len
        )));
    }
    Ok(())
}

pub fn compute_zkmp_binding_digest(
    statement: &TransactionPublicStatement,
    target_nullifiers: &[[u8; 32]],
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(DST_ZKMP_BINDING_V1);
    h.update(statement.tx_hash);
    h.update(statement.signing_digest);
    h.update([statement.tx_type.to_byte()]);
    h.update([statement.ring_scheme]);
    h.update((statement.input_count as u32).to_le_bytes());
    h.update((statement.output_count as u32).to_le_bytes());
    h.update(statement.sum_inputs.to_le_bytes());
    h.update(statement.sum_outputs.to_le_bytes());
    h.update(statement.fee.to_le_bytes());
    h.update((statement.output_amounts.len() as u32).to_le_bytes());
    for amount in &statement.output_amounts {
        h.update(amount.to_le_bytes());
    }
    h.update((statement.membership_targets.len() as u32).to_le_bytes());
    for target in &statement.membership_targets {
        h.update([membership_target_tag(target.target_model)]);
        h.update((target.target_label.len() as u32).to_le_bytes());
        h.update(target.target_label.as_bytes());
        h.update(target.target_root);
        h.update((target.member_count as u32).to_le_bytes());
    }
    h.update((target_nullifiers.len() as u32).to_le_bytes());
    for nullifier in target_nullifiers {
        h.update(nullifier);
    }
    h.finalize().into()
}

pub fn build_zkmp_stub_constraints(
    constraints: &TransactionPrivacyConstraints,
    statement: &TransactionPublicStatement,
    target_nullifiers: &[[u8; 32]],
) -> Result<TxConstraints, CryptoError> {
    if constraints.input_count != target_nullifiers.len() {
        return Err(CryptoError::RingSignatureInvalid(format!(
            "ZKMP nullifier count mismatch: constraints={} target_nullifiers={}",
            constraints.input_count,
            target_nullifiers.len()
        )));
    }

    Ok(TxConstraints {
        tx_digest: compute_zkmp_binding_digest(statement, target_nullifiers),
        sum_inputs: constraints.sum_inputs,
        sum_outputs: constraints.sum_outputs,
        fee: constraints.fee,
        num_outputs: constraints.output_count,
        output_amounts: constraints.output_amounts.clone(),
        key_images: target_nullifiers.to_vec(),
    })
}

pub fn build_zkmp_stub(
    tx: &UtxoTransaction,
    constraints: &TransactionPrivacyConstraints,
    statement: &TransactionPublicStatement,
    witnesses: &[ZkmpInputWitness],
) -> Result<ZkmpBuildResult, CryptoError> {
    validate_zkmp_target_statement(constraints, statement, witnesses.len())?;

    let target_nullifiers: Vec<[u8; 32]> = witnesses
        .iter()
        .map(|w| canonical_key_image_bound(&w.secret_poly, &w.spent_one_time_address))
        .collect();

    let zkmp_constraints = build_zkmp_stub_constraints(constraints, statement, &target_nullifiers)?;
    let binding_digest = zkmp_constraints.tx_digest;
    let proof = stark_prove(&zkmp_constraints)?;
    let carrier = ZeroKnowledgeProofCarrier {
        backend_tag: zero_knowledge_stub_backend().scheme_tag,
        proof_bytes: proof.to_bytes(),
    };

    let _ = tx;

    Ok(ZkmpBuildResult {
        target_nullifiers,
        binding_digest,
        proof,
        carrier,
    })
}

pub fn verify_zkmp_stub(
    constraints: &TransactionPrivacyConstraints,
    statement: &TransactionPublicStatement,
    target_nullifiers: &[[u8; 32]],
    proof: &StarkProof,
) -> Result<(), CryptoError> {
    validate_zkmp_target_statement(constraints, statement, target_nullifiers.len())?;
    let zkmp_constraints = build_zkmp_stub_constraints(constraints, statement, target_nullifiers)?;
    stark_verify(&zkmp_constraints, proof)
}

pub fn attach_zkmp_carrier(tx: &mut UtxoTransaction, build: &ZkmpBuildResult) {
    tx.zk_proof = Some(build.carrier.clone());
}

pub fn apply_zkmp_target_nullifiers(
    tx: &mut UtxoTransaction,
    target_nullifiers: &[[u8; 32]],
) -> Result<(), CryptoError> {
    if tx.inputs.len() != target_nullifiers.len() {
        return Err(CryptoError::RingSignatureInvalid(format!(
            "ZKMP target nullifier count mismatch: tx_inputs={} target_nullifiers={}",
            tx.inputs.len(),
            target_nullifiers.len()
        )));
    }
    for (input, nullifier) in tx.inputs.iter_mut().zip(target_nullifiers.iter()) {
        input.key_image = *nullifier;
    }
    Ok(())
}

pub fn attach_zkmp_build_result(
    tx: &mut UtxoTransaction,
    build: &ZkmpBuildResult,
) -> Result<(), CryptoError> {
    apply_zkmp_target_nullifiers(tx, &build.target_nullifiers)?;
    attach_zkmp_carrier(tx, build);
    Ok(())
}

pub fn build_and_attach_zkmp_stub(
    tx: &mut UtxoTransaction,
    constraints: &TransactionPrivacyConstraints,
    statement: &TransactionPublicStatement,
    witnesses: &[ZkmpInputWitness],
) -> Result<ZkmpBuildResult, CryptoError> {
    let build = build_zkmp_stub(tx, constraints, statement, witnesses)?;
    attach_zkmp_build_result(tx, &build)?;
    Ok(build)
}

pub fn materialize_zkmp_stub_tx(
    tx: &mut UtxoTransaction,
    input_amounts: &[u64],
    ring_pubkeys: &[Vec<Poly>],
    witnesses: &[ZkmpInputWitness],
) -> Result<
    (
        TransactionPrivacyConstraints,
        TransactionPublicStatement,
        ZkmpBuildResult,
    ),
    CryptoError,
> {
    let target_nullifiers: Vec<[u8; 32]> = witnesses
        .iter()
        .map(|w| canonical_key_image_bound(&w.secret_poly, &w.spent_one_time_address))
        .collect();
    apply_zkmp_target_nullifiers(tx, &target_nullifiers)?;

    let constraints = TransactionPrivacyConstraints::from_tx_and_input_amounts_for_backend(
        tx,
        input_amounts,
        PrivacyBackendFamily::ZeroKnowledge,
    )?;
    let statement = TransactionPublicStatement::from_constraints_and_resolved_rings(
        tx,
        &constraints,
        ring_pubkeys,
        PrivacyBackendFamily::ZeroKnowledge,
    )?;
    let build = build_zkmp_stub(tx, &constraints, &statement, witnesses)?;
    if build.target_nullifiers != target_nullifiers {
        return Err(CryptoError::RingSignatureInvalid(
            "materialized ZKMP target nullifiers diverged from witness-derived nullifiers".into(),
        ));
    }
    attach_zkmp_carrier(tx, &build);

    Ok((constraints, statement, build))
}

pub fn verify_zkmp_stub_tx(
    tx: &UtxoTransaction,
    constraints: &TransactionPrivacyConstraints,
    statement: &TransactionPublicStatement,
) -> Result<(), CryptoError> {
    let target_nullifiers: Vec<[u8; 32]> = tx.inputs.iter().map(|input| input.key_image).collect();
    let proof = read_zero_knowledge_proof_from_tx(tx)?;
    verify_zkmp_stub(constraints, statement, &target_nullifiers, &proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_statement::InputMembershipTarget;
    use crate::{PrivacyBackendFamily, TransactionPublicStatement};
    use misaka_types::utxo::{
        OutputRef, RingInput, TxOutput, TxType, UtxoTransaction, RING_SCHEME_LOGRING,
        UTXO_TX_VERSION_V3,
    };

    fn sample_tx() -> UtxoTransaction {
        UtxoTransaction {
            version: UTXO_TX_VERSION_V3,
            ring_scheme: RING_SCHEME_LOGRING,
            tx_type: TxType::Transfer,
            inputs: vec![RingInput {
                ring_members: vec![
                    OutputRef {
                        tx_hash: [1u8; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [2u8; 32],
                        output_index: 0,
                    },
                ],
                ring_signature: vec![0xAA; 32],
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

    fn sample_statement(
        tx: &UtxoTransaction,
    ) -> (TransactionPrivacyConstraints, TransactionPublicStatement) {
        let constraints = TransactionPrivacyConstraints::from_tx_and_input_amounts_for_backend(
            tx,
            &[10_000],
            PrivacyBackendFamily::ZeroKnowledge,
        )
        .unwrap();
        let mut one = Poly::zero();
        one.coeffs[0] = 1;
        let rings = vec![vec![Poly::zero(), one]];
        let statement = TransactionPublicStatement::from_constraints_and_resolved_rings(
            tx,
            &constraints,
            &rings,
            PrivacyBackendFamily::ZeroKnowledge,
        )
        .unwrap();
        (constraints, statement)
    }

    #[test]
    fn test_build_zkmp_stub_produces_target_nullifier_and_carrier() {
        let tx = sample_tx();
        let (constraints, statement) = sample_statement(&tx);
        let mut secret = Poly::zero();
        secret.coeffs[0] = 7;
        let witness = ZkmpInputWitness {
            secret_poly: secret.clone(),
            spent_one_time_address: [0x11; 32],
        };

        let built = build_zkmp_stub(&tx, &constraints, &statement, &[witness]).unwrap();
        assert_eq!(built.target_nullifiers.len(), 1);
        assert_eq!(
            built.target_nullifiers[0],
            canonical_key_image_bound(&secret, &[0x11; 32])
        );
        assert_eq!(
            built.carrier.backend_tag,
            zero_knowledge_stub_backend().scheme_tag
        );
        let expected_constraints =
            build_zkmp_stub_constraints(&constraints, &statement, &built.target_nullifiers)
                .unwrap();
        assert_eq!(built.binding_digest, expected_constraints.tx_digest);
        assert_eq!(built.proof.constraint_digest, expected_constraints.digest());
    }

    #[test]
    fn test_verify_zkmp_stub_accepts_matching_statement() {
        let tx = sample_tx();
        let (constraints, statement) = sample_statement(&tx);
        let mut secret = Poly::zero();
        secret.coeffs[0] = 9;
        let witness = ZkmpInputWitness {
            secret_poly: secret,
            spent_one_time_address: [0x22; 32],
        };

        let built = build_zkmp_stub(&tx, &constraints, &statement, &[witness]).unwrap();
        verify_zkmp_stub(
            &constraints,
            &statement,
            &built.target_nullifiers,
            &built.proof,
        )
        .unwrap();
    }

    #[test]
    fn test_verify_zkmp_stub_rejects_tampered_membership_target() {
        let tx = sample_tx();
        let (constraints, mut statement) = sample_statement(&tx);
        let mut secret = Poly::zero();
        secret.coeffs[0] = 3;
        let witness = ZkmpInputWitness {
            secret_poly: secret,
            spent_one_time_address: [0x33; 32],
        };

        let built = build_zkmp_stub(&tx, &constraints, &statement, &[witness]).unwrap();
        statement.membership_targets[0] = InputMembershipTarget {
            target_root: [0x44; 32],
            ..statement.membership_targets[0].clone()
        };

        assert!(verify_zkmp_stub(
            &constraints,
            &statement,
            &built.target_nullifiers,
            &built.proof
        )
        .is_err());
    }

    #[test]
    fn test_attach_zkmp_carrier_sets_tx_proof() {
        let mut tx = sample_tx();
        let (constraints, statement) = sample_statement(&tx);
        let mut secret = Poly::zero();
        secret.coeffs[0] = 5;
        let witness = ZkmpInputWitness {
            secret_poly: secret,
            spent_one_time_address: [0x55; 32],
        };

        let built = build_zkmp_stub(&tx, &constraints, &statement, &[witness]).unwrap();
        attach_zkmp_carrier(&mut tx, &built);
        assert!(tx.zk_proof.is_some());
        assert_eq!(
            tx.zk_proof.as_ref().unwrap().proof_bytes,
            built.proof.to_bytes()
        );
    }

    #[test]
    fn test_build_and_attach_zkmp_stub_updates_tx_key_image() {
        let mut tx = sample_tx();
        let (constraints, statement) = sample_statement(&tx);
        let mut secret = Poly::zero();
        secret.coeffs[0] = 6;
        let witness = ZkmpInputWitness {
            secret_poly: secret,
            spent_one_time_address: [0x66; 32],
        };

        let built =
            build_and_attach_zkmp_stub(&mut tx, &constraints, &statement, &[witness]).unwrap();
        assert_eq!(tx.inputs[0].key_image, built.target_nullifiers[0]);
        assert_eq!(
            tx.zk_proof.as_ref().unwrap().proof_bytes,
            built.proof.to_bytes()
        );
    }

    #[test]
    fn test_verify_zkmp_stub_tx_accepts_attached_result() {
        let mut tx = sample_tx();
        let (constraints, statement) = sample_statement(&tx);
        let mut secret = Poly::zero();
        secret.coeffs[0] = 8;
        let witness = ZkmpInputWitness {
            secret_poly: secret,
            spent_one_time_address: [0x77; 32],
        };

        build_and_attach_zkmp_stub(&mut tx, &constraints, &statement, &[witness]).unwrap();
        verify_zkmp_stub_tx(&tx, &constraints, &statement).unwrap();
    }

    #[test]
    fn test_materialize_zkmp_stub_tx_rebuilds_statement_over_target_nullifier() {
        let mut tx = sample_tx();
        let mut secret = Poly::zero();
        secret.coeffs[0] = 4;
        let rings = vec![vec![Poly::zero(), {
            let mut one = Poly::zero();
            one.coeffs[0] = 1;
            one
        }]];
        let witness = ZkmpInputWitness {
            secret_poly: secret.clone(),
            spent_one_time_address: [0x88; 32],
        };

        let (constraints, statement, build) =
            materialize_zkmp_stub_tx(&mut tx, &[10_000], &rings, &[witness]).unwrap();

        assert_eq!(tx.inputs[0].key_image, build.target_nullifiers[0]);
        assert_eq!(constraints.signing_digest, tx.signing_digest());
        assert_eq!(statement.tx_hash, tx.tx_hash_without_zk_proof());
        verify_zkmp_stub_tx(&tx, &constraints, &statement).unwrap();
    }
}
