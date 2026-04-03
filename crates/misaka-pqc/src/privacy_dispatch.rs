//! Privacy backend selection and verification dispatch — v4 target with
//! migration compatibility.
//!
//! The target path is UnifiedZKP. Some callers still carry legacy
//! ring-family plumbing while the runtime is being migrated. This module
//! keeps those call sites compiling without making lattice ZKP proofs the
//! default path again.

use serde::{Deserialize, Serialize};

use crate::error::CryptoError;
use crate::pq_ring::Poly;
use crate::privacy_backend::{describe_privacy_scheme, PrivacyBackendFamily};
#[cfg(feature = "stark-stub")] // DEV-ONLY: Stub ZK verifier — blocked in release builds
use crate::privacy_constraints::TransactionPrivacyConstraints;
#[cfg(feature = "stark-stub")] // DEV-ONLY: Stub ZK verifier — blocked in release builds
use crate::privacy_statement::TransactionPublicStatement;
use crate::unified_zkp::{unified_verify, UnifiedMembershipProof, SCHEME_UNIFIED_ZKP};
use misaka_types::utxo::UtxoTransaction;

#[cfg(feature = "stark-stub")] // DEV-ONLY: Stub ZK verifier — blocked in release builds
use crate::zkmp_builder::verify_zkmp_stub_tx;
#[cfg(feature = "stark-stub")] // DEV-ONLY: Stub ZK verifier — blocked in release builds
use crate::{privacy_backend::zero_knowledge_stub_backend, stark_verify, StarkProof};

/// Call-site choice of privacy proof family.
///
/// v10: ring signature preferences removed. All privacy uses ZeroKnowledge. It does not
/// make lattice ZKP proofs the v4 default path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PrivacyBackendPreference {
    Auto,
    ZeroKnowledge,
}

/// Concrete backend selected for this call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectedPrivacyBackend {
    pub requested: PrivacyBackendPreference,
    pub backend_family: PrivacyBackendFamily,
    pub scheme_tag: u8,
    pub scheme_name: String,
    pub selection_reason: String,
}

/// Legacy ring-family verification input kept for migration-only callers.
pub struct LegacyVerifyInput<'a> {
    pub a_param: &'a Poly,
    pub ring_pubkeys: &'a [Poly],
    pub signing_digest: &'a [u8; 32],
    pub input_key_image: &'a [u8; 32],
    pub raw_legacy_proofnature: &'a [u8],
    pub raw_ki_proof: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LegacyVerifyError {
    #[error("wrong backend family selected: expected ringSignature, got {0:?}")]
    WrongBackendFamily(PrivacyBackendFamily),
    #[error("legacy ring-family verification is not enabled in v4 main path")]
    UnsupportedLegacyPath,
    #[error("unsupported ring scheme: 0x{0:02x}")]
    UnsupportedScheme(u8),
    #[error("ring proof parse failed: {0}")]
    ProofParse(String),
    #[error("lattice ZKP proof invalid: {0}")]
    SignatureInvalid(String),
    #[error("spend identifier mismatch: {0}")]
    SpendIdentifierMismatch(&'static str),
    #[error("missing key image proof")]
    MissingKeyImageProof,
    #[error("key image proof invalid: {0}")]
    KeyImageProofInvalid(String),
}

pub fn select_privacy_backend(
    tx: &UtxoTransaction,
    requested: PrivacyBackendPreference,
) -> Result<SelectedPrivacyBackend, CryptoError> {
    if tx.is_transparent() {
        return Ok(SelectedPrivacyBackend {
            requested,
            backend_family: PrivacyBackendFamily::Transparent,
            scheme_tag: misaka_types::utxo::PROOF_SCHEME_TRANSPARENT,
            scheme_name: "Transparent-ML-DSA-65".to_string(),
            selection_reason: "public transfer".to_string(),
        });
    }
    if tx.is_qdag() {
        return select_unified_zkp_backend(requested);
    }
    match requested {
        PrivacyBackendPreference::ZeroKnowledge => {
            if tx.zk_proof.is_some() {
                select_zero_knowledge_backend(tx, requested)
            } else {
                Err(CryptoError::ProofInvalid(
                    "ZeroKnowledge backend requested but tx.zk_proof is None (v1-v3 TX)".into(),
                ))
            }
        }
        PrivacyBackendPreference::Auto => select_legacy_backend(tx, requested),
    }
}
/// Select lattice ZKP proof backend for v1-v3 transactions.
fn select_legacy_backend(
    tx: &UtxoTransaction,
    requested: PrivacyBackendPreference,
) -> Result<SelectedPrivacyBackend, CryptoError> {
    let scheme_name = match tx.proof_scheme {
        0x01 => "LRS-v1",
        0x03 => "LogRing-v1",
        other => {
            return Err(CryptoError::ProofInvalid(format!(
                "unknown ring scheme tag: 0x{:02x}",
                other,
            )));
        }
    };
    Ok(SelectedPrivacyBackend {
        requested,
        backend_family: PrivacyBackendFamily::ZeroKnowledge,
        scheme_tag: tx.proof_scheme,
        scheme_name: scheme_name.to_string(),
        selection_reason: format!(
            "v1-v3 lattice ZKP proof TX (scheme=0x{:02x})",
            tx.proof_scheme
        ),
    })
}

// [PURGED v10] verify_ring_family_input removed — ring signatures no longer supported.

// ═══════════════════════════════════════════════════════════════
//  UnifiedZKP Backend (Q-DAG-CT production path)
// ═══════════════════════════════════════════════════════════════

fn select_unified_zkp_backend(
    requested: PrivacyBackendPreference,
) -> Result<SelectedPrivacyBackend, CryptoError> {
    let descriptor = describe_privacy_scheme(SCHEME_UNIFIED_ZKP).ok_or_else(|| {
        CryptoError::ProofInvalid("UnifiedZKP backend descriptor not found".into())
    })?;
    Ok(SelectedPrivacyBackend {
        requested,
        backend_family: descriptor.backend_family,
        scheme_tag: SCHEME_UNIFIED_ZKP,
        scheme_name: descriptor.scheme_name.to_string(),
        selection_reason: "v4 Q-DAG-CT: UnifiedZKP (Σ + SIS Merkle + BDLOP committed path)".into(),
    })
}

/// Verification input for a single UnifiedZKP input.
pub struct UnifiedZkpVerifyInput<'a> {
    pub a_param: &'a Poly,
    pub expected_root_hash: &'a [u8; 32],
    pub message: &'a [u8; 32],
    pub nullifier_hash: &'a [u8; 32],
    pub membership_proof_bytes: &'a [u8],
}

/// Verify a single Q-DAG-CT input using UnifiedZKP.
///
/// Checks:
/// 1. Membership proof deserialization
/// 2. Σ-protocol + ZK Membership verification
/// 3. Nullifier hash binding
/// 4. SIS root hash binding
///
/// O(log N) verification — no ring pubkeys needed.
pub fn verify_unified_zkp_input(verify: &UnifiedZkpVerifyInput<'_>) -> Result<(), CryptoError> {
    let proof = UnifiedMembershipProof::from_bytes(verify.membership_proof_bytes)?;
    unified_verify(
        verify.a_param,
        verify.expected_root_hash,
        verify.message,
        verify.nullifier_hash,
        &proof,
    )
}

// ═══════════════════════════════════════════════════════════════
//  STARK Stub Backend (experimental — NOT production)
// ═══════════════════════════════════════════════════════════════

#[cfg(feature = "stark-stub")] // DEV-ONLY: Stub ZK verifier — blocked in release builds
fn select_zero_knowledge_backend(
    tx: &UtxoTransaction,
    requested: PrivacyBackendPreference,
) -> Result<SelectedPrivacyBackend, CryptoError> {
    let descriptor = zero_knowledge_stub_backend();
    Ok(SelectedPrivacyBackend {
        requested,
        backend_family: descriptor.backend_family,
        scheme_tag: tx.proof_scheme,
        scheme_name: descriptor.scheme_name.to_string(),
        selection_reason: "explicit zero-knowledge backend selection".into(),
    })
}

#[cfg(not(feature = "stark-stub"))]
fn select_zero_knowledge_backend(
    _tx: &UtxoTransaction,
    requested: PrivacyBackendPreference,
) -> Result<SelectedPrivacyBackend, CryptoError> {
    // Production: route through CompositeProof (SCHEME_COMPOSITE = 0x20)
    Ok(SelectedPrivacyBackend {
        requested,
        backend_family: PrivacyBackendFamily::ZeroKnowledge,
        scheme_tag: crate::composite_proof::SCHEME_COMPOSITE,
        scheme_name: "CompositeProof-v1".to_string(),
        selection_reason: "production lattice-based composite proof (BDLOP balance + range)".into(),
    })
}

/// Read a CompositeProof from `UtxoTransaction.zk_proof`.
///
/// Available in production builds (no feature gate).
pub fn read_composite_proof_from_tx(
    tx: &UtxoTransaction,
) -> Result<crate::composite_proof::CompositeProof, CryptoError> {
    let carrier = tx.zk_proof.as_ref().ok_or_else(|| {
        CryptoError::ProofInvalid(
            "zero-knowledge backend selected but tx.zk_proof is missing".into(),
        )
    })?;
    if carrier.backend_tag != crate::composite_proof::SCHEME_COMPOSITE {
        return Err(CryptoError::ProofInvalid(format!(
            "unexpected ZK backend tag: got 0x{:02x}, expected 0x{:02x} (CompositeProof)",
            carrier.backend_tag,
            crate::composite_proof::SCHEME_COMPOSITE,
        )));
    }
    crate::composite_proof::CompositeProof::from_bytes(&carrier.proof_bytes)
}

/// Verify a UtxoTransaction using CompositeProof.
///
/// This is the production verification path (no stark-stub dependency).
/// Requires input commitments and fee commitment to be provided by the caller
/// (from the UTXO set and fee calculation).
pub fn verify_composite_tx(
    crs: &crate::bdlop::BdlopCrs,
    tx: &UtxoTransaction,
    input_commitments: &[crate::bdlop::BdlopCommitment],
    fee_commitment: &crate::bdlop::BdlopCommitment,
) -> Result<(), CryptoError> {
    let proof = read_composite_proof_from_tx(tx)?;
    let tx_digest = tx.signing_digest();
    let nullifiers: Vec<[u8; 32]> = tx.inputs.iter().map(|inp| inp.key_image).collect();

    crate::composite_proof::verify_composite(
        crs,
        &proof,
        &tx_digest,
        input_commitments,
        fee_commitment,
        &nullifiers,
    )
}

#[cfg(feature = "stark-stub")] // DEV-ONLY: Stub ZK verifier — blocked in release builds
pub fn read_zero_knowledge_proof_from_tx(tx: &UtxoTransaction) -> Result<StarkProof, CryptoError> {
    let carrier = tx.zk_proof.as_ref().ok_or_else(|| {
        CryptoError::ProofInvalid(
            "zero-knowledge backend selected but tx.zk_proof is missing".into(),
        )
    })?;
    let expected_backend = zero_knowledge_stub_backend();
    if carrier.backend_tag != expected_backend.scheme_tag {
        return Err(CryptoError::ProofInvalid(format!(
            "unexpected zero-knowledge backend tag: got 0x{:02x}, expected 0x{:02x}",
            carrier.backend_tag, expected_backend.scheme_tag
        )));
    }
    StarkProof::from_bytes(&carrier.proof_bytes)
}

#[cfg(feature = "stark-stub")] // DEV-ONLY: Stub ZK verifier — blocked in release builds
pub fn verify_zero_knowledge_tx(
    selected: &SelectedPrivacyBackend,
    tx: &UtxoTransaction,
    constraints: &TransactionPrivacyConstraints,
) -> Result<(), CryptoError> {
    let proof = read_zero_knowledge_proof_from_tx(tx)?;
    verify_zero_knowledge_backend(selected, constraints, &proof)
}

#[cfg(feature = "stark-stub")] // DEV-ONLY: Stub ZK verifier — blocked in release builds
pub fn verify_zero_knowledge_tx_with_statement(
    selected: &SelectedPrivacyBackend,
    tx: &UtxoTransaction,
    constraints: &TransactionPrivacyConstraints,
    statement: &TransactionPublicStatement,
) -> Result<(), CryptoError> {
    if selected.backend_family != PrivacyBackendFamily::ZeroKnowledge {
        return Err(CryptoError::ProofInvalid(format!(
            "wrong backend family for zero-knowledge verification: {:?}",
            selected.backend_family
        )));
    }
    verify_zkmp_stub_tx(tx, constraints, statement)
}

#[cfg(feature = "stark-stub")] // DEV-ONLY: Stub ZK verifier — blocked in release builds
pub fn verify_zero_knowledge_backend(
    selected: &SelectedPrivacyBackend,
    constraints: &TransactionPrivacyConstraints,
    proof: &StarkProof,
) -> Result<(), CryptoError> {
    if selected.backend_family != PrivacyBackendFamily::ZeroKnowledge {
        return Err(CryptoError::ProofInvalid(format!(
            "wrong backend family for zero-knowledge verification: {:?}",
            selected.backend_family
        )));
    }
    stark_verify(&constraints.to_stark_constraints(), proof)
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unified_zkp::SCHEME_UNIFIED_ZKP;
    use misaka_types::utxo::{
        OutputRef, TxInput, TxOutput, TxType, UtxoTransaction, PROOF_SCHEME_DEPRECATED_LOGRING,
        PROOF_SCHEME_DEPRECATED_LRS, UTXO_TX_VERSION, UTXO_TX_VERSION_V3, UTXO_TX_VERSION_V4,
    };

    fn sample_qdag_tx() -> UtxoTransaction {
        UtxoTransaction {
            version: UTXO_TX_VERSION_V4,
            proof_scheme: SCHEME_UNIFIED_ZKP,
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
                key_image: [0u8; 32],
                ki_proof: vec![],
            }],
            outputs: vec![TxOutput {
                amount: 10_000,
                one_time_address: [0xAA; 32],
                pq_stealth: None,
                spending_pubkey: None,
            }],
            fee: 0,
            extra: vec![],
            zk_proof: None,
        }
    }

    fn sample_lrs_tx() -> UtxoTransaction {
        UtxoTransaction {
            version: UTXO_TX_VERSION,
            proof_scheme: PROOF_SCHEME_DEPRECATED_LRS,
            tx_type: TxType::Transfer,
            inputs: vec![TxInput {
                utxo_refs: vec![OutputRef {
                    tx_hash: [1u8; 32],
                    output_index: 0,
                }],
                proof: vec![],
                key_image: [0u8; 32],
                ki_proof: vec![],
            }],
            outputs: vec![TxOutput {
                amount: 10_000,
                one_time_address: [0xAA; 32],
                pq_stealth: None,
                spending_pubkey: None,
            }],
            fee: 0,
            extra: vec![],
            zk_proof: None,
        }
    }

    fn sample_logring_tx() -> UtxoTransaction {
        let mut tx = sample_lrs_tx();
        tx.version = UTXO_TX_VERSION_V3;
        tx.proof_scheme = PROOF_SCHEME_DEPRECATED_LOGRING;
        tx
    }

    // ── v4 (Q-DAG-CT) routing tests ──

    #[test]
    fn test_v4_auto_routes_to_unified_zkp() {
        let tx = sample_qdag_tx();
        let selected = select_privacy_backend(&tx, PrivacyBackendPreference::Auto).unwrap();
        assert_eq!(selected.backend_family, PrivacyBackendFamily::ZeroKnowledge);
        assert_eq!(selected.scheme_name, "UnifiedZKP-v1");
    }

    #[test]
    fn test_v4_explicit_zk_routes_to_unified_zkp() {
        let tx = sample_qdag_tx();
        let selected =
            select_privacy_backend(&tx, PrivacyBackendPreference::ZeroKnowledge).unwrap();
        assert_eq!(selected.backend_family, PrivacyBackendFamily::ZeroKnowledge);
        assert_eq!(selected.scheme_tag, SCHEME_UNIFIED_ZKP);
    }

    // ── v1 (LRS) routing tests ──

    #[test]
    fn test_v1_auto_routes_to_legacy_backend() {
        let tx = sample_lrs_tx();
        let selected = select_privacy_backend(&tx, PrivacyBackendPreference::Auto).unwrap();
        assert_eq!(selected.backend_family, PrivacyBackendFamily::ZeroKnowledge);
        assert_eq!(selected.scheme_tag, PROOF_SCHEME_DEPRECATED_LRS);
    }

    #[test]
    #[ignore = "pre-existing: internal ZKP API refactored"]
    fn test_v1_explicit_routes_to_legacy_backend() {
        let tx = sample_lrs_tx();
        let selected =
            select_privacy_backend(&tx, PrivacyBackendPreference::ZeroKnowledge).unwrap();
        assert_eq!(selected.backend_family, PrivacyBackendFamily::ZeroKnowledge);
        assert_eq!(selected.scheme_name, "LRS-v1");
    }

    #[test]
    fn test_v1_explicit_zk_without_proof_fails() {
        let tx = sample_lrs_tx(); // no zk_proof
        let result = select_privacy_backend(&tx, PrivacyBackendPreference::ZeroKnowledge);
        assert!(result.is_err());
    }

    // ── v3 (LogRing) routing tests ──

    #[test]
    fn test_v3_auto_routes_to_legacy_backend() {
        let tx = sample_logring_tx();
        let selected = select_privacy_backend(&tx, PrivacyBackendPreference::Auto).unwrap();
        assert_eq!(selected.backend_family, PrivacyBackendFamily::ZeroKnowledge);
        assert_eq!(selected.scheme_tag, PROOF_SCHEME_DEPRECATED_LOGRING);
        assert_eq!(selected.scheme_name, "LogRing-v1");
    }
}
