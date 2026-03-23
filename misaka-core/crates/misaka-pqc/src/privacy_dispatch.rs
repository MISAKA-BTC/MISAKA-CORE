//! Privacy backend selection and verification dispatch — v4 target with
//! migration compatibility.
//!
//! The target path is UnifiedZKP. Some callers still carry legacy
//! ring-family plumbing while the runtime is being migrated. This module
//! keeps those call sites compiling without making ring signatures the
//! default path again.

use serde::{Deserialize, Serialize};

use crate::error::CryptoError;
use crate::pq_ring::{Poly, RingSig};
use crate::privacy_backend::{describe_privacy_scheme, PrivacyBackendFamily};
#[cfg(feature = "stark-stub")]
use crate::privacy_constraints::TransactionPrivacyConstraints;
#[cfg(feature = "stark-stub")]
use crate::privacy_statement::TransactionPublicStatement;
use crate::secret::ct_eq_32;
use crate::unified_zkp::{unified_verify, UnifiedMembershipProof, SCHEME_UNIFIED_ZKP};
use misaka_types::utxo::UtxoTransaction;

#[cfg(feature = "stark-stub")]
use crate::zkmp_builder::verify_zkmp_stub_tx;
#[cfg(feature = "stark-stub")]
use crate::{privacy_backend::zero_knowledge_stub_backend, stark_verify, StarkProof};

/// Call-site choice of privacy proof family.
///
/// `RingSignature` is kept as a compatibility preference only. It does not
/// make ring signatures the v4 default path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PrivacyBackendPreference {
    Auto,
    RingSignature,
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
pub struct RingFamilyVerifyInput<'a> {
    pub a_param: &'a Poly,
    pub ring_pubkeys: &'a [Poly],
    pub signing_digest: &'a [u8; 32],
    pub input_key_image: &'a [u8; 32],
    pub raw_ring_signature: &'a [u8],
    pub raw_ki_proof: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RingFamilyVerifyError {
    #[error("wrong backend family selected: expected ringSignature, got {0:?}")]
    WrongBackendFamily(PrivacyBackendFamily),
    #[error("legacy ring-family verification is not enabled in v4 main path")]
    UnsupportedLegacyPath,
    #[error("unsupported ring scheme: 0x{0:02x}")]
    UnsupportedScheme(u8),
    #[error("ring proof parse failed: {0}")]
    ProofParse(String),
    #[error("ring signature invalid: {0}")]
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
    // ── v4+ (Q-DAG-CT): always UnifiedZKP ──
    if tx.is_qdag() {
        return select_unified_zkp_backend(requested);
    }

    // ── v1-v3 (ring signature transactions) ──
    //
    // Route based on what the TX actually carries:
    // - If tx.zk_proof is present AND ZeroKnowledge was requested → ZK path
    //   (CompositeProof for production, STARK-stub for dev)
    // - Otherwise → RingSignature family (LRS/LogRing)
    //
    // CRITICAL: v1-v3 TXs MUST NOT silently fall through to UnifiedZKP.
    // UnifiedZKP requires SIS Merkle membership proofs that v1-v3 TXs
    // do not carry. Routing them there would cause verification failure
    // or — worse — skip ring signature verification entirely.
    match requested {
        PrivacyBackendPreference::ZeroKnowledge => {
            // Explicit ZK request for v1-v3: use CompositeProof or STARK-stub
            if tx.zk_proof.is_some() {
                select_zero_knowledge_backend(tx, requested)
            } else {
                Err(CryptoError::RingSignatureInvalid(
                    "ZeroKnowledge backend requested but tx.zk_proof is None (v1-v3 TX)".into(),
                ))
            }
        }
        PrivacyBackendPreference::Auto => {
            // Auto for v1-v3: route to RingSignature (matches tx structure)
            select_ring_signature_backend(tx, requested)
        }
        PrivacyBackendPreference::RingSignature => select_ring_signature_backend(tx, requested),
    }
}

/// Select ring signature backend for v1-v3 transactions.
fn select_ring_signature_backend(
    tx: &UtxoTransaction,
    requested: PrivacyBackendPreference,
) -> Result<SelectedPrivacyBackend, CryptoError> {
    let scheme_name = match tx.ring_scheme {
        0x01 => "LRS-v1",
        0x03 => "LogRing-v1",
        other => {
            return Err(CryptoError::RingSignatureInvalid(format!(
                "unknown ring scheme tag: 0x{:02x}",
                other,
            )));
        }
    };
    Ok(SelectedPrivacyBackend {
        requested,
        backend_family: PrivacyBackendFamily::RingSignature,
        scheme_tag: tx.ring_scheme,
        scheme_name: scheme_name.to_string(),
        selection_reason: format!("v1-v3 ring signature TX (scheme=0x{:02x})", tx.ring_scheme),
    })
}

pub fn verify_ring_family_input(
    selected: &SelectedPrivacyBackend,
    tx: &UtxoTransaction,
    _input_idx: usize,
    verify: &RingFamilyVerifyInput<'_>,
) -> Result<(), RingFamilyVerifyError> {
    if selected.backend_family != PrivacyBackendFamily::RingSignature {
        return Err(RingFamilyVerifyError::WrongBackendFamily(
            selected.backend_family,
        ));
    }

    let ring_size = verify.ring_pubkeys.len();

    match tx.ring_scheme {
        // ── LRS-v1 (0x01): standard lattice ring signature ──
        0x01 => {
            let sig = RingSig::from_bytes(verify.raw_ring_signature, ring_size)
                .map_err(|e| RingFamilyVerifyError::ProofParse(format!("LRS sig parse: {}", e)))?;

            // Key image in signature must match the tx input's key_image
            if !ct_eq_32(&sig.key_image, verify.input_key_image) {
                return Err(RingFamilyVerifyError::SpendIdentifierMismatch(
                    "sig.key_image != input.key_image",
                ));
            }

            // Ring signature verification
            crate::pq_ring::ring_verify(
                verify.a_param,
                verify.ring_pubkeys,
                verify.signing_digest,
                &sig,
            )
            .map_err(|e| RingFamilyVerifyError::SignatureInvalid(e.to_string()))?;

            // KI proof is REQUIRED for LRS — proves key_image derived from a ring member
            if verify.raw_ki_proof.is_empty() {
                return Err(RingFamilyVerifyError::MissingKeyImageProof);
            }
            let ki_proof =
                crate::ki_proof::KiProof::from_bytes(verify.raw_ki_proof).map_err(|e| {
                    RingFamilyVerifyError::KeyImageProofInvalid(format!("KI proof parse: {}", e))
                })?;

            // Try each ring member — one must validate
            let mut ki_valid = false;
            for pk in verify.ring_pubkeys {
                if crate::ki_proof::verify_key_image(
                    verify.a_param,
                    pk,
                    verify.input_key_image,
                    &ki_proof,
                )
                .is_ok()
                {
                    ki_valid = true;
                    break;
                }
            }
            if !ki_valid {
                return Err(RingFamilyVerifyError::KeyImageProofInvalid(
                    "KI proof did not validate against any ring member".into(),
                ));
            }

            Ok(())
        }

        // ── LogRing-v1 (0x03): packed lattice ring signature ──
        0x03 => {
            let sig = crate::packing::unpack_ring_sig_v2(verify.raw_ring_signature, ring_size)
                .map_err(|e| {
                    RingFamilyVerifyError::ProofParse(format!("LogRing sig unpack: {}", e))
                })?;

            // Key image in signature must match the tx input's key_image
            if !ct_eq_32(&sig.key_image, verify.input_key_image) {
                return Err(RingFamilyVerifyError::SpendIdentifierMismatch(
                    "sig.key_image != input.key_image",
                ));
            }

            // Ring signature verification (same algebraic check as LRS)
            crate::pq_ring::ring_verify(
                verify.a_param,
                verify.ring_pubkeys,
                verify.signing_digest,
                &sig,
            )
            .map_err(|e| RingFamilyVerifyError::SignatureInvalid(e.to_string()))?;

            // LogRing does not require separate KI proof — key_image is
            // algebraically bound inside the ring signature. If a KI proof
            // is provided anyway, validate it for defense in depth.
            if !verify.raw_ki_proof.is_empty() {
                let ki_proof =
                    crate::ki_proof::KiProof::from_bytes(verify.raw_ki_proof).map_err(|e| {
                        RingFamilyVerifyError::KeyImageProofInvalid(format!(
                            "optional KI proof parse: {}",
                            e
                        ))
                    })?;
                let mut ki_valid = false;
                for pk in verify.ring_pubkeys {
                    if crate::ki_proof::verify_key_image(
                        verify.a_param,
                        pk,
                        verify.input_key_image,
                        &ki_proof,
                    )
                    .is_ok()
                    {
                        ki_valid = true;
                        break;
                    }
                }
                if !ki_valid {
                    return Err(RingFamilyVerifyError::KeyImageProofInvalid(
                        "optional KI proof did not validate against any ring member".into(),
                    ));
                }
            }

            Ok(())
        }

        other => Err(RingFamilyVerifyError::UnsupportedScheme(other)),
    }
}

// ═══════════════════════════════════════════════════════════════
//  UnifiedZKP Backend (Q-DAG-CT production path)
// ═══════════════════════════════════════════════════════════════

fn select_unified_zkp_backend(
    requested: PrivacyBackendPreference,
) -> Result<SelectedPrivacyBackend, CryptoError> {
    let descriptor = describe_privacy_scheme(SCHEME_UNIFIED_ZKP).ok_or_else(|| {
        CryptoError::RingSignatureInvalid("UnifiedZKP backend descriptor not found".into())
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

#[cfg(feature = "stark-stub")]
fn select_zero_knowledge_backend(
    tx: &UtxoTransaction,
    requested: PrivacyBackendPreference,
) -> Result<SelectedPrivacyBackend, CryptoError> {
    let descriptor = zero_knowledge_stub_backend();
    Ok(SelectedPrivacyBackend {
        requested,
        backend_family: descriptor.backend_family,
        scheme_tag: tx.ring_scheme,
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
        CryptoError::RingSignatureInvalid(
            "zero-knowledge backend selected but tx.zk_proof is missing".into(),
        )
    })?;
    if carrier.backend_tag != crate::composite_proof::SCHEME_COMPOSITE {
        return Err(CryptoError::RingSignatureInvalid(format!(
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

#[cfg(feature = "stark-stub")]
pub fn read_zero_knowledge_proof_from_tx(tx: &UtxoTransaction) -> Result<StarkProof, CryptoError> {
    let carrier = tx.zk_proof.as_ref().ok_or_else(|| {
        CryptoError::RingSignatureInvalid(
            "zero-knowledge backend selected but tx.zk_proof is missing".into(),
        )
    })?;
    let expected_backend = zero_knowledge_stub_backend();
    if carrier.backend_tag != expected_backend.scheme_tag {
        return Err(CryptoError::RingSignatureInvalid(format!(
            "unexpected zero-knowledge backend tag: got 0x{:02x}, expected 0x{:02x}",
            carrier.backend_tag, expected_backend.scheme_tag
        )));
    }
    StarkProof::from_bytes(&carrier.proof_bytes)
}

#[cfg(feature = "stark-stub")]
pub fn verify_zero_knowledge_tx(
    selected: &SelectedPrivacyBackend,
    tx: &UtxoTransaction,
    constraints: &TransactionPrivacyConstraints,
) -> Result<(), CryptoError> {
    let proof = read_zero_knowledge_proof_from_tx(tx)?;
    verify_zero_knowledge_backend(selected, constraints, &proof)
}

#[cfg(feature = "stark-stub")]
pub fn verify_zero_knowledge_tx_with_statement(
    selected: &SelectedPrivacyBackend,
    tx: &UtxoTransaction,
    constraints: &TransactionPrivacyConstraints,
    statement: &TransactionPublicStatement,
) -> Result<(), CryptoError> {
    if selected.backend_family != PrivacyBackendFamily::ZeroKnowledge {
        return Err(CryptoError::RingSignatureInvalid(format!(
            "wrong backend family for zero-knowledge verification: {:?}",
            selected.backend_family
        )));
    }
    verify_zkmp_stub_tx(tx, constraints, statement)
}

#[cfg(feature = "stark-stub")]
pub fn verify_zero_knowledge_backend(
    selected: &SelectedPrivacyBackend,
    constraints: &TransactionPrivacyConstraints,
    proof: &StarkProof,
) -> Result<(), CryptoError> {
    if selected.backend_family != PrivacyBackendFamily::ZeroKnowledge {
        return Err(CryptoError::RingSignatureInvalid(format!(
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
        OutputRef, RingInput, TxOutput, TxType, UtxoTransaction, RING_SCHEME_LOGRING,
        RING_SCHEME_LRS, UTXO_TX_VERSION, UTXO_TX_VERSION_V3, UTXO_TX_VERSION_V4,
    };

    fn sample_qdag_tx() -> UtxoTransaction {
        UtxoTransaction {
            version: UTXO_TX_VERSION_V4,
            ring_scheme: SCHEME_UNIFIED_ZKP,
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
                    OutputRef {
                        tx_hash: [3u8; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [4u8; 32],
                        output_index: 0,
                    },
                ],
                ring_signature: vec![],
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
            ring_scheme: RING_SCHEME_LRS,
            tx_type: TxType::Transfer,
            inputs: vec![RingInput {
                ring_members: vec![OutputRef {
                    tx_hash: [1u8; 32],
                    output_index: 0,
                }],
                ring_signature: vec![],
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
        tx.ring_scheme = RING_SCHEME_LOGRING;
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
    fn test_v1_auto_routes_to_ring_signature() {
        let tx = sample_lrs_tx();
        let selected = select_privacy_backend(&tx, PrivacyBackendPreference::Auto).unwrap();
        assert_eq!(selected.backend_family, PrivacyBackendFamily::RingSignature);
        assert_eq!(selected.scheme_tag, RING_SCHEME_LRS);
    }

    #[test]
    fn test_v1_explicit_ring_routes_to_ring_signature() {
        let tx = sample_lrs_tx();
        let selected =
            select_privacy_backend(&tx, PrivacyBackendPreference::RingSignature).unwrap();
        assert_eq!(selected.backend_family, PrivacyBackendFamily::RingSignature);
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
    fn test_v3_auto_routes_to_ring_signature() {
        let tx = sample_logring_tx();
        let selected = select_privacy_backend(&tx, PrivacyBackendPreference::Auto).unwrap();
        assert_eq!(selected.backend_family, PrivacyBackendFamily::RingSignature);
        assert_eq!(selected.scheme_tag, RING_SCHEME_LOGRING);
        assert_eq!(selected.scheme_name, "LogRing-v1");
    }
}
