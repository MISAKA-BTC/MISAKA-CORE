//! Privacy backend selection and verification dispatch — ZKP-only (v4).
//!
//! Ring signature verification paths (LRS, LogRing, Chipmunk) have been
//! completely removed. All transaction verification goes through the
//! UnifiedZKP path (Σ-protocol + SIS Merkle + BDLOP committed path).

use serde::{Deserialize, Serialize};

use crate::error::CryptoError;
use crate::pq_ring::Poly;
use crate::privacy_backend::{describe_privacy_scheme, PrivacyBackendFamily};
use crate::unified_zkp::{UnifiedMembershipProof, unified_verify, SCHEME_UNIFIED_ZKP};
#[cfg(feature = "stark-stub")]
use crate::privacy_constraints::TransactionPrivacyConstraints;
#[cfg(feature = "stark-stub")]
use crate::privacy_statement::TransactionPublicStatement;
use misaka_types::utxo::UtxoTransaction;

#[cfg(feature = "stark-stub")]
use crate::zkmp_builder::verify_zkmp_stub_tx;
#[cfg(feature = "stark-stub")]
use crate::{stark_verify, privacy_backend::zero_knowledge_stub_backend, StarkProof};

/// Call-site choice of privacy proof family.
///
/// Post-purge: `RingSignature` is no longer supported and will return an error.
/// `Auto` and `ZeroKnowledge` both route to UnifiedZKP.
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

pub fn select_privacy_backend(
    tx: &UtxoTransaction,
    requested: PrivacyBackendPreference,
) -> Result<SelectedPrivacyBackend, CryptoError> {
    // v4+ always uses UnifiedZKP
    if tx.is_qdag() {
        return select_unified_zkp_backend(requested);
    }

    // For legacy tx versions, attempt ZKP path or STARK stub
    match requested {
        PrivacyBackendPreference::Auto | PrivacyBackendPreference::ZeroKnowledge => {
            // Try UnifiedZKP first, then STARK stub
            if let Ok(backend) = select_unified_zkp_backend(requested) {
                return Ok(backend);
            }
            select_zero_knowledge_backend(tx, requested)
        }
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
pub fn verify_unified_zkp_input(
    verify: &UnifiedZkpVerifyInput<'_>,
) -> Result<(), CryptoError> {
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
    _requested: PrivacyBackendPreference,
) -> Result<SelectedPrivacyBackend, CryptoError> {
    Err(CryptoError::RingSignatureInvalid(
        "zero-knowledge backend unavailable without stark-stub feature".into(),
    ))
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
        OutputRef, RingInput, TxOutput, TxType, UtxoTransaction, UTXO_TX_VERSION_V4,
    };

    fn sample_qdag_tx() -> UtxoTransaction {
        UtxoTransaction {
            version: UTXO_TX_VERSION_V4,
            ring_scheme: SCHEME_UNIFIED_ZKP,
            tx_type: TxType::Transfer,
            inputs: vec![RingInput {
                ring_members: vec![
                    OutputRef { tx_hash: [1u8; 32], output_index: 0 },
                    OutputRef { tx_hash: [2u8; 32], output_index: 0 },
                    OutputRef { tx_hash: [3u8; 32], output_index: 0 },
                    OutputRef { tx_hash: [4u8; 32], output_index: 0 },
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

    #[test]
    fn test_auto_selection_routes_to_zkp() {
        let tx = sample_qdag_tx();
        let selected = select_privacy_backend(&tx, PrivacyBackendPreference::Auto).unwrap();
        assert_eq!(selected.backend_family, PrivacyBackendFamily::ZeroKnowledge);
        assert_eq!(selected.scheme_name, "UnifiedZKP-v1");
    }

    #[test]
    fn test_explicit_zk_selection() {
        let tx = sample_qdag_tx();
        let selected = select_privacy_backend(&tx, PrivacyBackendPreference::ZeroKnowledge).unwrap();
        assert_eq!(selected.backend_family, PrivacyBackendFamily::ZeroKnowledge);
        assert_eq!(selected.scheme_tag, SCHEME_UNIFIED_ZKP);
    }
}
