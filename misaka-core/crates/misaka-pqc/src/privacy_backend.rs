//! Privacy backend descriptor — ZKP-only (v4).
//!
//! Ring signature descriptors (LRS, LogRing, Chipmunk) have been removed.
//! The only production privacy backend is UnifiedZKP-v1.

use crate::unified_zkp::SCHEME_UNIFIED_ZKP;
use misaka_types::utxo::UtxoTransaction;
use serde::{Deserialize, Serialize};

/// High-level privacy proof family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PrivacyBackendFamily {
    ZeroKnowledge,
    RingSignature,
}

/// Public model for the chain's spent-input detector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SpendIdentifierModel {
    CanonicalNullifier,
    LinkTag,
}

/// Private witness field that the canonical nullifier binds to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NullifierWitnessBindingModel {
    None,
    WitnessOneTimeAddress,
}

/// Small descriptor exposed through RPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyBackendDescriptor {
    pub scheme_tag: u8,
    pub scheme_name: &'static str,
    pub backend_family: PrivacyBackendFamily,
    pub anonymity_model: &'static str,
    pub spend_identifier_model: SpendIdentifierModel,
    pub tx_spend_identifier_label: &'static str,
    pub full_verifier_member_index_hidden: bool,
    pub zkp_migration_ready: bool,
    pub status_note: &'static str,
}

/// Per-transaction view of the currently active spend identifier semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionSpendSemantics {
    pub scheme_tag: u8,
    pub spend_identifier_model: SpendIdentifierModel,
    pub spend_identifier_label: String,
    pub spend_identifiers: Vec<[u8; 32]>,
}

/// Future-facing spend semantics target used by the public statement layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetSpendSemanticsDescriptor {
    pub target_spend_identifier_model: SpendIdentifierModel,
    pub target_spend_identifier_label: &'static str,
    pub nullifier_witness_binding_model: NullifierWitnessBindingModel,
    pub nullifier_witness_binding_label: &'static str,
}

/// The UnifiedZKP-v1 descriptor — compile-time constant.
///
/// This is the SINGLE production privacy backend for v4.
/// By making it a constant, `default_privacy_backend()` and
/// `tx_spend_semantics()` can never panic.
pub const UNIFIED_ZKP_DESCRIPTOR: PrivacyBackendDescriptor = PrivacyBackendDescriptor {
    scheme_tag: SCHEME_UNIFIED_ZKP,
    scheme_name: "UnifiedZKP-v1",
    backend_family: PrivacyBackendFamily::ZeroKnowledge,
    anonymity_model: "SIS Merkle + BDLOP committed path + algebraic nullifier (pk non-recoverable)",
    spend_identifier_model: SpendIdentifierModel::CanonicalNullifier,
    tx_spend_identifier_label: "nullifier",
    full_verifier_member_index_hidden: true,
    zkp_migration_ready: true,
    status_note: "Production ZK path. Verifier learns nothing about signer identity, leaf index, or Merkle path. O(log N) verification.",
};

/// Look up a privacy scheme descriptor by tag.
///
/// Post-purge: only UnifiedZKP-v1 (0x10) and optionally STARK-stub are recognized.
pub fn describe_privacy_scheme(scheme: u8) -> Option<PrivacyBackendDescriptor> {
    match scheme {
        SCHEME_UNIFIED_ZKP => Some(UNIFIED_ZKP_DESCRIPTOR),
        _ => None,
    }
}

pub fn tx_spend_semantics(tx: &UtxoTransaction) -> TransactionSpendSemantics {
    // All transactions now use canonical nullifier semantics.
    // key_images in UtxoTransaction carry nullifiers for v4 transactions.
    // Uses UNIFIED_ZKP_DESCRIPTOR const — no .expect() needed (zero-panic).
    TransactionSpendSemantics {
        scheme_tag: SCHEME_UNIFIED_ZKP,
        spend_identifier_model: UNIFIED_ZKP_DESCRIPTOR.spend_identifier_model,
        spend_identifier_label: UNIFIED_ZKP_DESCRIPTOR.tx_spend_identifier_label.to_string(),
        spend_identifiers: tx.inputs.iter().map(|inp| inp.key_image).collect(),
    }
}

pub fn tx_spend_semantics_for_backend(
    tx: &UtxoTransaction,
    backend_family: PrivacyBackendFamily,
) -> TransactionSpendSemantics {
    match backend_family {
        PrivacyBackendFamily::ZeroKnowledge => tx_spend_semantics(tx),
        // Compatibility branch for transitional callers that still materialize
        // ring-family statements while the runtime converges on UnifiedZKP.
        PrivacyBackendFamily::RingSignature => TransactionSpendSemantics {
            scheme_tag: tx.ring_scheme,
            spend_identifier_model: SpendIdentifierModel::LinkTag,
            spend_identifier_label: "linkTag".to_string(),
            spend_identifiers: tx.inputs.iter().map(|inp| inp.key_image).collect(),
        },
    }
}

pub fn target_spend_semantics_for_backend(
    backend_family: PrivacyBackendFamily,
) -> TargetSpendSemanticsDescriptor {
    match backend_family {
        PrivacyBackendFamily::ZeroKnowledge => TargetSpendSemanticsDescriptor {
            target_spend_identifier_model: SpendIdentifierModel::CanonicalNullifier,
            target_spend_identifier_label: "canonicalNullifier",
            nullifier_witness_binding_model: NullifierWitnessBindingModel::WitnessOneTimeAddress,
            nullifier_witness_binding_label: "witnessOneTimeAddress",
        },
        PrivacyBackendFamily::RingSignature => TargetSpendSemanticsDescriptor {
            target_spend_identifier_model: SpendIdentifierModel::LinkTag,
            target_spend_identifier_label: "linkTag",
            nullifier_witness_binding_model: NullifierWitnessBindingModel::None,
            nullifier_witness_binding_label: "none",
        },
    }
}

pub fn describe_transaction(tx: &UtxoTransaction) -> Option<PrivacyBackendDescriptor> {
    // v4 → UnifiedZKP; legacy versions also route to ZKP now
    Some(UNIFIED_ZKP_DESCRIPTOR)
}

pub fn describe_transaction_for_backend(
    tx: &UtxoTransaction,
    _backend_family: PrivacyBackendFamily,
) -> Option<PrivacyBackendDescriptor> {
    describe_transaction(tx)
}

/// Default privacy backend — UnifiedZKP-v1 (zero-panic const access).
pub fn default_privacy_backend() -> PrivacyBackendDescriptor {
    UNIFIED_ZKP_DESCRIPTOR
}

#[cfg(feature = "stark-stub")]
pub fn zero_knowledge_stub_backend() -> PrivacyBackendDescriptor {
    PrivacyBackendDescriptor {
        scheme_tag: 0xF1,
        scheme_name: "STARK-stub-v1",
        backend_family: PrivacyBackendFamily::ZeroKnowledge,
        anonymity_model: "Statement-level zero-knowledge stub over tx constraints",
        spend_identifier_model: SpendIdentifierModel::CanonicalNullifier,
        tx_spend_identifier_label: "canonicalNullifier",
        full_verifier_member_index_hidden: true,
        zkp_migration_ready: false,
        status_note: "Experimental ZKMP-facing seam only. NOT a production ZKP verifier.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_zkp_descriptor() {
        let d = describe_privacy_scheme(SCHEME_UNIFIED_ZKP).unwrap();
        assert_eq!(d.scheme_name, "UnifiedZKP-v1");
        assert_eq!(d.backend_family, PrivacyBackendFamily::ZeroKnowledge);
        assert_eq!(
            d.spend_identifier_model,
            SpendIdentifierModel::CanonicalNullifier
        );
        assert!(d.full_verifier_member_index_hidden);
        assert!(d.zkp_migration_ready);
    }

    #[test]
    fn test_unknown_scheme_returns_none() {
        assert!(describe_privacy_scheme(0x01).is_none()); // Old LRS
        assert!(describe_privacy_scheme(0x02).is_none()); // Old Chipmunk
        assert!(describe_privacy_scheme(0x03).is_none()); // Old LogRing
    }

    #[test]
    fn test_default_privacy_backend_is_zkp() {
        let d = default_privacy_backend();
        assert_eq!(d.backend_family, PrivacyBackendFamily::ZeroKnowledge);
        assert_eq!(d.scheme_name, "UnifiedZKP-v1");
    }

    #[test]
    fn test_target_spend_semantics_canonical_nullifier() {
        let target = target_spend_semantics_for_backend(PrivacyBackendFamily::ZeroKnowledge);
        assert_eq!(
            target.target_spend_identifier_model,
            SpendIdentifierModel::CanonicalNullifier
        );
    }
}
