//! MISAKA Network Post-Quantum Cryptography — ZKP-Only Architecture (v4).
//!
//! # Architecture (v4: Ring Signature Purge Complete)
//!
//! All ring signature schemes (LogRing, LRS, ChipmunkRing) have been removed.
//! The privacy model is now exclusively:
//!
//! - **Output-bound Nullifier**: deterministic, ring-independent double-spend prevention
//! - **Confidential Commitment**: BDLOP lattice Pedersen over R_q
//! - **FCMP / UnifiedZKP**: Σ-protocol + SIS Merkle + BDLOP committed path
//!   with O(log N) verification and pk non-recoverable

pub mod error;
pub mod ki_proof;
pub mod ntt;
pub mod output_recovery;
pub mod packing;
pub mod pq_kem;
pub mod pq_ring;
pub mod pq_sign;
// Legacy stealth remains required by the current wallet/output recovery path.
pub mod pq_stealth;
pub mod tx_codec;

// ── Privacy dispatch (ZKP-only) ──
pub mod privacy_backend;
pub mod privacy_constraints;
pub mod privacy_dispatch;
pub mod privacy_statement;

#[cfg(feature = "stark-stub")]
pub mod stark_proof;
#[cfg(feature = "stark-stub")]
pub mod zkmp_builder;

#[cfg(feature = "stealth-v2")]
pub mod stealth_v2;

// ── Q-DAG-CT Foundation (Phase 1.1) ──
pub mod secret;
pub mod transcript;
pub mod bdlop;

// ── Q-DAG-CT ZK Core (Phase 1.2) ──
pub mod nullifier;
pub mod range_proof;
pub mod membership;
pub mod unified_zkp;

// ── Q-DAG-CT Transaction Layer (Phase 1.3) ──
pub mod zkp_types;
pub mod privacy;
pub mod confidential_fee;
pub mod qdag_tx;
pub mod confidential_stealth;

// ── Canonical Key Image (ring-independent, used by nullifier migration) ──
pub mod canonical_ki;

// ── Cryptographic Type System (Phase 1.1: compile-time secret/public separation) ──
pub mod crypto_types;

// ── Verified Transaction Envelope (Phase 2.1: state-update protection) ──
pub mod verified_envelope;

// ═══════════════════════════════════════════════════════════════
//  Re-exports
// ═══════════════════════════════════════════════════════════════

pub use error::CryptoError;
pub use ki_proof::{
    canonical_strong_ki, compute_ki_poly, hash_to_poly, ki_poly_to_nullifier, prove_key_image,
    verify_key_image, verify_key_image_proof, KiProof, KI_PROOF_SIZE,
};
pub use output_recovery::OutputRecovery;
pub use packing::{
    pack_ring_sig, pack_ring_sig_v2, unpack_ring_sig, unpack_ring_sig_v2, PACKED_RESPONSE_SIZE,
};
pub use pq_kem::{
    MlKemCiphertext, MlKemKeypair, MlKemPublicKey, MlKemSecretKey, MlKemSharedSecret,
};
pub use pq_ring::{
    compute_key_image, derive_public_param, ring_sign, ring_verify, Poly, RingSig, SpendingKeypair,
    DEFAULT_A_SEED,
};
pub use pq_sign::{MlDsaKeypair, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
pub use pq_stealth::{create_stealth_output, RecoveredOutput, StealthOutput, StealthScanner};
pub use tx_codec::{decode_transaction, encode_transaction, wire_size};

pub use canonical_ki::{canonical_key_image, canonical_key_image_bound, CANONICAL_KI_DST};

// ── Cryptographic Type System re-exports ──
pub use crypto_types::{
    PublicNullifier, CommitmentHash, CommittedLeaf, AnonymityRoot, TxDigest,
    SecretWitness, SharedSecret, VerifiedNullifier,
};

pub use verified_envelope::{
    VerifiedTransactionEnvelope, TxVerificationError, verify_and_seal,
};

pub use privacy_backend::{
    default_privacy_backend, describe_privacy_scheme, describe_transaction,
    describe_transaction_for_backend, target_spend_semantics_for_backend, tx_spend_semantics,
    tx_spend_semantics_for_backend, NullifierWitnessBindingModel, PrivacyBackendDescriptor,
    PrivacyBackendFamily, SpendIdentifierModel, TargetSpendSemanticsDescriptor,
    TransactionSpendSemantics,
};
pub use privacy_constraints::TransactionPrivacyConstraints;
#[cfg(feature = "stark-stub")]
pub use privacy_dispatch::{
    read_zero_knowledge_proof_from_tx, verify_zero_knowledge_backend, verify_zero_knowledge_tx,
    verify_zero_knowledge_tx_with_statement,
};
pub use privacy_dispatch::{
    select_privacy_backend, verify_ring_family_input, verify_unified_zkp_input,
    PrivacyBackendPreference, RingFamilyVerifyError, RingFamilyVerifyInput,
    SelectedPrivacyBackend, UnifiedZkpVerifyInput,
};
pub use privacy_statement::{
    build_membership_targets, compute_membership_target, validate_public_statement,
    InputMembershipTarget, MembershipTargetModel, PublicStatementError, TransactionPublicStatement,
    MEMBERSHIP_TARGET_DST,
};

#[cfg(feature = "stark-stub")]
pub use stark_proof::{stark_prove, stark_verify, StarkProof, TxConstraints, STARK_PROOF_VERSION};
#[cfg(feature = "stark-stub")]
pub use zkmp_builder::{
    apply_zkmp_target_nullifiers, attach_zkmp_build_result, attach_zkmp_carrier,
    build_and_attach_zkmp_stub, build_zkmp_stub, build_zkmp_stub_constraints,
    compute_zkmp_binding_digest, materialize_zkmp_stub_tx, verify_zkmp_stub, verify_zkmp_stub_tx,
    ZkmpBuildResult, ZkmpInputWitness, DST_ZKMP_BINDING_V1,
};

#[cfg(feature = "stealth-v2")]
pub use stealth_v2::{
    create_stealth_v2, RecoveredOutputV2, StealthPayloadV2, StealthScannerV2, STEALTH_V2_TAG,
};

pub use secret::{SecretPoly, SecureBuffer, SecretKey32, ZeroizeGuard};
pub use transcript::{TranscriptBuilder, merkle_node_hash, domain};
pub use bdlop::{
    BdlopCrs, BdlopCommitment, BlindingFactor, BalanceExcessProof,
    compute_balance_diff, verify_balance_with_excess, BDLOP_CRS_SEED,
};

pub use nullifier::{OutputId, NullifierProof, compute_nullifier, verify_nullifier, canonical_nullifier_hash};
pub use range_proof::{RangeProof, prove_range, verify_range, RANGE_BITS};
pub use membership::{
    SisMerkleCrs, ZkMembershipProofV2,
    sis_leaf, compute_sis_root, sis_root_hash,
    prove_membership_v2, verify_membership_v2,
};
pub use unified_zkp::{
    UnifiedMembershipProof, unified_prove, unified_verify, compute_merkle_root,
    SCHEME_UNIFIED_ZKP, ZKP_MIN_RING_SIZE, ZKP_MAX_RING_SIZE,
};

pub use zkp_types::{
    PublicTxStatement, InputPublicInstance, PrivateTxWitness,
    MembershipInstance, MembershipWitness,
    NullifierInstance, NullifierWitness,
    RangeInstance, RangeWitness,
};
pub use privacy::{OneTimeAddress, TxPaddingPolicy, PrivacyMode, ScanConfig};
pub use confidential_fee::{
    ConfidentialFee, FeeMinimumProof,
    create_confidential_fee, verify_confidential_fee, MIN_FEE, MAX_FEE,
};
pub use qdag_tx::{
    QdagTransaction, QdagTxType, ConfidentialInput, ConfidentialOutput,
    ConfidentialStealthData, RingMemberLeaf, TxAuxData, QDAG_VERSION,
};
pub use confidential_stealth::{
    CtStealthOutput, VerifiedCtOutput, CtStealthScanner,
    create_confidential_stealth, CT_STEALTH_VERSION,
};
