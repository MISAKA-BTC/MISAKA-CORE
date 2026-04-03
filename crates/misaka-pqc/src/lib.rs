//! MISAKA Network Post-Quantum Cryptography — ZKP-Only Architecture (v4).
//!
//! # Architecture (v4: Ring Signature Purge Complete)
//!
//! All lattice ZKP proof schemes (LogRing, LRS, ChipmunkRing) have been removed.
//! The privacy model is now exclusively:
//!
//! - **Output-bound Nullifier**: deterministic, ring-independent double-spend prevention
//! - **Confidential Commitment**: BDLOP lattice Pedersen over R_q
//! - **FCMP / UnifiedZKP**: Σ-protocol + SIS Merkle + BDLOP committed path
//!   with O(log N) verification and pk non-recoverable

#[cfg(all(not(debug_assertions), feature = "stark-stub"))]
compile_error!(
    "FATAL: 'stark-stub' feature MUST NOT be compiled in release mode. \
     This feature links placeholder proof builders/verifiers with no production soundness."
);

#[cfg(all(not(debug_assertions), feature = "experimental-privacy"))]
compile_error!(
    "FATAL: 'experimental-privacy' feature MUST NOT be compiled in release mode. \
     This feature currently aliases development-only privacy backends and must stay out of production builds."
);

pub mod error;
pub mod ki_proof;
pub mod ntt;
pub mod output_recovery;
/// Ring signature packing utilities.
pub mod packing;
pub mod pq_kem;
/// Lattice-based ring signature and polynomial arithmetic (core types: Poly, N, Q).
/// Used by bdlop, membership, nullifier, range_proof, unified_zkp, composite_proof.
pub mod pq_ring;
pub mod pq_sign;
/// Stealth address implementation (v1 + recovery support).
pub mod pq_stealth;
pub mod tx_codec;

// ── Privacy dispatch (ZKP-only) ──
pub mod privacy_backend;
pub mod privacy_constraints;
pub mod privacy_dispatch;
pub mod privacy_statement;

#[cfg(feature = "stark-stub")] // DEV-ONLY: Stub ZK verifier — blocked in release builds
pub mod stark_proof;
#[cfg(feature = "stark-stub")] // DEV-ONLY: Stub ZK verifier — blocked in release builds
pub mod zkmp_builder;

#[cfg(feature = "stealth-v2")]
pub mod stealth_v2;

// ── Q-DAG-CT Foundation (Phase 1.1) ──
pub mod bdlop;
pub mod secret;
pub mod transcript;

// ── Q-DAG-CT ZK Core (Phase 1.2) ──
pub mod membership;
pub mod nullifier;
pub mod range_proof;
pub mod unified_zkp;

// ── Production Composite Proof (STARK stub replacement) ──
pub mod composite_proof;

// ── Q-DAG-CT Transaction Layer (Phase 1.3) ──
pub mod confidential_fee;
pub mod confidential_stealth;
pub mod privacy;
pub mod qdag_tx;
pub mod zkp_types;

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
    pack_ring_sig, pack_ring_sig_v2, unpack_legacy_proof, unpack_legacy_proof_v2,
    PACKED_RESPONSE_SIZE,
};
pub use pq_kem::{
    MlKemCiphertext, MlKemKeypair, MlKemPublicKey, MlKemSecretKey, MlKemSharedSecret,
};
pub use pq_ring::{
    compute_key_image, derive_public_param, pq_sign, ring_verify, LegacyProofData, Poly,
    SpendingKeypair, DEFAULT_A_SEED,
};
pub use pq_sign::{ml_dsa_sign, ml_dsa_verify};
pub use pq_sign::{MlDsaKeypair, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
pub use tx_codec::{decode_transaction, encode_transaction, wire_size};

pub use canonical_ki::{canonical_key_image, canonical_key_image_bound, CANONICAL_KI_DST};

// ── Cryptographic Type System re-exports ──
pub use crypto_types::{
    AnonymityRoot, CommitmentHash, CommittedLeaf, PublicNullifier, SecretWitness, SharedSecret,
    TxDigest, VerifiedNullifier,
};

pub use verified_envelope::{verify_and_seal, TxVerificationError, VerifiedTransactionEnvelope};

pub use privacy_backend::{
    default_privacy_backend, describe_privacy_scheme, describe_transaction,
    describe_transaction_for_backend, target_spend_semantics_for_backend, tx_spend_semantics,
    tx_spend_semantics_for_backend, NullifierWitnessBindingModel, PrivacyBackendDescriptor,
    PrivacyBackendFamily, SpendIdentifierModel, TargetSpendSemanticsDescriptor,
    TransactionSpendSemantics,
};
pub use privacy_constraints::TransactionPrivacyConstraints;
pub use privacy_dispatch::{
    read_composite_proof_from_tx, select_privacy_backend, verify_composite_tx, LegacyVerifyError,
    LegacyVerifyInput, PrivacyBackendPreference, SelectedPrivacyBackend, UnifiedZkpVerifyInput,
};
#[cfg(feature = "stark-stub")] // DEV-ONLY: Stub ZK verifier — blocked in release builds
pub use privacy_dispatch::{
    read_zero_knowledge_proof_from_tx, verify_zero_knowledge_backend, verify_zero_knowledge_tx,
    verify_zero_knowledge_tx_with_statement,
};
pub use privacy_statement::{
    build_membership_targets, compute_membership_target, validate_public_statement,
    InputMembershipTarget, MembershipTargetModel, PublicStatementError, TransactionPublicStatement,
    MEMBERSHIP_TARGET_DST,
};

#[cfg(feature = "stark-stub")] // DEV-ONLY: Stub ZK verifier — blocked in release builds
pub use stark_proof::{stark_prove, stark_verify, StarkProof, TxConstraints, STARK_PROOF_VERSION};
#[cfg(feature = "stark-stub")] // DEV-ONLY: Stub ZK verifier — blocked in release builds
pub use zkmp_builder::{
    apply_zkmp_target_nullifiers, attach_zkmp_build_result, attach_zkmp_carrier,
    build_and_attach_zkmp_stub, build_zkmp_stub, build_zkmp_stub_constraints,
    compute_zkmp_binding_digest, materialize_zkmp_stub_tx, verify_zkmp_stub, verify_zkmp_stub_tx,
    ZkmpBuildResult, ZkmpInputWitness, DST_ZKMP_BINDING_V1,
};

pub use composite_proof::{
    compute_binding_digest, prove_composite, verify_composite, CompositeProof, OutputWitness,
    COMPOSITE_VERSION, SCHEME_COMPOSITE,
};

#[cfg(feature = "stealth-v2")]
pub use stealth_v2::{
    create_stealth_v2, RecoveredOutputV2, StealthPayloadV2, StealthScannerV2, STEALTH_V2_TAG,
};

pub use bdlop::{
    compute_balance_diff, verify_balance_with_excess, BalanceExcessProof, BdlopCommitment,
    BdlopCrs, BlindingFactor, BDLOP_CRS_SEED, MAX_CONFIDENTIAL_AMOUNT,
};
pub use secret::{ct_eq, ct_eq_32, SecretKey32, SecretPoly, SecureBuffer, ZeroizeGuard};
pub use transcript::{domain, merkle_node_hash, TranscriptBuilder};

pub use membership::{
    compute_sis_root, prove_membership_v2, sis_leaf, sis_root_hash, verify_membership_v2,
    SisMerkleCrs, ZkMembershipProofV2,
};
pub use nullifier::{
    canonical_nullifier_hash, compute_nullifier, verify_nullifier, NullifierProof, OutputId,
};
pub use range_proof::{prove_range, verify_range, RangeProof, RANGE_BITS};
pub use unified_zkp::{
    compute_merkle_root, unified_prove, unified_verify, unified_verify_ctx, UnifiedMembershipProof,
    SCHEME_UNIFIED_ZKP, ZKP_MAX_RING_SIZE, ZKP_MIN_RING_SIZE,
};

pub use confidential_fee::{
    create_confidential_fee, verify_confidential_fee, ConfidentialFee, FeeMinimumProof, MAX_FEE,
    MIN_FEE,
};
pub use confidential_stealth::{
    create_confidential_stealth, CtStealthOutput, CtStealthScanner, VerifiedCtOutput,
    CT_STEALTH_VERSION,
};
pub use privacy::{OneTimeAddress, PrivacyMode, ScanConfig, TxPaddingPolicy};
pub use qdag_tx::{
    ConfidentialInput, ConfidentialOutput, ConfidentialStealthData, QdagTransaction, QdagTxType,
    RingMemberLeaf, TxAuxData, QDAG_VERSION,
};
pub use zkp_types::{
    InputPublicInstance, MembershipInstance, MembershipWitness, NullifierInstance,
    NullifierWitness, PrivateTxWitness, PublicTxStatement, RangeInstance, RangeWitness,
};
