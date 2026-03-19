//! MISAKA Network Post-Quantum Cryptography — No ECC.
//!
//! - **ML-DSA-65** (FIPS 204): All signatures
//! - **ML-KEM-768** (FIPS 203): Stealth address KEM
//! - **LogRing-v1** (DEFAULT): O(log n) linkable ring signature (Merkle + lattice Σ)
//! - **LRS-v1** (legacy): O(n) lattice ring signature over R_q
//! - **ChipmunkRing-v1** (opt-in): Extended ring sizes (research)
//! - **Stealth v1/v2**: HKDF + XChaCha20-Poly1305 one-time outputs
//! - **Ring Scheme Trait**: Unified interface for all ring schemes

pub mod error;
pub mod pq_sign;
pub mod pq_kem;
pub mod pq_ring;
pub mod ntt;
pub mod packing;
pub mod ki_proof;
pub mod tx_codec;
pub mod pq_stealth;
pub mod output_recovery;

// ── New modules (v0.4.1+) ──
pub mod ring_scheme;
pub mod lrs_adapter;
pub mod canonical_ki;
// STARK proof is experimental — NOT production ready (hash-commitment stub only).
// Gated behind feature to prevent accidental use in mainnet validation.
#[cfg(feature = "stark-stub")]
pub mod stark_proof;

#[cfg(feature = "chipmunk")]
pub mod chipmunk;
#[cfg(feature = "chipmunk")]
pub mod chipmunk_adapter;

#[cfg(feature = "stealth-v2")]
pub mod stealth_v2;

// LogRing is always compiled — system default ring signature scheme.
pub mod logring;

// ── Re-exports ──
pub use error::CryptoError;
pub use pq_sign::{MlDsaKeypair, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
pub use pq_kem::{MlKemKeypair, MlKemPublicKey, MlKemSecretKey, MlKemCiphertext, MlKemSharedSecret};
pub use pq_ring::{SpendingKeypair, RingSig, ring_sign, ring_verify, compute_key_image, Poly, derive_public_param, DEFAULT_A_SEED};
pub use pq_stealth::{StealthOutput, StealthScanner, RecoveredOutput, create_stealth_output};
pub use output_recovery::OutputRecovery;
pub use packing::{pack_ring_sig, unpack_ring_sig, pack_ring_sig_v2, unpack_ring_sig_v2, PACKED_RESPONSE_SIZE};
pub use tx_codec::{encode_transaction, decode_transaction, wire_size};
pub use ki_proof::{
    KiProof, verify_key_image, verify_key_image_proof, prove_key_image, KI_PROOF_SIZE,
    hash_to_poly, compute_ki_poly, ki_poly_to_nullifier, canonical_strong_ki,
};

// ── Trait re-exports ──
pub use ring_scheme::{RingScheme, BatchVerifiable, RingSchemeVersion};
pub use lrs_adapter::LrsScheme;
pub use canonical_ki::{canonical_key_image, canonical_key_image_bound, CANONICAL_KI_DST};
#[cfg(feature = "stark-stub")]
pub use stark_proof::{StarkProof, TxConstraints, stark_prove, stark_verify, STARK_PROOF_VERSION};

#[cfg(feature = "chipmunk")]
pub use chipmunk::{ChipmunkSig, ChipmunkKiProof, chipmunk_ring_sign, chipmunk_ring_verify, chipmunk_compute_key_image};
#[cfg(feature = "chipmunk")]
pub use chipmunk_adapter::ChipmunkScheme;

#[cfg(feature = "stealth-v2")]
pub use stealth_v2::{StealthPayloadV2, StealthScannerV2, RecoveredOutputV2, create_stealth_v2, STEALTH_V2_TAG};

// LogRing — system default O(log n) ring signature
pub use logring::{
    LogRingSignature, logring_sign_v2 as logring_sign, logring_verify,
    compute_link_tag, compute_ring_root, RING_SCHEME_LOGRING,
    MAX_RING_SIZE as LOGRING_MAX_RING_SIZE,
};
