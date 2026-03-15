//! MISAKA Network Post-Quantum Cryptography — No ECC.
//!
//! - **ML-DSA-65** (FIPS 204): All signatures
//! - **ML-KEM-768** (FIPS 203): Stealth address KEM
//! - **LRS-v1** (legacy): Lattice ring signature over R_q
//! - **ChipmunkRing-v1**: New lattice ring signature with extended ring sizes
//! - **Stealth v1/v2**: HKDF + XChaCha20-Poly1305 one-time outputs
//! - **Ring Scheme Trait**: Unified interface for LRS / ChipmunkRing

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

#[cfg(feature = "chipmunk")]
pub mod chipmunk;
#[cfg(feature = "chipmunk")]
pub mod chipmunk_adapter;

#[cfg(feature = "stealth-v2")]
pub mod stealth_v2;

// ── Re-exports ──
pub use error::CryptoError;
pub use pq_sign::{MlDsaKeypair, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
pub use pq_kem::{MlKemKeypair, MlKemPublicKey, MlKemSecretKey, MlKemCiphertext, MlKemSharedSecret};
pub use pq_ring::{SpendingKeypair, RingSig, ring_sign, ring_verify, compute_key_image, Poly, derive_public_param, DEFAULT_A_SEED};
pub use pq_stealth::{StealthOutput, StealthScanner, RecoveredOutput, create_stealth_output};
pub use output_recovery::OutputRecovery;
pub use packing::{pack_ring_sig, unpack_ring_sig, pack_ring_sig_v2, unpack_ring_sig_v2, PACKED_RESPONSE_SIZE};
pub use tx_codec::{encode_transaction, decode_transaction, wire_size};
pub use ki_proof::{KiProof, verify_key_image, verify_key_image_proof, prove_key_image, KI_PROOF_SIZE};

// ── Trait re-exports ──
pub use ring_scheme::{RingScheme, BatchVerifiable, RingSchemeVersion};
pub use lrs_adapter::LrsScheme;
pub use canonical_ki::{canonical_key_image, canonical_key_image_bound, CANONICAL_KI_DST};

#[cfg(feature = "chipmunk")]
pub use chipmunk::{ChipmunkSig, ChipmunkKiProof, chipmunk_ring_sign, chipmunk_ring_verify, chipmunk_compute_key_image};
#[cfg(feature = "chipmunk")]
pub use chipmunk_adapter::ChipmunkScheme;

#[cfg(feature = "stealth-v2")]
pub use stealth_v2::{StealthPayloadV2, StealthScannerV2, RecoveredOutputV2, create_stealth_v2, STEALTH_V2_TAG};
