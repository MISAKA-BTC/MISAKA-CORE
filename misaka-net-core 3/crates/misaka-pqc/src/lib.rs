//! MISAKA Network Post-Quantum Cryptography — No ECC.
//!
//! - **ML-DSA-65** (FIPS 204): All signatures
//! - **ML-KEM-768** (FIPS 203): Stealth address KEM
//! - **Lattice Ring Sig** (MISAKA-LRS-v1): TX sender anonymity over R_q
//! - **PQ Stealth**: HKDF + XChaCha20-Poly1305 one-time outputs

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

pub use error::CryptoError;
pub use pq_sign::{MlDsaKeypair, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
pub use pq_kem::{MlKemKeypair, MlKemPublicKey, MlKemSecretKey, MlKemCiphertext, MlKemSharedSecret};
pub use pq_ring::{SpendingKeypair, RingSig, ring_sign, ring_verify, compute_key_image, Poly, derive_public_param, DEFAULT_A_SEED};
pub use pq_stealth::{StealthOutput, StealthScanner, RecoveredOutput, create_stealth_output};
pub use output_recovery::OutputRecovery;
pub use packing::{pack_ring_sig, unpack_ring_sig, pack_ring_sig_v2, unpack_ring_sig_v2, PACKED_RESPONSE_SIZE};
pub use tx_codec::{encode_transaction, decode_transaction, wire_size};
pub use ki_proof::{KiProof, verify_key_image, verify_key_image_proof, prove_key_image, KI_PROOF_SIZE};
