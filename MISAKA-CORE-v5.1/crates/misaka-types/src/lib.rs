//! MISAKA Network Core Types — PQC-native
//!
//! All cryptographic types use exclusively
//! post-quantum signature schemes. No ECC.

pub mod checkpoint;
pub mod constants;
pub mod error;
pub mod gas;
pub mod genesis;
pub mod mcs1;
pub mod object;
pub mod scheme;
pub mod stealth;
pub mod transaction;
pub mod utxo;
pub mod validator;

pub use scheme::{MisakaPublicKey, MisakaSecretKey, MisakaSignature, SignatureScheme};

/// 32-byte hash digest (SHA3-256).
pub type Digest = [u8; 32];

/// 32-byte object identifier.
pub type ObjectId = [u8; 32];

/// 20-byte address derived from public key.
/// addr = SHA3-256(scheme_tag || pk_bytes)[0..20]
pub type Address = [u8; 20];

/// Chain identifier.
pub type ChainId = u32;

/// Epoch number.
pub type Epoch = u64;

/// Checkpoint sequence number.
pub type CheckpointSeq = u64;
