//! MISAKA Network Core Types — PQC-native
//!
//! All cryptographic types use exclusively
//! post-quantum signature schemes. No ECC.

pub mod address;
pub mod checkpoint;
pub mod constants;
pub mod error;
pub mod gas;
pub mod genesis;
pub mod mcs1;
pub mod object;
pub mod quarantine;
pub mod scheme;
pub mod stealth;
pub mod transaction;
pub mod utxo;
pub mod validator;
pub mod validator_stake_tx;

pub use validator_stake_tx::{
    RegisterParams, StakeInput, StakeMoreParams, StakeTxError, StakeTxKind, StakeTxParams,
    ValidatorStakeTx, MAX_COMMISSION_BPS, MAX_STAKE_TX_MEMO_SIZE, MIN_UNBONDING_EPOCHS,
};

pub use quarantine::{
    BlockAcceptanceState, BridgeSafetyState, FinalityLevel, PauseOrigin, QuarantineEntry,
    QuarantineReason, QuarantineType, SnapshotTrustState, TxAcceptanceState,
};
pub use scheme::{MisakaPublicKey, MisakaSecretKey, MisakaSignature, SignatureScheme};

/// 32-byte hash digest (SHA3-256).
pub type Digest = [u8; 32];

/// 32-byte object identifier.
pub type ObjectId = [u8; 32];

/// 32-byte address derived from public key (full SHA3-256, PQ-safe).
/// addr = SHA3-256(scheme_tag || pk_bytes)[0..20]
pub type Address = [u8; 32];

/// Chain identifier.
pub type ChainId = u32;

/// Epoch number.
pub type Epoch = u64;

/// Checkpoint sequence number.
pub type CheckpointSeq = u64;
