//! Auxiliary data and required signers.

use borsh::{BorshDeserialize, BorshSerialize};

/// Maximum number of required signers per transaction.
pub const MAX_REQUIRED_SIGNERS: usize = 16;

/// Maximum auxiliary data size in bytes.
pub const MAX_AUXILIARY_DATA_SIZE: usize = 65_536;

/// Required signers: public key hashes that MUST sign the transaction.
///
/// Scripts can check `required_signers` to implement multi-sig logic
/// without building it into the script itself.
pub type RequiredSigners = Vec<[u8; 32]>;

/// Auxiliary data: arbitrary metadata attached to a transaction.
///
/// Used for on-chain metadata labels (CIP-10 style), oracle data, etc.
/// Not validated by consensus — purely informational.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct AuxiliaryData {
    /// Metadata entries (label → value bytes).
    pub entries: Vec<AuxEntry>,
}

/// A single metadata entry.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct AuxEntry {
    /// Metadata label (application-defined).
    pub label: u64,
    /// Metadata value (arbitrary bytes, max 8192 per entry).
    pub data: Vec<u8>,
}

impl AuxiliaryData {
    /// SHA3-256 hash of the auxiliary data.
    pub fn hash(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:aux:v1:");
        let encoded = borsh::to_vec(self).unwrap_or_default();
        h.update(&encoded);
        h.finalize().into()
    }

    pub fn total_size(&self) -> usize {
        self.entries.iter().map(|e| e.data.len() + 8).sum()
    }
}
