//! Datum types for eUTXO script outputs (CIP-32 inline datum).
//!
//! A datum is arbitrary data attached to a UTXO that scripts can
//! inspect. Supports both inline (embedded in output) and hash-only
//! (datum provided in witness at spending time).

use borsh::{BorshDeserialize, BorshSerialize};

/// Maximum inline datum size in bytes.
pub const MAX_DATUM_SIZE: usize = 16_384;

/// Datum attachment on a TxOutputV2.
///
/// CIP-32: inline datum is embedded directly in the output.
/// Hash-only: the 32-byte hash is stored; actual datum provided at spend time.
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
pub enum DatumOrHash {
    /// Inline datum (CIP-32): full data embedded in the output.
    Inline(InlineDatum),
    /// Hash-only: SHA3-256 of the datum bytes. Actual datum supplied in redeemer.
    Hash([u8; 32]),
}

/// Inline datum: raw bytes embedded in a transaction output.
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
pub struct InlineDatum(pub Vec<u8>);

impl InlineDatum {
    /// SHA3-256 hash of the datum bytes.
    pub fn hash(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:datum:v1:");
        h.update(&self.0);
        h.finalize().into()
    }

    pub fn is_valid_size(&self) -> bool {
        self.0.len() <= MAX_DATUM_SIZE
    }
}
