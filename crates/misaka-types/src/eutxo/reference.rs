//! Reference inputs (CIP-31): read-only UTXO references.
//!
//! Reference inputs allow a transaction to observe a UTXO without
//! consuming it. Used for oracle feeds, DEX state, etc.

use crate::utxo::OutputRef;
use borsh::{BorshDeserialize, BorshSerialize};

/// A reference input: a UTXO that is observed but NOT consumed.
///
/// CIP-31: the UTXO must exist at validation time and must not be
/// consumed by any input in the same transaction.
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
pub struct ReferenceInput {
    /// The UTXO being referenced (must exist, not consumed).
    pub outref: OutputRef,
}
