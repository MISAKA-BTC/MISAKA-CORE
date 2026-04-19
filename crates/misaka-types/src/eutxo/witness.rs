//! Witness types for v2 transaction inputs.

use borsh::{BorshDeserialize, BorshSerialize};

/// How an input is authorized in a v2 transaction.
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
pub enum WitnessKindV2 {
    /// Public key signature (ML-DSA-65). Same as v1 TransparentTransfer.
    Signature(Vec<u8>),
    /// Script validation: script source + redeemer + optional datum.
    Script {
        script: super::script::ScriptSource,
        redeemer: super::redeemer::Redeemer,
        /// Datum provided at spend time (for Hash-datum outputs).
        /// Not needed for Inline datum outputs.
        datum: Option<Vec<u8>>,
    },
}
