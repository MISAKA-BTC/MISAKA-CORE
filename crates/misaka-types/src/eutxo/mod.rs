//! eUTXO v2 type definitions — frozen wire format for v2.0 hard fork.
//!
//! Feature-gated behind `eutxo-v1-types`. This module defines the
//! complete transaction format including native assets, datums,
//! reference scripts/inputs, collateral, and cost model structures.
//!
//! Execution logic is NOT in this module (E2-E8).

pub mod auxiliary;
pub mod collateral;
pub mod compat;
pub mod cost_model;
pub mod datum;
pub mod mint;
pub mod redeemer;
pub mod reference;
pub mod script;
pub mod test_vectors;
pub mod tx_v2;
pub mod validate;
pub mod validity;
pub mod value;
pub mod witness;
