//! # misaka-indexes
//!
//! Block and UTXO indexing for fast lookups. Provides:
//! - UTXO index by script public key (address)
//! - Transaction index for block inclusion lookup
//! - DAA score index for time-based queries

pub mod utxoindex;
pub mod txindex;
pub mod core;

pub use utxoindex::UtxoIndex;
pub use txindex::TxIndex;
