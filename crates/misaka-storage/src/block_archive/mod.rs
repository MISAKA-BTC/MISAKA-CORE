//! Block archive — persistent block and transaction index for Bitcoin-compat RPC.
//!
//! Stores committed sub-DAGs as "blocks" with full transaction bodies,
//! enabling `getblock`, `getrawtransaction`, and `getblockhash` to serve
//! arbitrary historical data.
//!
//! Uses a SEPARATE RocksDB instance from the Narwhal consensus store.

pub mod store;
pub mod types;

#[cfg(test)]
mod tests {
    mod v2_forward_compat_test;
}

pub use store::{BlockArchive, BlockArchiveError};
pub use types::*;
