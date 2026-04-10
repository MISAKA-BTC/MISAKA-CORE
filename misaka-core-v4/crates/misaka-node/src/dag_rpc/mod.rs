//! DAG RPC — modular handler structure.
//!
//! Previously a 32K-line monolith, now split into functional modules.
//! External API is fully backward-compatible via re-exports.
//!
//! # Module Structure
//!
//! - `state` — DagRpcState, DagSharedState, shared types
//! - `router` — Router construction, route registration
//! - `chain` — get_chain_info, get_block, get_tips
//! - `tx` — submit_tx, get_tx_by_hash, get_mempool_info
//! - `dag` — get_dag_info, get_virtual_chain, get_virtual_state
//! - `validator` — checkpoint votes, validator info
//! - `privacy` — get_utxos_by_address, get_decoy_utxos, get_anonymity_set
//! - `admin` — health, openapi, swagger, faucet, fee_estimate
//!
//! The original monolithic `dag_rpc.rs` is retained as `legacy.rs` during
//! the migration period. New code should be added to the appropriate module.

// During migration: re-export everything from the legacy monolith.
// TODO: Once all handlers are migrated, delete legacy.rs.
#[path = "../dag_rpc_legacy.rs"]
mod legacy;

pub use legacy::*;
