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
pub(crate) use legacy::{
    checkpoint_vote_pool_json, dag_authority_switch_readiness_json,
    dag_consensus_architecture_json, dag_consumer_surfaces_json, dag_ordering_contract_json,
    dag_runtime_recovery_json, dag_sr21_committee_json, dag_tx_dissemination_json,
    dag_validator_attestation_json, latest_checkpoint_json,
    sync_runtime_recovery_from_shadow_state, validator_lifecycle_recovery_json,
};
