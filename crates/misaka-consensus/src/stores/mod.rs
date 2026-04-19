//! Typed consensus stores — all backed by misaka-database.

pub mod acceptance_data;
pub mod block_transactions;
// Phase 2 Path X R6-b Option W (2026-04-19): Narwhal-native replacement
// for the GhostDAG-bound pruning store (`pruning.rs`), which was
// deleted in the dead-code cleanup commit.
pub mod commit_pruning;
pub mod daa;
pub mod depth;
pub mod ghostdag;
pub mod headers;
pub mod reachability;
pub mod relations;
pub mod selected_chain;
pub mod statuses;
pub mod tips;
pub mod utxo_diffs;
pub mod virtual_state;

pub use ghostdag::{BlueWorkType, Hash, KType, ZERO_HASH};
