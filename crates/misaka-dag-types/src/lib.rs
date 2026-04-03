//! MISAKA DAG Consensus Types — Mysticeti-aligned.
//!
//! Key design: NO explicit Vote/Certificate messages.
//! Voting is implicit via block ancestry (direct inclusion).
pub mod block;
pub mod commit;
pub mod committee;
