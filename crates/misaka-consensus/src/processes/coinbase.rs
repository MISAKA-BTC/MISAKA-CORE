//! Coinbase/block reward management.
//!
//! SEC-FIX: The Bitcoin/Kaspa-style halving logic (daa_score / 210_000)
//! has been removed. MISAKA uses a PoS emission model where block rewards
//! are controlled by `UtxoExecutor::validate_system_emission()` with:
//! - Per-block cap: `PHASE2_MAX_COINBASE_PER_BLOCK` (50 MISAKA)
//! - Total supply cap: `MAX_TOTAL_SUPPLY` (21B MISAKA)
//! - Proposer address verification: `leader_address` binding
//!
//! The `CoinbaseManager` and `calc_block_reward()` with PoW-style halving
//! were dead code (#[allow(dead_code)]) incompatible with PoS tokenomics.
//!
//! For the actual emission logic, see:
//! - `crates/misaka-node/src/utxo_executor.rs::validate_system_emission()`
//! - `crates/misaka-tokenomics/src/supply.rs::SupplyTracker`
