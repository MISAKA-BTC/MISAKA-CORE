//! MISAKA value unit definitions.
//!
//! Hierarchy:
//!   1 MISAKA = 10^9 ulrz (micro-MISAKA)
//!   1 ulrz   = 10^3 nlrz (nano)
//!   1 nlrz   = 10^3 plrz (pico)
//!
//! Sub-ulrz granularity is needed because PQC opcode fees are
//! fractions of ulrz: e.g., ML-DSA verify = 5e6 cpu × 60 nlrz/cpu = 0.3 ulrz.

pub const PLRZ_PER_NLRZ: u128 = 1_000;
pub const NLRZ_PER_ULRZ: u128 = 1_000;
pub const ULRZ_PER_MISAKA: u128 = 1_000_000_000;

pub const PLRZ_PER_ULRZ: u128 = NLRZ_PER_ULRZ * PLRZ_PER_NLRZ; // 1_000_000
pub const PLRZ_PER_MISAKA: u128 = ULRZ_PER_MISAKA * PLRZ_PER_ULRZ; // 10^15
