#![allow(dead_code, unused_imports, unused_variables)]
//! Difficulty adjustment for MISAKA PoS.

use crate::stores::ghostdag::BlueWorkType;

/// Calculate work from header bits.
pub fn calc_work(bits: u32) -> BlueWorkType {
    // Simplified: In PoS, difficulty is based on stake weight
    // rather than hash difficulty.
    let mantissa = (bits & 0x00FFFFFF) as u128;
    let exponent = (bits >> 24) as u32;
    if exponent <= 3 {
        mantissa >> (8 * (3 - exponent))
    } else {
        mantissa << (8 * (exponent - 3))
    }
}

/// Level work for multi-level GhostDAG.
pub fn level_work(level: u8, max_level: u8) -> BlueWorkType {
    if level >= max_level {
        return 0;
    }
    1u128 << (level as u128)
}
