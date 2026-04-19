//! Static limits FROZEN for v2.0 launch.
//! Single source of truth — must match E1 type-level constants exactly.

pub const MAX_TX_SIZE_BYTES: usize = 16_384;
pub const MAX_VALUE_SIZE_BYTES: usize = 5_000;
pub const MAX_COLLATERAL_INPUTS_PER_TX: usize = 3;
pub const MAX_REQUIRED_SIGNERS: usize = 16;
pub const MAX_ASSETS_PER_OUTPUT: usize = 64;
