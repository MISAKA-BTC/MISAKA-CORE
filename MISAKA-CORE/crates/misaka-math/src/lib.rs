//! # misaka-math
//!
//! Mathematical primitives for MISAKA: uint256, difficulty calculation,
//! compact target encoding, blue work computation.

pub mod uint;
pub mod difficulty;
pub mod compact;
pub mod blue_work;

pub use uint::Uint256;
pub use difficulty::{calc_work, difficulty_to_target, target_to_difficulty};
pub use compact::{compact_to_target, target_to_compact};
