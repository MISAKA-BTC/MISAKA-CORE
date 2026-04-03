//! # misaka-math
//!
//! Mathematical primitives for MISAKA: uint256, difficulty calculation,
//! compact target encoding, blue work computation.

pub mod blue_work;
pub mod compact;
pub mod difficulty;
pub mod uint;

pub use compact::{compact_to_target, target_to_compact};
pub use difficulty::{calc_work, difficulty_to_target, target_to_difficulty};
pub use uint::Uint256;
