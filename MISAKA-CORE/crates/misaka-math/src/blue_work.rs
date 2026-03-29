//! Blue work computation for GhostDAG chain selection.

use crate::uint::Uint256;
use crate::difficulty::calc_work;

/// Compute the blue work for a block given its target and parent blue work.
pub fn compute_blue_work(parent_blue_work: &Uint256, target: &Uint256) -> Uint256 {
    let work = calc_work(target);
    *parent_blue_work + work
}

/// Compare blue work values for chain selection.
pub fn select_by_blue_work(a: &Uint256, b: &Uint256) -> std::cmp::Ordering {
    a.cmp(b)
}

/// Accumulate blue work from multiple parent blocks.
pub fn accumulate_blue_work(parent_works: &[Uint256], new_work: &Uint256) -> Uint256 {
    let max_parent = parent_works.iter().max().cloned().unwrap_or(Uint256::ZERO);
    max_parent + *new_work
}
