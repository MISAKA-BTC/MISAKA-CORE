#![allow(dead_code, unused_imports, unused_variables)]
//! Past median time calculation.

use crate::stores::ghostdag::{DbGhostdagStore, GhostdagStoreReader, Hash, ZERO_HASH};
use crate::stores::headers::{DbHeadersStore, HeaderStoreReader};

/// Number of blocks used for median time calculation.
pub const MEDIAN_TIME_WINDOW: usize = 11;

/// Calculate past median time by walking back from a given block.
pub fn calc_past_median_time(
    headers_store: &DbHeadersStore,
    ghostdag_store: &DbGhostdagStore,
    block_hash: Hash,
) -> u64 {
    let mut timestamps = Vec::with_capacity(MEDIAN_TIME_WINDOW);
    let mut current = block_hash;

    for _ in 0..MEDIAN_TIME_WINDOW {
        if current == ZERO_HASH {
            break;
        }
        if let Ok(ts) = headers_store.get_timestamp(current) {
            timestamps.push(ts);
        }
        current = ghostdag_store.get_selected_parent(&current).unwrap_or(ZERO_HASH);
    }

    if timestamps.is_empty() {
        return 0;
    }

    timestamps.sort_unstable();
    timestamps[timestamps.len() / 2]
}
