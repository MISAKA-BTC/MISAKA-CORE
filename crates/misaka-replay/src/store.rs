// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! ReadOnlyStore trait and in-memory implementation.
//!
//! ## Honest Report: No RocksDB Read-Only API
//!
//! misaka-storage does not provide a read-only DB open API.
//! RocksDB locks the DB directory, preventing concurrent access
//! from both the production node and the replay tool.
//!
//! **Workaround**: The replay tool operates on UtxoSetSnapshot files
//! (produced by `UtxoSet::save_to_file()`) rather than live RocksDB.
//! For block data, use serialized block lists.
//!
//! **Future**: Add `RocksDB::open_as_secondary()` support to
//! misaka-storage for live DB tailing.

use std::collections::BTreeMap;

use misaka_storage::utxo_set::UtxoSetSnapshot;
use misaka_types::utxo::UtxoTransaction;

use crate::error::ReplayError;

/// A block's worth of transactions for replay.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReplayBlock {
    pub height: u64,
    pub transactions: Vec<Vec<u8>>, // borsh-encoded UtxoTransaction bytes
    pub expected_state_root: [u8; 32],
    pub leader_address: Option<[u8; 32]>,
}

/// Read-only store for replay data.
///
/// The replay tool NEVER writes to production storage.
pub trait ReadOnlyStore: Send + Sync {
    fn get_block(&self, height: u64) -> Result<Option<ReplayBlock>, ReplayError>;
    fn get_snapshot(&self) -> Result<UtxoSetSnapshot, ReplayError>;
    fn latest_height(&self) -> Result<u64, ReplayError>;
}

/// In-memory store for testing and forensic analysis from exported data.
#[derive(Debug, Default)]
pub struct MemoryReplayStore {
    pub blocks: BTreeMap<u64, ReplayBlock>,
    pub snapshot: Option<UtxoSetSnapshot>,
}

impl MemoryReplayStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_snapshot(mut self, snapshot: UtxoSetSnapshot) -> Self {
        self.snapshot = Some(snapshot);
        self
    }

    pub fn add_block(&mut self, block: ReplayBlock) {
        self.blocks.insert(block.height, block);
    }
}

impl ReadOnlyStore for MemoryReplayStore {
    fn get_block(&self, height: u64) -> Result<Option<ReplayBlock>, ReplayError> {
        Ok(self.blocks.get(&height).cloned())
    }

    fn get_snapshot(&self) -> Result<UtxoSetSnapshot, ReplayError> {
        self.snapshot
            .clone()
            .ok_or(ReplayError::SnapshotNotFound(0))
    }

    fn latest_height(&self) -> Result<u64, ReplayError> {
        Ok(self.blocks.keys().last().copied().unwrap_or(0))
    }
}
