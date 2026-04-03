#![allow(dead_code, unused_imports, unused_variables)]
//! Pruning processor — handles DAG pruning and history compaction.

use crate::stores::ghostdag::{DbGhostdagStore, GhostdagStoreReader, Hash, ZERO_HASH};
use crate::stores::headers::{DbHeadersStore, HeaderStoreReader};
use crate::stores::pruning::{DbPruningStore, PruningPointInfo};
use misaka_database::prelude::*;
use parking_lot::RwLock;
use std::sync::Arc;

pub struct PruningProcessorConfig {
    pub pruning_depth: u64,
    pub finality_depth: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum PruningError {
    #[error("store error: {0}")]
    StoreError(#[from] StoreError),
}

pub struct PruningProcessor {
    config: PruningProcessorConfig,
    db: Arc<DB>,
    ghostdag_store: DbGhostdagStore,
    headers_store: DbHeadersStore,
    pruning_store: Arc<RwLock<DbPruningStore>>,
}

impl PruningProcessor {
    pub fn new(
        config: PruningProcessorConfig,
        db: Arc<DB>,
        ghostdag_store: DbGhostdagStore,
        headers_store: DbHeadersStore,
        pruning_store: Arc<RwLock<DbPruningStore>>,
    ) -> Self {
        Self {
            config,
            db,
            ghostdag_store,
            headers_store,
            pruning_store,
        }
    }

    /// Attempt to advance the pruning point based on current virtual state.
    pub fn maybe_advance_pruning_point(
        &self,
        virtual_selected_parent: Hash,
    ) -> Result<bool, PruningError> {
        let virtual_blue_score = self
            .ghostdag_store
            .get_blue_score(&virtual_selected_parent)
            .unwrap_or(0);
        let current_pruning = self.pruning_store.read().get();

        let current_pruning_score = match &current_pruning {
            Ok(info) => self
                .ghostdag_store
                .get_blue_score(&info.pruning_point)
                .unwrap_or(0),
            Err(_) => 0,
        };

        if virtual_blue_score <= current_pruning_score + self.config.pruning_depth {
            return Ok(false);
        }

        // Walk back from virtual selected parent to find new pruning point
        let target_score = virtual_blue_score.saturating_sub(self.config.pruning_depth);
        let new_pruning_point = self.find_block_at_score(virtual_selected_parent, target_score)?;

        let new_index = match current_pruning {
            Ok(info) => info.index + 1,
            Err(_) => 0,
        };

        self.pruning_store.write().set(&PruningPointInfo {
            pruning_point: new_pruning_point,
            candidate: virtual_selected_parent,
            index: new_index,
        })?;

        Ok(true)
    }

    fn find_block_at_score(&self, start: Hash, target_score: u64) -> Result<Hash, PruningError> {
        let mut current = start;
        loop {
            let score = self.ghostdag_store.get_blue_score(&current).unwrap_or(0);
            if score <= target_score || current == ZERO_HASH {
                return Ok(current);
            }
            current = self
                .ghostdag_store
                .get_selected_parent(&current)
                .unwrap_or(ZERO_HASH);
        }
    }
}
