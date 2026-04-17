// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Light client storage abstraction.

use std::collections::BTreeMap;

use crate::error::LightClientError;
use crate::trust_root::TrustRoot;
use crate::verified_commit::VerifiedCommit;
use crate::verified_epoch::VerifiedEpoch;

/// Abstract storage for light client state.
pub trait LightStorage: Send + Sync {
    fn store_trust_root(&mut self, root: &TrustRoot) -> Result<(), LightClientError>;
    fn load_trust_root(&self) -> Result<Option<TrustRoot>, LightClientError>;

    fn store_epoch(&mut self, epoch: &VerifiedEpoch) -> Result<(), LightClientError>;
    fn load_epoch(&self, epoch_num: u64) -> Result<Option<VerifiedEpoch>, LightClientError>;
    fn latest_epoch(&self) -> Result<Option<VerifiedEpoch>, LightClientError>;

    fn store_commit(&mut self, commit: &VerifiedCommit) -> Result<(), LightClientError>;
    fn load_commit(&self, index: u64) -> Result<Option<VerifiedCommit>, LightClientError>;
    fn latest_commit(&self) -> Result<Option<VerifiedCommit>, LightClientError>;
    fn highest_commit_index(&self) -> Result<u64, LightClientError>;
}

/// In-memory storage for testing and light-duty use.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    trust_root: Option<TrustRoot>,
    epochs: BTreeMap<u64, VerifiedEpoch>,
    commits: BTreeMap<u64, VerifiedCommit>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl LightStorage for MemoryStorage {
    fn store_trust_root(&mut self, root: &TrustRoot) -> Result<(), LightClientError> {
        self.trust_root = Some(root.clone());
        Ok(())
    }

    fn load_trust_root(&self) -> Result<Option<TrustRoot>, LightClientError> {
        Ok(self.trust_root.clone())
    }

    fn store_epoch(&mut self, epoch: &VerifiedEpoch) -> Result<(), LightClientError> {
        self.epochs.insert(epoch.epoch, epoch.clone());
        Ok(())
    }

    fn load_epoch(&self, epoch_num: u64) -> Result<Option<VerifiedEpoch>, LightClientError> {
        Ok(self.epochs.get(&epoch_num).cloned())
    }

    fn latest_epoch(&self) -> Result<Option<VerifiedEpoch>, LightClientError> {
        Ok(self.epochs.values().last().cloned())
    }

    fn store_commit(&mut self, commit: &VerifiedCommit) -> Result<(), LightClientError> {
        self.commits.insert(commit.commit_index, commit.clone());
        Ok(())
    }

    fn load_commit(&self, index: u64) -> Result<Option<VerifiedCommit>, LightClientError> {
        Ok(self.commits.get(&index).cloned())
    }

    fn latest_commit(&self) -> Result<Option<VerifiedCommit>, LightClientError> {
        Ok(self.commits.values().last().cloned())
    }

    fn highest_commit_index(&self) -> Result<u64, LightClientError> {
        Ok(self.commits.keys().last().copied().unwrap_or(0))
    }
}
