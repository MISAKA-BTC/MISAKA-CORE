// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! `LightClient<S>` — trust-minimized PQ light client core.

use crate::error::LightClientError;
use crate::storage::LightStorage;
use crate::stream::{CommitStreamProvider, UnverifiedCommit};
use crate::trust_root::TrustRoot;
use crate::verification;
use crate::verified_commit::VerifiedCommit;
use crate::verified_epoch::VerifiedEpoch;
use misaka_types::validator::EpochTransitionProof;

/// Trust-minimized PQ light client for MISAKA Network.
///
/// Verifies ML-DSA-65 quorum proofs from genesis through epoch chain.
/// Does NOT trust the full node or observer — every commit is verified.
pub struct LightClient<S: LightStorage> {
    storage: S,
    chain_id: u32,
}

impl<S: LightStorage> LightClient<S> {
    /// Initialize from a TrustRoot (genesis).
    pub fn new(trust_root: TrustRoot, mut storage: S) -> Result<Self, LightClientError> {
        if trust_root.initial_committee.is_empty() {
            return Err(LightClientError::EmptyCommittee);
        }

        let chain_id = trust_root.chain_id;
        let committee_hash = verification::committee_hash(&trust_root.initial_committee);

        // Store the genesis epoch
        let epoch0 = VerifiedEpoch {
            epoch: trust_root.initial_epoch,
            committee: trust_root.initial_committee.clone(),
            committee_hash,
            highest_commit_index: 0,
        };
        storage.store_trust_root(&trust_root)?;
        storage.store_epoch(&epoch0)?;

        Ok(Self { storage, chain_id })
    }

    /// Current verified epoch number.
    pub fn current_epoch(&self) -> Result<u64, LightClientError> {
        self.storage
            .latest_epoch()?
            .map(|e| e.epoch)
            .ok_or(LightClientError::NotInitialized)
    }

    /// Latest verified commit.
    pub fn latest_verified_commit(&self) -> Result<Option<VerifiedCommit>, LightClientError> {
        self.storage.latest_commit()
    }

    /// Verify and store an epoch transition.
    ///
    /// The proof must contain 2f+1 ML-DSA-65 signatures from the
    /// current epoch's committee attesting to the new committee.
    pub fn verify_epoch_transition(
        &mut self,
        proof: EpochTransitionProof,
    ) -> Result<VerifiedEpoch, LightClientError> {
        let current = self
            .storage
            .latest_epoch()?
            .ok_or(LightClientError::NotInitialized)?;

        // Epoch must be sequential
        if proof.old_epoch != current.epoch {
            return Err(LightClientError::EpochMismatch {
                expected: current.epoch,
                got: proof.old_epoch,
            });
        }
        if proof.new_epoch != current.epoch + 1 {
            return Err(LightClientError::EpochGap {
                expected: current.epoch + 1,
                got: proof.new_epoch,
            });
        }

        // Cryptographic verification: 2f+1 of outgoing committee signed this
        verification::verify_epoch_transition(&current.committee, &proof)?;

        let new_epoch = VerifiedEpoch {
            epoch: proof.new_epoch,
            committee: proof.new_committee.clone(),
            committee_hash: proof.new_committee_hash,
            highest_commit_index: 0,
        };
        self.storage.store_epoch(&new_epoch)?;
        Ok(new_epoch)
    }

    /// Verify and store a commit.
    ///
    /// Each vote is ML-DSA-65 verified — no stub verifiers.
    pub fn verify_commit(
        &mut self,
        commit: UnverifiedCommit,
    ) -> Result<VerifiedCommit, LightClientError> {
        // Replay detection
        let highest = self.storage.highest_commit_index()?;
        if commit.commit_index <= highest && highest > 0 {
            return Err(LightClientError::CommitReplay(commit.commit_index));
        }

        // Chain ID binding
        if commit.chain_id != self.chain_id {
            return Err(LightClientError::ChainIdMismatch {
                expected: self.chain_id,
                got: commit.chain_id,
            });
        }

        // Load current epoch's committee
        let current_epoch = self
            .storage
            .latest_epoch()?
            .ok_or(LightClientError::NotInitialized)?;

        if commit.epoch != current_epoch.epoch {
            return Err(LightClientError::EpochMismatch {
                expected: current_epoch.epoch,
                got: commit.epoch,
            });
        }

        // ML-DSA-65 quorum verification
        let accumulated = verification::verify_committee_votes(
            &current_epoch.committee,
            &commit.votes,
            commit.slot,
            &commit.block_hash,
            commit.epoch,
            commit.chain_id,
        )?;

        let threshold = verification::quorum_threshold(&current_epoch.committee);
        if accumulated < threshold {
            return Err(LightClientError::QuorumNotReached {
                got: accumulated,
                need: threshold,
            });
        }

        let verified = VerifiedCommit {
            epoch: commit.epoch,
            commit_index: commit.commit_index,
            commit_digest: commit.commit_digest,
            leader: commit.leader,
            block_refs: commit.block_refs,
            timestamp_ms: commit.timestamp_ms,
            block_hash: commit.block_hash,
            slot: commit.slot,
            verified_stake: accumulated,
        };
        self.storage.store_commit(&verified)?;
        Ok(verified)
    }

    /// Sync from a CommitStreamProvider until exhausted.
    /// Returns the number of commits verified.
    pub fn sync<P: CommitStreamProvider>(
        &mut self,
        provider: &mut P,
    ) -> Result<u64, LightClientError> {
        let mut count = 0u64;

        // Process epoch transitions first
        while let Some(transition) = provider.next_epoch_transition()? {
            self.verify_epoch_transition(transition)?;
        }

        // Then process commits
        while let Some(commit) = provider.next_commit()? {
            self.verify_commit(commit)?;
            count += 1;
        }

        Ok(count)
    }
}
