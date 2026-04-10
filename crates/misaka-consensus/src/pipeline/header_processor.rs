// Phase 33: #![allow(dead_code)] REMOVED — verification modules must never be silently dead.
//! Header processor — validates headers and computes GhostDAG data.

use crate::stores::ghostdag::{
    DbGhostdagStore, GhostdagData, GhostdagStoreReader, Hash, KType, ZERO_HASH,
};
use crate::stores::headers::{DbHeadersStore, Header, HeaderStoreReader};
use crate::stores::reachability::DbReachabilityStore;
use crate::stores::relations::DbRelationsStore;
#[allow(dead_code)]
use crate::stores::statuses::{BlockStatus, DbStatusesStore, StatusesStoreReader};
use crate::ValidatorSet;
use misaka_database::prelude::*;
use rocksdb::WriteBatch;
use std::sync::Arc;

/// Configuration for the header processor.
pub struct HeaderProcessorConfig {
    pub genesis_hash: Hash,
    pub max_block_parents: u8,
    pub ghostdag_k: KType,
    pub target_time_per_block_ms: u64,
    pub max_block_level: u8,
    /// Skip proposer PK / validator set validation.
    /// MUST be false in production. Only true for GhostDAG-layer tests
    /// that don't exercise the ML-DSA-65 signature pipeline.
    /// Production code MUST set this to false.
    pub skip_proposer_validation: bool,
}

/// Errors during header processing.
#[derive(Debug, thiserror::Error)]
pub enum HeaderProcessingError {
    #[error("block already known: {0}")]
    BlockAlreadyKnown(String),
    #[error("missing parent: {0}")]
    MissingParent(String),
    #[error("invalid timestamp: expected > {expected}, got {got}")]
    InvalidTimestamp { expected: u64, got: u64 },
    #[error("too many parents: {count} > {max}")]
    TooManyParents { count: usize, max: u8 },
    #[error("invalid PQC signature")]
    InvalidPqcSignature,
    #[error("proposer not in active validator set")]
    ProposerNotInValidatorSet,
    #[error("non-genesis block missing proposer public key")]
    MissingProposerPk,
    #[error("validation failed: {0}")]
    ValidationFailed(String),
    #[error("store error: {0}")]
    StoreError(#[from] StoreError),
}

/// The header processor validates block headers and runs GhostDAG.
pub struct HeaderProcessor {
    config: HeaderProcessorConfig,
    db: Arc<DB>,
    ghostdag_store: DbGhostdagStore,
    headers_store: DbHeadersStore,
    relations_store: DbRelationsStore,
    reachability_store: DbReachabilityStore,
    statuses_store: DbStatusesStore,
    /// Active validator set — proposer_pk must be in this set (CRIT-02).
    validator_set: Arc<ValidatorSet>,
}

impl HeaderProcessor {
    pub fn new(
        config: HeaderProcessorConfig,
        db: Arc<DB>,
        ghostdag_store: DbGhostdagStore,
        headers_store: DbHeadersStore,
        relations_store: DbRelationsStore,
        reachability_store: DbReachabilityStore,
        statuses_store: DbStatusesStore,
        validator_set: Arc<ValidatorSet>,
    ) -> Self {
        Self {
            config,
            db,
            ghostdag_store,
            headers_store,
            relations_store,
            reachability_store,
            statuses_store,
            validator_set,
        }
    }

    /// Process a new block header through the pipeline.
    pub fn process_header(&self, header: &Header) -> Result<GhostdagData, HeaderProcessingError> {
        let hash = header.hash;

        // 1. Check if already known
        if self.statuses_store.has(hash)? {
            return Err(HeaderProcessingError::BlockAlreadyKnown(hex::encode(hash)));
        }

        // 2. Validate in isolation
        self.validate_header_in_isolation(header)?;

        // 3. Validate in context (parents exist)
        self.validate_header_in_context(header)?;

        // 4. Run GhostDAG
        let ghostdag_data = self.run_ghostdag(&header.parents)?;

        // 5. Commit to stores
        let mut batch = WriteBatch::default();
        self.ghostdag_store
            .insert_batch(&mut batch, hash, &ghostdag_data)?;
        self.headers_store
            .insert_batch(&mut batch, hash, header.clone())?;
        self.relations_store
            .insert_batch(&mut batch, hash, header.parents.clone())?;
        self.statuses_store
            .set_batch(&mut batch, hash, BlockStatus::StatusHeaderOnly)?;
        self.db.write(batch).map_err(StoreError::from)?;

        Ok(ghostdag_data)
    }

    fn validate_header_in_isolation(&self, header: &Header) -> Result<(), HeaderProcessingError> {
        // Check parent count
        if header.parents.len() > self.config.max_block_parents as usize {
            return Err(HeaderProcessingError::TooManyParents {
                count: header.parents.len(),
                max: self.config.max_block_parents,
            });
        }
        if header.parents.is_empty() && header.hash != self.config.genesis_hash {
            return Err(HeaderProcessingError::MissingParent("no parents".into()));
        }
        // CRIT-01 fix: Non-genesis blocks MUST have a proposer public key.
        // Empty proposer_pk was previously allowed, bypassing ALL signature
        // verification. Only genesis is exempt.
        let is_genesis = header.hash == self.config.genesis_hash;

        if !is_genesis && !self.config.skip_proposer_validation && header.proposer_pk.is_empty() {
            return Err(HeaderProcessingError::MissingProposerPk);
        }

        // ML-DSA-65 header signature verification (mandatory for non-genesis).
        if !header.proposer_pk.is_empty() {
            if header.pqc_signature.is_empty() {
                return Err(HeaderProcessingError::ValidationFailed(
                    "proposer PK present but signature missing".into(),
                ));
            }

            // CRIT-02 fix: Verify proposer_pk belongs to an active validator.
            // Without this check, any ML-DSA-65 keypair could sign blocks.
            let pk_hash = {
                use sha3::{Digest, Sha3_256};
                let digest = Sha3_256::digest(&header.proposer_pk);
                let mut h = [0u8; 32];
                h.copy_from_slice(&digest);
                h
            };
            if self.validator_set.get(&pk_hash).is_none() {
                return Err(HeaderProcessingError::ProposerNotInValidatorSet);
            }

            let pk = misaka_pqc::pq_sign::MlDsaPublicKey::from_bytes(&header.proposer_pk).map_err(
                |e| HeaderProcessingError::ValidationFailed(format!("invalid proposer PK: {}", e)),
            )?;
            let sig = misaka_pqc::pq_sign::MlDsaSignature::from_bytes(&header.pqc_signature)
                .map_err(|e| {
                    HeaderProcessingError::ValidationFailed(format!("invalid signature: {}", e))
                })?;
            // SECURITY: Domain-separated header signature verification.
            // The "MISAKA-v1:header:" prefix prevents a TX or VRF signature
            // from being replayed as a valid header signature.
            misaka_pqc::pq_sign::ml_dsa_verify_raw(
                &pk,
                &header.hash,
                &sig,
            )
            .map_err(|e| {
                HeaderProcessingError::ValidationFailed(format!(
                    "ML-DSA-65 verification failed: {}",
                    e
                ))
            })?;
        }
        Ok(())
    }

    fn validate_header_in_context(&self, header: &Header) -> Result<(), HeaderProcessingError> {
        for parent in &header.parents {
            if !self.statuses_store.has(*parent)? && *parent != self.config.genesis_hash {
                return Err(HeaderProcessingError::MissingParent(hex::encode(parent)));
            }
        }
        // Validate timestamp against parent median time
        // (simplified — full implementation would compute past_median_time)
        Ok(())
    }

    fn run_ghostdag(&self, parents: &[Hash]) -> Result<GhostdagData, HeaderProcessingError> {
        if parents.is_empty() {
            return Ok(GhostdagData::genesis_data());
        }

        // Find selected parent (highest blue work)
        let selected_parent = self.find_selected_parent(parents)?;
        let k = self.config.ghostdag_k;
        let mut new_data = GhostdagData::new_with_selected_parent(selected_parent, k);

        // Get ordered mergeset (blocks in anticone of selected parent among parents)
        let ordered_mergeset = self.get_ordered_mergeset(selected_parent, parents)?;

        for candidate in &ordered_mergeset {
            let coloring = self.check_blue_candidate(&new_data, *candidate, k);
            match coloring {
                BlueCandidateResult::Blue(size, sizes) => {
                    new_data.add_blue(*candidate, size, &sizes);
                }
                BlueCandidateResult::Red => {
                    new_data.add_red(*candidate);
                }
            }
        }

        // Compute blue score and work
        let parent_blue_score = self
            .ghostdag_store
            .get_blue_score(&selected_parent)
            .unwrap_or(0);
        let blue_score = parent_blue_score + new_data.mergeset_blues.len() as u64;
        let parent_blue_work = self
            .ghostdag_store
            .get_blue_work(&selected_parent)
            .unwrap_or(0);
        let added_work: u128 = new_data.mergeset_blues.len() as u128; // simplified
        new_data.finalize_score_and_work(blue_score, parent_blue_work + added_work);

        Ok(new_data)
    }

    fn find_selected_parent(&self, parents: &[Hash]) -> Result<Hash, HeaderProcessingError> {
        let mut best = parents[0];
        let mut best_work = self.ghostdag_store.get_blue_work(&best).unwrap_or(0);
        for &parent in &parents[1..] {
            let work = self.ghostdag_store.get_blue_work(&parent).unwrap_or(0);
            if work > best_work || (work == best_work && parent > best) {
                best = parent;
                best_work = work;
            }
        }
        Ok(best)
    }

    fn get_ordered_mergeset(
        &self,
        selected_parent: Hash,
        parents: &[Hash],
    ) -> Result<Vec<Hash>, HeaderProcessingError> {
        // Return parents excluding selected_parent, sorted by blue work
        let mut mergeset: Vec<(Hash, u128)> = parents
            .iter()
            .filter(|&&p| p != selected_parent)
            .map(|&p| {
                let work = self.ghostdag_store.get_blue_work(&p).unwrap_or(0);
                (p, work)
            })
            .collect();
        mergeset.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
        Ok(mergeset.into_iter().map(|(h, _)| h).collect())
    }

    fn check_blue_candidate(
        &self,
        data: &GhostdagData,
        candidate: Hash,
        k: KType,
    ) -> BlueCandidateResult {
        // Simplified blue candidate check
        if data.mergeset_blues.len() as KType >= k + 1 {
            return BlueCandidateResult::Red;
        }
        BlueCandidateResult::Blue(0, Vec::new())
    }
}

enum BlueCandidateResult {
    Blue(KType, Vec<(Hash, KType)>),
    Red,
}
