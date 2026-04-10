// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! Block verification — validates blocks before acceptance.
//!
//! Sui equivalent: consensus/core/block_verifier.rs (~400 lines)
//!
//! Checks:
//! 1. Author is a valid committee member
//! 2. Round > 0 (genesis is round 0)
//! 3. Epoch matches current epoch
//! 4. Ancestor count ≥ quorum threshold for round > 1
//! 5. No duplicate ancestors
//! 6. Ancestors are from round-1 (or earlier for skip)
//! 7. Timestamp is not too far in the future
//! 8. Block size within limits
//! 9. ML-DSA-65 signature verification

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::narwhal_types::block::*;
use crate::narwhal_types::committee::Committee;

/// Maximum allowed future drift for block timestamps (30 seconds).
pub const MAX_TIMESTAMP_FUTURE_DRIFT_MS: u64 = 30_000;

/// Maximum block size in bytes.
pub const MAX_BLOCK_SIZE_BYTES: usize = 16 * 1024 * 1024; // 16 MB

/// Maximum transactions per block.
pub const MAX_TRANSACTIONS_PER_BLOCK: usize = 10_000;

/// Maximum ancestors (parents) per block.
pub const MAX_ANCESTORS: usize = 1024;

/// Maximum past timestamp drift (60 seconds).
pub const MAX_TIMESTAMP_PAST_DRIFT_MS: u64 = 60_000;

/// Block verification errors.
#[derive(Debug, thiserror::Error)]
pub enum BlockVerifyError {
    #[error("invalid author {author}: not in committee of {committee_size}")]
    InvalidAuthor {
        author: AuthorityIndex,
        committee_size: usize,
    },
    #[error("invalid round 0 (genesis only)")]
    InvalidRoundZero,
    #[error("epoch mismatch: block={block_epoch}, expected={expected_epoch}")]
    EpochMismatch {
        block_epoch: u64,
        expected_epoch: u64,
    },
    #[error("insufficient ancestors: have {have}, need {need} (quorum)")]
    InsufficientAncestors { have: usize, need: usize },
    #[error("insufficient distinct ancestor authors: have {have}, need {need} (quorum)")]
    InsufficientDistinctAncestorAuthors { have: usize, need: usize },
    #[error("duplicate ancestor: {0}")]
    DuplicateAncestor(BlockRef),
    #[error(
        "ancestor from wrong round: ancestor_round={ancestor_round}, block_round={block_round}"
    )]
    AncestorWrongRound {
        ancestor_round: Round,
        block_round: Round,
    },
    #[error(
        "timestamp too far in future: {block_ts_ms} > now + {MAX_TIMESTAMP_FUTURE_DRIFT_MS}ms"
    )]
    TimestampTooFarInFuture { block_ts_ms: BlockTimestampMs },
    #[error("block too large: {size} bytes > {MAX_BLOCK_SIZE_BYTES}")]
    BlockTooLarge { size: usize },
    #[error("too many transactions: {count} > {MAX_TRANSACTIONS_PER_BLOCK}")]
    TooManyTransactions { count: usize },
    #[error("too many ancestors: {count} > {MAX_ANCESTORS}")]
    TooManyAncestors { count: usize },
    #[error("timestamp too far in past: {block_ts_ms}")]
    TimestampTooFarInPast { block_ts_ms: BlockTimestampMs },
    #[error("invalid signature: {reason}")]
    InvalidSignature { reason: String },
}

/// Block verifier — validates blocks before DAG acceptance.
pub struct BlockVerifier {
    /// Committee for the current epoch.
    committee: Committee,
    /// Current epoch.
    epoch: u64,
    /// Signature verifier (ML-DSA-65).
    verifier: Arc<dyn SignatureVerifier>,
    /// Phase 30 (CR-2): Chain context for cross-network replay prevention.
    chain_ctx: misaka_types::chain_context::ChainContext,
    /// Phase 2b: AppId for IntentMessage-based block signing.
    app_id: misaka_types::intent::AppId,
    /// Clock abstraction (Phase 0-2 completion).
    clock: Arc<dyn super::clock::Clock>,
    /// When true, skip past-drift timestamp check (sync/catch-up mode).
    /// Future-drift is always checked regardless.
    syncing: AtomicBool,
}

impl BlockVerifier {
    pub fn new(
        committee: Committee,
        epoch: u64,
        verifier: Arc<dyn SignatureVerifier>,
        chain_ctx: misaka_types::chain_context::ChainContext,
    ) -> Self {
        // Phase 2b: construct AppId from chain_ctx
        let app_id = misaka_types::intent::AppId::new(
            chain_ctx.chain_id,
            chain_ctx.genesis_hash,
        );
        Self {
            committee,
            epoch,
            verifier,
            chain_ctx,
            app_id,
            clock: Arc::new(super::clock::SystemClock),
            syncing: AtomicBool::new(false),
        }
    }

    /// Set sync mode — when true, past-drift timestamp checks are skipped
    /// to allow catch-up from peers with older blocks.
    pub fn set_syncing(&self, syncing: bool) {
        self.syncing.store(syncing, Ordering::Release);
    }

    /// Inject a custom clock (for deterministic simulation).
    pub fn with_clock(mut self, clock: Arc<dyn super::clock::Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Parallel block verification via rayon.
    ///
    /// IMPORTANT: ML-DSA-65 (Dilithium) does NOT support cryptographic batch
    /// verification (no shared-base-point trick like Ed25519). "Batch" here
    /// means rayon parallelism only. Speedup bounded by core count.
    pub fn verify_batch(&self, blocks: &[Block]) -> Vec<Result<VerifiedBlock, BlockVerifyError>> {
        use rayon::prelude::*;
        const VERIFY_PARALLEL_THRESHOLD: usize = 4;

        if blocks.len() < VERIFY_PARALLEL_THRESHOLD {
            return blocks.iter().map(|b| self.verify(b)).collect();
        }

        super::verify_pool::verify_pool()
            .install(|| blocks.par_iter().map(|b| self.verify(b)).collect())
    }

    /// Verify a block and return a VerifiedBlock on success.
    /// Check order optimized for DoS resistance:
    /// cheap structural checks → signature (reject forgeries early) → heavy checks.
    ///
    /// NOTE: `state_root` is included in the block digest and covered by the
    /// ML-DSA-65 signature, but is NOT independently validated here. State root
    /// verification requires re-executing all transactions in the block and
    /// comparing the resulting UTXO state hash, which belongs in the execution
    /// layer (UtxoExecutor) after commit ordering — not in the DAG verifier.
    pub fn verify(&self, block: &Block) -> Result<VerifiedBlock, BlockVerifyError> {
        // Phase 1: cheap O(1) structural checks
        self.check_author(block)?;
        self.check_round(block)?;
        self.check_epoch(block)?;

        // Phase 2: signature verification (rejects forged blocks before heavy work)
        self.check_signature(block)?;

        // Phase 3: heavier checks (ancestors stake aggregation, size traversal)
        self.check_ancestors(block)?;
        self.check_timestamp(block)?;
        self.check_size(block)?;

        Ok(VerifiedBlock::new_verified(block.clone()))
    }

    fn check_author(&self, block: &Block) -> Result<(), BlockVerifyError> {
        if block.author as usize >= self.committee.size() {
            return Err(BlockVerifyError::InvalidAuthor {
                author: block.author,
                committee_size: self.committee.size(),
            });
        }
        Ok(())
    }

    fn check_round(&self, block: &Block) -> Result<(), BlockVerifyError> {
        if block.round == 0 {
            return Err(BlockVerifyError::InvalidRoundZero);
        }
        Ok(())
    }

    fn check_epoch(&self, block: &Block) -> Result<(), BlockVerifyError> {
        if block.epoch != self.epoch {
            return Err(BlockVerifyError::EpochMismatch {
                block_epoch: block.epoch,
                expected_epoch: self.epoch,
            });
        }
        Ok(())
    }

    fn check_ancestors(&self, block: &Block) -> Result<(), BlockVerifyError> {
        // HI-4: Early reject for too many ancestors (DoS protection)
        if block.ancestors.len() > MAX_ANCESTORS {
            return Err(BlockVerifyError::TooManyAncestors {
                count: block.ancestors.len(),
            });
        }

        // Round 1 blocks have no ancestors (genesis round)
        if block.round <= 1 {
            return Ok(());
        }

        // Need at least quorum ancestors for round > 1
        let quorum = self.committee.quorum_threshold() as usize;
        if block.ancestors.len() < quorum {
            return Err(BlockVerifyError::InsufficientAncestors {
                have: block.ancestors.len(),
                need: quorum,
            });
        }

        // Check for duplicates and collect distinct authors
        let mut seen = HashSet::new();
        let mut distinct_authors = HashSet::new();
        for ancestor in &block.ancestors {
            if !seen.insert(*ancestor) {
                return Err(BlockVerifyError::DuplicateAncestor(*ancestor));
            }
            // Ancestors must be from a previous round
            if ancestor.round >= block.round {
                return Err(BlockVerifyError::AncestorWrongRound {
                    ancestor_round: ancestor.round,
                    block_round: block.round,
                });
            }
            distinct_authors.insert(ancestor.author);
        }

        // Phase 1 fix (CRIT session-2): BFT safety requires ancestors to come
        // from distinct authorities with sufficient total stake. Without this,
        // a Byzantine validator can forge quorum using multiple equivocated
        // blocks from one author. Stake-weighted to handle heterogeneous sets.
        // See docs/architecture.md §10 Phase 1 deliverables.
        let distinct_stake: u64 = distinct_authors
            .iter()
            .filter_map(|a| self.committee.authority(*a).map(|auth| auth.stake))
            .sum();
        if distinct_stake < self.committee.quorum_threshold() {
            return Err(BlockVerifyError::InsufficientDistinctAncestorAuthors {
                have: distinct_authors.len(),
                need: quorum,
            });
        }

        Ok(())
    }

    fn check_timestamp(&self, block: &Block) -> Result<(), BlockVerifyError> {
        let now_ms = self.clock.now_millis();

        // HI-8: Future drift check
        if block.timestamp_ms > now_ms + MAX_TIMESTAMP_FUTURE_DRIFT_MS {
            return Err(BlockVerifyError::TimestampTooFarInFuture {
                block_ts_ms: block.timestamp_ms,
            });
        }

        // HI-8: Past drift check — reject blocks with very old timestamps.
        // Skip during sync/catch-up mode to allow processing historic blocks
        // from peers after node downtime.
        if !self.syncing.load(Ordering::Acquire)
            && now_ms > MAX_TIMESTAMP_PAST_DRIFT_MS
            && block.timestamp_ms < now_ms - MAX_TIMESTAMP_PAST_DRIFT_MS
        {
            return Err(BlockVerifyError::TimestampTooFarInPast {
                block_ts_ms: block.timestamp_ms,
            });
        }

        Ok(())
    }

    fn check_size(&self, block: &Block) -> Result<(), BlockVerifyError> {
        let size = block.size_bytes();
        if size > MAX_BLOCK_SIZE_BYTES {
            return Err(BlockVerifyError::BlockTooLarge { size });
        }
        if block.transactions.len() > MAX_TRANSACTIONS_PER_BLOCK {
            return Err(BlockVerifyError::TooManyTransactions {
                count: block.transactions.len(),
            });
        }
        Ok(())
    }

    fn check_signature(&self, block: &Block) -> Result<(), BlockVerifyError> {
        if block.signature.is_empty() {
            return Err(BlockVerifyError::InvalidSignature {
                reason: "empty signature".to_string(),
            });
        }

        // Get author's public key
        let pubkey = self
            .committee
            .authority(block.author)
            .map(|a| &a.public_key)
            .ok_or_else(|| BlockVerifyError::InvalidAuthor {
                author: block.author,
                committee_size: self.committee.size(),
            })?;

        // Early reject for wrong-length signatures (avoid sending to verify pool)
        const ML_DSA_SIG_LEN: usize = 3309;
        const ML_DSA_PK_LEN: usize = 1952;
        if block.signature.len() != ML_DSA_SIG_LEN {
            return Err(BlockVerifyError::InvalidSignature {
                reason: format!(
                    "signature length {} != expected {}",
                    block.signature.len(),
                    ML_DSA_SIG_LEN
                ),
            });
        }
        if pubkey.len() != ML_DSA_PK_LEN {
            return Err(BlockVerifyError::InvalidSignature {
                reason: format!(
                    "public key length {} != expected {}",
                    pubkey.len(),
                    ML_DSA_PK_LEN
                ),
            });
        }

        // Phase 2b: Verify signature over IntentMessage-based digest.
        // Uses signing_digest_v2(app_id) which wraps NarwhalBlockPayload
        // in IntentMessage for domain separation and cross-chain replay protection.
        let digest = block.signing_digest_v2(self.app_id.clone());
        self.verifier
            .verify(pubkey, &digest.0, &block.signature)
            .map_err(|reason| BlockVerifyError::InvalidSignature { reason })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::narwhal_types::block::{MlDsa65Verifier, TestValidatorSet};

    /// CR-1 fix: All tests use real ML-DSA-65 keypairs via TestValidatorSet.
    /// No more StructuralVerifier or DummySigner.

    fn setup() -> (TestValidatorSet, BlockVerifier) {
        let tvs = TestValidatorSet::new(4);
        let v = tvs.verifier(0);
        (tvs, v)
    }

    fn unsigned_block(round: Round, author: AuthorityIndex) -> Block {
        Block {
            epoch: 0,
            round,
            author,
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
            ancestors: vec![],
            transactions: vec![vec![1, 2, 3]],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![], // unsigned — must be signed via TestValidatorSet
        }
    }

    fn signed_block(tvs: &TestValidatorSet, round: Round, author: AuthorityIndex) -> Block {
        let mut block = unsigned_block(round, author);
        tvs.sign_block(author as usize, &mut block);
        block
    }

    #[test]
    fn test_valid_block() {
        let (tvs, v) = setup();
        let block = signed_block(&tvs, 1, 0);
        assert!(v.verify(&block).is_ok());
    }

    #[test]
    fn test_invalid_author() {
        let (_tvs, v) = setup();
        let mut block = unsigned_block(1, 99); // not in committee
        block.signature = vec![0xAA; 3309]; // dummy sig (author check fires before sig check)
        assert!(matches!(
            v.verify(&block),
            Err(BlockVerifyError::InvalidAuthor { .. })
        ));
    }

    #[test]
    fn test_invalid_round_zero() {
        let (tvs, v) = setup();
        let block = signed_block(&tvs, 0, 0);
        assert!(matches!(
            v.verify(&block),
            Err(BlockVerifyError::InvalidRoundZero)
        ));
    }

    #[test]
    fn test_wrong_epoch() {
        let (tvs, v) = setup();
        let mut block = signed_block(&tvs, 1, 0);
        block.epoch = 99;
        // Re-sign after mutation to avoid invalid-sig masking the epoch error
        // Actually no — we want epoch check to fire BEFORE sig check.
        // The verify order is: author, round, epoch, ancestors, timestamp, size, sig.
        // So epoch mismatch should fire with or without valid sig.
        assert!(matches!(
            v.verify(&block),
            Err(BlockVerifyError::EpochMismatch { .. })
        ));
    }

    #[test]
    fn test_empty_signature_rejected() {
        let (_tvs, v) = setup();
        let block = unsigned_block(1, 0); // empty signature
        assert!(matches!(
            v.verify(&block),
            Err(BlockVerifyError::InvalidSignature { .. })
        ));
    }

    #[test]
    fn test_timestamp_in_future() {
        let (tvs, v) = setup();
        let mut block = unsigned_block(1, 0);
        block.timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
            + MAX_TIMESTAMP_FUTURE_DRIFT_MS
            + 10_000;
        tvs.sign_block(0, &mut block);
        assert!(matches!(
            v.verify(&block),
            Err(BlockVerifyError::TimestampTooFarInFuture { .. })
        ));
    }

    #[test]
    fn test_too_many_transactions() {
        let (tvs, v) = setup();
        let mut block = unsigned_block(1, 0);
        block.transactions = vec![vec![0]; MAX_TRANSACTIONS_PER_BLOCK + 1];
        tvs.sign_block(0, &mut block);
        assert!(matches!(
            v.verify(&block),
            Err(BlockVerifyError::TooManyTransactions { .. })
        ));
    }

    #[test]
    fn test_duplicate_ancestor() {
        let (tvs, v) = setup();
        let ancestor = BlockRef::new(1, 0, BlockDigest([0x11; 32]));
        let mut block = unsigned_block(2, 0);
        block.ancestors = vec![ancestor, ancestor, ancestor]; // duplicate
        tvs.sign_block(0, &mut block); // sign so check_signature passes
        assert!(matches!(
            v.verify(&block),
            Err(BlockVerifyError::DuplicateAncestor(_))
        ));
    }

    #[test]
    fn test_ancestor_from_future_round() {
        let (tvs, v) = setup();
        let good1 = BlockRef::new(1, 0, BlockDigest([0x11; 32]));
        let good2 = BlockRef::new(1, 1, BlockDigest([0x22; 32]));
        let future = BlockRef::new(5, 2, BlockDigest([0x33; 32]));
        let mut block = unsigned_block(2, 0);
        block.ancestors = vec![good1, good2, future];
        tvs.sign_block(0, &mut block); // sign so check_signature passes
        assert!(matches!(
            v.verify(&block),
            Err(BlockVerifyError::AncestorWrongRound { .. })
        ));
    }

    // ── CR-1 Regression: fail-open paths that MUST be rejected ──

    #[test]
    fn cr1_arbitrary_bytes_signature_rejected() {
        let (_tvs, v) = setup();
        let mut block = unsigned_block(1, 0);
        block.signature = vec![0xAA; 3309]; // ML-DSA-65 sig length but garbage
        assert!(matches!(
            v.verify(&block),
            Err(BlockVerifyError::InvalidSignature { .. })
        ));
    }

    #[test]
    fn cr1_impersonation_with_attacker_key_rejected() {
        let (tvs, v) = setup();
        let attacker = misaka_pqc::MlDsaKeypair::generate();
        let mut block = unsigned_block(1, 0);
        // Sign with attacker's key, not validator 0's key
        let digest = block.digest();
        let bad_sig = misaka_pqc::pq_sign::ml_dsa_sign_raw(&attacker.secret_key, &digest.0)
            .expect("attacker signing");
        block.signature = bad_sig.as_bytes().to_vec();
        assert!(matches!(
            v.verify(&block),
            Err(BlockVerifyError::InvalidSignature { .. })
        ));
    }

    #[test]
    fn cr1_wrong_author_signature_rejected() {
        let (tvs, v) = setup();
        let mut block = unsigned_block(1, 0);
        // Sign as validator 1 but claim to be validator 0
        tvs.sign_block(1, &mut block);
        assert!(matches!(
            v.verify(&block),
            Err(BlockVerifyError::InvalidSignature { .. })
        ));
    }

    #[test]
    fn cr1_legitimate_signature_accepted() {
        let (tvs, v) = setup();
        let block = signed_block(&tvs, 1, 0);
        v.verify(&block).expect("legitimate signature must pass");
    }

    // ── CR-2 Regression: cross-network replay prevention ──

    #[test]
    fn cr2_testnet_block_rejected_on_mainnet() {
        let tvs = TestValidatorSet::new(4);
        let testnet_ctx = misaka_types::chain_context::ChainContext::new(2, [0u8; 32]);
        let mainnet_ctx = misaka_types::chain_context::ChainContext::new(1, [0u8; 32]);

        // Sign block for testnet (Phase 2b: IntentMessage-based)
        let testnet_app_id = misaka_types::intent::AppId::new(2, [0u8; 32]);
        let mut block = unsigned_block(1, 0);
        let testnet_digest = block.signing_digest_v2(testnet_app_id);
        block.signature = tvs.signers[0].sign(&testnet_digest.0);

        // Verify on mainnet verifier — must fail
        let mainnet_verifier =
            BlockVerifier::new(tvs.committee(), 0, Arc::new(MlDsa65Verifier), mainnet_ctx);
        assert!(
            matches!(
                mainnet_verifier.verify(&block),
                Err(BlockVerifyError::InvalidSignature { .. })
            ),
            "testnet-signed block must NOT verify on mainnet"
        );
    }

    #[test]
    fn cr2_fork_block_rejected_on_main_chain() {
        let tvs = TestValidatorSet::new(4);
        let chain_a = misaka_types::chain_context::ChainContext::new(1, [0xAA; 32]);
        let chain_b = misaka_types::chain_context::ChainContext::new(1, [0xBB; 32]);

        // Sign block for chain_a (same chain_id, different genesis)
        let app_id_a = misaka_types::intent::AppId::new(1, [0xAA; 32]);
        let mut block = unsigned_block(1, 0);
        let digest_a = block.signing_digest_v2(app_id_a);
        block.signature = tvs.signers[0].sign(&digest_a.0);

        // Verify on chain_b verifier — must fail
        let verifier_b = BlockVerifier::new(tvs.committee(), 0, Arc::new(MlDsa65Verifier), chain_b);
        assert!(
            matches!(
                verifier_b.verify(&block),
                Err(BlockVerifyError::InvalidSignature { .. })
            ),
            "block from fork A must NOT verify on fork B"
        );
    }

    #[test]
    fn cr2_same_chain_context_verifies() {
        let tvs = TestValidatorSet::new(4);
        let ctx = misaka_types::chain_context::ChainContext::new(1, [0xCC; 32]);

        let app_id = misaka_types::intent::AppId::new(1, [0xCC; 32]);
        let mut block = unsigned_block(1, 0);
        let digest = block.signing_digest_v2(app_id);
        block.signature = tvs.signers[0].sign(&digest.0);

        let verifier = BlockVerifier::new(tvs.committee(), 0, Arc::new(MlDsa65Verifier), ctx);
        verifier
            .verify(&block)
            .expect("same chain context must verify");
    }
}
