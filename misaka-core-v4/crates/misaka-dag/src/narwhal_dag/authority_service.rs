// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation
//
//! AuthorityService — incoming RPC handler for peer consensus messages.
//!
//! Sui equivalent: `consensus/core/src/authority_service.rs`
//!
//! Handles incoming requests from other validators:
//! - Block submission (SendBlock)
//! - Block fetch (FetchBlocks)
//! - Commit fetch (FetchCommits)
//!
//! Previously this logic was in `misaka-node/src/dag_rpc_legacy.rs`
//! (10,818 LOC) mixed with node-specific RPC handlers. AuthorityService
//! isolates the consensus-specific peer handlers.

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::authority_node::AuthorityNode;
use super::context::Context;
use super::dag_state::DagState;
use super::metrics::ConsensusMetrics;
use super::runtime::ConsensusMessage;
use crate::narwhal_types::block::*;
use crate::narwhal_types::commit::*;

/// Incoming block from a peer — result of processing.
#[derive(Debug)]
pub enum BlockResponse {
    /// Block accepted into the consensus pipeline.
    Accepted,
    /// Block rejected (bad signature, structural error, etc.).
    Rejected(String),
    /// Block already known (duplicate).
    Duplicate,
    /// Service is shutting down.
    Unavailable,
}

/// Service for handling incoming consensus messages from peers.
///
/// Owns a reference to the consensus runtime's message channel and
/// DAG state for serving read requests.
pub struct AuthorityService {
    /// Consensus message channel.
    msg_tx: tokio::sync::mpsc::Sender<ConsensusMessage>,
    /// DAG state for read-only queries.
    dag_state: Arc<RwLock<DagState>>,
    /// Metrics.
    metrics: Arc<ConsensusMetrics>,
    /// Context for epoch info.
    context: Context,
}

impl AuthorityService {
    /// Create a new authority service.
    pub fn new(
        msg_tx: tokio::sync::mpsc::Sender<ConsensusMessage>,
        dag_state: Arc<RwLock<DagState>>,
        metrics: Arc<ConsensusMetrics>,
        context: Context,
    ) -> Self {
        Self {
            msg_tx,
            dag_state,
            metrics,
            context,
        }
    }

    /// Handle an incoming block from a peer.
    ///
    /// Performs structural pre-validation at the network edge, then
    /// forwards to the consensus runtime for full verification.
    pub async fn handle_send_block(&self, block: Block) -> BlockResponse {
        // Structural pre-validation (cheap, no crypto)
        if block.author >= self.context.committee_size() as u32 {
            return BlockResponse::Rejected(format!(
                "author {} exceeds committee size {}",
                block.author,
                self.context.committee_size()
            ));
        }
        if block.round == 0 {
            return BlockResponse::Rejected("round 0 is reserved for genesis".into());
        }
        if block.signature.len() != self.context.protocol_config.ml_dsa_sig_len() as usize {
            return BlockResponse::Rejected(format!(
                "signature length {} != expected {}",
                block.signature.len(),
                self.context.protocol_config.ml_dsa_sig_len()
            ));
        }

        // Forward to consensus runtime
        let vb = VerifiedBlock::new_pending_verification(block);
        match self.msg_tx.try_send(ConsensusMessage::NewBlock(vb)) {
            Ok(()) => BlockResponse::Accepted,
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                warn!("Consensus message channel full — dropping incoming block");
                BlockResponse::Unavailable
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                BlockResponse::Unavailable
            }
        }
    }

    /// Handle a block fetch request from a peer.
    ///
    /// Returns blocks in the requested round range.
    pub async fn handle_fetch_blocks(
        &self,
        since_round: Round,
        limit: usize,
    ) -> Vec<Block> {
        let limit = limit.min(1000); // cap
        let dag = self.dag_state.read().await;
        let highest = dag.highest_accepted_round();
        let mut blocks = Vec::new();

        for round in since_round..=highest {
            for block in dag.get_blocks_at_round(round) {
                blocks.push(block.inner().clone());
                if blocks.len() >= limit {
                    return blocks;
                }
            }
        }

        blocks
    }

    /// Handle a commit fetch request from a peer.
    ///
    /// Returns commits in the requested index range.
    pub async fn handle_fetch_commits(
        &self,
        since_index: CommitIndex,
        limit: usize,
    ) -> Vec<CommittedSubDag> {
        let limit = limit.min(100); // cap
        let dag = self.dag_state.read().await;
        let mut commits = Vec::new();
        let mut idx = since_index;
        loop {
            match dag.get_commit(idx) {
                Some(commit) => {
                    commits.push(commit.clone());
                    if commits.len() >= limit {
                        break;
                    }
                    idx += 1;
                }
                None => break,
            }
        }
        commits
    }

    /// Get the current epoch.
    pub fn epoch(&self) -> u64 {
        self.context.epoch()
    }

    /// Get the authority index.
    pub fn authority_index(&self) -> AuthorityIndex {
        self.context.own_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::dag_state::DagStateConfig;

    #[tokio::test]
    async fn test_reject_invalid_author() {
        let ctx = Context::new_for_test(4);
        let (msg_tx, _msg_rx) = tokio::sync::mpsc::channel(100);
        let dag = Arc::new(RwLock::new(DagState::new(
            (*ctx.committee).clone(),
            DagStateConfig::default(),
        )));
        let metrics = Arc::new(ConsensusMetrics::new());
        let service = AuthorityService::new(msg_tx, dag, metrics, ctx);

        let block = Block {
            epoch: 0,
            round: 1,
            author: 99, // invalid — committee has 4
            timestamp_ms: 1000,
            ancestors: vec![],
            transactions: vec![],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xAA; 3309],
        };

        let resp = service.handle_send_block(block).await;
        assert!(matches!(resp, BlockResponse::Rejected(_)));
    }

    #[tokio::test]
    async fn test_reject_round_zero() {
        let ctx = Context::new_for_test(4);
        let (msg_tx, _msg_rx) = tokio::sync::mpsc::channel(100);
        let dag = Arc::new(RwLock::new(DagState::new(
            (*ctx.committee).clone(),
            DagStateConfig::default(),
        )));
        let metrics = Arc::new(ConsensusMetrics::new());
        let service = AuthorityService::new(msg_tx, dag, metrics, ctx);

        let block = Block {
            epoch: 0,
            round: 0, // invalid
            author: 0,
            timestamp_ms: 1000,
            ancestors: vec![],
            transactions: vec![],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![0xAA; 3309],
        };

        let resp = service.handle_send_block(block).await;
        assert!(matches!(resp, BlockResponse::Rejected(_)));
    }

    /// Tests that a structurally valid block with real ML-DSA-65 signature
    /// passes pre-validation and is forwarded to the consensus runtime.
    ///
    /// NOTE: `handle_send_block` only performs structural pre-validation
    /// (author range, round != 0, signature length). Full ML-DSA-65
    /// verification happens in `CoreEngine::process_block`. This test
    /// uses a real signature to ensure the block is also valid end-to-end,
    /// not just structurally correct.
    ///
    /// Phase 1-3 fix: replaced `0xAA; 3309` mock signature with real
    /// ML-DSA-65 signature. The old test name `test_accept_valid_block`
    /// was misleading — it only tested structural pre-validation, not
    /// signature validity.
    #[tokio::test]
    async fn test_forward_real_signed_block() {
        use crate::narwhal_types::block::TestValidatorSet;

        let vs = TestValidatorSet::new(4);
        let committee = vs.committee();
        let ctx = Context::new_for_test(4);
        let (msg_tx, mut msg_rx) = tokio::sync::mpsc::channel(100);
        let dag = Arc::new(RwLock::new(DagState::new(
            committee.clone(),
            DagStateConfig::default(),
        )));
        let metrics = Arc::new(ConsensusMetrics::new());
        let service = AuthorityService::new(msg_tx, dag, metrics, ctx);

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_millis() as u64;

        let mut block = Block {
            epoch: 0,
            round: 1,
            author: 0,
            timestamp_ms: now_ms,
            ancestors: vec![],
            transactions: vec![vec![1, 2, 3]],
            commit_votes: vec![],
            tx_reject_votes: vec![],
            state_root: [0u8; 32],
            signature: vec![], // will be replaced by real signature
        };
        vs.sign_block(0, &mut block);
        assert_eq!(block.signature.len(), 3309, "ML-DSA-65 signature must be 3309 bytes");

        let resp = service.handle_send_block(block.clone()).await;
        assert!(matches!(resp, BlockResponse::Accepted));

        // Verify it was forwarded to the runtime
        let msg = msg_rx.try_recv().unwrap();
        assert!(matches!(msg, ConsensusMessage::NewBlock(_)));

        // Additionally verify the signature is actually valid via BlockVerifier.
        // This uses the SAME TestValidatorSet's committee (with matching public
        // keys) to ensure the block passes full ML-DSA-65 verification.
        let verifier = vs.verifier(0);
        assert!(
            verifier.verify(&block).is_ok(),
            "block signature must pass full ML-DSA-65 verification"
        );
    }
}
