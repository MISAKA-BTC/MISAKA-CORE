use misaka_dag_types::block::*;
use super::dag_state::DagState;
use super::ancestor_selector::AncestorSelector;
use std::sync::Arc;

/// Core consensus engine — creates blocks and processes incoming blocks.
pub struct CoreEngine {
    pub authority: AuthorityIndex,
    pub epoch: Epoch,
    pending_transactions: Vec<Transaction>,
    max_transactions_per_block: usize,
    /// Block signer — produces ML-DSA-65 signatures for proposed blocks.
    /// In production: `MlDsa65Signer` (real dilithium3::detached_sign).
    /// In tests: `DummySigner` (structural-only).
    signer: Arc<dyn BlockSigner>,
}

impl CoreEngine {
    /// Create a new core engine with the given block signer.
    ///
    /// **Production:** pass `Arc::new(MlDsa65Signer::new(secret_key))`.
    /// **Tests:** pass `Arc::new(DummySigner)`.
    pub fn new(
        authority: AuthorityIndex,
        epoch: Epoch,
        max_tx: usize,
        signer: Arc<dyn BlockSigner>,
    ) -> Self {
        Self {
            authority,
            epoch,
            pending_transactions: Vec::new(),
            max_transactions_per_block: max_tx,
            signer,
        }
    }

    pub fn add_transactions(&mut self, txs: Vec<Transaction>) {
        self.pending_transactions.extend(txs);
    }

    /// Try to create a new block if conditions are met.
    /// Conditions: quorum of blocks exist from prior round.
    ///
    /// The block is signed with the injected `BlockSigner` (ML-DSA-65 in production).
    pub fn try_propose(&mut self, dag: &DagState) -> Option<Block> {
        let round = dag.highest_accepted_round() + 1;
        let ancestors = AncestorSelector::select(dag, self.authority, round);

        // Need quorum of ancestors to propose
        let ancestor_stake: u64 = ancestors.iter()
            .map(|a| dag.committee().stake(a.author))
            .sum();
        if ancestor_stake < dag.committee().quorum_threshold() {
            return None;
        }

        let tx_count = self.max_transactions_per_block.min(self.pending_transactions.len());
        let transactions: Vec<Transaction> = self.pending_transactions.drain(..tx_count).collect();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default().as_millis() as u64;

        // Build unsigned block to compute digest
        let mut block = Block {
            epoch: self.epoch,
            round,
            author: self.authority,
            timestamp_ms: timestamp,
            ancestors,
            transactions,
            commit_votes: vec![],
            tx_reject_votes: vec![],
            signature: vec![], // empty until signed
        };

        // Sign the block digest with ML-DSA-65 (production) or dummy (test)
        let digest = block.digest();
        match self.signer.sign_block(&digest.0) {
            Ok(sig) => {
                block.signature = sig;
            }
            Err(e) => {
                tracing::error!("Block signing failed: {}", e);
                return None;
            }
        }

        Some(block)
    }
}
