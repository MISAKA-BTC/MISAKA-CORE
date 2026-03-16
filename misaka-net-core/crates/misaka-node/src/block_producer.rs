//! Block producer — proposes new blocks at configured interval.
//!
//! Drains pending transactions from the mempool into each block.

use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tracing::info;

use crate::chain_store::{ChainStore, StoredTx};

/// A pending transaction awaiting inclusion in a block.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingTx {
    pub tx_hash: [u8; 32],
    pub raw_json: String,
    pub fee: u64,
    pub input_count: usize,
    pub output_count: usize,
    pub key_images: Vec<[u8; 32]>,
    pub submitted_at_ms: u64,
}

/// Shared node state accessible from block producer + RPC + P2P.
pub struct NodeState {
    pub chain: ChainStore,
    pub height: u64,
    pub tx_count_total: u64,
    pub validator_count: usize,
    pub genesis_timestamp_ms: u64,
    pub chain_id: u32,
    pub chain_name: String,
    pub version: String,
    /// Pending transactions (mempool).
    pub pending_txs: VecDeque<PendingTx>,
    /// Spent key images (double-spend protection).
    pub spent_key_images: std::collections::HashSet<[u8; 32]>,
    /// Faucet drip tracking: address -> last drip timestamp.
    pub faucet_drips: std::collections::HashMap<String, u64>,
}

impl NodeState {
    pub fn mempool_size(&self) -> usize {
        self.pending_txs.len()
    }
}

pub type SharedState = Arc<RwLock<NodeState>>;

/// Start the block production loop.
pub async fn run_block_producer(
    state: SharedState,
    block_time_secs: u64,
    proposer_index: usize,
) {
    let mut ticker = interval(Duration::from_secs(block_time_secs));
    ticker.tick().await;

    info!(
        "Block producer started (interval={}s, proposer={})",
        block_time_secs, proposer_index
    );

    loop {
        ticker.tick().await;
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;

        let mut s = state.write().await;

        // Drain pending TXs into this block (up to 1000)
        let max_txs = 1000;
        let mut block_txs: Vec<StoredTx> = Vec::new();
        let mut total_fees = 0u64;

        while let Some(ptx) = s.pending_txs.pop_front() {
            if block_txs.len() >= max_txs { break; }

            // Mark key images as spent
            for ki in &ptx.key_images {
                s.spent_key_images.insert(*ki);
            }

            total_fees += ptx.fee;
            let raw_len = ptx.raw_json.len();
            block_txs.push(StoredTx {
                hash: ptx.tx_hash,
                fee: ptx.fee,
                input_count: ptx.input_count,
                output_count: ptx.output_count,
                timestamp_ms: ptx.submitted_at_ms,
                status: "confirmed".into(),
                key_images: ptx.key_images.clone(),
                size: raw_len,
                has_payload: false,
            });
        }

        let tx_count = block_txs.len();
        s.tx_count_total += tx_count as u64;

        let header = s.chain.append_block(tx_count, total_fees, proposer_index, now_ms, block_txs);
        s.height = header.height;

        let hash_hex = hex::encode(&header.hash[..8]);
        let parent_hex = hex::encode(&header.parent_hash[..8]);

        if tx_count > 0 {
            info!(
                "⛏  Block #{} | hash={}… | txs={} | fees={} | mempool={}",
                header.height, hash_hex, tx_count, total_fees, s.pending_txs.len()
            );
        } else {
            info!(
                "⛏  Block #{} | hash={}… | parent={}… | empty",
                header.height, hash_hex, parent_hex
            );
        }
    }
}
