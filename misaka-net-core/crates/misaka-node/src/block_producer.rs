//! Block producer — proposes new blocks at configured interval.
//!
//! ## Monero-style Output Model
//!
//! Transaction outputs are PUBLIC chain data. They are stored in every block
//! and served to any requesting wallet. The wallet uses its private view key
//! to determine ownership. The node never knows which wallet owns which output.
//!
//! "Storing outputs" ≠ "revealing the owner"

use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tracing::info;

use crate::chain_store::{ChainStore, StoredTx, TxOutput, TxInput};

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
    pub pending_txs: VecDeque<PendingTx>,
    pub spent_key_images: std::collections::HashSet<[u8; 32]>,
    pub faucet_drips: std::collections::HashMap<String, u64>,
}

impl NodeState {
    pub fn mempool_size(&self) -> usize {
        self.pending_txs.len()
    }
}

pub type SharedState = Arc<RwLock<NodeState>>;

/// Parse outputs from the raw transaction JSON.
///
/// The raw_json contains the submitted transaction body which includes
/// an "outputs" array with address and amount for each output.
/// These are PUBLIC chain data — not secret.
fn parse_outputs_from_raw(raw_json: &str) -> Vec<TxOutput> {
    let parsed: serde_json::Value = match serde_json::from_str(raw_json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let outputs = match parsed["outputs"].as_array() {
        Some(arr) => arr,
        None => return Vec::new(),
    };

    outputs.iter().enumerate().map(|(i, o)| {
        let address = o["address"].as_str().unwrap_or("").to_string();
        let amount = o["amount"].as_u64().unwrap_or(0);

        // View tag: use provided or auto-generate for fast wallet scanning.
        // view_tag = SHA3-256("MISAKA:viewtag:v1:" || address || amount)[0:2] hex
        // This is PUBLIC data — does not reveal ownership.
        let view_tag = o["viewTag"].as_str()
            .or(o["view_tag"].as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                use sha3::{Sha3_256, Digest};
                let mut h = Sha3_256::new();
                h.update(b"MISAKA:viewtag:v1:");
                h.update(address.as_bytes());
                h.update(amount.to_le_bytes());
                h.update((i as u32).to_le_bytes());
                let hash: [u8; 32] = h.finalize().into();
                hex::encode(&hash[..2])
            });

        TxOutput {
            address,
            amount,
            output_index: i as u32,
            one_time_pubkey: o["oneTimePubkey"].as_str()
                .or(o["one_time_pubkey"].as_str())
                .unwrap_or("").to_string(),
            ephemeral_pubkey: o["ephemeralPubkey"].as_str()
                .or(o["ephemeral_pubkey"].as_str())
                .unwrap_or("").to_string(),
            view_tag,
        }
    }).collect()
}

/// Parse inputs from the raw transaction JSON.
fn parse_inputs_from_raw(raw_json: &str, key_images: &[[u8; 32]]) -> Vec<TxInput> {
    let parsed: serde_json::Value = serde_json::from_str(raw_json).unwrap_or_default();

    // Build from explicit inputs array if present
    if let Some(inputs) = parsed["inputs"].as_array() {
        return inputs.iter().map(|inp| {
            TxInput {
                key_image: inp["keyImage"].as_str()
                    .or(inp["key_image"].as_str())
                    .unwrap_or("").to_string(),
                ring_size: inp["ringSize"].as_u64()
                    .or(inp["ring_size"].as_u64())
                    .unwrap_or(0) as usize,
            }
        }).collect();
    }

    // Fallback: build from key_images array
    key_images.iter().map(|ki| {
        TxInput {
            key_image: hex::encode(ki),
            ring_size: 4,
        }
    }).collect()
}

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

        let max_txs = 1000;
        let mut block_txs: Vec<StoredTx> = Vec::new();
        let mut total_fees = 0u64;

        while let Some(ptx) = s.pending_txs.pop_front() {
            if block_txs.len() >= max_txs { break; }

            for ki in &ptx.key_images {
                s.spent_key_images.insert(*ki);
            }

            total_fees += ptx.fee;
            let raw_len = ptx.raw_json.len();

            // Parse outputs and inputs from raw transaction JSON
            // These are PUBLIC chain data stored in every block
            let outputs = parse_outputs_from_raw(&ptx.raw_json);
            let inputs = parse_inputs_from_raw(&ptx.raw_json, &ptx.key_images);

            block_txs.push(StoredTx {
                hash: ptx.tx_hash,
                fee: ptx.fee,
                input_count: ptx.input_count,
                output_count: outputs.len().max(ptx.output_count),
                timestamp_ms: ptx.submitted_at_ms,
                status: "confirmed".into(),
                key_images: ptx.key_images.clone(),
                size: raw_len,
                has_payload: false,
                outputs,
                inputs,
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
