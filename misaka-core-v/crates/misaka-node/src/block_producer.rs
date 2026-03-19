//! Block producer — proposes candidate blocks, delegates to consensus validation.
//!
//! ## Architecture (Mainnet)
//!
//! INVARIANT: block_producer NEVER mutates chain state directly.
//! ALL state transitions go through `execute_block()` which calls
//! `validate_and_apply_block()` — the single consensus validation path.
//!
//! ## Phase 1.1 Fix: Consensus Bypass Elimination
//!
//! Previously, block_producer called `utxo_set.apply_block_atomic()` directly,
//! bypassing full consensus validation. Now all blocks (including empty ones)
//! go through `execute_block()` → `validate_and_apply_block()`.
//!
//! FORBIDDEN in this module:
//! - utxo_set.apply_block_atomic()
//! - utxo_set.add_output()
//! - utxo_set.record_nullifier()
//! - Any direct state mutation

use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tracing::info;

use misaka_types::utxo::{UtxoTransaction, OutputRef};
use misaka_mempool::UtxoMempool;
use misaka_storage::utxo_set::UtxoSet;
use misaka_consensus::block_validation::{BlockCandidate, VerifiedTx};
use misaka_consensus::tx_resolve;
use misaka_execution::block_apply::execute_block;

use crate::chain_store::{ChainStore, StoredTx, TxOutput, TxInput};

/// Shared node state.
///
/// INVARIANT: Only `execute_block()` → `validate_and_apply_block()` may modify `utxo_set`.
pub struct NodeState {
    pub chain: ChainStore,
    pub height: u64,
    pub tx_count_total: u64,
    pub validator_count: usize,
    pub genesis_timestamp_ms: u64,
    pub chain_id: u32,
    pub chain_name: String,
    pub version: String,
    pub mempool: UtxoMempool,
    /// UTXO set — ONLY modified via execute_block().
    pub utxo_set: UtxoSet,
    pub coinbase_pending: Vec<UtxoTransaction>,
    pub faucet_drips: std::collections::HashMap<String, u64>,
    pub faucet_amount: u64,
    pub faucet_cooldown_ms: u64,
}

impl NodeState {
    pub fn mempool_size(&self) -> usize {
        self.mempool.len()
    }
}

pub type SharedState = Arc<RwLock<NodeState>>;

/// Convert a verified UtxoTransaction to StoredTx for chain storage.
fn verified_tx_to_stored(tx: &UtxoTransaction, now_ms: u64) -> StoredTx {
    let tx_hash = tx.tx_hash();
    let outputs: Vec<TxOutput> = tx.outputs.iter().enumerate().map(|(i, o)| {
        let view_tag = {
            use sha3::{Sha3_256, Digest};
            let mut h = Sha3_256::new();
            h.update(b"MISAKA:viewtag:v1:");
            h.update(&o.one_time_address);
            h.update(o.amount.to_le_bytes());
            h.update(&tx_hash);
            h.update((i as u32).to_le_bytes());
            let hash: [u8; 32] = h.finalize().into();
            hex::encode(&hash[..2])
        };
        TxOutput {
            address: hex::encode(&o.one_time_address),
            amount: o.amount, output_index: i as u32,
            one_time_pubkey: String::new(), ephemeral_pubkey: String::new(),
            view_tag,
        }
    }).collect();
    let inputs: Vec<TxInput> = tx.inputs.iter().map(|inp| {
        let source_ref = inp.ring_members.first();
        TxInput {
            key_image: hex::encode(inp.key_image),
            ring_size: inp.ring_members.len(),
            source_tx_hash: source_ref.map(|r| hex::encode(&r.tx_hash[..8])).unwrap_or_default(),
            source_output_index: source_ref.map(|r| r.output_index).unwrap_or(0),
        }
    }).collect();
    let key_images: Vec<[u8; 32]> = tx.inputs.iter().map(|inp| inp.key_image).collect();
    let size = serde_json::to_vec(tx).map(|v| v.len()).unwrap_or(0);
    StoredTx {
        hash: tx_hash, fee: tx.fee,
        input_count: tx.inputs.len(), output_count: tx.outputs.len(),
        timestamp_ms: now_ms, status: "confirmed".into(),
        key_images, size, has_payload: !tx.extra.is_empty(),
        outputs, inputs,
    }
}

/// Register spending keys for newly created outputs (Phase 1.2 fix).
///
/// Without this, new UTXOs cannot be used as ring members in future
/// transactions because the verifier cannot resolve their public keys.
fn register_output_spending_keys(utxo_set: &mut UtxoSet, tx: &UtxoTransaction) {
    let tx_hash = tx.tx_hash();
    for (idx, output) in tx.outputs.iter().enumerate() {
        if let Some(ref spk_bytes) = output.spending_pubkey {
            let outref = OutputRef { tx_hash, output_index: idx as u32 };
            utxo_set.register_spending_key(outref, spk_bytes.clone());
        }
    }
}

/// Block production loop.
///
/// ALL blocks (including empty) go through execute_block() to maintain
/// height synchronization between utxo_set and chain_store (Phase 2.4 fix).
pub async fn run_block_producer(
    state: SharedState,
    block_time_secs: u64,
    proposer_index: usize,
) {
    let mut ticker = interval(Duration::from_secs(block_time_secs));
    ticker.tick().await;
    info!("Block producer started (interval={}s, proposer={})", block_time_secs, proposer_index);

    loop {
        ticker.tick().await;
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let mut guard = state.write().await;
        let s = &mut *guard;

        let new_height = s.height + 1;
        let slot = new_height;
        let parent_hash = s.chain.tip_hash;

        // ── Phase 1: Read candidates (NO state mutation) ──
        let candidate_txs: Vec<UtxoTransaction> = s.mempool.top_by_fee(256)
            .into_iter().cloned().collect();
        let coinbase_txs: Vec<UtxoTransaction> = s.coinbase_pending.drain(..).collect();
        let all_txs: Vec<&UtxoTransaction> = coinbase_txs.iter()
            .chain(candidate_txs.iter()).collect();

        // ── Phase 2: Resolve txs into VerifiedTx (NO state mutation) ──
        let mut verified_txs: Vec<VerifiedTx> = Vec::new();
        for tx in &all_txs {
            if tx.inputs.is_empty() {
                // Coinbase/Faucet: no ring resolution needed
                verified_txs.push(VerifiedTx {
                    tx: (*tx).clone(),
                    ring_pubkeys: vec![], ring_amounts: vec![],
                    ring_sigs: vec![], ki_proofs: vec![],
                });
                continue;
            }
            match tx_resolve::resolve_tx(tx, &s.utxo_set) {
                Ok(vtx) => verified_txs.push(vtx),
                Err(e) => {
                    tracing::warn!("TX resolution failed for {}: {}. Excluding.",
                        hex::encode(&tx.tx_hash()[..8]), e);
                    s.mempool.remove(&tx.tx_hash());
                }
            }
        }

        // ── Phase 3: Assemble BlockCandidate ──
        let block = BlockCandidate {
            height: new_height, slot, parent_hash,
            transactions: verified_txs,
            proposer_signature: None, // Single-proposer testnet
        };

        // ── Phase 4: EXECUTE via consensus — SINGLE VALIDATION PATH ──
        match execute_block(&block, &mut s.utxo_set, None) {
            Ok(result) => {
                // Phase 5: Register spending keys
                for vtx in &block.transactions {
                    register_output_spending_keys(&mut s.utxo_set, &vtx.tx);
                }
                // Phase 6: Update chain store + evict from mempool
                let mut block_stored_txs: Vec<StoredTx> = Vec::new();
                for vtx in &block.transactions {
                    let tx = &vtx.tx;
                    s.mempool.remove(&tx.tx_hash());
                    for inp in &tx.inputs { s.mempool.mark_spent(inp.key_image); }
                    block_stored_txs.push(verified_tx_to_stored(tx, now_ms));
                }
                s.tx_count_total += result.tx_count as u64;
                // Compute REAL state root from UTXO + nullifier state (C1 audit fix)
                let state_root = s.utxo_set.compute_state_root();
                let header = s.chain.append_block(
                    result.tx_count, result.total_fees,
                    proposer_index, now_ms, block_stored_txs,
                    state_root,
                );
                s.height = header.height;
                let h = hex::encode(&header.hash[..8]);
                if result.tx_count > 0 {
                    info!("⛏  Block #{} | hash={}… | txs={} | fees={} | created={} | mempool={}",
                        header.height, h, result.tx_count, result.total_fees,
                        result.utxos_created, s.mempool.len());
                } else {
                    info!("⛏  Block #{} | hash={}… | empty", header.height, h);
                }
            }
            Err(e) => {
                tracing::error!("Block #{} REJECTED: {}. No state modified.", new_height, e);
            }
        }
    }
}
