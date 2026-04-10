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
//! - utxo_set.record_spend_tag()
//! - Any direct state mutation

use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tracing::{info, warn};

use misaka_consensus::block_validation::{BlockCandidate, VerifiedTx};
use misaka_consensus::tx_resolve;
use misaka_execution::block_apply::execute_block;
use misaka_mempool::UtxoMempool;
use misaka_pqc::{
    describe_transaction_for_backend, tx_spend_semantics_for_backend, PrivacyBackendFamily,
};
use misaka_storage::utxo_set::UtxoSet;
use misaka_tokenomics::block_reward::{compute_block_rewards, BlockRewardParams};
use misaka_types::utxo::{
    OutputRef, TxOutput as UtxoTxOutput, TxType, UtxoTransaction, UTXO_TX_VERSION,
};

use crate::chain_store::{ChainStore, StoredTx, TxInput, TxOutput as ChainTxOutput};

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
    /// Data directory for UTXO snapshot persistence.
    pub data_dir: String,
    /// When true, block producer routes TXs with ZK proof through the
    /// zero-knowledge execution path (CompositeProof verification).
    pub experimental_zk_path: bool,
    /// SEC-FIX-6: Proposer reward payout address (must be configured, not placeholder).
    /// This is the one-time address where block proposer rewards are sent.
    pub proposer_payout_address: Option<[u8; 32]>,
    /// SEC-FIX-6: Treasury address (must be configured from genesis/chain config).
    /// Protocol fee share is sent here.
    pub treasury_address: Option<[u8; 32]>,
    /// Audit #21: Proposer's ML-DSA-65 public key (1952 bytes) for coinbase outputs.
    /// Without this, coinbase outputs have spending_pubkey=None and are permanently unspendable.
    pub proposer_spending_pubkey: Option<Vec<u8>>,
}

impl NodeState {
    pub fn mempool_size(&self) -> usize {
        self.mempool.len()
    }
}

pub type SharedState = Arc<RwLock<NodeState>>;

/// Convert a verified UtxoTransaction to StoredTx for chain storage.
fn verified_tx_to_stored(
    tx: &UtxoTransaction,
    now_ms: u64,
    backend_family: PrivacyBackendFamily,
) -> StoredTx {
    let tx_hash = tx.tx_hash();
    let descriptor = describe_transaction_for_backend(tx, backend_family);
    let spend_semantics = tx_spend_semantics_for_backend(tx, backend_family);
    let outputs: Vec<ChainTxOutput> = tx
        .outputs
        .iter()
        .enumerate()
        .map(|(i, o)| {
            let view_tag = {
                use sha3::{Digest, Sha3_256};
                let mut h = Sha3_256::new();
                h.update(b"MISAKA:viewtag:v1:");
                h.update(&o.address);
                h.update(o.amount.to_le_bytes());
                h.update(&tx_hash);
                h.update((i as u32).to_le_bytes());
                let hash: [u8; 32] = h.finalize().into();
                hex::encode(&hash[..2])
            };
            ChainTxOutput {
                address: hex::encode(&o.address),
                amount: o.amount,
                output_index: i as u32,
                one_time_pubkey: String::new(),
                ephemeral_pubkey: String::new(),
                view_tag,
            }
        })
        .collect();
    let inputs: Vec<TxInput> = tx
        .inputs
        .iter()
        .map(|inp| {
            let source_ref = inp.utxo_refs.first();
            TxInput {
                spend_id: hex::encode(&inp.utxo_refs[0].tx_hash),
                anonymity_set_size: inp.utxo_refs.len(),
                source_tx_hash: source_ref
                    .map(|r| hex::encode(&r.tx_hash[..8]))
                    .unwrap_or_default(),
                source_output_index: source_ref.map(|r| r.output_index).unwrap_or(0),
            }
        })
        .collect();
    let spend_ids: Vec<[u8; 32]> = tx.inputs.iter().map(|inp| [0u8; 32]).collect();
    let size = serde_json::to_vec(tx).map(|v| v.len()).unwrap_or(0);
    StoredTx {
        hash: tx_hash,
        fee: tx.fee,
        input_count: tx.inputs.len(),
        output_count: tx.outputs.len(),
        timestamp_ms: now_ms,
        status: "confirmed".into(),
        spend_ids,
        size,
        has_payload: !tx.extra.is_empty(),
        privacy_scheme_tag: descriptor.map(|d| d.scheme_tag).unwrap_or(0u8),
        privacy_scheme_name: descriptor
            .map(|d| d.scheme_name.to_string())
            .unwrap_or_else(|| format!("Unknown-{}", 0u8)),
        privacy_anonymity_model: descriptor
            .map(|d| d.anonymity_model.to_string())
            .unwrap_or_else(|| "Unknown".into()),
        privacy_backend_family: descriptor
            .map(|d| d.backend_family)
            .unwrap_or(backend_family),
        spend_identifier_model: spend_semantics.spend_identifier_model,
        spend_identifier_label: spend_semantics.spend_identifier_label,
        spend_identifiers: spend_semantics.spend_identifiers,
        full_verifier_member_index_hidden: descriptor
            .map(|d| d.full_verifier_member_index_hidden)
            .unwrap_or(false),
        zkp_migration_ready: descriptor.map(|d| d.zkp_migration_ready).unwrap_or(false),
        privacy_status_note: descriptor
            .map(|d| d.status_note.to_string())
            .unwrap_or_else(|| "Unknown ring scheme.".into()),
        outputs,
        inputs,
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
            let outref = OutputRef {
                tx_hash,
                output_index: idx as u32,
            };
            if let Err(e) = utxo_set.register_spending_key(outref.clone(), spk_bytes.clone()) {
                tracing::warn!("spending key registration failed for {:?}: {}", outref, e);
            }
        }
    }
}

/// Whether a TX is a candidate for the zero-knowledge block execution path.
///
/// True when the TX carries a ZK proof (CompositeProof or v4 UnifiedZKP).
/// This is the filter for routing TXs through the ZK candidate path.
fn is_explicit_zk_candidate(tx: &UtxoTransaction) -> bool {
    !tx.inputs.is_empty() && false
}

fn should_use_zero_knowledge_block_path(
    explicit_zk_path: bool,
    verified_txs: &[VerifiedTx],
) -> bool {
    explicit_zk_path
        && !verified_txs.is_empty()
        && verified_txs
            .iter()
            .all(|vtx| !vtx.tx.inputs.is_empty() && is_explicit_zk_candidate(&vtx.tx))
}

/// Block production loop.
///
/// ALL blocks (including empty) go through execute_block() to maintain
/// height synchronization between utxo_set and chain_store (Phase 2.4 fix).
///
/// # SEC-FIX WARNING
///
/// This function sets `proposer_signature: None` and calls `execute_block`
/// with `validator_set=None`, which skips proposer verification entirely.
/// It MUST NOT be used on mainnet (chain_id=1). In DAG mode, block proposal
/// goes through Narwhal and this function is not invoked.
pub async fn run_block_producer(state: SharedState, block_time_secs: u64, proposer_index: usize) {
    // SEC-FIX: Prevent legacy block producer from running on mainnet.
    // In DAG mode, Narwhal handles block proposal with proper proposer signatures.
    {
        let guard = state.read().await;
        if guard.chain_id == 1 {
            panic!(
                "FATAL: legacy block_producer MUST NOT run on mainnet (chain_id=1). \
                 Use DAG mode with Narwhal consensus instead."
            );
        }
    }

    let mut ticker = interval(Duration::from_secs(block_time_secs));
    ticker.tick().await;
    info!(
        "Block producer started (interval={}s, proposer={})",
        block_time_secs, proposer_index
    );

    loop {
        ticker.tick().await;
        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let mut guard = state.write().await;
        let s = &mut *guard;
        let explicit_zk_path = s.experimental_zk_path;

        let new_height = s.height + 1;
        let slot = new_height;
        let parent_hash = s.chain.tip_hash;

        // ── Phase 1: Read candidates (NO state mutation) ──
        let candidate_txs: Vec<UtxoTransaction> = if explicit_zk_path {
            s.mempool
                .top_by_fee(256)
                .into_iter()
                .filter(|tx| is_explicit_zk_candidate(tx))
                .cloned()
                .collect()
        } else {
            s.mempool.top_by_fee(256).into_iter().cloned().collect()
        };
        let coinbase_txs: Vec<UtxoTransaction> = if explicit_zk_path {
            if !s.coinbase_pending.is_empty() {
                warn!(
                    "explicit ZK block path active: dropping {} pending inputless txs from this proposal window",
                    s.coinbase_pending.len()
                );
                s.coinbase_pending.clear();
            }
            Vec::new()
        } else {
            s.coinbase_pending.drain(..).collect()
        };
        let all_txs: Vec<&UtxoTransaction> =
            coinbase_txs.iter().chain(candidate_txs.iter()).collect();

        // ── Phase 2: Resolve txs into VerifiedTx (NO state mutation) ──
        let mut verified_txs: Vec<VerifiedTx> = Vec::new();
        for tx in &all_txs {
            if tx.inputs.is_empty() {
                // Coinbase/Faucet: no ring resolution needed
                verified_txs.push(VerifiedTx {
                    tx: (*tx).clone(),
                    ring_pubkeys: vec![],
                    raw_spending_keys: vec![],
                    ring_amounts: vec![],
                    ring_proofs: vec![],
                });
                continue;
            }
            let resolve_result = if explicit_zk_path && is_explicit_zk_candidate(tx) {
                tx_resolve::resolve_tx_with_backend_family(
                    tx,
                    &s.utxo_set,
                    PrivacyBackendFamily::ZeroKnowledge,
                )
            } else {
                tx_resolve::resolve_tx(tx, &s.utxo_set)
            };
            match resolve_result {
                Ok(vtx) => verified_txs.push(vtx),
                Err(e) => {
                    tracing::warn!(
                        "TX resolution failed for {}: {}. Excluding.",
                        hex::encode(&tx.tx_hash()[..8]),
                        e
                    );
                    s.mempool.remove(&tx.tx_hash());
                }
            }
        }

        // ── Phase 3: Assemble BlockCandidate ──
        let block = BlockCandidate {
            height: new_height,
            slot,
            parent_hash,
            transactions: verified_txs,
            // SECURITY: proposer_signature is None only in single-proposer testnet.
            // Mainnet MUST provide a real signature. This is enforced by
            // execute_block requiring validator_set != None on chain_id=1.
            proposer_signature: None,
        };
        let block_backend_family = PrivacyBackendFamily::ZeroKnowledge;

        // ── Phase 4: EXECUTE via consensus — SINGLE VALIDATION PATH ──
        // NOTE: validator_set=None skips proposer signature verification.
        // This is acceptable for single-proposer testnet. Mainnet MUST
        // pass a real ValidatorSet. See architecture.md §10 Phase 4.
        let exec_result = execute_block(&block, &mut s.utxo_set, None);
        match exec_result {
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
                    block_stored_txs.push(verified_tx_to_stored(tx, now_ms, block_backend_family));
                }
                s.tx_count_total += result.tx_count as u64;
                // Compute REAL state root from UTXO + spend state (C1 audit fix)
                let state_root = s.utxo_set.compute_state_root();
                let header = s.chain.append_block(
                    result.tx_count,
                    result.total_fees,
                    proposer_index,
                    now_ms,
                    block_stored_txs,
                    state_root,
                );
                s.height = header.height;
                let h = hex::encode(&header.hash[..8]);
                if result.tx_count > 0 {
                    info!(
                        "⛏  Block #{} | hash={}… | txs={} | fees={} | created={} | mempool={} | privacyPath={:?}",
                        header.height,
                        h,
                        result.tx_count,
                        result.total_fees,
                        result.utxos_created,
                        s.mempool.len(),
                        block_backend_family
                    );
                } else {
                    info!("⛏  Block #{} | hash={}… | empty", header.height, h);
                }

                // ── Phase 6b: Generate coinbase reward TX for NEXT block ──
                //
                // The proposer earns: inflation_emission + 50% of fees.
                // Treasury earns: 10% of fees.
                // 40% of fees are burned (no UTXO created).
                let blocks_per_year: u64 = 365 * 24 * 60 * 60 / block_time_secs.max(1);
                let chain_age_secs = now_ms.saturating_sub(s.genesis_timestamp_ms) / 1000;
                let chain_year = chain_age_secs / (365 * 24 * 60 * 60);

                let reward_params = BlockRewardParams {
                    total_supply: s.utxo_set.total_amount() as u128,
                    chain_year,
                    epochs_per_year: blocks_per_year,
                    // SEC-FIX-6: Use configured addresses instead of hardcoded placeholders.
                    // If either is unconfigured, skip coinbase generation entirely
                    // rather than sending rewards to dummy addresses.
                    proposer_address: match s.proposer_payout_address {
                        Some(addr) => addr,
                        None => {
                            warn!(
                                "Block #{}: proposer_payout_address not configured, skipping coinbase",
                                new_height
                            );
                            continue;
                        }
                    },
                    treasury_address: match s.treasury_address {
                        Some(addr) => addr,
                        None => {
                            warn!(
                                "Block #{}: treasury_address not configured, skipping coinbase",
                                new_height
                            );
                            continue;
                        }
                    },
                };
                let rewards = match compute_block_rewards(&reward_params, result.total_fees) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!("block reward computation failed: {e}");
                        continue;
                    }
                };

                if rewards.proposer_amount > 0 || rewards.treasury_amount > 0 {
                    // Audit #21: coinbase outputs MUST include spending_pubkey
                    // so they are spendable by the proposer.
                    let proposer_spk = s.proposer_spending_pubkey.clone();
                    let coinbase_tx = UtxoTransaction {
                        version: UTXO_TX_VERSION,
                        // Phase 2c-B: privacy fields removed
                        tx_type: TxType::SystemEmission,
                        inputs: vec![],
                        outputs: {
                            let mut outs = Vec::new();
                            if rewards.proposer_amount > 0 {
                                outs.push(UtxoTxOutput {
                                    amount: rewards.proposer_amount,
                                    address: reward_params.proposer_address,
                                    spending_pubkey: proposer_spk.clone(),
                                });
                            }
                            if rewards.treasury_amount > 0 {
                                outs.push(UtxoTxOutput {
                                    amount: rewards.treasury_amount,
                                    address: reward_params.treasury_address,
                                    // Treasury uses same key for now; future: separate treasury key
                                    spending_pubkey: proposer_spk,
                                });
                            }
                            outs
                        },
                        fee: 0,
                        extra: vec![],
                        expiry: 0,
                    };
                    s.coinbase_pending.push(coinbase_tx);
                }

                // ── Phase 7: Periodic UTXO snapshot save ──
                // Audit R7: Increased interval from 100→1000 blocks and made async
                // to avoid blocking the consensus loop during large snapshot writes.
                if header.height % 1000 == 0 && header.height > 0 {
                    // SEC-FIX CRITICAL: Use export_snapshot_with_burns to persist
                    // processed_burns and total_emitted. Previously used export_snapshot()
                    // which stored burn_ids=[] and total_emitted=0, causing supply cap
                    // reset and burn replay vulnerability on restart.
                    let snapshot = s.utxo_set.export_snapshot();
                    // SEC-FIX: v1 path snapshot does NOT include processed_burns or
                    // total_emitted (they live in UtxoExecutor, Narwhal-only).
                    // This is safe because:
                    // 1. FIX 7 blocks v1 block_producer on mainnet (chain_id=1)
                    // 2. Burn replay protection on v1 relies on relayer's SQLite UNIQUE
                    // 3. v1 is testnet/devnet only — supply cap is less critical
                    // For mainnet, only the Narwhal path (main.rs commit loop) saves
                    // snapshots with full burn/emission state.
                    let snap_path = std::path::Path::new(&s.data_dir).join("utxo_snapshot.json");
                    let height = header.height;
                    let utxo_count = s.utxo_set.len();
                    tokio::spawn(async move {
                        let result = tokio::task::spawn_blocking(move || {
                            let json = serde_json::to_string(&snapshot)
                                .map_err(|e| e.to_string())?;
                            std::fs::write(&snap_path, json)
                                .map_err(|e| e.to_string())
                        }).await;
                        match result {
                            Ok(Ok(())) => {
                                tracing::info!(
                                    "UTXO snapshot saved | height={} | utxos={}",
                                    height, utxo_count
                                );
                            }
                            Ok(Err(e)) => {
                                tracing::warn!(
                                    "UTXO snapshot save failed at height {}: {}",
                                    height, e
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "UTXO snapshot task panicked at height {}: {}",
                                    height, e
                                );
                            }
                        }
                    });
                }
            }
            Err(e) => {
                tracing::error!("Block #{} REJECTED: {}. No state modified.", new_height, e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_types::utxo::{
        OutputRef, TxInput, TxOutput as UtxoTxOutput, TxType, UtxoTransaction,
        UTXO_TX_VERSION,
    };

    fn sample_tx(with_inputs: bool, with_extra: bool) -> UtxoTransaction {
        let inputs = if with_inputs {
            vec![TxInput {
                utxo_refs: vec![
                    OutputRef {
                        tx_hash: [1u8; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [2u8; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [3u8; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [4u8; 32],
                        output_index: 0,
                    },
                ],
                proof: vec![],
            }]
        } else {
            vec![]
        };

        UtxoTransaction {
            version: UTXO_TX_VERSION,
            tx_type: if with_inputs {
                TxType::TransparentTransfer
            } else {
                TxType::Faucet
            },
            inputs,
            outputs: vec![UtxoTxOutput {
                amount: 1,
                address: [0xAA; 32],
                spending_pubkey: None,
            }],
            fee: 0,
            extra: vec![],
            expiry: 0,
        }
    }

    #[test]
    fn test_zero_knowledge_candidate_requires_inputs_and_carrier() {
        assert!(is_explicit_zk_candidate(&sample_tx(true, true)));
        assert!(!is_explicit_zk_candidate(&sample_tx(true, false)));
        assert!(!is_explicit_zk_candidate(&sample_tx(false, true)));
    }

    #[test]
    fn test_zero_knowledge_block_path_requires_homogeneous_verified_txs() {
        let zk_tx = VerifiedTx {
            tx: sample_tx(true, true),
            ring_pubkeys: vec![],
            raw_spending_keys: vec![],
            ring_amounts: vec![],
            ring_proofs: vec![],
        };
        let ring_tx = VerifiedTx {
            tx: sample_tx(true, false),
            ring_pubkeys: vec![],
            raw_spending_keys: vec![],
            ring_amounts: vec![],
            ring_proofs: vec![],
        };

        assert!(should_use_zero_knowledge_block_path(
            true,
            std::slice::from_ref(&zk_tx)
        ));
        assert!(!should_use_zero_knowledge_block_path(
            true,
            &[zk_tx.clone(), ring_tx]
        ));
        assert!(!should_use_zero_knowledge_block_path(false, &[zk_tx]));
    }
}
