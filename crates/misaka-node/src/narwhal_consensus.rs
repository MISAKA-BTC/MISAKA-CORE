// SPDX-License-Identifier: Apache-2.0
//! Narwhal/Bullshark Consensus Adapter — bridges DAG consensus with the node.

#[cfg(feature = "dag")]
use std::collections::VecDeque;

#[cfg(feature = "dag")]
use std::sync::Arc;

#[cfg(feature = "dag")]
use misaka_dag::{
    narwhal_dag::block_verifier::BlockVerifier, narwhal_dag::core_engine::ProposeContext,
    narwhal_types::block::BlockSigner, BlockManager, BlockRef, CommitFinalizer, Committee,
    CoreEngine, DagState, DagStateConfig, LeaderSchedule, Linearizer, Round, Synchronizer,
    SynchronizerConfig, ThresholdClock, UniversalCommitter, VerifiedBlock,
};
#[cfg(feature = "dag")]
use misaka_mempool::UtxoMempool;
#[cfg(feature = "dag")]
use misaka_storage::utxo_set::UtxoSet;
#[cfg(feature = "dag")]
use misaka_types::utxo::UtxoTransaction;
#[cfg(feature = "dag")]
use tokio::sync::Mutex;

#[cfg(feature = "dag")]
#[derive(Clone, Debug)]
pub struct NarwhalConsensusConfig {
    pub committee: Committee,
    pub authority_index: u32,
    pub leader_round_wave: u32,
    pub dag_config: DagStateConfig,
    pub chain_ctx: misaka_types::chain_context::ChainContext,
}

#[cfg(feature = "dag")]
pub struct NarwhalConsensusAdapter {
    pub core: CoreEngine,
    pub dag_state: DagState,
    pub block_manager: BlockManager,
    pub committee: Committee,
    pub config: NarwhalConsensusConfig,
}

#[cfg(feature = "dag")]
impl NarwhalConsensusAdapter {
    pub fn new(config: NarwhalConsensusConfig, signer: Arc<dyn BlockSigner>) -> Self {
        let committee = config.committee.clone();
        let verifier = BlockVerifier::new(
            committee.clone(),
            committee.epoch,
            Arc::new(misaka_dag::MlDsa65Verifier),
            config.chain_ctx.clone(),
        );
        let core = CoreEngine::new(
            config.authority_index,
            committee.epoch,
            committee.clone(),
            signer,
            verifier,
            config.chain_ctx.clone(),
        );
        Self {
            core,
            dag_state: DagState::new(committee.clone(), config.dag_config.clone()),
            block_manager: BlockManager::new(committee.clone()),
            committee,
            config,
        }
    }

    pub fn process_block(&mut self, block: VerifiedBlock) -> Vec<misaka_dag::LinearizedOutput> {
        let result = self
            .core
            .process_block(block, &mut self.block_manager, &mut self.dag_state);
        result.outputs
    }

    pub fn propose(&mut self, transactions: Vec<Vec<u8>>, state_root: [u8; 32]) -> VerifiedBlock {
        self.core.propose_block(
            &mut self.dag_state,
            ProposeContext::normal(transactions, state_root),
        )
    }

    pub fn current_round(&self) -> Round {
        self.core.current_round()
    }
    pub fn num_blocks(&self) -> usize {
        self.dag_state.num_blocks()
    }
    pub fn num_commits(&self) -> usize {
        self.dag_state.num_commits()
    }
}

#[cfg(feature = "dag")]
#[derive(Clone)]
pub struct NarwhalMempoolIngress {
    mempool: Arc<Mutex<UtxoMempool>>,
    /// R7 C-2: Shared canonical UtxoSet — same instance used by the
    /// executor so admission checks see committed state.
    utxo_set: Arc<tokio::sync::RwLock<UtxoSet>>,
    /// Audit #26: AppId for IntentMessage signature verification at admission.
    app_id: misaka_types::intent::AppId,
}

#[cfg(feature = "dag")]
impl NarwhalMempoolIngress {
    pub fn new(
        max_size: usize,
        utxo_set: UtxoSet,
        relay_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
        app_id: misaka_types::intent::AppId,
    ) -> Self {
        let mut mempool = UtxoMempool::new(max_size);
        mempool.set_narwhal_relay(relay_tx);
        Self {
            mempool: Arc::new(Mutex::new(mempool)),
            utxo_set: Arc::new(tokio::sync::RwLock::new(utxo_set)),
            app_id,
        }
    }

    /// R7 C-2: Access the shared UtxoSet handle so the executor can
    /// clone the Arc and keep both sides in sync.
    pub fn utxo_set(&self) -> Arc<tokio::sync::RwLock<UtxoSet>> {
        self.utxo_set.clone()
    }

    pub async fn submit_tx(&self, body: &[u8]) -> serde_json::Value {
        if body.len() > 131_072 {
            return serde_json::json!({
                "txHash": serde_json::Value::Null,
                "accepted": false,
                "error": format!("tx body too large: {} bytes (max 131072)", body.len()),
            });
        }

        let tx: UtxoTransaction = match serde_json::from_slice(body) {
            Ok(tx) => tx,
            Err(e) => {
                return serde_json::json!({
                    "txHash": serde_json::Value::Null,
                    "accepted": false,
                    "error": format!("invalid transaction format: {}", e),
                });
            }
        };

        // ── SEC-FIX: Reject system-only tx types at RPC ingress ──
        // SystemEmission and Faucet transactions MUST NOT be user-submittable.
        // Without this guard, any external user can mint tokens via the public RPC.
        match tx.tx_type {
            misaka_types::utxo::TxType::SystemEmission | misaka_types::utxo::TxType::Faucet => {
                return serde_json::json!({
                    "txHash": serde_json::Value::Null,
                    "accepted": false,
                    "error": "SystemEmission/Faucet transactions cannot be user-submitted",
                });
            }
            _ => {}
        }

        let tx_hash = hex::encode(tx.tx_hash());

        // ── Audit #26: ML-DSA-65 signature verification BEFORE mempool admission ──
        // Previously, submit_tx admitted transactions with NO signature check,
        // allowing garbage txs to flood mempool/DAG/consensus for free.
        if tx.tx_type == misaka_types::utxo::TxType::TransparentTransfer {
            if let Err(e) = self.verify_tx_signatures(&tx).await {
                return serde_json::json!({
                    "txHash": tx_hash,
                    "accepted": false,
                    "error": format!("signature verification failed: {}", e),
                });
            }
        }

        let now_ms = chrono::Utc::now().timestamp_millis() as u64;
        let utxo_guard = self.utxo_set.read().await;
        let mut mempool = self.mempool.lock().await;
        match mempool.admit(tx, &utxo_guard, now_ms) {
            Ok(_) => serde_json::json!({
                "txHash": tx_hash,
                "accepted": true,
                "queued": true,
                "error": serde_json::Value::Null,
            }),
            Err(e) => serde_json::json!({
                "txHash": tx_hash,
                "accepted": false,
                "queued": false,
                "error": e.to_string(),
            }),
        }
    }

    /// Audit #26: Verify ML-DSA-65 signatures via IntentMessage before mempool admission.
    /// This is the same verification logic as utxo_executor::validate_transparent_transfer
    /// but performed at the RPC ingress point to prevent garbage tx flooding.
    async fn verify_tx_signatures(&self, tx: &UtxoTransaction) -> Result<(), String> {
        use misaka_pqc::pq_sign::{ml_dsa_verify_raw, MlDsaPublicKey, MlDsaSignature};
        use misaka_types::intent::{IntentMessage, IntentScope};
        use misaka_types::tx_signable::TxSignablePayload;

        let payload = TxSignablePayload::from(tx);
        let intent = IntentMessage::wrap(
            IntentScope::TransparentTransfer,
            self.app_id.clone(),
            &payload,
        );
        let signing_digest = intent.signing_digest();

        let utxo_guard = self.utxo_set.read().await;
        for (i, input) in tx.inputs.iter().enumerate() {
            if input.utxo_refs.is_empty() {
                return Err(format!("input {} has no UTXO refs", i));
            }
            let outref = &input.utxo_refs[0];
            let pk_bytes = utxo_guard
                .get_spending_key(outref)
                .ok_or_else(|| format!("spending key not found for input {}", i))?;

            let pk = MlDsaPublicKey::from_bytes(pk_bytes)
                .map_err(|e| format!("input {} invalid pubkey: {}", i, e))?;
            let sig = MlDsaSignature::from_bytes(&input.proof)
                .map_err(|e| format!("input {} invalid signature: {}", i, e))?;

            ml_dsa_verify_raw(&pk, &signing_digest, &sig)
                .map_err(|e| format!("input {} ML-DSA-65 verify failed: {}", i, e))?;
        }
        Ok(())
    }

    pub async fn mempool_info(&self) -> serde_json::Value {
        let mempool = self.mempool.lock().await;
        let utxo_guard = self.utxo_set.read().await;
        serde_json::json!({
            "mempoolSize": mempool.len(),
            "maxSize": mempool.max_size(),
            "utxoSetSize": utxo_guard.len(),
        })
    }

    pub async fn contains_tx(&self, tx_hash: &[u8; 32]) -> bool {
        let mempool = self.mempool.lock().await;
        mempool.contains_tx(tx_hash)
    }
}

// ═══════════════════════════════════════════════════════════════
//  Phase 1: Propose Loop — drains mempool into CoreEngine
// ═══════════════════════════════════════════════════════════════

/// Configuration for the propose loop.
#[cfg(feature = "dag")]
pub struct ProposeLoopConfig {
    /// Maximum transactions per block proposal.
    pub max_block_txs: usize,
    /// Status poll interval for threshold-clock round advancement.
    pub status_poll_ms: u64,
}

#[cfg(feature = "dag")]
impl Default for ProposeLoopConfig {
    fn default() -> Self {
        Self {
            max_block_txs: 1000,
            status_poll_ms: 100,
        }
    }
}

/// Spawn the propose loop as an async task.
///
/// This is the critical missing link between mempool and consensus:
/// - Drains transactions from the mempool channel
/// - Batches them up to `max_block_txs`
/// - Calls `CoreEngine::propose_block` via the consensus message channel
/// - Proposed blocks are sent to `block_broadcast_tx` for P2P dissemination
///
/// Without this, transactions only flow 1-at-a-time through RPC ProposeBlock.
///
/// v0.5.9: accepts an optional `SafeMode` handle; when the flag is
/// tripped the propose loop stops producing new proposals and drains
/// the mempool channel only to avoid back-pressuring the RPC layer.
#[cfg(feature = "dag")]
pub fn spawn_propose_loop(
    msg_tx: tokio::sync::mpsc::Sender<misaka_dag::narwhal_dag::runtime::ConsensusMessage>,
    mut mempool_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    config: ProposeLoopConfig,
    // Shared state_root updated by the commit/executor loop.
    shared_state_root: std::sync::Arc<tokio::sync::RwLock<[u8; 32]>>,
    // v0.5.9: safe-mode halt flag. None in tests and legacy callers.
    safe_mode: Option<std::sync::Arc<crate::safe_mode::SafeMode>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut pending_txs: VecDeque<Vec<u8>> = VecDeque::with_capacity(config.max_block_txs);
        let mut status_tick =
            tokio::time::interval(tokio::time::Duration::from_millis(config.status_poll_ms));
        let mut last_proposed_round: Option<Round> = None;

        tracing::info!(
            "Propose loop started: max_block_txs={}, status_poll={}ms",
            config.max_block_txs,
            config.status_poll_ms
        );

        loop {
            tokio::select! {
                tx = mempool_rx.recv() => {
                    match tx {
                        Some(tx_bytes) => {
                            pending_txs.push_back(tx_bytes);
                            while pending_txs.len() < config.max_block_txs {
                                match mempool_rx.try_recv() {
                                    Ok(more) => pending_txs.push_back(more),
                                    Err(_) => break,
                                }
                            }
                        }
                        None => {
                            tracing::info!("Mempool channel closed, propose loop stopping");
                            break;
                        }
                    }
                }
                _ = status_tick.tick() => {}
            }

            // v0.5.9: skip proposing when safe-mode is engaged. Keep
            // draining the channel so the RPC layer isn't blocked; txs
            // admitted during safe-mode are silently discarded.
            if let Some(sm) = safe_mode.as_ref() {
                if sm.is_halted() {
                    pending_txs.clear();
                    continue;
                }
            }

            let (status_tx, status_rx) = tokio::sync::oneshot::channel();
            if msg_tx
                .try_send(misaka_dag::narwhal_dag::runtime::ConsensusMessage::GetStatus(status_tx))
                .is_err()
            {
                tracing::error!("Consensus runtime stopped, propose loop exiting");
                break;
            }
            let status = match status_rx.await {
                Ok(status) => status,
                Err(_) => {
                    tracing::warn!("Status reply dropped (runtime busy?)");
                    continue;
                }
            };

            let can_propose = match last_proposed_round {
                None => true,
                Some(last_round) => status.current_round > last_round,
            };
            if !can_propose {
                continue;
            }

            let tx_count = pending_txs.len().min(config.max_block_txs);
            let candidates: Vec<Vec<u8>> = pending_txs.drain(..tx_count).collect();

            // SECURITY: proposer-side validation gate.
            // Filter out tx bytes that cannot be borsh-decoded or fail structural
            // validation. Without this, a Byzantine bypass route (faucet, bridge)
            // could inject garbage that causes all validators to reject-or-skip
            // the tx after consensus, wasting block space and round time.
            let txs: Vec<Vec<u8>> = candidates
                .into_iter()
                .filter(
                    |raw| match borsh::from_slice::<misaka_types::utxo::UtxoTransaction>(raw) {
                        Ok(tx) => tx.validate_structure().is_ok(),
                        Err(_) => {
                            tracing::warn!(
                                "proposer: dropping malformed tx ({} bytes, borsh decode failed)",
                                raw.len()
                            );
                            false
                        }
                    },
                )
                .collect();

            // Send proposal to consensus runtime
            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            // Read the latest state_root from the executor (updated after each commit)
            let current_state_root = *shared_state_root.read().await;
            if msg_tx
                .try_send(
                    misaka_dag::narwhal_dag::runtime::ConsensusMessage::ProposeBlock {
                        context: ProposeContext::normal(txs, current_state_root),
                        reply: reply_tx,
                    },
                )
                .is_err()
            {
                tracing::error!("Consensus runtime stopped, propose loop exiting");
                break;
            }

            // Wait for proposal result
            match reply_rx.await {
                Ok(block) => {
                    last_proposed_round = Some(block.round());
                    tracing::info!(
                        "propose_block round={} author={} tx_count={} sig_len={}",
                        block.round(),
                        block.author(),
                        tx_count,
                        block.inner().signature.len()
                    );
                }
                Err(_) => {
                    tracing::warn!("Propose reply dropped (runtime busy?)");
                }
            }
        }

        tracing::info!("Propose loop stopped");
    })
}

/// Create a mempool → propose channel pair.
///
/// Returns (sender, receiver). The sender goes to the mempool/RPC layer,
/// the receiver goes to `spawn_propose_loop`.
#[cfg(feature = "dag")]
pub fn mempool_propose_channel(
    buffer: usize,
) -> (
    tokio::sync::mpsc::Sender<Vec<u8>>,
    tokio::sync::mpsc::Receiver<Vec<u8>>,
) {
    tokio::sync::mpsc::channel(buffer)
}

#[cfg(all(test, feature = "dag"))]
mod tests {
    use super::*;
    use misaka_pqc::pq_sign::{ml_dsa_sign_raw, MlDsaKeypair};
    use misaka_types::intent::{AppId, IntentMessage, IntentScope};
    use misaka_types::tx_signable::TxSignablePayload;
    use misaka_types::utxo::{OutputRef, TxInput, TxOutput, TxType, UTXO_TX_VERSION};

    /// Audit #26: ingress now performs ML-DSA-65 signature verification,
    /// so tests must sign with a real keypair and store the matching pubkey
    /// on the referenced UTXO.
    fn signed_sample_tx(
        kp: &MlDsaKeypair,
        outref: OutputRef,
        app_id: &AppId,
        salt: [u8; 32],
    ) -> UtxoTransaction {
        let mut tx = UtxoTransaction {
            version: UTXO_TX_VERSION,
            tx_type: TxType::TransparentTransfer,
            inputs: vec![TxInput {
                utxo_refs: vec![outref],
                proof: Vec::new(),
            }],
            outputs: vec![TxOutput {
                amount: 9_900,
                address: [0xCC; 32],
                spending_pubkey: None,
            }],
            fee: 100,
            extra: salt.to_vec(),
            expiry: 0,
        };
        let payload = TxSignablePayload::from(&tx);
        let intent =
            IntentMessage::wrap(IntentScope::TransparentTransfer, app_id.clone(), &payload);
        let sig =
            ml_dsa_sign_raw(&kp.secret_key, &intent.signing_digest()).expect("ml_dsa_sign_raw");
        tx.inputs[0].proof = sig.as_bytes().to_vec();
        tx
    }

    fn utxo_set_with_pubkey(pk_bytes: Vec<u8>) -> (UtxoSet, OutputRef) {
        let mut utxo_set = UtxoSet::new(100);
        let outref = OutputRef {
            tx_hash: [1u8; 32],
            output_index: 0,
        };
        utxo_set
            .add_output(
                outref.clone(),
                TxOutput {
                    amount: 10_000,
                    address: [0x11; 32],
                    spending_pubkey: Some(pk_bytes.clone()),
                },
                0,
                false,
            )
            .expect("add sample utxo");
        utxo_set
            .register_spending_key(outref.clone(), pk_bytes)
            .expect("register_spending_key");
        (utxo_set, outref)
    }

    #[tokio::test]
    async fn narwhal_consensus_submit_tx_relays_admitted_transaction() {
        let kp = MlDsaKeypair::generate();
        let pk_bytes = kp.public_key.as_bytes().to_vec();
        let (utxo_set, outref) = utxo_set_with_pubkey(pk_bytes);

        let (relay_tx, mut relay_rx) = mempool_propose_channel(4);
        let test_app_id = AppId::new(2, [0u8; 32]);
        let ingress = NarwhalMempoolIngress::new(16, utxo_set, relay_tx, test_app_id.clone());
        let tx = signed_sample_tx(&kp, outref, &test_app_id, [0xAB; 32]);
        let response = ingress
            .submit_tx(&serde_json::to_vec(&tx).expect("serialize tx"))
            .await;

        assert_eq!(
            response["accepted"],
            serde_json::Value::Bool(true),
            "response: {response}"
        );
        let relayed = relay_rx.recv().await.expect("relayed tx");
        // The mempool relays borsh-encoded UtxoTransaction bytes.
        let relayed_tx: UtxoTransaction =
            borsh::from_slice(&relayed).expect("deserialize relayed tx");
        assert_eq!(relayed_tx.tx_hash(), tx.tx_hash());
    }
}
