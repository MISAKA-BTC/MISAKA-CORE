use std::sync::Arc;

use misaka_dag::{
    DagNodeState, OrderingContractSummary, TxDisseminationContractSummary, TxDisseminationLane,
};
use misaka_types::utxo::UtxoTransaction;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct DagTxDisseminationService {
    state: Arc<RwLock<DagNodeState>>,
}

impl DagTxDisseminationService {
    pub fn new(state: Arc<RwLock<DagNodeState>>) -> Self {
        Self { state }
    }

    pub async fn admit_transaction(&self, tx: UtxoTransaction) -> Result<[u8; 32], String> {
        self.admit_transaction_with_validation(tx, |_state, _tx| Ok(()))
            .await
            .map(|(tx_hash, ())| tx_hash)
    }

    pub async fn admit_transaction_with_validation<T, V>(
        &self,
        tx: UtxoTransaction,
        validate: V,
    ) -> Result<([u8; 32], T), String>
    where
        V: FnOnce(&DagNodeState, &UtxoTransaction) -> Result<T, String>,
    {
        let mut guard = self.state.write().await;
        let state = &mut *guard;
        let validation = validate(state, &tx)?;
        let pipeline = state.dissemination_pipeline();
        let state_mgr = &state.state_manager;
        let tx_hash = pipeline.admit_transaction(&mut state.mempool, tx, |ki| {
            state_mgr.is_spend_tag_spent(ki)
        })?;
        Ok((tx_hash, validation))
    }

    pub async fn stage_narwhal_worker_batch<I>(&self, txs: I) -> Result<Vec<[u8; 32]>, String>
    where
        I: IntoIterator<Item = UtxoTransaction>,
    {
        self.state
            .write()
            .await
            .stage_narwhal_worker_batch_transactions(txs)
    }

    pub async fn mark_narwhal_worker_batch_delivered(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> Result<usize, String> {
        self.state
            .write()
            .await
            .mark_narwhal_worker_batch_delivered(tx_hashes)
    }

    pub async fn ingest_narwhal_delivered_batch<I>(&self, txs: I) -> Result<Vec<[u8; 32]>, String>
    where
        I: IntoIterator<Item = UtxoTransaction>,
    {
        let tx_hashes = self.stage_narwhal_worker_batch(txs).await?;
        self.mark_narwhal_worker_batch_delivered(&tx_hashes).await?;
        Ok(tx_hashes)
    }

    pub async fn mark_bullshark_candidate_preview(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> Result<usize, String> {
        self.state
            .write()
            .await
            .mark_bullshark_candidate_preview(tx_hashes)
    }

    pub async fn mark_bullshark_commit_preview(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> Result<usize, String> {
        self.state
            .write()
            .await
            .mark_bullshark_commit_preview(tx_hashes)
    }

    pub async fn mark_bullshark_commit(&self, tx_hashes: &[[u8; 32]]) -> Result<usize, String> {
        self.state.write().await.mark_bullshark_commit(tx_hashes)
    }

    pub async fn contract_summary(&self) -> TxDisseminationContractSummary {
        self.state.read().await.dissemination_contract_summary()
    }

    pub async fn ordering_contract_summary(&self) -> OrderingContractSummary {
        self.state.read().await.ordering_contract_summary()
    }

    pub async fn bullshark_candidate_preview_hashes(
        &self,
        lane: TxDisseminationLane,
        max_txs: usize,
    ) -> Vec<[u8; 32]> {
        self.state
            .read()
            .await
            .select_bullshark_candidate_preview_candidates(lane, max_txs)
            .into_iter()
            .map(|tx| tx.tx_hash())
            .collect()
    }

    pub async fn bullshark_commit_preview_hashes(
        &self,
        lane: TxDisseminationLane,
        max_txs: usize,
    ) -> Vec<[u8; 32]> {
        self.state
            .read()
            .await
            .select_bullshark_commit_preview_candidates(lane, max_txs)
            .into_iter()
            .map(|tx| tx.tx_hash())
            .collect()
    }

    pub async fn bullshark_commit_hashes(
        &self,
        lane: TxDisseminationLane,
        max_txs: usize,
    ) -> Vec<[u8; 32]> {
        self.state
            .read()
            .await
            .select_bullshark_commit_candidates(lane, max_txs)
            .into_iter()
            .map(|tx| tx.tx_hash())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::DagTxDisseminationService;
    use misaka_dag::{
        dag_block::DAG_VERSION, reachability::ReachabilityStore, DagBlockHeader, DagMempool,
        DagNodeState, DagStateManager, GhostDagEngine, IngestionPipeline, ThreadSafeDagStore,
        TxDisseminationLane, VirtualState, ZERO_HASH,
    };
    use misaka_storage::utxo_set::UtxoSet;
    use misaka_types::utxo::{
        OutputRef, TxInput, TxOutput, TxType, UtxoTransaction, UTXO_TX_VERSION, UTXO_TX_VERSION,
    };
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn make_test_dag_state() -> DagNodeState {
        let genesis_header = DagBlockHeader {
            version: DAG_VERSION,
            parents: vec![],
            timestamp_ms: 1_700_000_000_000,
            tx_root: ZERO_HASH,
            proposer_id: [0u8; 32],
            nonce: 0,
            blue_score: 0,
            bits: 0,
        };
        let genesis_hash = genesis_header.compute_hash();

        DagNodeState {
            dag_store: Arc::new(ThreadSafeDagStore::new(genesis_hash, genesis_header)),
            ghostdag: GhostDagEngine::new(18, genesis_hash),
            state_manager: DagStateManager::new(HashSet::new(), HashSet::new()),
            utxo_set: UtxoSet::new(32),
            virtual_state: VirtualState::new(genesis_hash),
            ingestion_pipeline: IngestionPipeline::new([genesis_hash].into_iter().collect()),
            quarantined_blocks: HashSet::new(),
            mempool: DagMempool::new(32),
            chain_id: 31337,
            validator_count: 2,
            known_validators: Vec::new(),
            proposer_id: [0xAB; 32],
            sr_index: 0,
            num_active_srs: 1,
            runtime_active_sr_validator_ids: Vec::new(),
            local_validator: None,
            genesis_hash,
            snapshot_path: PathBuf::from("/tmp/misaka-dag-dissemination-service-test.json"),
            latest_checkpoint: None,
            latest_checkpoint_vote: None,
            latest_checkpoint_finality: None,
            checkpoint_vote_pool: std::collections::HashMap::new(),
            attestation_rpc_peers: Vec::new(),
            blocks_produced: 0,
            reachability: ReachabilityStore::new(genesis_hash),
            persistent_backend: None,
            faucet_cooldowns: std::collections::HashMap::new(),
            pending_transactions: std::collections::HashMap::new(),
        }
    }

    fn make_test_tx(seed: u8, tx_type: TxType) -> UtxoTransaction {
        UtxoTransaction {
            version: UTXO_TX_VERSION,
            tx_type,
            inputs: vec![TxInput {
                utxo_refs: vec![OutputRef {
                    tx_hash: [seed; 32],
                    output_index: 0,
                }],
                proof: vec![],
            }],
            outputs: vec![TxOutput {
                amount: 10,
                address: [seed; 32],
                spending_pubkey: None,
            }],
            fee: 1,
            extra: vec![],
            expiry: 0,
        }
    }

    #[tokio::test]
    async fn stage_narwhal_worker_batch_rolls_back_partial_progress_on_error() {
        let state = Arc::new(RwLock::new(make_test_dag_state()));
        let service = DagTxDisseminationService::new(state.clone());
        let first = make_test_tx(0x41, TxType::TransparentTransfer);
        let duplicate_spend_tag = make_test_tx(0x41, TxType::TransparentTransfer);

        let err = service
            .stage_narwhal_worker_batch(vec![first, duplicate_spend_tag])
            .await
            .expect_err("duplicate key image should reject batch");

        assert!(err.contains("key image"));
        let summary = service.contract_summary().await;
        assert_eq!(summary.completion_target_shadow_queue.queued, 0);
        assert_eq!(summary.completion_target_delivered_queue.queued, 0);
    }

    #[tokio::test]
    async fn admit_transaction_with_validation_returns_validation_output() {
        let state = Arc::new(RwLock::new(make_test_dag_state()));
        let service = DagTxDisseminationService::new(state.clone());
        let tx = make_test_tx(0x55, TxType::TransparentTransfer);

        let (tx_hash, validation) = service
            .admit_transaction_with_validation(tx, |_state, tx| Ok(tx.tx_type))
            .await
            .expect("validated admit");

        assert_eq!(validation, TxType::TransparentTransfer);
        let summary = service.contract_summary().await;
        assert_eq!(summary.current_runtime_queue.queued, 1);
        assert_eq!(summary.completion_target_delivered_queue.queued, 1);
        let guard = state.read().await;
        assert!(guard.mempool.contains_tx(&tx_hash));
    }

    #[tokio::test]
    async fn bullshark_preview_hashes_follow_candidate_and_commit_visibility() {
        let service = DagTxDisseminationService::new(Arc::new(RwLock::new(make_test_dag_state())));
        let transparent = make_test_tx(0x61, TxType::TransparentTransfer);
        let tx_hashes = service
            .ingest_narwhal_delivered_batch(vec![transparent.clone()])
            .await
            .expect("ingest delivered batch");

        assert!(service
            .bullshark_candidate_preview_hashes(TxDisseminationLane::Any, 8)
            .await
            .is_empty());
        assert!(service
            .bullshark_commit_preview_hashes(TxDisseminationLane::Any, 8)
            .await
            .is_empty());
        assert!(service
            .bullshark_commit_hashes(TxDisseminationLane::Any, 8)
            .await
            .is_empty());

        service
            .mark_bullshark_candidate_preview(&tx_hashes)
            .await
            .expect("mark candidate preview");
        assert_eq!(
            service
                .bullshark_candidate_preview_hashes(TxDisseminationLane::Any, 8)
                .await,
            tx_hashes
        );
        assert_eq!(
            service
                .bullshark_candidate_preview_hashes(TxDisseminationLane::FastTransparent, 8)
                .await,
            vec![transparent.tx_hash()]
        );

        service
            .mark_bullshark_commit_preview(&tx_hashes)
            .await
            .expect("mark commit preview");
        assert_eq!(
            service
                .bullshark_commit_preview_hashes(TxDisseminationLane::Any, 8)
                .await,
            tx_hashes
        );
        assert_eq!(
            service
                .bullshark_commit_preview_hashes(TxDisseminationLane::FastTransparent, 8)
                .await,
            vec![transparent.tx_hash()]
        );

        service
            .mark_bullshark_commit(&tx_hashes)
            .await
            .expect("mark bullshark commit");
        assert_eq!(
            service
                .bullshark_commit_hashes(TxDisseminationLane::Any, 8)
                .await,
            tx_hashes
        );
        assert_eq!(
            service
                .bullshark_commit_hashes(TxDisseminationLane::FastTransparent, 8)
                .await,
            vec![transparent.tx_hash()]
        );
    }
}
