use crate::dag_tx_dissemination_service::DagTxDisseminationService;
use anyhow::anyhow;
use misaka_dag::{
    DagNodeState, OrderingContractSummary, TxDisseminationContractSummary, TxDisseminationLane,
};
use misaka_types::utxo::UtxoTransaction;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};

const NARWHAL_DISSEMINATION_CHANNEL_CAPACITY: usize = 16;

enum NarwhalDisseminationCommand {
    StageWorkerBatch {
        txs: Vec<UtxoTransaction>,
        reply: oneshot::Sender<Result<Vec<[u8; 32]>, String>>,
    },
    MarkDeliveredBatch {
        tx_hashes: Vec<[u8; 32]>,
        reply: oneshot::Sender<Result<usize, String>>,
    },
    IngestDeliveredBatch {
        txs: Vec<UtxoTransaction>,
        reply: oneshot::Sender<Result<Vec<[u8; 32]>, String>>,
    },
    ContractSummary {
        reply: oneshot::Sender<TxDisseminationContractSummary>,
    },
    OrderingContractSummary {
        reply: oneshot::Sender<OrderingContractSummary>,
    },
    MarkBullsharkCandidatePreview {
        tx_hashes: Vec<[u8; 32]>,
        reply: oneshot::Sender<Result<usize, String>>,
    },
    MarkBullsharkCommitPreview {
        tx_hashes: Vec<[u8; 32]>,
        reply: oneshot::Sender<Result<usize, String>>,
    },
    MarkBullsharkCommit {
        tx_hashes: Vec<[u8; 32]>,
        reply: oneshot::Sender<Result<usize, String>>,
    },
    BullsharkCandidatePreviewHashes {
        lane: TxDisseminationLane,
        max_txs: usize,
        reply: oneshot::Sender<Vec<[u8; 32]>>,
    },
    BullsharkCommitPreviewHashes {
        lane: TxDisseminationLane,
        max_txs: usize,
        reply: oneshot::Sender<Vec<[u8; 32]>>,
    },
    BullsharkCommitHashes {
        lane: TxDisseminationLane,
        max_txs: usize,
        reply: oneshot::Sender<Vec<[u8; 32]>>,
    },
}

pub struct DagNarwhalDisseminationService {
    dissemination: DagTxDisseminationService,
    running: AtomicBool,
    command_tx: Mutex<Option<mpsc::Sender<NarwhalDisseminationCommand>>>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl DagNarwhalDisseminationService {
    pub fn new(state: Arc<RwLock<DagNodeState>>) -> Arc<Self> {
        Arc::new(Self {
            dissemination: DagTxDisseminationService::new(state),
            running: AtomicBool::new(false),
            command_tx: Mutex::new(None),
            task: Mutex::new(None),
        })
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            anyhow::bail!("Narwhal dissemination service already running");
        }

        let (command_tx, mut command_rx) =
            mpsc::channel::<NarwhalDisseminationCommand>(NARWHAL_DISSEMINATION_CHANNEL_CAPACITY);
        let dissemination = self.dissemination.clone();
        let handle = tokio::spawn(async move {
            while let Some(command) = command_rx.recv().await {
                match command {
                    NarwhalDisseminationCommand::StageWorkerBatch { txs, reply } => {
                        let _ = reply.send(dissemination.stage_narwhal_worker_batch(txs).await);
                    }
                    NarwhalDisseminationCommand::MarkDeliveredBatch { tx_hashes, reply } => {
                        let _ = reply.send(
                            dissemination
                                .mark_narwhal_worker_batch_delivered(&tx_hashes)
                                .await,
                        );
                    }
                    NarwhalDisseminationCommand::IngestDeliveredBatch { txs, reply } => {
                        let _ = reply.send(dissemination.ingest_narwhal_delivered_batch(txs).await);
                    }
                    NarwhalDisseminationCommand::ContractSummary { reply } => {
                        let _ = reply.send(dissemination.contract_summary().await);
                    }
                    NarwhalDisseminationCommand::OrderingContractSummary { reply } => {
                        let _ = reply.send(dissemination.ordering_contract_summary().await);
                    }
                    NarwhalDisseminationCommand::MarkBullsharkCandidatePreview {
                        tx_hashes,
                        reply,
                    } => {
                        let _ = reply.send(
                            dissemination
                                .mark_bullshark_candidate_preview(&tx_hashes)
                                .await,
                        );
                    }
                    NarwhalDisseminationCommand::MarkBullsharkCommitPreview {
                        tx_hashes,
                        reply,
                    } => {
                        let _ = reply.send(
                            dissemination
                                .mark_bullshark_commit_preview(&tx_hashes)
                                .await,
                        );
                    }
                    NarwhalDisseminationCommand::MarkBullsharkCommit { tx_hashes, reply } => {
                        let _ = reply.send(dissemination.mark_bullshark_commit(&tx_hashes).await);
                    }
                    NarwhalDisseminationCommand::BullsharkCandidatePreviewHashes {
                        lane,
                        max_txs,
                        reply,
                    } => {
                        let _ = reply.send(
                            dissemination
                                .bullshark_candidate_preview_hashes(lane, max_txs)
                                .await,
                        );
                    }
                    NarwhalDisseminationCommand::BullsharkCommitPreviewHashes {
                        lane,
                        max_txs,
                        reply,
                    } => {
                        let _ = reply.send(
                            dissemination
                                .bullshark_commit_preview_hashes(lane, max_txs)
                                .await,
                        );
                    }
                    NarwhalDisseminationCommand::BullsharkCommitHashes {
                        lane,
                        max_txs,
                        reply,
                    } => {
                        let _ =
                            reply.send(dissemination.bullshark_commit_hashes(lane, max_txs).await);
                    }
                }
            }
        });

        *self.command_tx.lock().await = Some(command_tx);
        *self.task.lock().await = Some(handle);
        Ok(())
    }

    pub async fn stop(&self) -> anyhow::Result<()> {
        if !self.running.swap(false, Ordering::SeqCst) {
            anyhow::bail!("Narwhal dissemination service not running");
        }

        self.command_tx.lock().await.take();
        if let Some(task) = self.task.lock().await.take() {
            task.await
                .map_err(|err| anyhow!("Narwhal dissemination service join failed: {err}"))?;
        }
        Ok(())
    }

    pub async fn stage_narwhal_worker_batch(
        &self,
        txs: Vec<UtxoTransaction>,
    ) -> Result<Vec<[u8; 32]>, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_sender()
            .await?
            .send(NarwhalDisseminationCommand::StageWorkerBatch {
                txs,
                reply: reply_tx,
            })
            .await
            .map_err(|_| "narwhal dissemination service stopped".to_string())?;
        reply_rx
            .await
            .map_err(|_| "narwhal dissemination service reply dropped".to_string())?
    }

    pub async fn ingest_narwhal_delivered_batch(
        &self,
        txs: Vec<UtxoTransaction>,
    ) -> Result<Vec<[u8; 32]>, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_sender()
            .await?
            .send(NarwhalDisseminationCommand::IngestDeliveredBatch {
                txs,
                reply: reply_tx,
            })
            .await
            .map_err(|_| "narwhal dissemination service stopped".to_string())?;
        reply_rx
            .await
            .map_err(|_| "narwhal dissemination service reply dropped".to_string())?
    }

    pub async fn mark_narwhal_worker_batch_delivered(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> Result<usize, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_sender()
            .await?
            .send(NarwhalDisseminationCommand::MarkDeliveredBatch {
                tx_hashes: tx_hashes.to_vec(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| "narwhal dissemination service stopped".to_string())?;
        reply_rx
            .await
            .map_err(|_| "narwhal dissemination service reply dropped".to_string())?
    }

    pub async fn contract_summary(&self) -> Result<TxDisseminationContractSummary, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_sender()
            .await?
            .send(NarwhalDisseminationCommand::ContractSummary { reply: reply_tx })
            .await
            .map_err(|_| "narwhal dissemination service stopped".to_string())?;
        reply_rx
            .await
            .map_err(|_| "narwhal dissemination service reply dropped".to_string())
    }

    pub async fn ordering_contract_summary(&self) -> Result<OrderingContractSummary, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_sender()
            .await?
            .send(NarwhalDisseminationCommand::OrderingContractSummary { reply: reply_tx })
            .await
            .map_err(|_| "narwhal dissemination service stopped".to_string())?;
        reply_rx
            .await
            .map_err(|_| "narwhal dissemination service reply dropped".to_string())
    }

    pub async fn mark_bullshark_candidate_preview(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> Result<usize, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_sender()
            .await?
            .send(NarwhalDisseminationCommand::MarkBullsharkCandidatePreview {
                tx_hashes: tx_hashes.to_vec(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| "narwhal dissemination service stopped".to_string())?;
        reply_rx
            .await
            .map_err(|_| "narwhal dissemination service reply dropped".to_string())?
    }

    pub async fn mark_bullshark_commit_preview(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> Result<usize, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_sender()
            .await?
            .send(NarwhalDisseminationCommand::MarkBullsharkCommitPreview {
                tx_hashes: tx_hashes.to_vec(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| "narwhal dissemination service stopped".to_string())?;
        reply_rx
            .await
            .map_err(|_| "narwhal dissemination service reply dropped".to_string())?
    }

    pub async fn mark_bullshark_commit(&self, tx_hashes: &[[u8; 32]]) -> Result<usize, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_sender()
            .await?
            .send(NarwhalDisseminationCommand::MarkBullsharkCommit {
                tx_hashes: tx_hashes.to_vec(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| "narwhal dissemination service stopped".to_string())?;
        reply_rx
            .await
            .map_err(|_| "narwhal dissemination service reply dropped".to_string())?
    }

    pub async fn bullshark_candidate_preview_hashes(
        &self,
        lane: TxDisseminationLane,
        max_txs: usize,
    ) -> Result<Vec<[u8; 32]>, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_sender()
            .await?
            .send(
                NarwhalDisseminationCommand::BullsharkCandidatePreviewHashes {
                    lane,
                    max_txs,
                    reply: reply_tx,
                },
            )
            .await
            .map_err(|_| "narwhal dissemination service stopped".to_string())?;
        reply_rx
            .await
            .map_err(|_| "narwhal dissemination service reply dropped".to_string())
    }

    pub async fn bullshark_commit_preview_hashes(
        &self,
        lane: TxDisseminationLane,
        max_txs: usize,
    ) -> Result<Vec<[u8; 32]>, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_sender()
            .await?
            .send(NarwhalDisseminationCommand::BullsharkCommitPreviewHashes {
                lane,
                max_txs,
                reply: reply_tx,
            })
            .await
            .map_err(|_| "narwhal dissemination service stopped".to_string())?;
        reply_rx
            .await
            .map_err(|_| "narwhal dissemination service reply dropped".to_string())
    }

    pub async fn bullshark_commit_hashes(
        &self,
        lane: TxDisseminationLane,
        max_txs: usize,
    ) -> Result<Vec<[u8; 32]>, String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_sender()
            .await?
            .send(NarwhalDisseminationCommand::BullsharkCommitHashes {
                lane,
                max_txs,
                reply: reply_tx,
            })
            .await
            .map_err(|_| "narwhal dissemination service stopped".to_string())?;
        reply_rx
            .await
            .map_err(|_| "narwhal dissemination service reply dropped".to_string())
    }

    async fn command_sender(&self) -> Result<mpsc::Sender<NarwhalDisseminationCommand>, String> {
        self.command_tx
            .lock()
            .await
            .clone()
            .ok_or_else(|| "narwhal dissemination service not running".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::DagNarwhalDisseminationService;
    use misaka_dag::{
        dag_block::DAG_VERSION, reachability::ReachabilityStore, DagBlockHeader, DagMempool,
        DagNodeState, DagStateManager, GhostDagEngine, IngestionPipeline, ThreadSafeDagStore,
        TxDisseminationLane, VirtualState, ZERO_HASH,
    };
    use misaka_storage::utxo_set::UtxoSet;
    use misaka_types::utxo::{
        OutputRef, TxInput, TxOutput, TxType, UtxoTransaction, UTXO_TX_VERSION,
        UTXO_TX_VERSION,
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
            snapshot_path: PathBuf::from("/tmp/misaka-dag-narwhal-dissemination-test.json"),
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
    async fn stage_worker_batch_updates_shadow_queue_through_orchestration_loop() {
        let service =
            DagNarwhalDisseminationService::new(Arc::new(RwLock::new(make_test_dag_state())));
        service.start().await.expect("start service");

        service
            .stage_narwhal_worker_batch(vec![
                make_test_tx(0x41, TxType::TransparentTransfer),
                make_test_tx(0x42, TxType::TransparentTransfer),
            ])
            .await
            .expect("stage worker batch");

        let summary = service.contract_summary().await.expect("summary");
        assert_eq!(summary.current_runtime_queue.queued, 0);
        assert_eq!(summary.completion_target_shadow_queue.queued, 2);
        assert_eq!(
            summary
                .completion_target_shadow_queue
                .narwhal_worker_batch_ingress_queued,
            2
        );
        assert_eq!(summary.completion_target_delivered_queue.queued, 0);

        service.stop().await.expect("stop service");
    }

    #[tokio::test]
    async fn ingest_delivered_batch_updates_delivered_queue_through_orchestration_loop() {
        let service =
            DagNarwhalDisseminationService::new(Arc::new(RwLock::new(make_test_dag_state())));
        service.start().await.expect("start service");

        service
            .ingest_narwhal_delivered_batch(vec![
                make_test_tx(0x51, TxType::TransparentTransfer),
                make_test_tx(0x52, TxType::TransparentTransfer),
            ])
            .await
            .expect("ingest delivered batch");

        let summary = service.contract_summary().await.expect("summary");
        assert_eq!(summary.completion_target_shadow_queue.queued, 2);
        assert_eq!(summary.completion_target_delivered_queue.queued, 2);
        assert_eq!(
            summary
                .completion_target_delivered_queue
                .fast_transparent_queued,
            1
        );
        service.stop().await.expect("stop service");
    }

    #[tokio::test]
    async fn bullshark_preview_updates_ordering_contract_through_orchestration_loop() {
        let service =
            DagNarwhalDisseminationService::new(Arc::new(RwLock::new(make_test_dag_state())));
        service.start().await.expect("start service");

        let transparent = make_test_tx(0x61, TxType::TransparentTransfer);
        let tx_hashes = service
            .ingest_narwhal_delivered_batch(vec![transparent.clone()])
            .await
            .expect("ingest delivered batch");

        service
            .mark_bullshark_candidate_preview(&tx_hashes)
            .await
            .expect("mark candidate preview");
        assert_eq!(
            service
                .bullshark_candidate_preview_hashes(TxDisseminationLane::Any, 8)
                .await
                .expect("candidate preview hashes"),
            tx_hashes
        );
        service
            .mark_bullshark_commit_preview(&tx_hashes)
            .await
            .expect("mark commit preview");
        assert_eq!(
            service
                .bullshark_commit_preview_hashes(TxDisseminationLane::Any, 8)
                .await
                .expect("commit preview hashes"),
            tx_hashes
        );
        service
            .mark_bullshark_commit(&tx_hashes)
            .await
            .expect("mark bullshark commit");
        assert_eq!(
            service
                .bullshark_commit_hashes(TxDisseminationLane::Any, 8)
                .await
                .expect("commit hashes"),
            tx_hashes
        );

        let summary = service
            .ordering_contract_summary()
            .await
            .expect("ordering summary");
        assert_eq!(summary.completion_target_shadow_state.queued, 2);
        assert_eq!(
            summary
                .completion_target_shadow_state
                .candidate_preview_queued,
            2
        );
        assert_eq!(
            summary.completion_target_shadow_state.commit_preview_queued,
            2
        );
        assert_eq!(summary.completion_target_shadow_state.committed_queued, 2);
        assert!(
            summary
                .completion_target_shadow_state
                .candidate_preview_live
        );
        assert!(summary.completion_target_shadow_state.commit_preview_live);
        assert!(summary.completion_target_shadow_state.committed_live);

        service.stop().await.expect("stop service");
    }
}
