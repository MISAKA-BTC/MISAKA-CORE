use crate::dag_narwhal_dissemination_service::DagNarwhalDisseminationService;
use crate::dag_p2p_surface::DagP2pObservationState;
use crate::dag_rpc::{
    run_dag_rpc_server_with_observation_and_shutdown, DagRuntimeRecoveryObservation, DagSharedState,
};
use crate::dag_tx_dissemination_service::DagTxDisseminationService;
use misaka_dag::{TxDisseminationContractSummary, TxDisseminationLane};
use misaka_types::utxo::UtxoTransaction;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::{watch, Mutex, RwLock};
use tokio::time::{interval, Duration};

struct DagRpcServerTask {
    shutdown: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<anyhow::Result<()>>,
    runtime_recovery_observer: Option<tokio::task::JoinHandle<()>>,
}

pub struct DagRpcServerService {
    state: DagSharedState,
    tx_dissemination: DagTxDisseminationService,
    narwhal_dissemination: Arc<DagNarwhalDisseminationService>,
    observation: Option<Arc<RwLock<DagP2pObservationState>>>,
    runtime_recovery: Option<Arc<RwLock<DagRuntimeRecoveryObservation>>>,
    registry: Option<Arc<RwLock<misaka_consensus::staking::StakingRegistry>>>,
    epoch: Arc<RwLock<u64>>,
    epoch_progress:
        Option<Arc<Mutex<crate::validator_lifecycle_persistence::ValidatorEpochProgress>>>,
    addr: SocketAddr,
    chain_id: u32,
    genesis_hash: [u8; 32],
    running: AtomicBool,
    task: Mutex<Option<DagRpcServerTask>>,
}

async fn run_runtime_recovery_bullshark_commit_observer(
    narwhal_dissemination: Arc<DagNarwhalDisseminationService>,
    runtime_recovery: Arc<RwLock<DagRuntimeRecoveryObservation>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut ticker = interval(Duration::from_millis(50));
    let mut last_observed_hashes: Vec<[u8; 32]> = Vec::new();

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let commit_hashes = match narwhal_dissemination
                    .bullshark_commit_hashes(TxDisseminationLane::Any, 256)
                    .await
                {
                    Ok(hashes) => hashes,
                    Err(_) => continue,
                };
                if commit_hashes.is_empty() || commit_hashes == last_observed_hashes {
                    continue;
                }
                last_observed_hashes = commit_hashes.clone();
                let mut guard = runtime_recovery.write().await;
                guard.mark_bullshark_commit(&commit_hashes);
            }
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow_and_update() {
                    break;
                }
            }
        }
    }
}

impl DagRpcServerService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: DagSharedState,
        observation: Option<Arc<RwLock<DagP2pObservationState>>>,
        runtime_recovery: Option<Arc<RwLock<DagRuntimeRecoveryObservation>>>,
        registry: Option<Arc<RwLock<misaka_consensus::staking::StakingRegistry>>>,
        epoch: Arc<RwLock<u64>>,
        epoch_progress: Option<
            Arc<Mutex<crate::validator_lifecycle_persistence::ValidatorEpochProgress>>,
        >,
        addr: SocketAddr,
        chain_id: u32,
        genesis_hash: [u8; 32],
    ) -> Arc<Self> {
        Arc::new(Self {
            tx_dissemination: DagTxDisseminationService::new(state.clone()),
            narwhal_dissemination: DagNarwhalDisseminationService::new(state.clone()),
            state,
            observation,
            runtime_recovery,
            registry,
            epoch,
            epoch_progress,
            addr,
            chain_id,
            genesis_hash,
            running: AtomicBool::new(false),
            task: Mutex::new(None),
        })
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            anyhow::bail!("DAG RPC service already running");
        }

        if !self.narwhal_dissemination.is_running() {
            self.narwhal_dissemination.start().await?;
        }

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let runtime_recovery_observer = self.runtime_recovery.as_ref().map(|runtime_recovery| {
            tokio::spawn(run_runtime_recovery_bullshark_commit_observer(
                self.narwhal_dissemination.clone(),
                runtime_recovery.clone(),
                shutdown_tx.subscribe(),
            ))
        });
        let handle = tokio::spawn(run_dag_rpc_server_with_observation_and_shutdown(
            self.state.clone(),
            Some(self.narwhal_dissemination.clone()),
            self.observation.clone(),
            self.runtime_recovery.clone(),
            self.registry.clone(),
            self.epoch.clone(),
            self.epoch_progress.clone(),
            self.addr,
            self.chain_id,
            self.genesis_hash,
            async move {
                while !*shutdown_rx.borrow_and_update() {
                    if shutdown_rx.changed().await.is_err() {
                        break;
                    }
                }
            },
        ));

        *self.task.lock().await = Some(DagRpcServerTask {
            shutdown: shutdown_tx,
            handle,
            runtime_recovery_observer,
        });
        Ok(())
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    pub async fn signal_exit(&self) {
        if let Some(task) = self.task.lock().await.as_ref() {
            let _ = task.shutdown.send(true);
        }
    }

    pub async fn stop(&self) -> anyhow::Result<()> {
        if !self.running.swap(false, Ordering::SeqCst) {
            anyhow::bail!("DAG RPC service not running");
        }

        let task = self.task.lock().await.take();
        let result = if let Some(task) = task {
            let _ = task.shutdown.send(true);
            if let Some(observer) = task.runtime_recovery_observer {
                let _ = observer.await;
            }
            match task.handle.await {
                Ok(result) => result,
                Err(err) => Err(anyhow::anyhow!("DAG RPC service join failed: {err}")),
            }
        } else {
            Ok(())
        };

        if self.narwhal_dissemination.is_running() {
            self.narwhal_dissemination.stop().await?;
        }

        result
    }

    pub async fn tx_dissemination_contract_summary(&self) -> TxDisseminationContractSummary {
        self.tx_dissemination.contract_summary().await
    }

    pub async fn stage_narwhal_worker_batch(
        &self,
        txs: Vec<UtxoTransaction>,
    ) -> Result<Vec<[u8; 32]>, String> {
        self.narwhal_dissemination
            .stage_narwhal_worker_batch(txs)
            .await
    }

    pub async fn mark_narwhal_worker_batch_delivered(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> Result<usize, String> {
        self.narwhal_dissemination
            .mark_narwhal_worker_batch_delivered(tx_hashes)
            .await
    }

    pub async fn mark_bullshark_candidate_preview(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> Result<usize, String> {
        let marked = self
            .narwhal_dissemination
            .mark_bullshark_candidate_preview(tx_hashes)
            .await?;
        if let Some(runtime_recovery) = self.runtime_recovery.as_ref() {
            let mut guard = runtime_recovery.write().await;
            guard.mark_bullshark_candidate_preview(tx_hashes);
        }
        Ok(marked)
    }

    pub async fn mark_bullshark_commit_preview(
        &self,
        tx_hashes: &[[u8; 32]],
    ) -> Result<usize, String> {
        let marked = self
            .narwhal_dissemination
            .mark_bullshark_commit_preview(tx_hashes)
            .await?;
        if let Some(runtime_recovery) = self.runtime_recovery.as_ref() {
            let mut guard = runtime_recovery.write().await;
            guard.mark_bullshark_commit_preview(tx_hashes);
        }
        Ok(marked)
    }

    pub async fn mark_bullshark_commit(&self, tx_hashes: &[[u8; 32]]) -> Result<usize, String> {
        let marked = self
            .narwhal_dissemination
            .mark_bullshark_commit(tx_hashes)
            .await?;
        if let Some(runtime_recovery) = self.runtime_recovery.as_ref() {
            let mut guard = runtime_recovery.write().await;
            guard.mark_bullshark_commit(tx_hashes);
        }
        Ok(marked)
    }

    pub async fn bullshark_candidate_preview_hashes(
        &self,
        lane: TxDisseminationLane,
        max_txs: usize,
    ) -> Result<Vec<[u8; 32]>, String> {
        self.narwhal_dissemination
            .bullshark_candidate_preview_hashes(lane, max_txs)
            .await
    }

    pub async fn bullshark_commit_preview_hashes(
        &self,
        lane: TxDisseminationLane,
        max_txs: usize,
    ) -> Result<Vec<[u8; 32]>, String> {
        self.narwhal_dissemination
            .bullshark_commit_preview_hashes(lane, max_txs)
            .await
    }

    pub async fn bullshark_commit_hashes(
        &self,
        lane: TxDisseminationLane,
        max_txs: usize,
    ) -> Result<Vec<[u8; 32]>, String> {
        self.narwhal_dissemination
            .bullshark_commit_hashes(lane, max_txs)
            .await
    }

    pub async fn ingest_narwhal_delivered_batch(
        &self,
        txs: Vec<UtxoTransaction>,
    ) -> Result<Vec<[u8; 32]>, String> {
        self.narwhal_dissemination
            .ingest_narwhal_delivered_batch(txs)
            .await
    }

    pub fn narwhal_dissemination_running(&self) -> bool {
        self.narwhal_dissemination.is_running()
    }
}
