use crate::dag_p2p_surface::DagP2pObservationState;
use crate::dag_rpc::{
    run_dag_rpc_server_with_observation_and_shutdown, DagRuntimeRecoveryObservation,
    DagSharedState,
};
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::{watch, Mutex, RwLock};

struct DagRpcServerTask {
    shutdown: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<anyhow::Result<()>>,
}

pub struct DagRpcServerService {
    state: DagSharedState,
    observation: Option<Arc<RwLock<DagP2pObservationState>>>,
    runtime_recovery: Option<Arc<RwLock<DagRuntimeRecoveryObservation>>>,
    registry: Option<Arc<RwLock<misaka_consensus::staking::StakingRegistry>>>,
    epoch: Arc<RwLock<u64>>,
    epoch_progress:
        Option<Arc<Mutex<crate::validator_lifecycle_persistence::ValidatorEpochProgress>>>,
    shielded_state: Option<misaka_shielded::SharedShieldedState>,
    addr: SocketAddr,
    chain_id: u32,
    running: AtomicBool,
    task: Mutex<Option<DagRpcServerTask>>,
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
        shielded_state: Option<misaka_shielded::SharedShieldedState>,
        addr: SocketAddr,
        chain_id: u32,
    ) -> Arc<Self> {
        Arc::new(Self {
            state,
            observation,
            runtime_recovery,
            registry,
            epoch,
            epoch_progress,
            shielded_state,
            addr,
            chain_id,
            running: AtomicBool::new(false),
            task: Mutex::new(None),
        })
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            anyhow::bail!("DAG RPC service already running");
        }

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(run_dag_rpc_server_with_observation_and_shutdown(
            self.state.clone(),
            self.observation.clone(),
            self.runtime_recovery.clone(),
            self.registry.clone(),
            self.epoch.clone(),
            self.epoch_progress.clone(),
            self.shielded_state.clone(),
            self.addr,
            self.chain_id,
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
        if let Some(task) = task {
            let _ = task.shutdown.send(true);
            match task.handle.await {
                Ok(result) => result,
                Err(err) => Err(anyhow::anyhow!("DAG RPC service join failed: {err}")),
            }
        } else {
            Ok(())
        }
    }
}
