use anyhow::Context;
use misaka_consensus::{
    epoch::EpochManager,
    staking::{StakingConfig, StakingRegistry},
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tokio::sync::{Mutex, RwLock};

const SNAPSHOT_VERSION: u32 = 1;

static GLOBAL_STORE: OnceLock<Arc<ValidatorLifecycleStore>> = OnceLock::new();

fn default_snapshot_version() -> u32 {
    SNAPSHOT_VERSION
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidatorEpochProgress {
    #[serde(default)]
    pub checkpoints_in_epoch: u64,
    #[serde(default)]
    pub last_finalized_checkpoint_score: Option<u64>,
}

impl ValidatorEpochProgress {
    pub fn should_use_fallback_clock(&self) -> bool {
        self.last_finalized_checkpoint_score.is_none()
    }

    /// Apply a finalized checkpoint score that was already restored at startup.
    ///
    /// This is a small explicit entry point for the node bootstrap path: when
    /// finality state is recovered from the runtime snapshot, lifecycle
    /// progression should catch up immediately instead of waiting for the
    /// periodic finality ticker to fire.
    pub fn apply_restored_finality_score(
        &mut self,
        current_epoch: &mut u64,
        restored_finalized_score: Option<u64>,
        checkpoint_interval: u64,
    ) -> bool {
        let Some(restored_finalized_score) = restored_finalized_score else {
            return false;
        };

        self.apply_finalized_checkpoint_score(
            current_epoch,
            restored_finalized_score,
            checkpoint_interval,
        )
    }

    /// Replay finalized checkpoint scores recovered from a restart snapshot.
    ///
    /// The helper normalizes ordering before replay so that recovery validation
    /// can consume scores from any bounded source without changing consensus
    /// semantics.
    pub fn replay_finalized_checkpoint_scores<I>(
        &mut self,
        current_epoch: &mut u64,
        finalized_scores: I,
        checkpoint_interval: u64,
    ) -> usize
    where
        I: IntoIterator<Item = u64>,
    {
        let mut scores: Vec<u64> = finalized_scores.into_iter().collect();
        scores.sort_unstable();
        scores.dedup();
        self.apply_finalized_checkpoint_scores(current_epoch, scores, checkpoint_interval)
    }

    pub fn apply_finalized_checkpoint_scores<I>(
        &mut self,
        current_epoch: &mut u64,
        finalized_scores: I,
        checkpoint_interval: u64,
    ) -> usize
    where
        I: IntoIterator<Item = u64>,
    {
        let mut applied = 0;
        for finalized_score in finalized_scores {
            if self.apply_finalized_checkpoint_score(
                current_epoch,
                finalized_score,
                checkpoint_interval,
            ) {
                applied += 1;
            }
        }
        applied
    }

    pub fn apply_finalized_checkpoint_score(
        &mut self,
        current_epoch: &mut u64,
        finalized_score: u64,
        checkpoint_interval: u64,
    ) -> bool {
        let checkpoint_interval = checkpoint_interval.max(1);
        match self.last_finalized_checkpoint_score {
            Some(last_score) if finalized_score <= last_score => false,
            None => {
                self.last_finalized_checkpoint_score = Some(finalized_score);
                true
            }
            Some(last_score) => {
                let mut manager = EpochManager {
                    current_epoch: *current_epoch,
                    checkpoints_in_epoch: self.checkpoints_in_epoch,
                };
                let checkpoints_elapsed =
                    ((finalized_score.saturating_sub(last_score)) / checkpoint_interval).max(1);
                for _ in 0..checkpoints_elapsed {
                    manager.on_checkpoint();
                }
                *current_epoch = manager.current_epoch;
                self.checkpoints_in_epoch = manager.checkpoints_in_epoch;
                self.last_finalized_checkpoint_score = Some(finalized_score);
                true
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorLifecycleSnapshot {
    #[serde(default = "default_snapshot_version")]
    pub version: u32,
    pub current_epoch: u64,
    pub registry: StakingRegistry,
    #[serde(default)]
    pub epoch_progress: ValidatorEpochProgress,
}

#[derive(Debug)]
pub struct ValidatorLifecycleStore {
    path: PathBuf,
    save_lock: Mutex<()>,
}

impl ValidatorLifecycleStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            save_lock: Mutex::new(()),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub async fn load(&self) -> anyhow::Result<Option<ValidatorLifecycleSnapshot>> {
        if !tokio::fs::try_exists(&self.path).await? {
            return Ok(None);
        }

        let raw = tokio::fs::read_to_string(&self.path)
            .await
            .with_context(|| {
                format!(
                    "failed to read validator lifecycle snapshot at '{}'",
                    self.path.display()
                )
            })?;
        let snapshot: ValidatorLifecycleSnapshot =
            serde_json::from_str(&raw).with_context(|| {
                format!(
                    "failed to parse validator lifecycle snapshot at '{}'",
                    self.path.display()
                )
            })?;
        Ok(Some(snapshot))
    }

    pub async fn save_snapshot(&self, snapshot: &ValidatorLifecycleSnapshot) -> anyhow::Result<()> {
        let _guard = self.save_lock.lock().await;
        self.write_snapshot(snapshot).await
    }

    async fn write_snapshot(&self, snapshot: &ValidatorLifecycleSnapshot) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await.with_context(|| {
                format!(
                    "failed to create validator lifecycle parent dir '{}'",
                    parent.display()
                )
            })?;
        }

        let tmp_path = self.path.with_extension("json.tmp");
        let raw = serde_json::to_vec_pretty(snapshot)?;
        tokio::fs::write(&tmp_path, raw).await.with_context(|| {
            format!(
                "failed to write validator lifecycle snapshot to '{}'",
                tmp_path.display()
            )
        })?;
        tokio::fs::rename(&tmp_path, &self.path)
            .await
            .with_context(|| {
                format!(
                    "failed to replace validator lifecycle snapshot at '{}'",
                    self.path.display()
                )
            })?;
        Ok(())
    }

    pub async fn load_or_default(
        &self,
        config: StakingConfig,
    ) -> anyhow::Result<(StakingRegistry, u64, ValidatorEpochProgress)> {
        if let Some(snapshot) = self.load().await? {
            return Ok((
                snapshot.registry,
                snapshot.current_epoch,
                snapshot.epoch_progress,
            ));
        }

        Ok((
            StakingRegistry::new(config),
            0,
            ValidatorEpochProgress::default(),
        ))
    }

    pub async fn persist_state(
        &self,
        registry: &Arc<RwLock<StakingRegistry>>,
        current_epoch: &Arc<RwLock<u64>>,
        epoch_progress: &Arc<Mutex<ValidatorEpochProgress>>,
    ) -> anyhow::Result<()> {
        let _guard = self.save_lock.lock().await;
        let current_epoch = *current_epoch.read().await;
        let registry = registry.read().await.clone();
        let epoch_progress = epoch_progress.lock().await.clone();

        self.write_snapshot(&ValidatorLifecycleSnapshot {
            version: SNAPSHOT_VERSION,
            current_epoch,
            registry,
            epoch_progress,
        })
        .await
    }

    /// Replay a restored finalized checkpoint score and persist the resulting
    /// lifecycle snapshot immediately.
    ///
    /// This keeps the post-restart in-memory lifecycle state and the on-disk
    /// snapshot aligned as soon as authoritative finality is available, while
    /// still reusing the existing finalized-checkpoint progression logic.
    pub async fn replay_restored_finality_and_persist(
        &self,
        registry: &Arc<RwLock<StakingRegistry>>,
        current_epoch: &Arc<RwLock<u64>>,
        epoch_progress: &Arc<Mutex<ValidatorEpochProgress>>,
        restored_finalized_score: Option<u64>,
        checkpoint_interval: u64,
    ) -> anyhow::Result<bool> {
        let Some(restored_finalized_score) = restored_finalized_score else {
            return Ok(false);
        };

        let replayed = {
            let mut progress = epoch_progress.lock().await;
            let mut epoch = current_epoch.write().await;
            progress.apply_restored_finality_score(
                &mut *epoch,
                Some(restored_finalized_score),
                checkpoint_interval,
            )
        };

        if !replayed {
            return Ok(false);
        }

        self.persist_state(registry, current_epoch, epoch_progress)
            .await?;
        Ok(true)
    }
}

pub fn install_global_store(store: Arc<ValidatorLifecycleStore>) -> Arc<ValidatorLifecycleStore> {
    GLOBAL_STORE.get_or_init(|| store).clone()
}

pub fn global_store() -> Option<Arc<ValidatorLifecycleStore>> {
    GLOBAL_STORE.get().cloned()
}

pub async fn persist_global_state(
    registry: &Arc<RwLock<StakingRegistry>>,
    current_epoch: &Arc<RwLock<u64>>,
    epoch_progress: &Arc<Mutex<ValidatorEpochProgress>>,
) -> anyhow::Result<()> {
    let Some(store) = global_store() else {
        return Ok(());
    };
    store
        .persist_state(registry, current_epoch, epoch_progress)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_path() -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("validator-lifecycle-{stamp}.json"))
    }

    #[tokio::test]
    async fn round_trip_snapshot() {
        let path = unique_path();
        let store = ValidatorLifecycleStore::new(&path);
        let mut registry = StakingRegistry::new(StakingConfig::testnet());
        let mut validator_id = [0u8; 20];
        validator_id[0] = 7;
        registry
            .register(
                validator_id,
                vec![1; 1952],
                10_000_000,
                500,
                validator_id,
                42,
                [9; 32],
                0,
            )
            .expect("register");

        store
            .save_snapshot(&ValidatorLifecycleSnapshot {
                version: SNAPSHOT_VERSION,
                current_epoch: 42,
                registry: registry.clone(),
                epoch_progress: ValidatorEpochProgress {
                    checkpoints_in_epoch: 12,
                    last_finalized_checkpoint_score: Some(720),
                },
            })
            .await
            .expect("save snapshot");

        let loaded = store
            .load()
            .await
            .expect("load snapshot")
            .expect("snapshot");
        assert_eq!(loaded.current_epoch, 42);
        assert_eq!(loaded.epoch_progress.checkpoints_in_epoch, 12);
        assert_eq!(
            loaded.epoch_progress.last_finalized_checkpoint_score,
            Some(720)
        );
        assert_eq!(
            loaded.registry.total_locked_stake(),
            registry.total_locked_stake()
        );

        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn restart_round_trip_preserves_progress_and_catches_up_after_finalized_scores() {
        let path = unique_path();
        let store = ValidatorLifecycleStore::new(&path);
        let mut registry = StakingRegistry::new(StakingConfig::testnet());
        let mut validator_id = [0u8; 20];
        validator_id[0] = 9;
        registry
            .register(
                validator_id,
                vec![2; 1952],
                12_000_000,
                750,
                validator_id,
                17,
                [3; 32],
                0,
            )
            .expect("register");

        store
            .save_snapshot(&ValidatorLifecycleSnapshot {
                version: SNAPSHOT_VERSION,
                current_epoch: 3,
                registry: registry.clone(),
                epoch_progress: ValidatorEpochProgress {
                    checkpoints_in_epoch: 719,
                    last_finalized_checkpoint_score: Some(600),
                },
            })
            .await
            .expect("save snapshot");

        let loaded = store
            .load()
            .await
            .expect("load snapshot")
            .expect("snapshot");
        assert_eq!(loaded.current_epoch, 3);
        assert_eq!(loaded.epoch_progress.checkpoints_in_epoch, 719);
        assert_eq!(
            loaded.epoch_progress.last_finalized_checkpoint_score,
            Some(600)
        );
        assert_eq!(
            loaded.registry.total_locked_stake(),
            registry.total_locked_stake()
        );

        let mut current_epoch = loaded.current_epoch;
        let mut progress = loaded.epoch_progress.clone();
        let applied = progress.replay_finalized_checkpoint_scores(
            &mut current_epoch,
            [618, 606, 612, 606],
            6,
        );
        assert_eq!(applied, 3);
        assert_eq!(current_epoch, 4);
        assert_eq!(progress.checkpoints_in_epoch, 2);
        assert_eq!(progress.last_finalized_checkpoint_score, Some(618));
        assert!(!progress.should_use_fallback_clock());

        store
            .save_snapshot(&ValidatorLifecycleSnapshot {
                version: SNAPSHOT_VERSION,
                current_epoch,
                registry: loaded.registry.clone(),
                epoch_progress: progress.clone(),
            })
            .await
            .expect("save updated snapshot");

        let reloaded = store
            .load()
            .await
            .expect("reload snapshot")
            .expect("snapshot");
        assert_eq!(reloaded.current_epoch, 4);
        assert_eq!(reloaded.epoch_progress.checkpoints_in_epoch, 2);
        assert_eq!(
            reloaded.epoch_progress.last_finalized_checkpoint_score,
            Some(618)
        );
        assert_eq!(
            reloaded.registry.total_locked_stake(),
            registry.total_locked_stake()
        );

        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn restored_finality_replay_is_persisted_on_startup() {
        let path = unique_path();
        let store = ValidatorLifecycleStore::new(&path);
        let registry = Arc::new(RwLock::new(StakingRegistry::new(StakingConfig::testnet())));
        let current_epoch = Arc::new(RwLock::new(3));
        let epoch_progress = Arc::new(Mutex::new(ValidatorEpochProgress {
            checkpoints_in_epoch: 719,
            last_finalized_checkpoint_score: Some(600),
        }));

        let applied = store
            .replay_restored_finality_and_persist(
                &registry,
                &current_epoch,
                &epoch_progress,
                Some(618),
                6,
            )
            .await
            .expect("replay and persist");
        assert!(applied);
        assert_eq!(*current_epoch.read().await, 4);
        assert_eq!(epoch_progress.lock().await.checkpoints_in_epoch, 2);
        assert_eq!(
            epoch_progress.lock().await.last_finalized_checkpoint_score,
            Some(618)
        );

        let reloaded = store
            .load()
            .await
            .expect("reload snapshot")
            .expect("snapshot");
        assert_eq!(reloaded.current_epoch, 4);
        assert_eq!(reloaded.epoch_progress.checkpoints_in_epoch, 2);
        assert_eq!(
            reloaded.epoch_progress.last_finalized_checkpoint_score,
            Some(618)
        );

        let _ = tokio::fs::remove_file(&path).await;
    }

    #[test]
    fn first_finalized_checkpoint_sets_anchor_without_forcing_epoch_jump() {
        let mut progress = ValidatorEpochProgress::default();
        let mut current_epoch = 7;
        assert!(progress.apply_finalized_checkpoint_score(&mut current_epoch, 66, 6));
        assert_eq!(current_epoch, 7);
        assert_eq!(progress.checkpoints_in_epoch, 0);
        assert_eq!(progress.last_finalized_checkpoint_score, Some(66));
        assert!(!progress.should_use_fallback_clock());
    }

    #[test]
    fn finalized_checkpoint_progress_uses_epoch_manager_boundaries() {
        let mut progress = ValidatorEpochProgress {
            checkpoints_in_epoch: 719,
            last_finalized_checkpoint_score: Some(600),
        };
        let mut current_epoch = 3;
        assert!(progress.apply_finalized_checkpoint_score(&mut current_epoch, 606, 6));
        assert_eq!(current_epoch, 4);
        assert_eq!(progress.checkpoints_in_epoch, 0);
        assert_eq!(progress.last_finalized_checkpoint_score, Some(606));
    }

    #[test]
    fn restored_finality_score_is_applied_immediately_on_startup() {
        let mut progress = ValidatorEpochProgress {
            checkpoints_in_epoch: 719,
            last_finalized_checkpoint_score: Some(600),
        };
        let mut current_epoch = 3;

        assert!(progress.apply_restored_finality_score(&mut current_epoch, Some(618), 6));
        assert_eq!(current_epoch, 4);
        assert_eq!(progress.checkpoints_in_epoch, 2);
        assert_eq!(progress.last_finalized_checkpoint_score, Some(618));
        assert!(!progress.should_use_fallback_clock());

        assert!(!progress.apply_restored_finality_score(&mut current_epoch, None, 6));
        assert_eq!(current_epoch, 4);
    }

    #[test]
    fn stale_finalized_checkpoint_is_ignored_after_restart() {
        let mut progress = ValidatorEpochProgress {
            checkpoints_in_epoch: 12,
            last_finalized_checkpoint_score: Some(720),
        };
        let mut current_epoch = 4;
        assert!(!progress.apply_finalized_checkpoint_score(&mut current_epoch, 720, 6));
        assert_eq!(current_epoch, 4);
        assert_eq!(progress.checkpoints_in_epoch, 12);
        assert_eq!(progress.last_finalized_checkpoint_score, Some(720));

        let applied = progress.replay_finalized_checkpoint_scores(
            &mut current_epoch,
            [721, 720, 719, 721],
            6,
        );
        assert_eq!(applied, 1);
        assert_eq!(current_epoch, 4);
        assert_eq!(progress.checkpoints_in_epoch, 13);
        assert_eq!(progress.last_finalized_checkpoint_score, Some(721));
    }
}
