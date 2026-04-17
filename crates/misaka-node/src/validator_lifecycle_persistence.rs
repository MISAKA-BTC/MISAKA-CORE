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
const SNAPSHOT_MAGIC: &str = "MISAKA_VALIDATOR_LIFECYCLE";

/// Envelope wrapper for integrity-protected validator snapshots.
#[derive(Debug, Serialize, Deserialize)]
struct ValidatorSnapshotEnvelope {
    magic: String,
    schema_version: u32,
    checksum: String,
    payload: serde_json::Value,
}

/// Compute SHA3-256 checksum of a validator snapshot payload.
fn compute_snapshot_checksum(payload: &serde_json::Value) -> String {
    use sha3::{Digest, Sha3_256};
    let canonical = serde_json::to_string(payload).unwrap_or_default();
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:validator_snapshot:checksum:v1:");
    h.update(canonical.as_bytes());
    let hash: [u8; 32] = h.finalize().into();
    hex::encode(hash)
}

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

        match self.load_inner(&self.path).await {
            Ok(snapshot) => Ok(Some(snapshot)),
            Err(e) => {
                // Primary corrupt → try backup
                let backup = self.path.with_extension("bak.json");
                if tokio::fs::try_exists(&backup).await.unwrap_or(false) {
                    tracing::warn!("Primary validator snapshot corrupt ({}), trying backup", e);
                    match self.load_inner(&backup).await {
                        Ok(snapshot) => {
                            // Restore backup as primary (with fsync)
                            let raw = tokio::fs::read(&backup).await?;
                            let tmp = self.path.with_extension("json.tmp");
                            tokio::fs::write(&tmp, &raw).await?;
                            // SEC-C1: fsync before rename — prevent zero-byte on power loss
                            if let Ok(file) = tokio::fs::File::open(&tmp).await {
                                let _ = file.sync_all().await;
                            }
                            tokio::fs::rename(&tmp, &self.path).await?;
                            tracing::info!("Restored validator snapshot from backup");
                            Ok(Some(snapshot))
                        }
                        Err(e2) => {
                            anyhow::bail!(
                                "Both primary and backup validator snapshots corrupt: primary={}, backup={}",
                                e,
                                e2
                            );
                        }
                    }
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn load_inner(&self, path: &Path) -> anyhow::Result<ValidatorLifecycleSnapshot> {
        let raw = tokio::fs::read_to_string(path).await.with_context(|| {
            format!(
                "failed to read validator lifecycle snapshot at '{}'",
                path.display()
            )
        })?;

        // Try envelope format first (v2+)
        if let Ok(envelope) = serde_json::from_str::<ValidatorSnapshotEnvelope>(&raw) {
            // Verify magic
            if envelope.magic != SNAPSHOT_MAGIC {
                anyhow::bail!(
                    "invalid magic: expected '{}', got '{}'",
                    SNAPSHOT_MAGIC,
                    envelope.magic
                );
            }
            // Verify checksum
            let computed = compute_snapshot_checksum(&envelope.payload);
            if computed != envelope.checksum {
                anyhow::bail!(
                    "checksum mismatch: expected {}, computed {}",
                    envelope.checksum,
                    computed
                );
            }
            let snapshot: ValidatorLifecycleSnapshot = serde_json::from_value(envelope.payload)
                .with_context(|| "failed to parse validator snapshot payload")?;
            return Ok(snapshot);
        }

        // Fallback: bare JSON (v1 compat)
        let snapshot: ValidatorLifecycleSnapshot =
            serde_json::from_str(&raw).with_context(|| {
                format!(
                    "failed to parse validator lifecycle snapshot at '{}'",
                    path.display()
                )
            })?;
        Ok(snapshot)
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

        // Serialize payload
        let payload = serde_json::to_value(snapshot)?;
        let checksum = compute_snapshot_checksum(&payload);

        // Wrap in integrity envelope
        let envelope = ValidatorSnapshotEnvelope {
            magic: SNAPSHOT_MAGIC.to_string(),
            schema_version: SNAPSHOT_VERSION,
            checksum,
            payload,
        };

        let tmp_path = self.path.with_extension("json.tmp");
        let raw = serde_json::to_vec_pretty(&envelope)?;
        tokio::fs::write(&tmp_path, &raw).await.with_context(|| {
            format!(
                "failed to write validator lifecycle snapshot to '{}'",
                tmp_path.display()
            )
        })?;

        // File fsync
        if let Ok(file) = tokio::fs::File::open(&tmp_path).await {
            let _ = file.sync_all().await;
        }

        // Backup existing snapshot before overwrite
        let backup_path = self.path.with_extension("bak.json");
        if tokio::fs::try_exists(&self.path).await.unwrap_or(false) {
            let _ = tokio::fs::copy(&self.path, &backup_path).await;
        }

        // Atomic rename
        tokio::fs::rename(&tmp_path, &self.path)
            .await
            .with_context(|| {
                format!(
                    "failed to replace validator lifecycle snapshot at '{}'",
                    self.path.display()
                )
            })?;

        // Dir fsync (best-effort, async context)
        #[cfg(unix)]
        {
            if let Some(parent) = self.path.parent() {
                if let Ok(dir) = std::fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
        }

        Ok(())
    }

    /// γ-3: production callers should prefer
    /// [`crate::validator_lifecycle_bootstrap::bootstrap_validator_lifecycle`]
    /// which shares one `Arc<StakingConfig>` across executor / api state.
    /// This helper is retained for test convenience; the internal
    /// `StakingRegistry::new` call is deprecated-but-allowed here.
    #[allow(deprecated)]
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
#[allow(deprecated)] // γ-3: existing tests still call `StakingRegistry::new`
mod tests {
    use super::*;
    use misaka_types::constants::EPOCH_LENGTH;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_path() -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let counter = UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "validator-lifecycle-{}-{stamp}-{counter}.json",
            std::process::id()
        ))
    }

    #[tokio::test]
    async fn round_trip_snapshot() {
        let path = unique_path();
        let store = ValidatorLifecycleStore::new(&path);
        let mut registry = StakingRegistry::new(StakingConfig::testnet());
        let mut validator_id = [0u8; 32];
        validator_id[0] = 7;
        registry
            .register(
                validator_id,
                vec![1; 1952],
                StakingConfig::testnet().min_validator_stake,
                500,
                validator_id,
                42,
                [9; 32],
                0,
                true,
                None,
                false,
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

    /// Regression test: a `persist_global_state` call after a REST
    /// `/api/register_validator` write MUST leave the on-disk snapshot in a
    /// state that restores the newly-registered validator on the next boot.
    ///
    /// This was the bug behind the operator report where a validator that
    /// had gone through `/api/register_validator` came back up with only
    /// the genesis TOML committee on restart: the REST handler mutated the
    /// in-memory registry but never called `persist_global_state`, so the
    /// `validator_lifecycle_chain_N.json` snapshot was never rewritten.
    #[tokio::test]
    async fn persist_global_state_round_trips_rest_registration() {
        use super::install_global_store;

        let path = unique_path();
        let store = Arc::new(ValidatorLifecycleStore::new(&path));
        // Install as the process-wide store so `persist_global_state`
        // (which is the exact API the REST handlers now call) picks it up.
        let _installed = install_global_store(store.clone());

        // Start from an empty registry — simulates a fresh node that has
        // never seen any REST registration.
        let registry = Arc::new(RwLock::new(StakingRegistry::new(StakingConfig::testnet())));
        let current_epoch = Arc::new(RwLock::new(0u64));
        let epoch_progress = Arc::new(Mutex::new(ValidatorEpochProgress::default()));

        // Simulate the REST handler: write to the registry, then call
        // persist_global_state (the call the PR adds to register_validator).
        let mut validator_id = [0u8; 32];
        validator_id[0] = 0x42;
        {
            let mut guard = registry.write().await;
            guard
                .register(
                    validator_id,
                    vec![0xAB; 1952],
                    StakingConfig::testnet().min_validator_stake,
                    500,
                    validator_id,
                    0,
                    [0xCD; 32],
                    0,
                    true,
                    None,
                    false,
                )
                .expect("register succeeds on empty registry");
        }
        persist_global_state(&registry, &current_epoch, &epoch_progress)
            .await
            .expect("persist_global_state succeeds");

        // Simulate a restart: load the snapshot into a fresh registry and
        // confirm the REST-registered validator is still present.
        let reloaded = store
            .load()
            .await
            .expect("load snapshot")
            .expect("snapshot exists after persist");
        assert_eq!(
            reloaded.registry.all_validators().count(),
            1,
            "reloaded registry should contain the REST-registered validator"
        );
        let v = reloaded
            .registry
            .get(&validator_id)
            .expect("validator_id present after reload");
        assert_eq!(v.pubkey.len(), 1952, "pubkey preserved across reload");

        let _ = tokio::fs::remove_file(&path).await;
    }

    #[tokio::test]
    async fn restart_round_trip_preserves_progress_and_catches_up_after_finalized_scores() {
        let path = unique_path();
        let store = ValidatorLifecycleStore::new(&path);
        let mut registry = StakingRegistry::new(StakingConfig::testnet());
        let mut validator_id = [0u8; 32];
        validator_id[0] = 9;
        registry
            .register(
                validator_id,
                vec![2; 1952],
                StakingConfig::testnet().min_validator_stake + 2_000_000,
                750,
                validator_id,
                17,
                [3; 32],
                0,
                true,
                None,
                false,
            )
            .expect("register");

        store
            .save_snapshot(&ValidatorLifecycleSnapshot {
                version: SNAPSHOT_VERSION,
                current_epoch: 3,
                registry: registry.clone(),
                epoch_progress: ValidatorEpochProgress {
                    checkpoints_in_epoch: EPOCH_LENGTH - 1,
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
        assert_eq!(loaded.epoch_progress.checkpoints_in_epoch, EPOCH_LENGTH - 1);
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
            checkpoints_in_epoch: EPOCH_LENGTH - 1,
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
            checkpoints_in_epoch: EPOCH_LENGTH - 1,
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
            checkpoints_in_epoch: EPOCH_LENGTH - 1,
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
