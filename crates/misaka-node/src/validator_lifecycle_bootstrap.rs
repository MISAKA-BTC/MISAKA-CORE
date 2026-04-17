//! Validator lifecycle bootstrap (γ-2.5)
//!
//! Extracted from the duplicated bootstrap blocks previously living in
//! `start_narwhal_node` (main.rs:1253-1329, β-2) and `start_dag_node`
//! (main.rs:4906-4996 + migration at 5658-5669). This module owns:
//!
//! 1. Resolving the lifecycle snapshot file path.
//! 2. Instantiating `ValidatorLifecycleStore` and registering the global
//!    singleton via `install_global_store`.
//! 3. Loading any existing snapshot, falling back to an empty registry
//!    on cache miss / error (optionally seeding a fresh file).
//! 4. Running the `registered_validators.json` → `StakingRegistry`
//!    migration via `genesis_committee::migrate_registered_validators_if_present`.
//! 5. Wrapping the registry in `Arc<RwLock<_>>` so downstream callers
//!    share a single live handle.
//!
//! γ-2.5 is a *pure refactor*: behavior is preserved. Parameters capture
//! the only two points where the two call sites used to diverge:
//!
//! - `log_prefix`   — log label differed ("narwhal:" vs "Layer 6:").
//! - `seed_on_fresh` — `start_dag_node` eagerly `save_snapshot`'d an empty
//!   registry on first run; `start_narwhal_node` did not.
//!
//! γ-3 will add a `StakingConfig` Arc-wrap and wire `StakingRegistry`
//! writes from the `utxo_executor` — both of which live *outside* this
//! module.

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::RwLock;
use tracing::{info, warn};

use misaka_consensus::staking::{StakingConfig, StakingRegistry};

use crate::genesis_committee;
use crate::validator_lifecycle_persistence::{
    self, ValidatorEpochProgress, ValidatorLifecycleSnapshot, ValidatorLifecycleStore,
};

/// Bundle returned from [`bootstrap_validator_lifecycle`].
///
/// Downstream callers wrap `current_epoch` and `epoch_progress` in their own
/// `Arc<RwLock<_>>` / `Arc<Mutex<_>>` as required — those shapes diverge
/// between `start_narwhal_node` and `start_dag_node` today and are out of
/// scope for γ-2.5.
///
/// γ-3: `staking_config` is the canonical process-wide `Arc<StakingConfig>`
/// to share with `ValidatorApiState`, the `UtxoExecutor` and the mempool.
/// It is the *same* Arc as the one stored inside `registry` (verifiable via
/// `Arc::ptr_eq`).
pub struct ValidatorLifecycleBootstrap {
    pub store: Arc<ValidatorLifecycleStore>,
    pub registry: Arc<RwLock<StakingRegistry>>,
    pub current_epoch: u64,
    pub epoch_progress: ValidatorEpochProgress,
    pub staking_config: std::sync::Arc<StakingConfig>,
}

/// Bootstrap the validator lifecycle layer.
///
/// See module-level docs for semantics. Signature arguments map 1:1 to
/// values that used to be computed inline at the two call sites:
///
/// - `data_dir`, `chain_id` — for snapshot path resolution.
/// - `staking_config`       — passed through to a fresh `StakingRegistry`.
/// - `genesis_path`         — used by the β-1 migration hook.
/// - `log_prefix`           — identifies the caller in log lines.
/// - `seed_on_fresh`        — whether to `save_snapshot` an empty registry
///   when no snapshot yet exists (legacy dag-path behavior).
pub async fn bootstrap_validator_lifecycle(
    data_dir: &Path,
    chain_id: u32,
    staking_config: std::sync::Arc<StakingConfig>,
    genesis_path: &Path,
    log_prefix: &str,
    seed_on_fresh: bool,
) -> Result<ValidatorLifecycleBootstrap> {
    let snapshot_path = crate::validator_lifecycle_snapshot_path(data_dir, chain_id);

    // install_global_store is backed by OnceCell::get_or_init, so re-calls
    // with a different Arc return the *first* installed Arc. That gives the
    // desired singleton behavior — the extraction is safe to call once per
    // node startup.
    let store = Arc::new(ValidatorLifecycleStore::new(snapshot_path.clone()));
    let store = validator_lifecycle_persistence::install_global_store(store);

    let (mut restored_registry, restored_epoch, restored_epoch_progress) = match store.load().await
    {
        Ok(Some(mut snapshot)) => {
            info!(
                "{}: restored validator lifecycle snapshot | epoch={} | validators={} | file={}",
                log_prefix,
                snapshot.current_epoch,
                snapshot.registry.all_validators().count(),
                snapshot_path.display(),
            );
            // γ-3: bind the deserialized registry to the caller's
            // canonical `Arc<StakingConfig>` so every downstream consumer
            // (executor, api state, mempool) sees the same instance.
            snapshot.registry.rewire_config_arc(staking_config.clone());
            (
                snapshot.registry,
                snapshot.current_epoch,
                snapshot.epoch_progress,
            )
        }
        Ok(None) => {
            info!(
                "{}: validator lifecycle initialized fresh | file={}",
                log_prefix,
                snapshot_path.display(),
            );
            let registry = StakingRegistry::new_with_config_arc(staking_config.clone());
            let epoch = 0u64;
            let progress = ValidatorEpochProgress::default();
            if seed_on_fresh {
                seed_empty_snapshot(&store, log_prefix, &registry, epoch, &progress).await;
            }
            (registry, epoch, progress)
        }
        Err(e) => {
            warn!(
                "{}: failed to load validator lifecycle snapshot ({}); starting fresh",
                log_prefix, e,
            );
            let registry = StakingRegistry::new_with_config_arc(staking_config.clone());
            let epoch = 0u64;
            let progress = ValidatorEpochProgress::default();
            if seed_on_fresh {
                seed_empty_snapshot(&store, log_prefix, &registry, epoch, &progress).await;
            }
            (registry, epoch, progress)
        }
    };

    // β-1 migration hook (previously lived inline at both call sites, on
    // diverging lines — narwhal:1315-1325, dag:5658-5669). Unified here so
    // that any future path picking up this helper gets the migration for
    // free.
    if let Err(e) = genesis_committee::migrate_registered_validators_if_present(
        genesis_path,
        &mut restored_registry,
        restored_epoch,
    ) {
        warn!(
            "{}: registered_validators.json migration returned error \
             (treated as non-fatal): {}",
            log_prefix, e,
        );
    }

    let bootstrap = ValidatorLifecycleBootstrap {
        store,
        registry: Arc::new(RwLock::new(restored_registry)),
        current_epoch: restored_epoch,
        epoch_progress: restored_epoch_progress,
        staking_config: staking_config.clone(),
    };

    // γ-3: singleton invariant — the registry must share the caller-owned
    // Arc<StakingConfig>. Verify in debug builds so misconfiguration fails
    // loudly at startup (any consumer holding a stale Arc would see stale
    // consensus parameters after a hot config change).
    #[cfg(debug_assertions)]
    {
        let registry_arc = bootstrap.registry.read().await.config_arc();
        debug_assert!(
            std::sync::Arc::ptr_eq(&bootstrap.staking_config, &registry_arc),
            "γ-3 invariant: bootstrap staking_config Arc must match \
             StakingRegistry::config_arc()",
        );
    }

    Ok(bootstrap)
}

async fn seed_empty_snapshot(
    store: &ValidatorLifecycleStore,
    log_prefix: &str,
    registry: &StakingRegistry,
    current_epoch: u64,
    epoch_progress: &ValidatorEpochProgress,
) {
    if let Err(e) = store
        .save_snapshot(&ValidatorLifecycleSnapshot {
            version: 1,
            current_epoch,
            registry: registry.clone(),
            epoch_progress: epoch_progress.clone(),
        })
        .await
    {
        warn!(
            "{}: failed to seed validator lifecycle snapshot: {}",
            log_prefix, e,
        );
    }
}
