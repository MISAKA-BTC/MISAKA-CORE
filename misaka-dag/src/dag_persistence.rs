use std::collections::HashSet;
use std::fs;
use std::path::Path;

use misaka_storage::utxo_set::{UtxoSet, UtxoSetSnapshot};
use misaka_types::validator::{
    DagCheckpointFinalityProof, DagCheckpointTarget, DagCheckpointVote, ValidatorIdentity,
};

use crate::dag_block::Hash;
use crate::dag_finality::DagCheckpoint;
use crate::dag_state_manager::{ApplyStats, DagStateManager};
use crate::dag_store::{DagStoreDump, ThreadSafeDagStore};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DagCheckpointVotePoolEntry {
    pub target: DagCheckpointTarget,
    pub votes: Vec<DagCheckpointVote>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DagRuntimeSnapshot {
    pub version: u32,
    pub genesis_hash: Hash,
    pub dag_store: DagStoreDump,
    pub utxo_set: UtxoSetSnapshot,
    pub apply_stats: ApplyStats,
    pub latest_checkpoint: Option<DagCheckpoint>,
    pub known_validators: Vec<ValidatorIdentity>,
    pub latest_checkpoint_vote: Option<DagCheckpointVote>,
    pub latest_checkpoint_finality: Option<DagCheckpointFinalityProof>,
    pub checkpoint_vote_pool: Vec<DagCheckpointVotePoolEntry>,
}

pub struct RestoredDagRuntime {
    pub genesis_hash: Hash,
    pub dag_store: ThreadSafeDagStore,
    pub utxo_set: UtxoSet,
    pub state_manager: DagStateManager,
    pub latest_checkpoint: Option<DagCheckpoint>,
    pub known_validators: Vec<ValidatorIdentity>,
    pub latest_checkpoint_vote: Option<DagCheckpointVote>,
    pub latest_checkpoint_finality: Option<DagCheckpointFinalityProof>,
    pub checkpoint_vote_pool:
        std::collections::HashMap<DagCheckpointTarget, Vec<DagCheckpointVote>>,
}

pub fn save_runtime_snapshot(
    path: &Path,
    dag_store: &ThreadSafeDagStore,
    utxo_set: &UtxoSet,
    apply_stats: &ApplyStats,
    latest_checkpoint: Option<&DagCheckpoint>,
    known_validators: &[ValidatorIdentity],
    latest_checkpoint_vote: Option<&DagCheckpointVote>,
    latest_checkpoint_finality: Option<&DagCheckpointFinalityProof>,
    checkpoint_vote_pool: &std::collections::HashMap<DagCheckpointTarget, Vec<DagCheckpointVote>>,
) -> Result<(), String> {
    let dag_dump = dag_store.export_dump();
    let checkpoint_vote_pool: Vec<DagCheckpointVotePoolEntry> = checkpoint_vote_pool
        .iter()
        .map(|(target, votes)| DagCheckpointVotePoolEntry {
            target: target.clone(),
            votes: votes.clone(),
        })
        .collect();
    let snapshot = DagRuntimeSnapshot {
        version: 1,
        genesis_hash: dag_dump.genesis_hash,
        dag_store: dag_dump,
        utxo_set: utxo_set.export_snapshot(),
        apply_stats: apply_stats.clone(),
        latest_checkpoint: latest_checkpoint.cloned(),
        known_validators: known_validators.to_vec(),
        latest_checkpoint_vote: latest_checkpoint_vote.cloned(),
        latest_checkpoint_finality: latest_checkpoint_finality.cloned(),
        checkpoint_vote_pool: checkpoint_vote_pool.clone(),
    };

    let bytes = serde_json::to_vec_pretty(&snapshot).map_err(|e| e.to_string())?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    // ── SEC-C1: Crash-safe write (matches checkpoint.rs pattern) ──
    //
    // Previous code used `fs::write()` which does NOT guarantee fsync.
    // On power loss between write and rename, the OS page cache may not
    // have flushed to disk, resulting in a zero-byte or truncated .tmp
    // file being renamed over the valid snapshot — total data loss.
    //
    // Fix: explicit File::create → BufWriter → flush → sync_all → rename → dir sync.
    // This is the same pattern used by checkpoint.rs (L1 FIX).
    //
    // Sequence of events that was previously dangerous:
    //   1. fs::write(&tmp_path, bytes)  ← data in page cache only
    //   2. fs::rename(&tmp_path, path)  ← rename is journaled immediately
    //   3. ⚡ POWER LOSS               ← page cache lost, file = 0 bytes
    //   4. On restart: path exists but contains 0 bytes → unrecoverable
    //
    // After fix:
    //   1. File::create → write_all → sync_all  ← data on disk
    //   2. fs::rename                            ← atomic swap
    //   3. dir sync_all                          ← rename durable
    //   4. ⚡ Power loss at any point is safe:
    //      - Before sync_all: old snapshot intact (rename hasn't happened)
    //      - After sync_all, before rename: old snapshot intact
    //      - After rename: new snapshot is complete on disk
    let tmp_path = path.with_extension("json.tmp");
    {
        let file = fs::File::create(&tmp_path)
            .map_err(|e| format!("snapshot: create tmp '{}': {}", tmp_path.display(), e))?;
        let mut writer = std::io::BufWriter::new(file);
        std::io::Write::write_all(&mut writer, &bytes)
            .map_err(|e| format!("snapshot: write tmp: {}", e))?;
        std::io::Write::flush(&mut writer).map_err(|e| format!("snapshot: flush tmp: {}", e))?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|e| format!("snapshot: fsync tmp: {}", e))?;
    }
    fs::rename(&tmp_path, path).map_err(|e| {
        format!(
            "snapshot: rename '{}' → '{}': {}",
            tmp_path.display(),
            path.display(),
            e
        )
    })?;

    // fsync parent directory — ensures the rename (directory entry update) is durable.
    // Without this, a power loss after rename but before dir journal flush could
    // leave the directory pointing to the old inode.
    if let Some(parent) = path.parent() {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

pub fn load_runtime_snapshot(
    path: &Path,
    max_delta_history: usize,
) -> Result<Option<RestoredDagRuntime>, String> {
    if !path.exists() {
        return Ok(None);
    }

    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    let snapshot: DagRuntimeSnapshot = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if snapshot.version != 1 {
        return Err(format!(
            "unsupported dag snapshot version: {}",
            snapshot.version
        ));
    }

    let dag_store = ThreadSafeDagStore::from_dump(snapshot.dag_store);
    let utxo_set = UtxoSet::from_snapshot(snapshot.utxo_set, max_delta_history);
    let known_key_images: HashSet<[u8; 32]> =
        utxo_set.export_snapshot().key_images.into_iter().collect();
    // Q-DAG-CT nullifiers: empty for pre-v4 snapshots.
    // v4 snapshot format will include persisted nullifiers.
    let known_nullifiers: HashSet<[u8; 32]> = HashSet::new();
    let state_manager =
        DagStateManager::from_snapshot(known_key_images, known_nullifiers, snapshot.apply_stats);
    let checkpoint_vote_pool = snapshot
        .checkpoint_vote_pool
        .into_iter()
        .map(|entry| (entry.target, entry.votes))
        .collect();

    Ok(Some(RestoredDagRuntime {
        genesis_hash: snapshot.genesis_hash,
        dag_store,
        utxo_set,
        state_manager,
        latest_checkpoint: snapshot.latest_checkpoint,
        known_validators: snapshot.known_validators,
        latest_checkpoint_vote: snapshot.latest_checkpoint_vote,
        latest_checkpoint_finality: snapshot.latest_checkpoint_finality,
        checkpoint_vote_pool,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::dag_block::{DagBlockHeader, DAG_VERSION, ZERO_HASH};

    #[test]
    fn test_runtime_snapshot_roundtrip() {
        let base = std::env::temp_dir().join(format!(
            "misaka-dag-snapshot-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let genesis_hash = [0x01; 32];
        let dag_store = ThreadSafeDagStore::new(
            genesis_hash,
            DagBlockHeader {
                version: DAG_VERSION,
                parents: vec![],
                timestamp_ms: 1_700_000_000_000,
                tx_root: ZERO_HASH,
                proposer_id: [0; 32],
                nonce: 0,
                blue_score: 0,
                bits: 0,
            },
        );
        let utxo_set = UtxoSet::new(32);

        save_runtime_snapshot(
            &base,
            &dag_store,
            &utxo_set,
            &ApplyStats::default(),
            None,
            &[],
            None,
            None,
            &std::collections::HashMap::new(),
        )
        .unwrap();
        let restored = load_runtime_snapshot(&base, 32).unwrap().unwrap();

        assert_eq!(restored.genesis_hash, genesis_hash);
        assert_eq!(restored.utxo_set.height, 0);
        assert_eq!(restored.dag_store.block_count(), 1);
        assert!(restored.known_validators.is_empty());
        assert!(restored.latest_checkpoint_vote.is_none());
        assert!(restored.latest_checkpoint_finality.is_none());
        assert!(restored.checkpoint_vote_pool.is_empty());

        let _ = fs::remove_file(base);
    }
}
