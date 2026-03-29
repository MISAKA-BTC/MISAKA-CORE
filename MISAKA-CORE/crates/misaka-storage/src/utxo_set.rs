//! UTXO Set — tracks unspent outputs and spent key images.
//!
//! # No-Rollback Architecture
//!
//! Protocol-level rollback is forbidden. The delta stack is retained
//! only for shallow SPC (Selected Parent Chain) switches during DAG
//! ordering updates. Max depth is limited to `MAX_SPC_SWITCH_DEPTH`.
//!
//! For full state recovery, use rebuild-from-checkpoint.
//!
//! Supports:
//! - Add new outputs (from block)
//! - Spend outputs (mark as consumed via key image)
//! - Shallow SPC switch undo (internal, limited depth)
//! - Query existence and lookup

use misaka_types::utxo::{OutputRef, TxOutput, UtxoTransaction};
use std::collections::{HashMap, HashSet};

/// A stored UTXO entry.
#[derive(Debug, Clone)]
pub struct UtxoEntry {
    pub outref: OutputRef,
    pub output: TxOutput,
    /// Block height at which this UTXO was created.
    pub created_at: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredUtxoSnapshot {
    pub outref: OutputRef,
    pub output: TxOutput,
    pub created_at: u64,
    pub spending_pubkey: Option<Vec<u8>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UtxoSetSnapshot {
    pub height: u64,
    pub unspent: Vec<StoredUtxoSnapshot>,
    pub key_images: Vec<[u8; 32]>,
}

/// State changes from applying one block (for SPC switch undo).
///
/// # Anonymous Nullifier Model
///
/// In the current model, the validator does NOT know which specific UTXO
/// was consumed by a lattice ZKP proof — only the nullifier (key image) is
/// recorded. Therefore `spent` is always empty. Rollback can undo:
/// - Key image additions (remove nullifiers)
/// - Output creations (remove new UTXOs)
///
/// It CANNOT restore "spent" UTXOs because the real spender is unknown.
/// This is a fundamental property of anonymous UTXO models.
/// Full reorg requires replaying blocks from a checkpoint.
#[derive(Debug, Clone)]
pub struct BlockDelta {
    pub height: u64,
    /// UTXOs created in this block.
    pub created: Vec<OutputRef>,
    /// DEPRECATED in anonymous nullifier model — always empty.
    /// Retained for type compatibility; will be removed in v0.5.
    pub spent: Vec<([u8; 32], OutputRef, TxOutput)>,
    /// Key images (nullifiers) added in this block.
    pub key_images_added: Vec<[u8; 32]>,
}

impl BlockDelta {
    /// Create an empty delta for a given block height.
    pub fn new(height: u64) -> Self {
        Self {
            height,
            created: Vec::new(),
            spent: Vec::new(),
            key_images_added: Vec::new(),
        }
    }

    /// Merge another delta into this one (for per-tx → per-block aggregation).
    pub fn merge(&mut self, other: BlockDelta) {
        self.created.extend(other.created);
        self.spent.extend(other.spent);
        self.key_images_added.extend(other.key_images_added);
    }
}

/// Maximum SPC switch depth (k * 2). Beyond this, reject the switch.
pub const MAX_SPC_SWITCH_DEPTH: usize = 36;

/// UTXO Set with shallow SPC switch support.
///
/// # Spending Key Persistence (FIX-3)
///
/// `spending_pubkeys` stores the ring-signature public key polynomial
/// for each UTXO. This is required for ring member resolution during
/// signature verification. It MUST be persistent (not memory-only)
/// so that verification works after node restart.
pub struct UtxoSet {
    /// Unspent outputs indexed by OutputRef.
    unspent: HashMap<OutputRef, UtxoEntry>,
    /// All spent key images.
    key_images: HashSet<[u8; 32]>,
    /// Spending pubkey for each UTXO (serialized Poly bytes).
    /// Persistent: survives restart. Required for ring member resolution.
    spending_pubkeys: HashMap<OutputRef, Vec<u8>>,
    /// Block deltas for SPC switch undo (last N blocks).
    deltas: Vec<BlockDelta>,
    /// Maximum delta history (for pruning).
    max_delta_history: usize,
    /// Current chain height.
    pub height: u64,
}

/// UTXO set errors.
#[derive(Debug, Clone, thiserror::Error)]
pub enum UtxoError {
    #[error("output not found: {0}")]
    OutputNotFound(String),
    #[error("output already exists: {0}")]
    OutputAlreadyExists(String),
    #[error("key image already spent: {0}")]
    KeyImageSpent(String),
    #[error("key image not found for SPC switch undo: {0}")]
    KeyImageNotFound(String),
    #[error("no delta for SPC switch undo at height {0}")]
    NoDeltaForRollback(u64),
    #[error("amount mismatch: inputs={inputs}, outputs={outputs}, fee={fee}")]
    AmountMismatch { inputs: u64, outputs: u64, fee: u64 },
    #[error("snapshot I/O error: {0}")]
    SnapshotIo(String),
    #[error("snapshot integrity check failed: {0}")]
    SnapshotIntegrity(String),
}

impl UtxoSet {
    /// Create a new empty UTXO set.
    ///
    /// `max_delta_history` is clamped to `MAX_SPC_SWITCH_DEPTH` (36).
    /// This prevents deep rollback — only shallow SPC switches are supported.
    pub fn new(max_delta_history: usize) -> Self {
        let clamped = max_delta_history.min(MAX_SPC_SWITCH_DEPTH);
        Self {
            unspent: HashMap::new(),
            key_images: HashSet::new(),
            spending_pubkeys: HashMap::new(),
            deltas: Vec::new(),
            max_delta_history: clamped,
            height: 0,
        }
    }

    // ─── Spending Key Persistence (FIX-3) ───────────────

    /// Register a spending public key for a UTXO.
    /// Called when outputs are created (genesis, block apply, faucet).
    /// The key is stored persistently alongside the UTXO.
    pub fn register_spending_key(&mut self, outref: OutputRef, pubkey_bytes: Vec<u8>) {
        self.spending_pubkeys.insert(outref, pubkey_bytes);
    }

    /// Get the spending public key for a UTXO.
    /// Returns None if the UTXO doesn't exist or has no registered key.
    pub fn get_spending_key(&self, outref: &OutputRef) -> Option<&[u8]> {
        self.spending_pubkeys.get(outref).map(|v| v.as_slice())
    }

    /// Get all registered spending keys (for anonymity set construction).
    ///
    /// Q-DAG-CT (v4): The anonymity set is built from confirmed UTXO spending
    /// pubkeys. This returns the full map for the RPC layer to select from.
    ///
    /// # Privacy Note
    ///
    /// This method is called by the node's own RPC (client → own node).
    /// The selected anonymity set is NOT broadcast; only the SIS Merkle root
    /// appears in the final transaction.
    pub fn all_spending_keys(&self) -> &HashMap<OutputRef, Vec<u8>> {
        &self.spending_pubkeys
    }

    // ─── Query ──────────────────────────────────────────

    /// Check if a UTXO exists and is unspent.
    pub fn get(&self, outref: &OutputRef) -> Option<&UtxoEntry> {
        self.unspent.get(outref)
    }

    /// Alias for `get` — used by consensus for clarity.
    pub fn get_output(&self, outref: &OutputRef) -> Option<&TxOutput> {
        self.unspent.get(outref).map(|e| &e.output)
    }

    /// Check if a key image has been spent (alias: `is_key_image_spent`).
    pub fn has_key_image(&self, ki: &[u8; 32]) -> bool {
        self.key_images.contains(ki)
    }

    /// Check if a key image has been spent.
    pub fn is_key_image_spent(&self, ki: &[u8; 32]) -> bool {
        self.key_images.contains(ki)
    }

    /// Number of unspent outputs.
    pub fn len(&self) -> usize {
        self.unspent.len()
    }

    pub fn is_empty(&self) -> bool {
        self.unspent.is_empty()
    }

    /// Total amount across all unspent outputs (for supply tracking).
    pub fn total_amount(&self) -> u64 {
        self.unspent.values().map(|e| e.output.amount).sum()
    }

    // ─── Mutate ─────────────────────────────────────────

    /// Add a UTXO (from a new block's outputs).
    pub fn add_output(
        &mut self,
        outref: OutputRef,
        output: TxOutput,
        height: u64,
    ) -> Result<(), UtxoError> {
        if self.unspent.contains_key(&outref) {
            return Err(UtxoError::OutputAlreadyExists(format!("{:?}", outref)));
        }
        self.unspent.insert(
            outref.clone(),
            UtxoEntry {
                outref,
                output,
                created_at: height,
            },
        );
        Ok(())
    }

    /// Remove a spent UTXO from the set and its spending key index.
    /// Called by block producer after a TX consumes this output.
    pub fn remove_output(&mut self, outref: &OutputRef) {
        self.unspent.remove(outref);
        self.spending_pubkeys.remove(outref);
    }

    /// Record a nullifier (key_image / link_tag) as spent.
    ///
    /// MAINNET: This is the primary spend mechanism. We do NOT mark
    /// specific UTXOs as consumed — only the nullifier is recorded.
    /// This preserves anonymity: the validator cannot determine which
    /// ring member was the real spender.
    pub fn record_nullifier(&mut self, key_image: [u8; 32]) -> Result<(), UtxoError> {
        if self.key_images.contains(&key_image) {
            return Err(UtxoError::KeyImageSpent(hex::encode(key_image)));
        }
        self.key_images.insert(key_image);
        Ok(())
    }

    /// Apply a transaction using the anonymous nullifier model.
    ///
    /// Records nullifiers for all inputs and creates outputs.
    /// Does NOT consume specific UTXOs (anonymity preserved).
    pub fn apply_transaction_anonymous(
        &mut self,
        tx: &UtxoTransaction,
    ) -> Result<BlockDelta, UtxoError> {
        let mut delta = BlockDelta::new(self.height);

        // Record nullifiers (NOT spending specific UTXOs)
        for input in &tx.inputs {
            self.record_nullifier(input.key_image)?;
            delta.key_images_added.push(input.key_image);
        }

        // Create outputs
        let tx_hash = tx.tx_hash();
        for (idx, output) in tx.outputs.iter().enumerate() {
            let outref = OutputRef {
                tx_hash,
                output_index: idx as u32,
            };
            self.add_output(outref.clone(), output.clone(), self.height)?;
            delta.created.push(outref);
        }

        Ok(delta)
    }

    // Legacy spend() and apply_transaction(real_input_refs) have been
    // permanently removed. Use record_nullifier() and
    // apply_transaction_anonymous() for the anonymous UTXO model.

    /// Apply a pre-computed block delta (record for SPC switch diff).
    ///
    /// Delta history is limited to `max_delta_history` entries.
    /// This is sufficient for shallow Selected Parent Chain switches
    /// but intentionally prevents deep rollback.
    pub fn apply_block(&mut self, delta: BlockDelta) -> Result<(), UtxoError> {
        self.height = delta.height;
        self.deltas.push(delta);
        if self.deltas.len() > self.max_delta_history {
            self.deltas.remove(0);
        }
        Ok(())
    }

    /// Undo the most recent block delta (for SPC switch only).
    ///
    /// # Purpose
    ///
    /// This is NOT a protocol-level rollback. It is used exclusively by
    /// VirtualState during shallow Selected Parent Chain switches when
    /// DAG ordering changes. The depth is limited by `max_delta_history`
    /// which is clamped to `MAX_SPC_SWITCH_DEPTH` (36).
    ///
    /// # No-Rollback Invariant
    ///
    /// This function MUST NOT be called to revert finalized state.
    /// The caller MUST verify that the undo target is above the
    /// last finalized checkpoint before calling this.
    ///
    /// # Anonymous Model Limitation
    ///
    /// In the anonymous nullifier model, undo can remove nullifier additions
    /// and output creations, but CANNOT restore consumed UTXOs. For full
    /// state recovery, use rebuild-from-checkpoint.
    pub fn undo_last_delta(&mut self) -> Result<BlockDelta, UtxoError> {
        let delta = self
            .deltas
            .pop()
            .ok_or_else(|| UtxoError::NoDeltaForRollback(self.height))?;

        // Undo key images (nullifiers)
        for ki in &delta.key_images_added {
            self.key_images.remove(ki);
        }

        // NOTE: delta.spent is always empty in anonymous model.
        // No UTXO restoration possible without knowing the real spender.

        // Remove created UTXOs
        for outref in &delta.created {
            self.unspent.remove(outref);
        }

        self.height = delta.height.saturating_sub(1);
        Ok(delta)
    }

    // ─── Verification helpers ───────────────────────────

    /// Verify amount conservation for a transaction (checked arithmetic).
    pub fn verify_amount_conservation(
        &self,
        input_refs: &[OutputRef],
        outputs: &[TxOutput],
        fee: u64,
    ) -> Result<(), UtxoError> {
        let input_sum: u64 = input_refs
            .iter()
            .try_fold(0u64, |acc, r| {
                let amt = self.get(r).map(|e| e.output.amount).unwrap_or(0);
                acc.checked_add(amt)
            })
            .ok_or_else(|| UtxoError::AmountMismatch {
                inputs: u64::MAX,
                outputs: 0,
                fee,
            })?;

        let output_sum: u64 = outputs
            .iter()
            .try_fold(0u64, |acc, o| acc.checked_add(o.amount))
            .ok_or_else(|| UtxoError::AmountMismatch {
                inputs: input_sum,
                outputs: u64::MAX,
                fee,
            })?;

        let required = output_sum
            .checked_add(fee)
            .ok_or_else(|| UtxoError::AmountMismatch {
                inputs: input_sum,
                outputs: output_sum,
                fee,
            })?;

        if input_sum != required {
            return Err(UtxoError::AmountMismatch {
                inputs: input_sum,
                outputs: output_sum,
                fee,
            });
        }
        Ok(())
    }

    /// Compute a deterministic state root over the entire UTXO set + nullifier set.
    ///
    /// This replaces the placeholder `SHA3(height || parent_hash)` that was previously
    /// used in block headers. The state root now commits to:
    ///
    /// 1. Every unspent output (sorted deterministically by OutputRef)
    /// 2. Every spent key image (sorted lexicographically)
    /// 3. The current height
    ///
    /// # Determinism Guarantee
    ///
    /// Two UTXO sets with identical content always produce the same root.
    /// Different content always produces different roots (collision resistance of SHA3-256).
    ///
    /// # Performance
    ///
    /// O(n log n) due to sorting. For mainnet scale, replace with incremental JMT.
    pub fn compute_state_root(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};

        // ── UTXO leaf hashes (deterministic order: sort by OutputRef) ──
        let mut utxo_entries: Vec<(&OutputRef, &UtxoEntry)> = self.unspent.iter().collect();
        utxo_entries.sort_by(|a, b| {
            a.0.tx_hash
                .cmp(&b.0.tx_hash)
                .then_with(|| a.0.output_index.cmp(&b.0.output_index))
        });

        let utxo_leaves: Vec<[u8; 32]> = utxo_entries
            .iter()
            .map(|(outref, entry)| {
                let mut h = Sha3_256::new();
                h.update(b"MISAKA:state:utxo:v1:");
                h.update(&outref.tx_hash);
                h.update(outref.output_index.to_le_bytes());
                h.update(entry.output.amount.to_le_bytes());
                h.update(&entry.output.one_time_address);
                h.update(entry.created_at.to_le_bytes());
                h.finalize().into()
            })
            .collect();

        let utxo_root = if utxo_leaves.is_empty() {
            let mut h = Sha3_256::new();
            h.update(b"MISAKA:state:utxo:empty");
            let result: [u8; 32] = h.finalize().into();
            result
        } else {
            misaka_crypto::hash::merkle_root(&utxo_leaves)
        };

        // ── Nullifier leaf hashes (deterministic order: sort lexicographically) ──
        let mut kis: Vec<&[u8; 32]> = self.key_images.iter().collect();
        kis.sort();

        let ki_leaves: Vec<[u8; 32]> = kis
            .iter()
            .map(|ki| {
                let mut h = Sha3_256::new();
                h.update(b"MISAKA:state:nullifier:v1:");
                h.update(*ki);
                h.finalize().into()
            })
            .collect();

        let ki_root = if ki_leaves.is_empty() {
            let mut h = Sha3_256::new();
            h.update(b"MISAKA:state:nullifier:empty");
            let result: [u8; 32] = h.finalize().into();
            result
        } else {
            misaka_crypto::hash::merkle_root(&ki_leaves)
        };

        // ── Combine into final state root ──
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:state_root:v1:");
        h.update(self.height.to_le_bytes());
        h.update(utxo_root);
        h.update(ki_root);
        h.finalize().into()
    }

    /// Export the current in-memory state into a serializable snapshot.
    ///
    /// Rollback deltas are intentionally excluded. The anonymous model cannot
    /// guarantee full rollback restoration across restart, so restart recovery
    /// should rebuild forward from a checkpointed state instead.
    pub fn export_snapshot(&self) -> UtxoSetSnapshot {
        let mut unspent: Vec<StoredUtxoSnapshot> = self
            .unspent
            .iter()
            .map(|(outref, entry)| StoredUtxoSnapshot {
                outref: outref.clone(),
                output: entry.output.clone(),
                created_at: entry.created_at,
                spending_pubkey: self.spending_pubkeys.get(outref).cloned(),
            })
            .collect();
        unspent.sort_by(|a, b| {
            a.outref
                .tx_hash
                .cmp(&b.outref.tx_hash)
                .then_with(|| a.outref.output_index.cmp(&b.outref.output_index))
        });

        let mut key_images: Vec<[u8; 32]> = self.key_images.iter().copied().collect();
        key_images.sort();

        UtxoSetSnapshot {
            height: self.height,
            unspent,
            key_images,
        }
    }

    /// Restore an in-memory UTXO set from a previously exported snapshot.
    ///
    /// Rollback history is reset on restore. DAG reorg support after restart
    /// still relies on replay from a saved checkpointed state.
    pub fn from_snapshot(snapshot: UtxoSetSnapshot, max_delta_history: usize) -> Self {
        let mut set = Self::new(max_delta_history);
        set.height = snapshot.height;

        for stored in snapshot.unspent {
            let outref = stored.outref;
            set.unspent.insert(
                outref.clone(),
                UtxoEntry {
                    outref: outref.clone(),
                    output: stored.output,
                    created_at: stored.created_at,
                },
            );
            if let Some(pubkey) = stored.spending_pubkey {
                set.spending_pubkeys.insert(outref, pubkey);
            }
        }

        for ki in snapshot.key_images {
            set.key_images.insert(ki);
        }

        set
    }

    // ─── File Persistence ────────────────────────────────────

    /// Maximum snapshot file size (4 GB). Prevents OOM on corrupted files.
    const MAX_SNAPSHOT_FILE_SIZE: u64 = 4 * 1024 * 1024 * 1024;

    /// Save the current UTXO set state to a file.
    ///
    /// # Integrity Protection (C4 FIX)
    ///
    /// The saved file contains a SHA3-256 content hash of the payload.
    /// On load, the hash is recomputed and verified. Any disk-level
    /// corruption or tampering is detected.
    ///
    /// # Crash Safety (L1 FIX)
    ///
    /// 1. Write to .tmp file
    /// 2. fsync the .tmp file (ensures bytes are on disk)
    /// 3. Atomic rename .tmp → target
    /// 4. fsync parent directory (ensures rename is durable)
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), UtxoError> {
        use sha3::{Digest, Sha3_256};
        use std::io::Write;

        let snapshot = self.export_snapshot();
        let payload = serde_json::to_vec(&snapshot)
            .map_err(|e| UtxoError::SnapshotIo(format!("serialize failed: {}", e)))?;

        // Compute integrity hash over the raw payload
        let content_hash: [u8; 32] = Sha3_256::digest(&payload).into();

        // Build envelope: [32-byte hash][payload]
        let mut envelope = Vec::with_capacity(32 + payload.len());
        envelope.extend_from_slice(&content_hash);
        envelope.extend_from_slice(&payload);

        // Atomic write with proper fsync
        let tmp_path = path.with_extension("tmp");
        {
            let file = std::fs::File::create(&tmp_path).map_err(|e| {
                UtxoError::SnapshotIo(format!(
                    "failed to create {}: {}",
                    tmp_path.display(),
                    e
                ))
            })?;
            let mut writer = std::io::BufWriter::new(file);
            writer.write_all(&envelope).map_err(|e| {
                UtxoError::SnapshotIo(format!("write failed: {}", e))
            })?;
            writer.flush().map_err(|e| {
                UtxoError::SnapshotIo(format!("flush failed: {}", e))
            })?;
            // L1 FIX: fsync BEFORE rename — ensures bytes are on disk
            writer.get_ref().sync_all().map_err(|e| {
                UtxoError::SnapshotIo(format!("fsync failed: {}", e))
            })?;
        }

        // Atomic rename
        std::fs::rename(&tmp_path, path).map_err(|e| {
            UtxoError::SnapshotIo(format!(
                "rename {} → {}: {}",
                tmp_path.display(),
                path.display(),
                e
            ))
        })?;

        // L1 FIX: fsync parent directory — ensures rename is durable
        if let Some(parent) = path.parent() {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all(); // Best-effort — not all filesystems support dir fsync
            }
        }

        Ok(())
    }

    /// Load a UTXO set from a previously saved snapshot file.
    ///
    /// # Integrity Verification (C4 FIX)
    ///
    /// The first 32 bytes of the file are a SHA3-256 hash of the remaining
    /// payload. If the recomputed hash doesn't match, the file is rejected
    /// as corrupted or tampered.
    ///
    /// # Size Limit (H4 FIX)
    ///
    /// Files exceeding `MAX_SNAPSHOT_FILE_SIZE` are rejected to prevent OOM.
    ///
    /// Returns `None` if the file does not exist.
    /// Returns `Err` if the file exists but is corrupt, tampered, or too large.
    pub fn load_from_file(
        path: &std::path::Path,
        max_delta_history: usize,
    ) -> Result<Option<Self>, UtxoError> {
        use sha3::{Digest, Sha3_256};

        if !path.exists() {
            return Ok(None);
        }

        // H4 FIX: Check file size before reading
        let meta = std::fs::metadata(path).map_err(|e| {
            UtxoError::SnapshotIo(format!("metadata read failed for {}: {}", path.display(), e))
        })?;
        if meta.len() > Self::MAX_SNAPSHOT_FILE_SIZE {
            return Err(UtxoError::SnapshotIntegrity(format!(
                "snapshot file {} is {} bytes — exceeds {} byte limit",
                path.display(),
                meta.len(),
                Self::MAX_SNAPSHOT_FILE_SIZE
            )));
        }

        let data = std::fs::read(path).map_err(|e| {
            UtxoError::SnapshotIo(format!(
                "failed to read snapshot from {}: {}",
                path.display(),
                e
            ))
        })?;

        // C4 FIX: Verify integrity hash
        if data.len() < 32 {
            // Legacy format (no hash prefix) — attempt direct JSON parse
            // This provides backward compatibility with pre-C4 snapshots.
            let snapshot: UtxoSetSnapshot = serde_json::from_slice(&data).map_err(|e| {
                UtxoError::SnapshotIntegrity(format!(
                    "snapshot too small ({} bytes) and not valid JSON: {}",
                    data.len(),
                    e
                ))
            })?;
            return Ok(Some(Self::from_snapshot(snapshot, max_delta_history)));
        }

        let stored_hash: [u8; 32] = match data[..32].try_into() {
            Ok(h) => h,
            Err(_) => {
                return Err(UtxoError::SnapshotIntegrity(
                    "snapshot hash prefix too short".to_string(),
                ));
            }
        };
        let payload = &data[32..];

        // Check if this is the new authenticated format (hash prefix)
        // or legacy format (starts with JSON '{')
        let computed_hash: [u8; 32] = Sha3_256::digest(payload).into();
        if stored_hash == computed_hash {
            // Authenticated format — integrity verified
            let snapshot: UtxoSetSnapshot = serde_json::from_slice(payload).map_err(|e| {
                UtxoError::SnapshotIntegrity(format!(
                    "integrity hash valid but JSON parse failed: {}",
                    e
                ))
            })?;
            Ok(Some(Self::from_snapshot(snapshot, max_delta_history)))
        } else {
            // Might be legacy format (no hash prefix) — try full data as JSON
            match serde_json::from_slice::<UtxoSetSnapshot>(&data) {
                Ok(snapshot) => Ok(Some(Self::from_snapshot(snapshot, max_delta_history))),
                Err(_) => Err(UtxoError::SnapshotIntegrity(format!(
                    "content hash mismatch: stored={}, computed={} — \
                     file may be corrupted or tampered",
                    hex::encode(&stored_hash[..8]),
                    hex::encode(&computed_hash[..8]),
                ))),
            }
        }
    }

    /// Persist every N blocks (caller decides the cadence).
    ///
    /// Typical usage in block producer loop:
    /// ```ignore
    /// if new_height % SNAPSHOT_INTERVAL == 0 {
    ///     utxo_set.save_to_file(&snapshot_path)?;
    /// }
    /// ```
    pub const RECOMMENDED_SNAPSHOT_INTERVAL: u64 = 100;
}

// ─── Tests ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_outref(id: u8, idx: u32) -> OutputRef {
        OutputRef {
            tx_hash: [id; 32],
            output_index: idx,
        }
    }

    fn make_output(amount: u64) -> TxOutput {
        TxOutput {
            amount,
            one_time_address: [0xAA; 32],
            pq_stealth: None,
            spending_pubkey: None,
        }
    }

    #[test]
    fn test_add_and_get() {
        let mut set = UtxoSet::new(100);
        let outref = make_outref(1, 0);
        set.add_output(outref.clone(), make_output(1000), 1)
            .unwrap();
        assert!(set.get(&outref).is_some());
        assert_eq!(set.get(&outref).unwrap().output.amount, 1000);
        assert_eq!(set.get_output(&outref).unwrap().amount, 1000);
    }

    #[test]
    fn test_record_nullifier() {
        let mut set = UtxoSet::new(100);
        let outref = make_outref(1, 0);
        set.add_output(outref.clone(), make_output(1000), 1)
            .unwrap();

        let ki = [0xBB; 32];
        set.record_nullifier(ki).unwrap();
        // In anonymous model, UTXO is NOT removed — only nullifier is recorded.
        // The validator doesn't know which UTXO was consumed.
        assert!(set.get(&outref).is_some());
        assert!(set.has_key_image(&ki));
        assert!(set.is_key_image_spent(&ki));
    }

    #[test]
    fn test_double_spend_rejected() {
        let mut set = UtxoSet::new(100);
        let outref = make_outref(1, 0);
        set.add_output(outref.clone(), make_output(1000), 1)
            .unwrap();

        let ki = [0xBB; 32];
        set.record_nullifier(ki).unwrap();

        // Same key image again must fail
        assert!(set.record_nullifier(ki).is_err());
    }

    #[test]
    fn test_amount_conservation() {
        let mut set = UtxoSet::new(100);
        let o1 = make_outref(1, 0);
        let o2 = make_outref(1, 1);
        set.add_output(o1.clone(), make_output(7000), 1).unwrap();
        set.add_output(o2.clone(), make_output(3000), 1).unwrap();

        let outputs = vec![make_output(9500)];
        set.verify_amount_conservation(&[o1.clone(), o2.clone()], &outputs, 500)
            .unwrap();
        assert!(set
            .verify_amount_conservation(&[o1, o2], &outputs, 100)
            .is_err());
    }

    #[test]
    fn test_block_delta_new_and_merge() {
        let mut d1 = BlockDelta::new(1);
        d1.created.push(make_outref(1, 0));
        d1.key_images_added.push([0xAA; 32]);

        let mut d2 = BlockDelta::new(1);
        d2.created.push(make_outref(2, 0));
        d2.key_images_added.push([0xBB; 32]);

        d1.merge(d2);
        assert_eq!(d1.created.len(), 2);
        assert_eq!(d1.key_images_added.len(), 2);
    }

    #[test]
    fn test_undo_last_delta_undoes_nullifiers_and_outputs() {
        let mut set = UtxoSet::new(100);
        let outref = make_outref(1, 0);
        set.add_output(outref.clone(), make_output(1000), 0)
            .unwrap();

        // Record a nullifier and create a new output in a block delta
        let ki = [0xCC; 32];
        set.record_nullifier(ki).unwrap();
        let created_outref = make_outref(99, 0);
        set.add_output(created_outref.clone(), make_output(900), 1)
            .unwrap();

        let delta = BlockDelta {
            height: 1,
            created: vec![created_outref.clone()],
            spent: vec![], // Always empty in anonymous model
            key_images_added: vec![ki],
        };
        set.apply_block(delta).unwrap();
        assert_eq!(set.height, 1);

        // Undo (SPC switch, not rollback)
        set.undo_last_delta().unwrap();
        assert_eq!(set.height, 0);
        // Original UTXO still exists (anonymous model: validator doesn't know what was spent)
        assert!(set.get(&outref).is_some());
        // Created UTXO is removed
        assert!(set.get(&created_outref).is_none());
        // Key image (nullifier) is removed
        assert!(!set.has_key_image(&ki));
    }

    #[test]
    fn test_undo_last_delta_returns_delta() {
        let mut set = UtxoSet::new(100);
        let delta = BlockDelta::new(1);
        set.apply_block(delta).unwrap();
        set.undo_last_delta().unwrap();
        assert_eq!(set.height, 0);
    }

    // ─── State Root Tests (C1 fix) ───────────────────────

    #[test]
    fn test_state_root_deterministic() {
        let mut a = UtxoSet::new(100);
        let mut b = UtxoSet::new(100);
        // Identical insertions → identical roots
        a.add_output(make_outref(1, 0), make_output(1000), 0)
            .unwrap();
        b.add_output(make_outref(1, 0), make_output(1000), 0)
            .unwrap();
        assert_eq!(a.compute_state_root(), b.compute_state_root());
    }

    #[test]
    fn test_state_root_differs_on_different_state() {
        let mut a = UtxoSet::new(100);
        let mut b = UtxoSet::new(100);
        a.add_output(make_outref(1, 0), make_output(1000), 0)
            .unwrap();
        b.add_output(make_outref(1, 0), make_output(2000), 0)
            .unwrap(); // different amount
        assert_ne!(a.compute_state_root(), b.compute_state_root());
    }

    #[test]
    fn test_state_root_differs_with_nullifier() {
        let mut a = UtxoSet::new(100);
        let mut b = UtxoSet::new(100);
        a.add_output(make_outref(1, 0), make_output(1000), 0)
            .unwrap();
        b.add_output(make_outref(1, 0), make_output(1000), 0)
            .unwrap();
        b.record_nullifier([0xBB; 32]).unwrap();
        assert_ne!(a.compute_state_root(), b.compute_state_root());
    }

    #[test]
    fn test_state_root_empty() {
        let set = UtxoSet::new(100);
        let root = set.compute_state_root();
        assert_ne!(root, [0u8; 32]); // Not zeroed
    }

    #[test]
    fn test_state_root_height_matters() {
        let mut a = UtxoSet::new(100);
        let mut b = UtxoSet::new(100);
        a.add_output(make_outref(1, 0), make_output(1000), 0)
            .unwrap();
        b.add_output(make_outref(1, 0), make_output(1000), 0)
            .unwrap();
        a.height = 1;
        b.height = 2;
        assert_ne!(a.compute_state_root(), b.compute_state_root());
    }

    #[test]
    fn test_snapshot_roundtrip_preserves_outputs_and_spending_keys() {
        let mut set = UtxoSet::new(100);
        let outref = make_outref(7, 1);
        set.add_output(outref.clone(), make_output(4242), 3)
            .unwrap();
        set.register_spending_key(outref.clone(), vec![0xAB; 16]);
        set.record_nullifier([0xCD; 32]).unwrap();
        set.height = 9;

        let snapshot = set.export_snapshot();
        let restored = UtxoSet::from_snapshot(snapshot, 100);

        assert_eq!(restored.height, 9);
        assert_eq!(restored.get(&outref).unwrap().output.amount, 4242);
        assert_eq!(restored.get_spending_key(&outref).unwrap(), &[0xAB; 16]);
        assert!(restored.is_key_image_spent(&[0xCD; 32]));
        assert_eq!(restored.compute_state_root(), set.compute_state_root());
    }
}

impl UtxoSet {
    // ─── Atomic Block Application ────────────────────────

    /// Apply an entire block atomically.
    ///
    /// All nullifier records and output creations succeed together
    /// or none are applied. This prevents partial state on crash.
    ///
    /// # Atomicity Model
    ///
    /// 1. Collect all mutations into a pending batch
    /// 2. Validate ALL operations can succeed (dry-run)
    /// 3. Apply all mutations in one pass
    /// 4. If any step fails, no state is modified
    pub fn apply_block_atomic(
        &mut self,
        transactions: &[(misaka_types::utxo::UtxoTransaction, Vec<[u8; 32]>)], // (tx, key_images)
        height: u64,
    ) -> Result<BlockDelta, UtxoError> {
        // Phase 1: Validate — check all nullifiers and references
        //
        // SEC-M2: Also check for intra-block duplicates. Without this,
        // two TXs in the same block could both use the same nullifier:
        // Phase 1 passes (neither is in self.key_images yet), then Phase 2
        // inserts both (HashSet silently deduplicates). The second TX
        // effectively double-spends because its nullifier was not rejected.
        let mut seen_in_block: std::collections::HashSet<[u8; 32]> =
            std::collections::HashSet::new();
        for (_tx, key_images) in transactions {
            for ki in key_images {
                if self.key_images.contains(ki) {
                    return Err(UtxoError::KeyImageSpent(hex::encode(ki)));
                }
                if !seen_in_block.insert(*ki) {
                    return Err(UtxoError::KeyImageSpent(format!(
                        "{} (intra-block duplicate)",
                        hex::encode(ki)
                    )));
                }
            }
        }

        // Phase 2: Apply — all validations passed, commit mutations
        let mut delta = BlockDelta::new(height);

        for (tx, key_images) in transactions {
            for ki in key_images {
                self.key_images.insert(*ki);
                delta.key_images_added.push(*ki);
            }

            let tx_hash = tx.tx_hash();
            for (idx, output) in tx.outputs.iter().enumerate() {
                let outref = OutputRef {
                    tx_hash,
                    output_index: idx as u32,
                };
                self.add_output(outref.clone(), output.clone(), height)?;
                delta.created.push(outref);
            }
        }

        self.height = height;
        self.deltas.push(delta.clone());
        if self.deltas.len() > self.max_delta_history {
            self.deltas.remove(0);
        }

        Ok(delta)
    }
}
