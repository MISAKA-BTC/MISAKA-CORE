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

use misaka_muhash::MuHash;
// PR E: SMT state root migration.
use misaka_smt::key::{smt_key, smt_value};
use misaka_smt::tree::SparseMerkleTree;
use misaka_types::utxo::{OutputRef, TxOutput, TxType, UtxoTransaction};
use std::collections::{HashMap, HashSet};

/// A stored UTXO entry.
#[derive(Debug, Clone)]
pub struct UtxoEntry {
    pub outref: OutputRef,
    pub output: TxOutput,
    /// Block height at which this UTXO was created.
    pub created_at: u64,
    /// §4.4: Whether this UTXO was created by a SystemEmission/Coinbase transaction.
    /// Emission outputs require 300-block maturity before spending.
    pub is_emission: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredUtxoSnapshot {
    pub outref: OutputRef,
    pub output: TxOutput,
    pub created_at: u64,
    pub spending_pubkey: Option<Vec<u8>>,
    /// §4.4: Whether this UTXO was created by SystemEmission.
    #[serde(default)]
    pub is_emission: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UtxoSetSnapshot {
    pub height: u64,
    pub unspent: Vec<StoredUtxoSnapshot>,
    // Phase 2c-B D4c: spend_ids deleted
    /// SEC-FIX: Persisted burn IDs for bridge replay protection across restarts.
    /// Without this, `UtxoExecutor::check_burn_replay()` is ineffective after
    /// a node restart — the same Solana burn tx can be replayed for double-mint.
    /// Uses `#[serde(default)]` for backward compatibility with existing snapshots.
    #[serde(default)]
    pub processed_burns: Vec<[u8; 32]>,

    /// SEC-FIX CRITICAL: Cumulative total emission amount for supply cap enforcement.
    /// Without persistence, `total_emitted` resets to 0 on restart, allowing
    /// unlimited SystemEmission beyond MAX_TOTAL_SUPPLY.
    #[serde(default)]
    pub total_emitted: u64,
}

/// State changes from applying one block (for SPC switch undo).
///
/// # Anonymous SpendTag Model
///
/// In the current model, the validator does NOT know which specific UTXO
/// was consumed by a ML-DSA signature — only the spend identifier is
/// recorded. Therefore `spent` is always empty. Rollback can undo:
/// - Spend tag additions (remove spent tags)
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
    /// DEPRECATED in transparent model — always empty.
    /// Retained for type compatibility; will be removed in v0.5.
    pub spent: Vec<([u8; 32], OutputRef, TxOutput)>,
    // Phase 2c-B D4c: spend_ids_added deleted
}

impl BlockDelta {
    pub fn new(height: u64) -> Self {
        Self {
            height,
            created: Vec::new(),
            spent: Vec::new(),
        }
    }

    pub fn merge(&mut self, other: BlockDelta) {
        self.created.extend(other.created);
        self.spent.extend(other.spent);
    }
}

/// Maximum SPC switch depth. Must be >= 2x max finality lag to handle
/// legitimate DAG reorgs. Previously 36, expanded to 1000 per audit HIGH #12.
pub const MAX_SPC_SWITCH_DEPTH: usize = 1000;

/// UTXO Set with shallow SPC switch support.
///
/// # Spending Key Persistence (FIX-3)
///
/// `spending_pubkeys` stores the ring-signature public key polynomial
/// for each UTXO. This is required for ring member resolution during
/// signature verification. It MUST be persistent (not memory-only)
/// so that verification works after node restart.
#[derive(Clone)]
pub struct UtxoSet {
    /// Unspent outputs indexed by OutputRef.
    unspent: HashMap<OutputRef, UtxoEntry>,
    // Phase 2c-B D4c: spend_ids HashSet deleted (ring removed)
    /// Spending pubkey for each UTXO (serialized Poly bytes).
    /// Persistent: survives restart. Required for ring member resolution.
    spending_pubkeys: HashMap<OutputRef, Vec<u8>>,
    /// Block deltas for SPC switch undo (last N blocks).
    deltas: Vec<BlockDelta>,
    /// Maximum delta history (for pruning).
    max_delta_history: usize,
    /// Current chain height.
    pub height: u64,
    /// PR E (Phase 4): SMT (Sparse Merkle Tree) for state root.
    /// Activated pre-mainnet. Provides O(log N) inclusion/exclusion proofs
    /// and deterministic roots independent of insertion order.
    ///
    /// Key:   `smt_key(tx_hash, output_index)`  — 32 bytes
    /// Value: `smt_value(borsh(TxOutput))`      — 32 bytes
    ///
    /// Superseded the MuHash3072 accumulator (v4 state root) which was
    /// itself a drop-in replacement for the insecure XOR-based MuHash
    /// (v3). Domain is bumped to `v5` on finalize.
    smt: SparseMerkleTree,
    /// DEPRECATED: kept as a no-op shim so `apply_block`/`undo_last_delta`
    /// paths that still call `muhash.add_element/remove_element` continue
    /// to compile during the incremental migration. The field is not
    /// used by `compute_state_root()` — the SMT root is authoritative.
    #[allow(dead_code)]
    muhash: MuHash,
    /// Cached total amount across all UTXOs (JSON-RPC DoS prevention).
    /// Updated incrementally on add_output / remove_output.
    cached_total_amount: u64,
}

/// Phase 3 C6: Compute the canonical byte representation of a UTXO element
/// for MuHash accumulation. Uses borsh encoding for determinism.
fn utxo_element_bytes(outref: &OutputRef, output: &TxOutput, height: u64) -> Vec<u8> {
    use borsh::BorshSerialize;
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(b"MISAKA:muhash:utxo:v1:");
    // SEC-FIX CRITICAL: borsh failures MUST panic, not silently skip.
    // Previously `if let Ok(...)` silently dropped failed serializations,
    // causing the MuHash accumulator to produce incorrect state roots.
    // Different nodes could compute different roots for the same UTXO set.
    let outref_bytes = borsh::to_vec(outref)
        .expect("OutputRef borsh serialization must not fail — type is fixed-size");
    buf.extend_from_slice(&outref_bytes);
    let output_bytes = borsh::to_vec(output).expect("TxOutput borsh serialization must not fail");
    buf.extend_from_slice(&output_bytes);
    buf.extend_from_slice(&height.to_le_bytes());
    buf
}

/// Public v4 element bytes accessor for test/comparison purposes.
pub fn utxo_element_bytes_v4_pub(outref: &OutputRef, output: &TxOutput, height: u64) -> Vec<u8> {
    utxo_element_bytes(outref, output, height)
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

/// Errors from `register_spending_key`.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SpendingKeyError {
    #[error("spending key already registered for outref {outref:?}")]
    AlreadyRegistered { outref: OutputRef },
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
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
            spending_pubkeys: HashMap::new(),
            deltas: Vec::new(),
            max_delta_history: clamped,
            height: 0,
            smt: SparseMerkleTree::new(),
            muhash: MuHash::new(), // shim — see field docstring
            cached_total_amount: 0,
        }
    }

    // ─── Spending Key Persistence (FIX-3) ───────────────

    /// Register a spending public key for a UTXO.
    /// Called when outputs are created (genesis, block apply, faucet).
    /// The key is stored persistently alongside the UTXO.
    ///
    /// # Security (Audit #11)
    /// - Rejects duplicate registration for the same outref (prevents UTXO hijack)
    /// - Validates key length (must be ML-DSA-65 = 1952 bytes)
    /// - Returns Err if validation fails
    pub fn register_spending_key(
        &mut self,
        outref: OutputRef,
        pubkey_bytes: Vec<u8>,
    ) -> Result<(), SpendingKeyError> {
        // Length validation: ML-DSA-65 public key is exactly 1952 bytes
        if pubkey_bytes.len() != 1952 {
            return Err(SpendingKeyError::InvalidKeyLength {
                expected: 1952,
                got: pubkey_bytes.len(),
            });
        }

        // Duplicate check: reject if this outref already has a registered key
        if self.spending_pubkeys.contains_key(&outref) {
            return Err(SpendingKeyError::AlreadyRegistered { outref });
        }

        self.spending_pubkeys.insert(outref, pubkey_bytes);
        Ok(())
    }

    /// Get the spending public key for a UTXO.
    /// Falls back to the output's embedded spending_pubkey if the key
    /// was not explicitly registered (recovery for pre-fix faucet UTXOs).
    pub fn get_spending_key(&self, outref: &OutputRef) -> Option<&[u8]> {
        self.spending_pubkeys
            .get(outref)
            .map(|v| v.as_slice())
            .or_else(|| {
                self.unspent
                    .get(outref)
                    .and_then(|e| e.output.spending_pubkey.as_deref())
            })
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

    /// Query all unspent outputs belonging to a given address (P2PKH: SHA3-256 of pubkey).
    /// O(N) scan over all unspent outputs. Acceptable for testnet scale.
    pub fn get_utxos_by_address(&self, address: &[u8; 32]) -> Vec<&UtxoEntry> {
        self.unspent
            .values()
            .filter(|e| &e.output.address == address)
            .collect()
    }

    /// Number of unspent outputs.
    pub fn len(&self) -> usize {
        self.unspent.len()
    }

    pub fn is_empty(&self) -> bool {
        self.unspent.is_empty()
    }

    /// Total amount across all unspent outputs (for supply tracking).
    /// Total amount across all unspent outputs.
    /// Uses cached value maintained incrementally by add_output/remove_output.
    /// O(1) instead of O(N).
    pub fn total_amount(&self) -> u64 {
        self.cached_total_amount
    }

    // ─── Mutate ─────────────────────────────────────────

    /// Add a UTXO (from a new block's outputs).
    ///
    /// `is_emission`: true if this output was created by a SystemEmission transaction.
    /// Emission outputs require 300-block maturity before spending (§4.4).
    pub fn add_output(
        &mut self,
        outref: OutputRef,
        output: TxOutput,
        height: u64,
        is_emission: bool,
    ) -> Result<(), UtxoError> {
        if self.unspent.contains_key(&outref) {
            return Err(UtxoError::OutputAlreadyExists(format!("{:?}", outref)));
        }
        let amount = output.amount;
        // PR E (Phase 4): incremental SMT update.
        //   key   = smt_key(tx_hash, output_index)
        //   value = smt_value(borsh(TxOutput))
        // The `height` is intentionally NOT mixed into the value so that
        // the same UTXO at the same (outref, output) always hashes to
        // the same SMT value — keeps the tree fully content-addressed.
        let k = smt_key(&outref.tx_hash, outref.output_index);
        let v = smt_value(
            &borsh::to_vec(&output).expect("TxOutput is borsh-serializable by construction"),
        );
        self.smt.insert(k, v);
        // Legacy MuHash accumulator kept updated during migration for
        // snapshot round-trip parity; safe to drop when all callers
        // stop reading muhash.
        let elem = utxo_element_bytes(&outref, &output, height);
        self.muhash.add_element(&elem);
        self.unspent.insert(
            outref.clone(),
            UtxoEntry {
                outref,
                output,
                created_at: height,
                is_emission,
            },
        );
        self.cached_total_amount = self.cached_total_amount.saturating_add(amount);
        Ok(())
    }

    /// Remove a spent UTXO from the set and its spending key index.
    /// Called by block producer after a TX consumes this output.
    pub fn remove_output(&mut self, outref: &OutputRef) {
        if let Some(entry) = self.unspent.remove(outref) {
            // PR E (Phase 4): SMT tombstone the key so the tree no longer
            // contains it (exclusion proofs become valid).
            let k = smt_key(&outref.tx_hash, outref.output_index);
            self.smt.remove(&k);
            // Legacy MuHash mirror — see add_output comment.
            let elem = utxo_element_bytes(outref, &entry.output, entry.created_at);
            self.muhash.remove_element(&elem);
            self.cached_total_amount = self.cached_total_amount.saturating_sub(entry.output.amount);
        }
        self.spending_pubkeys.remove(outref);
    }

    /// Record a spend identifier / link_tag) as spent.
    ///
    /// MAINNET: This is the primary spend mechanism. We do NOT mark
    /// specific UTXOs as consumed — spend tracking is handled transparently.
    /// This preserves anonymity: the validator cannot determine which
    // Phase 2c-B D4c: record_spend_tag deleted (ring removed)

    /// Apply a transaction — consume inputs and create outputs.
    ///
    /// SECURITY: Each input UTXO is removed from the unspent set.
    /// This is the fundamental double-spend prevention mechanism.
    pub fn apply_transaction(&mut self, tx: &UtxoTransaction) -> Result<BlockDelta, UtxoError> {
        let mut delta = BlockDelta::new(self.height);

        // SEC-FIX: Defense-in-depth — reject multi-ref inputs at storage layer.
        // The executor already checks this (FIX 98), but enforce here too
        // to prevent any bypass path from consuming unowned UTXOs.
        for (i, input) in tx.inputs.iter().enumerate() {
            if input.utxo_refs.len() > 1 {
                return Err(UtxoError::OutputNotFound(format!(
                    "input[{}]: multi-ref inputs not allowed (got {} refs) — signature bypass risk",
                    i,
                    input.utxo_refs.len()
                )));
            }
        }

        // Consume inputs: remove each referenced UTXO from the unspent set
        for input in &tx.inputs {
            for outref in &input.utxo_refs {
                if self.unspent.contains_key(outref) {
                    // Record spent UTXO in delta for potential rollback
                    if let Some(entry) = self.unspent.get(outref) {
                        delta
                            .spent
                            .push((outref.tx_hash, outref.clone(), entry.output.clone()));
                    }
                    self.remove_output(outref);
                } else {
                    return Err(UtxoError::OutputNotFound(format!(
                        "input UTXO {}:{} not found (already spent or never existed)",
                        hex::encode(&outref.tx_hash[..8]),
                        outref.output_index,
                    )));
                }
            }
        }

        // Create outputs
        let tx_hash = tx.tx_hash();
        for (idx, output) in tx.outputs.iter().enumerate() {
            let outref = OutputRef {
                tx_hash,
                output_index: idx as u32,
            };
            self.add_output(outref.clone(), output.clone(), self.height, false)?;

            // SEC-FIX CRITICAL: Register spending_pubkey for new outputs.
            // Without this, get_spending_key() returns None for all DAG-committed
            // outputs, causing validate_transparent_transfer() to reject every
            // subsequent spend of these outputs (chain functionality failure).
            // Previously only the legacy block_producer path called register_spending_key().
            if let Some(ref spk) = output.spending_pubkey {
                // Ignore errors (key already registered from snapshot restore, etc.)
                let _ = self.register_spending_key(outref.clone(), spk.clone());
            }

            delta.created.push(outref);
        }

        Ok(delta)
    }

    // Legacy spend() and apply_transaction(real_input_refs) have been
    // permanently removed. Use record_spend_tag() and
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
    /// In the transparent model, undo can remove spend-tag additions
    /// and output creations, but CANNOT restore consumed UTXOs. For full
    /// state recovery, use rebuild-from-checkpoint.
    pub fn undo_last_delta(&mut self) -> Result<BlockDelta, UtxoError> {
        let delta = self
            .deltas
            .pop()
            .ok_or_else(|| UtxoError::NoDeltaForRollback(self.height))?;

        // Phase 2c-B D4c: spend-tag undo deleted

        // Audit R7: Restore spent UTXOs (previously skipped, causing state divergence on reorg)
        // SEC-FIX H-12: Propagate restore failures instead of logging and continuing.
        // A failed UTXO restore means corrupted state; must abort the undo.
        for (_tx_hash, outref, output) in &delta.spent {
            let height = delta.height;
            self.add_output(outref.clone(), output.clone(), height, false)
                .map_err(|e| {
                    tracing::error!(
                        "undo_last_delta: failed to restore spent UTXO {:?}: {}",
                        outref,
                        e
                    );
                    e
                })?;
        }

        // Remove created UTXOs (and update MuHash)
        for outref in &delta.created {
            self.remove_output(outref);
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

    /// Compute the state root using a Sparse Merkle Tree (HARD FORK v5).
    ///
    /// PR E (Phase 4) activates SMT pre-mainnet, replacing the MuHash3072
    /// accumulator that PR B introduced as the `v4` drop-in for the
    /// insecure XOR-based MuHash (`v3`). SMT gives:
    ///   - content-addressed, order-independent roots (O(log N) update)
    ///   - inclusion / exclusion proofs for RPC clients
    ///   - a stable tree that matches the frozen v1.0 consensus spec
    ///
    /// Domain: `MISAKA:state_root:v5:` — bumped from `v4` for SMT transition.
    ///
    /// # Determinism Guarantee
    ///
    /// `SparseMerkleTree` is a keyed structure: the root is the hash of
    /// the tree with all (smt_key, smt_value) pairs for currently-unspent
    /// outputs. The same UTXO set always produces the same root.
    pub fn compute_state_root(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};

        let smt_root = self.smt.root();

        let mut h = Sha3_256::new();
        h.update(b"MISAKA:state_root:v5:");
        h.update(self.height.to_le_bytes());
        h.update(smt_root);
        h.finalize().into()
    }

    /// Alias for `compute_state_root()` — O(1) thanks to MuHash3072.
    /// Exposed as a named getter for RPC callers.
    #[inline]
    pub fn cached_state_root(&self) -> [u8; 32] {
        self.compute_state_root()
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
                spending_pubkey: self
                    .spending_pubkeys
                    .get(outref)
                    .cloned()
                    .or_else(|| entry.output.spending_pubkey.clone()),
                is_emission: entry.is_emission,
            })
            .collect();
        unspent.sort_by(|a, b| {
            a.outref
                .tx_hash
                .cmp(&b.outref.tx_hash)
                .then_with(|| a.outref.output_index.cmp(&b.outref.output_index))
        });

        UtxoSetSnapshot {
            height: self.height,
            unspent,
            processed_burns: Vec::new(), // Populated by UtxoExecutor before save
            total_emitted: 0,            // Populated by UtxoExecutor before save
        }
    }

    /// SEC-FIX: Export snapshot with processed burn IDs for persistence.
    ///
    /// The caller (UtxoExecutor) provides the burn IDs since they are tracked
    /// by the executor, not the UTXO set itself.
    pub fn export_snapshot_with_burns(&self, burn_ids: Vec<[u8; 32]>) -> UtxoSetSnapshot {
        let mut snapshot = self.export_snapshot();
        snapshot.processed_burns = burn_ids;
        snapshot
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
            // PR E: rebuild SMT from all unspent UTXOs during snapshot restore.
            let k = smt_key(&outref.tx_hash, outref.output_index);
            let v = smt_value(
                &borsh::to_vec(&stored.output)
                    .expect("TxOutput is borsh-serializable by construction"),
            );
            set.smt.insert(k, v);
            // Legacy MuHash mirror kept consistent during migration.
            let elem = utxo_element_bytes(&outref, &stored.output, stored.created_at);
            set.muhash.add_element(&elem);
            set.cached_total_amount = set.cached_total_amount.saturating_add(stored.output.amount);
            set.unspent.insert(
                outref.clone(),
                UtxoEntry {
                    outref: outref.clone(),
                    output: stored.output,
                    created_at: stored.created_at,
                    is_emission: stored.is_emission,
                },
            );
            if let Some(pubkey) = stored.spending_pubkey {
                set.spending_pubkeys.insert(outref, pubkey);
            }
        }

        // Phase 2c-B D4c: spend_ids restore deleted

        set
    }

    /// SEC-FIX: Restore from snapshot AND return processed burn IDs.
    ///
    /// `processed_burns` are stored in the snapshot but not part of the UTXO set
    /// itself — they belong to the UtxoExecutor. This method returns them so the
    /// caller can pass them to `UtxoExecutor::load_processed_burns()`.
    /// SEC-FIX: Returns (UtxoSet, burn_ids, total_emitted) for full executor restoration.
    pub fn from_snapshot_with_burns(
        snapshot: UtxoSetSnapshot,
        max_delta_history: usize,
    ) -> (Self, Vec<[u8; 32]>, u64) {
        let burns = snapshot.processed_burns.clone();
        let total_emitted = snapshot.total_emitted;
        let set = Self::from_snapshot(snapshot, max_delta_history);
        (set, burns, total_emitted)
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
                UtxoError::SnapshotIo(format!("failed to create {}: {}", tmp_path.display(), e))
            })?;
            let mut writer = std::io::BufWriter::new(file);
            writer
                .write_all(&envelope)
                .map_err(|e| UtxoError::SnapshotIo(format!("write failed: {}", e)))?;
            writer
                .flush()
                .map_err(|e| UtxoError::SnapshotIo(format!("flush failed: {}", e)))?;
            // L1 FIX: fsync BEFORE rename — ensures bytes are on disk
            writer
                .get_ref()
                .sync_all()
                .map_err(|e| UtxoError::SnapshotIo(format!("fsync failed: {}", e)))?;
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
            let dir = std::fs::File::open(parent)
                .map_err(|e| UtxoError::SnapshotIo(format!("open parent dir: {}", e)))?;
            dir.sync_all()
                .map_err(|e| UtxoError::SnapshotIo(format!("dir fsync: {}", e)))?;
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
            UtxoError::SnapshotIo(format!(
                "metadata read failed for {}: {}",
                path.display(),
                e
            ))
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

    /// BLOCKER A: Save the UTXO set together with the full UtxoExecutor
    /// metadata (`processed_burns` + `total_emitted`) atomically.
    ///
    /// The MuHash3072 → SMT migration (PR E) kept `UtxoSet` as the single
    /// durable state object, but `total_emitted` and `processed_burns`
    /// live on `UtxoExecutor`. Without this helper the save path had two
    /// silent bugs:
    ///
    /// 1. `save_to_file` called `export_snapshot()` → wrote
    ///    `total_emitted = 0`, so `MAX_TOTAL_SUPPLY` enforcement reset to
    ///    zero after every restart (unlimited SystemEmission possible).
    /// 2. `save_to_file` also wrote `processed_burns = []`, so the bridge
    ///    replay check (`UtxoExecutor::check_burn_replay`) lost its state.
    ///
    /// This function writes the envelope format used by `load_from_file`
    /// / `load_from_file_with_burns` (32-byte SHA3-256 integrity prefix +
    /// JSON payload), using the same atomic write path as `save_to_file`
    /// (tmp → fsync → rename → dir fsync).
    pub fn save_to_file_full(
        &self,
        path: &std::path::Path,
        burn_ids: Vec<[u8; 32]>,
        total_emitted: u64,
    ) -> Result<(), UtxoError> {
        use sha3::{Digest, Sha3_256};
        use std::io::Write;

        let mut snapshot = self.export_snapshot();
        snapshot.processed_burns = burn_ids;
        snapshot.total_emitted = total_emitted;

        let payload = serde_json::to_vec(&snapshot)
            .map_err(|e| UtxoError::SnapshotIo(format!("serialize failed: {}", e)))?;

        let content_hash: [u8; 32] = Sha3_256::digest(&payload).into();

        let mut envelope = Vec::with_capacity(32 + payload.len());
        envelope.extend_from_slice(&content_hash);
        envelope.extend_from_slice(&payload);

        let tmp_path = path.with_extension("tmp");
        {
            let file = std::fs::File::create(&tmp_path).map_err(|e| {
                UtxoError::SnapshotIo(format!("failed to create {}: {}", tmp_path.display(), e))
            })?;
            let mut writer = std::io::BufWriter::new(file);
            writer
                .write_all(&envelope)
                .map_err(|e| UtxoError::SnapshotIo(format!("write failed: {}", e)))?;
            writer
                .flush()
                .map_err(|e| UtxoError::SnapshotIo(format!("flush failed: {}", e)))?;
            writer
                .get_ref()
                .sync_all()
                .map_err(|e| UtxoError::SnapshotIo(format!("fsync failed: {}", e)))?;
        }

        std::fs::rename(&tmp_path, path).map_err(|e| {
            UtxoError::SnapshotIo(format!(
                "rename {} → {}: {}",
                tmp_path.display(),
                path.display(),
                e
            ))
        })?;

        if let Some(parent) = path.parent() {
            let dir = std::fs::File::open(parent)
                .map_err(|e| UtxoError::SnapshotIo(format!("open parent dir: {}", e)))?;
            dir.sync_all()
                .map_err(|e| UtxoError::SnapshotIo(format!("dir fsync: {}", e)))?;
        }

        Ok(())
    }

    /// SEC-FIX: Load UTXO set AND processed burn IDs from snapshot.
    ///
    /// Returns `(UtxoSet, Vec<burn_id>)` where burn_ids should be passed to
    /// `UtxoExecutor::load_processed_burns()` at startup.
    pub fn load_from_file_with_burns(
        path: &std::path::Path,
        max_delta_history: usize,
    ) -> Result<Option<(Self, Vec<[u8; 32]>, u64)>, UtxoError> {
        use sha3::{Digest, Sha3_256};

        if !path.exists() {
            return Ok(None);
        }

        let meta = std::fs::metadata(path).map_err(|e| {
            UtxoError::SnapshotIo(format!(
                "metadata read failed for {}: {}",
                path.display(),
                e
            ))
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

        let parse_snapshot = |bytes: &[u8]| -> Result<UtxoSetSnapshot, UtxoError> {
            serde_json::from_slice(bytes)
                .map_err(|e| UtxoError::SnapshotIntegrity(format!("JSON parse failed: {}", e)))
        };

        let snapshot = if data.len() < 32 {
            parse_snapshot(&data)?
        } else {
            let stored_hash: [u8; 32] = data[..32]
                .try_into()
                .map_err(|_| UtxoError::SnapshotIntegrity("hash prefix too short".into()))?;
            let payload = &data[32..];
            let computed_hash: [u8; 32] = Sha3_256::digest(payload).into();
            if stored_hash == computed_hash {
                parse_snapshot(payload)?
            } else {
                parse_snapshot(&data).map_err(|_| {
                    UtxoError::SnapshotIntegrity(format!(
                        "content hash mismatch: stored={}, computed={}",
                        hex::encode(&stored_hash[..8]),
                        hex::encode(&computed_hash[..8]),
                    ))
                })?
            }
        };

        let (set, burns, total_emitted) =
            Self::from_snapshot_with_burns(snapshot, max_delta_history);
        Ok(Some((set, burns, total_emitted)))
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
            address: [0xCC; 32],
            spending_pubkey: None,
        }
    }

    #[test]
    fn test_add_and_get() {
        let mut set = UtxoSet::new(100);
        let outref = make_outref(1, 0);
        set.add_output(outref.clone(), make_output(1000), 1, false)
            .unwrap();
        assert!(set.get(&outref).is_some());
        assert_eq!(set.get(&outref).unwrap().output.amount, 1000);
        assert_eq!(set.get_output(&outref).unwrap().amount, 1000);
    }

    // Phase 2c-B D4c: test_record_spend_tag and test_double_spend_rejected deleted

    #[test]
    fn test_amount_conservation() {
        let mut set = UtxoSet::new(100);
        let o1 = make_outref(1, 0);
        let o2 = make_outref(1, 1);
        set.add_output(o1.clone(), make_output(7000), 1, false)
            .unwrap();
        set.add_output(o2.clone(), make_output(3000), 1, false)
            .unwrap();

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

        let mut d2 = BlockDelta::new(1);
        d2.created.push(make_outref(2, 0));

        d1.merge(d2);
        assert_eq!(d1.created.len(), 2);
    }

    #[test]
    fn test_undo_last_delta_undoes_spent_tags_and_outputs() {
        let mut set = UtxoSet::new(100);
        let outref = make_outref(1, 0);
        set.add_output(outref.clone(), make_output(1000), 0, false)
            .unwrap();

        // Create a new output in a block delta
        let created_outref = make_outref(99, 0);
        set.add_output(created_outref.clone(), make_output(900), 1, false)
            .unwrap();

        let delta = BlockDelta {
            height: 1,
            created: vec![created_outref.clone()],
            spent: vec![],
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
        // Phase 2c-B: spend-tag assertion deleted
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
        a.add_output(make_outref(1, 0), make_output(1000), 0, false)
            .unwrap();
        b.add_output(make_outref(1, 0), make_output(1000), 0, false)
            .unwrap();
        assert_eq!(a.compute_state_root(), b.compute_state_root());
    }

    #[test]
    fn test_state_root_differs_on_different_state() {
        let mut a = UtxoSet::new(100);
        let mut b = UtxoSet::new(100);
        a.add_output(make_outref(1, 0), make_output(1000), 0, false)
            .unwrap();
        b.add_output(make_outref(1, 0), make_output(2000), 0, false)
            .unwrap(); // different amount
        assert_ne!(a.compute_state_root(), b.compute_state_root());
    }

    // Phase 3 C6: test_state_root_differs_with_spend_tag deleted (spend tags removed).

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
        a.add_output(make_outref(1, 0), make_output(1000), 0, false)
            .unwrap();
        b.add_output(make_outref(1, 0), make_output(1000), 0, false)
            .unwrap();
        a.height = 1;
        b.height = 2;
        assert_ne!(a.compute_state_root(), b.compute_state_root());
    }

    #[test]
    fn test_snapshot_roundtrip_preserves_outputs_and_spending_keys() {
        let mut set = UtxoSet::new(100);
        let outref = make_outref(7, 1);
        set.add_output(outref.clone(), make_output(4242), 3, false)
            .unwrap();
        set.register_spending_key(outref.clone(), vec![0xAB; 1952])
            .unwrap();
        set.height = 9;

        let snapshot = set.export_snapshot();
        let restored = UtxoSet::from_snapshot(snapshot, 100);

        assert_eq!(restored.height, 9);
        assert_eq!(restored.get(&outref).unwrap().output.amount, 4242);
        assert_eq!(
            restored.get_spending_key(&outref).unwrap(),
            &[0xAB; 1952][..]
        );
        assert_eq!(restored.compute_state_root(), set.compute_state_root());
    }
}

impl UtxoSet {
    // ─── Atomic Block Application ────────────────────────

    /// Apply an entire block atomically.
    ///
    /// All spend records and output creations succeed together
    /// or none are applied. This prevents partial state on crash.
    ///
    /// # Atomicity Model
    ///
    /// 1. Collect all mutations into a pending batch
    /// 2. Validate ALL operations can succeed (dry-run)
    /// 3. Apply all mutations in one pass
    /// 4. If any step fails, no state is modified
    /// Phase 2c-B D4c: spend_ids parameter removed.
    pub fn apply_block_atomic(
        &mut self,
        transactions: &[misaka_types::utxo::UtxoTransaction],
        height: u64,
    ) -> Result<BlockDelta, UtxoError> {
        let mut seen_outrefs: std::collections::HashSet<OutputRef> =
            std::collections::HashSet::new();

        for tx in transactions {
            // SEC-FIX CRITICAL: Reject non-emission tx types.
            // apply_block_atomic only creates outputs — it does NOT consume inputs.
            // If a TransparentTransfer were passed here, input UTXOs would remain
            // unspent, enabling double-spending. Restrict to emission-only types.
            if !matches!(
                tx.tx_type,
                misaka_types::utxo::TxType::SystemEmission | misaka_types::utxo::TxType::Faucet
            ) {
                return Err(UtxoError::OutputNotFound(format!(
                    "apply_block_atomic: rejected tx_type {:?} — only SystemEmission/Faucet allowed",
                    tx.tx_type
                )));
            }

            // Output ref pre-validation (C-T7-4 fix)
            let tx_hash = tx.tx_hash();
            for idx in 0..tx.outputs.len() {
                let outref = OutputRef {
                    tx_hash,
                    output_index: idx as u32,
                };
                if self.unspent.contains_key(&outref) {
                    return Err(UtxoError::OutputAlreadyExists(format!(
                        "{}:{} (already in UTXO set)",
                        hex::encode(&outref.tx_hash[..8]),
                        outref.output_index,
                    )));
                }
                if !seen_outrefs.insert(outref) {
                    return Err(UtxoError::OutputAlreadyExists(format!(
                        "{}:{} (intra-block duplicate output)",
                        hex::encode(&tx_hash[..8]),
                        idx,
                    )));
                }
            }
        }

        // Phase 2: Apply — all validations passed, commit mutations
        let mut delta = BlockDelta::new(height);

        for tx in transactions {
            let is_emission = tx.tx_type == TxType::SystemEmission;
            let tx_hash = tx.tx_hash();
            for (idx, output) in tx.outputs.iter().enumerate() {
                let outref = OutputRef {
                    tx_hash,
                    output_index: idx as u32,
                };
                self.add_output(outref.clone(), output.clone(), height, is_emission)?;
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
