//! UTXO Set — tracks unspent outputs and spent key images.
//!
//! Supports:
//! - Add new outputs (from block)
//! - Spend outputs (mark as consumed via key image)
//! - Rollback (undo a block's state changes)
//! - Query existence and lookup

use std::collections::{HashMap, HashSet};
use misaka_types::utxo::{OutputRef, TxOutput, UtxoTransaction};

/// A stored UTXO entry.
#[derive(Debug, Clone)]
pub struct UtxoEntry {
    pub outref: OutputRef,
    pub output: TxOutput,
    /// Block height at which this UTXO was created.
    pub created_at: u64,
}

/// State changes from applying one block (for rollback).
#[derive(Debug, Clone)]
pub struct BlockDelta {
    pub height: u64,
    /// UTXOs created in this block.
    pub created: Vec<OutputRef>,
    /// UTXOs spent in this block (key_image → spent OutputRef + output for restore).
    pub spent: Vec<([u8; 32], OutputRef, TxOutput)>,
    /// Key images added in this block.
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

/// UTXO Set with rollback support.
pub struct UtxoSet {
    /// Unspent outputs indexed by OutputRef.
    unspent: HashMap<OutputRef, UtxoEntry>,
    /// All spent key images.
    key_images: HashSet<[u8; 32]>,
    /// Block deltas for rollback (last N blocks).
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
    #[error("key image not found for rollback: {0}")]
    KeyImageNotFound(String),
    #[error("no delta for rollback at height {0}")]
    NoDeltaForRollback(u64),
    #[error("amount mismatch: inputs={inputs}, outputs={outputs}, fee={fee}")]
    AmountMismatch { inputs: u64, outputs: u64, fee: u64 },
}

impl UtxoSet {
    pub fn new(max_delta_history: usize) -> Self {
        Self {
            unspent: HashMap::new(),
            key_images: HashSet::new(),
            deltas: Vec::new(),
            max_delta_history,
            height: 0,
        }
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
    pub fn len(&self) -> usize { self.unspent.len() }

    pub fn is_empty(&self) -> bool { self.unspent.is_empty() }

    // ─── Mutate ─────────────────────────────────────────

    /// Add a UTXO (from a new block's outputs).
    pub fn add_output(
        &mut self, outref: OutputRef, output: TxOutput, height: u64,
    ) -> Result<(), UtxoError> {
        if self.unspent.contains_key(&outref) {
            return Err(UtxoError::OutputAlreadyExists(format!("{:?}", outref)));
        }
        self.unspent.insert(outref.clone(), UtxoEntry {
            outref, output, created_at: height,
        });
        Ok(())
    }

    /// Spend a UTXO by key image.
    pub fn spend(
        &mut self, key_image: [u8; 32], outref: &OutputRef,
    ) -> Result<UtxoEntry, UtxoError> {
        if self.key_images.contains(&key_image) {
            return Err(UtxoError::KeyImageSpent(hex::encode(key_image)));
        }
        let entry = self.unspent.remove(outref)
            .ok_or_else(|| UtxoError::OutputNotFound(format!("{:?}", outref)))?;
        self.key_images.insert(key_image);
        Ok(entry)
    }

    /// Apply a full transaction: spend inputs, create outputs, return delta.
    ///
    /// `real_input_refs` maps each input to the actual UTXO being spent
    /// (since ring members include decoys).
    pub fn apply_transaction(
        &mut self,
        tx: &UtxoTransaction,
        real_input_refs: &[OutputRef],
    ) -> Result<BlockDelta, UtxoError> {
        let mut delta = BlockDelta::new(self.height);

        // Spend inputs
        for (i, input) in tx.inputs.iter().enumerate() {
            let real_ref = &real_input_refs[i];
            let entry = self.spend(input.key_image, real_ref)?;
            delta.spent.push((input.key_image, real_ref.clone(), entry.output));
            delta.key_images_added.push(input.key_image);
        }

        // Create outputs
        let tx_hash = tx.tx_hash();
        for (idx, output) in tx.outputs.iter().enumerate() {
            let outref = OutputRef { tx_hash, output_index: idx as u32 };
            self.add_output(outref.clone(), output.clone(), self.height)?;
            delta.created.push(outref);
        }

        Ok(delta)
    }

    /// Apply a pre-computed block delta (record for rollback).
    pub fn apply_block(&mut self, delta: BlockDelta) -> Result<(), UtxoError> {
        self.height = delta.height;
        self.deltas.push(delta);
        if self.deltas.len() > self.max_delta_history {
            self.deltas.remove(0);
        }
        Ok(())
    }

    /// Rollback the most recent block.
    pub fn rollback(&mut self) -> Result<BlockDelta, UtxoError> {
        let delta = self.deltas.pop()
            .ok_or_else(|| UtxoError::NoDeltaForRollback(self.height))?;

        // Undo key images
        for ki in &delta.key_images_added {
            self.key_images.remove(ki);
        }

        // Restore spent UTXOs
        for (_, outref, output) in &delta.spent {
            self.unspent.insert(outref.clone(), UtxoEntry {
                outref: outref.clone(),
                output: output.clone(),
                created_at: delta.height.saturating_sub(1),
            });
        }

        // Remove created UTXOs
        for outref in &delta.created {
            self.unspent.remove(outref);
        }

        self.height = delta.height.saturating_sub(1);
        Ok(delta)
    }

    /// Alias for `rollback` — used by consensus module.
    pub fn rollback_block(&mut self) -> Result<BlockDelta, UtxoError> {
        self.rollback()
    }

    // ─── Verification helpers ───────────────────────────

    /// Verify amount conservation for a transaction.
    pub fn verify_amount_conservation(
        &self,
        input_refs: &[OutputRef],
        outputs: &[TxOutput],
        fee: u64,
    ) -> Result<(), UtxoError> {
        let input_sum: u64 = input_refs.iter()
            .map(|r| self.get(r).map(|e| e.output.amount).unwrap_or(0))
            .sum();
        let output_sum: u64 = outputs.iter().map(|o| o.amount).sum();

        if input_sum != output_sum + fee {
            return Err(UtxoError::AmountMismatch {
                inputs: input_sum, outputs: output_sum, fee,
            });
        }
        Ok(())
    }
}

// ─── Tests ──────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_outref(id: u8, idx: u32) -> OutputRef {
        OutputRef { tx_hash: [id; 32], output_index: idx }
    }

    fn make_output(amount: u64) -> TxOutput {
        TxOutput { amount, one_time_address: [0xAA; 20], pq_stealth: None }
    }

    #[test]
    fn test_add_and_get() {
        let mut set = UtxoSet::new(100);
        let outref = make_outref(1, 0);
        set.add_output(outref.clone(), make_output(1000), 1).unwrap();
        assert!(set.get(&outref).is_some());
        assert_eq!(set.get(&outref).unwrap().output.amount, 1000);
        assert_eq!(set.get_output(&outref).unwrap().amount, 1000);
    }

    #[test]
    fn test_spend() {
        let mut set = UtxoSet::new(100);
        let outref = make_outref(1, 0);
        set.add_output(outref.clone(), make_output(1000), 1).unwrap();

        let ki = [0xBB; 32];
        let entry = set.spend(ki, &outref).unwrap();
        assert_eq!(entry.output.amount, 1000);
        assert!(set.get(&outref).is_none());
        assert!(set.has_key_image(&ki));
        assert!(set.is_key_image_spent(&ki));
    }

    #[test]
    fn test_double_spend_rejected() {
        let mut set = UtxoSet::new(100);
        let outref = make_outref(1, 0);
        set.add_output(outref.clone(), make_output(1000), 1).unwrap();

        let ki = [0xBB; 32];
        set.spend(ki, &outref).unwrap();

        let outref2 = make_outref(2, 0);
        set.add_output(outref2.clone(), make_output(500), 2).unwrap();
        assert!(set.spend(ki, &outref2).is_err());
    }

    #[test]
    fn test_amount_conservation() {
        let mut set = UtxoSet::new(100);
        let o1 = make_outref(1, 0);
        let o2 = make_outref(1, 1);
        set.add_output(o1.clone(), make_output(7000), 1).unwrap();
        set.add_output(o2.clone(), make_output(3000), 1).unwrap();

        let outputs = vec![make_output(9500)];
        set.verify_amount_conservation(&[o1.clone(), o2.clone()], &outputs, 500).unwrap();
        assert!(set.verify_amount_conservation(&[o1, o2], &outputs, 100).is_err());
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
    fn test_rollback_restores_spent() {
        let mut set = UtxoSet::new(100);
        let outref = make_outref(1, 0);
        set.add_output(outref.clone(), make_output(1000), 0).unwrap();

        // Manually build and apply a delta that spent this UTXO
        let ki = [0xCC; 32];
        let entry = set.spend(ki, &outref).unwrap();
        let created_outref = make_outref(99, 0);
        set.add_output(created_outref.clone(), make_output(900), 1).unwrap();

        let delta = BlockDelta {
            height: 1,
            created: vec![created_outref.clone()],
            spent: vec![(ki, outref.clone(), entry.output.clone())],
            key_images_added: vec![ki],
        };
        set.apply_block(delta).unwrap();
        assert_eq!(set.height, 1);

        // Rollback
        set.rollback().unwrap();
        assert_eq!(set.height, 0);
        // Spent UTXO is restored
        assert!(set.get(&outref).is_some());
        assert_eq!(set.get(&outref).unwrap().output.amount, 1000);
        // Created UTXO is removed
        assert!(set.get(&created_outref).is_none());
        // Key image is removed
        assert!(!set.has_key_image(&ki));
    }

    #[test]
    fn test_rollback_block_alias() {
        let mut set = UtxoSet::new(100);
        let delta = BlockDelta::new(1);
        set.apply_block(delta).unwrap();
        set.rollback_block().unwrap();
        assert_eq!(set.height, 0);
    }
}

    // ─── Mainnet: Nullifier-only spending ────────────────

    /// Record a nullifier (key_image / link_tag) as spent.
    ///
    /// # Mainnet Change
    ///
    /// This replaces the old `spend()` which required knowing the specific UTXO.
    /// In the anonymous ring model, we only record the nullifier — we do NOT
    /// mark a specific UTXO as consumed. The ring signature proves the signer
    /// has authority over one UTXO, and the nullifier prevents double-spend.
    pub fn record_nullifier(&mut self, key_image: [u8; 32]) -> Result<(), UtxoError> {
        if self.key_images.contains(&key_image) {
            return Err(UtxoError::KeyImageSpent(hex::encode(key_image)));
        }
        self.key_images.insert(key_image);
        Ok(())
    }
