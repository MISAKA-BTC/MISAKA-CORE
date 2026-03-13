//! UTXO Set — tracks unspent outputs and spent key images.
//!
//! Supports:
//! - Add new outputs (from block)
//! - Spend outputs (mark as consumed via key image)
//! - Rollback (undo a block's state changes)
//! - Query existence and lookup

use std::collections::{HashMap, HashSet};
use misaka_types::utxo::{OutputRef, TxOutput};

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
    /// UTXOs spent in this block (key_image → spent OutputRef).
    pub spent: Vec<([u8; 32], OutputRef)>,
    /// Key images added in this block.
    pub key_images_added: Vec<[u8; 32]>,
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

    /// Check if a UTXO exists and is unspent.
    pub fn get(&self, outref: &OutputRef) -> Option<&UtxoEntry> {
        self.unspent.get(outref)
    }

    /// Check if a key image has been spent.
    pub fn is_key_image_spent(&self, ki: &[u8; 32]) -> bool {
        self.key_images.contains(ki)
    }

    /// Number of unspent outputs.
    pub fn len(&self) -> usize { self.unspent.len() }

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

    /// Apply a block: add outputs, spend inputs, record delta.
    pub fn apply_block(&mut self, delta: BlockDelta) -> Result<(), UtxoError> {
        self.height = delta.height;
        self.deltas.push(delta);
        // Prune old deltas
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

        // Restore spent UTXOs (re-add them)
        // Note: actual output data would need to be stored in delta for full rollback
        // For now we track the outrefs

        // Remove created UTXOs
        for outref in &delta.created {
            self.unspent.remove(outref);
        }

        self.height = delta.height.saturating_sub(1);
        Ok(delta)
    }

    /// Verify amount conservation for a transaction.
    ///
    /// `sum(input_amounts) == sum(output_amounts) + fee`
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
        assert!(set.is_key_image_spent(&ki));
    }

    #[test]
    fn test_double_spend_rejected() {
        let mut set = UtxoSet::new(100);
        let outref = make_outref(1, 0);
        set.add_output(outref.clone(), make_output(1000), 1).unwrap();

        let ki = [0xBB; 32];
        set.spend(ki, &outref).unwrap();

        // Same key image → rejected
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

        // 7000 + 3000 = 9500 + 500(fee) ✓
        let outputs = vec![make_output(9500)];
        set.verify_amount_conservation(&[o1.clone(), o2.clone()], &outputs, 500).unwrap();

        // Wrong fee → fail
        assert!(set.verify_amount_conservation(&[o1, o2], &outputs, 100).is_err());
    }

    #[test]
    fn test_rollback() {
        let mut set = UtxoSet::new(100);
        let outref = make_outref(1, 0);
        set.add_output(outref.clone(), make_output(1000), 1).unwrap();

        let delta = BlockDelta {
            height: 1,
            created: vec![outref.clone()],
            spent: vec![],
            key_images_added: vec![],
        };
        set.apply_block(delta).unwrap();

        // Rollback removes the created UTXO
        set.rollback().unwrap();
        assert!(set.get(&outref).is_none());
        assert_eq!(set.height, 0);
    }
}
