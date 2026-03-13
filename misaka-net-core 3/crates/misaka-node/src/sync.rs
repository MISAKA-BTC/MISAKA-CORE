//! Block sync engine — applies blocks from peers with FULL verification.
//!
//! No skip. No trust. Every block is re-validated.

use misaka_storage::utxo_set::UtxoSet;
use misaka_consensus::block_validation::BlockCandidate;
use misaka_consensus::validator_set::ValidatorSet;
use crate::block_apply::{execute_block, rollback_last_block, BlockResult};
use misaka_consensus::block_validation::BlockError;

/// Sync state.
pub struct SyncEngine {
    pub blocks_synced: u64,
    pub blocks_rejected: u64,
}

impl SyncEngine {
    pub fn new() -> Self {
        Self { blocks_synced: 0, blocks_rejected: 0 }
    }

    /// Apply a single synced block with full verification.
    pub fn apply_synced_block(
        &mut self,
        block: &BlockCandidate,
        utxo_set: &mut UtxoSet,
        validator_set: Option<&ValidatorSet>,
    ) -> Result<BlockResult, BlockError> {
        // Height must be sequential
        if block.height != utxo_set.height + 1 {
            self.blocks_rejected += 1;
            return Err(BlockError::Proposer(
                format!("height mismatch: expected {}, got {}", utxo_set.height + 1, block.height)));
        }

        match execute_block(block, utxo_set, validator_set) {
            Ok(result) => {
                self.blocks_synced += 1;
                Ok(result)
            }
            Err(e) => {
                self.blocks_rejected += 1;
                Err(e)
            }
        }
    }

    /// Apply a batch of blocks in order. Stops at first failure.
    pub fn apply_block_batch(
        &mut self,
        blocks: &[BlockCandidate],
        utxo_set: &mut UtxoSet,
        validator_set: Option<&ValidatorSet>,
    ) -> Result<Vec<BlockResult>, (usize, BlockError)> {
        let mut results = Vec::with_capacity(blocks.len());
        for (i, block) in blocks.iter().enumerate() {
            match self.apply_synced_block(block, utxo_set, validator_set) {
                Ok(r) => results.push(r),
                Err(e) => return Err((i, e)),
            }
        }
        Ok(results)
    }

    /// Reorg: rollback N blocks, then apply new chain.
    pub fn reorg(
        &mut self,
        rollback_count: usize,
        new_blocks: &[BlockCandidate],
        utxo_set: &mut UtxoSet,
        validator_set: Option<&ValidatorSet>,
    ) -> Result<Vec<BlockResult>, BlockError> {
        // Rollback
        for _ in 0..rollback_count {
            rollback_last_block(utxo_set)?;
        }
        // Apply new chain
        self.apply_block_batch(new_blocks, utxo_set, validator_set)
            .map_err(|(_, e)| e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_pqc::pq_sign::MlDsaKeypair;
    use misaka_pqc::pq_ring::*;
    use misaka_pqc::ki_proof::prove_key_image;
    use misaka_consensus::block_validation::VerifiedTx;
    use misaka_types::utxo::*;

    fn setup() -> (UtxoSet, Vec<SpendingKeypair>, Poly) {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let mut utxo_set = UtxoSet::new(100);
        let wallets: Vec<SpendingKeypair> = (0..6)
            .map(|_| SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key))
            .collect();
        for (i, _) in wallets.iter().enumerate() {
            utxo_set.add_output(
                OutputRef { tx_hash: [(i+1) as u8; 32], output_index: 0 },
                TxOutput { amount: if i == 0 { 10_000 } else { 5_000 }, one_time_address: [0xAA; 20], pq_stealth: None },
                0,
            ).unwrap();
        }
        (utxo_set, wallets, a)
    }

    fn make_block(a: &Poly, wallets: &[SpendingKeypair], height: u64) -> BlockCandidate {
        let ring_pks: Vec<Poly> = (0..4).map(|i| wallets[i].public_poly.clone()).collect();
        let tx = UtxoTransaction {
            version: UTXO_TX_VERSION,
            inputs: vec![RingInput {
                ring_members: (0..4).map(|i| OutputRef { tx_hash: [(i+1) as u8; 32], output_index: 0 }).collect(),
                ring_signature: vec![], key_image: wallets[0].key_image, ki_proof: vec![],
            }],
            outputs: vec![
                TxOutput { amount: 7000, one_time_address: [0xBB; 20], pq_stealth: None },
                TxOutput { amount: 2900, one_time_address: [0xCC; 20], pq_stealth: None },
            ],
            fee: 100, extra: vec![],
        };
        let sig = ring_sign(a, &ring_pks, 0, &wallets[0].secret_poly, &tx.signing_digest()).unwrap();
        let kip = prove_key_image(a, &wallets[0].secret_poly, &wallets[0].public_poly, &wallets[0].key_image).unwrap();
        let mut tx_final = tx;
        tx_final.inputs[0].ki_proof = kip.to_bytes();
        BlockCandidate {
            height, slot: height, parent_hash: [0; 32],
            transactions: vec![VerifiedTx {
                tx: tx_final, ring_pubkeys: vec![ring_pks], ring_sigs: vec![sig],
                ki_proofs: vec![Some(kip)],
                real_input_refs: vec![OutputRef { tx_hash: [1; 32], output_index: 0 }],
            }],
            proposer_signature: None,
        }
    }

    #[test]
    fn test_sync_sequential() {
        let (mut utxo_set, wallets, a) = setup();
        let mut sync = SyncEngine::new();
        let block = make_block(&a, &wallets, 1);
        let result = sync.apply_synced_block(&block, &mut utxo_set, None).unwrap();
        assert_eq!(result.height, 1);
        assert_eq!(sync.blocks_synced, 1);
    }

    #[test]
    fn test_sync_wrong_height_rejected() {
        let (mut utxo_set, wallets, a) = setup();
        let mut sync = SyncEngine::new();
        let block = make_block(&a, &wallets, 5); // wrong height
        assert!(sync.apply_synced_block(&block, &mut utxo_set, None).is_err());
        assert_eq!(sync.blocks_rejected, 1);
    }
}
