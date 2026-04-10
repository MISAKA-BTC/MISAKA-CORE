//! Block sync engine — applies blocks from peers with FULL verification.
//!
//! # No-Rollback Architecture
//!
//! This sync engine is forward-only. There is no `reorg()` method.
//! DAG reorgs (SPC switches) are handled by VirtualState::resolve()
//! in the misaka-dag crate, not by rolling back and re-applying blocks.
//!
//! No skip. No trust. Every block is re-validated.

use misaka_consensus::block_validation::BlockCandidate;
use misaka_consensus::block_validation::BlockError;
use misaka_consensus::validator_set::ValidatorSet;
use misaka_execution::block_apply::{execute_block, BlockResult};
use misaka_storage::utxo_set::UtxoSet;

/// Forward-only sync state.
pub struct SyncEngine {
    pub blocks_synced: u64,
    pub blocks_rejected: u64,
}

impl SyncEngine {
    pub fn new() -> Self {
        Self {
            blocks_synced: 0,
            blocks_rejected: 0,
        }
    }

    /// Apply a single synced block with full verification.
    pub fn apply_synced_block(
        &mut self,
        block: &BlockCandidate,
        utxo_set: &mut UtxoSet,
        validator_set: Option<&ValidatorSet>,
    ) -> Result<BlockResult, BlockError> {
        if block.height != utxo_set.height + 1 {
            self.blocks_rejected += 1;
            return Err(BlockError::Proposer(format!(
                "height mismatch: expected {}, got {}",
                utxo_set.height + 1,
                block.height
            )));
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

    // NOTE: reorg() has been deliberately removed.
    // Protocol-level rollback is forbidden. SPC switches are handled
    // by VirtualState::resolve() with MAX_SPC_SWITCH_DEPTH limit.
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_consensus::block_validation::{VerifiedProof, VerifiedTx};
    use misaka_pqc::pq_ring::SpendingKeypair;
    use misaka_pqc::pq_sign::{ml_dsa_sign_raw, MlDsaKeypair};
    use misaka_types::utxo::*;

    fn setup() -> (UtxoSet, Vec<SpendingKeypair>) {
        let mut utxo_set = UtxoSet::new(100);
        let wallets: Vec<SpendingKeypair> = (0..6)
            .map(|_| {
                let kp = MlDsaKeypair::generate();
                SpendingKeypair::from_ml_dsa_pair(kp.secret_key, kp.public_key.as_bytes().to_vec())
                    .unwrap()
            })
            .collect();
        for (i, wallet) in wallets.iter().enumerate() {
            utxo_set
                .add_output(
                    OutputRef {
                        tx_hash: [(i + 1) as u8; 32],
                        output_index: 0,
                    },
                    TxOutput {
                        amount: 10_000,
                        address: [0xAA; 32],
                        spending_pubkey: Some(wallet.ml_dsa_pk().to_vec()),
                    },
                    0,
                    false,
                )
                .unwrap();
        }
        (utxo_set, wallets)
    }

    fn make_block(wallets: &[SpendingKeypair], height: u64) -> BlockCandidate {
        let signer = &wallets[0];
        let tx = UtxoTransaction {
            tx_type: TxType::TransparentTransfer,
            version: UTXO_TX_VERSION,
            inputs: vec![TxInput {
                utxo_refs: vec![OutputRef {
                    tx_hash: [1; 32],
                    output_index: 0,
                }],
                proof: vec![],
            }],
            outputs: vec![
                TxOutput {
                    amount: 7000,
                    address: [0xBB; 32],
                    spending_pubkey: Some(signer.ml_dsa_pk().to_vec()),
                },
                TxOutput {
                    amount: 2900,
                    address: [0xCC; 32],
                    spending_pubkey: Some(signer.ml_dsa_pk().to_vec()),
                },
            ],
            fee: 100,
            extra: vec![],
            expiry: 0,
        };
        // Phase 2c-A: TxSignablePayload-based signing for sync test fixture
        use misaka_types::tx_signable::TxSignablePayload;

        let payload = TxSignablePayload::from(&tx);
        let intent = misaka_types::intent::IntentMessage::wrap(
            misaka_types::intent::IntentScope::TransparentTransfer,
            misaka_types::intent::AppId::new(2, [0u8; 32]), // test fixture
            &payload,
        );
        let sig = ml_dsa_sign_raw(&signer.ml_dsa_sk, &intent.signing_digest()).unwrap();
        let mut tx_final = tx;
        tx_final.inputs[0].proof = sig.as_bytes().to_vec();
        BlockCandidate {
            height,
            slot: height,
            parent_hash: [0; 32],
            transactions: vec![VerifiedTx {
                tx: tx_final.clone(),
                raw_spending_keys: vec![signer.ml_dsa_pk().to_vec()],
                ring_pubkeys: vec![vec![signer.public_poly.clone()]],
                ring_amounts: vec![vec![10_000]],
                ring_proofs: vec![VerifiedProof::Transparent {
                    raw_sig: sig.as_bytes().to_vec(),
                }],
            }],
            proposer_signature: None,
        }
    }

    #[test]
    fn test_sync_sequential() {
        let (mut utxo_set, wallets) = setup();
        let mut sync = SyncEngine::new();
        let block = make_block(&wallets, 1);
        let result = sync
            .apply_synced_block(&block, &mut utxo_set, None)
            .unwrap();
        assert_eq!(result.height, 1);
        assert_eq!(sync.blocks_synced, 1);
    }

    #[test]
    fn test_sync_wrong_height_rejected() {
        let (mut utxo_set, wallets) = setup();
        let mut sync = SyncEngine::new();
        let block = make_block(&wallets, 5);
        assert!(sync
            .apply_synced_block(&block, &mut utxo_set, None)
            .is_err());
        assert_eq!(sync.blocks_rejected, 1);
    }
}
