//! Block application — full UTXO state transition.
//!
//! Orchestrates: validation → UTXO spend → UTXO create → key image commit.
//! This is the single entry point for block execution.

use misaka_storage::utxo_set::{UtxoSet, BlockDelta};
use misaka_consensus::block_validation::{self, BlockCandidate, BlockError};
use misaka_consensus::proposer;
use misaka_consensus::validator_set::ValidatorSet;

// 必要な型を misaka-types からインポート
use misaka_types::utxo::{
    OutputRef, TxOutput, UtxoTransaction, RingInput, UTXO_TX_VERSION, RING_SCHEME_LRS
};

/// Full block execution result.
#[derive(Debug)]
pub struct BlockResult {
    pub height: u64,
    pub tx_count: usize,
    pub total_fees: u64,
    pub utxos_created: usize,
    pub utxos_spent: usize,
    pub key_images_added: usize,
}

/// Execute a block: validate all txs, apply state changes, return result.
///
/// This is the ONLY way to modify the UTXO set from block data.
pub fn execute_block(
    block: &BlockCandidate,
    utxo_set: &mut UtxoSet,
    validator_set: Option<&ValidatorSet>,
) -> Result<BlockResult, BlockError> {
    // 1. Proposer verification (if validator set provided)
    if let (Some(vs), Some(proposal)) = (validator_set, &block.proposer_signature) {
        proposer::verify_proposal(vs, proposal)
            .map_err(|e| BlockError::Proposer(e.to_string()))?;
    }

    // 2. Validate and apply all transactions
    let delta = block_validation::validate_and_apply_block(block, utxo_set)?;

    // 3. Compute result
    let total_fees: u64 = block.transactions.iter().map(|vtx| vtx.tx.fee).sum();

    Ok(BlockResult {
        height: block.height,
        tx_count: block.transactions.len(),
        total_fees,
        utxos_created: delta.created.len(),
        utxos_spent: delta.spent.len(),
        key_images_added: delta.key_images_added.len(),
    })
}

/// Undo the last block (for reorg).
pub fn rollback_last_block(utxo_set: &mut UtxoSet) -> Result<BlockDelta, BlockError> {
    block_validation::rollback_block(utxo_set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_pqc::pq_sign::MlDsaKeypair;
    use misaka_pqc::pq_ring::*;
    use misaka_pqc::ki_proof::prove_key_image;
    use misaka_consensus::block_validation::VerifiedTx;

    fn setup() -> (UtxoSet, Vec<SpendingKeypair>, Poly) {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let mut utxo_set = UtxoSet::new(100);
        let wallets: Vec<SpendingKeypair> = (0..6)
            .map(|_| SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key))
            .collect();
        for (i, _w) in wallets.iter().enumerate() {
            let outref = OutputRef { tx_hash: [(i + 1) as u8; 32], output_index: 0 };
            utxo_set.add_output(outref, TxOutput {
                amount: if i == 0 { 10_000 } else { 5_000 },
                one_time_address: [0xAA; 20], pq_stealth: None,
            }, 0).unwrap();
        }
        (utxo_set, wallets, a)
    }

    fn make_vtx(a: &Poly, wallets: &[SpendingKeypair], amount: u64, fee: u64) -> VerifiedTx {
        let ring_pks: Vec<Poly> = (0..4).map(|i| wallets[i].public_poly.clone()).collect();
        let real_ref = OutputRef { tx_hash: [1; 32], output_index: 0 };
        
        // 1. 基本構造の構築
        let tx = UtxoTransaction { ring_scheme: RING_SCHEME_LRS,
            version: UTXO_TX_VERSION,
            inputs: vec![RingInput {
                ring_members: (0..4).map(|i| OutputRef { tx_hash: [(i+1) as u8; 32], output_index: 0 }).collect(),
                ring_signature: vec![], // 後で代入
                key_image: wallets[0].key_image,
                ki_proof: vec![],        // 後で代入
            }],
            outputs: vec![
                TxOutput { amount, one_time_address: [0xBB; 20], pq_stealth: None },
                TxOutput { amount: 10_000 - amount - fee, one_time_address: [0xCC; 20], pq_stealth: None },
            ],
            fee,
            extra: vec![],
        };

        // 2. 署名と Key Image 証明の生成
        let sig = ring_sign(a, &ring_pks, 0, &wallets[0].secret_poly, &tx.signing_digest()).unwrap();
        let kip = prove_key_image(a, &wallets[0].secret_poly, &wallets[0].public_poly, &wallets[0].key_image).unwrap();
        
        // 3. 署名データをセット
        let mut tx_final = tx;
        tx_final.inputs[0].ring_signature = sig.to_bytes();
        tx_final.inputs[0].ki_proof = kip.to_bytes();

        VerifiedTx { 
            tx: tx_final, 
            ring_pubkeys: vec![ring_pks], 
            ring_sigs: vec![sig], 
            ki_proofs: vec![Some(kip)], 
            real_input_refs: vec![real_ref] 
        }
    }

    #[test]
    fn test_execute_block_ok() {
        let (mut utxo_set, wallets, a) = setup();
        let vtx = make_vtx(&a, &wallets, 7000, 100);
        let block = BlockCandidate { height: 1, slot: 1, parent_hash: [0; 32], transactions: vec![vtx], proposer_signature: None };
        let result = execute_block(&block, &mut utxo_set, None).unwrap();
        assert_eq!(result.tx_count, 1);
        assert_eq!(result.total_fees, 100);
        assert_eq!(result.utxos_created, 2);
        assert_eq!(result.utxos_spent, 1);
    }

    #[test]
    fn test_execute_and_rollback() {
        let (mut utxo_set, wallets, a) = setup();
        let _initial = utxo_set.len(); // 警告回避のため _ を追加
        let vtx = make_vtx(&a, &wallets, 7000, 100);
        let block = BlockCandidate { height: 1, slot: 1, parent_hash: [0; 32], transactions: vec![vtx], proposer_signature: None };
        execute_block(&block, &mut utxo_set, None).unwrap();
        assert_eq!(utxo_set.height, 1);
        rollback_last_block(&mut utxo_set).unwrap();
        assert_eq!(utxo_set.height, 0);
    }
}
