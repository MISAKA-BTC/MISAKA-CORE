//! Block application — full UTXO state transition.
//!
//! Orchestrates: validation → UTXO spend → UTXO create → key image commit.
//! This is the single entry point for block execution.

use misaka_consensus::block_validation::{self, BlockCandidate, BlockError};
use misaka_consensus::validator_set::ValidatorSet;
use misaka_storage::utxo_set::{BlockDelta, UtxoSet};

// 必要な型を misaka-types からインポート
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
///
/// # Proposer Verification Responsibility
///
/// ALL validation (including proposer sig, block hash binding, tx validation)
/// is delegated to `validate_and_apply_block`. This function does NOT
/// duplicate any checks — it is a thin orchestration layer.
pub fn execute_block(
    block: &BlockCandidate,
    utxo_set: &mut UtxoSet,
    validator_set: Option<&ValidatorSet>,
) -> Result<BlockResult, BlockError> {
    // Single entry point for all validation — no duplicate proposer check.
    let delta = block_validation::validate_and_apply_block(block, utxo_set, validator_set)?;

    let total_fees: u64 = block.transactions.iter().map(|vtx| vtx.tx.fee).sum();

    Ok(BlockResult {
        height: block.height,
        tx_count: block.transactions.len(),
        total_fees,
        utxos_created: delta.created.len(),
        // In anonymous nullifier model, "spent" count = nullifiers added
        utxos_spent: delta.key_images_added.len(),
        key_images_added: delta.key_images_added.len(),
    })
}

/// Execute a block using the zero-knowledge backend.
///
/// Production builds use CompositeProof (lattice-based, full soundness).
/// Dev builds with `stark-stub` additionally support the STARK stub backend.
pub fn execute_block_zero_knowledge(
    block: &BlockCandidate,
    utxo_set: &mut UtxoSet,
    validator_set: Option<&ValidatorSet>,
) -> Result<BlockResult, BlockError> {
    let delta =
        block_validation::validate_and_apply_block_zero_knowledge(block, utxo_set, validator_set)?;

    let total_fees: u64 = block.transactions.iter().map(|vtx| vtx.tx.fee).sum();

    Ok(BlockResult {
        height: block.height,
        tx_count: block.transactions.len(),
        total_fees,
        utxos_created: delta.created.len(),
        utxos_spent: delta.key_images_added.len(),
        key_images_added: delta.key_images_added.len(),
    })
}

/// Undo the last block (for SPC switch only).
///
/// This is NOT a protocol-level rollback. Used exclusively during
/// shallow Selected Parent Chain switches. Finality boundary check
/// MUST be performed by the caller before invoking this.
pub fn undo_last_block(utxo_set: &mut UtxoSet) -> Result<BlockDelta, BlockError> {
    block_validation::undo_last_block(utxo_set)
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_consensus::block_validation::{VerifiedProof, VerifiedTx};
    use misaka_pqc::ki_proof::{canonical_strong_ki, prove_key_image};
    use misaka_pqc::pq_ring::*;
    use misaka_pqc::pq_sign::MlDsaKeypair;
    use misaka_pqc::{TransactionPrivacyConstraints, TransactionPublicStatement};

    fn setup() -> (UtxoSet, Vec<SpendingKeypair>, Poly) {
        let a = derive_public_param(&DEFAULT_A_SEED);
        let mut utxo_set = UtxoSet::new(100);
        let wallets: Vec<SpendingKeypair> = (0..6)
            .map(|_| SpendingKeypair::from_ml_dsa(MlDsaKeypair::generate().secret_key).unwrap())
            .collect();
        for (i, _w) in wallets.iter().enumerate() {
            let outref = OutputRef {
                tx_hash: [(i + 1) as u8; 32],
                output_index: 0,
            };
            utxo_set
                .add_output(
                    outref,
                    TxOutput {
                        amount: 10_000,
                        one_time_address: [0xAA; 32],
                        pq_stealth: None,
                        spending_pubkey: None,
                    },
                    0,
                )
                .unwrap();
        }
        (utxo_set, wallets, a)
    }

    fn make_vtx(a: &Poly, wallets: &[SpendingKeypair], amount: u64, fee: u64) -> VerifiedTx {
        let ring_pks: Vec<Poly> = (0..4).map(|i| wallets[i].public_poly.clone()).collect();

        // Use strong-binding canonical key image (matches ki_proof algebra)
        let (_, strong_ki) = canonical_strong_ki(&wallets[0].public_poly, &wallets[0].secret_poly);

        let tx = UtxoTransaction {
            proof_scheme: PROOF_SCHEME_DEPRECATED_LRS,
            tx_type: TxType::Transfer,
            version: UTXO_TX_VERSION,
            inputs: vec![TxInput {
                utxo_refs: (0..4)
                    .map(|i| OutputRef {
                        tx_hash: [(i + 1) as u8; 32],
                        output_index: 0,
                    })
                    .collect(),
                proof: vec![],
                key_image: strong_ki,
                ki_proof: vec![],
            }],
            outputs: vec![
                TxOutput {
                    amount,
                    one_time_address: [0xBB; 32],
                    pq_stealth: None,
                    spending_pubkey: None,
                },
                TxOutput {
                    amount: 10_000 - amount - fee,
                    one_time_address: [0xCC; 32],
                    pq_stealth: None,
                    spending_pubkey: None,
                },
            ],
            fee,
            extra: vec![],
            zk_proof: None,
        };

        let sig = pq_sign(
            a,
            &ring_pks,
            0,
            &wallets[0].secret_poly,
            &tx.signing_digest(),
        )
        .unwrap();
        let kip = prove_key_image(
            a,
            &wallets[0].secret_poly,
            &wallets[0].public_poly,
            &strong_ki,
        )
        .unwrap();

        // 3. 署名データをセット
        let mut tx_final = tx;
        tx_final.inputs[0].proof = sig.to_bytes();
        tx_final.inputs[0].ki_proof = kip.to_bytes();

        VerifiedTx {
            tx: tx_final.clone(),
            ring_pubkeys: vec![ring_pks.clone()],
            ring_amounts: vec![vec![10_000; 4]], // same-amount ring
            ring_proofs: vec![VerifiedProof::Lrs {
                sig,
                ki_proof: Some(kip),
            }],
            privacy_constraints: TransactionPrivacyConstraints::from_tx_and_input_amounts(
                &tx_final,
                &[10_000],
            )
            .ok(),
            privacy_statement: TransactionPrivacyConstraints::from_tx_and_input_amounts(
                &tx_final,
                &[10_000],
            )
            .ok()
            .and_then(|constraints| {
                TransactionPublicStatement::from_constraints_and_resolved_rings(
                    &tx_final,
                    &constraints,
                    &[ring_pks.clone()],
                    misaka_pqc::PrivacyBackendFamily::ZeroKnowledge,
                )
                .ok()
            }),
        }
    }

    #[test]
    fn test_execute_block_ok() {
        let (mut utxo_set, wallets, a) = setup();
        let vtx = make_vtx(&a, &wallets, 7000, 100);
        let block = BlockCandidate {
            height: 1,
            slot: 1,
            parent_hash: [0; 32],
            transactions: vec![vtx],
            proposer_signature: None,
        };
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
        let block = BlockCandidate {
            height: 1,
            slot: 1,
            parent_hash: [0; 32],
            transactions: vec![vtx],
            proposer_signature: None,
        };
        execute_block(&block, &mut utxo_set, None).unwrap();
        assert_eq!(utxo_set.height, 1);
        undo_last_block(&mut utxo_set).unwrap();
        assert_eq!(utxo_set.height, 0);
    }
}
