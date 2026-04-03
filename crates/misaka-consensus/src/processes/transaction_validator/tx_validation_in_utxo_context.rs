#![allow(dead_code, unused_imports, unused_variables)]
//! Phase 3: Transaction validation in UTXO context.

use super::{TransactionValidator, TxValidationFlags};
use crate::stores::block_transactions::StoredTransaction;
use crate::stores::utxo_diffs::UtxoEntry;

#[derive(Debug, thiserror::Error)]
pub enum TxUtxoContextError {
    #[error("missing UTXO for input: tx={tx_id} index={index}")]
    MissingUtxo { tx_id: String, index: u32 },
    #[error("insufficient funds: input_sum={input_sum}, output_sum={output_sum}")]
    InsufficientFunds { input_sum: u64, output_sum: u64 },
    #[error("coinbase not mature: daa_diff={daa_diff}, required={required}")]
    CoinbaseNotMature { daa_diff: u64, required: u64 },
    #[error("PQC signature verification failed")]
    PqcSignatureInvalid,
    #[error("missing spending key for input {input_index}")]
    MissingSpendingKey { input_index: usize },
    #[error("invalid spending key for input {input_index}: {reason}")]
    InvalidSpendingKey { input_index: usize, reason: String },
    #[error("signature verification failed for input {input_index}")]
    SignatureVerificationFailed { input_index: usize },
    #[error("shielded proof verification failed")]
    ShieldedProofInvalid,
}

/// Resolved UTXO entries for a transaction's inputs.
pub struct PopulatedTransaction<'a> {
    pub tx: &'a StoredTransaction,
    pub utxo_entries: Vec<UtxoEntry>,
}

impl TransactionValidator {
    /// Validate a transaction against the UTXO set.
    pub fn validate_tx_in_utxo_context(
        &self,
        populated_tx: &PopulatedTransaction<'_>,
        current_daa_score: u64,
        flags: TxValidationFlags,
    ) -> Result<u64, TxUtxoContextError> {
        let tx = populated_tx.tx;

        if tx.is_coinbase {
            return Ok(0); // Coinbase has no fee
        }

        // Check all UTXOs exist and match
        if populated_tx.utxo_entries.len() != tx.inputs.len() {
            return Err(TxUtxoContextError::MissingUtxo {
                tx_id: hex::encode(tx.tx_id),
                index: 0,
            });
        }

        // Verify coinbase maturity for coinbase UTXOs
        for entry in &populated_tx.utxo_entries {
            if entry.is_coinbase {
                let daa_diff = current_daa_score.saturating_sub(entry.block_daa_score);
                if daa_diff < self.coinbase_maturity {
                    return Err(TxUtxoContextError::CoinbaseNotMature {
                        daa_diff,
                        required: self.coinbase_maturity,
                    });
                }
            }
        }

        // Check total input >= total output (the difference is the fee)
        let input_sum: u64 = populated_tx.utxo_entries.iter().map(|e| e.amount).sum();
        let output_sum: u64 = tx.outputs.iter().map(|o| o.amount).sum();
        if input_sum < output_sum {
            return Err(TxUtxoContextError::InsufficientFunds {
                input_sum,
                output_sum,
            });
        }

        // Verify PQC signatures (ML-DSA-65) using UTXO spending keys
        if !flags.skip_script_verification {
            for (i, (input, utxo)) in tx.inputs.iter().zip(populated_tx.utxo_entries.iter()).enumerate() {
                // Extract spending public key from UTXO
                let spending_pk = &utxo.script_public_key;
                if spending_pk.is_empty() {
                    return Err(TxUtxoContextError::MissingSpendingKey {
                        input_index: i,
                    });
                }

                // Compute transaction signing digest
                let digest = {
                    let mut h = sha3::Sha3_256::new();
                    use sha3::Digest;
                    h.update(b"MISAKA:tx:sign:v1:");
                    h.update(&tx.tx_id);
                    for inp in &tx.inputs {
                        h.update(&inp.previous_tx_id);
                        h.update(&inp.previous_index.to_le_bytes());
                    }
                    for out in &tx.outputs {
                        h.update(&out.amount.to_le_bytes());
                        h.update(&out.script_public_key);
                    }
                    h.finalize().to_vec()
                };

                // Verify ML-DSA-65 signature
                match (
                    misaka_pqc::pq_sign::MlDsaPublicKey::from_bytes(spending_pk),
                    misaka_pqc::pq_sign::MlDsaSignature::from_bytes(&tx.signature),
                ) {
                    (Ok(pk), Ok(sig)) => {
                        misaka_pqc::pq_sign::ml_dsa_verify(&pk, &digest, &sig)
                            .map_err(|_| TxUtxoContextError::SignatureVerificationFailed {
                                input_index: i,
                            })?;
                    }
                    (Err(_), _) => {
                        return Err(TxUtxoContextError::InvalidSpendingKey {
                            input_index: i,
                            reason: format!(
                                "cannot parse {} bytes as ML-DSA-65 pk",
                                spending_pk.len()
                            ),
                        });
                    }
                    (_, Err(_)) => {
                        return Err(TxUtxoContextError::SignatureVerificationFailed {
                            input_index: i,
                        });
                    }
                }
            }
        }

        let fee = input_sum - output_sum;
        Ok(fee)
    }
}
