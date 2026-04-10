//! Transaction builder: constructs signed transactions from plans.

use crate::TxPlan;
use serde::{Deserialize, Serialize};

/// Built transaction ready for submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuiltTransaction {
    pub tx_id: [u8; 32],
    pub version: u32,
    pub inputs: Vec<SignedInput>,
    pub outputs: Vec<TransactionOutput>,
    pub fee: u64,
    pub mass: u64,
    pub raw_bytes: Vec<u8>,
}

/// A signed transaction input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedInput {
    pub previous_tx_hash: [u8; 32],
    pub previous_output_index: u32,
    pub signature_script: Vec<u8>,
    pub sequence: u64,
}

/// A transaction output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionOutput {
    pub value: u64,
    pub script_public_key: Vec<u8>,
    pub script_version: u16,
}

/// Transaction builder configuration.
#[derive(Debug, Clone)]
pub struct TxBuilderConfig {
    pub version: u32,
    pub default_sequence: u64,
    pub mass_per_input: u64,
    pub mass_per_output: u64,
    pub mass_base: u64,
    pub mass_per_sig_op: u64,
}

impl Default for TxBuilderConfig {
    fn default() -> Self {
        Self {
            version: 1,
            default_sequence: u64::MAX,
            mass_per_input: 100,
            mass_per_output: 50,
            mass_base: 100,
            mass_per_sig_op: 1000,
        }
    }
}

/// Builds transactions from plans.
pub struct TxBuilder {
    config: TxBuilderConfig,
}

impl TxBuilder {
    pub fn new(config: TxBuilderConfig) -> Self {
        Self { config }
    }

    /// Estimate the mass (fee weight) of a transaction.
    pub fn estimate_mass(&self, input_count: usize, output_count: usize) -> u64 {
        self.config.mass_base
            + (input_count as u64 * self.config.mass_per_input)
            + (output_count as u64 * self.config.mass_per_output)
            + (input_count as u64 * self.config.mass_per_sig_op)
    }

    /// Estimate fee for given mass and fee rate.
    pub fn estimate_fee(&self, mass: u64, fee_rate: f64) -> u64 {
        (mass as f64 * fee_rate).ceil() as u64
    }

    /// Build an unsigned transaction from a plan.
    pub fn build_unsigned(&self, plan: &TxPlan) -> UnsignedTransaction {
        let inputs: Vec<UnsignedInput> = plan
            .inputs
            .iter()
            .map(|i| UnsignedInput {
                previous_tx_hash: i.tx_hash,
                previous_output_index: i.output_index,
                sequence: self.config.default_sequence,
                amount: i.amount,
            })
            .collect();

        let outputs: Vec<TransactionOutput> = plan
            .outputs
            .iter()
            .map(|o| TransactionOutput {
                value: o.amount,
                script_public_key: address_to_script(&o.address),
                script_version: 0,
            })
            .collect();

        let mass = self.estimate_mass(inputs.len(), outputs.len());

        UnsignedTransaction {
            version: self.config.version,
            inputs,
            outputs,
            fee: plan.fee,
            mass,
        }
    }

    /// SEC-FIX: Downgraded from `pub` to `pub(crate)` to prevent external SDK users
    /// from calling this incompatible signing method. Transactions signed with this
    /// digest will be rejected by the DAG executor (IntentMessage mismatch).
    ///
    /// This function uses a custom `"MISAKA:tx:sighash:v1:"` domain separator
    /// that is INCOMPATIBLE with the executor's `IntentMessage::signing_digest()`.
    /// Transactions signed with this digest will be rejected by the DAG executor.
    #[deprecated(
        note = "SEC-FIX: Use compute_intent_signing_digest() for executor-compatible signatures"
    )]
    pub(crate) fn compute_sig_hash(
        &self,
        unsigned: &UnsignedTransaction,
        input_index: usize,
    ) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:tx:sighash:v1:");
        h.update(&unsigned.version.to_le_bytes());
        h.update(&(input_index as u32).to_le_bytes());

        // Hash all inputs
        for input in &unsigned.inputs {
            h.update(&input.previous_tx_hash);
            h.update(&input.previous_output_index.to_le_bytes());
        }

        // Hash all outputs
        for output in &unsigned.outputs {
            h.update(&output.value.to_le_bytes());
            h.update(&output.script_public_key);
        }

        h.finalize().into()
    }
}

/// Unsigned transaction (needs signatures).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedTransaction {
    pub version: u32,
    pub inputs: Vec<UnsignedInput>,
    pub outputs: Vec<TransactionOutput>,
    pub fee: u64,
    pub mass: u64,
}

/// Unsigned input (needs signature).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsignedInput {
    pub previous_tx_hash: [u8; 32],
    pub previous_output_index: u32,
    pub sequence: u64,
    pub amount: u64,
}

fn address_to_script(address: &[u8; 32]) -> Vec<u8> {
    let mut script = Vec::with_capacity(37);
    // P2PKH_PQ script template
    script.push(0x76); // OP_DUP
    script.push(0xa7); // OP_BLAKE3
    script.push(32); // Push 32 bytes
    script.extend_from_slice(address);
    script.push(0x88); // OP_EQUALVERIFY
    script.push(0xc0); // OP_CHECKSIG_PQ
    script
}

/// Signing context for hardware wallets or multi-party signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningContext {
    pub unsigned_tx: UnsignedTransaction,
    pub sig_hashes: Vec<[u8; 32]>,
    pub utxo_entries: Vec<UtxoEntryForSigning>,
}

/// UTXO info needed for signing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoEntryForSigning {
    pub amount: u64,
    pub script_public_key: Vec<u8>,
    pub block_daa_score: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TxPlanInput;

    #[test]
    fn test_mass_estimation() {
        let builder = TxBuilder::new(TxBuilderConfig::default());
        let mass = builder.estimate_mass(2, 2);
        assert!(mass > 0);
    }

    #[test]
    fn test_build_unsigned() {
        let builder = TxBuilder::new(TxBuilderConfig::default());
        let plan = TxPlan {
            inputs: vec![TxPlanInput {
                tx_hash: [1u8; 32],
                output_index: 0,
                amount: 5000,
            }],
            outputs: vec![crate::TxPlanOutput {
                address: [2u8; 32],
                amount: 4000,
                is_change: false,
            }],
            fee: 1000,
            summary: "test".into(),
        };
        let unsigned = builder.build_unsigned(&plan);
        assert_eq!(unsigned.inputs.len(), 1);
        assert_eq!(unsigned.outputs.len(), 1);
        assert_eq!(unsigned.fee, 1000);
    }
}
