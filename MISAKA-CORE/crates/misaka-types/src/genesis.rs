//! Genesis configuration — chain profile + initial UTXO distribution.

use crate::utxo::TxOutput;
use crate::validator::ValidatorIdentity;

/// Chain profile.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChainProfile {
    pub chain_id: u32,
    pub chain_name: String,
    pub genesis_timestamp_ms: u64,
    /// Require PQ ring sig for all txs.
    pub pq_tx_required: bool,
    /// Require KI proof for block validation.
    pub ki_proof_required: bool,
    /// Minimum ring size.
    pub min_ring_size: usize,
    /// Maximum ring size.
    pub max_anonymity_set: usize,
    /// Block time target (seconds).
    pub block_time_secs: u64,
    /// Maximum txs per block.
    pub max_txs_per_block: usize,
}

impl ChainProfile {
    pub fn testnet() -> Self {
        Self {
            chain_id: 2,
            chain_name: "MISAKA Testnet".into(),
            genesis_timestamp_ms: 0,
            pq_tx_required: true,
            ki_proof_required: true,
            min_ring_size: 4,
            max_anonymity_set: 16,
            block_time_secs: 2, // Fast lane default (ZKP lane: 30s)
            max_txs_per_block: 1000,
        }
    }

    pub fn mainnet() -> Self {
        Self {
            chain_id: 1,
            chain_name: "MISAKA Mainnet".into(),
            genesis_timestamp_ms: 0,
            pq_tx_required: true,
            ki_proof_required: true,
            min_ring_size: 4,
            max_anonymity_set: 16,
            block_time_secs: 2, // Fast lane default (ZKP lane: 30s)
            max_txs_per_block: 1000,
        }
    }
}

/// Genesis UTXO entry.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenesisUtxo {
    pub output: TxOutput,
    /// Identifier for this genesis output.
    pub label: String,
}

/// Genesis block configuration.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GenesisConfig {
    pub profile: ChainProfile,
    pub initial_utxos: Vec<GenesisUtxo>,
    pub initial_validators: Vec<ValidatorIdentity>,
}

impl GenesisConfig {
    /// Create a minimal testnet genesis.
    pub fn testnet_default() -> Self {
        Self {
            profile: ChainProfile::testnet(),
            initial_utxos: vec![GenesisUtxo {
                output: TxOutput {
                    amount: 10_000_000_000, // 10B MISAKA
                    one_time_address: [0x01; 32],
                    pq_stealth: None,
                    spending_pubkey: None,
                },
                label: "treasury".into(),
            }],
            initial_validators: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_testnet_profile() {
        let p = ChainProfile::testnet();
        assert_eq!(p.chain_id, 2);
        assert!(p.pq_tx_required);
        assert!(p.ki_proof_required);
    }

    #[test]
    fn test_genesis_config() {
        let g = GenesisConfig::testnet_default();
        assert_eq!(g.initial_utxos.len(), 1);
        assert_eq!(g.initial_utxos[0].output.amount, 10_000_000_000);
    }
}
