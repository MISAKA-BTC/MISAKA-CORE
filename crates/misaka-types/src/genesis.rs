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
                    address: [0x01; 32],
                    spending_pubkey: None,
                },
                label: "treasury".into(),
            }],
            initial_validators: vec![],
        }
    }
}

// ────────────────────────────────────────────────────────────────
//  Phase 2c-A: Genesis hash computation
// ────────────────────────────────────────────────────────────────

/// Domain prefix for genesis hash computation.
pub const GENESIS_HASH_DOMAIN: &[u8] = b"MISAKA-GENESIS:v1:";

/// Compute the v1 genesis hash from chain_id and committee public keys.
///
/// # Deprecation
///
/// This function only hashes `chain_id + committee_pks` and ignores the
/// UTXO set, ProtocolVersion, and genesis timestamp. Use
/// `misaka_genesis_builder::Genesis::hash()` for the complete v2 hash.
///
/// `committee_pks` MUST be in canonical order (same as `committee.authorities`).
#[deprecated(
    since = "0.8.0",
    note = "Use misaka_genesis_builder::Genesis::hash() — this function ignores UTXOs and ProtocolVersion"
)]
pub fn compute_genesis_hash(chain_id: u32, committee_pks: &[Vec<u8>]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(GENESIS_HASH_DOMAIN);
    h.update(chain_id.to_le_bytes());
    for pk in committee_pks {
        h.update(pk);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_hash_deterministic() {
        let pks = vec![vec![0xAA; 1952], vec![0xBB; 1952]];
        let h1 = compute_genesis_hash(2, &pks);
        let h2 = compute_genesis_hash(2, &pks);
        assert_eq!(h1, h2);
    }

    #[test]
    fn genesis_hash_chain_id_separation() {
        let pks = vec![vec![0xAA; 1952]];
        assert_ne!(compute_genesis_hash(1, &pks), compute_genesis_hash(2, &pks));
    }

    #[test]
    fn genesis_hash_pk_order_matters() {
        let pks_a = vec![vec![0xAA; 1952], vec![0xBB; 1952]];
        let pks_b = vec![vec![0xBB; 1952], vec![0xAA; 1952]];
        assert_ne!(
            compute_genesis_hash(2, &pks_a),
            compute_genesis_hash(2, &pks_b)
        );
    }

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
