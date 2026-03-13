//! MISAKA Network — PQ-first UTXO node.

use misaka_types::constants::*;
use misaka_types::genesis::{GenesisConfig, ChainProfile};
use misaka_types::utxo::OutputRef;
use misaka_mempool::UtxoMempool;
use misaka_storage::{JellyfishMerkleTree, ObjectStore, UtxoSet};
use misaka_execution::DeterministicExecutor;
use misaka_consensus::epoch::EpochManager;
use misaka_consensus::safe_mode::SafeMode;
use misaka_p2p::PeerManager;

pub mod sync;

pub use misaka_execution::block_apply::{self, execute_block, rollback_last_block, BlockResult};

pub struct MisakaNode {
    pub profile: ChainProfile,
    pub mempool: UtxoMempool,
    pub utxo_set: UtxoSet,
    pub state: JellyfishMerkleTree,
    pub objects: ObjectStore,
    pub executor: DeterministicExecutor,
    pub epoch_mgr: EpochManager,
    pub safe_mode: SafeMode,
    pub peers: PeerManager,
    pub sync: sync::SyncEngine,
}

impl MisakaNode {
    pub fn new(genesis: GenesisConfig) -> Result<Self, anyhow::Error> {
        let mut utxo_set = UtxoSet::new(1000);

        // Apply genesis UTXOs
        for (i, gutxo) in genesis.initial_utxos.iter().enumerate() {
            let outref = OutputRef {
                tx_hash: [0u8; 32], // genesis tx hash = all zeros
                output_index: i as u32,
            };
            utxo_set.add_output(outref, gutxo.output.clone(), 0)
                .map_err(|e| anyhow::anyhow!("genesis UTXO: {}", e))?;
        }

        Ok(Self {
            profile: genesis.profile,
            mempool: UtxoMempool::new(MAX_TXS_PER_BLOCK * 10),
            utxo_set,
            state: JellyfishMerkleTree::new(),
            objects: ObjectStore::new(),
            executor: DeterministicExecutor::new(BASE_GAS_PRICE),
            epoch_mgr: EpochManager::new(),
            safe_mode: SafeMode::new(10),
            peers: PeerManager::new(),
            sync: sync::SyncEngine::new(),
        })
    }
}

fn main() {
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║  MISAKA Network v0.4.0 — PQ Main Path                   ║");
    println!("║  Validator: Hybrid (Ed25519 + ML-DSA-65)                 ║");
    println!("║  TX Privacy: Lattice ring sig + ML-KEM stealth           ║");
    println!("║  Verification: ring sig + KI proof + amount conservation ║");
    println!("║  Storage: UTXO set with rollback                         ║");
    println!("╚═══════════════════════════════════════════════════════════╝");

    let genesis = GenesisConfig::testnet_default();
    println!("Chain: {} (id={})", genesis.profile.chain_name, genesis.profile.chain_id);

    match MisakaNode::new(genesis) {
        Ok(node) => {
            println!("Genesis UTXOs: {}", node.utxo_set.len());
            println!("Ready.");
        }
        Err(e) => eprintln!("Failed to start: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_with_genesis() {
        let genesis = GenesisConfig::testnet_default();
        let node = MisakaNode::new(genesis).unwrap();
        assert_eq!(node.utxo_set.len(), 1); // 1 treasury UTXO
        assert_eq!(node.profile.chain_id, 2);
    }
}
