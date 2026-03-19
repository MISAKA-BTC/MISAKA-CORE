//! Wallet State — Q-DAG-CT UTXO tracking.
//!
//! Tracks owned outputs, spending keys, blinding factors.
//! Uses nullifier-based spending (not key_image).

use misaka_pqc::pq_ring::Poly;
use misaka_pqc::pq_sign::MlDsaSecretKey;
use misaka_pqc::bdlop::BlindingFactor;
use misaka_pqc::qdag_tx::RingMemberLeaf;

/// A wallet-owned output.
#[derive(Debug, Clone)]
pub struct OwnedOutput {
    pub tx_hash: [u8; 32],
    pub output_index: u32,
    pub amount: u64,
    pub blinding: BlindingFactor,
    pub spending_sk: MlDsaSecretKey,
    pub spending_pk: Poly,
    /// Nullifier (computed lazily when spending).
    pub nullifier: Option<[u8; 32]>,
    pub spent: bool,
}

/// Wallet state for Q-DAG-CT.
pub struct WalletState {
    pub outputs: Vec<OwnedOutput>,
    pub chain_id: u32,
}

impl WalletState {
    pub fn new(chain_id: u32) -> Self {
        Self { outputs: Vec::new(), chain_id }
    }

    /// Register a new owned output.
    pub fn register_output(
        &mut self,
        tx_hash: [u8; 32],
        output_index: u32,
        amount: u64,
        blinding: BlindingFactor,
        spending_sk: MlDsaSecretKey,
        spending_pk: Poly,
    ) {
        self.outputs.push(OwnedOutput {
            tx_hash, output_index, amount, blinding,
            spending_sk, spending_pk, nullifier: None, spent: false,
        });
    }

    /// Select an unspent output with sufficient balance.
    pub fn select_utxo(&self, min_amount: u64) -> Option<&OwnedOutput> {
        self.outputs.iter()
            .filter(|o| !o.spent && o.amount >= min_amount)
            .min_by_key(|o| o.amount) // Smallest sufficient UTXO
    }

    /// Mark an output as spent by nullifier.
    pub fn mark_spent(&mut self, nullifier_hex: &str) {
        for o in &mut self.outputs {
            if let Some(ref n) = o.nullifier {
                if hex::encode(n) == nullifier_hex {
                    o.spent = true;
                    return;
                }
            }
        }
    }

    /// Get ring member leaves for a UTXO (real output + decoys).
    ///
    /// In the CLI flow, this queries the node's UTXO set via RPC for
    /// eligible decoy candidates, then constructs the ring locally.
    ///
    /// # Arguments
    /// - `utxo`: The real UTXO being spent
    /// - `chain_id`: Network chain ID for domain separation
    ///
    /// # Production Flow
    ///
    /// 1. RPC request to node: `get_eligible_decoys(chain_id, min_depth=100, count=64)`
    /// 2. Node returns candidate OutputIds + spending pubkeys + commitments
    /// 3. Client selects `STANDARD_RING_SIZE - 1` decoys uniformly
    /// 4. Client inserts real output at random position
    /// 5. Client builds RingMemberLeaf for each, computes Merkle root
    ///
    /// For offline/testnet mode where no node connection is available,
    /// this returns Err. The caller should handle this gracefully.
    pub fn get_ring_leaves(
        &self,
        utxo: &OwnedOutput,
        chain_id: u32,
    ) -> Result<Vec<RingMemberLeafWithPk>, String> {
        // Check if we have enough UTXOs locally for a testnet ring
        // (In production, decoys come from the full UTXO set via RPC)
        let decoys_needed = misaka_pqc::privacy::STANDARD_RING_SIZE - 1;

        let candidates: Vec<&OwnedOutput> = self.outputs.iter()
            .filter(|o| !o.spent)
            .filter(|o| !(o.tx_hash == utxo.tx_hash && o.output_index == utxo.output_index))
            .collect();

        if candidates.len() < decoys_needed {
            return Err(format!(
                "insufficient local UTXOs for ring: {} available, {} needed. \
                 Connect to a node for full UTXO set decoy selection.",
                candidates.len(), decoys_needed
            ));
        }

        // Select decoys (uniform random sampling)
        use rand::seq::SliceRandom;
        let mut rng = rand::thread_rng();
        let selected_decoys: Vec<&OwnedOutput> = candidates
            .choose_multiple(&mut rng, decoys_needed)
            .copied()
            .collect();

        // Build ring: real output at random position
        let signer_pos = rand::Rng::gen_range(&mut rng, 0..misaka_pqc::privacy::STANDARD_RING_SIZE);
        let mut ring = Vec::with_capacity(misaka_pqc::privacy::STANDARD_RING_SIZE);

        let crs = misaka_pqc::bdlop::BdlopCrs::default_crs();
        let mut decoy_iter = selected_decoys.into_iter();

        for i in 0..misaka_pqc::privacy::STANDARD_RING_SIZE {
            let output = if i == signer_pos { utxo } else {
                decoy_iter.next().ok_or("decoy exhausted")?
            };

            let commitment = misaka_pqc::bdlop::BdlopCommitment::commit(
                &crs, &output.blinding, output.amount,
            );
            let outid = misaka_pqc::nullifier::OutputId {
                tx_hash: output.tx_hash,
                output_index: output.output_index,
            };

            ring.push(RingMemberLeafWithPk {
                leaf: RingMemberLeaf {
                    spending_pubkey: output.spending_pk.to_bytes(),
                    commitment,
                    output_id: outid,
                    chain_id,
                },
                spending_pk: output.spending_pk.clone(),
            });
        }

        Ok(ring)
    }

    pub fn balance(&self) -> u64 {
        self.outputs.iter()
            .filter(|o| !o.spent)
            .map(|o| o.amount)
            .sum()
    }

    pub fn unspent_count(&self) -> usize {
        self.outputs.iter().filter(|o| !o.spent).count()
    }
}

/// Ring member leaf with spending public key for signer identification.
#[derive(Debug, Clone)]
pub struct RingMemberLeafWithPk {
    pub leaf: RingMemberLeaf,
    pub spending_pk: Poly,
}

impl RingMemberLeafWithPk {
    pub fn leaf_hash(&self) -> [u8; 32] {
        self.leaf.leaf_hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_balance() {
        let ws = WalletState::new(2);
        assert_eq!(ws.balance(), 0);
        assert_eq!(ws.unspent_count(), 0);
    }
}
