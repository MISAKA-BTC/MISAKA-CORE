//! Cross-chain bridge (Spec 06 + 07).
use std::collections::HashMap;
use misaka_types::Digest;

pub const CHAIN_ID_SOLANA: u32 = 1;

#[derive(Debug, Clone)]
pub struct BridgeAttestation {
    pub source_chain: u32,
    pub source_tx_hash: Digest,
    pub amount: u64,
    pub recipient: [u8; 20],
    pub attester_count: usize,
}

pub struct BridgeState {
    pub attestations: HashMap<Digest, BridgeAttestation>,
    pub processed: HashMap<Digest, bool>,
    pub required_attestations: usize,
}

impl BridgeState {
    pub fn new(required: usize) -> Self {
        Self { attestations: HashMap::new(), processed: HashMap::new(), required_attestations: required }
    }

    pub fn add_attestation(&mut self, att: BridgeAttestation) -> bool {
        let key = att.source_tx_hash;
        if self.processed.contains_key(&key) { return false; }
        let entry = self.attestations.entry(key).or_insert(att);
        entry.attester_count += 1;
        if entry.attester_count >= self.required_attestations {
            self.processed.insert(key, true);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_bridge_attestation_threshold() {
        let mut bs = BridgeState::new(3);
        let att = BridgeAttestation {
            source_chain: CHAIN_ID_SOLANA, source_tx_hash: [0xAA; 32],
            amount: 1000, recipient: [0xBB; 20], attester_count: 0,
        };
        assert!(!bs.add_attestation(att.clone()));
        assert!(!bs.add_attestation(att.clone()));
        assert!(bs.add_attestation(att));
    }
}
