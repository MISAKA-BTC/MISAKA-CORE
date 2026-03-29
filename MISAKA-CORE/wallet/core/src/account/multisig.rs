//! Multi-signature account: M-of-N threshold signing.

use super::{Account, AccountId, AccountKind, AccountMeta};
use serde::{Serialize, Deserialize};

/// Multi-signature account configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigAccount {
    pub meta: AccountMeta,
    /// Required signatures (M).
    pub required: usize,
    /// Total cosigner count (N).
    pub total: usize,
    /// Public keys of all cosigners.
    pub cosigner_pubkeys: Vec<Vec<u8>>,
    /// Index of this wallet's key in cosigner list.
    pub own_index: Option<usize>,
    /// Whether PQ signatures are used.
    pub is_pq: bool,
    /// Redeem script hash.
    pub script_hash: [u8; 32],
}

impl MultisigAccount {
    pub fn new(
        id: AccountId,
        name: String,
        required: usize,
        cosigner_pubkeys: Vec<Vec<u8>>,
        own_index: Option<usize>,
        is_pq: bool,
    ) -> Result<Self, String> {
        let total = cosigner_pubkeys.len();
        if required == 0 || required > total {
            return Err(format!("invalid M-of-N: {}-of-{}", required, total));
        }
        if total > 20 {
            return Err("maximum 20 cosigners".into());
        }

        // Compute redeem script hash
        let script_hash = Self::compute_script_hash(required, &cosigner_pubkeys, is_pq);

        Ok(Self {
            meta: AccountMeta::new(id, name, AccountKind::MultiSig),
            required,
            total,
            cosigner_pubkeys,
            own_index,
            is_pq,
            script_hash,
        })
    }

    fn compute_script_hash(required: usize, pubkeys: &[Vec<u8>], is_pq: bool) -> [u8; 32] {
        use sha3::{Sha3_256, Digest};
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:multisig:v1:");
        h.update(&(required as u32).to_le_bytes());
        h.update(&(pubkeys.len() as u32).to_le_bytes());
        h.update(&[is_pq as u8]);
        for pk in pubkeys {
            h.update(&(pk.len() as u32).to_le_bytes());
            h.update(pk);
        }
        h.finalize().into()
    }

    pub fn address(&self) -> String {
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&self.script_hash[..20]);
        crate::encode_address(&addr)
    }

    /// Create a partial signature for a transaction.
    pub fn create_partial_sig(&self, tx_hash: &[u8; 32], signing_key: &[u8]) -> PartialSignature {
        PartialSignature {
            signer_index: self.own_index.unwrap_or(0),
            signer_pubkey: self.own_index
                .map(|i| self.cosigner_pubkeys[i].clone())
                .unwrap_or_default(),
            signature: Vec::new(), // Actual signing delegated to PQC module
            tx_hash: *tx_hash,
        }
    }

    /// Combine partial signatures into a complete multisig.
    pub fn combine_signatures(&self, partials: &[PartialSignature]) -> Result<Vec<u8>, String> {
        if partials.len() < self.required {
            return Err(format!(
                "need {} signatures, got {}", self.required, partials.len()
            ));
        }
        // Verify each partial sig is from a valid cosigner
        for partial in partials {
            if partial.signer_index >= self.total {
                return Err(format!("invalid signer index: {}", partial.signer_index));
            }
        }
        // Concatenate signatures (actual verification in consensus)
        let mut combined = Vec::new();
        combined.push(self.required as u8);
        combined.push(partials.len() as u8);
        for partial in partials {
            combined.push(partial.signer_index as u8);
            combined.extend_from_slice(&(partial.signature.len() as u32).to_le_bytes());
            combined.extend_from_slice(&partial.signature);
        }
        Ok(combined)
    }
}

/// A partial signature from one cosigner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialSignature {
    pub signer_index: usize,
    pub signer_pubkey: Vec<u8>,
    pub signature: Vec<u8>,
    pub tx_hash: [u8; 32],
}

impl Account for MultisigAccount {
    fn meta(&self) -> &AccountMeta { &self.meta }
    fn kind(&self) -> AccountKind { AccountKind::MultiSig }
    fn receive_address(&self) -> String { self.address() }
    fn change_address(&self) -> String { self.address() }
    fn next_receive_address(&mut self) -> String { self.address() }
    fn next_change_address(&mut self) -> String { self.address() }
    fn can_sign(&self) -> bool { self.own_index.is_some() }
}
