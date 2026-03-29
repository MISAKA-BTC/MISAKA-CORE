//! # PSMT — Partially Signed MISAKA Transaction
//!
//! PQ-native equivalent of Kaspa's PSKT (Partially Signed Kaspa Transaction).
//! Enables multi-party signing workflows:
//!
//! 1. Creator builds the unsigned transaction
//! 2. Each signer adds their ML-DSA-65 signature
//! 3. Finalizer combines all signatures and broadcasts
//!
//! Unlike ECDSA multisig, PQ multisig requires each signer to produce
//! an independent signature (no Schnorr-style aggregation for ML-DSA).

use serde::{Deserialize, Serialize};

pub type Hash = [u8; 32];

/// PSMT role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsmtRole {
    Creator,
    Signer,
    Combiner,
    Finalizer,
    Extractor,
}

/// A PSMT input (UTXO being spent).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsmtInput {
    /// Previous outpoint: tx_hash.
    pub previous_tx_hash: Hash,
    /// Previous outpoint: output index.
    pub previous_output_index: u32,
    /// Value of the UTXO being spent.
    pub value: u64,
    /// ML-DSA-65 public key that can spend this UTXO.
    pub signer_public_key: Vec<u8>,
    /// Signature (filled in by the signer, None initially).
    pub signature: Option<Vec<u8>>,
    /// Sighash type.
    pub sighash_type: u8,
    /// For multisig: index of this signer in the cosigner list.
    pub signer_index: Option<u8>,
    /// Additional partial signatures from other cosigners.
    #[serde(default)]
    pub partial_signatures: Vec<PartialSignature>,
}

/// A partial signature from one cosigner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialSignature {
    /// ML-DSA-65 public key of the signer.
    pub public_key: Vec<u8>,
    /// The signature bytes.
    pub signature: Vec<u8>,
}

/// A PSMT output (destination).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsmtOutput {
    /// Destination address (misaka1...).
    pub address: String,
    /// Amount in base units.
    pub value: u64,
    /// Script public key (PQ-native: ML-DSA-65 pubkey hash).
    pub script_public_key: Vec<u8>,
}

/// A Partially Signed MISAKA Transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Psmt {
    /// PSMT format version.
    pub version: u32,
    /// Transaction inputs (UTXOs being spent).
    pub inputs: Vec<PsmtInput>,
    /// Transaction outputs (destinations).
    pub outputs: Vec<PsmtOutput>,
    /// Lock time (0 = no lock).
    pub lock_time: u64,
    /// The transaction hash (computed after all inputs are filled).
    pub tx_hash: Option<Hash>,
    /// Creation timestamp.
    pub created_at: u64,
    /// Whether all required signatures have been collected.
    pub is_finalized: bool,
    /// For multisig: required number of signatures.
    pub required_signatures: Option<u8>,
}

impl Psmt {
    /// Create a new unsigned PSMT.
    pub fn new(inputs: Vec<PsmtInput>, outputs: Vec<PsmtOutput>) -> Self {
        Self {
            version: 1,
            inputs,
            outputs,
            lock_time: 0,
            tx_hash: None,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            is_finalized: false,
            required_signatures: None,
        }
    }

    /// Create a multisig PSMT.
    pub fn new_multisig(
        inputs: Vec<PsmtInput>,
        outputs: Vec<PsmtOutput>,
        threshold: u8,
    ) -> Self {
        let mut psmt = Self::new(inputs, outputs);
        psmt.required_signatures = Some(threshold);
        psmt
    }

    /// Add a signature for an input.
    pub fn add_signature(
        &mut self,
        input_index: usize,
        public_key: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<(), String> {
        let input = self
            .inputs
            .get_mut(input_index)
            .ok_or_else(|| format!("input index {} out of range", input_index))?;

        if self.required_signatures.is_some() {
            // Multisig: add as partial signature.
            input.partial_signatures.push(PartialSignature {
                public_key,
                signature,
            });
        } else {
            // Single-sig: set the signature directly.
            input.signature = Some(signature);
        }

        Ok(())
    }

    /// Check if the PSMT is ready to finalize.
    pub fn can_finalize(&self) -> bool {
        if let Some(required) = self.required_signatures {
            // Multisig: check all inputs have enough partial sigs.
            self.inputs.iter().all(|input| {
                input.partial_signatures.len() >= required as usize
            })
        } else {
            // Single-sig: check all inputs have a signature.
            self.inputs.iter().all(|input| input.signature.is_some())
        }
    }

    /// Finalize the PSMT — no more signatures can be added.
    pub fn finalize(&mut self) -> Result<(), String> {
        if !self.can_finalize() {
            return Err("not all required signatures collected".into());
        }
        self.is_finalized = true;
        // Compute transaction hash.
        self.tx_hash = Some(self.compute_hash());
        Ok(())
    }

    /// Total input value.
    pub fn total_input_value(&self) -> u64 {
        self.inputs.iter().map(|i| i.value).sum()
    }

    /// Total output value.
    pub fn total_output_value(&self) -> u64 {
        self.outputs.iter().map(|o| o.value).sum()
    }

    /// Fee (input - output). Returns 0 if outputs exceed inputs.
    pub fn fee(&self) -> u64 {
        self.total_input_value()
            .saturating_sub(self.total_output_value())
    }

    /// Compute the transaction hash (SHA3-256 of canonical form).
    fn compute_hash(&self) -> Hash {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&self.version.to_le_bytes());
        hasher.update(&(self.inputs.len() as u32).to_le_bytes());
        for input in &self.inputs {
            hasher.update(&input.previous_tx_hash);
            hasher.update(&input.previous_output_index.to_le_bytes());
            hasher.update(&input.value.to_le_bytes());
        }
        hasher.update(&(self.outputs.len() as u32).to_le_bytes());
        for output in &self.outputs {
            hasher.update(&output.value.to_le_bytes());
            hasher.update(&output.script_public_key);
        }
        hasher.update(&self.lock_time.to_le_bytes());
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Serialize to JSON for transport.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}
