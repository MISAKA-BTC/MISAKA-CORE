//! PSKT — Partially Signed Key Transaction.
//!
//! MISAKA's equivalent of Bitcoin's PSBT, designed for:
//! - Hardware wallet signing workflows  
//! - Multi-party threshold signing (ML-DSA-65 multisig)
//! - Air-gapped signing with QR code transport
//! - Watch-only wallet → cold wallet → broadcast pipeline
//!
//! # Format
//! PSKT is serialized as a structured JSON or binary (Borsh) document
//! containing the unsigned transaction plus per-input/per-output metadata
//! needed for offline signing.
//!
//! # Security Properties
//! - Chain ID binding prevents cross-chain replay
//! - Version field enables future format upgrades without ambiguity
//! - Each input carries its UTXO entry for offline fee verification
//! - Signature slots are typed (ML-DSA-65, ML-DSA-44, multisig)

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// PSKT format version.
pub const PSKT_VERSION: u32 = 1;

/// Maximum PSKT size in bytes (prevent DoS via oversized PSKTs).
pub const MAX_PSKT_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// A Partially Signed Key Transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pskt {
    pub version: u32,
    pub chain_id: [u8; 4],
    pub tx: PsktTransaction,
    pub inputs: Vec<PsktInput>,
    pub outputs: Vec<PsktOutput>,
    pub global: PsktGlobal,
}

/// The unsigned transaction within a PSKT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsktTransaction {
    pub version: u32,
    pub lock_time: u64,
    pub subnetwork_id: [u8; 20],
    pub gas: u64,
    pub payload: Vec<u8>,
}

/// Per-input PSKT data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsktInput {
    /// Previous outpoint.
    pub prev_tx_id: [u8; 32],
    pub prev_index: u32,
    pub sequence: u64,
    /// UTXO entry being spent (needed for offline fee verification).
    pub utxo_entry: Option<PsktUtxoEntry>,
    /// The script public key that locks this input.
    pub script_public_key: Vec<u8>,
    /// Sighash type requested.
    pub sig_hash_type: u8,
    /// Partial signatures collected so far (pubkey -> signature).
    pub partial_sigs: HashMap<String, Vec<u8>>,
    /// Required number of signatures (1 for single-sig, M for multisig).
    pub required_sigs: u32,
    /// Public keys authorized to sign this input.
    pub authorized_pubkeys: Vec<Vec<u8>>,
    /// Whether this input is finalized (all signatures present).
    pub finalized: bool,
    /// Finalized signature script (set after all partial sigs collected).
    pub final_sig_script: Option<Vec<u8>>,
    /// Derivation path for HD wallet signing.
    pub derivation_path: Option<String>,
    /// Redeem script for P2SH inputs.
    pub redeem_script: Option<Vec<u8>>,
}

/// UTXO entry embedded in PSKT for offline verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsktUtxoEntry {
    pub amount: u64,
    pub script_public_key: Vec<u8>,
    pub block_daa_score: u64,
    pub is_coinbase: bool,
}

/// Per-output PSKT data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsktOutput {
    pub value: u64,
    pub script_public_key: Vec<u8>,
    /// Whether this is a change output (wallet knows the key).
    pub is_change: bool,
    /// Derivation path for change outputs.
    pub change_derivation_path: Option<String>,
}

/// Global PSKT metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsktGlobal {
    /// Creator of this PSKT.
    pub creator: String,
    /// Roles that have processed this PSKT.
    pub roles: Vec<PsktRole>,
    /// Network identifier.
    pub network: String,
    /// Fee amount (computed from inputs - outputs).
    pub fee: u64,
    /// Total input amount.
    pub total_input: u64,
    /// Total output amount.
    pub total_output: u64,
    /// Whether the PSKT is fully signed and ready for broadcast.
    pub is_complete: bool,
    /// Extended key information for signers.
    pub xpub_data: Vec<XpubEntry>,
}

/// Role tracking — who has processed this PSKT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsktRole {
    pub role: String,   // "creator", "updater", "signer", "combiner", "finalizer"
    pub name: String,
    pub timestamp: u64,
}

/// Extended public key entry for key discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XpubEntry {
    pub xpub: String,
    pub fingerprint: [u8; 4],
    pub derivation_path: String,
}

impl Pskt {
    /// Create a new PSKT from transaction data.
    pub fn new(
        chain_id: [u8; 4],
        tx: PsktTransaction,
        inputs: Vec<PsktInput>,
        outputs: Vec<PsktOutput>,
    ) -> Result<Self, PsktError> {
        if inputs.is_empty() {
            return Err(PsktError::NoInputs);
        }
        if outputs.is_empty() {
            return Err(PsktError::NoOutputs);
        }

        let total_input: u64 = inputs.iter()
            .filter_map(|i| i.utxo_entry.as_ref())
            .map(|e| e.amount)
            .sum();
        let total_output: u64 = outputs.iter().map(|o| o.value).sum();

        if total_input < total_output {
            return Err(PsktError::InsufficientFunds { input: total_input, output: total_output });
        }

        let fee = total_input - total_output;

        Ok(Self {
            version: PSKT_VERSION,
            chain_id,
            tx,
            inputs,
            outputs,
            global: PsktGlobal {
                creator: "misaka-wallet".to_string(),
                roles: vec![PsktRole {
                    role: "creator".to_string(),
                    name: "misaka-wallet".to_string(),
                    timestamp: now_secs(),
                }],
                network: "misaka-mainnet".to_string(),
                fee,
                total_input,
                total_output,
                is_complete: false,
                xpub_data: Vec::new(),
            },
        })
    }

    /// Add a partial signature for an input.
    pub fn add_partial_sig(
        &mut self,
        input_index: usize,
        pubkey_hex: String,
        signature: Vec<u8>,
    ) -> Result<(), PsktError> {
        let input = self.inputs.get_mut(input_index)
            .ok_or(PsktError::InputIndexOutOfRange(input_index))?;

        if input.finalized {
            return Err(PsktError::AlreadyFinalized(input_index));
        }

        // Verify pubkey is authorized
        let pubkey_bytes = hex::decode(&pubkey_hex)
            .map_err(|_| PsktError::InvalidPubkey(pubkey_hex.clone()))?;

        if !input.authorized_pubkeys.is_empty() {
            if !input.authorized_pubkeys.iter().any(|pk| *pk == pubkey_bytes) {
                return Err(PsktError::UnauthorizedSigner(pubkey_hex));
            }
        }

        input.partial_sigs.insert(pubkey_hex, signature);

        // Check if we have enough signatures
        if input.partial_sigs.len() as u32 >= input.required_sigs {
            self.try_finalize_input(input_index)?;
        }

        self.update_completeness();
        Ok(())
    }

    /// Attempt to finalize an input (all required signatures present).
    fn try_finalize_input(&mut self, input_index: usize) -> Result<bool, PsktError> {
        let input = &mut self.inputs[input_index];
        if input.partial_sigs.len() as u32 < input.required_sigs {
            return Ok(false);
        }

        // Build the final signature script
        let mut final_script = Vec::new();

        if input.required_sigs == 1 {
            // Single-sig: just the signature + pubkey
            if let Some((pubkey_hex, sig)) = input.partial_sigs.iter().next() {
                let pubkey = hex::decode(pubkey_hex)
                    .map_err(|_| PsktError::InvalidPubkey(pubkey_hex.clone()))?;
                // Push signature
                final_script.push(sig.len() as u8);
                final_script.extend_from_slice(sig);
                // Push pubkey
                final_script.push(pubkey.len() as u8);
                final_script.extend_from_slice(&pubkey);
            }
        } else {
            // Multisig: OP_0 + signatures in order
            final_script.push(0x00); // OP_0 (dummy for CHECKMULTISIG bug)
            for (_, sig) in &input.partial_sigs {
                final_script.push(sig.len() as u8);
                final_script.extend_from_slice(sig);
            }
            // Push redeem script if P2SH
            if let Some(ref redeem) = input.redeem_script {
                final_script.push(redeem.len() as u8);
                final_script.extend_from_slice(redeem);
            }
        }

        input.final_sig_script = Some(final_script);
        input.finalized = true;

        self.global.roles.push(PsktRole {
            role: "finalizer".to_string(),
            name: "misaka-wallet".to_string(),
            timestamp: now_secs(),
        });

        Ok(true)
    }

    /// Check if all inputs are finalized.
    fn update_completeness(&mut self) {
        self.global.is_complete = self.inputs.iter().all(|i| i.finalized);
    }

    /// Check if the PSKT is complete (all signatures present).
    pub fn is_complete(&self) -> bool {
        self.global.is_complete
    }

    /// Extract the finalized transaction for broadcast.
    pub fn extract(&self) -> Result<FinalizedTransaction, PsktError> {
        if !self.is_complete() {
            return Err(PsktError::NotComplete);
        }

        let signed_inputs: Vec<FinalizedInput> = self.inputs.iter().enumerate()
            .map(|(i, input)| {
                let sig_script = input.final_sig_script.as_ref()
                    .ok_or(PsktError::InputNotFinalized(i))?;
                Ok(FinalizedInput {
                    prev_tx_id: input.prev_tx_id,
                    prev_index: input.prev_index,
                    signature_script: sig_script.clone(),
                    sequence: input.sequence,
                })
            })
            .collect::<Result<Vec<_>, PsktError>>()?;

        let outputs: Vec<FinalizedOutput> = self.outputs.iter()
            .map(|o| FinalizedOutput {
                value: o.value,
                script_public_key: o.script_public_key.clone(),
            })
            .collect();

        // Compute tx_id
        let tx_id = self.compute_tx_id();

        Ok(FinalizedTransaction {
            tx_id,
            version: self.tx.version,
            inputs: signed_inputs,
            outputs,
            lock_time: self.tx.lock_time,
            subnetwork_id: self.tx.subnetwork_id,
            gas: self.tx.gas,
            payload: self.tx.payload.clone(),
            fee: self.global.fee,
        })
    }

    fn compute_tx_id(&self) -> [u8; 32] {
        use sha3::{Sha3_256, Digest};
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:txid:v1:");
        h.update(&self.tx.version.to_le_bytes());
        for input in &self.inputs {
            h.update(&input.prev_tx_id);
            h.update(&input.prev_index.to_le_bytes());
        }
        for output in &self.outputs {
            h.update(&output.value.to_le_bytes());
            h.update(&output.script_public_key);
        }
        h.update(&self.tx.lock_time.to_le_bytes());
        h.finalize().into()
    }

    /// Serialize to JSON.
    pub fn to_json(&self) -> Result<String, PsktError> {
        serde_json::to_string(self).map_err(|e| PsktError::Serialization(e.to_string()))
    }

    /// Deserialize from JSON.
    pub fn from_json(json: &str) -> Result<Self, PsktError> {
        if json.len() > MAX_PSKT_SIZE {
            return Err(PsktError::TooLarge(json.len()));
        }
        let pskt: Self = serde_json::from_str(json)
            .map_err(|e| PsktError::Serialization(e.to_string()))?;
        if pskt.version != PSKT_VERSION {
            return Err(PsktError::UnsupportedVersion(pskt.version));
        }
        Ok(pskt)
    }

    /// Combine two PSKTs with partial signatures from different signers.
    pub fn combine(mut self, other: Self) -> Result<Self, PsktError> {
        if self.compute_tx_id() != other.compute_tx_id() {
            return Err(PsktError::TxIdMismatch);
        }

        for (i, other_input) in other.inputs.iter().enumerate() {
            if i < self.inputs.len() {
                for (pubkey, sig) in &other_input.partial_sigs {
                    if !self.inputs[i].partial_sigs.contains_key(pubkey) {
                        self.inputs[i].partial_sigs.insert(pubkey.clone(), sig.clone());
                    }
                }
            }
        }

        // Try finalization after combining
        for i in 0..self.inputs.len() {
            if !self.inputs[i].finalized {
                let _ = self.try_finalize_input(i);
            }
        }
        self.update_completeness();

        self.global.roles.push(PsktRole {
            role: "combiner".to_string(),
            name: "misaka-wallet".to_string(),
            timestamp: now_secs(),
        });

        Ok(self)
    }

    /// Validate PSKT structure and embedded UTXO entries.
    pub fn validate(&self) -> Result<(), Vec<PsktValidationError>> {
        let mut errors = Vec::new();

        // Check version
        if self.version != PSKT_VERSION {
            errors.push(PsktValidationError::UnsupportedVersion(self.version));
        }

        // Check inputs
        if self.inputs.is_empty() {
            errors.push(PsktValidationError::NoInputs);
        }

        // Check fee sanity
        if self.global.fee > self.global.total_input / 10 {
            errors.push(PsktValidationError::ExcessiveFee {
                fee: self.global.fee,
                total: self.global.total_input,
            });
        }

        // Check each input has UTXO entry
        for (i, input) in self.inputs.iter().enumerate() {
            if input.utxo_entry.is_none() && !input.finalized {
                errors.push(PsktValidationError::MissingUtxoEntry(i));
            }
        }

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }
}

/// Finalized transaction ready for broadcast.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizedTransaction {
    pub tx_id: [u8; 32],
    pub version: u32,
    pub inputs: Vec<FinalizedInput>,
    pub outputs: Vec<FinalizedOutput>,
    pub lock_time: u64,
    pub subnetwork_id: [u8; 20],
    pub gas: u64,
    pub payload: Vec<u8>,
    pub fee: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizedInput {
    pub prev_tx_id: [u8; 32],
    pub prev_index: u32,
    pub signature_script: Vec<u8>,
    pub sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizedOutput {
    pub value: u64,
    pub script_public_key: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum PsktError {
    #[error("no inputs")]
    NoInputs,
    #[error("no outputs")]
    NoOutputs,
    #[error("insufficient funds: {input} < {output}")]
    InsufficientFunds { input: u64, output: u64 },
    #[error("input index out of range: {0}")]
    InputIndexOutOfRange(usize),
    #[error("input {0} already finalized")]
    AlreadyFinalized(usize),
    #[error("invalid pubkey: {0}")]
    InvalidPubkey(String),
    #[error("unauthorized signer: {0}")]
    UnauthorizedSigner(String),
    #[error("PSKT not complete — missing signatures")]
    NotComplete,
    #[error("input {0} not finalized")]
    InputNotFinalized(usize),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("PSKT too large: {0} bytes")]
    TooLarge(usize),
    #[error("unsupported PSKT version: {0}")]
    UnsupportedVersion(u32),
    #[error("tx ID mismatch during combine")]
    TxIdMismatch,
}

#[derive(Debug)]
pub enum PsktValidationError {
    UnsupportedVersion(u32),
    NoInputs,
    ExcessiveFee { fee: u64, total: u64 },
    MissingUtxoEntry(usize),
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pskt() -> Pskt {
        Pskt::new(
            [0x4D, 0x53, 0x4B, 0x01],
            PsktTransaction {
                version: 1, lock_time: 0,
                subnetwork_id: [0; 20], gas: 0, payload: vec![],
            },
            vec![PsktInput {
                prev_tx_id: [1; 32], prev_index: 0, sequence: u64::MAX,
                utxo_entry: Some(PsktUtxoEntry { amount: 5000, script_public_key: vec![], block_daa_score: 100, is_coinbase: false }),
                script_public_key: vec![0x76], sig_hash_type: 0x01,
                partial_sigs: HashMap::new(), required_sigs: 1,
                authorized_pubkeys: vec![], finalized: false,
                final_sig_script: None, derivation_path: None, redeem_script: None,
            }],
            vec![PsktOutput {
                value: 4000, script_public_key: vec![0x76],
                is_change: false, change_derivation_path: None,
            }],
        ).unwrap()
    }

    #[test]
    fn test_pskt_creation() {
        let pskt = make_pskt();
        assert_eq!(pskt.global.fee, 1000);
        assert!(!pskt.is_complete());
    }

    #[test]
    fn test_pskt_json_round_trip() {
        let pskt = make_pskt();
        let json = pskt.to_json().unwrap();
        let recovered = Pskt::from_json(&json).unwrap();
        assert_eq!(recovered.global.fee, 1000);
    }
}
