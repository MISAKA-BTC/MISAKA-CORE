//! UTXO Transaction Model (stability-first privacy PoS).
//!
//! - Sender anonymity: CLSAG-inspired PQ ring signatures
//! - Receiver anonymity: ML-KEM-768 stealth outputs
//! - Amount: PUBLIC (no confidential transactions)
//! - Key images: double-spend prevention

use sha3::{Digest as Sha3Digest, Sha3_256};
use crate::mcs1;
use crate::error::MisakaError;
use crate::stealth::PqStealthData;

/// Reference to a previous output (UTXO pointer).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct OutputRef {
    /// Transaction hash containing the output.
    pub tx_hash: [u8; 32],
    /// Output index within that transaction.
    pub output_index: u32,
}

impl OutputRef {
    pub fn mcs1_encode(&self, buf: &mut Vec<u8>) {
        mcs1::write_fixed(buf, &self.tx_hash);
        mcs1::write_u32(buf, self.output_index);
    }
}

/// A ring-signed input: spends one real UTXO hidden among decoys.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RingInput {
    /// Ring member references (includes the real spend + decoys).
    pub ring_members: Vec<OutputRef>,
    /// PQ ring signature bytes (MISAKA-PQRS-v1).
    pub ring_signature: Vec<u8>,
    /// Key image for double-spend detection (32 bytes, deterministic from sk).
    pub key_image: [u8; 32],
    /// Key image correctness proof bytes (Σ-protocol).
    /// REQUIRED for transaction validity.
    pub ki_proof: Vec<u8>,
}

/// Transaction output with public amount and optional stealth data.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TxOutput {
    /// Amount in base units — PUBLIC.
    pub amount: u64,
    /// One-time destination address (20 bytes).
    pub one_time_address: [u8; 20],
    /// Optional PQ stealth extension for recipient recovery.
    pub pq_stealth: Option<PqStealthData>,
}

/// Complete UTXO transaction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UtxoTransaction {
    /// Protocol version.
    pub version: u8,
    /// Ring-signed inputs.
    pub inputs: Vec<RingInput>,
    /// Outputs with public amounts.
    pub outputs: Vec<TxOutput>,
    /// Transaction fee (public).
    pub fee: u64,
    /// Extra data (memo, etc.).
    pub extra: Vec<u8>,
}

/// Current protocol version.
pub const UTXO_TX_VERSION: u8 = 0x01;
/// Minimum ring size (including real spend).
pub const MIN_RING_SIZE: usize = 4;
/// Maximum ring size.
pub const MAX_RING_SIZE: usize = 16;
/// Maximum extra data length.
pub const MAX_EXTRA_LEN: usize = 1024;

impl UtxoTransaction {
    /// Compute the canonical signing digest (§12).
    ///
    /// Includes all consensus-relevant fields EXCEPT signatures.
    /// Used as the message for ring signatures.
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(256);
        mcs1::write_u8(&mut buf, self.version);

        // Inputs: only ring members + key images (not signatures)
        mcs1::write_u32(&mut buf, self.inputs.len() as u32);
        for inp in &self.inputs {
            mcs1::write_u32(&mut buf, inp.ring_members.len() as u32);
            for member in &inp.ring_members {
                member.mcs1_encode(&mut buf);
            }
            mcs1::write_fixed(&mut buf, &inp.key_image);
        }

        // Outputs
        mcs1::write_u32(&mut buf, self.outputs.len() as u32);
        for out in &self.outputs {
            mcs1::write_u64(&mut buf, out.amount);
            mcs1::write_fixed(&mut buf, &out.one_time_address);
            match &out.pq_stealth {
                Some(sd) => { mcs1::write_u8(&mut buf, 1); sd.mcs1_encode(&mut buf); }
                None => { mcs1::write_u8(&mut buf, 0); }
            }
        }

        // Fee + extra
        mcs1::write_u64(&mut buf, self.fee);
        mcs1::write_bytes(&mut buf, &self.extra);

        let mut h = Sha3_256::new();
        h.update(&buf);
        h.finalize().into()
    }

    /// Structural validation (no crypto checks).
    pub fn validate_structure(&self) -> Result<(), MisakaError> {
        if self.version != UTXO_TX_VERSION {
            return Err(MisakaError::DeserializationError(
                format!("unsupported tx version: 0x{:02x}", self.version)));
        }
        if self.inputs.is_empty() {
            return Err(MisakaError::EmptyInputs);
        }
        if self.outputs.is_empty() {
            return Err(MisakaError::EmptyActions); // reuse: "empty outputs"
        }
        for (i, inp) in self.inputs.iter().enumerate() {
            if inp.ring_members.len() < MIN_RING_SIZE {
                return Err(MisakaError::DeserializationError(
                    format!("input[{i}]: ring size {} < minimum {MIN_RING_SIZE}", inp.ring_members.len())));
            }
            if inp.ring_members.len() > MAX_RING_SIZE {
                return Err(MisakaError::DeserializationError(
                    format!("input[{i}]: ring size {} > maximum {MAX_RING_SIZE}", inp.ring_members.len())));
            }
        }
        // Check key image uniqueness within tx
        let mut images = std::collections::HashSet::new();
        for inp in &self.inputs {
            if !images.insert(inp.key_image) {
                return Err(MisakaError::DuplicateInput(
                    hex::encode(inp.key_image)));
            }
        }
        // Key image proof is REQUIRED
        for (i, inp) in self.inputs.iter().enumerate() {
            if inp.ki_proof.is_empty() {
                return Err(MisakaError::DeserializationError(
                    format!("input[{i}]: ki_proof is empty (REQUIRED)")));
            }
        }

        if self.extra.len() > MAX_EXTRA_LEN {
            return Err(MisakaError::FieldTooLarge {
                field: "extra".into(), size: self.extra.len(), max: MAX_EXTRA_LEN,
            });
        }
        // Amount conservation: sum(outputs) + fee must be checkable at block level
        Ok(())
    }

    /// Compute tx_hash (full transaction including signatures).
    pub fn tx_hash(&self) -> [u8; 32] {
        // For simplicity, hash the signing digest + all ring sigs
        let mut h = Sha3_256::new();
        h.update(&self.signing_digest());
        for inp in &self.inputs {
            h.update(&inp.ring_signature);
        }
        h.finalize().into()
    }

    /// Total output amount.
    pub fn total_output(&self) -> u64 {
        self.outputs.iter().map(|o| o.amount).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_utxo_tx() -> UtxoTransaction {
        UtxoTransaction {
            version: UTXO_TX_VERSION,
            inputs: vec![RingInput {
                ring_members: vec![
                    OutputRef { tx_hash: [1; 32], output_index: 0 },
                    OutputRef { tx_hash: [2; 32], output_index: 0 },
                    OutputRef { tx_hash: [3; 32], output_index: 0 },
                    OutputRef { tx_hash: [4; 32], output_index: 0 },
                ],
                ring_signature: vec![0xAA; 128],
                key_image: [0xBB; 32],
                ki_proof: vec![0xDD; 64], // 追加
                // amount, one_time_address 等は削除
            }],
            outputs: vec![], // 追加
            fee: 100,
            extra: vec![],
        }
    }
    #[test]
    fn test_signing_digest_deterministic() {
        let tx = make_utxo_tx();
        assert_eq!(tx.signing_digest(), tx.signing_digest());
    }

    #[test]
    fn test_signing_digest_excludes_sig() {
        let mut tx1 = make_utxo_tx();
        let mut tx2 = make_utxo_tx();
        tx1.inputs[0].ring_signature = vec![0x11; 128];
        tx2.inputs[0].ring_signature = vec![0x22; 128];
        // signing_digest must be same (excludes ring_signature)
        assert_eq!(tx1.signing_digest(), tx2.signing_digest());
    }

    #[test]
    fn test_tx_hash_includes_sig() {
        let mut tx1 = make_utxo_tx();
        let mut tx2 = make_utxo_tx();
        tx1.inputs[0].ring_signature = vec![0x11; 128];
        tx2.inputs[0].ring_signature = vec![0x22; 128];
        assert_ne!(tx1.tx_hash(), tx2.tx_hash());
    }

    #[test]
    fn test_validate_structure_ok() {
        let tx = make_utxo_tx();
        tx.validate_structure().unwrap();
    }

    #[test]
    fn test_validate_ring_too_small() {
        let mut tx = make_utxo_tx();
        tx.inputs[0].ring_members.truncate(2);
        assert!(tx.validate_structure().is_err());
    }

fn test_validate_duplicate_key_image() {
        let mut tx = make_utxo_tx();
        tx.inputs.push(RingInput {
            ring_members: tx.inputs[0].ring_members.clone(),
            ring_signature: vec![0xDD; 128],
            key_image: [0xBB; 32], 
            ki_proof: vec![0xEE; 64], // 追加
        });
        assert!(tx.validate_structure().is_err());
    }
}
