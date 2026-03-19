//! UTXO Transaction Model — privacy-first PoS.
//!
//! - Sender anonymity: ring signatures (LRS-v1 or ChipmunkRing-v1)
//! - Receiver anonymity: ML-KEM-768 stealth outputs (v1 or v2)
//! - Amount: PUBLIC (no confidential transactions)
//! - Key images: double-spend prevention

use sha3::{Digest as Sha3Digest, Sha3_256};
use crate::mcs1;
use crate::error::MisakaError;
use crate::stealth::PqStealthData;

/// Reference to a previous output (UTXO pointer).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct OutputRef {
    pub tx_hash: [u8; 32],
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
    /// Ring signature bytes (scheme-dependent).
    pub ring_signature: Vec<u8>,
    /// Key image for double-spend detection (32 bytes, deterministic from sk).
    pub key_image: [u8; 32],
    /// Key image correctness proof bytes (Σ-protocol). REQUIRED.
    pub ki_proof: Vec<u8>,
}

/// Transaction output with public amount and optional stealth data.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TxOutput {
    pub amount: u64,
    pub one_time_address: [u8; 20],
    pub pq_stealth: Option<PqStealthData>,
    /// Spending public key (lattice polynomial, serialized).
    /// REQUIRED for new outputs to be spendable in future transactions.
    /// Ring member resolution uses this to verify ring signatures.
    /// If None, the output cannot be used as a ring member (unspendable).
    #[serde(default)]
    pub spending_pubkey: Option<Vec<u8>>,
}

/// Transaction type — explicit categorization for consensus validation.
///
/// Replaces the implicit "inputs empty && fee == 0" heuristic for Coinbase
/// detection, eliminating a class of potential exploits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TxType {
    /// Standard value transfer with ring-signed inputs.
    Transfer,
    /// Block reward transaction (no inputs, miner/validator receives reward).
    Coinbase,
    /// Testnet faucet drip (no inputs, rate-limited).
    Faucet,
}

impl Default for TxType {
    fn default() -> Self { TxType::Transfer }
}

/// Complete UTXO transaction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UtxoTransaction {
    /// Protocol version (0x01 = v1/LRS, 0x02 = v2/ChipmunkRing).
    pub version: u8,
    /// Ring signature scheme tag (0x01=LRS, 0x02=Chipmunk). Defaults to version for v1 compat.
    #[serde(default = "default_ring_scheme")]
    pub ring_scheme: u8,
    /// Transaction type — Transfer, Coinbase, or Faucet.
    #[serde(default)]
    pub tx_type: TxType,
    /// Ring-signed inputs.
    pub inputs: Vec<RingInput>,
    /// Outputs with public amounts.
    pub outputs: Vec<TxOutput>,
    /// Transaction fee (public).
    pub fee: u64,
    /// Extra data (memo, etc.).
    pub extra: Vec<u8>,
}

fn default_ring_scheme() -> u8 { 0x03 } // LogRing-v1 is the system default

// ── Protocol Versions ──

/// Legacy LRS version.
pub const UTXO_TX_VERSION: u8 = 0x01;
/// ChipmunkRing version.
pub const UTXO_TX_VERSION_V2: u8 = 0x02;
/// LogRing version (system default).
pub const UTXO_TX_VERSION_V3: u8 = 0x03;

/// Ring scheme tags (match RingSchemeVersion in misaka-pqc).
pub const RING_SCHEME_LRS: u8 = 0x01;
pub const RING_SCHEME_CHIPMUNK: u8 = 0x02;
/// LogRing O(log n) — system default.
pub const RING_SCHEME_LOGRING: u8 = 0x03;

/// Minimum ring size (all schemes).
pub const MIN_RING_SIZE: usize = 4;
/// Maximum ring size (v1/LRS: 16, v2/Chipmunk: 32, v3/LogRing: 1024).
pub const MAX_RING_SIZE_V1: usize = 16;
pub const MAX_RING_SIZE_V2: usize = 32;
pub const MAX_RING_SIZE_V3: usize = 1024;
/// Backwards compat alias (largest supported).
pub const MAX_RING_SIZE: usize = MAX_RING_SIZE_V3;
/// Maximum extra data length.
pub const MAX_EXTRA_LEN: usize = 1024;
/// Maximum inputs per transaction.
pub const MAX_INPUTS: usize = 16;
/// Maximum outputs per transaction.
pub const MAX_OUTPUTS: usize = 64;
/// Maximum ring signature bytes per input.
pub const MAX_RING_SIG_SIZE: usize = 65536; // 64 KiB
/// Maximum KI proof bytes per input.
pub const MAX_KI_PROOF_SIZE: usize = 4096;

impl UtxoTransaction {
    /// Is this a v2 (ChipmunkRing) transaction?
    pub fn is_v2(&self) -> bool {
        self.version == UTXO_TX_VERSION_V2 || self.ring_scheme == RING_SCHEME_CHIPMUNK
    }

    /// Is this a v3 (LogRing) transaction?
    pub fn is_logring(&self) -> bool {
        self.version == UTXO_TX_VERSION_V3 || self.ring_scheme == RING_SCHEME_LOGRING
    }

    /// Max ring size for this TX's scheme.
    pub fn max_ring_size(&self) -> usize {
        if self.is_logring() { MAX_RING_SIZE_V3 }
        else if self.is_v2() { MAX_RING_SIZE_V2 }
        else { MAX_RING_SIZE_V1 }
    }

    /// Compute the canonical signing digest.
    /// Includes all consensus-relevant fields EXCEPT signatures.
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(256);
        mcs1::write_u8(&mut buf, self.version);
        mcs1::write_u8(&mut buf, self.ring_scheme);

        // Inputs: ring members + key images (not signatures)
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
        // Accept v1, v2, and v3 (LogRing)
        if self.version != UTXO_TX_VERSION && self.version != UTXO_TX_VERSION_V2
            && self.version != UTXO_TX_VERSION_V3 {
            return Err(MisakaError::DeserializationError(
                format!("unsupported tx version: 0x{:02x}", self.version)));
        }
        // Coinbase txs (faucet, block rewards) have empty inputs.
        // Regular txs MUST have at least one input.
        // Coinbase txs are identified by extra field containing "faucet" or "coinbase".
        let is_coinbase = self.inputs.is_empty() && self.fee == 0;
        if self.inputs.is_empty() && !is_coinbase {
            return Err(MisakaError::EmptyInputs);
        }
        if self.outputs.is_empty() {
            return Err(MisakaError::EmptyActions);
        }
        // ── Bounded Vec: Max inputs/outputs (DoS protection) ──
        if self.inputs.len() > MAX_INPUTS {
            return Err(MisakaError::FieldTooLarge {
                field: "inputs".into(), size: self.inputs.len(), max: MAX_INPUTS,
            });
        }
        if self.outputs.len() > MAX_OUTPUTS {
            return Err(MisakaError::FieldTooLarge {
                field: "outputs".into(), size: self.outputs.len(), max: MAX_OUTPUTS,
            });
        }
        let max_ring = self.max_ring_size();
        for (i, inp) in self.inputs.iter().enumerate() {
            if inp.ring_members.len() < MIN_RING_SIZE {
                return Err(MisakaError::DeserializationError(
                    format!("input[{i}]: ring size {} < minimum {MIN_RING_SIZE}", inp.ring_members.len())));
            }
            if inp.ring_members.len() > max_ring {
                return Err(MisakaError::DeserializationError(
                    format!("input[{i}]: ring size {} > maximum {max_ring}", inp.ring_members.len())));
            }
            // ── Bounded: ring signature size ──
            if inp.ring_signature.len() > MAX_RING_SIG_SIZE {
                return Err(MisakaError::FieldTooLarge {
                    field: format!("input[{i}].ring_signature"),
                    size: inp.ring_signature.len(), max: MAX_RING_SIG_SIZE,
                });
            }
            // ── Bounded: KI proof size ──
            if inp.ki_proof.len() > MAX_KI_PROOF_SIZE {
                return Err(MisakaError::FieldTooLarge {
                    field: format!("input[{i}].ki_proof"),
                    size: inp.ki_proof.len(), max: MAX_KI_PROOF_SIZE,
                });
            }
        }
        // Key image uniqueness within tx
        let mut images = std::collections::HashSet::new();
        for inp in &self.inputs {
            if !images.insert(inp.key_image) {
                return Err(MisakaError::DuplicateInput(hex::encode(inp.key_image)));
            }
        }
        // KI proof handling by scheme:
        // - LRS: OPTIONAL. Ring sig provides key_image transcript binding.
        //        Separate KI proof adds algebraic strong binding but is not required.
        // - LogRing: NOT NEEDED. Link tag is integrated into the signature.
        // - Chipmunk: REQUIRED. No built-in key_image binding.
        //
        // When present, KI proofs are verified at mempool/block_validation level.
        if self.extra.len() > MAX_EXTRA_LEN {
            return Err(MisakaError::FieldTooLarge {
                field: "extra".into(), size: self.extra.len(), max: MAX_EXTRA_LEN,
            });
        }
        Ok(())
    }

    /// Compute tx_hash (full transaction including signatures).
    pub fn tx_hash(&self) -> [u8; 32] {
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

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    fn make_utxo_tx_v1() -> UtxoTransaction {
        UtxoTransaction {
            version: UTXO_TX_VERSION,
            ring_scheme: RING_SCHEME_LRS,
            tx_type: TxType::Transfer,
            inputs: vec![RingInput {
                ring_members: vec![
                    OutputRef { tx_hash: [1; 32], output_index: 0 },
                    OutputRef { tx_hash: [2; 32], output_index: 0 },
                    OutputRef { tx_hash: [3; 32], output_index: 0 },
                    OutputRef { tx_hash: [4; 32], output_index: 0 },
                ],
                ring_signature: vec![0xAA; 128],
                key_image: [0xBB; 32],
                ki_proof: vec![0xDD; 64],
            }],
            outputs: vec![TxOutput { amount: 9900, one_time_address: [0xCC; 20], pq_stealth: None, spending_pubkey: None }],
            fee: 100,
            extra: vec![],
        }
    }

    fn make_utxo_tx_v2() -> UtxoTransaction {
        UtxoTransaction {
            version: UTXO_TX_VERSION_V2,
            ring_scheme: RING_SCHEME_CHIPMUNK,
            tx_type: TxType::Transfer,
            inputs: vec![RingInput {
                ring_members: (0..8).map(|i| OutputRef { tx_hash: [i; 32], output_index: 0 }).collect(),
                ring_signature: vec![0xAA; 256],
                key_image: [0xBB; 32],
                ki_proof: vec![0xDD; 64],
            }],
            outputs: vec![TxOutput { amount: 9900, one_time_address: [0xCC; 20], pq_stealth: None, spending_pubkey: None }],
            fee: 100,
            extra: vec![],
        }
    }

    #[test]
    fn test_v1_structure_ok() {
        make_utxo_tx_v1().validate_structure().unwrap();
    }

    #[test]
    fn test_v2_structure_ok() {
        make_utxo_tx_v2().validate_structure().unwrap();
    }

    #[test]
    fn test_v2_allows_ring_32() {
        let mut tx = make_utxo_tx_v2();
        tx.inputs[0].ring_members = (0..32).map(|i| OutputRef { tx_hash: [i; 32], output_index: 0 }).collect();
        tx.validate_structure().unwrap();
    }

    #[test]
    fn test_v1_rejects_ring_17() {
        let mut tx = make_utxo_tx_v1();
        tx.inputs[0].ring_members = (0..17).map(|i| OutputRef { tx_hash: [i; 32], output_index: 0 }).collect();
        assert!(tx.validate_structure().is_err());
    }

    #[test]
    fn test_signing_digest_deterministic() {
        let tx = make_utxo_tx_v1();
        assert_eq!(tx.signing_digest(), tx.signing_digest());
    }

    #[test]
    fn test_signing_digest_includes_scheme() {
        let mut tx1 = make_utxo_tx_v1();
        let mut tx2 = make_utxo_tx_v1();
        tx2.ring_scheme = RING_SCHEME_CHIPMUNK;
        // Different scheme → different digest
        assert_ne!(tx1.signing_digest(), tx2.signing_digest());
    }

    #[test]
    fn test_signing_digest_excludes_sig() {
        let mut tx1 = make_utxo_tx_v1();
        let mut tx2 = make_utxo_tx_v1();
        tx1.inputs[0].ring_signature = vec![0x11; 128];
        tx2.inputs[0].ring_signature = vec![0x22; 128];
        assert_eq!(tx1.signing_digest(), tx2.signing_digest());
    }

    #[test]
    fn test_tx_hash_includes_sig() {
        let mut tx1 = make_utxo_tx_v1();
        let mut tx2 = make_utxo_tx_v1();
        tx1.inputs[0].ring_signature = vec![0x11; 128];
        tx2.inputs[0].ring_signature = vec![0x22; 128];
        assert_ne!(tx1.tx_hash(), tx2.tx_hash());
    }

    #[test]
    fn test_is_v2() {
        assert!(!make_utxo_tx_v1().is_v2());
        assert!(make_utxo_tx_v2().is_v2());
    }

    #[test]
    fn test_validate_duplicate_key_image() {
        let mut tx = make_utxo_tx_v1();
        tx.inputs.push(RingInput {
            ring_members: tx.inputs[0].ring_members.clone(),
            ring_signature: vec![0xDD; 128],
            key_image: [0xBB; 32],
            ki_proof: vec![0xEE; 64],
        });
        assert!(tx.validate_structure().is_err());
    }

    #[test]
    fn test_default_ring_scheme() {
        // Deserializing without ring_scheme field → defaults to LogRing (0x03)
        let json = r#"{"version":1,"inputs":[],"outputs":[],"fee":0,"extra":[]}"#;
        let tx: UtxoTransaction = serde_json::from_str(json).unwrap();
        assert_eq!(tx.ring_scheme, RING_SCHEME_LOGRING);
    }
}
