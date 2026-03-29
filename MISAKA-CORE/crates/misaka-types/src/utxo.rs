//! UTXO Transaction Model — privacy-first PoS.
//!
//! - Sender anonymity: lattice ZKP proofs (LRS-v1, LogRing-v1) or ZKP (UnifiedZKP-v1)
//! - Receiver anonymity: ML-KEM-768 stealth outputs (v1 or v2)
//! - Amount: PUBLIC (v1-v3) or CONFIDENTIAL (v4 Q-DAG-CT)
//! - Key images / nullifiers: double-spend prevention

use crate::error::MisakaError;
use crate::mcs1;
use crate::stealth::PqStealthData;
use sha3::{Digest as Sha3Digest, Sha3_256};

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
pub struct TxInput {
    /// Ring member references (includes the real spend + decoys).
    pub utxo_refs: Vec<OutputRef>,
    /// Lattice ZKP proof bytes (scheme-dependent).
    pub proof: Vec<u8>,
    /// Key image for double-spend detection (32 bytes, deterministic from sk).
    pub key_image: [u8; 32],
    /// Key image correctness proof bytes (Σ-protocol). REQUIRED.
    pub ki_proof: Vec<u8>,
}

/// Transaction output with public amount and optional stealth data.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TxOutput {
    pub amount: u64,
    /// One-time address.
    /// v4+ (Q-DAG-CT): full 32 bytes for PQ collision resistance.
    /// v3 and below: upper 12 bytes are zero-padded on deserialization
    /// from the legacy 20-byte wire format.
    pub one_time_address: [u8; 32],
    pub pq_stealth: Option<PqStealthData>,
    /// Spending public key (lattice polynomial, serialized).
    /// REQUIRED for new outputs to be spendable in future transactions.
    /// Ring member resolution uses this to verify lattice ZKP proofs.
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
    /// Stake deposit: locks MISAKA into the validator set.
    /// Input: UTXOs to stake. Output[0]: locked stake receipt.
    StakeDeposit,
    /// Stake withdrawal: unlocks MISAKA after unbonding period.
    /// Input: stake receipt UTXO. Output[0]: unlocked MISAKA.
    StakeWithdraw,
    /// Slash evidence: submits proof of validator misbehavior.
    /// Input: none (evidence is in `extra` field). Output: slash reward to submitter.
    SlashEvidence,
    /// Public (transparent) transfer — sender is identifiable, no ring anonymity.
    /// anonymity_set_size=1 (real UTXO only), ML-DSA direct signature instead of ring sig.
    /// Key image / nullifier still required for double-spend prevention.
    TransparentTransfer,
    /// Shield deposit: transparent UTXO → shielded note pool.
    /// Deposit amount and fee are public. Note commitment added to commitment tree.
    ShieldDeposit,
    /// Shielded transfer: note consumption and creation within shielded pool.
    /// ZK proof required. Amount, sender, recipient are hidden.
    ShieldedTransfer,
    /// Shield withdraw: shielded note → transparent address.
    /// Withdraw amount and recipient are public.
    ShieldWithdraw,
}

impl Default for TxType {
    fn default() -> Self {
        TxType::Transfer
    }
}

impl TxType {
    /// Stable binary tag used by signing digests and wire encoding.
    pub fn to_byte(self) -> u8 {
        match self {
            TxType::Transfer => 0,
            TxType::Coinbase => 1,
            TxType::Faucet => 2,
            TxType::StakeDeposit => 3,
            TxType::StakeWithdraw => 4,
            TxType::SlashEvidence => 5,
            TxType::TransparentTransfer => 6,
            TxType::ShieldDeposit => 7,
            TxType::ShieldedTransfer => 8,
            TxType::ShieldWithdraw => 9,
        }
    }

    pub fn from_byte(v: u8) -> Option<Self> {
        match v {
            0 => Some(TxType::Transfer),
            1 => Some(TxType::Coinbase),
            2 => Some(TxType::Faucet),
            3 => Some(TxType::StakeDeposit),
            4 => Some(TxType::StakeWithdraw),
            5 => Some(TxType::SlashEvidence),
            6 => Some(TxType::TransparentTransfer),
            7 => Some(TxType::ShieldDeposit),
            8 => Some(TxType::ShieldedTransfer),
            9 => Some(TxType::ShieldWithdraw),
            _ => None,
        }
    }

    /// Whether this tx type requires stake-related validation.
    pub fn is_staking(&self) -> bool {
        matches!(self, TxType::StakeDeposit | TxType::StakeWithdraw)
    }

    /// Whether this is a transparent (public, non-anonymous) transfer.
    pub fn is_transparent(&self) -> bool {
        matches!(self, TxType::TransparentTransfer)
    }

    /// Whether this is a shielded pool operation.
    pub fn is_shielded(&self) -> bool {
        matches!(
            self,
            TxType::ShieldDeposit | TxType::ShieldedTransfer | TxType::ShieldWithdraw
        )
    }

    /// Whether this tx type requires shielded module validation.
    pub fn requires_shielded_module(&self) -> bool {
        self.is_shielded()
    }
}

/// Optional transaction-level zero-knowledge proof carrier.
///
/// This is intentionally opaque at the transaction-model layer. The actual
/// proof format is selected by higher-level code (for example, the current
/// STARK stub on the experimental ZK track).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ZeroKnowledgeProofCarrier {
    /// Backend tag aligned with privacy backend descriptors.
    pub backend_tag: u8,
    /// Opaque proof bytes.
    pub proof_bytes: Vec<u8>,
}

/// Complete UTXO transaction.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UtxoTransaction {
    /// Protocol version (0x01 = v1/LRS, 0x03 = v3/LogRing, 0x10 = v4/Q-DAG-CT).
    pub version: u8,
    /// Lattice ZKP proof / ZKP scheme tag. Defaults to 0x10 (UnifiedZKP-v1).
    #[serde(default = "default_ring_scheme")]
    pub proof_scheme: u8,
    /// Transaction type — Transfer, Coinbase, Faucet, StakeDeposit, etc.
    #[serde(default)]
    pub tx_type: TxType,
    /// Ring-signed inputs.
    pub inputs: Vec<TxInput>,
    /// Outputs.
    pub outputs: Vec<TxOutput>,
    /// Transaction fee.
    pub fee: u64,
    /// Extra data (memo, etc.).
    pub extra: Vec<u8>,
    /// Optional transaction-level zero-knowledge proof carrier.
    #[serde(default)]
    pub zk_proof: Option<ZeroKnowledgeProofCarrier>,
}

fn default_ring_scheme() -> u8 {
    0x10
} // UnifiedZKP-v1 is the system default (v4)

// ── Protocol Versions ──

/// DEPRECATED: Legacy LRS version.
pub const UTXO_TX_VERSION: u8 = 0x01;
/// DEPRECATED: LogRing version.
pub const UTXO_TX_VERSION_V3: u8 = 0x03;
/// Q-DAG-CT version (confidential transactions with unified ZKP).
pub const UTXO_TX_VERSION_V4: u8 = 0x10;

/// Ring scheme tags.
pub const PROOF_SCHEME_DEPRECATED_LRS: u8 = 0x01;
/// LogRing O(log n) — production lattice ZKP proof scheme.
pub const PROOF_SCHEME_DEPRECATED_LOGRING: u8 = 0x03;
/// Transparent (ML-DSA direct signature, no ring anonymity).
pub const PROOF_SCHEME_TRANSPARENT: u8 = 0x20;

/// Minimum ring size (all schemes).
/// v10: Ring signatures purged. All inputs use direct UTXO reference.
pub const MIN_ANONYMITY_SET: usize = 1;
/// Maximum ring size (v1/LRS: 16, v3/LogRing: 1024).
pub const MAX_ANONYMITY_SET_LEGACY: usize = 16;
pub const MAX_ANONYMITY_SET: usize = 1024;
/// Backwards compat alias (largest supported).
pub const MAX_ANONYMITY_SET_CURRENT: usize = MAX_ANONYMITY_SET;
/// Maximum extra data length.
pub const MAX_EXTRA_LEN: usize = 1024;
/// Maximum inputs per transaction.
pub const MAX_INPUTS: usize = 16;
/// Maximum outputs per transaction.
pub const MAX_OUTPUTS: usize = 64;
/// Maximum lattice ZKP proof bytes per input.
pub const MAX_PROOF_SIZE: usize = 65536; // 64 KiB
/// Maximum KI proof bytes per input.
pub const MAX_KI_PROOF_SIZE: usize = 4096;
/// Maximum optional ZK proof bytes per transaction.
pub const MAX_ZK_PROOF_SIZE: usize = 1_048_576; // 1 MiB

impl UtxoTransaction {
    /// Is this a v3 (LogRing) transaction?
    pub fn is_legacy_scheme(&self) -> bool {
        self.version == UTXO_TX_VERSION_V3 || self.proof_scheme == PROOF_SCHEME_DEPRECATED_LOGRING
    }

    /// Is this a v4 (Q-DAG-CT / UnifiedZKP) transaction?
    pub fn is_qdag(&self) -> bool {
        self.version == UTXO_TX_VERSION_V4
    }

    /// Is this a transparent (public) transfer?
    pub fn is_transparent(&self) -> bool {
        self.tx_type.is_transparent() || self.proof_scheme == PROOF_SCHEME_TRANSPARENT
    }

    /// Max ring size for this TX's scheme.
    pub fn max_anonymity_set(&self) -> usize {
        if self.is_legacy_scheme() || self.is_qdag() {
            MAX_ANONYMITY_SET
        } else {
            MAX_ANONYMITY_SET_LEGACY
        }
    }

    /// Compute the canonical signing digest.
    /// Includes all consensus-relevant fields EXCEPT signatures.
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(256);
        mcs1::write_u8(&mut buf, self.version);
        mcs1::write_u8(&mut buf, self.proof_scheme);
        mcs1::write_u8(&mut buf, self.tx_type.to_byte());

        // Inputs: ring members + key images (not signatures)
        mcs1::write_u32(&mut buf, self.inputs.len() as u32);
        for inp in &self.inputs {
            mcs1::write_u32(&mut buf, inp.utxo_refs.len() as u32);
            for member in &inp.utxo_refs {
                member.mcs1_encode(&mut buf);
            }
            mcs1::write_fixed(&mut buf, &inp.key_image);
        }

        // Outputs
        mcs1::write_u32(&mut buf, self.outputs.len() as u32);
        for out in &self.outputs {
            mcs1::write_u64(&mut buf, out.amount);
            // v4+ (Q-DAG-CT): full 32-byte one_time_address in digest
            // v1/v2/v3: legacy 20-byte one_time_address (backward compat)
            if self.version >= UTXO_TX_VERSION_V4 {
                mcs1::write_fixed(&mut buf, &out.one_time_address);
            } else {
                mcs1::write_fixed(&mut buf, &out.one_time_address);
            }
            match &out.pq_stealth {
                Some(sd) => {
                    mcs1::write_u8(&mut buf, 1);
                    sd.mcs1_encode(&mut buf);
                }
                None => {
                    mcs1::write_u8(&mut buf, 0);
                }
            }
            match &out.spending_pubkey {
                Some(pk) => {
                    mcs1::write_u8(&mut buf, 1);
                    mcs1::write_bytes(&mut buf, pk);
                }
                None => {
                    mcs1::write_u8(&mut buf, 0);
                }
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
        // Accept v1 (LRS), v3 (LogRing), and v4 (Q-DAG-CT).
        if self.version != UTXO_TX_VERSION
            && self.version != UTXO_TX_VERSION_V3
            && self.version != UTXO_TX_VERSION_V4
        {
            return Err(MisakaError::DeserializationError(format!(
                "unsupported tx version: 0x{:02x}",
                self.version
            )));
        }
        match self.tx_type {
            TxType::Transfer => {
                if self.inputs.is_empty() {
                    return Err(MisakaError::EmptyInputs);
                }
            }
            TxType::TransparentTransfer => {
                if self.inputs.is_empty() {
                    return Err(MisakaError::EmptyInputs);
                }
                // Transparent transfers MUST have anonymity_set_size=1 (no decoys).
                for (i, inp) in self.inputs.iter().enumerate() {
                    if inp.utxo_refs.len() != 1 {
                        return Err(MisakaError::DeserializationError(format!(
                            "input[{i}]: TransparentTransfer requires anonymity_set_size=1, got {}",
                            inp.utxo_refs.len()
                        )));
                    }
                }
            }
            TxType::StakeDeposit | TxType::StakeWithdraw => {
                if self.inputs.is_empty() {
                    return Err(MisakaError::DeserializationError(format!(
                        "{:?} tx must have at least one input",
                        self.tx_type
                    )));
                }
            }
            TxType::Coinbase | TxType::Faucet => {
                if !self.inputs.is_empty() {
                    return Err(MisakaError::DeserializationError(format!(
                        "{:?} tx must have no inputs",
                        self.tx_type
                    )));
                }
                if self.fee != 0 {
                    return Err(MisakaError::DeserializationError(format!(
                        "{:?} tx must have zero fee",
                        self.tx_type
                    )));
                }
            }
            TxType::SlashEvidence => {
                if !self.inputs.is_empty() {
                    return Err(MisakaError::DeserializationError(
                        "SlashEvidence tx must have no inputs".into(),
                    ));
                }
                if self.fee != 0 {
                    return Err(MisakaError::DeserializationError(
                        "SlashEvidence tx must have zero fee".into(),
                    ));
                }
                if self.extra.is_empty() {
                    return Err(MisakaError::DeserializationError(
                        "SlashEvidence tx must carry evidence in extra".into(),
                    ));
                }
            }
            // ── Shielded pool operations ──
            // Structural validation here is minimal; full ZK proof verification
            // happens in the shielded module (misaka-shielded).
            TxType::ShieldDeposit => {
                // P1: Deposit burns transparent balance → shielded note.
                // The "from" address and amount are tracked in the serialized
                // ShieldDepositTx inside tx.extra. UTXO ring inputs are not used.
            }
            TxType::ShieldedTransfer => {
                // Fully shielded: no transparent UTXO inputs.
                // ZK proof in `extra` is validated by the shielded module.
                if !self.inputs.is_empty() {
                    return Err(MisakaError::DeserializationError(
                        "ShieldedTransfer tx must have no transparent inputs".into(),
                    ));
                }
            }
            TxType::ShieldWithdraw => {
                // Withdraw: shielded note → transparent output.
                // No transparent UTXO inputs; ZK proof in `extra`.
                if !self.inputs.is_empty() {
                    return Err(MisakaError::DeserializationError(
                        "ShieldWithdraw tx must have no transparent inputs".into(),
                    ));
                }
            }
        }
        // ShieldedTransfer/ShieldDeposit may have no transparent outputs
        if self.outputs.is_empty() && !matches!(self.tx_type, TxType::ShieldedTransfer | TxType::ShieldDeposit) {
            return Err(MisakaError::EmptyActions);
        }
        // ── Bounded Vec: Max inputs/outputs (DoS protection) ──
        if self.inputs.len() > MAX_INPUTS {
            return Err(MisakaError::FieldTooLarge {
                field: "inputs".into(),
                size: self.inputs.len(),
                max: MAX_INPUTS,
            });
        }
        if self.outputs.len() > MAX_OUTPUTS {
            return Err(MisakaError::FieldTooLarge {
                field: "outputs".into(),
                size: self.outputs.len(),
                max: MAX_OUTPUTS,
            });
        }
        let max_anon_set = self.max_anonymity_set();
        // v10: Ring signatures purged. All inputs use direct UTXO reference.
        let min_anon_set = 1;
        for (i, inp) in self.inputs.iter().enumerate() {
            if inp.utxo_refs.len() < min_anon_set {
                return Err(MisakaError::DeserializationError(format!(
                    "input[{i}]: ring size {} < minimum {min_anon_set}",
                    inp.utxo_refs.len()
                )));
            }
            if inp.utxo_refs.len() > max_anon_set {
                return Err(MisakaError::DeserializationError(format!(
                    "input[{i}]: ring size {} > maximum {max_anon_set}",
                    inp.utxo_refs.len()
                )));
            }
            // ── Bounded: lattice ZKP proof size ──
            if inp.proof.len() > MAX_PROOF_SIZE {
                return Err(MisakaError::FieldTooLarge {
                    field: format!("input[{i}].proof"),
                    size: inp.proof.len(),
                    max: MAX_PROOF_SIZE,
                });
            }
            // ── Bounded: KI proof size ──
            if inp.ki_proof.len() > MAX_KI_PROOF_SIZE {
                return Err(MisakaError::FieldTooLarge {
                    field: format!("input[{i}].ki_proof"),
                    size: inp.ki_proof.len(),
                    max: MAX_KI_PROOF_SIZE,
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
        //
        // When present, KI proofs are verified at mempool/block_validation level.
        if self.extra.len() > MAX_EXTRA_LEN {
            return Err(MisakaError::FieldTooLarge {
                field: "extra".into(),
                size: self.extra.len(),
                max: MAX_EXTRA_LEN,
            });
        }
        if let Some(proof) = &self.zk_proof {
            if proof.backend_tag == 0 {
                return Err(MisakaError::DeserializationError(
                    "zk proof carrier backend_tag must be non-zero".into(),
                ));
            }
            if proof.proof_bytes.is_empty() {
                return Err(MisakaError::DeserializationError(
                    "zk proof carrier must not be empty".into(),
                ));
            }
            if proof.proof_bytes.len() > MAX_ZK_PROOF_SIZE {
                return Err(MisakaError::FieldTooLarge {
                    field: "zk_proof.proof_bytes".into(),
                    size: proof.proof_bytes.len(),
                    max: MAX_ZK_PROOF_SIZE,
                });
            }
        }
        Ok(())
    }

    /// Compute tx hash without the optional ZK proof carrier.
    ///
    /// This is the stable binding hash for statement/proof generation on the
    /// explicit zero-knowledge path, where the proof bytes themselves are not
    /// allowed to perturb the statement being proven.
    pub fn tx_hash_without_zk_proof(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(&self.signing_digest());
        for inp in &self.inputs {
            h.update(&inp.proof);
        }
        h.finalize().into()
    }

    /// Compute tx_hash (full transaction including signatures and optional ZK proof).
    pub fn tx_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(&self.signing_digest());
        for inp in &self.inputs {
            h.update(&inp.proof);
        }
        if let Some(proof) = &self.zk_proof {
            h.update([0x5Au8]);
            h.update([proof.backend_tag]);
            h.update((proof.proof_bytes.len() as u32).to_le_bytes());
            h.update(&proof.proof_bytes);
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
            proof_scheme: PROOF_SCHEME_DEPRECATED_LRS,
            tx_type: TxType::Transfer,
            inputs: vec![TxInput {
                utxo_refs: vec![
                    OutputRef {
                        tx_hash: [1; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [2; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [3; 32],
                        output_index: 0,
                    },
                    OutputRef {
                        tx_hash: [4; 32],
                        output_index: 0,
                    },
                ],
                proof: vec![0xAA; 128],
                key_image: [0xBB; 32],
                ki_proof: vec![0xDD; 64],
            }],
            outputs: vec![TxOutput {
                amount: 9900,
                one_time_address: [0xCC; 32],
                pq_stealth: None,
                spending_pubkey: None,
            }],
            fee: 100,
            extra: vec![],
            zk_proof: None,
        }
    }

    #[test]
    fn test_v1_structure_ok() {
        make_utxo_tx_v1().validate_structure().unwrap();
    }

    #[test]
    fn test_v1_rejects_ring_17() {
        let mut tx = make_utxo_tx_v1();
        tx.inputs[0].utxo_refs = (0..17)
            .map(|i| OutputRef {
                tx_hash: [i; 32],
                output_index: 0,
            })
            .collect();
        assert!(tx.validate_structure().is_err());
    }

    #[test]
    fn test_signing_digest_deterministic() {
        let tx = make_utxo_tx_v1();
        assert_eq!(tx.signing_digest(), tx.signing_digest());
    }

    #[test]
    fn test_signing_digest_includes_scheme() {
        let tx1 = make_utxo_tx_v1();
        let mut tx2 = make_utxo_tx_v1();
        tx2.proof_scheme = PROOF_SCHEME_DEPRECATED_LOGRING;
        // Different scheme → different digest
        assert_ne!(tx1.signing_digest(), tx2.signing_digest());
    }

    #[test]
    fn test_signing_digest_includes_tx_type() {
        let tx1 = make_utxo_tx_v1();
        let mut tx2 = make_utxo_tx_v1();
        tx2.tx_type = TxType::Faucet;
        assert_ne!(tx1.signing_digest(), tx2.signing_digest());
        assert_ne!(tx1.tx_hash(), tx2.tx_hash());
    }

    #[test]
    fn test_signing_digest_includes_spending_pubkey() {
        let tx1 = make_utxo_tx_v1();
        let mut tx2 = make_utxo_tx_v1();
        tx2.outputs[0].spending_pubkey = Some(vec![0x42; 48]);
        assert_ne!(tx1.signing_digest(), tx2.signing_digest());
        assert_ne!(tx1.tx_hash(), tx2.tx_hash());
    }

    #[test]
    fn test_signing_digest_excludes_sig() {
        let mut tx1 = make_utxo_tx_v1();
        let mut tx2 = make_utxo_tx_v1();
        tx1.inputs[0].proof = vec![0x11; 128];
        tx2.inputs[0].proof = vec![0x22; 128];
        assert_eq!(tx1.signing_digest(), tx2.signing_digest());
    }

    #[test]
    fn test_tx_hash_includes_sig() {
        let mut tx1 = make_utxo_tx_v1();
        let mut tx2 = make_utxo_tx_v1();
        tx1.inputs[0].proof = vec![0x11; 128];
        tx2.inputs[0].proof = vec![0x22; 128];
        assert_ne!(tx1.tx_hash(), tx2.tx_hash());
    }

    #[test]
    fn test_signing_digest_excludes_zk_proof() {
        let mut tx1 = make_utxo_tx_v1();
        let mut tx2 = make_utxo_tx_v1();
        tx1.zk_proof = Some(ZeroKnowledgeProofCarrier {
            backend_tag: 0xF1,
            proof_bytes: vec![0x11; 32],
        });
        tx2.zk_proof = Some(ZeroKnowledgeProofCarrier {
            backend_tag: 0xF1,
            proof_bytes: vec![0x22; 32],
        });
        assert_eq!(tx1.signing_digest(), tx2.signing_digest());
    }

    #[test]
    fn test_tx_hash_includes_zk_proof() {
        let mut tx1 = make_utxo_tx_v1();
        let mut tx2 = make_utxo_tx_v1();
        tx1.zk_proof = Some(ZeroKnowledgeProofCarrier {
            backend_tag: 0xF1,
            proof_bytes: vec![0x11; 32],
        });
        tx2.zk_proof = Some(ZeroKnowledgeProofCarrier {
            backend_tag: 0xF1,
            proof_bytes: vec![0x22; 32],
        });
        assert_ne!(tx1.tx_hash(), tx2.tx_hash());
    }

    #[test]
    fn test_tx_hash_without_zk_proof_ignores_zk_carrier() {
        let mut tx1 = make_utxo_tx_v1();
        let mut tx2 = make_utxo_tx_v1();
        tx1.zk_proof = Some(ZeroKnowledgeProofCarrier {
            backend_tag: 0xF1,
            proof_bytes: vec![0x11; 32],
        });
        tx2.zk_proof = Some(ZeroKnowledgeProofCarrier {
            backend_tag: 0xF1,
            proof_bytes: vec![0x22; 32],
        });
        assert_eq!(
            tx1.tx_hash_without_zk_proof(),
            tx2.tx_hash_without_zk_proof()
        );
    }

    #[test]
    fn test_validate_duplicate_key_image() {
        let mut tx = make_utxo_tx_v1();
        tx.inputs.push(TxInput {
            utxo_refs: tx.inputs[0].utxo_refs.clone(),
            proof: vec![0xDD; 128],
            key_image: [0xBB; 32],
            ki_proof: vec![0xEE; 64],
        });
        assert!(tx.validate_structure().is_err());
    }

    #[test]
    fn test_default_ring_scheme() {
        // Deserializing without proof_scheme field → defaults to UnifiedZKP-v1 (0x10)
        let json = r#"{"version":1,"inputs":[],"outputs":[],"fee":0,"extra":[]}"#;
        let tx: UtxoTransaction = serde_json::from_str(json).unwrap();
        assert_eq!(tx.proof_scheme, default_ring_scheme());
    }

    #[test]
    fn test_transfer_requires_inputs() {
        let tx = UtxoTransaction {
            version: UTXO_TX_VERSION_V3,
            proof_scheme: PROOF_SCHEME_DEPRECATED_LOGRING,
            tx_type: TxType::Transfer,
            inputs: vec![],
            outputs: vec![TxOutput {
                amount: 1,
                one_time_address: [0x11; 32],
                pq_stealth: None,
                spending_pubkey: None,
            }],
            fee: 0,
            extra: vec![],
            zk_proof: None,
        };
        assert!(tx.validate_structure().is_err());
    }

    #[test]
    fn test_faucet_rejects_non_zero_fee() {
        let tx = UtxoTransaction {
            version: UTXO_TX_VERSION_V3,
            proof_scheme: PROOF_SCHEME_DEPRECATED_LOGRING,
            tx_type: TxType::Faucet,
            inputs: vec![],
            outputs: vec![TxOutput {
                amount: 1,
                one_time_address: [0x11; 32],
                pq_stealth: None,
                spending_pubkey: None,
            }],
            fee: 1,
            extra: vec![],
            zk_proof: None,
        };
        assert!(tx.validate_structure().is_err());
    }

    #[test]
    fn test_stake_deposit_requires_inputs() {
        let tx = UtxoTransaction {
            version: UTXO_TX_VERSION_V4,
            proof_scheme: default_ring_scheme(),
            tx_type: TxType::StakeDeposit,
            inputs: vec![],
            outputs: vec![TxOutput {
                amount: 1,
                one_time_address: [0x11; 32],
                pq_stealth: None,
                spending_pubkey: Some(vec![0x22; 32]),
            }],
            fee: 0,
            extra: vec![],
            zk_proof: None,
        };
        assert!(tx.validate_structure().is_err());
    }

    #[test]
    fn test_stake_withdraw_requires_inputs() {
        let tx = UtxoTransaction {
            version: UTXO_TX_VERSION_V4,
            proof_scheme: default_ring_scheme(),
            tx_type: TxType::StakeWithdraw,
            inputs: vec![],
            outputs: vec![TxOutput {
                amount: 1,
                one_time_address: [0x11; 32],
                pq_stealth: None,
                spending_pubkey: Some(vec![0x22; 32]),
            }],
            fee: 0,
            extra: vec![],
            zk_proof: None,
        };
        assert!(tx.validate_structure().is_err());
    }

    #[test]
    fn test_slash_evidence_requires_extra_and_no_inputs() {
        let mut tx = UtxoTransaction {
            version: UTXO_TX_VERSION_V4,
            proof_scheme: default_ring_scheme(),
            tx_type: TxType::SlashEvidence,
            inputs: vec![],
            outputs: vec![TxOutput {
                amount: 1,
                one_time_address: [0x11; 32],
                pq_stealth: None,
                spending_pubkey: Some(vec![0x22; 32]),
            }],
            fee: 0,
            extra: vec![],
            zk_proof: None,
        };
        assert!(tx.validate_structure().is_err());

        tx.extra = vec![0xAA; 8];
        tx.inputs.push(TxInput {
            utxo_refs: vec![
                OutputRef {
                    tx_hash: [1; 32],
                    output_index: 0,
                },
                OutputRef {
                    tx_hash: [2; 32],
                    output_index: 0,
                },
                OutputRef {
                    tx_hash: [3; 32],
                    output_index: 0,
                },
                OutputRef {
                    tx_hash: [4; 32],
                    output_index: 0,
                },
            ],
            proof: vec![0xBB; 128],
            key_image: [0xCC; 32],
            ki_proof: vec![0xDD; 64],
        });
        assert!(tx.validate_structure().is_err());
    }

    #[test]
    fn test_validate_rejects_empty_zk_proof() {
        let mut tx = make_utxo_tx_v1();
        tx.zk_proof = Some(ZeroKnowledgeProofCarrier {
            backend_tag: 0xF1,
            proof_bytes: vec![],
        });
        assert!(tx.validate_structure().is_err());
    }
}
