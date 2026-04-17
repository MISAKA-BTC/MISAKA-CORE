//! UTXO Transaction Model — transparent PoS.
//!
//! Phase 2c-B: privacy layer fully removed. All transfers are transparent
//! with ML-DSA-65 direct signatures.

use crate::error::MisakaError;
use crate::mcs1;
use borsh::{BorshDeserialize, BorshSerialize};
// Phase 2c-B: privacy imports removed.
use sha3::{Digest as Sha3Digest, Sha3_256};

/// Reference to a previous output (UTXO pointer).
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
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

/// Transaction input — spends a UTXO with ML-DSA-65 signature.
///
/// Phase 2c-B: ring fields deleted.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, BorshSerialize, BorshDeserialize)]
pub struct TxInput {
    /// UTXO references being spent.
    pub utxo_refs: Vec<OutputRef>,
    /// ML-DSA-65 signature bytes (3309 bytes).
    pub proof: Vec<u8>,
}

/// Transaction output — amount + recipient address hash.
///
/// Phase 2c-B: privacy fields deleted. Uses `address` directly.
/// Phase 3 will migrate to P2PKH (script_pubkey_hash: [u8; 32]).
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct TxOutput {
    pub amount: u64,
    /// Recipient address (32 bytes). Phase 3 replaces with script_pubkey_hash.
    #[serde(default)]
    pub address: [u8; 32],
    /// Spending public key (ML-DSA-65, 1952 bytes). REQUIRED for spendability.
    #[serde(default)]
    pub spending_pubkey: Option<Vec<u8>>,
}

/// Transaction type — explicit categorization for consensus validation.
///
/// Replaces the implicit "inputs empty && fee == 0" heuristic for Coinbase
/// detection, eliminating a class of potential exploits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TxType {
    /// System emission / block reward transaction (no inputs, validator receives reward).
    /// Previously named "Coinbase" — renamed in Phase 3 (§4.3).
    #[default]
    SystemEmission,
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
    /// Phase 2c-B: transparent only. ML-DSA-65 direct signature.
    TransparentTransfer,
}

impl TxType {
    /// Stable binary tag used by signing digests and wire encoding.
    pub fn to_byte(self) -> u8 {
        match self {
            // Phase 2c-B: Transfer (0) deleted
            TxType::SystemEmission => 1,
            TxType::Faucet => 2,
            TxType::StakeDeposit => 3,
            TxType::StakeWithdraw => 4,
            TxType::SlashEvidence => 5,
            TxType::TransparentTransfer => 6,
        }
    }

    pub fn from_byte(v: u8) -> Option<Self> {
        match v {
            // Phase 2c-B: Transfer (0) deleted
            1 => Some(TxType::SystemEmission),
            2 => Some(TxType::Faucet),
            3 => Some(TxType::StakeDeposit),
            4 => Some(TxType::StakeWithdraw),
            5 => Some(TxType::SlashEvidence),
            6 => Some(TxType::TransparentTransfer),
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
}

impl BorshSerialize for TxType {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&[self.to_byte()])
    }
}

impl BorshDeserialize for TxType {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        Self::from_byte(buf[0]).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown TxType tag: {}", buf[0]),
            )
        })
    }
}

// Phase 2c-B: ZK proof carrier deleted.

/// Complete UTXO transaction.
///
/// Phase 2c-B: privacy fields deleted.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, BorshSerialize, BorshDeserialize)]
pub struct UtxoTransaction {
    /// Protocol version.
    pub version: u8,
    /// Transaction type.
    #[serde(default)]
    pub tx_type: TxType,
    /// Inputs (UTXO references + ML-DSA-65 signatures).
    pub inputs: Vec<TxInput>,
    /// Outputs.
    pub outputs: Vec<TxOutput>,
    /// Transaction fee.
    pub fee: u64,
    /// Extra data (memo, etc.).
    pub extra: Vec<u8>,
    /// §4.2 step 4: Block height after which this TX is invalid (0 = no expiry).
    /// Hard fork field — changes borsh wire format.
    #[serde(default)]
    pub expiry: u64,
}

// Phase 2c-B D4b: privacy constants deleted (version constants, anonymity set).

// ── Protocol Versions ──

/// Current version.
pub const UTXO_TX_VERSION: u8 = 0x02;

/// Maximum extra data length.
///
/// γ-1: bumped from 2048 to 8192 to accommodate the `ValidatorStakeTx`
/// wire envelope on `TxType::StakeDeposit / StakeWithdraw`. A Register
/// envelope alone is ~2.1 KiB (1952-byte ML-DSA-65 consensus_pubkey +
/// metadata + 24-byte magic). Other tx types are unaffected — the bound is
/// only an upper limit.
pub const MAX_EXTRA_LEN: usize = 8 * 1024;
/// Maximum inputs per transaction.
pub const MAX_INPUTS: usize = 16;
/// Maximum outputs per transaction.
pub const MAX_OUTPUTS: usize = 64;
/// Maximum ML-DSA-65 signature bytes per input.
pub const MAX_PROOF_SIZE: usize = 3309;

impl UtxoTransaction {
    /// Is this a transparent (public) transfer?
    pub fn is_transparent(&self) -> bool {
        self.tx_type.is_transparent()
    }

    // Phase 2c-B D3: signing_digest() and signing_digest_with_chain() DELETED.
    // Signature verification now uses TxSignablePayload + IntentMessage.
    /// Compute content hash for tx_hash() — proof-independent.
    ///
    /// Uses TxSignablePayload (which excludes proof/signature bytes) so that
    /// tx_hash is stable regardless of whether proof is filled or empty.
    fn tx_content_hash_legacy(&self) -> [u8; 32] {
        use crate::tx_signable::TxSignablePayload;
        let mut h = Sha3_256::new();
        h.update(b"MISAKA-TX-HASH:v2:");
        let payload = TxSignablePayload::from(self);
        h.update(&borsh::to_vec(&payload).expect("borsh encode signable payload"));
        h.finalize().into()
    }

    /// Structural validation (no crypto checks).
    ///
    /// Phase 2c-B: simplified after ring layer deletion.
    pub fn validate_structure(&self) -> Result<(), MisakaError> {
        if self.version != UTXO_TX_VERSION {
            return Err(MisakaError::DeserializationError(format!(
                "unsupported tx version: 0x{:02x}",
                self.version
            )));
        }
        match self.tx_type {
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
                // ── γ-1: ValidatorStakeTx envelope must round-trip out of `extra` ──
                let stake_tx =
                    crate::validator_stake_tx::ValidatorStakeTx::decode_from_extra(&self.extra)
                        .map_err(|e| {
                            MisakaError::DeserializationError(format!(
                                "{:?} tx: invalid stake envelope: {}",
                                self.tx_type, e
                            ))
                        })?;
                stake_tx.validate_structure().map_err(|e| {
                    MisakaError::DeserializationError(format!(
                        "{:?} tx: stake envelope structure invalid: {}",
                        self.tx_type, e
                    ))
                })?;
                // tx_type と envelope kind の整合性チェック
                let envelope_kind = stake_tx.kind;
                let kind_ok = match self.tx_type {
                    TxType::StakeDeposit => matches!(
                        envelope_kind,
                        crate::validator_stake_tx::StakeTxKind::Register
                            | crate::validator_stake_tx::StakeTxKind::StakeMore
                    ),
                    TxType::StakeWithdraw => matches!(
                        envelope_kind,
                        crate::validator_stake_tx::StakeTxKind::BeginExit
                    ),
                    _ => unreachable!("outer match guarded by StakeDeposit | StakeWithdraw"),
                };
                if !kind_ok {
                    return Err(MisakaError::DeserializationError(format!(
                        "{:?} tx: envelope kind {} not allowed for this tx_type",
                        self.tx_type,
                        envelope_kind.as_str(),
                    )));
                }
            }
            TxType::SystemEmission | TxType::Faucet => {
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
        }
        if self.outputs.is_empty() {
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
        // Per-input validation
        for (i, inp) in self.inputs.iter().enumerate() {
            if inp.utxo_refs.is_empty() {
                return Err(MisakaError::DeserializationError(format!(
                    "input[{i}]: must have at least 1 UTXO reference"
                )));
            }
            if inp.proof.len() > MAX_PROOF_SIZE {
                return Err(MisakaError::FieldTooLarge {
                    field: format!("input[{i}].proof"),
                    size: inp.proof.len(),
                    max: MAX_PROOF_SIZE,
                });
            }
        }
        if self.extra.len() > MAX_EXTRA_LEN {
            return Err(MisakaError::FieldTooLarge {
                field: "extra".into(),
                size: self.extra.len(),
                max: MAX_EXTRA_LEN,
            });
        }
        // R7 M-1: Validate spending_pubkey length (must be None or exactly
        // ML-DSA-65 PK size). Prevents DoS via oversized pubkeys that would
        // be hashed during output binding validation.
        for (i, output) in self.outputs.iter().enumerate() {
            if let Some(ref spk) = output.spending_pubkey {
                if spk.len() != crate::constants::PQ_PK_SIZE {
                    return Err(MisakaError::FieldTooLarge {
                        field: format!("output[{i}].spending_pubkey"),
                        size: spk.len(),
                        max: crate::constants::PQ_PK_SIZE,
                    });
                }
            }
        }
        Ok(())
    }

    /// Compute tx hash without the optional ZK proof carrier.
    ///
    /// This is the stable binding hash for statement/proof generation on the
    /// explicit zero-knowledge path, where the proof bytes themselves are not
    /// allowed to perturb the statement being proven.
    /// Compute tx_hash (canonical transaction identifier).
    pub fn tx_hash(&self) -> [u8; 32] {
        // Phase 2c-B: simplified — no more ZK proof carrier.
        self.tx_content_hash_legacy()
    }

    /// Total output amount (saturating to prevent wrapping overflow).
    pub fn total_output(&self) -> u64 {
        self.outputs
            .iter()
            .fold(0u64, |acc, o| acc.saturating_add(o.amount))
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    // Phase 2c-B D4b: test fixtures updated for new field set.

    fn make_utxo_tx() -> UtxoTransaction {
        UtxoTransaction {
            version: UTXO_TX_VERSION,
            tx_type: TxType::TransparentTransfer,
            inputs: vec![TxInput {
                utxo_refs: vec![OutputRef {
                    tx_hash: [1; 32],
                    output_index: 0,
                }],
                proof: vec![0xAA; 128],
            }],
            outputs: vec![TxOutput {
                amount: 9900,
                address: [0xCC; 32],
                spending_pubkey: None,
            }],
            fee: 100,
            extra: vec![],
            expiry: 0,
        }
    }

    #[test]
    fn test_structure_ok() {
        make_utxo_tx().validate_structure().unwrap();
    }

    #[test]
    fn test_tx_hash_excludes_proof() {
        let mut tx1 = make_utxo_tx();
        let mut tx2 = make_utxo_tx();
        tx1.inputs[0].proof = vec![0x11; 128];
        tx2.inputs[0].proof = vec![0x22; 128];
        // tx_hash uses TxSignablePayload which excludes proof,
        // so different proofs on otherwise-identical txs produce the same hash.
        assert_eq!(tx1.tx_hash(), tx2.tx_hash());
    }

    #[test]
    fn test_transparent_requires_inputs() {
        let tx = UtxoTransaction {
            version: UTXO_TX_VERSION,
            tx_type: TxType::TransparentTransfer,
            inputs: vec![],
            outputs: vec![TxOutput {
                amount: 1,
                address: [0x11; 32],
                spending_pubkey: None,
            }],
            fee: 0,
            extra: vec![],
            expiry: 0,
        };
        assert!(tx.validate_structure().is_err());
    }

    #[test]
    fn test_faucet_rejects_non_zero_fee() {
        let tx = UtxoTransaction {
            version: UTXO_TX_VERSION,
            tx_type: TxType::Faucet,
            inputs: vec![],
            outputs: vec![TxOutput {
                amount: 1,
                address: [0x11; 32],
                spending_pubkey: None,
            }],
            fee: 1,
            extra: vec![],
            expiry: 0,
        };
        assert!(tx.validate_structure().is_err());
    }

    #[test]
    fn test_stake_deposit_requires_inputs() {
        let tx = UtxoTransaction {
            version: UTXO_TX_VERSION,
            tx_type: TxType::StakeDeposit,
            inputs: vec![],
            outputs: vec![TxOutput {
                amount: 1,
                address: [0x11; 32],
                spending_pubkey: Some(vec![0x22; 32]),
            }],
            fee: 0,
            extra: vec![],
            expiry: 0,
        };
        assert!(tx.validate_structure().is_err());
    }

    #[test]
    fn test_coinbase_rejects_inputs() {
        let tx = UtxoTransaction {
            version: UTXO_TX_VERSION,
            tx_type: TxType::SystemEmission,
            inputs: vec![TxInput {
                utxo_refs: vec![OutputRef {
                    tx_hash: [1; 32],
                    output_index: 0,
                }],
                proof: vec![],
            }],
            outputs: vec![TxOutput {
                amount: 1,
                address: [0x11; 32],
                spending_pubkey: None,
            }],
            fee: 0,
            extra: vec![],
            expiry: 0,
        };
        assert!(tx.validate_structure().is_err());
    }

    #[test]
    fn test_tx_hash_deterministic() {
        let tx = make_utxo_tx();
        assert_eq!(tx.tx_hash(), tx.tx_hash());
    }

    // ─── γ-1: stake envelope wiring through validate_structure ────────────

    #[allow(clippy::expect_used)]
    fn make_register_envelope_extra() -> Vec<u8> {
        use crate::validator_stake_tx::{
            RegisterParams, StakeInput, StakeTxKind, StakeTxParams, ValidatorStakeTx,
        };
        let tx = ValidatorStakeTx {
            kind: StakeTxKind::Register,
            validator_id: [1u8; 32],
            stake_inputs: vec![StakeInput {
                tx_hash: [0xABu8; 32],
                output_index: 0,
                amount: 10_001_000,
            }],
            fee: 1_000,
            nonce: 0,
            memo: None,
            params: StakeTxParams::Register(RegisterParams {
                consensus_pubkey: vec![0u8; 1952],
                reward_address: [2u8; 32],
                commission_bps: 500,
                p2p_endpoint: None,
                moniker: None,
            }),
            signature: vec![0u8; 32],
        };
        tx.encode_for_extra().expect("encode register envelope")
    }

    #[allow(clippy::expect_used)]
    fn make_begin_exit_envelope_extra() -> Vec<u8> {
        use crate::validator_stake_tx::{StakeTxKind, StakeTxParams, ValidatorStakeTx};
        let tx = ValidatorStakeTx {
            kind: StakeTxKind::BeginExit,
            validator_id: [1u8; 32],
            stake_inputs: vec![],
            fee: 1_000,
            nonce: 1,
            memo: None,
            params: StakeTxParams::BeginExit,
            signature: vec![0u8; 32],
        };
        tx.encode_for_extra().expect("encode begin_exit envelope")
    }

    fn make_stake_tx(tx_type: TxType, extra: Vec<u8>) -> UtxoTransaction {
        UtxoTransaction {
            version: UTXO_TX_VERSION,
            tx_type,
            inputs: vec![TxInput {
                utxo_refs: vec![OutputRef {
                    tx_hash: [1; 32],
                    output_index: 0,
                }],
                proof: vec![0xAA; 16],
            }],
            outputs: vec![TxOutput {
                amount: 1,
                address: [0x11; 32],
                // spending_pubkey は None または PQ_PK_SIZE (1952) ぴったり
                spending_pubkey: None,
            }],
            fee: 100,
            extra,
            expiry: 0,
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn validate_structure_stake_deposit_register_ok() {
        let extra = make_register_envelope_extra();
        let tx = make_stake_tx(TxType::StakeDeposit, extra);
        tx.validate_structure().expect("valid stake deposit register");
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn validate_structure_stake_withdraw_begin_exit_ok() {
        let extra = make_begin_exit_envelope_extra();
        let tx = make_stake_tx(TxType::StakeWithdraw, extra);
        tx.validate_structure()
            .expect("valid stake withdraw begin_exit");
    }

    #[test]
    fn validate_structure_stake_deposit_with_begin_exit_envelope_rejected() {
        let extra = make_begin_exit_envelope_extra();
        let tx = make_stake_tx(TxType::StakeDeposit, extra);
        match tx.validate_structure() {
            Err(MisakaError::DeserializationError(ref s)) if s.contains("envelope kind") => {}
            other => panic!("expected envelope kind error, got {:?}", other),
        }
    }

    #[test]
    fn validate_structure_stake_withdraw_with_register_envelope_rejected() {
        let extra = make_register_envelope_extra();
        let tx = make_stake_tx(TxType::StakeWithdraw, extra);
        match tx.validate_structure() {
            Err(MisakaError::DeserializationError(ref s)) if s.contains("envelope kind") => {}
            other => panic!("expected envelope kind error, got {:?}", other),
        }
    }

    #[test]
    fn validate_structure_stake_deposit_bad_magic_rejected() {
        let mut extra = make_register_envelope_extra();
        extra[0] ^= 0xFF;
        let tx = make_stake_tx(TxType::StakeDeposit, extra);
        match tx.validate_structure() {
            Err(MisakaError::DeserializationError(ref s)) if s.contains("magic") => {}
            other => panic!("expected magic error, got {:?}", other),
        }
    }

    #[test]
    fn validate_structure_stake_deposit_empty_extra_rejected() {
        let tx = make_stake_tx(TxType::StakeDeposit, vec![]);
        match tx.validate_structure() {
            Err(MisakaError::DeserializationError(ref s)) if s.contains("too short") => {}
            other => panic!("expected too short error, got {:?}", other),
        }
    }
}
