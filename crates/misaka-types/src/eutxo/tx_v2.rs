//! eUTXO v2 transaction types — the complete wire format.
//!
//! This is the consensus-critical transaction format for v2.0.
//! Cardano Vasil (Babbage era) equivalent.

use super::auxiliary::RequiredSigners;
use super::collateral::{CollateralInput, CollateralReturn};
use super::datum::DatumOrHash;
use super::mint::MintEntry;
use super::redeemer::Redeemer;
use super::reference::ReferenceInput;
use super::script::VersionedScript;
use super::validity::ValidityInterval;
use super::value::AssetValue;
use super::witness::WitnessKindV2;
use crate::utxo::{OutputRef, TxType};
use borsh::{BorshDeserialize, BorshSerialize};

/// Version byte for v2 transactions.
pub const EUTXO_TX_VERSION: u8 = 2;

/// Size limits (E1 initial values, E2 may adjust).
pub const MAX_INPUTS_PER_TX: usize = 64;
pub const MAX_OUTPUTS_PER_TX: usize = 64;
pub const MAX_REFERENCE_INPUTS_PER_TX: usize = 16;
pub const MAX_COLLATERAL_INPUTS_PER_TX: usize = 3;
pub const MAX_ASSETS_PER_OUTPUT: usize = 64;
pub const MAX_REDEEMERS_PER_TX: usize = 32;
pub const MAX_MINT_ENTRIES_PER_TX: usize = 64;
pub const MAX_TX_SIZE_BYTES: usize = 131_072; // 128 KiB

/// v2 transaction input.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct TxInputV2 {
    /// UTXO being consumed.
    pub outref: OutputRef,
    /// How this input is authorized.
    pub witness: WitnessKindV2,
}

/// v2 transaction output.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct TxOutputV2 {
    /// Recipient address (SHA3-256 of pubkey).
    pub address: [u8; 32],
    /// Multi-asset value (MLP + native assets).
    pub value: AssetValue,
    /// Spending public key (ML-DSA-65, 1952 bytes). For pubkey outputs.
    pub spending_pubkey: Option<Vec<u8>>,
    /// Datum attached to this output (CIP-32). For script outputs.
    pub datum: Option<DatumOrHash>,
    /// Reference script (CIP-33). Allows other txs to reference this script.
    pub script_ref: Option<VersionedScript>,
}

/// Complete eUTXO v2 transaction.
///
/// This is the consensus wire format. Field order is frozen.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    serde::Serialize,
    serde::Deserialize,
)]
pub struct UtxoTransactionV2 {
    /// Protocol version. Must be 2.
    pub version: u8,
    /// Network identifier (0=mainnet, 1=testnet).
    pub network_id: u8,
    /// Transaction type.
    pub tx_type: TxType,
    /// Inputs (consumed UTXOs).
    pub inputs: Vec<TxInputV2>,
    /// Outputs (created UTXOs).
    pub outputs: Vec<TxOutputV2>,
    /// Transaction fee (MLP).
    pub fee: u64,
    /// Validity interval (slot range).
    pub validity_interval: ValidityInterval,
    /// Minting entries. E1: must be empty. E3: minting/burning logic.
    pub mint: Vec<MintEntry>,
    /// Public key hashes that must sign this tx.
    pub required_signers: RequiredSigners,
    /// Reference inputs (CIP-31): read-only UTXO references.
    pub reference_inputs: Vec<ReferenceInput>,
    /// Collateral inputs (consumed on script failure).
    pub collateral_inputs: Vec<CollateralInput>,
    /// Collateral return output.
    pub collateral_return: Option<CollateralReturn>,
    /// Total collateral amount in MLP.
    pub total_collateral: Option<u64>,
    /// Hash of network parameters snapshot. RESERVED for E4.
    pub network_params_hash: Option<[u8; 32]>,
    /// Hash of auxiliary data (if present).
    pub aux_data_hash: Option<[u8; 32]>,
    /// Extra redeemers (for Mint / Cert / Reward purposes).
    pub extra_redeemers: Vec<Redeemer>,
    /// Optional auxiliary data (metadata).
    pub auxiliary_data: Option<super::auxiliary::AuxiliaryData>,
}

impl UtxoTransactionV2 {
    /// Compute the transaction hash (SHA3-256 of borsh-encoded body).
    pub fn tx_hash(&self) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:eutxo:tx:v2:");
        let encoded = borsh::to_vec(self).unwrap_or_default();
        h.update(&encoded);
        h.finalize().into()
    }

    /// Whether this transaction contains any script witnesses.
    pub fn has_scripts(&self) -> bool {
        self.inputs
            .iter()
            .any(|i| matches!(i.witness, WitnessKindV2::Script { .. }))
    }

    /// Sum declared ex_units across all redeemers (script witnesses + extra).
    /// Used for fee calculation at admission (Phase 1).
    pub fn declared_total_ex_units(&self) -> super::cost_model::ExUnits {
        let mut total = super::cost_model::ExUnits::ZERO;
        for input in &self.inputs {
            if let WitnessKindV2::Script { redeemer, .. } = &input.witness {
                total = total.saturating_add(&redeemer.ex_units);
            }
        }
        for r in &self.extra_redeemers {
            total = total.saturating_add(&r.ex_units);
        }
        total
    }
}
