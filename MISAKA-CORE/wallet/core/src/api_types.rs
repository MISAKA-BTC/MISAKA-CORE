//! API request/response types for MISAKA Node interaction.
//!
//! These types are used by both:
//! - **Native RPC client** (`native-rpc` feature): reqwest-based HTTP client
//! - **WASM/Chrome extension**: TypeScript calls the API directly,
//!   these types define the expected JSON shape for serialization.

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
//  Transfer Mode (matches CLI send.rs)
// ═══════════════════════════════════════════════════════════════

/// Transfer privacy mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SendMode {
    /// Public transfer — sender visible, ring_size=1. TxType=6, scheme=0x20.
    Transparent,
    /// Ring signature — sender hidden among decoys. TxType=0, scheme=0x01/0x03.
    Private,
    /// ZKP confidential — sender + amounts fully hidden. TxType=0, scheme=0x10.
    Shielded,
}

impl Default for SendMode {
    fn default() -> Self {
        SendMode::Transparent
    }
}

// ═══════════════════════════════════════════════════════════════
//  Request Types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Serialize, Deserialize)]
pub struct GetUtxosByAddressReq {
    pub address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetDecoyUtxosReq {
    pub amount: u64,
    #[serde(default = "default_decoy_count")]
    pub count: usize,
    #[serde(rename = "excludeTxHash", default)]
    pub exclude_tx_hash: String,
    #[serde(rename = "excludeOutputIndex", default)]
    pub exclude_output_index: u32,
}

fn default_decoy_count() -> usize {
    8
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetAnonymitySetReq {
    #[serde(rename = "ringSize", default = "default_ring_size")]
    pub ring_size: usize,
    #[serde(rename = "txHash", default)]
    pub tx_hash: String,
    #[serde(rename = "outputIndex", default)]
    pub output_index: u32,
}

fn default_ring_size() -> usize {
    16
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitTxReq {
    pub version: u8,
    #[serde(rename = "ringScheme")]
    pub ring_scheme: u8,
    #[serde(rename = "txType", default)]
    pub tx_type: u8,
    pub inputs: Vec<serde_json::Value>,
    pub outputs: Vec<serde_json::Value>,
    pub fee: u64,
    #[serde(rename = "zkProof", skip_serializing_if = "Option::is_none")]
    pub zk_proof: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FaucetReq {
    pub address: String,
    #[serde(rename = "spendingPubkey", skip_serializing_if = "Option::is_none")]
    pub spending_pubkey: Option<String>,
}

// ═══════════════════════════════════════════════════════════════
//  Response Types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtxoInfo {
    #[serde(rename = "txHash")]
    pub tx_hash: String,
    #[serde(rename = "outputIndex")]
    pub output_index: u32,
    pub amount: u64,
    #[serde(rename = "oneTimeAddress", default)]
    pub one_time_address: String,
    #[serde(rename = "spendingPubkey", default)]
    pub spending_pubkey: String,
    #[serde(rename = "createdAt", default)]
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletUtxoResponse {
    pub address: String,
    pub utxos: Vec<UtxoInfo>,
    pub balance: u64,
    #[serde(rename = "utxoCount")]
    pub utxo_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyUtxoResponse {
    pub utxos: Vec<DecoyUtxo>,
    pub count: usize,
    #[serde(rename = "requestedAmount")]
    pub requested_amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyUtxo {
    #[serde(rename = "txHash")]
    pub tx_hash: String,
    #[serde(rename = "outputIndex")]
    pub output_index: u32,
    pub amount: u64,
    #[serde(rename = "spendingPubkey")]
    pub spending_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymitySetResponse {
    pub leaves: Vec<String>,
    #[serde(rename = "signerIndex")]
    pub signer_index: usize,
    #[serde(rename = "ringSize")]
    pub ring_size: usize,
    #[serde(rename = "merkleRoot")]
    pub merkle_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTxResponse {
    #[serde(rename = "txHash")]
    pub tx_hash: Option<String>,
    pub accepted: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(rename = "admissionPath", default)]
    pub admission_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaucetResponse {
    pub accepted: bool,
    #[serde(rename = "txHash", default)]
    pub tx_hash: Option<String>,
    #[serde(default)]
    pub amount: Option<u64>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimate {
    pub low: u64,
    pub medium: u64,
    pub high: u64,
    pub unit: String,
    #[serde(rename = "mempoolSize")]
    pub mempool_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfo {
    #[serde(rename = "chainId")]
    pub chain_id: u32,
    #[serde(rename = "chainName", default)]
    pub chain_name: String,
    #[serde(rename = "dagSize", default)]
    pub dag_size: u64,
    #[serde(rename = "virtualTip", default)]
    pub virtual_tip: String,
    #[serde(rename = "mempoolSize", default)]
    pub mempool_size: usize,
    #[serde(rename = "utxoSetSize", default)]
    pub utxo_set_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub consensus: String,
    pub version: String,
}
