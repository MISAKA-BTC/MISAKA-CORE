//! MISAKA Wallet SDK — Key management, address encoding, and TX building.
//!
//! # Architecture
//!
//! The Chrome Extension wallet uses this SDK via one of:
//! - **WASM**: Compiled to `wasm32-unknown-unknown` for in-browser crypto
//! - **RPC**: Calls the node's `/api/get_anonymity_set` + local key ops
//!
//! # Key Hierarchy
//!
//! ```text
//! ML-DSA-65 Master Keypair
//!   ├── Spending Key (signs lattice ZKP proofs / ZKP witnesses)
//!   ├── View Key (ML-KEM-768, scans for incoming outputs)
//!   └── Derived One-Time Addresses (per-output stealth addresses)
//! ```

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

pub mod account;
pub mod address_manager;
pub mod api_types;
pub mod balance_manager;
pub mod coin_select;
pub mod daemon;
pub mod discovery;
pub mod import_export;
pub mod keystore;
pub mod metrics;
pub mod psmt;
pub mod rpc_methods;
pub mod serializer;
pub mod settings;
pub mod signing;
pub mod storage;
pub mod sync;
pub mod tx_builder;
pub mod tx_state;
pub mod wallet;
pub mod wallet_crypto;
pub mod wrpc_client;

// ─── Kaspa-Aligned Extensions ───
pub mod hd_keys;
pub mod utxo_processor;

#[cfg(feature = "native-rpc")]
pub mod rpc_client;

/// Wallet version (incremented on breaking format changes).
pub const WALLET_VERSION: u32 = 2;

// ═══════════════════════════════════════════════════════════════
//  Key Types (unchanged from v1)
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct WalletKeypair {
    pub spending_secret: Vec<u8>,
    #[zeroize(skip)]
    pub spending_public: Vec<u8>,
    pub view_secret: Vec<u8>,
    #[zeroize(skip)]
    pub view_public: Vec<u8>,
    #[zeroize(skip)]
    pub address: [u8; 20],
}

impl WalletKeypair {
    pub fn compute_address(spending_public: &[u8], view_public: &[u8]) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:wallet:address:v1:");
        h.update(spending_public);
        h.update(view_public);
        let hash: [u8; 32] = h.finalize().into();
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&hash[..20]);
        addr
    }
}

pub fn encode_address(addr: &[u8; 20]) -> String {
    let hex_part = hex::encode(addr);
    let checksum = compute_address_checksum(&hex_part);
    format!("misaka1{}{}", hex_part, checksum)
}

fn compute_address_checksum(hex_part: &str) -> String {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:addr:checksum:v1:");
    h.update(hex_part.as_bytes());
    let hash: [u8; 32] = h.finalize().into();
    hex::encode(&hash[..2])
}

pub fn decode_address(s: &str) -> Result<[u8; 32], String> {
    let stripped = s
        .strip_prefix("misaka1")
        .ok_or_else(|| "address must start with 'misaka1'".to_string())?;
    let (hex_part, expected_checksum) = if stripped.len() == 44 {
        (&stripped[..40], Some(&stripped[40..]))
    } else if stripped.len() == 40 {
        (stripped, None)
    } else {
        return Err(format!("invalid address length: {}", stripped.len()));
    };
    let bytes = hex::decode(hex_part).map_err(|e| format!("invalid hex: {}", e))?;
    if bytes.len() != 20 {
        return Err(format!("expected 20 bytes, got {}", bytes.len()));
    }
    if let Some(expected) = expected_checksum {
        let computed = compute_address_checksum(hex_part);
        if computed != expected {
            return Err(format!(
                "checksum mismatch: expected {}, got {}",
                computed, expected
            ));
        }
    }
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

// ═══════════════════════════════════════════════════════════════
//  UTXO Types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnedUtxo {
    pub tx_hash: [u8; 32],
    pub output_index: u32,
    pub amount: u64,
    pub one_time_address: [u8; 32],
    pub spent: bool,
    pub confirmed_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBalance {
    pub total: u64,
    pub utxo_count: usize,
    pub pending_spend: u64,
    pub available: u64,
}

// ═══════════════════════════════════════════════════════════════
//  Transaction Plan
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxPlan {
    pub inputs: Vec<TxPlanInput>,
    pub outputs: Vec<TxPlanOutput>,
    pub fee: u64,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxPlanInput {
    pub tx_hash: [u8; 32],
    pub output_index: u32,
    pub amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxPlanOutput {
    pub address: [u8; 32],
    pub amount: u64,
    pub is_change: bool,
}
pub mod account_manager;
pub mod address_book;
pub mod address_derivation;
pub mod backup_manager;
pub mod broadcast_manager;
pub mod cache_manager;
pub mod coin_join;
pub mod compatibility;
pub mod compound;
pub mod derivation_cache;
pub mod dust_manager;
pub mod encryption_manager;
pub mod error_recovery;
pub mod event_dispatcher;
pub mod fee_calculator;
pub mod hardware_bridge;
pub mod key_rotation;
pub mod migration;
pub mod network_monitor;
pub mod notification_handler;
pub mod persistence;
pub mod qr_encoding;
pub mod recovery_phrase;
pub mod signer_factory;
pub mod signing_coordinator;
pub mod sweep;
pub mod transaction_store;
pub mod tx_history;
pub mod utxo_context;
pub mod utxo_scanner;
pub mod wasm_bindings;
pub mod watcher;
