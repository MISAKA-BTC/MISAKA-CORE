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
//!   ├── Spending Key (signs ring signatures / ZKP witnesses)
//!   ├── View Key (ML-KEM-768, scans for incoming outputs)
//!   └── Derived One-Time Addresses (per-output stealth addresses)
//! ```
//!
//! # Wallet State
//!
//! The wallet maintains:
//! - `owned_utxos`: UTXOs the view key can decrypt (amount + blinding factor)
//! - `spent_nullifiers`: Nullifiers already submitted (prevent double-spend)
//! - `pending_txs`: TXs submitted but not yet confirmed

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

/// Wallet version (incremented on breaking format changes).
pub const WALLET_VERSION: u32 = 1;

// ═══════════════════════════════════════════════════════════════
//  Key Types
// ═══════════════════════════════════════════════════════════════

/// Wallet keypair — spending + view keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletKeypair {
    /// ML-DSA-65 signing key (for ring signatures and ZKP witnesses).
    pub spending_secret: Vec<u8>,
    /// ML-DSA-65 public key.
    pub spending_public: Vec<u8>,
    /// ML-KEM-768 view secret key (for decrypting incoming outputs).
    pub view_secret: Vec<u8>,
    /// ML-KEM-768 view public key (shared with senders for stealth addressing).
    pub view_public: Vec<u8>,
    /// Wallet address = SHA3-256(spending_public || view_public)[0..20].
    pub address: [u8; 20],
}

impl WalletKeypair {
    /// Derive the wallet address from public keys.
    pub fn compute_address(spending_public: &[u8], view_public: &[u8]) -> [u8; 20] {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:wallet:address:v1:");
        h.update(spending_public);
        h.update(view_public);
        let hash: [u8; 32] = h.finalize().into();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[..20]);
        addr
    }
}

/// Display-friendly wallet address (Bech32-like encoding).
///
/// Format: `misaka1<hex-encoded 20 bytes>`
/// Example: `misaka1a1b2c3d4e5f6...`
pub fn encode_address(addr: &[u8; 20]) -> String {
    format!("misaka1{}", hex::encode(addr))
}

/// Parse a display address back to bytes.
pub fn decode_address(s: &str) -> Result<[u8; 20], String> {
    let stripped = s
        .strip_prefix("misaka1")
        .ok_or_else(|| "address must start with 'misaka1'".to_string())?;

    let bytes = hex::decode(stripped).map_err(|e| format!("invalid hex: {}", e))?;
    if bytes.len() != 20 {
        return Err(format!("address must be 20 bytes (got {})", bytes.len()));
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

// ═══════════════════════════════════════════════════════════════
//  UTXO Tracking
// ═══════════════════════════════════════════════════════════════

/// An owned UTXO that the wallet can spend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnedUtxo {
    /// Transaction hash that created this output.
    pub tx_hash: [u8; 32],
    /// Output index within the transaction.
    pub output_index: u32,
    /// Decrypted amount (only known to the wallet).
    pub amount: u64,
    /// One-time address for this output.
    pub one_time_address: [u8; 32],
    /// Whether this UTXO has been spent (nullifier submitted).
    pub spent: bool,
    /// Block height at which this UTXO was confirmed.
    pub confirmed_at: u64,
}

/// Wallet balance summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBalance {
    /// Total balance across all unspent UTXOs.
    pub total: u64,
    /// Number of unspent UTXOs.
    pub utxo_count: usize,
    /// Balance locked in pending transactions.
    pub pending_spend: u64,
    /// Available balance (total - pending_spend).
    pub available: u64,
}

// ═══════════════════════════════════════════════════════════════
//  Coin Selection
// ═══════════════════════════════════════════════════════════════

/// Coin selection result.
#[derive(Debug, Clone)]
pub struct CoinSelection {
    /// Selected UTXOs to spend.
    pub selected: Vec<OwnedUtxo>,
    /// Total input amount.
    pub total_input: u64,
    /// Change amount (back to sender).
    pub change: u64,
}

/// Select UTXOs to cover a target amount + fee.
///
/// Strategy: Largest-first (simple, deterministic).
/// In the ZKP model, there is NO constraint that UTXOs must match
/// specific denominations — any combination that covers the total is valid.
pub fn select_coins(
    utxos: &[OwnedUtxo],
    target_amount: u64,
    fee: u64,
) -> Result<CoinSelection, String> {
    if target_amount == 0 {
        return Err("amount must be positive".into());
    }

    let needed = target_amount
        .checked_add(fee)
        .ok_or_else(|| "amount + fee overflow".to_string())?;

    let mut available: Vec<&OwnedUtxo> = utxos.iter().filter(|u| !u.spent).collect();
    available.sort_by(|a, b| b.amount.cmp(&a.amount)); // Largest first

    let mut selected = Vec::new();
    let mut accumulated = 0u64;

    for utxo in available {
        if accumulated >= needed {
            break;
        }
        selected.push(utxo.clone());
        accumulated += utxo.amount;
    }

    if accumulated < needed {
        return Err(format!(
            "insufficient funds: have {}, need {} (amount={}, fee={})",
            accumulated, needed, target_amount, fee
        ));
    }

    Ok(CoinSelection {
        selected,
        total_input: accumulated,
        change: accumulated - needed,
    })
}

// ═══════════════════════════════════════════════════════════════
//  Transaction Plan
// ═══════════════════════════════════════════════════════════════

/// High-level transaction plan (before cryptographic proof generation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxPlan {
    /// Input UTXOs to spend.
    pub inputs: Vec<TxPlanInput>,
    /// Outputs to create.
    pub outputs: Vec<TxPlanOutput>,
    /// Transaction fee.
    pub fee: u64,
    /// Summary for display.
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

/// Plan a transfer transaction.
pub fn plan_transfer(
    utxos: &[OwnedUtxo],
    recipient_address: [u8; 32],
    amount: u64,
    fee: u64,
    change_address: [u8; 32],
) -> Result<TxPlan, String> {
    let selection = select_coins(utxos, amount, fee)?;

    let mut outputs = vec![TxPlanOutput {
        address: recipient_address,
        amount,
        is_change: false,
    }];

    if selection.change > 0 {
        outputs.push(TxPlanOutput {
            address: change_address,
            amount: selection.change,
            is_change: true,
        });
    }

    let summary = format!(
        "Send {} MISAKA → {} ({} inputs, {} outputs, fee={})",
        amount,
        hex::encode(&recipient_address[..8]),
        selection.selected.len(),
        outputs.len(),
        fee,
    );

    Ok(TxPlan {
        inputs: selection
            .selected
            .iter()
            .map(|u| TxPlanInput {
                tx_hash: u.tx_hash,
                output_index: u.output_index,
                amount: u.amount,
            })
            .collect(),
        outputs,
        fee,
        summary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_utxo(amount: u64, index: u8) -> OwnedUtxo {
        OwnedUtxo {
            tx_hash: [index; 32],
            output_index: 0,
            amount,
            one_time_address: [0xAA; 32],
            spent: false,
            confirmed_at: 100,
        }
    }

    #[test]
    fn test_address_encode_decode() {
        let addr = [0x01; 20];
        let encoded = encode_address(&addr);
        assert!(encoded.starts_with("misaka1"));
        let decoded = decode_address(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_address_decode_invalid() {
        assert!(decode_address("bitcoin1abc").is_err());
        assert!(decode_address("misaka1zzzz").is_err()); // invalid hex
        assert!(decode_address("misaka1aabb").is_err()); // too short
    }

    #[test]
    fn test_coin_selection_exact() {
        let utxos = vec![make_utxo(1000, 1)];
        let result = select_coins(&utxos, 900, 100).unwrap();
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.total_input, 1000);
        assert_eq!(result.change, 0);
    }

    #[test]
    fn test_coin_selection_with_change() {
        let utxos = vec![make_utxo(5000, 1), make_utxo(3000, 2)];
        let result = select_coins(&utxos, 2000, 100).unwrap();
        assert_eq!(result.selected.len(), 1); // 5000 covers 2100
        assert_eq!(result.change, 2900);
    }

    #[test]
    fn test_coin_selection_insufficient() {
        let utxos = vec![make_utxo(100, 1)];
        assert!(select_coins(&utxos, 200, 10).is_err());
    }

    #[test]
    fn test_coin_selection_skip_spent() {
        let mut utxos = vec![make_utxo(5000, 1), make_utxo(3000, 2)];
        utxos[0].spent = true;
        let result = select_coins(&utxos, 2000, 100).unwrap();
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.selected[0].tx_hash, [2; 32]);
    }

    #[test]
    fn test_plan_transfer() {
        let utxos = vec![make_utxo(10_000, 1)];
        let plan = plan_transfer(
            &utxos,
            [0xBB; 32], // recipient
            7000,
            100,
            [0xCC; 32], // change address
        )
        .unwrap();

        assert_eq!(plan.inputs.len(), 1);
        assert_eq!(plan.outputs.len(), 2); // send + change
        assert_eq!(plan.outputs[0].amount, 7000);
        assert!(!plan.outputs[0].is_change);
        assert_eq!(plan.outputs[1].amount, 2900); // 10000 - 7000 - 100
        assert!(plan.outputs[1].is_change);
        assert_eq!(plan.fee, 100);
    }

    #[test]
    fn test_plan_transfer_no_change() {
        let utxos = vec![make_utxo(1100, 1)];
        let plan = plan_transfer(&utxos, [0xBB; 32], 1000, 100, [0xCC; 32]).unwrap();
        assert_eq!(plan.outputs.len(), 1); // no change
        assert_eq!(plan.outputs[0].amount, 1000);
    }

    #[test]
    fn test_wallet_address() {
        let addr = WalletKeypair::compute_address(&[1; 32], &[2; 32]);
        assert_eq!(addr.len(), 20);
        // Same inputs → same address
        let addr2 = WalletKeypair::compute_address(&[1; 32], &[2; 32]);
        assert_eq!(addr, addr2);
        // Different inputs → different address
        let addr3 = WalletKeypair::compute_address(&[3; 32], &[2; 32]);
        assert_ne!(addr, addr3);
    }
}
