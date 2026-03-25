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
use zeroize::Zeroize;

pub mod api_types;
pub mod coin_select;
pub mod storage;
pub mod tx_state;
pub mod wallet_crypto;

#[cfg(feature = "native-rpc")]
pub mod rpc_client;

/// Wallet version (incremented on breaking format changes).
pub const WALLET_VERSION: u32 = 1;

// ═══════════════════════════════════════════════════════════════
//  Key Types
// ═══════════════════════════════════════════════════════════════

/// Wallet keypair — spending + view keys.
///
/// # SEC-WALLET: Zeroize on Drop
///
/// Secret key material is zeroized when the struct is dropped.
/// This prevents secret keys from lingering in freed memory
/// where they could be extracted by memory-scanning malware.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
pub struct WalletKeypair {
    /// ML-DSA-65 signing key (for ring signatures and ZKP witnesses).
    pub spending_secret: Vec<u8>,
    /// ML-DSA-65 public key.
    #[zeroize(skip)]
    pub spending_public: Vec<u8>,
    /// ML-KEM-768 view secret key (for decrypting incoming outputs).
    pub view_secret: Vec<u8>,
    /// ML-KEM-768 view public key (shared with senders for stealth addressing).
    #[zeroize(skip)]
    pub view_public: Vec<u8>,
    /// Wallet address = SHA3-256(spending_public || view_public)[0..20].
    #[zeroize(skip)]
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
/// Format: `misaka1<hex-encoded 20 bytes><4-char checksum>`
/// Example: `misaka1a1b2c3d4e5f6...abcd`
///
/// The checksum is the first 4 hex chars of SHA3-256(prefix || address_hex),
/// providing typo detection when entering addresses manually.
pub fn encode_address(addr: &[u8; 20]) -> String {
    let hex_part = hex::encode(addr);
    let checksum = compute_address_checksum(&hex_part);
    format!("misaka1{}{}", hex_part, checksum)
}

/// Compute 4-char checksum for address error detection.
fn compute_address_checksum(hex_part: &str) -> String {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:addr:checksum:v1:");
    h.update(hex_part.as_bytes());
    let hash: [u8; 32] = h.finalize().into();
    hex::encode(&hash[..2]) // 4 hex chars
}

/// Parse a display address back to bytes.
///
/// Accepts both legacy (no checksum) and checksummed formats:
/// - `misaka1<40 hex chars>` — legacy, accepted without checksum validation
/// - `misaka1<40 hex chars><4 hex checksum>` — validates checksum
pub fn decode_address(s: &str) -> Result<[u8; 20], String> {
    let stripped = s
        .strip_prefix("misaka1")
        .ok_or_else(|| "address must start with 'misaka1'".to_string())?;

    // Determine if checksum is present
    let (hex_part, expected_checksum) = if stripped.len() == 44 {
        // 40 hex (address) + 4 hex (checksum)
        (&stripped[..40], Some(&stripped[40..]))
    } else if stripped.len() == 40 {
        // Legacy: no checksum
        (stripped, None)
    } else {
        return Err(format!(
            "address must be 40 hex chars (20 bytes) or 44 with checksum (got {})",
            stripped.len()
        ));
    };

    let bytes = hex::decode(hex_part).map_err(|e| format!("invalid hex: {}", e))?;
    if bytes.len() != 20 {
        return Err(format!("address must be 20 bytes (got {})", bytes.len()));
    }

    // Validate checksum if present
    if let Some(expected) = expected_checksum {
        let computed = compute_address_checksum(hex_part);
        if computed != expected {
            return Err(format!(
                "address checksum mismatch: expected {}, got {} (possible typo)",
                computed, expected
            ));
        }
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

/// Coin selection strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoinSelectionStrategy {
    /// Select largest UTXOs first. Simple, deterministic.
    LargestFirst,
    /// Select smallest sufficient UTXO first. Minimizes change.
    SmallestSufficient,
    /// Privacy-aware: prefer UTXOs that create non-dust change,
    /// avoiding exact-match (which leaks amount information).
    PrivacyAware,
}

/// Minimum meaningful output amount (below this is "dust").
const DUST_THRESHOLD: u64 = 100; // 0.0001 MISAKA

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
    select_coins_with_strategy(utxos, target_amount, fee, CoinSelectionStrategy::LargestFirst)
}

/// Select UTXOs with a specified strategy.
pub fn select_coins_with_strategy(
    utxos: &[OwnedUtxo],
    target_amount: u64,
    fee: u64,
    strategy: CoinSelectionStrategy,
) -> Result<CoinSelection, String> {
    if target_amount == 0 {
        return Err("amount must be positive".into());
    }

    let needed = target_amount
        .checked_add(fee)
        .ok_or_else(|| "amount + fee overflow".to_string())?;

    let mut available: Vec<&OwnedUtxo> = utxos.iter().filter(|u| !u.spent).collect();

    match strategy {
        CoinSelectionStrategy::LargestFirst => {
            available.sort_by(|a, b| b.amount.cmp(&a.amount));
        }
        CoinSelectionStrategy::SmallestSufficient => {
            // Try to find a single UTXO that covers the amount
            available.sort_by_key(|u| u.amount);
            if let Some(pos) = available.iter().position(|u| u.amount >= needed) {
                let selected = vec![available[pos].clone()];
                let change = available[pos].amount - needed;
                return Ok(CoinSelection {
                    selected,
                    total_input: available[pos].amount,
                    change,
                });
            }
            // Fall back to largest-first for multi-UTXO
            available.sort_by(|a, b| b.amount.cmp(&a.amount));
        }
        CoinSelectionStrategy::PrivacyAware => {
            // Prefer UTXOs that produce non-dust, non-zero change.
            // This avoids leaking "exact amount" information.
            available.sort_by_key(|u| u.amount);
            if let Some(pos) = available.iter().position(|u| {
                u.amount >= needed && (u.amount - needed) >= DUST_THRESHOLD
            }) {
                let selected = vec![available[pos].clone()];
                let change = available[pos].amount - needed;
                return Ok(CoinSelection {
                    selected,
                    total_input: available[pos].amount,
                    change,
                });
            }
            // Fall back to largest-first
            available.sort_by(|a, b| b.amount.cmp(&a.amount));
        }
    }

    let mut selected = Vec::new();
    let mut accumulated = 0u64;

    for utxo in available {
        if accumulated >= needed {
            break;
        }
        selected.push(utxo.clone());
        accumulated = accumulated.saturating_add(utxo.amount);
    }

    if accumulated < needed {
        return Err(format!(
            "insufficient funds: have {}, need {} (amount={}, fee={})",
            accumulated, needed, target_amount, fee
        ));
    }

    // Warn about dust change (caller can decide what to do)
    let change = accumulated - needed;

    Ok(CoinSelection {
        selected,
        total_input: accumulated,
        change,
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
    fn test_address_encode_decode_checksummed() {
        let addr = [0x01; 20];
        let encoded = encode_address(&addr);
        assert!(encoded.starts_with("misaka1"));
        // New: 44 chars after prefix (40 hex + 4 checksum)
        let after_prefix = encoded.strip_prefix("misaka1").expect("test: prefix");
        assert_eq!(after_prefix.len(), 44);
        let decoded = decode_address(&encoded).expect("test: valid decode");
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_address_checksum_detects_typo() {
        let addr = [0x01; 20];
        let mut encoded = encode_address(&addr);
        // Corrupt one character
        let bytes = unsafe { encoded.as_bytes_mut() };
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'0' { b'1' } else { b'0' };
        let result = decode_address(&encoded);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("checksum mismatch"));
    }

    #[test]
    fn test_address_decode_legacy_no_checksum() {
        // Legacy 40-char hex (no checksum) should still be accepted
        let addr = [0x02; 20];
        let legacy = format!("misaka1{}", hex::encode(addr));
        assert_eq!(legacy.strip_prefix("misaka1").expect("test: prefix").len(), 40);
        let decoded = decode_address(&legacy).expect("test: legacy decode");
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
        let result = select_coins(&utxos, 900, 100).expect("test: select");
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.total_input, 1000);
        assert_eq!(result.change, 0);
    }

    #[test]
    fn test_coin_selection_with_change() {
        let utxos = vec![make_utxo(5000, 1), make_utxo(3000, 2)];
        let result = select_coins(&utxos, 2000, 100).expect("test: select");
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
        let result = select_coins(&utxos, 2000, 100).expect("test: select");
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.selected[0].tx_hash, [2; 32]);
    }

    #[test]
    fn test_coin_selection_smallest_sufficient() {
        let utxos = vec![make_utxo(5000, 1), make_utxo(3000, 2), make_utxo(2200, 3)];
        let result = select_coins_with_strategy(
            &utxos, 2000, 100, CoinSelectionStrategy::SmallestSufficient,
        ).expect("test: select");
        // Should pick the 2200 UTXO (smallest that covers 2100)
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.selected[0].amount, 2200);
        assert_eq!(result.change, 100);
    }

    #[test]
    fn test_coin_selection_privacy_aware() {
        // PrivacyAware should avoid exact match, prefer non-dust change
        let utxos = vec![
            make_utxo(2100, 1),  // exact match → avoids (change = 0)
            make_utxo(2300, 2),  // change = 200 (>= dust threshold)
            make_utxo(5000, 3),  // too large
        ];
        let result = select_coins_with_strategy(
            &utxos, 2000, 100, CoinSelectionStrategy::PrivacyAware,
        ).expect("test: select");
        assert_eq!(result.selected.len(), 1);
        assert_eq!(result.selected[0].amount, 2300);
        assert_eq!(result.change, 200);
    }

    #[test]
    fn test_coin_selection_multi_utxo() {
        // No single UTXO covers the target; needs combination
        let utxos = vec![make_utxo(1000, 1), make_utxo(800, 2), make_utxo(600, 3)];
        let result = select_coins(&utxos, 2000, 100).expect("test: select");
        assert!(result.selected.len() >= 2);
        assert!(result.total_input >= 2100);
    }

    #[test]
    fn test_plan_transfer() {
        let utxos = vec![make_utxo(10_000, 1)];
        let plan = plan_transfer(
            &utxos, [0xBB; 32], // recipient
            7000, 100, [0xCC; 32], // change address
        )
        .expect("test: plan");

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
        let plan = plan_transfer(&utxos, [0xBB; 32], 1000, 100, [0xCC; 32]).expect("test: plan");
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

    #[test]
    fn test_address_roundtrip_deterministic() {
        // Encode → decode roundtrip must be stable
        let addr = [0xAB; 20];
        let encoded = encode_address(&addr);
        let decoded = decode_address(&encoded).expect("test: roundtrip");
        assert_eq!(addr, decoded);

        // Same address → same encoding
        let encoded2 = encode_address(&addr);
        assert_eq!(encoded, encoded2);
    }
}
