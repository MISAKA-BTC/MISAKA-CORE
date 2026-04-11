//! Unified `send` command — single entry point for transparent transfers.
//!
//! Transparent mode uses ML-DSA-65 direct signatures (equivalent to Kaspa's
//! Schnorr approach but post-quantum safe).
//!
//! # Amount Handling
//!
//! Accepts human-readable decimals (e.g. `1.5` MISAKA) and converts to
//! base units internally (9 decimal places: 1 MISAKA = 1,000,000,000 units).

use anyhow::{bail, Context, Result};
use std::io::{self, Write};

/// MISAKA uses 9 decimal places.
/// 1 MISAKA = 1_000_000_000 base units.
const DECIMALS: u32 = 9;
const MULTIPLIER: u64 = 10u64.pow(DECIMALS);

/// Transfer mode derived from CLI flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendMode {
    /// Public transfer — sender visible, ML-DSA-65 direct signature.
    /// Equivalent to Kaspa's Schnorr, but post-quantum safe.
    Transparent,
}

impl std::fmt::Display for SendMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendMode::Transparent => write!(f, "Transparent (ML-DSA-65)"),
        }
    }
}

/// Parsed send arguments ready for dispatch.
pub struct SendArgs {
    pub to: String,
    #[allow(dead_code)]
    pub amount_raw: f64,
    pub amount_base: u64,
    pub fee_base: u64,
    pub mode: SendMode,
    pub wallet_path: String,
    pub rpc_url: String,
    pub chain_id: u32,
    pub skip_confirm: bool,
    pub genesis_hash: Option<String>,
}

/// Convert human-readable amount (e.g. "1.5") to base units.
///
/// Rounds to the nearest base unit. Returns error if negative or overflow.
pub fn parse_amount(amount: f64) -> Result<u64> {
    if amount < 0.0 {
        bail!("amount cannot be negative: {}", amount);
    }
    if amount > (u64::MAX as f64 / MULTIPLIER as f64) {
        bail!("amount overflow: {}", amount);
    }
    let base = (amount * MULTIPLIER as f64).round() as u64;
    if base == 0 && amount > 0.0 {
        bail!(
            "amount {} is too small (minimum: 0.{:0>width$}1 MISAKA)",
            amount,
            "",
            width = DECIMALS as usize - 1
        );
    }
    Ok(base)
}

/// Format base units back to human-readable MISAKA amount.
pub fn format_amount(base: u64) -> String {
    let whole = base / MULTIPLIER;
    let frac = base % MULTIPLIER;
    if frac == 0 {
        format!("{} MISAKA", whole)
    } else {
        // Trim trailing zeros
        let frac_str = format!("{:0>width$}", frac, width = DECIMALS as usize);
        let trimmed = frac_str.trim_end_matches('0');
        format!("{}.{} MISAKA", whole, trimmed)
    }
}

/// Resolve send mode from CLI flags.
pub fn resolve_mode(_deprecated: bool) -> SendMode {
    SendMode::Transparent
}

/// Print transaction summary and ask for confirmation.
fn confirm_transaction(args: &SendArgs) -> Result<bool> {
    if args.skip_confirm {
        return Ok(true);
    }

    println!();
    println!("╭──────────────────────────────────────────────╮");
    println!("│            Transaction Summary                │");
    println!("├──────────────────────────────────────────────┤");
    println!("│  Mode:   {:<36}│", format!("{}", args.mode));
    println!("│  To:     {:<36}│", truncate_addr(&args.to, 34));
    println!("│  Amount: {:<36}│", format_amount(args.amount_base));
    println!("│  Fee:    {:<36}│", format_amount(args.fee_base));
    println!(
        "│  Total:  {:<36}│",
        format_amount(args.amount_base + args.fee_base)
    );
    println!("╰──────────────────────────────────────────────╯");

    println!();

    print!("Broadcast this transaction? [Y/n] ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let answer = input.trim().to_lowercase();

    Ok(answer.is_empty() || answer == "y" || answer == "yes")
}

/// Truncate address for display.
fn truncate_addr(addr: &str, max: usize) -> String {
    if addr.len() <= max {
        addr.to_string()
    } else {
        format!("{}…{}", &addr[..12], &addr[addr.len() - 8..])
    }
}

/// Main entry point — route to the appropriate transfer backend.
pub async fn run(args: SendArgs) -> Result<()> {
    // ── Validate ──
    if args.amount_base == 0 {
        bail!("amount must be greater than zero");
    }

    // ── Confirm ──
    if !confirm_transaction(&args)? {
        println!("Transaction cancelled.");
        return Ok(());
    }

    // ── Resolve genesis hash ──
    let genesis_hash = match &args.genesis_hash {
        Some(hex) => {
            let bytes = hex::decode(hex).context("--genesis-hash must be valid hex (64 chars)")?;
            let mut arr = [0u8; 32];
            if bytes.len() != 32 {
                bail!("--genesis-hash must be exactly 32 bytes (64 hex chars)");
            }
            arr.copy_from_slice(&bytes);
            arr
        }
        None => {
            fetch_genesis_hash(&args.rpc_url).await.unwrap_or_else(|e| {
                eprintln!("Warning: could not fetch genesis hash from node: {e}");
                eprintln!("  Using zero hash — pass --genesis-hash explicitly if needed");
                [0u8; 32]
            })
        }
    };

    // ── Dispatch ──
    crate::public_transfer::run(
        &args.wallet_path,
        &args.to,
        args.amount_base,
        args.fee_base,
        &args.rpc_url,
        args.chain_id,
        genesis_hash,
    )
    .await
}

/// Fetch genesis hash from the node, falling back to `[0u8; 32]` on failure.
pub async fn fetch_genesis_hash_or_default(rpc_url: &str) -> [u8; 32] {
    fetch_genesis_hash(rpc_url).await.unwrap_or_else(|e| {
        eprintln!("Warning: could not fetch genesis hash from node: {e}");
        [0u8; 32]
    })
}

async fn fetch_genesis_hash(rpc_url: &str) -> Result<[u8; 32]> {
    let url = format!("{}/api/get_chain_info", rpc_url.trim_end_matches('/'));
    let resp: serde_json::Value = reqwest::get(&url)
        .await
        .context("failed to connect to node")?
        .json()
        .await
        .context("invalid JSON from node")?;
    let hex = resp
        .get("genesisHash")
        .and_then(|v| v.as_str())
        .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
    let bytes = hex::decode(hex).context("invalid genesisHash hex from node")?;
    let mut arr = [0u8; 32];
    if bytes.len() == 32 {
        arr.copy_from_slice(&bytes);
    }
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_amount_whole() {
        assert_eq!(parse_amount(1.0).unwrap(), 1_000_000_000);
        assert_eq!(parse_amount(100.0).unwrap(), 100_000_000_000);
    }

    #[test]
    fn test_parse_amount_decimal() {
        assert_eq!(parse_amount(1.5).unwrap(), 1_500_000_000);
        assert_eq!(parse_amount(0.000001).unwrap(), 1_000);
        assert_eq!(parse_amount(1234.567890).unwrap(), 1_234_567_890_000);
    }

    #[test]
    fn test_parse_amount_zero() {
        assert_eq!(parse_amount(0.0).unwrap(), 0);
    }

    #[test]
    fn test_parse_amount_negative() {
        assert!(parse_amount(-1.0).is_err());
    }

    #[test]
    fn test_format_amount() {
        assert_eq!(format_amount(1_000_000_000), "1 MISAKA");
        assert_eq!(format_amount(1_500_000_000), "1.5 MISAKA");
        assert_eq!(format_amount(1), "0.000000001 MISAKA");
        assert_eq!(format_amount(1_234_567_890), "1.23456789 MISAKA");
        assert_eq!(format_amount(0), "0 MISAKA");
    }

    #[test]
    fn test_resolve_mode() {
        assert_eq!(resolve_mode(false), SendMode::Transparent);
        assert_eq!(resolve_mode(true), SendMode::Transparent);
    }
}
