//! CLI — Check Validator Staking Status
//!
//! Solana 上の MISAKA ステーキングプログラムから、自分のバリデータに
//! 紐づけられた預入枚数をオンチェーンで照会する。
//!
//! # On-Chain Data (改ざん不可能)
//!
//! Solana 上のアカウントデータは **プログラム Owner のみ** が書き込み可能。
//! つまりステーキングプログラム `27WjgCAWkkjS4H4j...` のコードだけが
//! `total_staked` や `is_active` を変更できる。
//!
//! ユーザーや第三者が:
//! - PDA のデータを直接書き換えることは **不可能** (Solana ランタイムが拒否)
//! - 偽のステーキング TX を作ることは **不可能** (プログラムが amount を検証)
//! - 他人の L1 公開鍵で登録することは **不可能** (PDA = hash(l1_key) で一意)
//!
//! # Account Layout (confirmed offsets)
//!
//! - ValidatorRegistration (242 bytes): offset 72..104 = L1 公開鍵
//! - ValidatorStake (117 bytes):       offset 72..80  = total_staked (u64 LE)
//! - StakingPosition (200 bytes):      offset 96..104 = position amount (u64 LE)

use anyhow::{bail, Context, Result};
use serde::Deserialize;

const PROGRAM_ID: &str = "27WjgCAWkkjS4H4jqytkKQoCrAN3qgzjp6f6pXLdP8hG";
const SOLANA_RPC: &str = "https://api.mainnet-beta.solana.com";
const DECIMALS: f64 = 1_000_000_000.0;

// ── Base58 ────────────────────────────────────────────────────

const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn b58encode(bytes: &[u8]) -> String {
    let mut n = {
        let mut v = Vec::with_capacity(bytes.len());
        v.extend_from_slice(bytes);
        v
    };
    // Convert bytes to a big integer
    let mut result = Vec::new();
    loop {
        let mut rem = 0u32;
        let mut new_n = Vec::new();
        let mut started = false;
        for &byte in &n {
            let val = rem * 256 + byte as u32;
            let div = val / 58;
            rem = val % 58;
            if div > 0 || started {
                new_n.push(div as u8);
                started = true;
            }
        }
        result.push(ALPHABET[rem as usize]);
        if new_n.is_empty() {
            break;
        }
        n = new_n;
    }
    // Leading zeros
    for &byte in bytes {
        if byte == 0 {
            result.push(b'1');
        } else {
            break;
        }
    }
    result.reverse();
    String::from_utf8(result).unwrap_or_default()
}

// ── Solana RPC Types ──────────────────────────────────────────

#[allow(dead_code)]
#[derive(Deserialize)]
struct RpcResponse {
    result: Option<Vec<ProgramAccount>>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct ProgramAccount {
    pubkey: String,
    account: AccountData,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct AccountData {
    data: (String, String), // (base64_data, "base64")
    space: u64,
}

// ── Main Entry Point ──────────────────────────────────────────

pub async fn run(l1_public_key: &str) -> Result<()> {
    let l1_bytes =
        hex::decode(l1_public_key).context("L1 public key must be valid hex (64 chars)")?;
    if l1_bytes.len() != 32 {
        bail!("L1 public key must be exactly 64 hex characters (32 bytes)");
    }

    println!();
    println!("  MISAKA Validator Staking Inspector");
    println!("  ══════════════════════════════════");
    println!(
        "  L1 Key:  {}...{}",
        &l1_public_key[..24],
        &l1_public_key[56..]
    );
    println!("  Program: {}", PROGRAM_ID);
    println!();
    println!("  Querying Solana mainnet (on-chain, tamper-proof)...");

    // ── Fetch all program accounts ──
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("failed to build HTTP client")?;

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getProgramAccounts",
        "params": [PROGRAM_ID, {"encoding": "base64"}],
    });

    let resp: serde_json::Value = client
        .post(SOLANA_RPC)
        .json(&body)
        .send()
        .await
        .context("Solana RPC request failed")?
        .json()
        .await
        .context("failed to parse Solana RPC response")?;

    let accounts = resp
        .get("result")
        .and_then(|r| r.as_array())
        .ok_or_else(|| anyhow::anyhow!("no result from Solana RPC"))?;

    println!("  Found {} program accounts", accounts.len());
    println!();

    // ── Step 1: Find registration (contains L1 public key) ──
    let mut user_bytes: Option<Vec<u8>> = None;
    let mut reg_account = String::new();
    let mut node_name = String::new();

    for acc in accounts {
        let raw = decode_account_data(acc)?;
        if raw.len() < 104 {
            continue;
        }
        if raw[72..104] == l1_bytes[..] || raw.windows(32).any(|w| w == &l1_bytes[..]) {
            user_bytes = Some(raw[8..40].to_vec());
            reg_account = acc["pubkey"].as_str().unwrap_or("").to_string();

            // Extract node name (offset 104, null-terminated, up to 64 bytes)
            if raw.len() >= 168 {
                let name_raw = &raw[104..168];
                let end = name_raw.iter().position(|&b| b == 0).unwrap_or(64);
                node_name = String::from_utf8_lossy(&name_raw[..end]).to_string();
            }
            break;
        }
    }

    let user_bytes = match user_bytes {
        Some(ub) => ub,
        None => {
            println!("  ❌ Validator NOT FOUND on-chain.");
            println!("     L1 key {} is not registered.", &l1_public_key[..32]);
            println!("     Register at https://misakastake.com first.");
            return Ok(());
        }
    };

    let user_wallet = b58encode(&user_bytes);
    println!("  ── Validator Registration ─────────────────────────");
    println!("  Account:  {}", reg_account);
    println!("  Wallet:   {}", user_wallet);
    println!(
        "  Node:     {}",
        if node_name.is_empty() {
            "(not set)"
        } else {
            &node_name
        }
    );
    println!("  L1 Key:   {}", l1_public_key);
    println!();

    // ── Step 2: Find total stake (117-byte account, offset 72) ──
    let mut total_staked: u64 = 0;

    for acc in accounts {
        let space = acc["account"]["space"].as_u64().unwrap_or(0);
        if space != 117 {
            continue;
        }
        let raw = decode_account_data(acc)?;
        if raw.len() >= 80 && raw[8..40] == user_bytes[..] {
            total_staked = u64::from_le_bytes(raw[72..80].try_into().unwrap_or([0; 8]));
            break;
        }
    }

    // ── Step 3: Find staking positions (200-byte accounts, offset 96) ──
    let mut positions: Vec<(String, u64)> = Vec::new();

    for acc in accounts {
        let space = acc["account"]["space"].as_u64().unwrap_or(0);
        if space != 200 {
            continue;
        }
        let raw = decode_account_data(acc)?;
        if raw.len() >= 104 && raw[8..40] == user_bytes[..] {
            let amt = u64::from_le_bytes(raw[96..104].try_into().unwrap_or([0; 8]));
            let pubkey = acc["pubkey"].as_str().unwrap_or("").to_string();
            positions.push((pubkey, amt));
        }
    }

    // ── Display Results ──
    let total_misaka = total_staked as f64 / DECIMALS;
    println!("  ── On-Chain Staking Data (tamper-proof) ──────────");
    println!("  TOTAL STAKED:     {:>14.0} MISAKA", total_misaka);

    if !positions.is_empty() {
        println!();
        println!("  Positions:");
        for (i, (pk, amt)) in positions.iter().enumerate() {
            let m = *amt as f64 / DECIMALS;
            println!("    #{}: {:>14.4} MISAKA  ({}...)", i, m, &pk[..20]);
        }
    }

    println!();

    // ── Security Status ──
    let min_stake: f64 = 10_000_000.0;
    let status = if total_misaka >= min_stake {
        "Active ✅"
    } else {
        "BELOW MINIMUM ⚠️"
    };

    println!("  ══════════════════════════════════════════════════");
    println!("  STATUS:           {}", status);
    println!("  MIN REQUIRED:     10,000,000 MISAKA");
    println!("  ══════════════════════════════════════════════════");

    if total_misaka < min_stake {
        let deficit = min_stake - total_misaka;
        println!();
        println!("  ⚠️  Need {:.0} more MISAKA.", deficit);
        println!("     Stake at https://misakastake.com");
    }

    println!();
    println!("  ── Security Note ──");
    println!("  This data is read directly from Solana mainnet.");
    println!("  Account data is owned by program {}", &PROGRAM_ID[..16]);
    println!("  and CANNOT be modified by anyone except the program.");
    println!("  Amounts are enforced on-chain by the staking smart contract.");
    println!();

    Ok(())
}

/// Decode base64 account data from Solana RPC response.
fn decode_account_data(acc: &serde_json::Value) -> Result<Vec<u8>> {
    use base64::Engine;
    let b64 = acc["account"]["data"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|s| s.as_str())
        .unwrap_or("");
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("failed to decode base64 account data")
}
