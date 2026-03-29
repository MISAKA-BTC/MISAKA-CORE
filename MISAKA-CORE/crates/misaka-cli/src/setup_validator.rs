//! Interactive Validator Setup — SR21 Onboarding Flow
//!
//! ```text
//! Step 1: Create / Load MISAKA Wallet (ML-DSA-65)
//! Step 2: Generate L1 Validator Key (block signing)
//! Step 3: Display Solana Staking Instructions
//! Step 4: Verify 10M+ MISAKA Stake On-Chain
//! Step 5: Output misaka-node Startup Command
//! ```

use anyhow::{Context, Result};
use std::path::Path;

const MIN_STAKE_MISAKA: u64 = 10_000_000; // 10M MISAKA
const STAKING_PROGRAM_DEFAULT: &str = "27WjgCAWkkjS4H4jqytkKQoCrAN3qgzjp6f6pXLdP8hG";

pub async fn run(data_dir: &str, chain_id: u32, validator_index: usize) -> Result<()> {
    let data_path = Path::new(data_dir);
    std::fs::create_dir_all(data_path)?;

    println!();
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  MISAKA Network — SR21 Validator Setup                      ║");
    println!("║  Post-Quantum • 21 Super Representatives • Dual-Lane DAG   ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // ═══ Step 1: Wallet ═══
    println!("━━━ Step 1/5: MISAKA Wallet (ML-DSA-65) ━━━");
    println!();

    let wallet_key_path = data_path.join("wallet.key.json");
    let wallet_pub_path = data_path.join("wallet.pub.json");

    let (wallet_address, wallet_pk_hex) = if wallet_key_path.exists() {
        println!("  ✅ Wallet found: {}", wallet_key_path.display());
        let pub_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&wallet_pub_path)
                .context("wallet.pub.json not found — re-run keygen")?
        )?;
        let addr = pub_json["address"].as_str().unwrap_or("").to_string();
        let pk = pub_json["ml_dsa_pk"].as_str().unwrap_or("").to_string();
        println!("  Address: {}", addr);
        (addr, pk)
    } else {
        println!("  ℹ  No wallet found. Creating new ML-DSA-65 keypair...");
        // Use keygen module
        let output = data_path.join("wallet").to_string_lossy().to_string();
        crate::keygen::run(&output, "validator", chain_id)?;
        let pub_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(&wallet_pub_path)?
        )?;
        let addr = pub_json["address"].as_str().unwrap_or("").to_string();
        let pk = pub_json["ml_dsa_pk"].as_str().unwrap_or("").to_string();
        println!("  ✅ Wallet created: {}", addr);
        (addr, pk)
    };
    println!();

    // ═══ Step 2: L1 Validator Key ═══
    println!("━━━ Step 2/5: L1 Validator Key (Block Signing) ━━━");
    println!();

    let enc_key_path = data_path.join(format!("dag_validator_{}.enc.json", validator_index));
    let pub_key_path = data_path.join("l1-public-key.json");

    let l1_pubkey_hex = if enc_key_path.exists() {
        println!("  ✅ Validator key found: {}", enc_key_path.display());
        if pub_key_path.exists() {
            let pk_json: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(&pub_key_path)?
            )?;
            let hex = pk_json["l1PublicKey"].as_str().unwrap_or("").to_string();
            println!("  L1 Public Key: {}...", &hex[..32.min(hex.len())]);
            hex
        } else {
            println!("  ⚠  l1-public-key.json not found. Run misaka-node --keygen-only first.");
            String::new()
        }
    } else {
        println!("  ℹ  No validator key found.");
        println!("  Run the following command to generate:");
        println!();
        println!("    export MISAKA_VALIDATOR_PASSPHRASE=\"your-secure-passphrase\"");
        println!("    misaka-node --keygen-only --name validator-{} --data-dir {}", validator_index, data_dir);
        println!();
        println!("  This will create:");
        println!("    - {} (encrypted validator key)", enc_key_path.display());
        println!("    - {} (public key for staking)", pub_key_path.display());
        String::new()
    };
    println!();

    // ═══ Step 3: Solana Staking Instructions ═══
    println!("━━━ Step 3/5: Solana Staking (10M+ MISAKA Required) ━━━");
    println!();
    println!("  To become an SR21 validator, you must stake at least");
    println!("  10,000,000 MISAKA on the Solana staking program.");
    println!();
    println!("  Staking Program: {}", STAKING_PROGRAM_DEFAULT);
    println!("  Staking Site:    https://misakastake.com");
    println!();
    println!("  Steps:");
    println!("    1. Go to https://misakastake.com");
    println!("    2. Connect your Solana wallet (Phantom/Solflare)");
    println!("    3. Enter your L1 Public Key:");
    if !l1_pubkey_hex.is_empty() {
        println!("       {}", l1_pubkey_hex);
    } else {
        println!("       (generate with Step 2 first)");
    }
    println!("    4. Stake 10,000,000+ MISAKA tokens");
    println!("    5. Copy the staking transaction signature");
    println!();

    // ═══ Step 4: Verify Stake ═══
    println!("━━━ Step 4/5: Verify Stake On-Chain ━━━");
    println!();

    let solana_rpc = std::env::var("MISAKA_SOLANA_RPC_URL").unwrap_or_default();
    if solana_rpc.is_empty() {
        println!("  ⚠  MISAKA_SOLANA_RPC_URL not set.");
        println!("  Set it to verify your stake:");
        println!("    export MISAKA_SOLANA_RPC_URL=\"https://api.mainnet-beta.solana.com\"");
        println!();
        println!("  After setting, run:");
        println!("    misaka-cli check-stake --key-file {}", pub_key_path.display());
    } else {
        println!("  Solana RPC: {}", &solana_rpc[..40.min(solana_rpc.len())]);
        if !l1_pubkey_hex.is_empty() {
            println!("  Checking stake for L1 key: {}...", &l1_pubkey_hex[..16]);
            // Try to verify
            match crate::check_stake::run(&l1_pubkey_hex).await {
                Ok(()) => println!("  ✅ Stake verification complete (see above)"),
                Err(e) => println!("  ⚠  Stake check failed: {}", e),
            }
        } else {
            println!("  ⚠  No L1 key — generate with Step 2 first.");
        }
    }
    println!();

    // ═══ Step 5: Node Startup Command ═══
    println!("━━━ Step 5/5: Start Validator Node ━━━");
    println!();
    println!("  Once staked, start your validator with:");
    println!();
    println!("  export MISAKA_VALIDATOR_PASSPHRASE=\"your-passphrase\"");
    println!("  export MISAKA_SOLANA_RPC_URL=\"https://api.mainnet-beta.solana.com\"");
    println!();
    println!("  misaka-node \\");
    println!("    --validator \\");
    println!("    --validator-index {} \\", validator_index);
    println!("    --validators 21 \\");
    println!("    --data-dir {} \\", data_dir);
    println!("    --chain-id {} \\", chain_id);
    println!("    --stake-signature <YOUR_SOLANA_TX_SIGNATURE> \\");
    println!("    --advertise-addr <YOUR_PUBLIC_IP>:6690");
    println!();

    // ═══ Summary ═══
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  SR21 Validator Setup Summary                               ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Wallet:       {} ║", if wallet_address.is_empty() { "❌ Not created" } else { "✅ Ready      " });
    println!("║  L1 Key:       {} ║", if l1_pubkey_hex.is_empty() { "❌ Not created" } else { "✅ Ready      " });
    println!("║  Stake (10M+): {} ║", if solana_rpc.is_empty() { "⏳ Unverified " } else { "⏳ Check above" });
    println!("║  Min Stake:    10,000,000 MISAKA                            ║");
    println!("║  SR Index:     {} / 21                                       ║", validator_index);
    println!("║  Chain ID:     {} ({})                          ║",
        chain_id,
        if chain_id == 1 { "mainnet " } else { "testnet " }
    );
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Next steps:");
    if l1_pubkey_hex.is_empty() {
        println!("    1. Generate L1 validator key (Step 2)");
        println!("    2. Stake 10M+ MISAKA on misakastake.com");
        println!("    3. Start misaka-node with --validator");
    } else if solana_rpc.is_empty() {
        println!("    1. Stake 10M+ MISAKA on misakastake.com");
        println!("    2. Set MISAKA_SOLANA_RPC_URL");
        println!("    3. Start misaka-node with --validator");
    } else {
        println!("    1. Verify stake amount (10M+ MISAKA)");
        println!("    2. Start misaka-node with --validator");
    }
    println!();

    Ok(())
}
