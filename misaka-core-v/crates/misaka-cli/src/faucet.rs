//! Faucet — request testnet tokens and optionally register UTXO in wallet state.

use anyhow::Result;
use crate::wallet_state::WalletState;

/// Wallet key file (just enough fields to read).
#[derive(serde::Deserialize)]
struct WalletKeyFile {
    address: String,
    key_image: String,
    #[serde(default)]
    name: String,
}

pub async fn run(address: &str, rpc_url: &str, wallet_key_path: Option<&str>) -> Result<()> {
    println!("🚰 Requesting testnet tokens...");
    println!("   Address: {}", address);
    println!("   Node:    {}", rpc_url);

    let client = crate::rpc_client::RpcClient::new(rpc_url)?;
    let body = serde_json::json!({ "address": address });
    let result = client.post_json("/api/faucet", &body).await?;

    let success = result["success"].as_bool().unwrap_or(false);
    if success {
        let amount = result["amount"].as_u64().unwrap_or(0);
        let tx_hash = result["txHash"].as_str().unwrap_or("?");
        println!();
        println!("✅ Faucet drip successful!");
        println!("   Amount:  {} MISAKA", amount);
        println!("   TX Hash: {}", tx_hash);
        println!("   Status:  pending (will be included in next block)");

        // Register UTXO in wallet state if wallet key path provided
        if let Some(key_path) = wallet_key_path {
            match register_faucet_utxo(key_path, tx_hash, amount, address) {
                Ok(balance) => {
                    println!("   💰 Wallet updated: balance = {} MISAKA", balance);
                }
                Err(e) => {
                    println!("   ⚠  Could not update wallet state: {}", e);
                    println!("      You may need to register this UTXO manually.");
                }
            }
        } else {
            println!();
            println!("   💡 Tip: Use --wallet <key_file> to auto-track this UTXO for transfers.");
        }
    } else {
        let error = result["error"].as_str().unwrap_or("unknown error");
        println!();
        println!("❌ Faucet request failed: {}", error);
    }

    Ok(())
}

fn register_faucet_utxo(key_path: &str, tx_hash: &str, amount: u64, address: &str) -> Result<u64> {
    // Load wallet key to get master info
    let key_json = std::fs::read_to_string(key_path)?;
    let wallet: WalletKeyFile = serde_json::from_str(&key_json)?;

    // Load or create wallet state
    let mut state = WalletState::load_or_create(key_path, &wallet.name, &wallet.address)?;

    // Faucet sends to the provided address.
    // If it matches master address → child_index=0
    // Otherwise it could be a child address (future enhancement)
    let child_index = if address == wallet.address { 0 } else { state.next_child() };
    let key_image = if child_index == 0 {
        wallet.key_image.clone()
    } else {
        // Derive child key to get its key image
        let master_sk_bytes = hex::decode(&{
            // Re-read the full key file for ml_dsa_sk
            #[derive(serde::Deserialize)]
            struct Full { ml_dsa_sk: String }
            let f: Full = serde_json::from_str(&key_json)?;
            f.ml_dsa_sk
        })?;
        let child = misaka_pqc::pq_ring::SpendingKeypair::derive_child(&master_sk_bytes, child_index)
            .map_err(|e| anyhow::anyhow!("child key derivation failed: {}", e))?;
        hex::encode(child.key_image)
    };

    state.register_utxo(tx_hash, 0, amount, child_index, &key_image, address);
    state.save(key_path)?;

    Ok(state.balance)
}

// HTTP client provided by crate::rpc_client::RpcClient
