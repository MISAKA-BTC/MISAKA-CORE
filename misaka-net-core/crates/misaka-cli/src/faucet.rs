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

    let url = format!("{}/api/faucet", rpc_url);
    let body = serde_json::json!({ "address": address });
    let result = post_json(&url, &body).await?;

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
        let child = misaka_pqc::pq_ring::SpendingKeypair::derive_child(&master_sk_bytes, child_index);
        hex::encode(child.key_image)
    };

    state.register_utxo(tx_hash, 0, amount, child_index, &key_image, address);
    state.save(key_path)?;

    Ok(state.balance)
}

async fn post_json(url: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
    let rest = url.strip_prefix("http://").unwrap_or(url);
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let path = format!("/{}", path);
    let (host, port) = authority.split_once(':')
        .map(|(h, p)| (h.to_string(), p.parse().unwrap_or(3001)))
        .unwrap_or((authority.to_string(), 3001));

    let body_str = serde_json::to_string(body)?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host, port, body_str.len(), body_str,
    );

    let mut stream = tokio::net::TcpStream::connect(format!("{}:{}", host, port)).await?;
    tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes()).await?;

    let mut response = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut response).await?;

    let response_str = String::from_utf8_lossy(&response);
    let body_start = response_str.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let body_text = &response_str[body_start..];

    serde_json::from_str(body_text)
        .map_err(|e| anyhow::anyhow!("JSON parse error: {}", e))
}
