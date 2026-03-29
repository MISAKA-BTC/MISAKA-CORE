//! Faucet — request testnet tokens and optionally register UTXO in wallet state.

use crate::wallet_state::WalletState;
use anyhow::Result;
use misaka_pqc::ki_proof::canonical_strong_ki;
use misaka_pqc::pq_ring::SpendingKeypair;

/// Wallet key file (just enough fields to read).
#[derive(serde::Deserialize)]
struct WalletKeyFile {
    address: String,
    key_image: String,
    #[serde(default, alias = "canonical_key_image")]
    tx_key_image: Option<String>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    spending_pubkey: Option<String>,
    #[serde(default)]
    ml_dsa_sk: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WalletAddressBinding {
    child_index: u32,
    key_image: String,
    spending_pubkey: String,
}

pub async fn run(
    address: &str,
    rpc_url: &str,
    wallet_key_path: Option<&str>,
    spending_pubkey_override: Option<&str>,
) -> Result<()> {
    println!("🚰 Requesting testnet tokens...");
    println!("   Address: {}", address);
    println!("   Node:    {}", rpc_url);

    let client = crate::rpc_client::RpcClient::new(rpc_url)?;
    let request_spending_pubkey = if let Some(spending_pubkey) = spending_pubkey_override {
        Some(spending_pubkey.to_string())
    } else if let Some(key_path) = wallet_key_path {
        let wallet = load_wallet_key(key_path)?;
        let state = WalletState::load_or_create(key_path, &wallet.name, &wallet.address)?;
        resolve_wallet_binding(&wallet, &state, address)?.map(|binding| binding.spending_pubkey)
    } else {
        None
    };
    let body = if let Some(spending_pubkey) = request_spending_pubkey {
        serde_json::json!({
            "address": address,
            "spendingPubkey": spending_pubkey,
        })
    } else {
        serde_json::json!({ "address": address })
    };
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
    let wallet = load_wallet_key(key_path)?;
    let mut state = WalletState::load_or_create(key_path, &wallet.name, &wallet.address)?;
    let binding = resolve_wallet_binding(&wallet, &state, address)?
        .ok_or_else(|| anyhow::anyhow!(
            "address {} is not recognized as the wallet master address or an existing derived child address",
            address
        ))?;

    state.register_utxo(
        tx_hash,
        0,
        amount,
        binding.child_index,
        &binding.key_image,
        address,
    );
    state.save(key_path)?;

    Ok(state.balance)
}

fn load_wallet_key(key_path: &str) -> Result<WalletKeyFile> {
    let key_json = std::fs::read_to_string(key_path)?;
    Ok(serde_json::from_str(&key_json)?)
}

fn resolve_wallet_binding(
    wallet: &WalletKeyFile,
    state: &WalletState,
    address: &str,
) -> Result<Option<WalletAddressBinding>> {
    if address == wallet.address {
        let spending_pubkey = wallet
            .spending_pubkey
            .clone()
            .ok_or_else(|| anyhow::anyhow!("wallet key file missing spending_pubkey"))?;
        return Ok(Some(WalletAddressBinding {
            child_index: 0,
            key_image: wallet
                .tx_key_image
                .clone()
                .unwrap_or_else(|| wallet.key_image.clone()),
            spending_pubkey,
        }));
    }

    let master_sk_hex = match wallet.ml_dsa_sk.as_deref() {
        Some(v) => v,
        None => return Ok(None),
    };
    let master_sk_bytes = hex::decode(master_sk_hex)?;
    let upper = state.next_child_index.saturating_sub(1);

    for idx in 1..=upper {
        let child = derive_child_spending(&master_sk_bytes, idx)?;
        if child.derive_address() == address {
            let (_, tx_key_image) = canonical_strong_ki(&child.public_poly, &child.secret_poly);
            return Ok(Some(WalletAddressBinding {
                child_index: idx,
                key_image: hex::encode(tx_key_image),
                spending_pubkey: hex::encode(child.ml_dsa_pk()),
            }));
        }
    }

    Ok(None)
}

fn derive_child_spending(master_sk_bytes: &[u8], index: u32) -> Result<SpendingKeypair> {
    SpendingKeypair::derive_child(master_sk_bytes, index)
        .map_err(|e| anyhow::anyhow!("child key derivation failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_pqc::pq_sign::MlDsaKeypair;

    fn sample_wallet_and_state() -> (WalletKeyFile, WalletState) {
        let kp = MlDsaKeypair::generate();
        let spending = SpendingKeypair::from_ml_dsa(kp.secret_key).unwrap();
        let (_, tx_key_image) = canonical_strong_ki(&spending.public_poly, &spending.secret_poly);
        let wallet = WalletKeyFile {
            address: spending.derive_address(),
            key_image: hex::encode(spending.key_image),
            tx_key_image: Some(hex::encode(tx_key_image)),
            name: "test".into(),
            spending_pubkey: Some(hex::encode(spending.public_poly.to_bytes())),
            ml_dsa_sk: Some(hex::encode(spending.ml_dsa_sk.as_bytes())),
        };
        let mut state = WalletState::new(&wallet.name, &wallet.address);
        state.next_child_index = 3;
        (wallet, state)
    }

    #[test]
    fn test_resolve_wallet_binding_master() {
        let (wallet, state) = sample_wallet_and_state();
        let binding = resolve_wallet_binding(&wallet, &state, &wallet.address)
            .unwrap()
            .unwrap();
        assert_eq!(binding.child_index, 0);
        assert_eq!(binding.key_image, wallet.tx_key_image.clone().unwrap());
        assert_eq!(binding.spending_pubkey, wallet.spending_pubkey.unwrap());
    }

    #[test]
    fn test_resolve_wallet_binding_known_child() {
        let (wallet, state) = sample_wallet_and_state();
        let master_sk_bytes = hex::decode(wallet.ml_dsa_sk.clone().unwrap()).unwrap();
        let child = derive_child_spending(&master_sk_bytes, 2).unwrap();
        let (_, tx_key_image) = canonical_strong_ki(&child.public_poly, &child.secret_poly);
        let binding = resolve_wallet_binding(&wallet, &state, &child.derive_address())
            .unwrap()
            .unwrap();
        assert_eq!(binding.child_index, 2);
        assert_eq!(binding.key_image, hex::encode(tx_key_image));
        assert_eq!(
            binding.spending_pubkey,
            hex::encode(child.public_poly.to_bytes())
        );
    }

    #[test]
    fn test_resolve_wallet_binding_unknown_address() {
        let (wallet, state) = sample_wallet_and_state();
        let binding =
            resolve_wallet_binding(&wallet, &state, "msk1deadbeefdeadbeefdeadbeefdeadbeefdead")
                .unwrap();
        assert!(binding.is_none());
    }

    #[test]
    fn test_resolve_wallet_binding_without_secret_only_matches_master() {
        let (mut wallet, state) = sample_wallet_and_state();
        wallet.ml_dsa_sk = None;
        let binding = resolve_wallet_binding(&wallet, &state, &wallet.address)
            .unwrap()
            .unwrap();
        assert_eq!(binding.child_index, 0);
        let child_binding =
            resolve_wallet_binding(&wallet, &state, "msk1deadbeefdeadbeefdeadbeefdeadbeefdead")
                .unwrap();
        assert!(child_binding.is_none());
    }
}

// HTTP client provided by crate::rpc_client::RpcClient
