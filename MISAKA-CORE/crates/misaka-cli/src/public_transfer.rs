//! Public (transparent) transfer — on-chain, sender identifiable.
//!
//! # ML-DSA-65 Direct Signature (v10)
//!
//! - **No lattice ZKP proof**: ML-DSA-65 (NIST FIPS 204) direct sign/verify
//! - **No anonymity**: Sender address is visible on-chain
//! - **Key image preserved**: Double-spend prevention via SHA3(secret_poly)
//! - **Fastest path**: pqcrypto C FFI, deterministic, no rejection sampling
//! - **Kaspa-equivalent**: Same UTXO model, PQ-safe signature replaces Schnorr
//!
//! Use this for all standard transfers. For privacy, use --shielded (ZKP).

use anyhow::{bail, Context, Result};
use misaka_pqc::ki_proof::canonical_strong_ki;
use misaka_pqc::pq_ring::SpendingKeypair;
use misaka_pqc::pq_sign::{ml_dsa_sign, MlDsaSecretKey};
use misaka_types::utxo::{
    OutputRef, TxInput, TxOutput, TxType, UtxoTransaction, PROOF_SCHEME_TRANSPARENT, UTXO_TX_VERSION,
};
use sha3::{Digest, Sha3_256};
use std::fs;

use crate::rpc_client::RpcClient;
use crate::wallet_state::WalletState;

/// Wallet key file (matches keygen output).
#[derive(serde::Deserialize)]
struct WalletKeyFile {
    address: String,
    ml_dsa_sk: String,
    #[serde(default)]
    ml_dsa_pk: String,
    #[allow(dead_code)]
    spending_pubkey: String,
    #[allow(dead_code)]
    key_image: String,
    #[allow(dead_code)]
    #[serde(default, alias = "canonical_key_image")]
    tx_key_image: Option<String>,
    #[serde(default)]
    name: String,
}

pub async fn run(
    key_path: &str,
    to_address: &str,
    amount: u64,
    fee: u64,
    rpc_url: &str,
) -> Result<()> {
    println!("📤 Building PUBLIC (transparent) transfer...");
    println!("   To:     {}", to_address);
    println!("   Amount: {} MISAKA", amount);
    println!("   Fee:    {} MISAKA", fee);
    println!("   ⚠  Sender address will be VISIBLE on-chain");

    let client = RpcClient::new(rpc_url)?;

    // 1. Load wallet key
    let key_json = fs::read_to_string(key_path).context("failed to read wallet key file")?;
    let wallet: WalletKeyFile =
        serde_json::from_str(&key_json).context("failed to parse wallet key file")?;
    let master_sk_bytes = hex::decode(&wallet.ml_dsa_sk).context("invalid hex in ml_dsa_sk")?;
    println!("   From:   {}", wallet.address);

    // 2. Sync wallet state
    let mut state = WalletState::load_or_create(key_path, &wallet.name, &wallet.address)?;
    sync_wallet_from_chain(&client, &mut state).await?;
    println!(
        "   Balance: {} MISAKA ({} UTXOs)",
        state.balance,
        state.unspent_utxos().len()
    );

    // 3. Select UTXO to spend
    let selected = state.select_utxo(amount, fee)?;
    let input_amount = selected.amount;
    let input_child_index = selected.child_index;
    let input_key_image_hex = selected.key_image.clone();
    let input_tx_hash = selected.tx_hash.clone();
    let input_output_index = selected.output_index;
    let change = input_amount - amount - fee;

    println!(
        "   Input:  {} MISAKA (child #{}, ki={}...)",
        input_amount,
        input_child_index,
        if input_key_image_hex.len() >= 16 { &input_key_image_hex[..16] } else { &input_key_image_hex }
    );
    if change > 0 {
        println!("   Change: {} MISAKA", change);
    }

    // 4. Get spending keypair with ML-DSA-65 public key
    let spending = if input_child_index == 0 {
        let ml_dsa_sk = MlDsaSecretKey::from_bytes(&master_sk_bytes)
            .map_err(|e| anyhow::anyhow!("invalid secret key: {}", e))?;
        let ml_dsa_pk_bytes = hex::decode(&wallet.ml_dsa_pk)
            .unwrap_or_default();
        SpendingKeypair::from_ml_dsa_pair(ml_dsa_sk, ml_dsa_pk_bytes)
            .map_err(|e| anyhow::anyhow!("spending keypair derivation failed: {}", e))?
    } else {
        SpendingKeypair::derive_child(&master_sk_bytes, input_child_index)
            .map_err(|e| anyhow::anyhow!("child key derivation failed: {}", e))?
    };

    // Verify key image matches (faucet UTXOs may have empty key_image — fill from spending key)
    let (_, canonical_ki) = canonical_strong_ki(&spending.public_poly, &spending.secret_poly);
    let computed_ki = hex::encode(canonical_ki);
    let input_key_image_hex = if input_key_image_hex.is_empty() {
        // Faucet UTXO: chain doesn't store key_image, derive from wallet
        computed_ki.clone()
    } else {
        input_key_image_hex
    };
    if computed_ki != input_key_image_hex {
        bail!(
            "key image mismatch for child #{}",
            input_child_index,
        );
    }

    // 5. ML-DSA-65 direct signature (no ring, no decoys)
    println!("   Signing with ML-DSA-65 (NIST FIPS 204)...");

    let input_ref_json = vec![serde_json::json!({
        "txHash": input_tx_hash,
        "outputIndex": input_output_index,
    })];

    // 6. Prepare change output
    let change_info: Option<(u32, String, String)> = if change > 0 {
        let idx = state.next_child();
        let child = SpendingKeypair::derive_child(&master_sk_bytes, idx)
            .map_err(|e| anyhow::anyhow!("change child key derivation failed: {}", e))?;
        Some((
            idx,
            child.derive_address(),
            hex::encode(child.canonical_key_image()),
        ))
    } else {
        None
    };

    // 7. Build outputs
    let mut outputs = vec![serde_json::json!({ "amount": amount, "address": to_address })];
    if let Some((_, ref addr, _)) = change_info {
        outputs.push(serde_json::json!({ "amount": change, "address": addr }));
    }

    // 8. Build unsigned UtxoTransaction first to compute signing_digest
    let input_tx_hash_bytes: [u8; 32] = hex::decode(&input_tx_hash)
        .map_err(|e| anyhow::anyhow!("invalid input tx hash hex: {}", e))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("input tx hash must be 32 bytes"))?;

    let to_addr_bytes = misaka_types::address::decode_address(&to_address, 2)
        .map_err(|e| anyhow::anyhow!("invalid destination address: {}", e))?;

    let mut tx_outputs = vec![TxOutput {
        amount,
        one_time_address: to_addr_bytes,
        pq_stealth: None,
        spending_pubkey: None,
    }];

    if let Some((_, ref addr, _)) = change_info {
        let change_addr_bytes = misaka_types::address::decode_address(addr, 2)
            .map_err(|e| anyhow::anyhow!("invalid change address: {}", e))?;
        tx_outputs.push(TxOutput {
            amount: change,
            one_time_address: change_addr_bytes,
            pq_stealth: None,
            spending_pubkey: Some(spending.ml_dsa_pk().to_vec()),
        });
    }

    let unsigned_tx = UtxoTransaction {
        version: UTXO_TX_VERSION,
        proof_scheme: PROOF_SCHEME_TRANSPARENT,
        tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            utxo_refs: vec![OutputRef {
                tx_hash: input_tx_hash_bytes,
                output_index: input_output_index,
            }],
            proof: vec![], // empty — will be filled after signing
            key_image: canonical_ki,
            ki_proof: vec![],
        }],
        outputs: tx_outputs.clone(),
        fee,
        extra: vec![],
        zk_proof: None,
    };

    // 9. Compute canonical signing digest (MCS-1 binary, excludes proof bytes)
    let digest = unsigned_tx.signing_digest();

    // 10. Sign with ML-DSA-65 (deterministic, no rejection sampling, FIPS 204)
    let sig = ml_dsa_sign(&spending.ml_dsa_sk, &digest)
        .map_err(|e| anyhow::anyhow!("ML-DSA-65 signing failed: {}", e))?;

    // 11. Build final signed transaction
    let submit_tx = UtxoTransaction {
        version: UTXO_TX_VERSION,
        proof_scheme: PROOF_SCHEME_TRANSPARENT,
        tx_type: TxType::Transfer,
        inputs: vec![TxInput {
            utxo_refs: vec![OutputRef {
                tx_hash: input_tx_hash_bytes,
                output_index: input_output_index,
            }],
            proof: sig.as_bytes().to_vec(),
            key_image: canonical_ki,
            ki_proof: vec![],
        }],
        outputs: tx_outputs,
        fee,
        extra: vec![],
        zk_proof: None,
    };

    let submit_body = serde_json::to_value(&submit_tx)?;

    // 13. Submit
    println!("   Submitting to {}...", rpc_url);
    let result = client.post_json("/api/submit_tx", &submit_body).await?;

    let accepted = result["accepted"].as_bool().unwrap_or(false);
    let tx_hash = result["txHash"].as_str().unwrap_or("?");

    if accepted {
        println!();
        println!("✅ Public transfer submitted successfully!");
        println!("   TX Hash: {}", tx_hash);

        state.mark_spent(&input_key_image_hex);
        if let Some((child_idx, ref addr, ref ki)) = change_info {
            state.register_utxo(tx_hash, 1, change, child_idx, ki, addr);
            println!("   Change:  {} MISAKA → child #{}", change, child_idx);
        }
        state.save(key_path)?;
        println!(
            "   Wallet balance: {} MISAKA ({} UTXOs)",
            state.balance,
            state.unspent_utxos().len()
        );
    } else {
        let error = result["error"].as_str().unwrap_or("unknown error");
        println!();
        println!("❌ Transaction rejected: {}", error);
    }

    Ok(())
}

/// Sync wallet state from chain.
async fn sync_wallet_from_chain(client: &RpcClient, state: &mut WalletState) -> Result<()> {
    let resp = match client
        .post_json(
            "/api/get_utxos_by_address",
            &serde_json::json!({
                "address": state.master_address,
            }),
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("   ⚠ Chain sync failed ({}), using local cache", e);
            return Ok(());
        }
    };

    if let Some(utxos) = resp["utxos"].as_array() {
        let master_addr = state.master_address.clone();
        for o in utxos {
            let tx_hash = o["txHash"].as_str().unwrap_or_default();
            let output_index = o["outputIndex"].as_u64().unwrap_or(0) as u32;
            let amount_val = o["amount"].as_u64().unwrap_or(0);
            let key_image = o["keyImage"].as_str().unwrap_or_default();

            if !state
                .utxos
                .iter()
                .any(|u| u.tx_hash == tx_hash && u.output_index == output_index)
            {
                state.register_utxo(tx_hash, output_index, amount_val, 0, key_image, &master_addr);
            }
        }
    }

    if let Some(spent_kis) = resp["spentKeyImages"].as_array() {
        let spent_set: std::collections::HashSet<&str> =
            spent_kis.iter().filter_map(|v| v.as_str()).collect();
        for utxo in &mut state.utxos {
            if spent_set.contains(utxo.key_image.as_str()) {
                utxo.spent = true;
            }
        }
        state.recalculate_balance();
    }

    Ok(())
}
