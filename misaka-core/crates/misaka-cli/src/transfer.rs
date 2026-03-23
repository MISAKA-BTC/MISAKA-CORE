//! Transfer command — build a MISAKA transaction with real on-chain decoys.
//!
//! # Security Properties
//!
//! - **No dummy decoys**: Ring members are real UTXOs fetched from the chain.
//! - **Same-amount ring**: All ring members have identical amounts (protocol rule).
//! - **reqwest HTTP client**: Proper timeout, status validation.
//! - **Wallet state = cache**: Chain scan is the source of truth.

use anyhow::{bail, Context, Result};
use misaka_pqc::ki_proof::{canonical_strong_ki, prove_key_image};
use misaka_pqc::pq_ring::{derive_public_param, ring_sign, Poly, SpendingKeypair, DEFAULT_A_SEED};
use misaka_pqc::pq_sign::MlDsaSecretKey;
use sha3::{Digest, Sha3_256};
use std::fs;

use crate::rpc_client::RpcClient;
use crate::wallet_state::WalletState;

/// Minimum ring size required by consensus.
const MIN_RING_SIZE: usize = 4;

/// Wallet key file (matches keygen output).
#[derive(serde::Deserialize)]
struct WalletKeyFile {
    address: String,
    ml_dsa_sk: String,
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

/// A candidate decoy UTXO fetched from the chain.
#[derive(Debug, Clone, serde::Deserialize)]
struct ChainUtxo {
    tx_hash: String,
    output_index: u32,
    amount: u64,
    spending_pubkey: Option<String>,
}

pub async fn run(
    key_path: &str,
    to_address: &str,
    amount: u64,
    fee: u64,
    rpc_url: &str,
) -> Result<()> {
    println!("💸 Building MISAKA transfer...");
    println!("   To:     {}", to_address);
    println!("   Amount: {} MISAKA", amount);
    println!("   Fee:    {} MISAKA", fee);

    let client = RpcClient::new(rpc_url)?;

    // 1. Load wallet key
    let key_json = fs::read_to_string(key_path).context("failed to read wallet key file")?;
    let wallet: WalletKeyFile =
        serde_json::from_str(&key_json).context("failed to parse wallet key file")?;
    let master_sk_bytes = hex::decode(&wallet.ml_dsa_sk).context("invalid hex in ml_dsa_sk")?;
    println!("   From:   {}", wallet.address);

    // 2. Sync wallet state from chain (chain is source of truth)
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
        &input_key_image_hex[..16]
    );
    if change > 0 {
        println!("   Change: {} MISAKA", change);
    }

    // 4. Get the spending keypair for the input UTXO
    let spending = if input_child_index == 0 {
        let ml_dsa_sk = MlDsaSecretKey::from_bytes(&master_sk_bytes)
            .map_err(|e| anyhow::anyhow!("invalid secret key: {}", e))?;
        SpendingKeypair::from_ml_dsa(ml_dsa_sk)
            .map_err(|e| anyhow::anyhow!("spending keypair derivation failed: {}", e))?
    } else {
        SpendingKeypair::derive_child(&master_sk_bytes, input_child_index)
            .map_err(|e| anyhow::anyhow!("child key derivation failed: {}", e))?
    };

    // Verify key image matches
    let (_, canonical_ki) = canonical_strong_ki(&spending.public_poly, &spending.secret_poly);
    let computed_ki = hex::encode(canonical_ki);
    if computed_ki != input_key_image_hex {
        bail!(
            "key image mismatch for child #{}: expected {}, got {}",
            input_child_index,
            &input_key_image_hex[..16],
            &computed_ki[..16]
        );
    }

    // 5. Fetch REAL same-amount decoys from chain
    println!("   Fetching same-amount decoys from chain...");
    let decoys = fetch_same_amount_decoys(
        &client,
        input_amount,
        &input_tx_hash,
        input_output_index,
        MIN_RING_SIZE - 1,
    )
    .await?;

    if decoys.len() < MIN_RING_SIZE - 1 {
        bail!(
            "insufficient same-amount UTXOs for ring: need {} decoys, found {} \
             (amount={}). Wait for more transactions or use a different UTXO.",
            MIN_RING_SIZE - 1,
            decoys.len(),
            input_amount
        );
    }

    // 6. Build ring with real pubkeys
    let a = derive_public_param(&DEFAULT_A_SEED);
    let ring_size = 1 + decoys.len();
    println!("   Building ring signature (ring_size={})...", ring_size);

    let our_pubkey = spending.public_poly.clone();

    // Parse decoy spending pubkeys into Poly
    let decoy_pks: Vec<Poly> = decoys
        .iter()
        .map(|d| {
            let pk_hex = d
                .spending_pubkey
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("decoy UTXO missing spending_pubkey"))?;
            let pk_bytes = hex::decode(pk_hex).context("invalid hex in decoy spending_pubkey")?;
            Poly::from_bytes(&pk_bytes)
                .map_err(|e| anyhow::anyhow!("invalid decoy pubkey poly: {}", e))
        })
        .collect::<Result<Vec<_>>>()?;

    // Randomize signer position within the ring (critical for anonymity)
    let signer_index = {
        use rand::Rng;
        rand::Rng::gen_range(&mut rand::rngs::OsRng, 0..ring_size)
    };

    let mut ring_pks = Vec::with_capacity(ring_size);
    let mut ring_members_json = Vec::with_capacity(ring_size);

    for i in 0..ring_size {
        if i == signer_index {
            ring_pks.push(our_pubkey.clone());
            ring_members_json.push(serde_json::json!({
                "txHash": input_tx_hash,
                "outputIndex": input_output_index,
            }));
        } else {
            let decoy_idx = if i < signer_index { i } else { i - 1 };
            ring_pks.push(decoy_pks[decoy_idx].clone());
            ring_members_json.push(serde_json::json!({
                "txHash": decoys[decoy_idx].tx_hash,
                "outputIndex": decoys[decoy_idx].output_index,
            }));
        }
    }

    // 7. Prepare change output
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

    // 8. Build outputs
    let mut outputs = vec![serde_json::json!({ "amount": amount, "address": to_address })];
    if let Some((_, ref addr, _)) = change_info {
        outputs.push(serde_json::json!({ "amount": change, "address": addr }));
    }

    // 9. Build transaction body with REAL ring members
    let tx_body = serde_json::json!({
        "version": 1,
        "inputs": [{
            "ringMembers": ring_members_json,
            "keyImage": hex::encode(canonical_ki),
        }],
        "outputs": outputs,
        "fee": fee,
    });

    // 10. Compute signing digest
    let digest: [u8; 32] = {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:tx:sign:v1:");
        h.update(serde_json::to_vec(&tx_body)?);
        h.finalize().into()
    };

    // 11. Sign with ring signature at randomized position
    println!("   Signing transaction...");
    let sig = ring_sign(&a, &ring_pks, signer_index, &spending.secret_poly, &digest)?;

    // 12. Generate KI proof
    println!("   Generating key image proof...");
    let ki_proof = prove_key_image(
        &a,
        &spending.secret_poly,
        &spending.public_poly,
        &canonical_ki,
    )?;

    // 12.5. Generate CompositeProof (balance + range proofs)
    //
    // This attaches a lattice-based ZK proof proving:
    // - Balance conservation: input = outputs + fee
    // - Range: each output amount is in [0, 2^64)
    // - Binding: proof is tied to this specific TX + nullifiers
    //
    // The ring signature (step 11) proves spending authority.
    // The CompositeProof (step 12.5) proves amount correctness.
    // Together they provide full transaction validity.
    println!("   Generating composite proof (balance + range)...");
    let composite_zk_proof = {
        use misaka_pqc::bdlop::{BdlopCommitment, BdlopCrs, BlindingFactor};
        use misaka_pqc::composite_proof::{prove_composite, OutputWitness, SCHEME_COMPOSITE};

        let crs = BdlopCrs::default_crs();

        // Input commitment
        let in_blind = BlindingFactor::random();
        let in_commitment = BdlopCommitment::commit(&crs, &in_blind, input_amount)?;

        // Output witnesses
        let mut out_witnesses = vec![OutputWitness {
            amount,
            blinding: BlindingFactor::random(),
        }];
        if change > 0 {
            out_witnesses.push(OutputWitness {
                amount: change,
                blinding: BlindingFactor::random(),
            });
        }

        // Fee
        let fee_blind = BlindingFactor::random();

        // TX digest for binding
        let tx_digest: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(b"MISAKA:composite:bind:v1:");
            h.update(&canonical_ki);
            h.update(&amount.to_le_bytes());
            h.update(&fee.to_le_bytes());
            h.finalize().into()
        };

        let proof = prove_composite(
            &crs,
            &tx_digest,
            &[in_commitment],
            &[in_blind],
            &out_witnesses,
            fee,
            &fee_blind,
            &[canonical_ki],
        )?;

        let proof_bytes = proof.to_bytes();
        println!(
            "   CompositeProof: {} bytes (balance + {} range proofs)",
            proof_bytes.len(),
            out_witnesses.len(),
        );

        Some(serde_json::json!({
            "backendTag": SCHEME_COMPOSITE,
            "proofBytes": hex::encode(&proof_bytes),
        }))
    };

    // 13. Build submission payload
    let mut submit_body = serde_json::json!({
        "version": 1,
        "inputs": [{
            "ringSize": ring_pks.len(),
            "ringMembers": ring_members_json,
            "ringSignature": hex::encode(sig.to_bytes()),
            "keyImage": hex::encode(canonical_ki),
            "kiProof": hex::encode(ki_proof.to_bytes()),
        }],
        "outputs": outputs,
        "fee": fee,
        "inputCount": 1,
        "outputCount": outputs.len(),
        "keyImages": [hex::encode(canonical_ki)],
    });

    // Attach CompositeProof if generated
    if let Some(zk_proof) = composite_zk_proof {
        submit_body["zkProof"] = zk_proof;
    }

    // 14. Submit via reqwest
    println!("   Submitting to {}...", rpc_url);
    let result = client.post_json("/api/submit_tx", &submit_body).await?;

    let accepted = result["accepted"].as_bool().unwrap_or(false);
    let tx_hash = result["txHash"].as_str().unwrap_or("?");

    if accepted {
        println!();
        println!("✅ Transaction submitted successfully!");
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

/// Fetch same-amount UTXO decoys from the chain via RPC.
async fn fetch_same_amount_decoys(
    client: &RpcClient,
    target_amount: u64,
    exclude_tx: &str,
    exclude_idx: u32,
    count: usize,
) -> Result<Vec<ChainUtxo>> {
    let resp = client
        .post_json(
            "/api/get_decoy_utxos",
            &serde_json::json!({
                "amount": target_amount,
                "count": count + 4,
                "excludeTxHash": exclude_tx,
                "excludeOutputIndex": exclude_idx,
            }),
        )
        .await?;

    let utxos_raw = resp["utxos"].as_array().ok_or_else(|| {
        anyhow::anyhow!(
            "RPC get_decoy_utxos: missing 'utxos' array. Node may not support decoy selection."
        )
    })?;

    let mut decoys: Vec<ChainUtxo> = Vec::new();
    for u in utxos_raw {
        let tx_hash = u["txHash"].as_str().unwrap_or_default().to_string();
        let output_index = u["outputIndex"].as_u64().unwrap_or(0) as u32;
        let amount = u["amount"].as_u64().unwrap_or(0);
        let spending_pubkey = u["spendingPubkey"].as_str().map(|s| s.to_string());

        if tx_hash == exclude_tx && output_index == exclude_idx {
            continue;
        }
        if amount != target_amount {
            continue;
        }
        if spending_pubkey.is_none() {
            continue;
        }

        decoys.push(ChainUtxo {
            tx_hash,
            output_index,
            amount,
            spending_pubkey,
        });
        if decoys.len() >= count {
            break;
        }
    }

    Ok(decoys)
}

/// Sync wallet state from chain (chain = source of truth, local = cache).
async fn sync_wallet_from_chain(client: &RpcClient, state: &mut WalletState) -> Result<()> {
    let resp = match client
        .post_json(
            "/api/get_address_outputs",
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

    if let Some(outputs) = resp["outputs"].as_array() {
        let master_addr = state.master_address.clone();
        for o in outputs {
            let tx_hash = o["txHash"].as_str().unwrap_or_default();
            let output_index = o["outputIndex"].as_u64().unwrap_or(0) as u32;
            let amount = o["amount"].as_u64().unwrap_or(0);
            let key_image = o["keyImage"].as_str().unwrap_or_default();

            if !state
                .utxos
                .iter()
                .any(|u| u.tx_hash == tx_hash && u.output_index == output_index)
            {
                state.register_utxo(tx_hash, output_index, amount, 0, key_image, &master_addr);
            }
        }
    }

    // Reconcile spent status against chain nullifier set
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
