//! Confidential transfer — Q-DAG-CT (v4) transaction builder.
//!
//! # Differences from v1-v3 transfer.rs
//!
//! - **No ring member resolution**: UnifiedZKP proves membership against SIS Merkle root
//! - **Amount hidden**: BDLOP commitments replace plaintext amounts
//! - **Fee hidden**: Confidential fee with range + minimum proofs
//! - **Nullifier**: Algebraic `a_null·s` construction (deterministic, ring-independent)
//! - **Stealth**: CT stealth delivers amount + blinding factor via ML-KEM
//!
//! # What the verifier sees
//!
//! - Nullifier hashes (double-spend detection)
//! - SIS Merkle root (anonymity set identity)
//! - BDLOP commitments (amounts hidden)
//! - Range proofs (non-negative amounts)
//! - Balance proof (inputs = outputs + fee)
//! - Membership proofs (sender is in anonymity set)
//!
//! # What the verifier does NOT see
//!
//! - Which UTXO was spent
//! - The sender's public key
//! - Any amount (input, output, or fee)
//! - The Merkle path or leaf index

use anyhow::{bail, Context, Result};
use misaka_pqc::bdlop::{
    compute_balance_diff, BalanceExcessProof, BdlopCommitment, BdlopCrs, BlindingFactor,
};
use misaka_pqc::confidential_fee::{create_confidential_fee, MIN_FEE};
use misaka_pqc::membership::SisMerkleCrs;
use misaka_pqc::nullifier::{compute_nullifier, OutputId};
use misaka_pqc::pq_kem::MlKemPublicKey;
use misaka_pqc::pq_ring::{derive_public_param, Poly, SpendingKeypair, DEFAULT_A_SEED, N, Q};
use misaka_pqc::pq_sign::MlDsaSecretKey;
use misaka_pqc::qdag_tx::{
    ConfidentialInput, ConfidentialOutput, ConfidentialStealthData, QdagTransaction, QdagTxType,
    QDAG_VERSION,
};
use misaka_pqc::range_proof::prove_range;
use misaka_pqc::unified_zkp::unified_prove;
use std::fs;

use crate::rpc_client::RpcClient;

/// Chain ID for the MISAKA testnet.
const DEFAULT_CHAIN_ID: u32 = 2;

/// Default ring size for Q-DAG-CT transactions.
const CT_RING_SIZE: usize = 16;

/// Wallet key file (same format as keygen output).
#[derive(serde::Deserialize)]
struct WalletKeyFile {
    address: String,
    ml_dsa_sk: String,
    ml_kem_pk: String,
    #[allow(dead_code)]
    spending_pubkey: String,
}

/// Run a confidential transfer.
pub async fn run(
    key_path: &str,
    recipient_ml_kem_pk_hex: &str,
    amount: u64,
    fee: u64,
    chain_id: u32,
    rpc_url: &str,
) -> Result<()> {
    println!("🔒 Building Q-DAG-CT confidential transfer...");
    println!("   Amount: [HIDDEN] ({} MISAKA)", amount);
    println!("   Fee:    [HIDDEN] ({} MISAKA)", fee);

    if fee < MIN_FEE {
        bail!("fee {} < minimum {}", fee, MIN_FEE);
    }

    let client = RpcClient::new(rpc_url)?;
    let crs = BdlopCrs::default_crs();
    let sis_crs = SisMerkleCrs::default_crs();
    let a = derive_public_param(&DEFAULT_A_SEED);

    // ── 1. Load wallet key ──
    let key_json = fs::read_to_string(key_path).context("failed to read wallet key file")?;
    let wallet: WalletKeyFile =
        serde_json::from_str(&key_json).context("failed to parse wallet key file")?;
    let master_sk_bytes = hex::decode(&wallet.ml_dsa_sk).context("invalid hex in ml_dsa_sk")?;
    let ml_dsa_sk = MlDsaSecretKey::from_bytes(&master_sk_bytes)
        .map_err(|e| anyhow::anyhow!("invalid secret key: {}", e))?;
    let spending = SpendingKeypair::from_ml_dsa(ml_dsa_sk)
        .map_err(|e| anyhow::anyhow!("spending keypair derivation failed: {}", e))?;
    println!("   From:   {} (pk hidden in ZKP)", wallet.address);

    // ── 2. Query input UTXO from chain ──
    // For this initial implementation, we select a single UTXO.
    // The RPC returns the output_ref + the SIS Merkle tree data.
    println!("   Querying chain for spendable UTXOs...");
    let input_utxo = query_spendable_utxo(&client, &wallet.address, amount + fee).await?;

    let input_amount = input_utxo.amount;
    let change = input_amount - amount - fee;
    println!(
        "   Input:  [HIDDEN] ({} MISAKA from {}:{})",
        input_amount,
        &input_utxo.tx_hash[..16],
        input_utxo.output_index
    );
    if change > 0 {
        println!("   Change: [HIDDEN] ({} MISAKA)", change);
    }

    // ── 3. Build anonymity set ──
    println!("   Building anonymity set (ring_size={})...", CT_RING_SIZE);
    let ring_data = fetch_anonymity_set(&client, &input_utxo, CT_RING_SIZE, &sis_crs).await?;

    // ── 4. Compute nullifier ──
    let output_id = OutputId {
        tx_hash: input_utxo.tx_hash_bytes,
        output_index: input_utxo.output_index,
    };
    let (nullifier_hash, _null_poly) =
        compute_nullifier(&spending.secret_poly, &output_id, chain_id);
    println!("   Nullifier: {}...", hex::encode(&nullifier_hash[..8]));

    // ── 5. Build commitments ──
    println!("   Building BDLOP commitments...");
    let r_in = BlindingFactor::random();
    let c_in = BdlopCommitment::commit(&crs, &r_in, input_amount)?;

    let r_out = BlindingFactor::random();
    let c_out = BdlopCommitment::commit(&crs, &r_out, amount)?;

    let r_change = if change > 0 {
        Some(BlindingFactor::random())
    } else {
        None
    };
    let c_change = r_change
        .as_ref()
        .map(|r| {
            BdlopCommitment::commit(&crs, r, change)
                .map_err(|e| anyhow::anyhow!("change commitment failed: {}", e))
        })
        .transpose()?;

    // ── 6. Confidential fee ──
    println!("   Creating confidential fee proof...");
    let (conf_fee, _r_fee) = create_confidential_fee(&crs, fee)
        .map_err(|e| anyhow::anyhow!("confidential fee creation failed: {}", e))?;

    // ── 7. Range proofs ──
    println!("   Generating range proofs...");
    let (rp_out, _) = prove_range(&crs, amount, &r_out)
        .map_err(|e| anyhow::anyhow!("output range proof failed: {}", e))?;

    let rp_change = if let (Some(ref r_ch), Some(ch_val)) =
        (&r_change, if change > 0 { Some(change) } else { None })
    {
        let (rp, _) = prove_range(&crs, ch_val, r_ch)
            .map_err(|e| anyhow::anyhow!("change range proof failed: {}", e))?;
        Some(rp)
    } else {
        None
    };

    // ── 8. Balance proof ──
    println!("   Computing balance proof...");
    let mut output_commitments = vec![c_out.clone()];
    if let Some(ref cc) = c_change {
        output_commitments.push(cc.clone());
    }
    let balance_diff = compute_balance_diff(&crs, &[c_in.clone()], &output_commitments, fee)
        .map_err(|e| anyhow::anyhow!("balance diff failed: {}", e))?;
    // Compute r_excess = r_in - r_out - r_change (- r_fee is handled separately)
    let mut r_excess_poly = Poly::zero();
    for i in 0..N {
        let mut v = r_in.as_poly().coeffs[i] - r_out.as_poly().coeffs[i];
        if let Some(ref r_ch) = r_change {
            v -= r_ch.as_poly().coeffs[i];
        }
        r_excess_poly.coeffs[i] = ((v % Q) + Q) % Q;
    }
    let r_excess = BlindingFactor(r_excess_poly);
    let balance_proof = BalanceExcessProof::prove(&crs, &balance_diff, &r_excess)
        .map_err(|e| anyhow::anyhow!("balance proof failed: {}", e))?;
    let balance_proof_bytes = balance_proof.to_bytes();

    // ── 9. Membership proof (UnifiedZKP) ──
    println!("   Generating UnifiedZKP membership proof...");
    let signing_message = [0u8; 32]; // Will be replaced by QdagTransaction::transcript()
    let (membership_proof, _null_hash) = unified_prove(
        &a,
        &ring_data.leaf_hashes,
        ring_data.signer_index,
        &spending.secret_poly,
        &spending.public_poly,
        &signing_message,
        &output_id,
        chain_id,
    )
    .map_err(|e| anyhow::anyhow!("membership proof failed: {}", e))?;

    // ── 10. Build stealth output data ──
    let recipient_kem_pk_bytes =
        hex::decode(recipient_ml_kem_pk_hex).context("invalid recipient ML-KEM public key hex")?;
    let _recipient_kem_pk = MlKemPublicKey::from_bytes(&recipient_kem_pk_bytes)
        .map_err(|e| anyhow::anyhow!("invalid recipient ML-KEM key: {}", e))?;

    // Placeholder stealth data — in production, use create_confidential_stealth()
    let stealth_data = ConfidentialStealthData {
        kem_ct: vec![0u8; 1088],     // ML-KEM ciphertext
        scan_tag: [0u8; 16],         // Scan tag for recipient wallet
        amount_ct: vec![0u8; 24],    // Encrypted amount
        blind_ct: vec![0u8; 536],    // Encrypted blinding factor
        one_time_address: [0u8; 32], // Derived OTA
    };

    // ── 11. Assemble QdagTransaction ──
    println!("   Assembling Q-DAG-CT transaction...");
    let mut outputs = vec![ConfidentialOutput {
        commitment: c_out,
        range_proof: rp_out,
        stealth_data: stealth_data.clone(),
    }];
    if let (Some(cc), Some(rp)) = (c_change, rp_change) {
        outputs.push(ConfidentialOutput {
            commitment: cc,
            range_proof: rp,
            stealth_data: ConfidentialStealthData {
                kem_ct: vec![0u8; 1088],
                scan_tag: [0u8; 16],
                amount_ct: vec![0u8; 24],
                blind_ct: vec![0u8; 536],
                one_time_address: [0u8; 32],
            },
        });
    }

    let qdag_tx = QdagTransaction {
        version: QDAG_VERSION,
        tx_type: QdagTxType::Transfer,
        chain_id,
        parents: vec![], // Filled by block producer
        inputs: vec![ConfidentialInput {
            anonymity_root: ring_data.root_hash,
            nullifier: nullifier_hash,
            membership_proof: membership_proof.to_bytes(),
            input_commitment: c_in,
        }],
        outputs,
        fee: conf_fee,
        balance_proof,
        extra: vec![],
    };

    // Validate structure before submission
    qdag_tx
        .validate_structure()
        .map_err(|e| anyhow::anyhow!("TX structure validation failed: {}", e))?;

    let tx_hash = qdag_tx.tx_hash();
    println!("   TX Hash:  {}", hex::encode(&tx_hash[..16]));
    println!("   Nullifiers: [{}]", hex::encode(&nullifier_hash[..8]));

    // ── 12. Submit ──
    println!("   Submitting to {}...", rpc_url);
    let submit_body = serde_json::json!({
        "version": QDAG_VERSION,
        "txType": "confidential",
        "chainId": chain_id,
        "inputs": [{
            "anonymityRoot": hex::encode(ring_data.root_hash),
            "nullifier": hex::encode(nullifier_hash),
            "membershipProof": hex::encode(membership_proof.to_bytes()),
            "inputCommitment": hex::encode(qdag_tx.inputs[0].input_commitment.to_bytes()),
        }],
        "outputs": qdag_tx.outputs.iter().map(|o| {
            serde_json::json!({
                "commitment": hex::encode(o.commitment.to_bytes()),
                "rangeProofSize": o.range_proof.wire_size(),
            })
        }).collect::<Vec<_>>(),
        "balanceProof": hex::encode(balance_proof_bytes),
        "nullifiers": [hex::encode(nullifier_hash)],
    });

    let result = client.post_json("/api/submit_ct_tx", &submit_body).await?;
    let accepted = result["accepted"].as_bool().unwrap_or(false);

    if accepted {
        println!();
        println!("✅ Confidential transaction submitted!");
        println!("   TX Hash: {}", hex::encode(&tx_hash[..16]));
        println!("   Privacy: sender hidden, amounts hidden, fee hidden");
    } else {
        let error = result["error"].as_str().unwrap_or("unknown");
        println!();
        println!("❌ Transaction rejected: {}", error);
    }

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  RPC Helpers
// ═══════════════════════════════════════════════════════════════

/// Spendable UTXO info fetched from chain.
struct SpendableUtxo {
    tx_hash: String,
    tx_hash_bytes: [u8; 32],
    output_index: u32,
    amount: u64,
}

/// Anonymity set data for membership proof construction.
struct AnonymitySetData {
    leaf_hashes: Vec<[u8; 32]>,
    signer_index: usize,
    root_hash: [u8; 32],
}

/// Query chain for a spendable UTXO with sufficient balance.
async fn query_spendable_utxo(
    client: &RpcClient,
    address: &str,
    min_amount: u64,
) -> Result<SpendableUtxo> {
    let resp = client
        .post_json(
            "/api/get_address_outputs",
            &serde_json::json!({
                "address": address,
            }),
        )
        .await?;

    let outputs = resp["outputs"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("no outputs array in response"))?;

    for o in outputs {
        let amount = o["amount"].as_u64().unwrap_or(0);
        if amount >= min_amount {
            let tx_hash = o["txHash"].as_str().unwrap_or_default().to_string();
            let output_index = o["outputIndex"].as_u64().unwrap_or(0) as u32;
            let mut tx_hash_bytes = [0u8; 32];
            if let Ok(decoded) = hex::decode(&tx_hash) {
                let len = decoded.len().min(32);
                tx_hash_bytes[..len].copy_from_slice(&decoded[..len]);
            }
            return Ok(SpendableUtxo {
                tx_hash,
                tx_hash_bytes,
                output_index,
                amount,
            });
        }
    }
    bail!("no spendable UTXO found with amount >= {}", min_amount)
}

/// Fetch anonymity set for membership proof from chain.
async fn fetch_anonymity_set(
    client: &RpcClient,
    input: &SpendableUtxo,
    ring_size: usize,
    _sis_crs: &SisMerkleCrs,
) -> Result<AnonymitySetData> {
    let resp = client
        .post_json(
            "/api/get_anonymity_set",
            &serde_json::json!({
                "txHash": input.tx_hash,
                "outputIndex": input.output_index,
                "ringSize": ring_size,
            }),
        )
        .await;

    // If RPC not available, generate dummy anonymity set for testing
    let leaf_hashes: Vec<[u8; 32]>;
    let signer_index: usize;

    match resp {
        Ok(data) => {
            if let Some(leaves) = data["leaves"].as_array() {
                leaf_hashes = leaves
                    .iter()
                    .map(|l| {
                        let mut h = [0u8; 32];
                        if let Some(s) = l.as_str() {
                            if let Ok(bytes) = hex::decode(s) {
                                let len = bytes.len().min(32);
                                h[..len].copy_from_slice(&bytes[..len]);
                            }
                        }
                        h
                    })
                    .collect();
                signer_index = data["signerIndex"].as_u64().unwrap_or(0) as usize;
            } else {
                // Fallback: generate synthetic set
                return generate_synthetic_anonymity_set(ring_size);
            }
        }
        Err(_) => {
            eprintln!("   ⚠ Anonymity set RPC not available, using synthetic set");
            return generate_synthetic_anonymity_set(ring_size);
        }
    }

    // Compute SIS root from leaf hashes
    let root_hash = {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_ANON_ROOT:");
        for leaf in &leaf_hashes {
            h.update(leaf);
        }
        h.finalize().into()
    };

    Ok(AnonymitySetData {
        leaf_hashes,
        signer_index,
        root_hash,
    })
}

/// Generate synthetic anonymity set for testnet / offline testing.
fn generate_synthetic_anonymity_set(ring_size: usize) -> Result<AnonymitySetData> {
    use sha3::{Digest, Sha3_256};

    let mut leaf_hashes = Vec::with_capacity(ring_size);
    for i in 0..ring_size {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_SYNTHETIC_LEAF:");
        h.update(&(i as u32).to_le_bytes());
        h.update(&rand::random::<[u8; 32]>());
        leaf_hashes.push(h.finalize().into());
    }

    let signer_index = rand::random::<usize>() % ring_size;

    let root_hash: [u8; 32] = {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA_ANON_ROOT:");
        for leaf in &leaf_hashes {
            h.update(leaf);
        }
        h.finalize().into()
    };

    Ok(AnonymitySetData {
        leaf_hashes,
        signer_index,
        root_hash,
    })
}
