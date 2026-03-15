//! Transfer command — build a MISAKA transaction, sign with ring sig + KI proof, submit.

use anyhow::{Result, bail};
use misaka_pqc::pq_sign::MlDsaSecretKey;
use misaka_pqc::pq_ring::{
    SpendingKeypair, Poly, ring_sign, derive_public_param, DEFAULT_A_SEED, N,
};
use misaka_pqc::ki_proof::prove_key_image;
use sha3::{Sha3_256, Digest};
use std::fs;

/// Wallet key file (matches keygen output).
#[derive(serde::Deserialize)]
struct WalletKeyFile {
    address: String,
    ml_dsa_sk: String,
    spending_pubkey: String,
    key_image: String,
}

/// UTXO from the node for building transactions.
#[derive(serde::Deserialize)]
struct AvailableUtxo {
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

    // 1. Load wallet key
    let key_json = fs::read_to_string(key_path)?;
    let wallet: WalletKeyFile = serde_json::from_str(&key_json)?;
    println!("   From:   {}", wallet.address);

    // 2. Reconstruct spending keypair
    let sk_bytes = hex::decode(&wallet.ml_dsa_sk)?;
    let ml_dsa_sk = MlDsaSecretKey::from_bytes(&sk_bytes)
        .map_err(|e| anyhow::anyhow!("invalid secret key: {}", e))?;
    let spending = SpendingKeypair::from_ml_dsa(ml_dsa_sk);

    // 3. Derive shared param 'a'
    let a = derive_public_param(&DEFAULT_A_SEED);

    // 4. Verify key image matches
    let expected_ki = hex::decode(&wallet.key_image)?;
    if spending.key_image[..] != expected_ki[..] {
        bail!("key image mismatch — wallet file may be corrupted");
    }

    // 5. Build ring (in real use, we'd fetch decoy UTXOs from the node)
    // For now, create a self-ring with our own pubkey at index 0 + 3 dummy decoys
    println!("   Building ring signature (ring_size=4)...");

    let our_pubkey = spending.public_poly.clone();
    let decoy_pks: Vec<Poly> = (0..3).map(|i| {
        // Deterministic dummy decoys (in production: real UTXOs from chain)
        let mut p = Poly::zero();
        for j in 0..N {
            p.coeffs[j] = ((i * 1000 + j as i32 * 7 + 42) % 12289).abs();
        }
        p
    }).collect();

    let mut ring_pks = vec![our_pubkey];
    ring_pks.extend(decoy_pks);

    // 6. Build transaction body for signing digest
    let change = amount; // placeholder: in real tx, compute from input UTXO
    let tx_body = serde_json::json!({
        "version": 1,
        "inputs": [{
            "ringMembers": [
                { "txHash": "00".repeat(32), "outputIndex": 0 },
                { "txHash": "01".repeat(32), "outputIndex": 0 },
                { "txHash": "02".repeat(32), "outputIndex": 0 },
                { "txHash": "03".repeat(32), "outputIndex": 0 },
            ],
            "keyImage": hex::encode(spending.key_image),
        }],
        "outputs": [
            { "amount": amount, "address": to_address },
        ],
        "fee": fee,
    });

    // 7. Compute signing digest
    let digest: [u8; 32] = {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:tx:sign:v1:");
        h.update(serde_json::to_vec(&tx_body)?);
        h.finalize().into()
    };

    // 8. Sign with ring signature
    println!("   Signing transaction...");
    let sig = ring_sign(&a, &ring_pks, 0, &spending.secret_poly, &digest)?;

    // 9. Generate KI proof
    println!("   Generating key image proof...");
    let ki_proof = prove_key_image(
        &a, &spending.secret_poly, &spending.public_poly, &spending.key_image,
    )?;

    // 10. Build submission payload
    let submit_body = serde_json::json!({
        "version": 1,
        "inputs": [{
            "ringSize": ring_pks.len(),
            "ringSignature": hex::encode(sig.to_bytes()),
            "keyImage": hex::encode(spending.key_image),
            "kiProof": hex::encode(ki_proof.to_bytes()),
        }],
        "outputs": [
            { "amount": amount, "address": to_address },
        ],
        "fee": fee,
        "inputCount": 1,
        "outputCount": 1,
        "keyImages": [hex::encode(spending.key_image)],
    });

    // 11. Submit to node
    println!("   Submitting to {}...", rpc_url);
    let result = submit_to_node(rpc_url, &submit_body).await?;

    let accepted = result["accepted"].as_bool().unwrap_or(false);
    let tx_hash = result["txHash"].as_str().unwrap_or("?");

    if accepted {
        println!();
        println!("✅ Transaction submitted successfully!");
        println!("   TX Hash: {}", tx_hash);
        println!("   Status:  pending (will be included in next block)");
    } else {
        let error = result["error"].as_str().unwrap_or("unknown error");
        println!();
        println!("❌ Transaction rejected: {}", error);
    }

    Ok(())
}

async fn submit_to_node(rpc_url: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
    // Minimal HTTP POST (same approach as rpc_client)
    let url_str = format!("{}/api/submit_tx", rpc_url);
    let parsed: SimpleUrl = url_str.parse().map_err(|_| anyhow::anyhow!("invalid URL"))?;
    let body_str = serde_json::to_string(body)?;

    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        parsed.path, parsed.host, parsed.port, body_str.len(), body_str,
    );

    let mut stream = tokio::net::TcpStream::connect(format!("{}:{}", parsed.host, parsed.port)).await?;
    tokio::io::AsyncWriteExt::write_all(&mut stream, request.as_bytes()).await?;

    let mut response = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut response).await?;

    let response_str = String::from_utf8_lossy(&response);
    let body_start = response_str.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let body_text = &response_str[body_start..];

    serde_json::from_str(body_text)
        .map_err(|e| anyhow::anyhow!("response parse error: {}", e))
}

struct SimpleUrl { host: String, port: u16, path: String }

impl std::str::FromStr for SimpleUrl {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        let rest = s.strip_prefix("http://").unwrap_or(s);
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let (host, port) = authority.split_once(':').map(|(h, p)| (h.to_string(), p.parse().unwrap_or(3001))).unwrap_or((authority.to_string(), 3001));
        Ok(SimpleUrl { host, port, path: format!("/{}", path) })
    }
}
