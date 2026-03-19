//! Wallet key generation — ML-DSA-65 identity + spending keypair.

use anyhow::Result;
use misaka_pqc::pq_sign::MlDsaKeypair;
use misaka_pqc::pq_kem::ml_kem_keygen;
use misaka_pqc::pq_ring::{SpendingKeypair, derive_public_param, DEFAULT_A_SEED};
use sha3::{Sha3_256, Digest};
use std::fs;
use std::path::Path;

/// Wallet key file (JSON-serializable).
#[derive(serde::Serialize, serde::Deserialize)]
struct WalletKeyFile {
    /// Wallet version.
    version: u32,
    /// Human-readable name.
    name: String,
    /// MISAKA address (hex-encoded, derived from public key).
    address: String,
    /// ML-DSA-65 secret key (hex-encoded).
    ml_dsa_sk: String,
    /// ML-DSA-65 public key (hex-encoded).
    ml_dsa_pk: String,
    /// ML-KEM-768 secret key (hex-encoded).
    ml_kem_sk: String,
    /// ML-KEM-768 public key (hex-encoded).
    ml_kem_pk: String,
    /// Lattice public polynomial (hex-encoded bytes).
    spending_pubkey: String,
    /// Key image (hex-encoded 32 bytes).
    key_image: String,
}

/// Derive a MISAKA address from the spending public key.
fn derive_address(spending_pub_bytes: &[u8]) -> String {
    let hash: [u8; 32] = {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:address:v1:");
        h.update(spending_pub_bytes);
        h.finalize().into()
    };
    // Address = "msk1" + first 40 hex chars of hash
    format!("msk1{}", hex::encode(&hash[..20]))
}

pub fn run(output_dir: &str, name: &str) -> Result<()> {
    println!("🔑 Generating MISAKA wallet keypair...");
    println!("   Name: {}", name);

    // 1. Generate ML-DSA-65 keypair (signature identity)
    let ml_dsa_kp = MlDsaKeypair::generate();
    // Save bytes before moving secret_key into SpendingKeypair
    let ml_dsa_sk_hex = hex::encode(ml_dsa_kp.secret_key.as_bytes());
    let ml_dsa_pk_hex = hex::encode(ml_dsa_kp.public_key.as_bytes());

    // 2. Generate ML-KEM-768 keypair (stealth address view key)
    let ml_kem_kp = ml_kem_keygen()?;
    let ml_kem_sk_hex = hex::encode(ml_kem_kp.secret_key.as_bytes());
    let ml_kem_pk_hex = hex::encode(ml_kem_kp.public_key.as_bytes());

    // 3. Derive spending keypair from ML-DSA secret
    let _a = derive_public_param(&DEFAULT_A_SEED);
    let spending = SpendingKeypair::from_ml_dsa(ml_dsa_kp.secret_key).unwrap();

    // 4. Derive address
    let pub_bytes = spending.public_poly.to_bytes();
    let address = derive_address(&pub_bytes);

    // 5. Build key file
    let key_file = WalletKeyFile {
        version: 1,
        name: name.to_string(),
        address: address.clone(),
        ml_dsa_sk: ml_dsa_sk_hex,
        ml_dsa_pk: ml_dsa_pk_hex,
        ml_kem_sk: ml_kem_sk_hex,
        ml_kem_pk: ml_kem_pk_hex,
        spending_pubkey: hex::encode(&pub_bytes),
        key_image: hex::encode(spending.key_image),
    };

    // 6. Write to file
    let dir = Path::new(output_dir);
    fs::create_dir_all(dir)?;
    let filepath = dir.join(format!("{}.key.json", name));
    let json = serde_json::to_string_pretty(&key_file)?;
    fs::write(&filepath, &json)?;

    // 7. Write public info separately (safe to share)
    let pub_file = serde_json::json!({
        "version": 1,
        "name": name,
        "address": address,
        "ml_dsa_pk": key_file.ml_dsa_pk,
        "ml_kem_pk": key_file.ml_kem_pk,
        "spending_pubkey": key_file.spending_pubkey,
        "key_image": key_file.key_image,
    });
    let pub_filepath = dir.join(format!("{}.pub.json", name));
    fs::write(&pub_filepath, serde_json::to_string_pretty(&pub_file)?)?;

    println!();
    println!("✅ Wallet generated successfully!");
    println!("   Address:   {}", address);
    println!("   Key Image: {}", hex::encode(&spending.key_image[..8]));
    println!();
    println!("   Secret key: {}", filepath.display());
    println!("   Public key: {}", pub_filepath.display());
    println!();
    println!("⚠  Keep {}.key.json SECRET. Never share it.", name);

    Ok(())
}
