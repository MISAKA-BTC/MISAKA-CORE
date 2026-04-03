//! Wallet key generation — ML-DSA-65 identity + spending keypair.

use anyhow::Result;
use misaka_pqc::ki_proof::canonical_strong_ki;
use misaka_pqc::pq_kem::ml_kem_keygen;
use misaka_pqc::pq_ring::{derive_public_param, SpendingKeypair, DEFAULT_A_SEED};
use misaka_pqc::pq_sign::MlDsaKeypair;
use sha3::{Digest, Sha3_256};
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
    /// Transaction key image / nullifier used by current tx + KI proof path.
    tx_key_image: String,
}

/// Derive a MISAKA address from the spending public key.
///
/// H-3 FIX: Uses unified `misaka_types::address::encode_address` — `misaka1` prefix
/// for all networks, with chain_id-bound checksum.
#[allow(dead_code)]
fn derive_address(spending_pub_bytes: &[u8], chain_id: u32) -> String {
    let hash: [u8; 32] = {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:address:v1:");
        h.update(spending_pub_bytes);
        h.finalize().into()
    };
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&hash);
    misaka_types::address::encode_address(&addr, chain_id)
}

pub fn run(output_dir: &str, name: &str, chain_id: u32) -> Result<()> {
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

    // 3. Derive spending keypair from ML-DSA keypair (both pk + sk)
    let _a = derive_public_param(&DEFAULT_A_SEED);
    let ml_dsa_pk_bytes_vec = ml_dsa_kp.public_key.as_bytes().to_vec();
    let spending = SpendingKeypair::from_ml_dsa_pair(ml_dsa_kp.secret_key, ml_dsa_pk_bytes_vec)
        .map_err(|e| anyhow::anyhow!("spending keypair derivation failed: {}", e))?;

    // 4. Derive address from ML-DSA-65 public key (mainnet: 1952-byte PK)
    // v10: Address = misaka1... (unified format, chain_id-bound checksum)
    let address = spending.derive_address_with_chain(chain_id);
    let (_, tx_key_image) = canonical_strong_ki(&spending.public_poly, &spending.secret_poly);

    // 5. Build key file
    // spending_pubkey = ML-DSA-65 public key (1952 bytes, hex)
    // This is the key stored in UTXOs and used for signature verification.
    let key_file = WalletKeyFile {
        version: 1,
        name: name.to_string(),
        address: address.clone(),
        ml_dsa_sk: ml_dsa_sk_hex,
        ml_dsa_pk: ml_dsa_pk_hex.clone(),
        ml_kem_sk: ml_kem_sk_hex,
        ml_kem_pk: ml_kem_pk_hex,
        spending_pubkey: ml_dsa_pk_hex,
        key_image: hex::encode(spending.key_image),
        tx_key_image: hex::encode(tx_key_image),
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
        "tx_key_image": key_file.tx_key_image,
    });
    let pub_filepath = dir.join(format!("{}.pub.json", name));
    fs::write(&pub_filepath, serde_json::to_string_pretty(&pub_file)?)?;

    println!();
    println!("✅ Wallet generated successfully!");
    println!("   Address:   {}", address);
    println!("   Legacy KI: {}", hex::encode(&spending.key_image[..8]));
    println!("   Tx KI:     {}", hex::encode(&tx_key_image[..8]));
    println!();
    println!("   Secret key: {}", filepath.display());
    println!("   Public key: {}", pub_filepath.display());
    println!();
    println!("⚠  Keep {}.key.json SECRET. Never share it.", name);

    Ok(())
}
