//! Wallet key generation — ML-DSA-65 identity + spending keypair.

use anyhow::Result;
use misaka_pqc::canonical_spend_id;
use misaka_pqc::key_derivation::{derive_public_param, SpendingKeypair, DEFAULT_A_SEED};
use misaka_pqc::pq_kem::ml_kem_keygen;
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
    spend_id: String,
    /// Transaction spend identifier used by current tx + KI proof path.
    tx_spend_id: String,
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
    let ml_dsa_sk_hex = ml_dsa_kp.secret_key.with_bytes(|bytes| hex::encode(bytes));
    let ml_dsa_pk_hex = hex::encode(ml_dsa_kp.public_key.as_bytes());

    // 2. Generate ML-KEM-768 keypair (PQ-KEM address view key)
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
    let tx_spend_id = canonical_spend_id(&spending.secret_poly);

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
        spend_id: hex::encode(spending.canonical_spend_id()),
        tx_spend_id: hex::encode(tx_spend_id),
    };

    // 6. Write to file
    // SEC-FIX CRITICAL: Set file permissions to 0o600 (owner read/write only).
    // Previously used default umask which could result in 0o644 (world-readable).
    // On shared servers, other users could read the plaintext secret key.
    let dir = Path::new(output_dir);
    fs::create_dir_all(dir)?;
    let filepath = dir.join(format!("{}.key.json", name));
    let json = serde_json::to_string_pretty(&key_file)?;
    fs::write(&filepath, &json)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&filepath, fs::Permissions::from_mode(0o600))
            .map_err(|e| anyhow::anyhow!("failed to set key file permissions: {}", e))?;
    }
    // SEC-AUDIT WARNING: This file still contains the ML-DSA-65 secret key in
    // plaintext JSON. For production use, encrypt with misaka-crypto::keystore::
    // encrypt_keystore() before saving. The validator keygen path (main.rs:537)
    // already uses Argon2id encryption — this CLI path should be aligned.
    eprintln!("  ⚠  WARNING: Key file saved without passphrase encryption.");
    eprintln!("     For production use, encrypt with: misaka-cli encrypt-keystore");

    // 7. Write public info separately (safe to share)
    let pub_file = serde_json::json!({
        "version": 1,
        "name": name,
        "address": address,
        "ml_dsa_pk": key_file.ml_dsa_pk,
        "ml_kem_pk": key_file.ml_kem_pk,
        "spending_pubkey": key_file.spending_pubkey,
        "spend_id": key_file.spend_id,
        "tx_spend_id": key_file.tx_spend_id,
    });
    let pub_filepath = dir.join(format!("{}.pub.json", name));
    fs::write(&pub_filepath, serde_json::to_string_pretty(&pub_file)?)?;

    println!();
    println!("✅ Wallet generated successfully!");
    println!("   Address:   {}", address);
    println!("   Legacy KI: {}", hex::encode(&spending.canonical_spend_id()[..8]));
    println!("   Tx KI:     {}", hex::encode(&tx_spend_id[..8]));
    println!();
    println!("   Secret key: {}", filepath.display());
    println!("   Public key: {}", pub_filepath.display());
    println!();
    println!("⚠  Keep {}.key.json SECRET. Never share it.", name);

    Ok(())
}
