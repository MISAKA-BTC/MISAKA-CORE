//! Genesis config generation for testnet bootstrap.

use anyhow::Result;
use misaka_types::genesis::{ChainProfile, GenesisConfig, GenesisUtxo};
use misaka_types::utxo::TxOutput;
use misaka_types::validator::{ValidatorIdentity, ValidatorPublicKey};
use sha3::{Digest, Sha3_256};
use std::fs;

pub fn run(
    validator_count: usize,
    treasury_amount: u64,
    chain_id: u32,
    output_path: &str,
) -> Result<()> {
    println!("🔧 Generating genesis configuration...");
    println!("   Validators: {}", validator_count);
    println!("   Treasury:   {} MISAKA", treasury_amount);
    println!("   Chain ID:   {}", chain_id);

    // ── Load validator keys if available ──
    let validator_keys_path = "validator_keys.json";
    let loaded_keys: Vec<Vec<u8>> = if std::path::Path::new(validator_keys_path).exists() {
        println!("   Loading validator keys from: {}", validator_keys_path);
        let key_json = fs::read_to_string(validator_keys_path)?;
        let keys: Vec<String> = serde_json::from_str(&key_json)
            .map_err(|e| anyhow::anyhow!("Failed to parse {}: {}", validator_keys_path, e))?;
        keys.iter()
            .map(|hex_key| {
                hex::decode(hex_key).map_err(|e| anyhow::anyhow!("Invalid hex key: {}", e))
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        // Testnet fallback: generate deterministic placeholder keys
        // MAINNET: validator_keys.json is MANDATORY
        if chain_id == 1 {
            anyhow::bail!(
                "Mainnet genesis requires validator_keys.json with real ML-DSA-65 public keys. \
                 Generate with: misaka-cli keygen --validators {}",
                validator_count
            );
        }
        println!("   ⚠ No validator_keys.json found — using testnet placeholders");
        vec![]
    };

    let now_ms = chrono::Utc::now().timestamp_millis() as u64;

    // Build profile
    let profile = ChainProfile {
        chain_id,
        chain_name: if chain_id == 1 {
            "MISAKA Mainnet".into()
        } else {
            "MISAKA Testnet".into()
        },
        genesis_timestamp_ms: now_ms,
        pq_tx_required: true,
        ki_proof_required: true,
        min_ring_size: 4,
        max_ring_size: 16,
        block_time_secs: 60,
        max_txs_per_block: 1000,
    };

    // Treasury UTXO
    let treasury = GenesisUtxo {
        output: TxOutput {
            amount: treasury_amount,
            one_time_address: [0x01; 32],
            pq_stealth: None,
            spending_pubkey: None,
        },
        label: "treasury".into(),
    };

    // Generate validator identities (deterministic from index for testnet)
    let validators: Vec<ValidatorIdentity> = (0..validator_count)
        .map(|i| {
            let id = derive_validator_id(i);
            ValidatorIdentity {
                validator_id: id,
                stake_weight: 1_000_000,
                public_key: ValidatorPublicKey {
                    bytes: if i < loaded_keys.len() {
                        // Use real key from validator_keys.json
                        loaded_keys[i].clone()
                    } else {
                        // Testnet only: deterministic placeholder (1952 bytes = ML-DSA-65 pk)
                        let mut pk = vec![0u8; 1952];
                        let seed = Sha3_256::new()
                            .chain_update(b"MISAKA_TESTNET_VALIDATOR:")
                            .chain_update(&(i as u32).to_le_bytes())
                            .finalize();
                        pk[..32].copy_from_slice(&seed);
                        pk
                    },
                },
                is_active: true,
            }
        })
        .collect();

    let genesis = GenesisConfig {
        profile,
        initial_utxos: vec![treasury],
        initial_validators: validators,
    };

    // Write JSON
    let json = serde_json::to_string_pretty(&genesis)?;
    fs::write(output_path, &json)?;

    println!();
    println!("✅ Genesis config written to: {}", output_path);
    println!("   Genesis timestamp: {}", now_ms);
    println!("   Validators:        {}", validator_count);
    println!("   Treasury:          {} MISAKA", treasury_amount);
    println!();
    println!("Usage:");
    println!("   misaka-node --chain-id {} ", chain_id);
    println!();
    println!("For multi-node testnet:");
    for i in 0..validator_count.min(4) {
        let rpc_port = 3001 + i;
        let p2p_port = 6690 + i;
        let peers: Vec<String> = (0..validator_count)
            .filter(|&j| j != i)
            .map(|j| format!("127.0.0.1:{}", 6690 + j))
            .collect();
        println!(
            "   misaka-node --name node-{} --validator-index {} --validators {} --rpc-port {} --p2p-port {} --peers {}",
            i, i, validator_count, rpc_port, p2p_port, peers.join(",")
        );
    }

    Ok(())
}

fn derive_validator_id(index: usize) -> [u8; 20] {
    let mut h = Sha3_256::new();
    h.update(b"MISAKA:validator:id:v1:");
    h.update((index as u64).to_le_bytes());
    let hash: [u8; 32] = h.finalize().into();
    let mut id = [0u8; 20];
    id.copy_from_slice(&hash[..20]);
    id
}
