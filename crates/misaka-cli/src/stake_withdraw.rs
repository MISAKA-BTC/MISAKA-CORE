//! Phase 9: `begin-exit` CLI command.
//!
//! Builds `UtxoTransaction { tx_type: StakeWithdraw }` whose `extra` carries
//! a `ValidatorStakeTx { kind: BeginExit }` envelope. No `stake_inputs`
//! inside the envelope (BeginExit doesn't add stake). Only a fee-paying
//! UTXO input on the outer tx.
//!
//! Mirrors the inner/outer split used by `stake_deposit.rs`:
//! - validator consensus key signs the inner envelope
//! - wallet spending key signs the outer input proof (IntentScope::StakeWithdraw)

use anyhow::{bail, Context, Result};
use misaka_pqc::pq_sign::{ml_dsa_sign_raw, MlDsaSecretKey};
use misaka_pqc::{canonical_spend_id, SpendingKeypair};
use misaka_types::utxo::{OutputRef, TxInput, TxOutput, TxType, UtxoTransaction, UTXO_TX_VERSION};
use misaka_types::validator_stake_tx::{StakeTxKind, StakeTxParams, ValidatorStakeTx};
use std::fs;

use crate::rpc_client::RpcClient;
use crate::send::fetch_genesis_hash_or_default;
use crate::stake_deposit::sign_envelope;
use crate::wallet_state::WalletState;

#[derive(serde::Deserialize)]
struct WalletKeyFile {
    address: String,
    ml_dsa_sk: String,
    #[serde(default)]
    ml_dsa_pk: String,
    #[allow(dead_code)]
    spending_pubkey: String,
    #[allow(dead_code)]
    spend_id: String,
    #[allow(dead_code)]
    #[serde(default, alias = "canonical_spend_id")]
    tx_spend_id: Option<String>,
    #[serde(default)]
    name: String,
}

/// Decrypt the validator keystore; re-uses `stake_deposit`'s helper via
/// a thin private shim (same semantics).
fn load_validator_consensus_key(
    validator_key_path: &str,
) -> Result<(MlDsaSecretKey, [u8; 32])> {
    use misaka_crypto::keystore::{decrypt_keystore, load_keystore};
    use misaka_crypto::validator_sig::ValidatorPqPublicKey;

    let path = std::path::Path::new(validator_key_path);
    let keystore = load_keystore(path)
        .with_context(|| format!("failed to load keystore from {}", path.display()))?;
    let passphrase = std::env::var("MISAKA_VALIDATOR_PASSPHRASE")
        .unwrap_or_default()
        .into_bytes();
    if passphrase.is_empty() {
        eprintln!("   ⚠  MISAKA_VALIDATOR_PASSPHRASE is empty — assuming empty-passphrase keystore.");
    }
    let sk_bytes = decrypt_keystore(&keystore, &passphrase)
        .context("failed to decrypt validator keystore")?;
    let sk = MlDsaSecretKey::from_bytes(&sk_bytes)
        .map_err(|e| anyhow::anyhow!("invalid ML-DSA-65 secret key: {}", e))?;
    let pk_bytes = hex::decode(&keystore.public_key_hex)
        .context("keystore public_key_hex not valid hex")?;
    let pq_pk = ValidatorPqPublicKey::from_bytes(&pk_bytes)
        .map_err(|e| anyhow::anyhow!("ValidatorPqPublicKey::from_bytes failed: {}", e))?;
    Ok((sk, pq_pk.to_canonical_id()))
}

/// `begin-exit` subcommand.
pub async fn run_begin_exit(
    wallet_key_path: &str,
    validator_key_path: &str,
    fee: u64,
    rpc_url: &str,
    chain_id: u32,
    genesis_hash_override: Option<[u8; 32]>,
) -> Result<()> {
    println!("📤 Building begin-exit transaction...");
    println!("   Fee: {} MISAKA (base units)", fee);

    let client = RpcClient::new(rpc_url)?;
    let genesis_hash = match genesis_hash_override {
        Some(h) => h,
        None => fetch_genesis_hash_or_default(rpc_url).await,
    };

    let (consensus_sk, validator_id) = load_validator_consensus_key(validator_key_path)?;
    println!("   Validator: {}", hex::encode(validator_id));

    // Load wallet + sync (for fee-paying input).
    let key_json = fs::read_to_string(wallet_key_path).context("failed to read wallet key file")?;
    let wallet: WalletKeyFile =
        serde_json::from_str(&key_json).context("failed to parse wallet key file")?;
    let mut state =
        WalletState::load_or_create(wallet_key_path, &wallet.name, &wallet.address)?;
    sync_wallet_from_chain(&client, &mut state).await?;

    // BeginExit has no stake_inputs in the envelope — validate_structure
    // rejects non-empty stake_inputs here. But the OUTER tx still needs a
    // fee-paying UTXO input. Amount = 0, fee paid from change.
    let mut envelope = ValidatorStakeTx {
        kind: StakeTxKind::BeginExit,
        validator_id,
        stake_inputs: Vec::new(),
        fee,
        nonce: 0,
        memo: None,
        params: StakeTxParams::BeginExit,
        signature: Vec::new(),
    };
    sign_envelope(&mut envelope, &consensus_sk)?;
    envelope.validate_structure().context("BeginExit envelope invalid")?;

    let extra = envelope
        .encode_for_extra()
        .context("encode_for_extra for BeginExit")?;

    // Pick a fee-paying UTXO.
    let (selected, change) = state
        .select_utxos_multi(0, fee)
        .context("no UTXOs available to pay the exit fee")?;
    let selected_snapshot: Vec<_> = selected
        .iter()
        .map(|u| {
            (
                u.tx_hash.clone(),
                u.output_index,
                u.amount,
                u.child_index,
                u.spend_id.clone(),
            )
        })
        .collect();

    // Outer outputs: just the change back (no receipt marker — BeginExit
    // has no `staked_receipt_table` entry to write).
    let master_sk_bytes =
        hex::decode(&wallet.ml_dsa_sk).context("invalid hex in wallet ml_dsa_sk")?;
    let mut tx_outputs: Vec<TxOutput> = Vec::new();
    let change_info: Option<(u32, String, String)> = if change > 0 {
        let idx = state.next_child();
        let child = SpendingKeypair::derive_child(&master_sk_bytes, idx)
            .map_err(|e| anyhow::anyhow!("change child key derivation failed: {}", e))?;
        let addr = child.derive_address();
        let ki = hex::encode(child.canonical_spend_id());
        let change_addr_bytes = misaka_types::address::decode_address(&addr, chain_id)
            .map_err(|e| anyhow::anyhow!("invalid change address: {}", e))?;
        tx_outputs.push(TxOutput {
            amount: change,
            address: change_addr_bytes,
            spending_pubkey: Some(child.ml_dsa_pk().to_vec()),
        });
        Some((idx, addr, ki))
    } else {
        None
    };

    let mut utxo_refs: Vec<OutputRef> = Vec::with_capacity(selected_snapshot.len());
    for (tx_hash_hex, output_index, _, _, _) in &selected_snapshot {
        let tx_hash_bytes: [u8; 32] = hex::decode(tx_hash_hex)
            .map_err(|e| anyhow::anyhow!("invalid input tx hash hex: {}", e))?
            .try_into()
            .map_err(|_| anyhow::anyhow!("input tx hash must be 32 bytes"))?;
        utxo_refs.push(OutputRef {
            tx_hash: tx_hash_bytes,
            output_index: *output_index,
        });
    }

    let unsigned_tx = UtxoTransaction {
        version: UTXO_TX_VERSION,
        tx_type: TxType::StakeWithdraw,
        inputs: vec![TxInput {
            utxo_refs: utxo_refs.clone(),
            proof: vec![],
        }],
        outputs: tx_outputs.clone(),
        fee,
        extra: extra.clone(),
        expiry: 0,
    };

    use misaka_types::tx_signable::TxSignablePayload;
    let payload = TxSignablePayload::from(&unsigned_tx);
    let intent = misaka_types::intent::IntentMessage::wrap(
        misaka_types::intent::IntentScope::StakeWithdraw,
        misaka_types::intent::AppId::new(chain_id, genesis_hash),
        &payload,
    );
    let digest = intent.signing_digest();

    // Sign with the first input's spending key.
    let (first_child, first_ki) = {
        let (_, _, _, child_index, spend_id) = &selected_snapshot[0];
        (*child_index, spend_id.clone())
    };
    let spending = if first_child == 0 {
        let sk = MlDsaSecretKey::from_bytes(&master_sk_bytes)
            .map_err(|e| anyhow::anyhow!("invalid wallet secret key: {}", e))?;
        let pk_bytes = hex::decode(&wallet.ml_dsa_pk).unwrap_or_default();
        SpendingKeypair::from_ml_dsa_pair(sk, pk_bytes)
            .map_err(|e| anyhow::anyhow!("spending keypair derivation failed: {}", e))?
    } else {
        SpendingKeypair::derive_child(&master_sk_bytes, first_child)
            .map_err(|e| anyhow::anyhow!("child key derivation failed: {}", e))?
    };
    let computed_ki = hex::encode(canonical_spend_id(&spending.secret_poly));
    let first_ki = if first_ki.is_empty() {
        computed_ki.clone()
    } else {
        first_ki
    };
    if computed_ki != first_ki {
        bail!(
            "key image mismatch for child #{} (expected {}, got {})",
            first_child, first_ki, computed_ki
        );
    }
    let outer_sig = ml_dsa_sign_raw(&spending.ml_dsa_sk, &digest)
        .map_err(|e| anyhow::anyhow!("outer ML-DSA-65 signing failed: {}", e))?;

    let submit_tx = UtxoTransaction {
        version: UTXO_TX_VERSION,
        tx_type: TxType::StakeWithdraw,
        inputs: vec![TxInput {
            utxo_refs,
            proof: outer_sig.as_bytes().to_vec(),
        }],
        outputs: tx_outputs,
        fee,
        extra,
        expiry: 0,
    };

    let submit_body = serde_json::to_value(&submit_tx)?;
    println!("   Submitting to {}...", rpc_url);
    let result = client.post_json("/api/submit_tx", &submit_body).await?;
    let accepted = result["accepted"].as_bool().unwrap_or(false);
    let tx_hash = result["txHash"].as_str().unwrap_or("?");

    if accepted {
        println!();
        println!("✅ BeginExit accepted — validator entered unbonding.");
        println!("   TX Hash:  {}", tx_hash);
        for (_, _, _, _, spend_id) in &selected_snapshot {
            state.mark_spent(spend_id);
        }
        if let Some((child_idx, ref addr, ref ki)) = change_info {
            // Change output is at index 0 here (no receipt marker).
            state.register_utxo(tx_hash, 0, change, child_idx, ki, addr);
            println!("   Change:   {} MISAKA → child #{}", change, child_idx);
        }
        state.save(wallet_key_path)?;
    } else {
        let err = result["error"].as_str().unwrap_or("unknown");
        println!();
        println!("❌ Rejected: {}", err);
    }
    Ok(())
}

/// Local sync helper — identical to `stake_deposit::sync_wallet_from_chain`.
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
            let spend_id_val = o["spendId"].as_str().unwrap_or_default();
            if !state
                .utxos
                .iter()
                .any(|u| u.tx_hash == tx_hash && u.output_index == output_index)
            {
                state.register_utxo(tx_hash, output_index, amount_val, 0, spend_id_val, &master_addr);
            }
        }
    }
    if let Some(spent_kis) = resp["spentKeyImages"].as_array() {
        let spent_set: std::collections::HashSet<&str> =
            spent_kis.iter().filter_map(|v| v.as_str()).collect();
        for utxo in &mut state.utxos {
            if spent_set.contains(utxo.spend_id.as_str()) {
                utxo.spent = true;
            }
        }
        state.recalculate_balance();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_crypto::validator_sig::ValidatorPqPublicKey;
    use misaka_pqc::pq_sign::MlDsaKeypair;

    #[test]
    fn begin_exit_envelope_has_no_stake_inputs() {
        let kp = MlDsaKeypair::generate();
        let vid = ValidatorPqPublicKey::from_bytes(kp.public_key.as_bytes())
            .unwrap()
            .to_canonical_id();
        let mut envelope = ValidatorStakeTx {
            kind: StakeTxKind::BeginExit,
            validator_id: vid,
            stake_inputs: Vec::new(),
            fee: 1_000_000_000,
            nonce: 0,
            memo: None,
            params: StakeTxParams::BeginExit,
            signature: Vec::new(),
        };
        sign_envelope(&mut envelope, &kp.secret_key).expect("sign");
        envelope.validate_structure().expect("valid BeginExit");
        assert_eq!(envelope.kind, StakeTxKind::BeginExit);
        assert!(envelope.stake_inputs.is_empty());

        // Non-empty stake_inputs must be rejected.
        let mut bad = envelope.clone();
        bad.stake_inputs.push(misaka_types::validator_stake_tx::StakeInput {
            tx_hash: [0; 32],
            output_index: 0,
            amount: 1,
        });
        // Re-sign so missing-signature doesn't mask the structural failure.
        sign_envelope(&mut bad, &kp.secret_key).unwrap();
        assert!(bad.validate_structure().is_err());
    }
}
