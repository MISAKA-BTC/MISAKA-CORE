//! Phase 9: `stake-register` and `stake-more` CLI commands.
//!
//! Produces `UtxoTransaction { tx_type: StakeDeposit }` whose `extra` field
//! carries a `ValidatorStakeTx` envelope (γ-1 wire format) signed with the
//! validator's ML-DSA-65 consensus key (from `l1-secret-key.json` encrypted
//! keystore).
//!
//! # Two keys are used
//!
//! | Key | Source | Signs |
//! |-----|--------|-------|
//! | Wallet spending key | `wallet.key.json` (ML-DSA-65) | outer UTXO inputs (IntentMessage digest) |
//! | Validator consensus key | `data/l1-secret-key.json` encrypted keystore | inner `ValidatorStakeTx.signing_payload()` |
//!
//! # Mirrored flow (public_transfer.rs + apply_stake_deposit invariants)
//!
//! 1. Decrypt validator keystore, derive consensus public key + canonical `validator_id`.
//! 2. Load wallet state, select UTXOs that cover `stake_amount + fee`.
//! 3. Build `ValidatorStakeTx` with the right `StakeTxKind` + params.
//! 4. Sign the envelope (ML-DSA-65 over `signing_payload()`).
//! 5. `encode_for_extra()` → `UtxoTransaction.extra` bytes.
//! 6. Assemble `UtxoTransaction`:
//!    - `tx_type = StakeDeposit`
//!    - `inputs = [TxInput { utxo_refs, proof: outer ML-DSA-65 sig }]`
//!    - `outputs[0] = { amount: 0, address: validator_id }` (receipt marker; `utxo_executor::apply_stake_deposit` routes it into `staked_receipt_table` rather than the UTXO set)
//!    - `outputs[1..]` = change
//! 7. Sign the outer inputs (IntentMessage with `IntentScope::StakeDeposit`).
//! 8. `borsh::to_vec` → POST `/api/submit_tx`.
//!
//! The receipt output at index 0 MUST have `amount == 0` — any other value
//! is rejected because the executor never adds it to the UTXO set; putting
//! value there would "burn" it.

use anyhow::{bail, Context, Result};
use misaka_crypto::keystore::{decrypt_keystore, load_keystore};
use misaka_crypto::validator_sig::ValidatorPqPublicKey;
use misaka_pqc::pq_sign::{ml_dsa_sign_raw, MlDsaSecretKey};
use misaka_pqc::{canonical_spend_id, SpendingKeypair};
use misaka_types::utxo::{OutputRef, TxInput, TxOutput, TxType, UtxoTransaction, UTXO_TX_VERSION};
use misaka_types::validator_stake_tx::{
    RegisterParams, StakeInput, StakeMoreParams, StakeTxKind, StakeTxParams, ValidatorStakeTx,
};
use std::fs;

use crate::rpc_client::RpcClient;
use crate::send::fetch_genesis_hash_or_default;
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

/// Decrypt the validator keystore and return a ready-to-use `(sk, pk_bytes)`.
///
/// Looks for `MISAKA_VALIDATOR_PASSPHRASE` env var — matches the
/// node's keygen path (`main.rs:609`). Empty passphrase is allowed on testnet
/// with a loud warning.
fn load_validator_consensus_key(
    validator_key_path: &str,
) -> Result<(MlDsaSecretKey, Vec<u8>, [u8; 32])> {
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
        .map_err(|e| anyhow::anyhow!("invalid ML-DSA-65 secret key in keystore: {}", e))?;

    // The keystore metadata stores the pubkey hex; prefer it over re-deriving.
    let pk_bytes = hex::decode(&keystore.public_key_hex)
        .context("keystore public_key_hex is not valid hex")?;
    if pk_bytes.len() != 1952 {
        bail!(
            "validator pubkey length {} != 1952 (ML-DSA-65)",
            pk_bytes.len()
        );
    }
    let pq_pk = ValidatorPqPublicKey::from_bytes(&pk_bytes)
        .map_err(|e| anyhow::anyhow!("ValidatorPqPublicKey::from_bytes failed: {}", e))?;
    let validator_id = pq_pk.to_canonical_id();
    Ok((sk, pk_bytes, validator_id))
}

/// Shared tail of stake-register / stake-more: assemble outer
/// `UtxoTransaction`, sign its inputs, borsh-encode, and submit.
#[allow(clippy::too_many_arguments)]
async fn submit_stake_deposit(
    rpc_url: &str,
    client: &RpcClient,
    chain_id: u32,
    genesis_hash: [u8; 32],
    wallet_key_path: &str,
    wallet: &WalletKeyFile,
    state: &mut WalletState,
    envelope: ValidatorStakeTx,
    validator_id: [u8; 32],
    stake_amount: u64,
    fee: u64,
) -> Result<()> {
    // 1. Encode the envelope into `extra`.
    let extra = envelope
        .encode_for_extra()
        .context("encode_for_extra (envelope too large?)")?;

    // 2. Coin selection: we need `stake_amount + fee` in owned UTXOs.
    let (selected, change) = state
        .select_utxos_multi(stake_amount, fee)
        .context("coin selection failed")?;
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

    println!(
        "   Inputs: {} UTXO(s), total={} MISAKA, change={}",
        selected_snapshot.len(),
        selected_snapshot.iter().map(|u| u.2).sum::<u64>(),
        change
    );

    // 3. Build the outer outputs.
    //    outputs[0] = receipt marker (amount=0, address=validator_id).
    //    outputs[1..] = change back to wallet (if any).
    let mut tx_outputs: Vec<TxOutput> = Vec::with_capacity(2);
    tx_outputs.push(TxOutput {
        amount: 0,
        address: validator_id,
        // spending_pubkey = None: the receipt marker is routed into
        // staked_receipt_table and NEVER spent as a UTXO — no key binding
        // is meaningful. If populated with a dummy key, the executor's
        // P2PKH binding check in validate_output_pubkey_binding would
        // require address == SHA3(key), which is not the case here.
        spending_pubkey: None,
    });

    // Prepare change if any (requires a fresh child key).
    let master_sk_bytes = hex::decode(&wallet.ml_dsa_sk).context("invalid hex in wallet ml_dsa_sk")?;
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

    // 4. Build utxo_refs.
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

    // 5. Unsigned transaction (for IntentMessage digest).
    let unsigned_tx = UtxoTransaction {
        version: UTXO_TX_VERSION,
        tx_type: TxType::StakeDeposit,
        inputs: vec![TxInput {
            utxo_refs: utxo_refs.clone(),
            proof: vec![], // filled after signing
        }],
        outputs: tx_outputs.clone(),
        fee,
        extra: extra.clone(),
        expiry: 0,
    };

    // 6. IntentMessage digest under IntentScope::StakeDeposit.
    use misaka_types::tx_signable::TxSignablePayload;
    let payload = TxSignablePayload::from(&unsigned_tx);
    let intent = misaka_types::intent::IntentMessage::wrap(
        misaka_types::intent::IntentScope::StakeDeposit,
        misaka_types::intent::AppId::new(chain_id, genesis_hash),
        &payload,
    );
    let digest = intent.signing_digest();

    // 7. Sign outer with wallet's spending key.
    //    Multi-UTXO note: all selected UTXOs must share the same spending
    //    key for a single input bucket to authenticate them. γ-3's stake tx
    //    input handling does not check per-input proofs individually, but
    //    we still sign with the master-level wallet key to produce a
    //    protocol-valid 3309-byte proof (defense in depth; matches the
    //    forward-compatible shape should the executor tighten).
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

    // 8. Finalize + submit.
    let submit_tx = UtxoTransaction {
        version: UTXO_TX_VERSION,
        tx_type: TxType::StakeDeposit,
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
        println!("✅ Stake deposit accepted!");
        println!("   TX Hash:     {}", tx_hash);
        println!("   Validator:   {}", hex::encode(validator_id));

        // Mark inputs spent in wallet state.
        for (_, _, _, _, spend_id) in &selected_snapshot {
            state.mark_spent(spend_id);
        }
        // Register change UTXO (output index 1 when change exists).
        if let Some((child_idx, ref addr, ref ki)) = change_info {
            state.register_utxo(tx_hash, 1, change, child_idx, ki, addr);
            println!("   Change:      {} MISAKA → child #{}", change, child_idx);
        }
        state.save(wallet_key_path)?;
    } else {
        let err = result["error"].as_str().unwrap_or("unknown");
        println!();
        println!("❌ Rejected: {}", err);
    }
    Ok(())
}

/// `stake-register` subcommand.
///
/// Builds `ValidatorStakeTx { kind: Register }`.
#[allow(clippy::too_many_arguments)]
pub async fn run_register(
    wallet_key_path: &str,
    validator_key_path: &str,
    stake_amount: u64,
    commission_bps: u32,
    reward_address: [u8; 32],
    p2p_endpoint: Option<String>,
    moniker: Option<String>,
    fee: u64,
    rpc_url: &str,
    chain_id: u32,
    genesis_hash_override: Option<[u8; 32]>,
) -> Result<()> {
    println!("📥 Building stake-register transaction...");
    println!("   Stake:       {} MISAKA (base units)", stake_amount);
    println!("   Fee:         {} MISAKA (base units)", fee);
    println!("   Commission:  {} bps", commission_bps);

    let client = RpcClient::new(rpc_url)?;
    let genesis_hash = match genesis_hash_override {
        Some(h) => h,
        None => fetch_genesis_hash_or_default(rpc_url).await,
    };

    // Load validator consensus key.
    let (consensus_sk, consensus_pk, validator_id) =
        load_validator_consensus_key(validator_key_path)?;
    println!("   Validator:   {}", hex::encode(validator_id));

    // Load wallet + sync.
    let key_json = fs::read_to_string(wallet_key_path).context("failed to read wallet key file")?;
    let wallet: WalletKeyFile =
        serde_json::from_str(&key_json).context("failed to parse wallet key file")?;
    let mut state =
        WalletState::load_or_create(wallet_key_path, &wallet.name, &wallet.address)?;
    sync_wallet_from_chain(&client, &mut state).await?;
    println!(
        "   Wallet:      {} ({} UTXOs, {} MISAKA total)",
        wallet.address,
        state.unspent_utxos().len(),
        state.balance
    );

    // Build ValidatorStakeTx envelope.
    let stake_inputs: Vec<StakeInput> = state
        .unspent_utxos()
        .iter()
        .take(16)
        .map(|u| {
            let tx_hash: [u8; 32] = hex::decode(&u.tx_hash)
                .ok()
                .and_then(|v| v.try_into().ok())
                .unwrap_or([0u8; 32]);
            StakeInput {
                tx_hash,
                output_index: u.output_index,
                amount: u.amount,
            }
        })
        .collect();
    if stake_inputs.is_empty() {
        bail!("no UTXOs available to fund the stake deposit");
    }

    let mut envelope = ValidatorStakeTx {
        kind: StakeTxKind::Register,
        validator_id,
        stake_inputs,
        fee,
        nonce: 0,
        memo: moniker.clone(),
        params: StakeTxParams::Register(RegisterParams {
            consensus_pubkey: consensus_pk.clone(),
            reward_address,
            commission_bps,
            p2p_endpoint: p2p_endpoint.clone(),
            moniker,
        }),
        signature: Vec::new(),
    };
    sign_envelope(&mut envelope, &consensus_sk)?;

    submit_stake_deposit(
        rpc_url,
        &client,
        chain_id,
        genesis_hash,
        wallet_key_path,
        &wallet,
        &mut state,
        envelope,
        validator_id,
        stake_amount,
        fee,
    )
    .await
}

/// `stake-more` subcommand.
///
/// Builds `ValidatorStakeTx { kind: StakeMore }`.
pub async fn run_stake_more(
    wallet_key_path: &str,
    validator_key_path: &str,
    additional_amount: u64,
    fee: u64,
    rpc_url: &str,
    chain_id: u32,
    genesis_hash_override: Option<[u8; 32]>,
) -> Result<()> {
    println!("📥 Building stake-more transaction...");
    println!("   Additional:  {} MISAKA (base units)", additional_amount);
    println!("   Fee:         {} MISAKA (base units)", fee);

    let client = RpcClient::new(rpc_url)?;
    let genesis_hash = match genesis_hash_override {
        Some(h) => h,
        None => fetch_genesis_hash_or_default(rpc_url).await,
    };

    let (consensus_sk, _consensus_pk, validator_id) =
        load_validator_consensus_key(validator_key_path)?;
    println!("   Validator:   {}", hex::encode(validator_id));

    let key_json = fs::read_to_string(wallet_key_path).context("failed to read wallet key file")?;
    let wallet: WalletKeyFile =
        serde_json::from_str(&key_json).context("failed to parse wallet key file")?;
    let mut state =
        WalletState::load_or_create(wallet_key_path, &wallet.name, &wallet.address)?;
    sync_wallet_from_chain(&client, &mut state).await?;

    let stake_inputs: Vec<StakeInput> = state
        .unspent_utxos()
        .iter()
        .take(16)
        .map(|u| {
            let tx_hash: [u8; 32] = hex::decode(&u.tx_hash)
                .ok()
                .and_then(|v| v.try_into().ok())
                .unwrap_or([0u8; 32]);
            StakeInput {
                tx_hash,
                output_index: u.output_index,
                amount: u.amount,
            }
        })
        .collect();
    if stake_inputs.is_empty() {
        bail!("no UTXOs available to fund stake-more");
    }

    let mut envelope = ValidatorStakeTx {
        kind: StakeTxKind::StakeMore,
        validator_id,
        stake_inputs,
        fee,
        // nonce: a non-zero sentinel so a `Register` and `StakeMore` for
        // the same validator do not collide on canonical hashes. The real
        // replay protection is `used_stake_signatures` on the registry
        // side (keyed by the L1 tx_hash of this envelope).
        nonce: 1,
        memo: None,
        params: StakeTxParams::StakeMore(StakeMoreParams {
            additional_amount,
        }),
        signature: Vec::new(),
    };
    sign_envelope(&mut envelope, &consensus_sk)?;

    submit_stake_deposit(
        rpc_url,
        &client,
        chain_id,
        genesis_hash,
        wallet_key_path,
        &wallet,
        &mut state,
        envelope,
        validator_id,
        additional_amount,
        fee,
    )
    .await
}

/// Local copy of `public_transfer::sync_wallet_from_chain` — pulls UTXOs
/// for the wallet's master_address from the node and updates local state.
///
/// Kept module-local instead of centralizing in a shared helper because
/// `public_transfer`'s version is also private and a single extraction
/// would be its own PR. Functionally identical.
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

/// Sign the inner `ValidatorStakeTx` envelope in place.
///
/// Matches the pattern in consensus/src/stake_tx_verify.rs tests: blank the
/// signature field, compute `signing_payload()`, ML-DSA-65 sign, write back.
pub(crate) fn sign_envelope(
    envelope: &mut ValidatorStakeTx,
    consensus_sk: &MlDsaSecretKey,
) -> Result<()> {
    envelope.signature.clear();
    let payload = envelope.signing_payload();
    let sig = ml_dsa_sign_raw(consensus_sk, &payload)
        .map_err(|e| anyhow::anyhow!("inner envelope signing failed: {}", e))?;
    envelope.signature = sig.as_bytes().to_vec();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_pqc::pq_sign::MlDsaKeypair;

    fn test_keypair_and_id() -> (MlDsaKeypair, [u8; 32]) {
        let kp = MlDsaKeypair::generate();
        let vid = ValidatorPqPublicKey::from_bytes(kp.public_key.as_bytes())
            .unwrap()
            .to_canonical_id();
        (kp, vid)
    }

    #[test]
    fn stake_register_envelope_encodes_and_signs() {
        let (kp, vid) = test_keypair_and_id();
        let mut envelope = ValidatorStakeTx {
            kind: StakeTxKind::Register,
            validator_id: vid,
            stake_inputs: vec![StakeInput {
                tx_hash: [0xAA; 32],
                output_index: 0,
                amount: 2_000_000_000_000, // well above fee
            }],
            fee: 1_000_000_000,
            nonce: 0,
            memo: None,
            params: StakeTxParams::Register(RegisterParams {
                consensus_pubkey: kp.public_key.as_bytes().to_vec(),
                reward_address: [0x11; 32],
                commission_bps: 500,
                p2p_endpoint: Some("127.0.0.1:30333".into()),
                moniker: Some("alice".into()),
            }),
            signature: Vec::new(),
        };
        sign_envelope(&mut envelope, &kp.secret_key).expect("sign");
        assert_eq!(envelope.signature.len(), 3309, "ML-DSA-65 signature is 3309 bytes");
        envelope.validate_structure().expect("valid structure");

        // Roundtrip via extra.
        let extra = envelope.encode_for_extra().expect("encode extra");
        let decoded = ValidatorStakeTx::decode_from_extra(&extra).expect("decode");
        assert_eq!(decoded.kind, StakeTxKind::Register);
        assert_eq!(decoded.validator_id, vid);
    }

    #[test]
    fn stake_more_envelope_encodes_and_signs() {
        let (kp, vid) = test_keypair_and_id();
        let mut envelope = ValidatorStakeTx {
            kind: StakeTxKind::StakeMore,
            validator_id: vid,
            stake_inputs: vec![StakeInput {
                tx_hash: [0xBB; 32],
                output_index: 0,
                amount: 6_000,
            }],
            fee: 1_000,
            nonce: 1,
            memo: None,
            params: StakeTxParams::StakeMore(StakeMoreParams {
                additional_amount: 5_000,
            }),
            signature: Vec::new(),
        };
        sign_envelope(&mut envelope, &kp.secret_key).expect("sign");
        envelope.validate_structure().expect("valid StakeMore");
        let decoded = ValidatorStakeTx::decode_from_extra(
            &envelope.encode_for_extra().expect("encode"),
        )
        .expect("decode");
        assert!(matches!(decoded.params, StakeTxParams::StakeMore(_)));
    }

    #[test]
    fn stake_register_below_min_stake_is_caught_by_validate_structure() {
        // ValidatorStakeTx structural check doesn't know the registry's
        // min_validator_stake, but it DOES check total_input >= fee. Build
        // a Register with stake_inputs summing below fee → rejected.
        let (kp, vid) = test_keypair_and_id();
        let mut envelope = ValidatorStakeTx {
            kind: StakeTxKind::Register,
            validator_id: vid,
            stake_inputs: vec![StakeInput {
                tx_hash: [0xAA; 32],
                output_index: 0,
                amount: 100,
            }],
            fee: 1_000,
            nonce: 0,
            memo: None,
            params: StakeTxParams::Register(RegisterParams {
                consensus_pubkey: kp.public_key.as_bytes().to_vec(),
                reward_address: [0x11; 32],
                commission_bps: 500,
                p2p_endpoint: None,
                moniker: None,
            }),
            signature: Vec::new(),
        };
        sign_envelope(&mut envelope, &kp.secret_key).expect("sign");
        // validate_structure() should reject because total_input (100) < fee (1000).
        assert!(envelope.validate_structure().is_err());
    }
}
