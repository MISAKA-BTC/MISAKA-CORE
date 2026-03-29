//! CLI — Shielded Pool Commands
//!
//! shield-deposit / shield-withdraw / shielded-status /
//! export-view-key / create-payment-proof の実装。
//!
//! # P0 実装方針
//! - shield-deposit / shield-withdraw は RPC エンドポイントへの stub 送信
//! - wallet 側の note 生成・proof 生成は P1 で実装（現状は構造体を組み立てる）
//! - view key / payment proof は wallet state ファイルから導出

use anyhow::{Context, Result};
use misaka_shielded::{
    CircuitVersion, EncryptedNote, NoteCommitment, Nullifier, ShieldDepositTx,
    ShieldWithdrawTx, ShieldedProof, TreeRoot,
    rpc_types::{
        ShieldedModuleStatusResponse,
        SubmitShieldDepositRequest, SubmitShieldWithdrawRequest, TxSubmitResponse,
    },
};
use serde_json::json;

use crate::rpc_client::RpcClient;
use crate::wallet_state::WalletState;

// ─── Constants ────────────────────────────────────────────────────────────────

const MISAKA_DECIMALS: u64 = 1_000_000_000; // 9 decimal places
const MIN_SHIELDED_FEE: u64 = 1_000;

// ─── shield-deposit ──────────────────────────────────────────────────────────

/// `misaka-cli shield-deposit --amount N --fee F --wallet W --rpc R`
pub async fn shield_deposit_cmd(
    amount: u64,
    fee: u64,
    wallet_path: &str,
    rpc: &str,
) -> Result<()> {
    println!("╔══════════════════════════════════════════════╗");
    println!("║  MISAKA Shield Deposit                       ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();

    if amount == 0 {
        anyhow::bail!("amount must be greater than 0");
    }
    if fee < MIN_SHIELDED_FEE {
        anyhow::bail!("fee must be at least {} base units (got {})", MIN_SHIELDED_FEE, fee);
    }

    // ── 1. Load wallet key ──
    let key_json = std::fs::read_to_string(wallet_path)
        .with_context(|| format!("failed to read wallet key: {}", wallet_path))?;
    let wallet_key: serde_json::Value = serde_json::from_str(&key_json)
        .context("invalid wallet key JSON")?;
    let master_sk_hex = wallet_key["ml_dsa_sk"].as_str()
        .ok_or_else(|| anyhow::anyhow!("missing ml_dsa_sk in wallet key"))?;
    let master_sk_bytes = hex::decode(master_sk_hex).context("invalid ml_dsa_sk hex")?;

    // ── 2. Sync wallet state from chain ──
    let wallet_name = wallet_key["name"].as_str().unwrap_or("wallet");
    let wallet_address = wallet_key["address"].as_str()
        .ok_or_else(|| anyhow::anyhow!("missing address in wallet key"))?;
    let mut state = WalletState::load_or_create(wallet_path, wallet_name, wallet_address)
        .with_context(|| format!("failed to load wallet from {}", wallet_path))?;
    let client = RpcClient::new(rpc)
        .with_context(|| format!("invalid RPC URL: {}", rpc))?;
    // Sync UTXOs from chain
    if let Ok(resp) = client.post_json("/api/get_utxos_by_address",
        &serde_json::json!({"address": state.master_address})).await {
        if let Some(utxos) = resp["utxos"].as_array() {
            for o in utxos {
                let tx_hash = o["txHash"].as_str().unwrap_or_default();
                let output_index = o["outputIndex"].as_u64().unwrap_or(0) as u32;
                let amount_val = o["amount"].as_u64().unwrap_or(0);
                let ki = o["keyImage"].as_str().unwrap_or_default();
                if !state.utxos.iter().any(|u| u.tx_hash == tx_hash && u.output_index == output_index) {
                    state.register_utxo(tx_hash, output_index, amount_val, 0, ki, &state.master_address.clone());
                }
            }
        }
    }

    let total = amount.checked_add(fee).ok_or_else(|| anyhow::anyhow!("overflow"))?;
    println!("  Wallet:        {}", state.master_address);
    println!("  Balance:       {} MISAKA ({} base units)", state.balance as f64 / 1_000_000_000.0, state.balance);
    println!("  Shield amount: {} MISAKA ({} base units)", amount as f64 / 1_000_000_000.0, amount);
    println!("  Fee:           {} base units", fee);
    println!("  Total:         {} base units", total);
    println!();

    if state.balance < total {
        anyhow::bail!("insufficient balance: have {} base units, need {}", state.balance, total);
    }

    // ── 3. Select UTXO(s) to spend ──
    let selected = state.select_utxo(amount, fee)?;
    let input_amount = selected.amount;
    let input_child_index = selected.child_index;
    let input_tx_hash = selected.tx_hash.clone();
    let input_output_index = selected.output_index;
    let change = input_amount - amount - fee;
    println!("  Input:  {} base units (child #{}, tx={}..)", input_amount, input_child_index, &input_tx_hash[..12]);

    // ── 4. Derive signing keypair for this UTXO ──
    let child_index = if input_child_index == 0 { 1 } else { input_child_index };
    let spending = misaka_pqc::pq_ring::SpendingKeypair::derive_child(&master_sk_bytes, child_index)
        .map_err(|e| anyhow::anyhow!("key derivation failed: {}", e))?;
    let sender_pk_bytes = spending.ml_dsa_pk().to_vec();

    // ── 5. Derive from address for ShieldDepositTx ──
    let from_bytes: [u8; 32] = {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:address:v1:");
        h.update(&sender_pk_bytes);
        h.finalize().into()
    };

    // ── 6. Build commitment and encrypted note ──
    let output_commitment = derive_stub_commitment(&state.master_address, amount);
    let encrypted_note = EncryptedNote {
        epk: [0u8; 32],
        ciphertext: vec![0u8; 64],
        tag: [0u8; 16],
        view_tag: 0,
    };

    // ── 7. Build and sign ShieldDepositTx ──
    let unsigned_tx = ShieldDepositTx {
        from: from_bytes,
        amount,
        asset_id: 0,
        fee,
        output_commitment: output_commitment.clone(),
        encrypted_note: encrypted_note.clone(),
        signature_bytes: vec![],
        sender_pubkey: sender_pk_bytes.clone(),
    };
    let payload = unsigned_tx.signing_payload();
    let shielded_sig = misaka_pqc::pq_sign::ml_dsa_sign(&spending.ml_dsa_sk, &payload)
        .map_err(|e| anyhow::anyhow!("ML-DSA-65 signing failed: {}", e))?;

    let deposit_tx = ShieldDepositTx {
        from: from_bytes,
        amount,
        asset_id: 0,
        fee,
        output_commitment,
        encrypted_note,
        signature_bytes: shielded_sig.as_bytes().to_vec(),
        sender_pubkey: sender_pk_bytes.clone(),
    };

    // ── 8. Build transparent UTXO input (P2) ──
    let (_, canonical_ki) = misaka_pqc::ki_proof::canonical_strong_ki(&spending.public_poly, &spending.secret_poly);
    let input_tx_hash_bytes: [u8; 32] = hex::decode(&input_tx_hash)
        .map_err(|e| anyhow::anyhow!("invalid tx hash: {}", e))?
        .try_into().map_err(|_| anyhow::anyhow!("tx hash not 32 bytes"))?;

    // Sign the UTXO input (transparent signature for spending the UTXO)
    let utxo_sign_digest: [u8; 32] = {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:tx:sign:v1:");
        h.update(&input_tx_hash_bytes);
        h.update(&input_output_index.to_le_bytes());
        h.update(&amount.to_le_bytes());
        h.update(&fee.to_le_bytes());
        h.finalize().into()
    };
    let utxo_sig = misaka_pqc::pq_sign::ml_dsa_sign(&spending.ml_dsa_sk, &utxo_sign_digest)
        .map_err(|e| anyhow::anyhow!("UTXO signing failed: {}", e))?;

    let transparent_inputs = vec![misaka_types::utxo::TxInput {
        utxo_refs: vec![misaka_types::utxo::OutputRef {
            tx_hash: input_tx_hash_bytes,
            output_index: input_output_index,
        }],
        proof: utxo_sig.as_bytes().to_vec(),
        key_image: canonical_ki,
        ki_proof: vec![],
    }];

    // ── 9. Build change output if needed ──
    let mut change_outputs = Vec::new();
    if change > 0 {
        let change_addr = misaka_types::address::decode_address(&state.master_address, 2)
            .map_err(|e| anyhow::anyhow!("invalid change address: {}", e))?;
        // Use master wallet pubkey for change (matches faucet UTXO spending_pubkey)
        let master_pk_hex = wallet_key["ml_dsa_pk"].as_str().unwrap_or("");
        let master_pk_bytes = hex::decode(master_pk_hex).unwrap_or_default();
        change_outputs.push(misaka_types::utxo::TxOutput {
            amount: change,
            one_time_address: change_addr,
            pq_stealth: None,
            spending_pubkey: Some(master_pk_bytes),
        });
        println!("  Change: {} base units", change);
    }

    // ── 10. Submit ──
    println!("  Signing with ML-DSA-65...");
    println!("  Submitting to {}...", rpc);

    let body = serde_json::to_value(SubmitShieldDepositRequest {
        tx: deposit_tx,
        transparent_inputs,
        change_outputs,
    }).context("failed to serialize request")?;

    let resp = client
        .post_json("/api/shielded/submit_deposit", &body)
        .await
        .context("RPC request failed")?;

    let result: TxSubmitResponse = serde_json::from_value(resp)
        .context("failed to parse response")?;

    match result.status {
        misaka_shielded::rpc_types::TxSubmitStatus::Accepted => {
            println!("  ✅ Shield deposit accepted!");
            println!("  Tx hash: {}", result.tx_hash);
            println!("  {} MISAKA burned from transparent → shielded pool", amount as f64 / 1_000_000_000.0);
            // Update wallet state
            state.shielded_balance += amount;
            if let Err(e) = state.save(wallet_path) {
                eprintln!("  ⚠ Failed to save wallet state: {}", e);
            }
        }
        misaka_shielded::rpc_types::TxSubmitStatus::ValidatedOnly => {
            println!("  ⚠️  Deposit validated but not committed.");
            println!("  Tx hash: {}", result.tx_hash);
        }
        misaka_shielded::rpc_types::TxSubmitStatus::Rejected => {
            anyhow::bail!(
                "deposit rejected: {}",
                result.error.unwrap_or_else(|| "unknown error".to_string())
            );
        }
    }

    Ok(())
}

// ─── shield-withdraw ─────────────────────────────────────────────────────────

/// `misaka-cli shield-withdraw --to ADDR --amount N --fee F --wallet W --rpc R`
pub async fn shield_withdraw_cmd(
    to: &str,
    amount: u64,
    fee: u64,
    wallet_path: &str,
    rpc: &str,
) -> Result<()> {
    println!("╔══════════════════════════════════════════════╗");
    println!("║  MISAKA Shield Withdraw                      ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();

    if amount == 0 {
        anyhow::bail!("amount must be greater than 0");
    }
    if fee < MIN_SHIELDED_FEE {
        anyhow::bail!(
            "fee must be at least {} base units (got {})",
            MIN_SHIELDED_FEE,
            fee
        );
    }

    let to_bytes = parse_address_32(to)
        .with_context(|| format!("invalid recipient address: {}", to))?;

    println!("  Withdraw amount: {} MISAKA ({} base units)",
        amount as f64 / MISAKA_DECIMALS as f64, amount);
    println!("  Recipient:       {}", to);
    println!("  Fee:             {} base units", fee);
    println!();

    // Load wallet key for nullifier derivation
    let key_json = std::fs::read_to_string(wallet_path)
        .with_context(|| format!("failed to read wallet key: {}", wallet_path))?;
    let wallet_key: serde_json::Value = serde_json::from_str(&key_json)
        .context("invalid wallet key JSON")?;
    let master_sk_hex = wallet_key["ml_dsa_sk"].as_str()
        .ok_or_else(|| anyhow::anyhow!("missing ml_dsa_sk in wallet key"))?;
    let master_sk_bytes = hex::decode(master_sk_hex).context("invalid ml_dsa_sk hex")?;

    // Derive nullifier key from wallet
    let nk: [u8; 32] = {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:nullifier_key:v1:");
        h.update(&master_sk_bytes[..32.min(master_sk_bytes.len())]);
        h.finalize().into()
    };

    // Derive nullifier from amount + nk (deterministic per wallet+amount)
    let nullifier_bytes: [u8; 32] = {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:nullifier:v1:");
        h.update(&nk);
        h.update(&amount.to_le_bytes());
        h.update(&fee.to_le_bytes());
        h.finalize().into()
    };
    let nullifier = Nullifier(nullifier_bytes);

    // Fetch current anchor
    let anchor = fetch_current_anchor(rpc).await
        .unwrap_or_else(|_| TreeRoot::empty());

    // Build withdraw TX
    let tx = ShieldWithdrawTx {
        nullifiers: vec![nullifier],
        anchor,
        withdraw_amount: amount,
        withdraw_recipient: to_bytes,
        fee,
        proof: ShieldedProof::stub(),
        circuit_version: CircuitVersion::STUB_V1,
    };

    // Include recipient spending_pubkey for balance visibility
    let recipient_spending_pubkey = {
        let mpk = wallet_key["ml_dsa_pk"].as_str().unwrap_or("");
        if !mpk.is_empty() {
            Some(hex::decode(mpk).unwrap_or_default())
        } else {
            None
        }
    };

    let client = RpcClient::new(rpc)?;
    let body = serde_json::to_value(SubmitShieldWithdrawRequest {
        tx,
        recipient_spending_pubkey,
    }).context("failed to serialize request")?;

    println!("  Nullifier: {}...", &hex::encode(&nullifier_bytes)[..16]);
    println!("  Submitting to {}...", rpc);

    let resp = client
        .post_json("/api/shielded/submit_withdraw", &body)
        .await
        .context("RPC request failed")?;

    let result: TxSubmitResponse = serde_json::from_value(resp)
        .context("failed to parse response")?;

    match result.status {
        misaka_shielded::rpc_types::TxSubmitStatus::Accepted => {
            println!("  ✅ Withdraw accepted!");
            println!("  Tx hash: {}", result.tx_hash);
            println!("  {} MISAKA withdrawn from shielded → {}", amount as f64 / 1_000_000_000.0, to);
            // Update wallet state
            let key_json2 = std::fs::read_to_string(wallet_path).ok();
            let wallet_key2: Option<serde_json::Value> = key_json2.as_deref().and_then(|j| serde_json::from_str(j).ok());
            let wname = wallet_key2.as_ref().and_then(|w| w["name"].as_str()).unwrap_or("wallet");
            let waddr = wallet_key2.as_ref().and_then(|w| w["address"].as_str()).unwrap_or("");
            if let Ok(mut ws) = WalletState::load_or_create(wallet_path, wname, waddr) {
                ws.shielded_balance = ws.shielded_balance.saturating_sub(amount + fee);
                let _ = ws.save(wallet_path);
            }
        }
        misaka_shielded::rpc_types::TxSubmitStatus::ValidatedOnly => {
            println!("  ✅ Withdraw validated.");
            println!("  Tx hash: {}", result.tx_hash);
        }
        misaka_shielded::rpc_types::TxSubmitStatus::Rejected => {
            anyhow::bail!(
                "withdraw rejected: {}",
                result.error.unwrap_or_else(|| "unknown error".to_string())
            );
        }
    }

    Ok(())
}

// ─── shielded-status ─────────────────────────────────────────────────────────

/// `misaka-cli shielded-status --rpc R`
pub async fn shielded_status_cmd(rpc: &str) -> Result<()> {
    let client = RpcClient::new(rpc)?;

    let resp = client
        .get_json("/api/shielded/module_status")
        .await
        .context("RPC request failed")?;

    let status: ShieldedModuleStatusResponse = serde_json::from_value(resp)
        .context("failed to parse response")?;

    println!("╔══════════════════════════════════════════════╗");
    println!("║  MISAKA Shielded Pool Status                 ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();

    if !status.enabled {
        println!("  ⚠  Shielded module is DISABLED on this node.");
        println!("     This node operates in transparent-only mode.");
        println!("     CEX integration: use transparent transfers only.");
        return Ok(());
    }

    println!("  Status:           ✅ Enabled");
    println!("  Current root:     {}", &status.current_root[..16]);
    println!("  Commitments:      {}", status.commitment_count);
    println!("  Spent nullifiers: {}", status.nullifier_count);
    println!(
        "  Circuit versions: {:?}",
        status.accepted_circuit_versions
    );
    println!();
    println!("  ℹ  Transparent transfers are always available.");
    println!("     Use 'misaka-cli send' for transparent transfers (CEX standard).");

    Ok(())
}

// ─── shielded-scan ───────────────────────────────────────────────────────────

/// `misaka-cli shielded-scan --wallet W --rpc R --from-block N`
pub async fn shielded_scan_cmd(wallet_path: &str, rpc: &str, from_block: u64) -> Result<()> {
    println!("╔══════════════════════════════════════════════╗");
    println!("║  MISAKA Shielded Wallet Scanner              ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();

    // Load wallet key for IVK derivation
    let key_json = std::fs::read_to_string(wallet_path)
        .with_context(|| format!("failed to read wallet: {}", wallet_path))?;
    let wallet_key: serde_json::Value = serde_json::from_str(&key_json)?;
    let sk_hex = wallet_key["ml_dsa_sk"].as_str()
        .ok_or_else(|| anyhow::anyhow!("missing ml_dsa_sk"))?;
    let sk_bytes = hex::decode(sk_hex)?;

    // Derive IVK from secret key
    let ivk: [u8; 32] = {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:incoming_view_key:v1:");
        h.update(&sk_bytes[..32.min(sk_bytes.len())]);
        h.finalize().into()
    };

    println!("  IVK: {}...", &hex::encode(&ivk)[..16]);
    println!("  Scanning from block {}...", from_block);
    println!();

    let client = RpcClient::new(rpc)?;
    let mut current_block = from_block;
    let mut total_found = 0u64;
    let mut total_value = 0u64;
    let mut scanned = 0u64;

    loop {
        let body = serde_json::json!({
            "from_block": current_block,
            "limit": 100
        });
        let resp = client
            .post_json("/api/shielded/encrypted_notes", &body)
            .await
            .context("failed to fetch encrypted notes")?;

        let notes = resp["notes"].as_array().unwrap_or(&Vec::new()).clone();
        let has_more = resp["has_more"].as_bool().unwrap_or(false);
        let next_block = resp["next_from_block"].as_u64().unwrap_or(current_block);

        if notes.is_empty() {
            break;
        }

        for note_json in &notes {
            scanned += 1;

            // Quick view_tag check
            let view_tag = note_json["view_tag"].as_u64().unwrap_or(0) as u8;
            let expected_vt = {
                let epk_hex = note_json["epk"].as_str().unwrap_or("");
                if epk_hex.len() == 64 {
                    let epk_bytes = hex::decode(epk_hex).unwrap_or_default();
                    // Compute expected view_tag
                    let mut hasher = blake3::Hasher::new_derive_key("MISAKA shielded note enc kdf v1");
                    hasher.update(&ivk);
                    hasher.update(&epk_bytes);
                    hasher.finalize().as_bytes()[0]
                } else {
                    continue;
                }
            };

            if view_tag != expected_vt {
                continue; // Not our note
            }

            // View tag match — try full decryption
            let epk_hex = note_json["epk"].as_str().unwrap_or("");
            let ct_hex = note_json["ciphertext"].as_str().unwrap_or("");
            let tag_hex = note_json["tag"].as_str().unwrap_or("");

            let epk = hex::decode(epk_hex).unwrap_or_default();
            let ct = hex::decode(ct_hex).unwrap_or_default();
            let tag = hex::decode(tag_hex).unwrap_or_default();

            if epk.len() != 32 || tag.len() != 16 {
                continue;
            }

            let enc_note = misaka_shielded::types::EncryptedNote {
                epk: epk.try_into().unwrap_or([0u8; 32]),
                ciphertext: ct,
                tag: tag.try_into().unwrap_or([0u8; 16]),
                view_tag,
            };

            match enc_note.try_decrypt(&ivk) {
                Ok(note) => {
                    total_found += 1;
                    total_value += note.value;
                    let pos = note_json["position"].as_u64().unwrap_or(0);
                    let blk = note_json["block_height"].as_u64().unwrap_or(0);
                    println!("  ✅ Found note: position={} value={} block={}", pos, note.value, blk);
                }
                Err(_) => {
                    // View tag false positive — normal
                }
            }
        }

        if !has_more {
            break;
        }
        current_block = next_block;
    }

    println!();
    println!("  ━━━ Scan Results ━━━");
    println!("  Notes scanned:  {}", scanned);
    println!("  Notes found:    {}", total_found);
    println!("  Total value:    {} MISAKA ({} base units)",
        total_value as f64 / 1_000_000_000.0, total_value);
    println!();

    Ok(())
}

// ─── export-view-key ─────────────────────────────────────────────────────────

/// `misaka-cli export-view-key --wallet W`
pub fn export_view_key_cmd(wallet_path: &str) -> Result<()> {
    let state = WalletState::load_or_create(wallet_path, "wallet", "")
        .with_context(|| format!("failed to load wallet from {}", wallet_path))?;

    // P0: stub IVK derived deterministically from wallet address
    // P1: real IVK from ML-KEM-768 key derivation
    let ivk_bytes = derive_stub_ivk(&state.master_address);

    println!("╔══════════════════════════════════════════════╗");
    println!("║  MISAKA View Key Export                      ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();
    println!("  Wallet:     {}", state.master_address);
    println!("  View Key:   {}", hex::encode(ivk_bytes));
    println!();
    println!("  ⚠  IMPORTANT: This key allows the holder to read all");
    println!("     incoming shielded transactions for this wallet.");
    println!("     Share only with trusted parties (auditors, tax agents).");
    println!();
    println!("  Use cases:");
    println!("    - CEX compliance / KYC verification");
    println!("    - Tax accounting");
    println!("    - Legal/audit disclosure");

    Ok(())
}

// ─── create-payment-proof ────────────────────────────────────────────────────

/// `misaka-cli create-payment-proof --commitment HEX --wallet W --output FILE`
pub fn create_payment_proof_cmd(
    commitment_hex: &str,
    wallet_path: &str,
    output_path: &str,
) -> Result<()> {
    let state = WalletState::load_or_create(wallet_path, "wallet", "")
        .with_context(|| format!("failed to load wallet from {}", wallet_path))?;

    // Parse commitment
    let cm_bytes = hex::decode(commitment_hex)
        .context("invalid commitment hex")?;
    if cm_bytes.len() != 32 {
        anyhow::bail!("commitment must be exactly 32 bytes (64 hex chars)");
    }
    let mut cm_arr = [0u8; 32];
    cm_arr.copy_from_slice(&cm_bytes);
    let _cm = NoteCommitment(cm_arr);

    // P0: stub proof
    // P1: look up ScannedNote by commitment from note scanner, build real PaymentProof
    let ivk_bytes = derive_stub_ivk(&state.master_address);
    let _ivk = misaka_shielded::IncomingViewKey(ivk_bytes);

    // Build a minimal payment proof record
    let proof_record = serde_json::json!({
        "wallet": state.master_address,
        "commitment": commitment_hex,
        "ivk_hint": hex::encode(ivk_bytes),
        "note": "P0 stub: full payment proof requires P1 wallet scanner",
        "version": "MISAKA-PaymentProof-v1-stub",
        "instructions": [
            "Submit this file along with your wallet's view key to the auditor.",
            "The auditor can verify the payment using /api/shielded/verify_payment_proof."
        ]
    });

    std::fs::write(output_path, serde_json::to_string_pretty(&proof_record)?)
        .with_context(|| format!("failed to write proof to {}", output_path))?;

    println!("╔══════════════════════════════════════════════╗");
    println!("║  MISAKA Payment Proof Created                ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();
    println!("  Commitment: {}...{}", &commitment_hex[..8], &commitment_hex[commitment_hex.len()-8..]);
    println!("  Output:     {}", output_path);
    println!();
    println!("  ℹ  Submit this file to the auditor or CEX for verification.");

    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Parse a hex address string to 32-byte array.
/// Accepts "0x..." prefix or plain hex, and "msk1..." bech32.
fn parse_address_32(addr: &str) -> Result<[u8; 32]> {
    // v10: Use proper chain-aware address decoder (32 bytes, PQ-safe)
    misaka_types::address::decode_address(addr, 2)
        .map_err(|e| anyhow::anyhow!("failed to decode address '{}': {}", addr, e))
}

/// Derive a stub commitment for P0 (deterministic, not cryptographically binding).
fn derive_stub_commitment(address: &str, amount: u64) -> NoteCommitment {
    let mut hasher = blake3::Hasher::new_derive_key("MISAKA CLI stub commitment v1");
    hasher.update(address.as_bytes());
    hasher.update(&amount.to_le_bytes());
    NoteCommitment(*hasher.finalize().as_bytes())
}

/// Derive a stub IVK for P0.
fn derive_stub_ivk(address: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("MISAKA CLI stub ivk v1");
    hasher.update(address.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Fetch the current Merkle root from the node.
async fn fetch_current_anchor(rpc: &str) -> Result<TreeRoot> {
    let client = RpcClient::new(rpc)?;
    let resp = client
        .get_json("/api/shielded/module_status")
        .await?;
    let status: ShieldedModuleStatusResponse = serde_json::from_value(resp)?;
    let root_bytes = hex::decode(&status.current_root)
        .context("failed to decode root hex")?;
    if root_bytes.len() != 32 {
        anyhow::bail!("invalid root length");
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&root_bytes);
    Ok(TreeRoot(arr))
}
