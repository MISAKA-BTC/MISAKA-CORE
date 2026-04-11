use super::HandlerResult;
use crate::dag_rpc::DagRpcState;
use crate::jsonrpc::error::*;
use serde_json::{json, Value};

/// `getbalance` — sum UTXO amounts for a given address.
///
/// Scans UTXO set via spending_pubkey → address derivation (same as
/// the existing dag_get_utxos_by_address endpoint). O(N) scan.
pub async fn get_balance(rpc: &DagRpcState, params: &Value) -> HandlerResult {
    let address = params
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            (
                INVALID_PARAMS,
                "params[0]: expected address string".into(),
                None,
            )
        })?
        .trim();

    let s = rpc.node.read().await;

    // Validate address with chain_id binding
    if let Err(e) = misaka_types::address::validate_address(address, s.chain_id) {
        return Err((ADDRESS_INVALID, format!("invalid address: {}", e), None));
    }

    let mut balance: u64 = 0;
    for (outref, pk_bytes) in s.utxo_set.all_spending_keys() {
        let derived = derive_address_from_spending_key(pk_bytes, s.chain_id);
        if derived != address {
            continue;
        }
        if let Some(entry) = s.utxo_set.get(outref) {
            balance = balance.saturating_add(entry.output.amount);
        }
    }

    Ok(json!({
        "balance": balance,
        "decimals": 9,
    }))
}

/// `listunspent` — list UTXOs for a given address.
pub async fn list_unspent(rpc: &DagRpcState, params: &Value) -> HandlerResult {
    let address = params
        .get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            (
                INVALID_PARAMS,
                "params[0]: expected address string".into(),
                None,
            )
        })?
        .trim();

    let s = rpc.node.read().await;

    if let Err(e) = misaka_types::address::validate_address(address, s.chain_id) {
        return Err((ADDRESS_INVALID, format!("invalid address: {}", e), None));
    }

    let mut utxos = Vec::new();
    for (outref, pk_bytes) in s.utxo_set.all_spending_keys() {
        let derived = derive_address_from_spending_key(pk_bytes, s.chain_id);
        if derived != address {
            continue;
        }
        if let Some(entry) = s.utxo_set.get(outref) {
            utxos.push(json!({
                "txid": hex::encode(outref.tx_hash),
                "vout": outref.output_index,
                "amount": entry.output.amount,
                "oneTimeAddress": hex::encode(entry.output.address),
                "spendingPubkey": hex::encode(pk_bytes),
                "createdAt": entry.created_at,
            }));
        }
    }

    Ok(Value::Array(utxos))
}

/// `validateaddress` — check whether an address string is valid.
pub async fn validate_address(params: &Value) -> HandlerResult {
    let address = params.get(0).and_then(|v| v.as_str()).ok_or_else(|| {
        (
            INVALID_PARAMS,
            "params[0]: expected address string".into(),
            None,
        )
    })?;

    // Format-only validation (no chain_id required)
    let is_valid = misaka_types::address::validate_format(address).is_ok();

    Ok(json!({
        "isvalid": is_valid,
        "address": address,
    }))
}

/// Derive a display address from a spending pubkey (mirrors dag_rpc::derive_address_from_spending_key).
fn derive_address_from_spending_key(pk_bytes: &[u8], chain_id: u32) -> String {
    use sha3::{Digest, Sha3_256};
    let hash: [u8; 32] = {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:address:v1:");
        h.update(pk_bytes);
        h.finalize().into()
    };
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&hash);
    misaka_types::address::encode_address(&addr, chain_id)
}
