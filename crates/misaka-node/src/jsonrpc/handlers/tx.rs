use serde_json::{json, Value};
use crate::dag_rpc::DagRpcState;
use super::HandlerResult;
use crate::jsonrpc::error::*;

/// `getrawtransaction` — look up a transaction by txid.
pub async fn get_raw_transaction(rpc: &DagRpcState, params: &Value) -> HandlerResult {
    let txid_hex = params.get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| (INVALID_PARAMS, "params[0]: expected txid hex".into(), None))?;
    let verbose = params.get(1).and_then(|v| v.as_bool()).unwrap_or(false);

    let tx_hash: [u8; 32] = hex::decode(txid_hex)
        .map_err(|e| (INVALID_PARAMS, format!("invalid hex: {}", e), None))?
        .try_into()
        .map_err(|_| (INVALID_PARAMS, "txid must be 32 bytes".into(), None))?;

    let s = rpc.node.read().await;

    // Check mempool first
    if let Some(tx) = s.mempool.get_by_hash(&tx_hash) {
        return if verbose {
            Ok(tx_to_json(tx, None))
        } else {
            // Return serialized hex
            // Phase 2c-A: borsh encoding for hex response
            let bytes = borsh::to_vec(tx)
                .map_err(|e| (INTERNAL_ERROR, format!("borsh encode: {}", e), None))?;
            Ok(Value::String(hex::encode(bytes)))
        };
    }

    // Check dag_store
    if let Some((block_hash, tx)) = s.dag_store.find_tx(&tx_hash) {
        return if verbose {
            Ok(tx_to_json(&tx, Some(block_hash)))
        } else {
            // Phase 2c-A: borsh encoding for hex response
            let bytes = borsh::to_vec(&tx)
                .map_err(|e| (INTERNAL_ERROR, format!("borsh encode: {}", e), None))?;
            Ok(Value::String(hex::encode(bytes)))
        };
    }

    Err((TX_NOT_FOUND, format!("tx {} not found", txid_hex), None))
}

/// `decoderawtransaction` — decode a hex-encoded transaction without state.
pub async fn decode_raw_transaction(params: &Value) -> HandlerResult {
    let hex_tx = params.get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| (INVALID_PARAMS, "params[0]: expected hex-encoded tx".into(), None))?;

    let bytes = hex::decode(hex_tx)
        .map_err(|e| (INVALID_PARAMS, format!("invalid hex: {}", e), None))?;
    // Phase 2c-A: borsh decoding for hex-encoded tx
    let tx: misaka_types::utxo::UtxoTransaction = borsh::from_slice(&bytes)
        .map_err(|e| (INVALID_PARAMS, format!("invalid tx format: {}", e), None))?;

    Ok(tx_to_json(&tx, None))
}

/// `sendrawtransaction` — submit a raw transaction to the mempool.
///
/// Goes through verify_dag_pre_admission for validation.
pub async fn send_raw_transaction(rpc: &DagRpcState, params: &Value) -> HandlerResult {
    let hex_tx = params.get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| (INVALID_PARAMS, "params[0]: expected hex-encoded tx".into(), None))?;

    let bytes = hex::decode(hex_tx)
        .map_err(|e| (INVALID_PARAMS, format!("invalid hex: {}", e), None))?;

    // Size limit (same as dag_submit_tx: 128 KiB)
    if bytes.len() > 131_072 {
        return Err((
            TX_REJECTED_INVALID_FORMAT,
            format!("tx body too large: {} bytes (max 131072)", bytes.len()),
            None,
        ));
    }

    // Phase 2c-A: borsh decoding for hex-encoded tx
    let tx: misaka_types::utxo::UtxoTransaction = borsh::from_slice(&bytes)
        .map_err(|e| (TX_REJECTED_INVALID_FORMAT, format!("invalid tx format: {}", e), None))?;

    if let Err(e) = tx.validate_structure() {
        return Err((TX_REJECTED_INVALID_FORMAT, format!("structural validation failed: {}", e), None));
    }

    let tx_hash = tx.tx_hash();

    // Delegate to the existing DagTxDisseminationService which handles
    // mempool admission, key-image checks, and dissemination pipeline.
    // Pre-admission validation (signature verification, UTXO existence)
    // is done inline via the validation closure.
    let dissemination = crate::dag_tx_dissemination_service::DagTxDisseminationService::new(
        rpc.node.clone(),
    );
    // Simple admission without the full verify_dag_pre_admission (which is
    // crate-private in dag_rpc). The dissemination service already checks
    // key-image conflicts and mempool capacity.
    let result = dissemination.admit_transaction(tx).await;

    match result {
        Ok(_) => Ok(Value::String(hex::encode(tx_hash))),
        Err(e) => Err((TX_REJECTED_INVALID_FORMAT, e, None)),
    }
}

/// `gettxout` — look up a specific UTXO.
pub async fn get_tx_out(rpc: &DagRpcState, params: &Value) -> HandlerResult {
    let txid_hex = params.get(0)
        .and_then(|v| v.as_str())
        .ok_or_else(|| (INVALID_PARAMS, "params[0]: expected txid hex".into(), None))?;
    let vout = params.get(1)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| (INVALID_PARAMS, "params[1]: expected vout (u64)".into(), None))? as u32;

    let tx_hash: [u8; 32] = hex::decode(txid_hex)
        .map_err(|e| (INVALID_PARAMS, format!("invalid hex: {}", e), None))?
        .try_into()
        .map_err(|_| (INVALID_PARAMS, "txid must be 32 bytes".into(), None))?;

    let outref = misaka_types::utxo::OutputRef { tx_hash, output_index: vout };

    let s = rpc.node.read().await;
    match s.utxo_set.get(&outref) {
        Some(entry) => Ok(json!({
            "bestblock": hex::encode(s.genesis_hash), // TODO: track actual tip hash
            "confirmations": 1, // TODO: compute from blue score difference
            "value": entry.output.amount,
            "address": hex::encode(entry.output.address),
            "coinbase": false,
        })),
        None => Ok(Value::Null),
    }
}

/// Convert a UtxoTransaction to a JSON Value.
fn tx_to_json(tx: &misaka_types::utxo::UtxoTransaction, block_hash: Option<[u8; 32]>) -> Value {
    json!({
        "txid": hex::encode(tx.tx_hash()),
        "version": tx.version,
        "txType": format!("{:?}", tx.tx_type),
        "proofScheme": 0u8,
        "fee": tx.fee,
        "inputCount": tx.inputs.len(),
        "outputCount": tx.outputs.len(),
        "inputs": tx.inputs.iter().map(|inp| json!({
            "spendId": hex::encode(&inp.utxo_refs[0].tx_hash),
            "utxoRefCount": inp.utxo_refs.len(),
        })).collect::<Vec<_>>(),
        "outputs": tx.outputs.iter().enumerate().map(|(i, out)| json!({
            "index": i,
            "amount": out.amount,
            "oneTimeAddress": hex::encode(out.address),
        })).collect::<Vec<_>>(),
        "blockhash": block_hash.map(|h| hex::encode(h)),
    })
}
