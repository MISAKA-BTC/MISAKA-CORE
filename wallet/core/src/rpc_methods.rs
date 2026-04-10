//! Full wallet RPC method implementations.
//!
//! Maps wallet operations to wRPC calls, handling:
//! - Request construction with proper parameters
//! - Response parsing with type-safe deserialization
//! - Error handling and retry logic
//! - Pagination for large result sets
//! - Caching of frequently accessed data

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Wallet RPC method result types.

// ─── Balance Operations ───────────────────────────

/// Get balance for a single address.
pub fn build_get_balance_request(address: &str) -> serde_json::Value {
    serde_json::json!({ "address": address })
}

pub fn parse_balance_response(response: &serde_json::Value) -> Result<u64, String> {
    response
        .get("balance")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "missing 'balance' in response".to_string())
}

/// Get balances for multiple addresses.
pub fn build_get_balances_request(addresses: &[String]) -> serde_json::Value {
    serde_json::json!({ "addresses": addresses })
}

pub fn parse_balances_response(
    response: &serde_json::Value,
) -> Result<Vec<AddressBalance>, String> {
    let entries = response
        .get("entries")
        .and_then(|v| v.as_array())
        .ok_or("missing 'entries'")?;
    entries
        .iter()
        .map(|e| {
            Ok(AddressBalance {
                address: e
                    .get("address")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                balance: e.get("balance").and_then(|v| v.as_u64()).unwrap_or(0),
            })
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressBalance {
    pub address: String,
    pub balance: u64,
}

// ─── UTXO Operations ──────────────────────────────

/// Get UTXOs for addresses.
pub fn build_get_utxos_request(addresses: &[String]) -> serde_json::Value {
    serde_json::json!({ "addresses": addresses })
}

pub fn parse_utxos_response(response: &serde_json::Value) -> Result<Vec<RpcUtxoEntry>, String> {
    let entries = response
        .get("entries")
        .and_then(|v| v.as_array())
        .ok_or("missing 'entries'")?;
    entries
        .iter()
        .map(|e| {
            Ok(RpcUtxoEntry {
                address: e
                    .get("address")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                outpoint: RpcOutpoint {
                    transaction_id: e
                        .get("outpoint")
                        .and_then(|o| o.get("transactionId"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    index: e
                        .get("outpoint")
                        .and_then(|o| o.get("index"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32,
                },
                utxo_entry: RpcUtxoEntryData {
                    amount: e
                        .get("utxoEntry")
                        .and_then(|u| u.get("amount"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    script_public_key: e
                        .get("utxoEntry")
                        .and_then(|u| u.get("scriptPublicKey"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    block_daa_score: e
                        .get("utxoEntry")
                        .and_then(|u| u.get("blockDaaScore"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    is_coinbase: e
                        .get("utxoEntry")
                        .and_then(|u| u.get("isCoinbase"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                },
            })
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcUtxoEntry {
    pub address: String,
    pub outpoint: RpcOutpoint,
    pub utxo_entry: RpcUtxoEntryData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcOutpoint {
    pub transaction_id: String,
    pub index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcUtxoEntryData {
    pub amount: u64,
    pub script_public_key: String,
    pub block_daa_score: u64,
    pub is_coinbase: bool,
}

// ─── Transaction Submission ───────────────────────

/// Build transaction submission request.
pub fn build_submit_tx_request(tx: &SignedTransactionData) -> serde_json::Value {
    serde_json::json!({
        "transaction": {
            "version": tx.version,
            "inputs": tx.inputs.iter().map(|i| serde_json::json!({
                "previousOutpoint": {
                    "transactionId": i.prev_tx_id,
                    "index": i.prev_index,
                },
                "signatureScript": i.signature_script,
                "sequence": i.sequence,
                "sigOpCount": i.sig_op_count,
            })).collect::<Vec<_>>(),
            "outputs": tx.outputs.iter().map(|o| serde_json::json!({
                "value": o.value,
                "scriptPublicKey": {
                    "version": o.script_version,
                    "script": o.script_public_key,
                },
            })).collect::<Vec<_>>(),
            "lockTime": tx.lock_time,
            "subnetworkId": tx.subnetwork_id,
            "gas": tx.gas,
            "payload": tx.payload,
        },
        "allowOrphan": false,
    })
}

pub fn parse_submit_response(response: &serde_json::Value) -> Result<String, String> {
    response
        .get("transactionId")
        .and_then(|v| v.as_str())
        .map(String::from)
        .ok_or_else(|| "missing 'transactionId' in response".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTransactionData {
    pub version: u32,
    pub inputs: Vec<SignedInputData>,
    pub outputs: Vec<OutputData>,
    pub lock_time: u64,
    pub subnetwork_id: String,
    pub gas: u64,
    pub payload: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedInputData {
    pub prev_tx_id: String,
    pub prev_index: u32,
    pub signature_script: String,
    pub sequence: u64,
    pub sig_op_count: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputData {
    pub value: u64,
    pub script_public_key: String,
    pub script_version: u16,
}

// ─── Block Template ───────────────────────────────

pub fn build_get_block_template_request(pay_address: &str) -> serde_json::Value {
    serde_json::json!({ "payAddress": pay_address, "extraData": "" })
}

// ─── Virtual Chain ────────────────────────────────

pub fn build_get_virtual_chain_request(start_hash: &str) -> serde_json::Value {
    serde_json::json!({
        "startHash": start_hash,
        "includeAcceptedTransactionIds": true,
    })
}

pub fn parse_virtual_chain_response(
    response: &serde_json::Value,
) -> Result<VirtualChainData, String> {
    Ok(VirtualChainData {
        removed: response
            .get("removedChainBlockHashes")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        added: response
            .get("addedChainBlockHashes")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        accepted_tx_ids: response
            .get("acceptedTransactionIds")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualChainData {
    pub removed: Vec<String>,
    pub added: Vec<String>,
    pub accepted_tx_ids: Vec<String>,
}

// ─── Subscription Requests ────────────────────────

pub fn build_subscribe_utxos_changed(addresses: &[String]) -> serde_json::Value {
    serde_json::json!({
        "command": "start",
        "scope": "utxosChanged",
        "addresses": addresses,
    })
}

pub fn build_subscribe_virtual_daa_score() -> serde_json::Value {
    serde_json::json!({ "command": "start", "scope": "virtualDaaScoreChanged" })
}

pub fn build_subscribe_block_added() -> serde_json::Value {
    serde_json::json!({ "command": "start", "scope": "blockAdded" })
}

pub fn build_unsubscribe(listener_id: u64) -> serde_json::Value {
    serde_json::json!({ "command": "stop", "listenerId": listener_id })
}

// ─── Network Info ─────────────────────────────────

pub fn parse_dag_info_response(response: &serde_json::Value) -> Result<DagInfoData, String> {
    Ok(DagInfoData {
        network: response
            .get("network")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        block_count: response
            .get("blockCount")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        header_count: response
            .get("headerCount")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        tip_hashes: response
            .get("tipHashes")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        difficulty: response
            .get("difficulty")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0),
        past_median_time: response
            .get("pastMedianTime")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        virtual_daa_score: response
            .get("virtualDaaScore")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        pruning_point_hash: response
            .get("pruningPointHash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagInfoData {
    pub network: String,
    pub block_count: u64,
    pub header_count: u64,
    pub tip_hashes: Vec<String>,
    pub difficulty: f64,
    pub past_median_time: u64,
    pub virtual_daa_score: u64,
    pub pruning_point_hash: String,
}

pub fn parse_fee_estimate_response(response: &serde_json::Value) -> Result<FeeEstimate, String> {
    Ok(FeeEstimate {
        priority: response
            .get("priorityFeeRate")
            .and_then(|v| v.as_f64())
            .unwrap_or(10.0),
        normal: response
            .get("normalFeeRate")
            .and_then(|v| v.as_f64())
            .unwrap_or(5.0),
        low: response
            .get("lowFeeRate")
            .and_then(|v| v.as_f64())
            .unwrap_or(1.0),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeEstimate {
    pub priority: f64,
    pub normal: f64,
    pub low: f64,
}

/// Paginated request helper.
pub struct PaginatedRequest {
    pub method: String,
    pub base_params: serde_json::Value,
    pub cursor: Option<String>,
    pub page_size: u32,
}

impl PaginatedRequest {
    pub fn build_request(&self) -> serde_json::Value {
        let mut params = self.base_params.clone();
        if let Some(ref cursor) = self.cursor {
            params["cursor"] = serde_json::json!(cursor);
        }
        params["limit"] = serde_json::json!(self.page_size);
        params
    }

    pub fn advance(&mut self, next_cursor: Option<String>) -> bool {
        self.cursor = next_cursor;
        self.cursor.is_some()
    }
}

/// Response cache for expensive queries.
pub struct ResponseCache {
    cache: parking_lot::Mutex<HashMap<String, CachedResponse>>,
    ttl_ms: u64,
    max_entries: usize,
}

#[derive(Debug, Clone)]
struct CachedResponse {
    value: serde_json::Value,
    cached_at: u64,
}

impl ResponseCache {
    pub fn new(ttl_ms: u64, max_entries: usize) -> Self {
        Self {
            cache: parking_lot::Mutex::new(HashMap::new()),
            ttl_ms,
            max_entries,
        }
    }

    pub fn get(&self, key: &str) -> Option<serde_json::Value> {
        let cache = self.cache.lock();
        cache.get(key).and_then(|entry| {
            let now = now_ms();
            if now - entry.cached_at < self.ttl_ms {
                Some(entry.value.clone())
            } else {
                None
            }
        })
    }

    pub fn put(&self, key: String, value: serde_json::Value) {
        let mut cache = self.cache.lock();
        if cache.len() >= self.max_entries {
            // Evict oldest
            let oldest_key = cache
                .iter()
                .min_by_key(|(_, v)| v.cached_at)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest_key {
                cache.remove(&k);
            }
        }
        cache.insert(
            key,
            CachedResponse {
                value,
                cached_at: now_ms(),
            },
        );
    }

    pub fn invalidate(&self, key: &str) {
        self.cache.lock().remove(key);
    }
    pub fn clear(&self) {
        self.cache.lock().clear();
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
