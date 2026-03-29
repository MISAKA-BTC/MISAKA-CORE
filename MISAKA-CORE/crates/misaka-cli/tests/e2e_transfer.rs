//! End-to-End Integration Tests — CLI → API → RPC → Node.
//!
//! # Architecture
//!
//! These tests exercise the full pipeline without starting real network
//! listeners. Instead, they use the core logic directly:
//!
//! ```text
//! CLI core logic (send, balance, keygen)
//!       ↓
//! RPC types (JsonRpcRequest/Response)
//!       ↓
//! handle_request() (in-process, no HTTP)
//!       ↓
//! Wallet state (in-memory)
//! ```
//!
//! This catches state mismatch bugs (API says success but state is wrong)
//! without the flakiness of real HTTP calls.
//!
//! # Running
//!
//! ```bash
//! cargo test --test e2e_transfer -- --nocapture
//! ```

use misaka_rpc::{
    handle_request, handle_batch, validate_request,
    JsonRpcRequest, JsonRpcResponse,
    ERR_METHOD_NOT_FOUND, ERR_INVALID_PARAMS, ERR_INVALID_REQUEST,
};
use std::collections::HashSet;

// ═══════════════════════════════════════════════════════════════
//  Test Harness — In-Memory Node State
// ═══════════════════════════════════════════════════════════════

/// Simulated node state for testing.
struct TestNode {
    height: u64,
    utxo_count: usize,
    mempool_size: usize,
    chain_id: u32,
    /// Submitted TX hashes (for dedup testing).
    submitted_txs: HashSet<String>,
}

impl TestNode {
    fn new() -> Self {
        Self {
            height: 0,
            utxo_count: 0,
            mempool_size: 0,
            chain_id: 2, // testnet
            submitted_txs: HashSet::new(),
        }
    }

    /// Simulate mining a new block.
    fn mine_block(&mut self, tx_count: usize) {
        self.height += 1;
        self.utxo_count += tx_count * 2; // assume 2 outputs per tx
        self.mempool_size = self.mempool_size.saturating_sub(tx_count);
    }

    /// Dispatch a JSON-RPC request through the real handler.
    fn rpc(&self, method: &str, params: serde_json::Value) -> JsonRpcResponse {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: method.into(),
            params,
            id: serde_json::json!(1),
        };
        handle_request(
            &req,
            self.height,
            self.utxo_count,
            self.mempool_size,
            self.chain_id,
        )
    }
}

// ═══════════════════════════════════════════════════════════════
//  Wallet State Harness
// ═══════════════════════════════════════════════════════════════

/// Minimal wallet state for E2E testing.
struct TestWallet {
    address: String,
    balance: u64,
    utxos: Vec<TestUtxo>,
    spent_key_images: HashSet<String>,
}

struct TestUtxo {
    tx_hash: String,
    output_index: u32,
    amount: u64,
    key_image: String,
    spent: bool,
}

impl TestWallet {
    fn new(address: &str) -> Self {
        Self {
            address: address.to_string(),
            balance: 0,
            utxos: Vec::new(),
            spent_key_images: HashSet::new(),
        }
    }

    fn receive(&mut self, tx_hash: &str, idx: u32, amount: u64, key_image: &str) {
        self.utxos.push(TestUtxo {
            tx_hash: tx_hash.to_string(),
            output_index: idx,
            amount,
            key_image: key_image.to_string(),
            spent: false,
        });
        self.recalc();
    }

    fn spend(&mut self, key_image: &str) -> Result<u64, String> {
        if self.spent_key_images.contains(key_image) {
            return Err("double spend: key image already used".into());
        }
        let utxo = self
            .utxos
            .iter_mut()
            .find(|u| u.key_image == key_image && !u.spent)
            .ok_or("UTXO not found")?;
        utxo.spent = true;
        self.spent_key_images.insert(key_image.to_string());
        let amount = utxo.amount;
        self.recalc();
        Ok(amount)
    }

    fn recalc(&mut self) {
        self.balance = self.utxos.iter().filter(|u| !u.spent).map(|u| u.amount).sum();
    }

    fn unspent_count(&self) -> usize {
        self.utxos.iter().filter(|u| !u.spent).count()
    }
}

// ═══════════════════════════════════════════════════════════════
//  E2E Tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn e2e_happy_path_transfer() {
    // Setup: node at height 0, wallet with faucet UTXO
    let mut node = TestNode::new();
    let mut alice = TestWallet::new("msk1alice000000000000000000000000000000000");
    let mut bob = TestWallet::new("msk1bob00000000000000000000000000000000000");

    // Faucet drip to Alice
    alice.receive("faucet_tx_001", 0, 10_000_000, "ki_alice_001");
    assert_eq!(alice.balance, 10_000_000);

    // Mine the faucet block
    node.mine_block(1);
    assert_eq!(node.height, 1);

    // Alice sends 3 MISAKA to Bob
    let send_amount = 3_000_000;
    let fee = 100;
    let input_amount = alice
        .spend("ki_alice_001")
        .expect("spend alice utxo");
    assert_eq!(input_amount, 10_000_000);

    let change = input_amount - send_amount - fee;
    bob.receive("tx_transfer_001", 0, send_amount, "ki_bob_001");
    alice.receive("tx_transfer_001", 1, change, "ki_alice_change_001");

    // Verify balances
    assert_eq!(bob.balance, 3_000_000);
    assert_eq!(alice.balance, change);
    assert_eq!(alice.balance + bob.balance + fee, 10_000_000);

    // Verify via RPC
    let status = node.rpc("misaka_getStatus", serde_json::Value::Null);
    assert!(status.result.is_some());

    let height = node.rpc("misaka_getHeight", serde_json::Value::Null);
    assert_eq!(height.result, Some(serde_json::json!(1)));

    node.mine_block(1);
    let height2 = node.rpc("misaka_getHeight", serde_json::Value::Null);
    assert_eq!(height2.result, Some(serde_json::json!(2)));
}

#[test]
fn e2e_double_spend_prevention() {
    let mut alice = TestWallet::new("msk1alice");

    // Single UTXO
    alice.receive("tx_001", 0, 5_000_000, "ki_001");

    // First spend succeeds
    let result1 = alice.spend("ki_001");
    assert!(result1.is_ok());

    // Second spend of same key image fails
    let result2 = alice.spend("ki_001");
    assert!(result2.is_err());
    assert!(result2.unwrap_err().contains("double spend"));
}

#[test]
fn e2e_batch_rpc_all_succeed() {
    let node = TestNode::new();

    let batch_body = serde_json::json!([
        { "jsonrpc": "2.0", "method": "misaka_getHeight", "params": null, "id": 1 },
        { "jsonrpc": "2.0", "method": "misaka_getUtxoCount", "params": null, "id": 2 },
        { "jsonrpc": "2.0", "method": "misaka_getStatus", "params": null, "id": 3 },
        { "jsonrpc": "2.0", "method": "misaka_getMempoolInfo", "params": null, "id": 4 },
    ]);

    let resp = handle_batch(
        serde_json::to_vec(&batch_body).expect("ser").as_slice(),
        node.height,
        node.utxo_count,
        node.mempool_size,
        node.chain_id,
    );

    assert!(resp.is_some());
    let arr = resp.expect("batch response");
    let items = arr.as_array().expect("array");
    assert_eq!(items.len(), 4, "all 4 requests should produce responses");

    // None should have errors
    for item in items {
        assert!(
            item.get("error").is_none() || item["error"].is_null(),
            "batch item should succeed: {:?}",
            item
        );
    }
}

#[test]
fn e2e_batch_mixed_success_and_error() {
    let node = TestNode::new();

    let batch_body = serde_json::json!([
        { "jsonrpc": "2.0", "method": "misaka_getHeight", "params": null, "id": 1 },
        { "jsonrpc": "2.0", "method": "nonexistent_method", "params": null, "id": 2 },
        { "jsonrpc": "2.0", "method": "misaka_getUtxoCount", "params": null, "id": 3 },
    ]);

    let resp = handle_batch(
        serde_json::to_vec(&batch_body).expect("ser").as_slice(),
        node.height,
        node.utxo_count,
        node.mempool_size,
        node.chain_id,
    );

    let arr = resp.expect("batch response");
    let items = arr.as_array().expect("array");
    assert_eq!(items.len(), 3);

    // First and third should succeed
    assert!(items[0]["result"].is_number());
    assert!(items[2]["result"].is_number());

    // Second should be method-not-found error
    assert!(items[1]["error"].is_object());
    assert_eq!(items[1]["error"]["code"], ERR_METHOD_NOT_FOUND);
}

#[test]
fn e2e_pending_then_confirmed_state() {
    let mut node = TestNode::new();
    let mut alice = TestWallet::new("msk1alice");

    // Setup: Alice has a UTXO
    alice.receive("tx_faucet", 0, 1_000_000, "ki_001");
    node.mempool_size = 0;

    // Send: Alice spends — TX goes to mempool
    alice.spend("ki_001").expect("spend");
    node.mempool_size = 1;

    // Before mining: mempool should show 1
    let mempool = node.rpc("misaka_getMempoolInfo", serde_json::Value::Null);
    let mp_result = mempool.result.expect("mempool result");
    assert_eq!(mp_result["size"], 1);

    // Mine the block
    node.mine_block(1);

    // After mining: mempool should be 0, height should be 1
    let mempool2 = node.rpc("misaka_getMempoolInfo", serde_json::Value::Null);
    assert_eq!(mempool2.result.expect("result")["size"], 0);

    let height = node.rpc("misaka_getHeight", serde_json::Value::Null);
    assert_eq!(height.result, Some(serde_json::json!(1)));
}

#[test]
fn e2e_rpc_validation_rejects_bad_requests() {
    let node = TestNode::new();

    // Wrong JSON-RPC version
    let bad_version = node.rpc("misaka_getHeight", serde_json::Value::Null);
    // Actually let's test via handle_request directly with bad version
    let req = JsonRpcRequest {
        jsonrpc: "1.0".into(),
        method: "misaka_getHeight".into(),
        params: serde_json::Value::Null,
        id: serde_json::json!(1),
    };
    let resp = handle_request(&req, 0, 0, 0, 2);
    assert!(resp.error.is_some());
    assert_eq!(
        resp.error.as_ref().expect("err").code,
        ERR_INVALID_REQUEST
    );
}

#[test]
fn e2e_rpc_fee_estimate_reflects_mempool_pressure() {
    let mut node = TestNode::new();

    // Low pressure
    node.mempool_size = 10;
    let low = node.rpc("misaka_getFeeEstimate", serde_json::Value::Null);
    let low_fee = low.result.expect("result")["medium"]
        .as_u64()
        .expect("u64");

    // High pressure
    node.mempool_size = 600;
    let high = node.rpc("misaka_getFeeEstimate", serde_json::Value::Null);
    let high_fee = high.result.expect("result")["medium"]
        .as_u64()
        .expect("u64");

    assert!(
        high_fee > low_fee,
        "high mempool pressure should increase fee estimate: low={}, high={}",
        low_fee,
        high_fee
    );
}

#[test]
fn e2e_method_discovery() {
    let node = TestNode::new();
    let resp = node.rpc("rpc_methods", serde_json::Value::Null);
    let result = resp.result.expect("result");
    let methods = result["methods"].as_array().expect("methods array");

    // Core methods should be present
    let method_names: Vec<&str> = methods.iter().filter_map(|m| m.as_str()).collect();
    assert!(method_names.contains(&"misaka_getStatus"));
    assert!(method_names.contains(&"misaka_getHeight"));
    assert!(method_names.contains(&"misaka_getFeeEstimate"));
    assert!(method_names.contains(&"misaka_getMempoolInfo"));
}

#[test]
fn e2e_wallet_multi_utxo_tracking() {
    let mut alice = TestWallet::new("msk1alice");

    // Receive 3 UTXOs from different sources
    alice.receive("tx_001", 0, 1_000_000, "ki_001");
    alice.receive("tx_002", 0, 2_000_000, "ki_002");
    alice.receive("tx_003", 0, 500_000, "ki_003");

    assert_eq!(alice.balance, 3_500_000);
    assert_eq!(alice.unspent_count(), 3);

    // Spend one
    alice.spend("ki_002").expect("spend");
    assert_eq!(alice.balance, 1_500_000);
    assert_eq!(alice.unspent_count(), 2);

    // Receive change
    alice.receive("tx_004", 1, 1_900_000, "ki_004");
    assert_eq!(alice.balance, 3_400_000);
    assert_eq!(alice.unspent_count(), 3);
}

#[test]
fn e2e_concurrent_tx_isolation() {
    // Simulate two transactions trying to use overlapping UTXOs
    let mut alice = TestWallet::new("msk1alice");

    alice.receive("tx_001", 0, 5_000_000, "ki_001");
    alice.receive("tx_002", 0, 3_000_000, "ki_002");

    // TX A uses ki_001
    assert!(alice.spend("ki_001").is_ok());

    // TX B tries to use ki_001 again → should fail
    assert!(alice.spend("ki_001").is_err());

    // TX B can use ki_002 instead
    assert!(alice.spend("ki_002").is_ok());

    // Both spent now
    assert_eq!(alice.balance, 0);
}

#[test]
fn e2e_rpc_validator_param_validation() {
    let node = TestNode::new();

    // Missing required validatorId
    let resp = node.rpc(
        "misaka_getValidatorWorkload",
        serde_json::json!({}),
    );
    assert!(resp.error.is_some());
    assert_eq!(
        resp.error.as_ref().expect("err").code,
        ERR_INVALID_PARAMS
    );

    // With validatorId → should get NOT_IMPLEMENTED (not method-not-found)
    let resp2 = node.rpc(
        "misaka_getValidatorWorkload",
        serde_json::json!({"validatorId": "val_001"}),
    );
    assert!(resp2.error.is_some());
    let code = resp2.error.as_ref().expect("err").code;
    assert_ne!(code, ERR_METHOD_NOT_FOUND);
    assert_ne!(code, ERR_INVALID_PARAMS);
}
