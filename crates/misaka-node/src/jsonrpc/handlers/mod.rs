//! JSON-RPC method handlers — route method names to implementations.
//!
//! Each sub-module handles a category of methods.
//! All handlers delegate to existing dag_rpc internals — no new business logic.

pub mod blockchain;
pub mod fee;
pub mod mempool;
pub mod misaka;
pub mod tx;
pub mod wallet;

use crate::dag_rpc::DagRpcState;
use serde_json::Value;

/// Handler result: Ok(result_value) or Err(code, message, optional_data).
pub type HandlerResult = Result<Value, (i32, String, Option<Value>)>;

/// Route a method name to the appropriate handler.
pub async fn handle(rpc: &DagRpcState, method: &str, params: &Value) -> HandlerResult {
    match method {
        // ── Blockchain ──
        "getblockchaininfo" => blockchain::get_blockchain_info(rpc).await,
        "getblockcount" => blockchain::get_block_count(rpc).await,
        "getbestblockhash" => blockchain::get_best_block_hash(rpc).await,
        "getblockhash" => blockchain::get_block_hash(rpc, params).await,
        "getblock" => blockchain::get_block(rpc, params).await,
        "getblockheader" => blockchain::get_block_header(rpc, params).await,
        "getmininginfo" => blockchain::get_mining_info(rpc).await,
        "gettxoutsetinfo" => blockchain::get_txout_set_info(rpc).await,
        "uptime" => blockchain::uptime(rpc).await,

        // ── Transactions ──
        "getrawtransaction" => tx::get_raw_transaction(rpc, params).await,
        "decoderawtransaction" => tx::decode_raw_transaction(params).await,
        "sendrawtransaction" => tx::send_raw_transaction(rpc, params).await,
        "gettxout" => tx::get_tx_out(rpc, params).await,

        // ── Wallet (private) ──
        "getbalance" => wallet::get_balance(rpc, params).await,
        "listunspent" => wallet::list_unspent(rpc, params).await,
        "validateaddress" => wallet::validate_address(params).await,

        // ── Fee ──
        "estimatesmartfee" => fee::estimate_smart_fee(rpc, params).await,

        // ── Mempool ──
        "getmempoolinfo" => mempool::get_mempool_info(rpc).await,
        "getrawmempool" => mempool::get_raw_mempool(rpc, params).await,

        // ── Network ──
        "getconnectioncount" => blockchain::get_connection_count(rpc).await,
        "getpeerinfo" => blockchain::get_peer_info(rpc).await,
        "getnetworkinfo" => blockchain::get_network_info(rpc).await,

        // ── MISAKA extensions ──
        "misaka_getDagInfo" => misaka::get_dag_info(rpc).await,
        "misaka_getDagTips" => misaka::get_dag_tips(rpc).await,
        "misaka_getDagBlock" => misaka::get_dag_block(rpc, params).await,
        "misaka_getVirtualChain" => misaka::get_virtual_chain(rpc, params).await,
        "misaka_getVirtualState" => misaka::get_virtual_state(rpc).await,
        "misaka_getCirculatingSupply" => misaka::get_circulating_supply(rpc).await,
        "misaka_getCheckpoint" => misaka::get_checkpoint(rpc).await,
        "misaka_getProtocolVersion" => misaka::get_protocol_version(rpc).await,
        "misaka_getEpochInfo" => misaka::get_epoch_info(rpc).await,
        "misaka_getValidatorSet" => misaka::get_validator_set(rpc).await,
        "misaka_getValidatorById" => misaka::get_validator_by_id(rpc, params).await,
        "misaka_getStakingInfo" => misaka::get_staking_info(rpc, params).await,

        // ── Private MISAKA extensions ──
        "misaka_getAnonymitySet" => misaka::get_anonymity_set(rpc, params).await,
        "misaka_getAddressHistory" => {
            misaka::not_implemented("address_history_index_not_yet_wired")
        }
        "misaka_getBlocksRange" => misaka::get_blocks_range(rpc, params).await,
        "misaka_getTxsRange" => misaka::get_txs_range(rpc, params).await,

        _ => Err((
            super::super::jsonrpc::error::METHOD_NOT_FOUND,
            format!("method '{}' not found", method),
            None,
        )),
    }
}
