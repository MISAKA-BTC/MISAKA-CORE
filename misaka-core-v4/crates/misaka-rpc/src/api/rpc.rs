//! Core RPC API trait — defines all available RPC methods.

use crate::error::RpcResult;
use crate::model::*;

/// Maximum safe window size for header/block queries.
pub const MAX_SAFE_WINDOW_SIZE: u32 = 10_000;

/// The main RPC API trait.
#[async_trait::async_trait]
pub trait RpcApi: Send + Sync {
    // ─── Node info ────────────────────
    async fn ping(&self) -> RpcResult<()>;
    async fn get_system_info(&self) -> RpcResult<GetSystemInfoResponse>;
    async fn get_connections(&self, include_profile: bool) -> RpcResult<GetConnectionsResponse>;
    async fn get_metrics(&self, req: GetMetricsRequest) -> RpcResult<GetMetricsResponse>;

    // ─── Block queries ────────────────
    async fn get_block(&self, hash: String, include_txs: bool) -> RpcResult<GetBlockResponse>;
    async fn get_blocks(
        &self,
        low_hash: Option<String>,
        include_txs: bool,
        max_blocks: u32,
    ) -> RpcResult<GetBlocksResponse>;
    async fn get_block_count(&self) -> RpcResult<GetBlockCountResponse>;
    async fn get_block_dag_info(&self) -> RpcResult<GetBlockDagInfoResponse>;
    async fn get_headers(&self, start_hash: String, limit: u32) -> RpcResult<GetHeadersResponse>;

    // ─── Transaction queries ──────────
    async fn get_mempool_entries(
        &self,
        include_orphans: bool,
        filter_tx_pool: bool,
    ) -> RpcResult<GetMempoolEntriesResponse>;
    async fn get_mempool_entry(&self, tx_id: String) -> RpcResult<GetMempoolEntryResponse>;
    async fn submit_transaction(
        &self,
        tx: RpcTransaction,
        allow_orphan: bool,
    ) -> RpcResult<SubmitTransactionResponse>;

    // ─── UTXO queries ─────────────────
    async fn get_utxos_by_addresses(
        &self,
        addresses: Vec<String>,
    ) -> RpcResult<GetUtxosByAddressesResponse>;
    async fn get_balance_by_address(
        &self,
        address: String,
    ) -> RpcResult<GetBalanceByAddressResponse>;
    async fn get_balances_by_addresses(
        &self,
        addresses: Vec<String>,
    ) -> RpcResult<GetBalancesByAddressesResponse>;

    // ─── DAG state ────────────────────
    async fn get_virtual_chain_from_block(
        &self,
        start_hash: String,
        include_accepted: bool,
    ) -> RpcResult<GetVirtualChainResponse>;
    async fn get_sink_blue_score(&self) -> RpcResult<u64>;
    async fn get_virtual_daa_score(&self) -> RpcResult<u64>;

    // ─── Mining ───────────────────────
    async fn get_block_template(
        &self,
        pay_address: String,
        extra_data: String,
    ) -> RpcResult<GetBlockTemplateResponse>;
    async fn submit_block(&self, block: RpcBlock) -> RpcResult<SubmitBlockResponse>;
    async fn get_coinbase_address(&self) -> RpcResult<String>;

    // ─── Fee estimation ───────────────
    async fn estimate_fee_rate(&self) -> RpcResult<FeeEstimateResponse>;

    // ─── Pruning ──────────────────────
    async fn get_pruning_point(&self) -> RpcResult<String>;
    async fn resolve_finality_conflict(&self, hash: String) -> RpcResult<()>;

    // ─── Subscription management ──────
    async fn subscribe(&self, scope: String) -> RpcResult<SubscribeResponse>;
    async fn unsubscribe(&self, listener_id: u64) -> RpcResult<()>;

    // ─── Network ──────────────────────
    async fn get_peer_addresses(&self) -> RpcResult<Vec<String>>;
    async fn add_peer(&self, address: String, is_permanent: bool) -> RpcResult<()>;
    async fn ban_peer(&self, address: String) -> RpcResult<()>;
    async fn unban_peer(&self, address: String) -> RpcResult<()>;

    // ─── Shutdown ─────────────────────
    async fn shutdown(&self) -> RpcResult<()>;
}
