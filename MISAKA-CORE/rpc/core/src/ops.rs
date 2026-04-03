//! RPC operation codes.
//!
//! Each RPC method has a corresponding op code for routing and dispatch.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RpcApiOps {
    GetBlock,
    GetBlockHeader,
    GetBlockCount,
    GetBlockHash,
    SubmitBlock,
    SubmitTransaction,
    GetTransaction,
    GetMempool,
    GetMempoolEntry,
    GetChainInfo,
    GetDagInfo,
    GetVirtualSelectedParent,
    GetBlockDagInfo,
    GetValidators,
    GetStakingInfo,
    RegisterValidator,
    GetPeerInfo,
    GetConnectedPeerInfo,
    GetNetworkInfo,
    GetUtxosByAddress,
    GetBalance,
    SubmitShieldedTransaction,
    GetInfo,
    GetHealth,
    Ping,
}
