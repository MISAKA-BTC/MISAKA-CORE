//! Bitcoin Core compatible JSON-RPC 2.0 dispatcher for MISAKA-CORE.
//!
//! All standard Bitcoin Core methods map to existing DAG RPC handlers.
//! MISAKA-specific extensions use the `misaka_*` namespace.
//!
//! # Architecture
//!
//! Single endpoint `POST /` accepts JSON-RPC 2.0 requests (single or batch).
//! Method tier (Public/Private) determines auth requirements.

// Phase 2c-B: dispatcher.rs deleted (fail-open auth dead code)
pub mod error;
pub mod handlers;

/// Method access tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodTier {
    /// No authentication required.
    Public,
    /// Requires `Authorization: Bearer <MISAKA_RPC_API_KEY>`.
    Private,
}

/// Look up the access tier for a JSON-RPC method.
///
/// Returns `None` for unknown methods (→ METHOD_NOT_FOUND).
pub fn method_tier(method: &str) -> Option<MethodTier> {
    match method {
        // ── Bitcoin Core compatible (public) ──
        "getblockchaininfo" | "getblockcount" | "getbestblockhash"
        | "getblockhash" | "getblock" | "getblockheader"
        | "getrawtransaction" | "decoderawtransaction" | "sendrawtransaction"
        | "getmempoolinfo" | "getrawmempool" | "estimatesmartfee"
        | "validateaddress" | "getconnectioncount" | "getnetworkinfo"
        | "getmininginfo" | "gettxout" | "gettxoutsetinfo" | "uptime"
        // ── MISAKA extensions (public) ──
        | "misaka_getDagInfo" | "misaka_getDagTips" | "misaka_getDagBlock"
        | "misaka_getVirtualChain" | "misaka_getVirtualState"
        | "misaka_getValidatorSet" | "misaka_getValidatorById"
        | "misaka_getCirculatingSupply" | "misaka_getCheckpoint"
        | "misaka_getEpochInfo" | "misaka_getStakingInfo"
        | "misaka_getProtocolVersion"
            => Some(MethodTier::Public),

        // ── Private (API key required) ──
        "getbalance" | "listunspent" | "getpeerinfo"
        | "misaka_getAnonymitySet" | "misaka_getAddressHistory"
        | "misaka_getBlocksRange" | "misaka_getTxsRange"
            => Some(MethodTier::Private),

        _ => None,
    }
}
