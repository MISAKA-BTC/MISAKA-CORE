//! Conversion between gRPC protobuf types and internal RPC model types.

use crate::model::*;

/// Convert internal block to gRPC response format.
pub fn block_to_grpc(block: &RpcBlock) -> serde_json::Value {
    serde_json::to_value(block).unwrap_or_default()
}

/// Convert internal transaction to gRPC format.
pub fn tx_to_grpc(tx: &RpcTransaction) -> serde_json::Value {
    serde_json::to_value(tx).unwrap_or_default()
}
