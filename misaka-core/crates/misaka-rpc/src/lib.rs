//! JSON-RPC server with PQ transaction support.

use serde::{Deserialize, Serialize};

pub const ERR_PARSE: i64 = -32700;
pub const ERR_INVALID_REQUEST: i64 = -32600;
pub const ERR_METHOD_NOT_FOUND: i64 = -32601;
pub const ERR_INVALID_PARAMS: i64 = -32602;
pub const ERR_INTERNAL: i64 = -32603;

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: serde_json::Value,
    pub id: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    pub id: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

impl JsonRpcResponse {
    pub fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: Some(result),
            error: None,
            id,
        }
    }
    pub fn error(id: serde_json::Value, code: i64, message: String) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: None,
            error: Some(JsonRpcError { code, message }),
            id,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NodeStatus {
    pub chain_id: u32,
    pub height: u64,
    pub utxo_count: usize,
    pub mempool_size: usize,
    pub validator_scheme: String,
    pub privacy_backend: String,
    pub tx_privacy_model: String,
    pub experimental_privacy_path: String,
    pub privacy_path_surface: PrivacyPathSurfaceStatus,
    pub privacy_backend_descriptor: PrivacyBackendStatus,
    pub validator_attestation: ValidatorAttestationSurfaceStatus,
    pub tx_status_vocabulary: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyBackendStatus {
    pub scheme_name: String,
    pub backend_family: String,
    pub spend_identifier_model: String,
    pub full_verifier_member_index_hidden: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatorAttestationSurfaceStatus {
    pub available: bool,
    pub bridge_readiness: String,
    pub explorer_confirmation_level: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsumerSurfacesStatus {
    pub validator_attestation: ValidatorAttestationSurfaceStatus,
    pub tx_status_vocabulary: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivacyPathSurfaceStatus {
    pub runtime_path: String,
    pub target_path: String,
    pub target_backend_family: String,
    pub note: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UtxoInfo {
    pub tx_hash: String,
    pub output_index: u32,
    pub amount: u64,
    pub has_stealth: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TxSubmitResult {
    pub tx_hash: String,
    pub accepted: bool,
    pub error: Option<String>,
}

// ═══════════════════════════════════════════════════════════════
//  Validator Workload / Yield API Types (v4.1)
// ═══════════════════════════════════════════════════════════════

/// Response for `misaka_getValidatorWorkload`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatorWorkloadResponse {
    pub validator_id: String,
    pub epoch: u64,
    pub finalized: bool,
    pub snapshot_time: String,
    pub workload: WorkloadMetrics,
    pub scores: WorkloadScores,
}

/// Raw workload metrics for one validator/epoch.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadMetrics {
    pub proposed_blocks: u64,
    pub accepted_blocks: u64,
    pub rejected_blocks: u64,
    pub validated_blocks: u64,
    pub signed_votes: u64,
    pub missed_votes: u64,
    pub attestation_count: u64,
    pub finalized_contribution_count: u64,
    pub mempool_tx_seen: u64,
    pub mempool_tx_included: u64,
    pub relayed_messages: u64,
    pub uptime_checks_passed: u64,
    pub uptime_checks_failed: u64,
    pub active_time_slots: u64,
    pub produced_data_bytes: String,
}

/// Computed scores.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadScores {
    pub workload_score: u64,
    pub smoothed_score: u64,
    pub reward_weight: String,
}

/// Params for `misaka_getValidatorRankings`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatorRankingParams {
    #[serde(default = "default_ranking_epoch")]
    pub epoch: String,
    #[serde(default = "default_ranking_sort")]
    pub sort: String,
    #[serde(default = "default_ranking_limit")]
    pub limit: usize,
}
fn default_ranking_epoch() -> String {
    "current".into()
}
fn default_ranking_sort() -> String {
    "workload".into()
}
fn default_ranking_limit() -> usize {
    100
}

/// Single entry in the validator ranking response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatorRankingEntry {
    pub rank: u32,
    pub validator_id: String,
    pub workload_score: u64,
    pub accepted_blocks: u64,
    pub signed_votes: u64,
    pub validated_blocks: u64,
    pub reward_weight: String,
    pub epoch_reward: String,
}

/// Single entry in workload history.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatorWorkloadHistoryEntry {
    pub epoch: u64,
    pub workload_score: u64,
    pub accepted_blocks: u64,
    pub signed_votes: u64,
    pub validated_blocks: u64,
    pub relayed_messages: u64,
    pub reward_weight: String,
}

/// Response for `misaka_getNetworkWorkload`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkWorkloadResponse {
    pub epoch: u64,
    pub active_validators: u32,
    pub total_accepted_blocks: u64,
    pub total_signed_votes: u64,
    pub total_validated_blocks: u64,
    pub total_relayed_messages: u64,
    pub avg_workload_score: u64,
    pub median_workload_score: u64,
}

/// Response for `misaka_getValidatorYield`.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatorYieldResponse {
    pub validator_id: String,
    pub epoch: u64,
    pub active_stake: String,
    pub sqrt_scaled_stake: String,
    pub smoothed_score: u64,
    pub reward_weight: String,
    pub reward_share_ppm: u64,
    pub epoch_reward: String,
}

pub fn default_v4_privacy_backend_status() -> PrivacyBackendStatus {
    PrivacyBackendStatus {
        scheme_name: "UnifiedZKP-v1".into(),
        backend_family: "zeroKnowledge".into(),
        spend_identifier_model: "canonicalNullifier".into(),
        full_verifier_member_index_hidden: true,
    }
}

pub fn linear_consumer_surfaces_status() -> ConsumerSurfacesStatus {
    ConsumerSurfacesStatus {
        validator_attestation: ValidatorAttestationSurfaceStatus {
            available: false,
            bridge_readiness: "notAvailable".into(),
            explorer_confirmation_level: "blockFinalized".into(),
        },
        tx_status_vocabulary: vec!["confirmed".into()],
    }
}

pub fn dag_consumer_surfaces_status(
    bridge_readiness: impl Into<String>,
    explorer_confirmation_level: impl Into<String>,
) -> ConsumerSurfacesStatus {
    ConsumerSurfacesStatus {
        validator_attestation: ValidatorAttestationSurfaceStatus {
            available: true,
            bridge_readiness: bridge_readiness.into(),
            explorer_confirmation_level: explorer_confirmation_level.into(),
        },
        tx_status_vocabulary: vec![
            "pending".into(),
            "ordered".into(),
            "finalized".into(),
            "failedNullifierConflict".into(),
            "failedKeyImageConflict".into(),
            "failedInvalidSignature".into(),
            "failedRingMemberNotFound".into(),
        ],
    }
}

pub fn v4_privacy_path_surface_status(runtime_path: impl Into<String>) -> PrivacyPathSurfaceStatus {
    PrivacyPathSurfaceStatus {
        runtime_path: runtime_path.into(),
        target_path: "zeroKnowledge".into(),
        target_backend_family: "zeroKnowledge".into(),
        note:
            "runtimePath reflects the currently active path; targetPath reflects the v4 direction."
                .into(),
    }
}

pub fn handle_request(
    req: &JsonRpcRequest,
    height: u64,
    utxo_count: usize,
    mempool_size: usize,
    chain_id: u32,
) -> JsonRpcResponse {
    match req.method.as_str() {
        "misaka_getStatus" => {
            let consumer_surfaces =
                dag_consumer_surfaces_status("checkpointDependent", "checkpointAware");
            let status = NodeStatus {
                chain_id,
                height,
                utxo_count,
                mempool_size,
                validator_scheme: "ML-DSA-65 (PQ-only)".into(),
                privacy_backend: "UnifiedZKP-v1".into(),
                tx_privacy_model: "CanonicalNullifier + UnifiedZKP membership + ML-KEM stealth"
                    .into(),
                experimental_privacy_path: "zeroKnowledge".into(),
                privacy_path_surface: v4_privacy_path_surface_status("zeroKnowledge"),
                privacy_backend_descriptor: default_v4_privacy_backend_status(),
                validator_attestation: consumer_surfaces.validator_attestation,
                tx_status_vocabulary: consumer_surfaces.tx_status_vocabulary,
            };
            JsonRpcResponse::success(
                req.id.clone(),
                serde_json::to_value(status)
                    .unwrap_or(serde_json::json!({"error": "serialization failed"})),
            )
        }
        "misaka_getUtxoCount" => {
            JsonRpcResponse::success(req.id.clone(), serde_json::json!(utxo_count))
        }
        "misaka_getHeight" => JsonRpcResponse::success(req.id.clone(), serde_json::json!(height)),

        // ── Validator Workload / Yield API (v4.1) ──
        // These methods accept params via req.params and delegate to the node backend.
        // In production, they read from pre-computed epoch snapshots (never re-aggregate on call).
        "misaka_getValidatorWorkload" => {
            // Params: { "validatorId": "...", "epoch": <optional u64> }
            // Returns: ValidatorWorkloadResponse | null
            JsonRpcResponse::error(
                req.id.clone(),
                ERR_INTERNAL,
                "misaka_getValidatorWorkload: requires backend wiring (see misaka-node/dag_rpc.rs)"
                    .into(),
            )
        }
        "misaka_getValidatorRankings" => {
            // Params: { "epoch": "current"|<u64>, "sort": "workload", "limit": 100 }
            // Returns: Vec<ValidatorRankingEntry>
            JsonRpcResponse::error(
                req.id.clone(),
                ERR_INTERNAL,
                "misaka_getValidatorRankings: requires backend wiring".into(),
            )
        }
        "misaka_getValidatorWorkloadHistory" => {
            // Params: { "validatorId": "...", "limit": 100 }
            // Returns: Vec<ValidatorWorkloadHistoryEntry>
            JsonRpcResponse::error(
                req.id.clone(),
                ERR_INTERNAL,
                "misaka_getValidatorWorkloadHistory: requires backend wiring".into(),
            )
        }
        "misaka_getNetworkWorkload" => {
            // Params: { "epoch": <optional u64> }
            // Returns: NetworkWorkloadResponse
            JsonRpcResponse::error(
                req.id.clone(),
                ERR_INTERNAL,
                "misaka_getNetworkWorkload: requires backend wiring".into(),
            )
        }
        "misaka_getValidatorYield" => {
            // Params: { "validatorId": "...", "epoch": <optional u64> }
            // Returns: ValidatorYieldResponse
            JsonRpcResponse::error(
                req.id.clone(),
                ERR_INTERNAL,
                "misaka_getValidatorYield: requires backend wiring".into(),
            )
        }
        _ => JsonRpcResponse::error(
            req.id.clone(),
            ERR_METHOD_NOT_FOUND,
            format!("unknown method: {}", req.method),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_status() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: "misaka_getStatus".into(),
            params: serde_json::Value::Null,
            id: serde_json::json!(1),
        };
        let resp = handle_request(&req, 42, 1000, 5, 2);
        assert!(resp.result.is_some());
        let status: NodeStatus = serde_json::from_value(resp.result.unwrap()).unwrap();
        assert_eq!(status.height, 42);
        assert_eq!(status.utxo_count, 1000);
        assert_eq!(status.experimental_privacy_path, "zeroKnowledge");
        assert_eq!(status.privacy_path_surface.runtime_path, "zeroKnowledge");
        assert_eq!(status.privacy_path_surface.target_path, "zeroKnowledge");
        assert_eq!(
            status.privacy_backend_descriptor.scheme_name,
            "UnifiedZKP-v1"
        );
        assert_eq!(
            status.privacy_backend_descriptor.spend_identifier_model,
            "canonicalNullifier"
        );
        assert!(status.validator_attestation.available);
        assert_eq!(
            status.validator_attestation.bridge_readiness,
            "checkpointDependent"
        );
        assert_eq!(
            status.validator_attestation.explorer_confirmation_level,
            "checkpointAware"
        );
        assert!(status
            .tx_status_vocabulary
            .contains(&"failedNullifierConflict".to_string()));
    }

    #[test]
    fn test_rpc_unknown_method() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: "foo".into(),
            params: serde_json::Value::Null,
            id: serde_json::json!(1),
        };
        let resp = handle_request(&req, 0, 0, 0, 2);
        assert!(resp.error.is_some());
    }

    #[test]
    fn test_rpc_height() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: "misaka_getHeight".into(),
            params: serde_json::Value::Null,
            id: serde_json::json!(1),
        };
        let resp = handle_request(&req, 99, 0, 0, 2);
        assert_eq!(resp.result.unwrap(), serde_json::json!(99));
    }

    #[test]
    fn test_linear_consumer_surface_defaults() {
        let surfaces = linear_consumer_surfaces_status();
        assert!(!surfaces.validator_attestation.available);
        assert_eq!(
            surfaces.validator_attestation.bridge_readiness,
            "notAvailable"
        );
        assert_eq!(surfaces.tx_status_vocabulary, vec!["confirmed".to_string()]);
    }

    #[test]
    fn test_dag_consumer_surface_defaults() {
        let surfaces = dag_consumer_surfaces_status("ready", "checkpointFinalized");
        assert!(surfaces.validator_attestation.available);
        assert_eq!(surfaces.validator_attestation.bridge_readiness, "ready");
        assert!(surfaces
            .tx_status_vocabulary
            .contains(&"failedNullifierConflict".to_string()));
    }

    // ── Workload / Yield API method routing tests ──

    #[test]
    fn test_rpc_workload_method_recognized() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: "misaka_getValidatorWorkload".into(),
            params: serde_json::json!({"validatorId": "val_001"}),
            id: serde_json::json!(1),
        };
        let resp = handle_request(&req, 0, 0, 0, 1);
        // Should NOT be method-not-found (it's a known method, just needs backend)
        let err = resp.error.as_ref().expect("should return error for now");
        assert_ne!(err.code, ERR_METHOD_NOT_FOUND);
    }

    #[test]
    fn test_rpc_yield_method_recognized() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: "misaka_getValidatorYield".into(),
            params: serde_json::json!({"validatorId": "val_001"}),
            id: serde_json::json!(1),
        };
        let resp = handle_request(&req, 0, 0, 0, 1);
        let err = resp.error.as_ref().expect("should return error for now");
        assert_ne!(err.code, ERR_METHOD_NOT_FOUND);
    }

    #[test]
    fn test_rpc_network_workload_recognized() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: "misaka_getNetworkWorkload".into(),
            params: serde_json::Value::Null,
            id: serde_json::json!(1),
        };
        let resp = handle_request(&req, 0, 0, 0, 1);
        let err = resp.error.as_ref().expect("should return error for now");
        assert_ne!(err.code, ERR_METHOD_NOT_FOUND);
    }

    #[test]
    fn test_rpc_rankings_recognized() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            method: "misaka_getValidatorRankings".into(),
            params: serde_json::json!({"sort": "workload"}),
            id: serde_json::json!(1),
        };
        let resp = handle_request(&req, 0, 0, 0, 1);
        let err = resp.error.as_ref().expect("should return error for now");
        assert_ne!(err.code, ERR_METHOD_NOT_FOUND);
    }

    #[test]
    fn test_workload_response_serde() {
        let resp = ValidatorWorkloadResponse {
            validator_id: "val_001".into(),
            epoch: 128,
            finalized: true,
            snapshot_time: "2026-03-22T12:00:00Z".into(),
            workload: WorkloadMetrics {
                proposed_blocks: 21,
                accepted_blocks: 19,
                rejected_blocks: 2,
                validated_blocks: 610,
                signed_votes: 602,
                missed_votes: 8,
                attestation_count: 599,
                finalized_contribution_count: 588,
                mempool_tx_seen: 220000,
                mempool_tx_included: 185000,
                relayed_messages: 92000,
                uptime_checks_passed: 1438,
                uptime_checks_failed: 2,
                active_time_slots: 1435,
                produced_data_bytes: "88473600".into(),
            },
            scores: WorkloadScores {
                workload_score: 812300,
                smoothed_score: 831500,
                reward_weight: "415220091".into(),
            },
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        let _: ValidatorWorkloadResponse = serde_json::from_str(&json).expect("deserialize");
    }

    #[test]
    fn test_yield_response_serde() {
        let resp = ValidatorYieldResponse {
            validator_id: "val_001".into(),
            epoch: 128,
            active_stake: "250000000000".into(),
            sqrt_scaled_stake: "500000".into(),
            smoothed_score: 831500,
            reward_weight: "415750000000".into(),
            reward_share_ppm: 8421,
            epoch_reward: "12000444".into(),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        let deser: ValidatorYieldResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deser.reward_share_ppm, 8421);
    }
}
