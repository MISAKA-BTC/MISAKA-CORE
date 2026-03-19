//! # DAG RPC アダプター (MISAKA-CORE v2)
//!
//! 既存の RPC エンドポイント (`/api/submit_tx`, `/api/get_chain_info` 等) を
//! DAG ベースの状態に接続するアダプター層。
//!
//! ## 設計方針
//!
//! v1 の `RpcState { node: SharedState, p2p: Arc<P2pNetwork> }` を
//! v2 の `DagRpcState` に置き換え、同一の HTTP エンドポイントを維持する。
//! Explorer やウォレットからは v1/v2 の違いが透過的に見える。

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use axum::{Router, Json, extract::State, routing::{post, get}, http::StatusCode};
use tower_http::cors::CorsLayer;
use serde::Deserialize;
use tracing::{info, warn};


#[allow(deprecated)]
use misaka_types::utxo::UtxoTransaction;
use misaka_dag::{
    DagNodeState,
    DagStore,   // trait — for snapshot.get_tips() etc.
};

// ═══════════════════════════════════════════════════════════════
//  DAG RPC State
// ═══════════════════════════════════════════════════════════════

/// DAG ノード用の共有 RPC 状態。
///
/// v1 の `RpcState { node: SharedState, p2p }` に相当する。
pub type DagSharedState = Arc<RwLock<DagNodeState>>;

#[derive(Clone)]
pub struct DagRpcState {
    pub node: DagSharedState,
    // TODO: Phase 3 で DAG P2P handle を追加
    // pub p2p: Arc<DagP2pNetwork>,
}

// ═══════════════════════════════════════════════════════════════
//  RPC サーバー起動
// ═══════════════════════════════════════════════════════════════

/// DAG 対応 RPC サーバーを起動する。
///
/// v1 と同じエンドポイントパスを使用し、Explorer/ウォレット互換性を維持。
pub async fn run_dag_rpc_server(
    state: DagSharedState,
    addr: SocketAddr,
) -> anyhow::Result<()> {
    let rpc_state = DagRpcState { node: state };

    let mut app = Router::new()
        .route("/api/get_chain_info", post(dag_get_chain_info))
        .route("/api/submit_tx", post(dag_submit_tx))
        .route("/api/get_dag_info", post(dag_get_dag_info))
        .route("/api/get_dag_tips", post(dag_get_tips))
        .route("/api/get_dag_block", post(dag_get_block))
        .route("/health", get(dag_health))
        .with_state(rpc_state);

    // CORS — 同じ fail-closed ポリシー
    let cors = match std::env::var("MISAKA_CORS_ORIGINS") {
        Ok(origins_str) => {
            let origins: Vec<axum::http::HeaderValue> = origins_str.split(',')
                .filter(|o| !o.trim().is_empty())
                .filter_map(|o| o.trim().parse().ok())
                .collect();
            if origins.is_empty() {
                anyhow::bail!(
                    "FATAL: MISAKA_CORS_ORIGINS contains no valid origins: '{}'",
                    origins_str
                );
            }
            CorsLayer::new()
                .allow_origin(origins)
                .allow_methods([axum::http::Method::POST, axum::http::Method::GET])
                .allow_headers([axum::http::header::CONTENT_TYPE])
        }
        Err(_) => {
            // No env var set: restrictive localhost-only default (same as v1)
            CorsLayer::new()
                .allow_origin([
                    "http://localhost:3000".parse().expect("static origin"),
                    "http://localhost:3001".parse().expect("static origin"),
                    "http://127.0.0.1:3000".parse().expect("static origin"),
                    "http://127.0.0.1:3001".parse().expect("static origin"),
                ])
                .allow_methods([axum::http::Method::POST, axum::http::Method::GET])
                .allow_headers([axum::http::header::CONTENT_TYPE])
        }
    };

    let app = app.layer(cors);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("DAG RPC server listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
//  エンドポイント: Chain Info (v1 互換)
// ═══════════════════════════════════════════════════════════════

/// `/api/get_chain_info` — v1 Explorer 互換レスポンス。
///
/// `latestBlockHeight` は `max_blue_score` にマッピング。
/// `blockTime` は DAG のブロック間隔目標。
async fn dag_get_chain_info(
    State(rpc): State<DagRpcState>,
) -> Json<serde_json::Value> {
    let guard = rpc.node.read().await;
    let s = &*guard;

    let max_score = s.dag_store.max_blue_score();
    let block_count = s.dag_store.block_count();
    let tip_count = s.dag_store.tip_count();

    Json(serde_json::json!({
        "networkName": "MISAKA DAG Testnet",
        "networkVersion": "v2.0.0-alpha",
        "consensus": "GhostDAG",
        "latestBlockHeight": max_score,
        "dagBlockCount": block_count,
        "dagTipCount": tip_count,
        "chainId": s.chain_id,
        "mempoolSize": s.mempool.len(),
        "txStats": {
            "applied": s.state_manager.stats.txs_applied,
            "failedKiConflict": s.state_manager.stats.txs_failed_ki_conflict,
            "coinbase": s.state_manager.stats.txs_coinbase,
            "totalFees": s.state_manager.stats.total_fees,
        },
    }))
}

// ═══════════════════════════════════════════════════════════════
//  エンドポイント: Submit TX (DAG Mempool 経由)
// ═══════════════════════════════════════════════════════════════

/// `/api/submit_tx` — TX を DAG Mempool に投入する。
///
/// v1 との違い:
/// - `mempool.admit()` → `dag_mempool.insert()` に変更
/// - KI チェックが DAG State Manager 経由
async fn dag_submit_tx(
    State(rpc): State<DagRpcState>,
    body: axum::body::Bytes,
) -> Json<serde_json::Value> {
    // ── 1. サイズ制限 ──
    if body.len() > 131_072 {
        return Json(serde_json::json!({
            "txHash": null, "accepted": false,
            "error": format!("tx body too large: {} bytes (max 131072)", body.len())
        }));
    }

    // ── 2. デシリアライズ ──
    let tx: UtxoTransaction = match serde_json::from_slice(&body) {
        Ok(tx) => tx,
        Err(e) => {
            return Json(serde_json::json!({
                "txHash": null, "accepted": false,
                "error": format!("invalid transaction format: {}", e)
            }));
        }
    };

    // ── 3. 構造バリデーション ──
    if let Err(e) = tx.validate_structure() {
        return Json(serde_json::json!({
            "txHash": null, "accepted": false,
            "error": format!("structural validation failed: {}", e)
        }));
    }

    let tx_hash = tx.tx_hash();
    let hash_hex = hex::encode(tx_hash);

    // ── 4. DAG Mempool に投入 ──
    let mut guard = rpc.node.write().await;
    let s = &mut *guard;

    // KI 既使用チェックは DagStateManager 経由
    // Disjoint field borrow: mempool (mut) + state_manager (immut)
    let state_mgr = &s.state_manager;
    let result = s.mempool.insert(tx, |ki| state_mgr.is_nullifier_spent(ki));

    match result {
        Ok(()) => {
            info!("TX admitted to DAG mempool: {} | pool={}", &hash_hex[..16], s.mempool.len());
            Json(serde_json::json!({
                "txHash": hash_hex,
                "accepted": true,
                "error": null
            }))
        }
        Err(e) => {
            warn!("TX rejected from DAG mempool: {} | reason: {}", &hash_hex[..16], e);
            Json(serde_json::json!({
                "txHash": hash_hex,
                "accepted": false,
                "error": e
            }))
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  エンドポイント: DAG 固有情報
// ═══════════════════════════════════════════════════════════════

/// `/api/get_dag_info` — DAG 固有のメトリクス。
async fn dag_get_dag_info(
    State(rpc): State<DagRpcState>,
) -> Json<serde_json::Value> {
    let guard = rpc.node.read().await;
    let s = &*guard;

    let snapshot = s.dag_store.snapshot();
    let tips = snapshot.get_tips();

    Json(serde_json::json!({
        "ghostdagK": s.ghostdag.k,
        "genesisHash": hex::encode(s.genesis_hash),
        "maxBlueScore": s.dag_store.max_blue_score(),
        "blockCount": s.dag_store.block_count(),
        "tipCount": tips.len(),
        "tips": tips.iter().map(|t| hex::encode(&t[..8])).collect::<Vec<_>>(),
        "blocksProduced": s.blocks_produced,
        "stateManager": {
            "applied": s.state_manager.stats.txs_applied,
            "failedKi": s.state_manager.stats.txs_failed_ki_conflict,
            "failedSig": s.state_manager.stats.txs_failed_invalid_sig,
            "coinbase": s.state_manager.stats.txs_coinbase,
            "totalFees": s.state_manager.stats.total_fees,
        },
    }))
}

/// `/api/get_dag_tips` — 現在の DAG Tips を取得。
async fn dag_get_tips(
    State(rpc): State<DagRpcState>,
) -> Json<serde_json::Value> {
    let guard = rpc.node.read().await;
    let snapshot = guard.dag_store.snapshot();
    let tips = snapshot.get_tips();

    let tip_info: Vec<serde_json::Value> = tips.iter().map(|tip_hash| {
        let score = snapshot
            .get_ghostdag_data(tip_hash)
            .map(|d| d.blue_score)
            .unwrap_or(0);
        serde_json::json!({
            "hash": hex::encode(tip_hash),
            "blueScore": score,
        })
    }).collect();

    Json(serde_json::json!({ "tips": tip_info }))
}

/// `/api/get_dag_block` — ハッシュ指定で DAG ブロック情報を取得。
#[derive(Deserialize)]
struct DagBlockQuery {
    hash: String,
}

async fn dag_get_block(
    State(rpc): State<DagRpcState>,
    Json(q): Json<DagBlockQuery>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let hash_bytes: [u8; 32] = hex::decode(&q.hash)
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .try_into()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let guard = rpc.node.read().await;
    let snapshot = guard.dag_store.snapshot();

    let header = snapshot.get_header(&hash_bytes)
        .ok_or(StatusCode::NOT_FOUND)?;
    let ghostdag = snapshot.get_ghostdag_data(&hash_bytes);

    let txs = guard.dag_store.get_block_txs(&hash_bytes);

    Ok(Json(serde_json::json!({
        "hash": q.hash,
        "version": header.version,
        "parents": header.parents.iter().map(hex::encode).collect::<Vec<_>>(),
        "timestampMs": header.timestamp_ms,
        "txRoot": hex::encode(header.tx_root),
        "proposerId": hex::encode(header.proposer_id),
        "blueScore": header.blue_score,
        "ghostdag": ghostdag.map(|d| serde_json::json!({
            "selectedParent": hex::encode(d.selected_parent),
            "mergesetBlues": d.mergeset_blues.len(),
            "mergesetReds": d.mergeset_reds.len(),
            "blueScore": d.blue_score,
        })),
        "txCount": txs.len(),
        "txHashes": txs.iter().map(|tx| hex::encode(tx.tx_hash())).collect::<Vec<_>>(),
    })))
}

/// `/health` — ヘルスチェック。
async fn dag_health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "consensus": "ghostdag",
        "version": "v2.0.0-alpha"
    }))
}
