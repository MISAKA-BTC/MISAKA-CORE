//! Explorer WebSocket endpoint — broadcasts `newBlock` and `newTransaction`
//! events to connected browser clients by polling the upstream node.

use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::AppState;

const POLL_INTERVAL_MS: u64 = 2_000;
const BROADCAST_CAPACITY: usize = 128;
/// R7 M-6: Maximum concurrent WebSocket connections
const MAX_WS_CONNECTIONS: usize = 256;
/// R7 M-6: Idle timeout — close if no activity for this duration
const WS_IDLE_TIMEOUT_SECS: u64 = 300;

#[derive(Clone)]
pub struct WsBroadcaster {
    tx: broadcast::Sender<String>,
    /// R7 M-6: Semaphore to cap concurrent connections
    conn_semaphore: Arc<tokio::sync::Semaphore>,
}

impl WsBroadcaster {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            tx,
            conn_semaphore: Arc::new(tokio::sync::Semaphore::new(MAX_WS_CONNECTIONS)),
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<String> {
        self.tx.subscribe()
    }

    pub fn start_polling(&self, proxy: Arc<crate::proxy::NodeProxy>) {
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let mut last_height: Option<u64> = None;
            let mut interval =
                tokio::time::interval(tokio::time::Duration::from_millis(POLL_INTERVAL_MS));
            loop {
                interval.tick().await;
                let info = match proxy.get("/api/get_chain_info").await {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let height = info
                    .get("tipHeight")
                    .or_else(|| info.get("blockHeight"))
                    .and_then(|v| v.as_u64());

                if let Some(h) = height {
                    if last_height.map_or(true, |prev| h > prev) {
                        let event = serde_json::json!({
                            "event": "newBlock",
                            "data": { "height": h }
                        });
                        let _ = tx.send(event.to_string());
                        last_height = Some(h);
                    }
                }
            }
        });
    }
}

pub fn router() -> Router<AppState> {
    Router::new().route("/ws", get(ws_handler))
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    // R7 M-6: Acquire connection permit before upgrade
    let sem = state.ws_broadcaster.conn_semaphore.clone();
    let permit = match sem.try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            return axum::response::Response::builder()
                .status(503)
                .body(axum::body::Body::from("too many WebSocket connections"))
                .unwrap()
                .into_response();
        }
    };
    ws.on_upgrade(move |socket| handle_socket(socket, state, permit))
        .into_response()
}

async fn handle_socket(
    mut socket: WebSocket,
    state: AppState,
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    let mut rx = state.ws_broadcaster.subscribe();
    let idle_timeout = tokio::time::Duration::from_secs(WS_IDLE_TIMEOUT_SECS);

    let hello = serde_json::json!({
        "event": "connected",
        "data": { "message": "MISAKA Explorer WebSocket" }
    });
    if socket.send(Message::Text(hello.to_string())).await.is_err() {
        return;
    }

    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Ok(text) => {
                        if socket.send(Message::Text(text)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        let warn = serde_json::json!({
                            "event": "warning",
                            "data": { "message": format!("dropped {} events", n) }
                        });
                        let _ = socket.send(Message::Text(warn.to_string())).await;
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Ping(data))) => {
                        if socket.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
            // R7 M-6: Close idle connections
            _ = tokio::time::sleep(idle_timeout) => {
                let _ = socket.send(Message::Close(None)).await;
                break;
            }
        }
    }
    // _permit drops here, releasing the semaphore slot
}
