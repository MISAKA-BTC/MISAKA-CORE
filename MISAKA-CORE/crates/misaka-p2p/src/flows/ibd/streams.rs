//! # IBD Streaming — Batched Header & Body Download
//!
//! Efficient streaming protocol for downloading headers and block bodies
//! during Initial Block Download. Headers are validated before any body
//! downloads begin (Kaspa's bandwidth-gate principle).

use std::sync::Arc;
use std::time::Duration;

use tracing::info;

use crate::flow_context::Hash;
use crate::payload_type::{MisakaMessage, MisakaPayloadType};
use crate::protocol_error::ProtocolError;
use crate::router::{IncomingRoute, Router};

/// Maximum headers per batch.
pub const HEADER_BATCH_SIZE: usize = 500;

/// Maximum bodies per batch.
pub const BODY_BATCH_SIZE: usize = 100;

/// Maximum parallel body download workers.
pub const MAX_BODY_WORKERS: usize = 4;

/// Timeout for header batch response.
const HEADER_BATCH_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout for body batch response.
const BODY_BATCH_TIMEOUT: Duration = Duration::from_secs(120);

/// Progress tracker for IBD.
#[derive(Debug, Clone)]
pub struct IbdProgress {
    pub headers_downloaded: u64,
    pub headers_total_estimate: u64,
    pub bodies_downloaded: u64,
    pub bodies_total: u64,
    pub phase: IbdPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IbdPhase {
    Negotiating,
    DownloadingHeaders,
    DownloadingBodies,
    Completing,
    Done,
}

/// Request a batch of headers starting from `from_hash`.
///
/// Returns the received headers as raw byte vectors.
pub async fn request_header_batch(
    router: &Arc<Router>,
    incoming: &mut IncomingRoute,
    from_hash: Hash,
    limit: usize,
) -> Result<Vec<(Hash, Vec<u8>)>, ProtocolError> {
    // Encode: from_hash(32) + limit(4)
    let mut payload = Vec::with_capacity(36);
    payload.extend_from_slice(&from_hash);
    payload.extend_from_slice(&(limit as u32).to_le_bytes());

    let request = MisakaMessage::new(MisakaPayloadType::RequestHeaders, payload);
    router.enqueue(request).await?;

    let response = incoming.recv_timeout(HEADER_BATCH_TIMEOUT).await?;

    if response.msg_type != MisakaPayloadType::Headers {
        return Err(ProtocolError::ProtocolViolation(format!(
            "expected Headers, got {:?}",
            response.msg_type
        )));
    }

    parse_header_batch(&response.payload)
}

/// Request block bodies for a set of hashes.
pub async fn request_body_batch(
    router: &Arc<Router>,
    incoming: &mut IncomingRoute,
    hashes: &[Hash],
) -> Result<Vec<(Hash, Vec<u8>)>, ProtocolError> {
    let mut payload = Vec::with_capacity(hashes.len() * 32);
    for h in hashes {
        payload.extend_from_slice(h);
    }

    let request = MisakaMessage::new(MisakaPayloadType::RequestIbdBlocks, payload);
    router.enqueue(request).await?;

    let mut bodies = Vec::with_capacity(hashes.len());

    // Receive blocks one at a time until DoneIbdBlocks.
    loop {
        let msg = incoming.recv_timeout(BODY_BATCH_TIMEOUT).await?;

        match msg.msg_type {
            MisakaPayloadType::IbdBlock => {
                if msg.payload.len() < 32 {
                    return Err(ProtocolError::ProtocolViolation(
                        "IBD block too small".into(),
                    ));
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&msg.payload[..32]);
                let body = msg.payload[32..].to_vec();
                bodies.push((hash, body));
            }
            MisakaPayloadType::DoneIbdBlocks => {
                break;
            }
            other => {
                return Err(ProtocolError::ProtocolViolation(format!(
                    "unexpected message during IBD body fetch: {:?}",
                    other
                )));
            }
        }
    }

    Ok(bodies)
}

/// Request the pruning point UTXO set in chunks.
pub async fn request_pruning_point_utxo_set(
    router: &Arc<Router>,
    incoming: &mut IncomingRoute,
    pruning_point: Hash,
) -> Result<Vec<Vec<u8>>, ProtocolError> {
    let request = MisakaMessage::new(
        MisakaPayloadType::RequestPruningPointUtxoSet,
        pruning_point.to_vec(),
    );
    router.enqueue(request).await?;

    let mut chunks = Vec::new();
    let timeout = Duration::from_secs(300); // UTXO set can be large.

    loop {
        let msg = incoming.recv_timeout(timeout).await?;

        match msg.msg_type {
            MisakaPayloadType::PruningPointUtxoSetChunk => {
                chunks.push(msg.payload);
            }
            MisakaPayloadType::DonePruningPointUtxoSet => {
                info!(
                    "P2P received pruning point UTXO set: {} chunks from {}",
                    chunks.len(),
                    router
                );
                break;
            }
            other => {
                return Err(ProtocolError::ProtocolViolation(format!(
                    "unexpected message during UTXO set fetch: {:?}",
                    other
                )));
            }
        }
    }

    Ok(chunks)
}

/// Parse a header batch response.
///
/// Format: repeated [hash(32) + header_len(4) + header_data(N)]
fn parse_header_batch(data: &[u8]) -> Result<Vec<(Hash, Vec<u8>)>, ProtocolError> {
    let mut headers = Vec::new();
    let mut offset = 0;

    while offset + 36 <= data.len() {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        let len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;

        if offset + len > data.len() {
            return Err(ProtocolError::ProtocolViolation(
                "header batch truncated".into(),
            ));
        }

        headers.push((hash, data[offset..offset + len].to_vec()));
        offset += len;
    }

    Ok(headers)
}
