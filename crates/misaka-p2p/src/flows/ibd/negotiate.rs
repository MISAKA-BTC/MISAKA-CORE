//! # IBD Chain Negotiation — Binary-Search Chain Intersection
//!
//! Kaspa-aligned algorithm to find the highest block in our DAG that
//! also exists on the syncer's selected chain:
//!
//! 1. Request full selected chain block locator from syncer
//! 2. Binary search for the highest block we know
//! 3. Zoom-in with progressively smaller locators until exact match
//! 4. Handle chain changes (restarts) gracefully
//!
//! Security: All block hash comparisons use SHA3-256. Locator size
//! is bounded by O(log₂(DAG_size)) ≈ 64 entries maximum.

use std::time::Duration;

use tracing::{debug, warn};

use crate::flow_context::Hash;
use crate::payload_type::{MisakaMessage, MisakaPayloadType};
use crate::protocol_error::{
    ProtocolError, MAX_BLOCK_LOCATOR_LEN, MAX_NEGOTIATION_RESTARTS, SHORT_TIMEOUT_SECS,
};
use crate::router::{IncomingRoute, Router};
use std::sync::Arc;

/// Result of chain negotiation.
#[derive(Debug)]
pub struct ChainNegotiationOutput {
    /// The syncer's virtual selected parent (tip of their chain).
    pub syncer_virtual_selected_parent: Hash,
    /// The highest block hash we have in common with the syncer's chain.
    /// `None` if we share no common block (full IBD needed).
    pub highest_known_syncer_chain_hash: Option<Hash>,
    /// The syncer's pruning point.
    pub syncer_pruning_point: Hash,
}

/// Callback trait for checking if we know a block hash.
///
/// The consensus layer implements this to check its local DAG.
pub trait BlockKnowledge: Send + Sync {
    /// Returns `Some(true)` if block is known and valid,
    /// `Some(false)` if block is known but invalid,
    /// `None` if block is unknown.
    fn get_block_status(&self, hash: &Hash) -> Option<bool>;
}

/// Run the chain negotiation protocol with a syncer peer.
///
/// This is the core Kaspa algorithm adapted for MISAKA's PQ transport:
/// all messages travel over the ML-KEM/ML-DSA authenticated channel.
pub async fn negotiate_chain_segment(
    router: &Arc<Router>,
    incoming: &mut IncomingRoute,
    knowledge: &dyn BlockKnowledge,
) -> Result<ChainNegotiationOutput, ProtocolError> {
    let default_timeout = Duration::from_secs(30);
    let short_timeout = Duration::from_secs(SHORT_TIMEOUT_SECS);

    // Step 1: Request the full selected chain locator.
    let mut locator = request_chain_locator(router, incoming, None, None, default_timeout).await?;

    if locator.is_empty() {
        return Err(ProtocolError::InvalidChainSegment(
            "empty initial chain locator".into(),
        ));
    }

    let mut syncer_pruning_point = *locator.last().expect("checked non-empty");
    let mut syncer_vsp = locator[0]; // Virtual selected parent.
    let mut restart_count = 0u32;
    let mut zoom_count = 0usize;
    let mut initial_len = locator.len();

    loop {
        let mut lowest_unknown: Option<Hash> = None;
        let mut highest_known: Option<Hash> = None;

        // Scan the locator for the boundary between known and unknown.
        for &hash in &locator {
            match knowledge.get_block_status(&hash) {
                None => {
                    lowest_unknown = Some(hash);
                }
                Some(false) => {
                    return Err(ProtocolError::InvalidChainSegment(format!(
                        "syncer sent invalid block {}",
                        hex::encode(hash)
                    )));
                }
                Some(true) => {
                    highest_known = Some(hash);
                    break;
                }
            }
        }

        // Case: no unknown blocks — we have everything.
        if lowest_unknown.is_none() {
            return Ok(ChainNegotiationOutput {
                syncer_virtual_selected_parent: syncer_vsp,
                highest_known_syncer_chain_hash: highest_known,
                syncer_pruning_point,
            });
        }

        // Case: no shared block — full IBD needed.
        if highest_known.is_none() {
            return Ok(ChainNegotiationOutput {
                syncer_virtual_selected_parent: syncer_vsp,
                highest_known_syncer_chain_hash: None,
                syncer_pruning_point,
            });
        }

        // Case: found the exact boundary (locator has 1 entry).
        if locator.len() == 1 {
            return Ok(ChainNegotiationOutput {
                syncer_virtual_selected_parent: syncer_vsp,
                highest_known_syncer_chain_hash: highest_known,
                syncer_pruning_point,
            });
        }

        // Zoom in: request a locator between the known and unknown hashes.
        let zoom_locator = request_chain_locator(
            router,
            incoming,
            highest_known,
            lowest_unknown,
            short_timeout,
        )
        .await?;

        if !zoom_locator.is_empty() {
            // Validate bounds.
            if zoom_locator.first().copied() != lowest_unknown
                || zoom_locator.last().copied() != highest_known
            {
                return Err(ProtocolError::InvalidChainSegment(
                    "zoom locator bounds mismatch".into(),
                ));
            }

            zoom_count += 1;
            debug!(
                "IBD negotiation zoom #{} with {}: {} hashes",
                zoom_count,
                router,
                zoom_locator.len()
            );

            // Exact match found.
            if zoom_locator.len() == 2 {
                return Ok(ChainNegotiationOutput {
                    syncer_virtual_selected_parent: syncer_vsp,
                    highest_known_syncer_chain_hash: highest_known,
                    syncer_pruning_point,
                });
            }

            // Guard against infinite zoom.
            if zoom_count > initial_len * 2 {
                return Err(ProtocolError::InvalidChainSegment(format!(
                    "zoom exceeded upper bound: {} > 2*{}",
                    zoom_count, initial_len
                )));
            }

            locator = zoom_locator;
        } else {
            // Empty locator = chain changed on syncer side, restart.
            zoom_count = 0;
            restart_count += 1;

            if restart_count > MAX_NEGOTIATION_RESTARTS {
                return Err(ProtocolError::NegotiationExhausted {
                    peer: router.to_string(),
                    restarts: restart_count,
                });
            }

            if restart_count > 10 {
                warn!(
                    "IBD negotiation with {} restarted {} times",
                    router, restart_count
                );
            } else {
                debug!(
                    "IBD negotiation with {} restarted ({})",
                    router, restart_count
                );
            }

            locator = request_chain_locator(router, incoming, None, None, short_timeout).await?;

            if locator.is_empty() {
                return Err(ProtocolError::InvalidChainSegment(
                    "empty locator on restart".into(),
                ));
            }

            initial_len = locator.len();
            syncer_vsp = locator[0];
            syncer_pruning_point = *locator.last().expect("checked non-empty");
        }
    }
}

/// Send a RequestIbdChainBlockLocator and receive the response.
async fn request_chain_locator(
    router: &Arc<Router>,
    incoming: &mut IncomingRoute,
    low: Option<Hash>,
    high: Option<Hash>,
    timeout: Duration,
) -> Result<Vec<Hash>, ProtocolError> {
    // Encode request: [low_present(1)] [low(32)?] [high_present(1)] [high(32)?]
    let mut payload = Vec::with_capacity(66);
    if let Some(l) = low {
        payload.push(1);
        payload.extend_from_slice(&l);
    } else {
        payload.push(0);
    }
    if let Some(h) = high {
        payload.push(1);
        payload.extend_from_slice(&h);
    } else {
        payload.push(0);
    }

    let request = MisakaMessage::new(MisakaPayloadType::RequestIbdChainBlockLocator, payload);
    router.enqueue(request).await?;

    let response = incoming.recv_timeout(timeout).await?;

    if response.msg_type != MisakaPayloadType::IbdChainBlockLocator {
        return Err(ProtocolError::ProtocolViolation(format!(
            "expected IbdChainBlockLocator, got {:?}",
            response.msg_type
        )));
    }

    // Decode: sequence of 32-byte hashes.
    let payload = &response.payload;
    if payload.len() % 32 != 0 {
        return Err(ProtocolError::ProtocolViolation(
            "locator payload not a multiple of 32".into(),
        ));
    }

    let count = payload.len() / 32;
    if count > MAX_BLOCK_LOCATOR_LEN {
        return Err(ProtocolError::ProtocolViolation(format!(
            "locator too large: {} (max {})",
            count, MAX_BLOCK_LOCATOR_LEN
        )));
    }

    let mut hashes = Vec::with_capacity(count);
    for chunk in payload.chunks_exact(32) {
        let mut h = [0u8; 32];
        h.copy_from_slice(chunk);
        hashes.push(h);
    }

    Ok(hashes)
}
