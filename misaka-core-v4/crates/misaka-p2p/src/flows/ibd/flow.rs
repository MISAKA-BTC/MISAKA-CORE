//! # IBD Flow — Full Initial Block Download State Machine
//!
//! Kaspa-aligned header-first, pruning-point-anchored IBD:
//! ```text
//! Negotiate → [PruningPoint UTXO?] → HeaderSync → BodyFetch → Done
//! ```
//! Security: headers validated BEFORE any body download (bandwidth gate).
//! All wire messages travel over ML-KEM-768 + ML-DSA-65 PQ-AEAD channel.

use std::sync::Arc;

use tracing::{debug, info};

use crate::flow_context::FlowContext;
use crate::flow_context::Hash;
use crate::flow_trait::Flow;
use crate::payload_type::{MisakaMessage, MisakaPayloadType};
use crate::protocol_error::ProtocolError;
use crate::router::{IncomingRoute, Router};

use super::negotiate::{negotiate_chain_segment, BlockKnowledge};
use super::streams::{
    request_body_batch, request_header_batch, request_pruning_point_utxo_set, IbdPhase,
    IbdProgress, BODY_BATCH_SIZE, HEADER_BATCH_SIZE,
};

/// Maximum headers per IBD session.
const MAX_IBD_HEADERS: u64 = 10_000_000;
/// Progress report interval.
const PROGRESS_INTERVAL: u64 = 5_000;

/// Consensus callbacks for IBD.
#[async_trait::async_trait]
pub trait IbdConsensus: BlockKnowledge + Send + Sync {
    /// Validate and store a batch of headers. Returns last valid hash.
    async fn validate_headers(&self, headers: &[(Hash, Vec<u8>)]) -> Result<Vec<Hash>, String>;
    /// Validate and commit a batch of full blocks.
    async fn validate_and_commit_bodies(&self, bodies: &[(Hash, Vec<u8>)]) -> Result<(), String>;
    /// Apply a pruning point UTXO set snapshot.
    async fn apply_pruning_utxo_set(&self, pp: Hash, chunks: Vec<Vec<u8>>) -> Result<(), String>;
    /// Get current blue score.
    fn current_blue_score(&self) -> u64;
}

pub struct IbdFlow {
    pub router: Arc<Router>,
    pub ctx: Arc<FlowContext>,
    pub incoming: IncomingRoute,
    pub consensus: Arc<dyn IbdConsensus>,
    pub progress: IbdProgress,
}

impl IbdFlow {
    pub fn new(
        router: Arc<Router>,
        ctx: Arc<FlowContext>,
        consensus: Arc<dyn IbdConsensus>,
    ) -> Self {
        let incoming = router.subscribe_with_capacity(
            vec![
                MisakaPayloadType::Headers,
                MisakaPayloadType::IbdBlock,
                MisakaPayloadType::DoneIbdBlocks,
                MisakaPayloadType::IbdChainBlockLocator,
                MisakaPayloadType::PruningPointProof,
                MisakaPayloadType::PruningPointUtxoSetChunk,
                MisakaPayloadType::DonePruningPointUtxoSet,
                MisakaPayloadType::RequestHeaders,
                MisakaPayloadType::RequestIbdBlocks,
                MisakaPayloadType::RequestIbdChainBlockLocator,
                MisakaPayloadType::RequestPruningPointProof,
                MisakaPayloadType::RequestPruningPointUtxoSet,
                MisakaPayloadType::RequestAntipast,
                MisakaPayloadType::Antipast,
            ],
            2048,
        );
        Self {
            router,
            ctx,
            incoming,
            consensus,
            progress: IbdProgress {
                headers_downloaded: 0,
                headers_total_estimate: 0,
                bodies_downloaded: 0,
                bodies_total: 0,
                phase: IbdPhase::Negotiating,
            },
        }
    }

    async fn run_ibd(&mut self) -> Result<(), ProtocolError> {
        self.ctx.set_ibd(true);

        // Phase 1: Chain Negotiation
        self.progress.phase = IbdPhase::Negotiating;
        info!("IBD: negotiating chain with {}", self.router);

        let negotiation =
            negotiate_chain_segment(&self.router, &mut self.incoming, self.consensus.as_ref())
                .await?;

        info!(
            "IBD: negotiation complete. syncer_vsp={}, highest_known={:?}",
            hex::encode(&negotiation.syncer_virtual_selected_parent[..8]),
            negotiation
                .highest_known_syncer_chain_hash
                .map(|h| hex::encode(&h[..8]))
        );

        // If no common block, download pruning point UTXO set
        if negotiation.highest_known_syncer_chain_hash.is_none() {
            info!("IBD: no common block — requesting pruning point UTXO set");
            let pp = negotiation.syncer_pruning_point;

            // Request pruning proof
            let req = MisakaMessage::new(MisakaPayloadType::RequestPruningPointProof, pp.to_vec());
            self.router.enqueue(req).await?;
            let proof_msg = self
                .incoming
                .recv_timeout(std::time::Duration::from_secs(120))
                .await?;
            if proof_msg.msg_type != MisakaPayloadType::PruningPointProof {
                return Err(ProtocolError::ProtocolViolation(format!(
                    "expected PruningPointProof, got {:?}",
                    proof_msg.msg_type
                )));
            }

            // Download and apply UTXO set
            let chunks =
                request_pruning_point_utxo_set(&self.router, &mut self.incoming, pp).await?;
            self.consensus
                .apply_pruning_utxo_set(pp, chunks)
                .await
                .map_err(|e| {
                    ProtocolError::InvalidChainSegment(format!("UTXO set apply failed: {}", e))
                })?;
            info!("IBD: pruning point UTXO set applied");
        }

        // Phase 2: Header Sync
        self.progress.phase = IbdPhase::DownloadingHeaders;
        let start = negotiation
            .highest_known_syncer_chain_hash
            .unwrap_or(negotiation.syncer_pruning_point);

        let validated = self.download_headers(start).await?;
        info!(
            "IBD: downloaded {} headers from {}",
            validated.len(),
            self.router
        );

        // Phase 3: Body Fetch
        self.progress.phase = IbdPhase::DownloadingBodies;
        self.progress.bodies_total = validated.len() as u64;
        self.download_bodies(&validated).await?;

        // Phase 4: Done
        self.progress.phase = IbdPhase::Done;
        self.ctx.set_ibd(false);
        info!(
            "IBD: complete. {} headers, {} bodies from {}",
            self.progress.headers_downloaded, self.progress.bodies_downloaded, self.router
        );
        Ok(())
    }

    async fn download_headers(&mut self, mut from: Hash) -> Result<Vec<Hash>, ProtocolError> {
        let mut all_hashes = Vec::new();

        loop {
            let batch =
                request_header_batch(&self.router, &mut self.incoming, from, HEADER_BATCH_SIZE)
                    .await?;
            if batch.is_empty() {
                break;
            }
            let batch_len = batch.len();

            let hashes = self.consensus.validate_headers(&batch).await.map_err(|e| {
                ProtocolError::InvalidChainSegment(format!("header validation: {}", e))
            })?;

            if let Some(last) = hashes.last() {
                from = *last;
            }
            all_hashes.extend_from_slice(&hashes);
            self.progress.headers_downloaded += batch_len as u64;

            if self.progress.headers_downloaded % PROGRESS_INTERVAL == 0 {
                info!(
                    "IBD: {} headers downloaded from {}",
                    self.progress.headers_downloaded, self.router
                );
            }
            if self.progress.headers_downloaded >= MAX_IBD_HEADERS || batch_len < HEADER_BATCH_SIZE
            {
                break;
            }
        }
        Ok(all_hashes)
    }

    async fn download_bodies(&mut self, hashes: &[Hash]) -> Result<(), ProtocolError> {
        for chunk in hashes.chunks(BODY_BATCH_SIZE) {
            let bodies = request_body_batch(&self.router, &mut self.incoming, chunk).await?;
            self.consensus
                .validate_and_commit_bodies(&bodies)
                .await
                .map_err(|e| {
                    ProtocolError::InvalidChainSegment(format!("body validation: {}", e))
                })?;
            self.progress.bodies_downloaded += chunk.len() as u64;
            if self.progress.bodies_downloaded % (PROGRESS_INTERVAL / 5).max(1) == 0 {
                info!(
                    "IBD: {}/{} bodies from {}",
                    self.progress.bodies_downloaded, self.progress.bodies_total, self.router
                );
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Flow for IbdFlow {
    fn name(&self) -> &'static str {
        "IbdFlow"
    }

    async fn run(mut self: Box<Self>) -> Result<(), ProtocolError> {
        let peer_props = self.router.properties();
        let our_score = self.consensus.current_blue_score();

        if self.ctx.should_start_ibd(peer_props.handshake_blue_score) {
            info!(
                "IBD: starting with {} (theirs={}, ours={})",
                self.router, peer_props.handshake_blue_score, our_score
            );
            match self.run_ibd().await {
                Ok(()) => {}
                Err(e) => {
                    self.ctx.set_ibd(false);
                    return Err(e);
                }
            }
        }

        // After IBD, serve requests from peers syncing from us.
        loop {
            let msg = match self.incoming.recv().await {
                Some(m) => m,
                None => return Err(ProtocolError::ConnectionClosed),
            };
            match msg.msg_type {
                MisakaPayloadType::RequestIbdChainBlockLocator => {
                    debug!("IBD: serving locator request from {}", self.router);
                    let resp = MisakaMessage::new(MisakaPayloadType::IbdChainBlockLocator, vec![]);
                    self.router.enqueue(resp).await?;
                }
                MisakaPayloadType::RequestHeaders => {
                    debug!("IBD: serving header request from {}", self.router);
                    let resp = MisakaMessage::new(MisakaPayloadType::Headers, vec![]);
                    self.router.enqueue(resp).await?;
                }
                MisakaPayloadType::RequestIbdBlocks => {
                    let done = MisakaMessage::new(MisakaPayloadType::DoneIbdBlocks, vec![]);
                    self.router.enqueue(done).await?;
                }
                MisakaPayloadType::RequestPruningPointProof => {
                    let resp = MisakaMessage::new(MisakaPayloadType::PruningPointProof, vec![]);
                    self.router.enqueue(resp).await?;
                }
                MisakaPayloadType::RequestPruningPointUtxoSet => {
                    let done =
                        MisakaMessage::new(MisakaPayloadType::DonePruningPointUtxoSet, vec![]);
                    self.router.enqueue(done).await?;
                }
                MisakaPayloadType::RequestAntipast => {
                    let resp = MisakaMessage::new(MisakaPayloadType::Antipast, vec![]);
                    self.router.enqueue(resp).await?;
                }
                _ => {} // Other message types handled by different flows
            }
        }
    }
}
