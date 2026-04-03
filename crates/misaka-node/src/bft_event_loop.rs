//! BFT Event Loop — async runtime integration for BFT consensus.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │  Node Runtime (tokio)                                   │
//! │                                                         │
//! │  ┌────────────────────┐  ┌──────────────────────────┐  │
//! │  │ DAG Block Producer  │  │ BFT Event Loop (this)    │  │
//! │  │ (block_time tick)   │  │ (slot tick + msg recv)   │  │
//! │  │                     │  │                           │  │
//! │  │ Produces DAG blocks │  │ Drives BFT consensus:    │  │
//! │  │ when proposer       │  │ • VRF proposer check     │  │
//! │  │                     │  │ • 3-phase voting         │  │
//! │  │                     │  │ • Timeout management     │  │
//! │  │                     │  │ • Slash detection        │  │
//! │  └────────────────────┘  └──────────────────────────┘  │
//! │           │                          │                  │
//! │           └──────────┬───────────────┘                  │
//! │                      ▼                                  │
//! │              Shared DagNodeState                        │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # Slot Lifecycle
//!
//! Each slot (= block_time_secs interval) follows this flow:
//!
//! 1. Slot timer fires → `on_new_slot()` via BFT driver
//! 2. VRF determines proposer → if us, produce block + BFT Proposal
//! 3. Broadcast proposal via P2P
//! 4. Collect prevotes from other validators
//! 5. On 2/3+ prevotes → broadcast precommit
//! 6. On 2/3+ precommits → BFT Commit → finality checkpoint
//!
//! # Integration Points
//!
//! - **P2P**: BFT messages (proposal/prevote/precommit) via `DagP2pMessage::Bft*`
//! - **DAG Block Producer**: BFT proposer produces DAG block, hash goes into proposal
//! - **Finality Monitor**: BFT commit triggers finality checkpoint creation
//! - **Staking Registry**: slash evidence from BFT applied to staking

use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use misaka_consensus::bft_driver::{self, BftConsensusState};
use misaka_consensus::bft_state_machine::{BftAction, BftStep};
use misaka_consensus::bft_types::*;
use misaka_consensus::validator_set::ValidatorSet;
use misaka_dag::dag_p2p::DagP2pMessage;
use misaka_dag::DagNodeState;
use misaka_types::validator::ValidatorId;

use crate::dag_p2p_network::OutboundDagEvent;

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

/// BFT message channel capacity.
pub const BFT_CHANNEL_SIZE: usize = 256;

// ═══════════════════════════════════════════════════════════════
//  Pending Timeout
// ═══════════════════════════════════════════════════════════════

/// A pending BFT timeout.
#[derive(Debug, Clone)]
struct PendingTimeout {
    slot: u64,
    round: u32,
    step: BftStep,
    deadline: Instant,
}

// ═══════════════════════════════════════════════════════════════
//  BFT Event Loop
// ═══════════════════════════════════════════════════════════════

/// The BFT consensus event loop.
///
/// Runs as a tokio task alongside the DAG block producer.
/// Processes slot ticks, BFT messages, and timeouts.
pub struct BftEventLoop {
    /// BFT consensus state (driver, slash detector, fork choice, etc.)
    bft_state: BftConsensusState,
    /// Shared DAG node state.
    dag_state: Arc<RwLock<DagNodeState>>,
    /// Channel to receive BFT messages from P2P.
    bft_msg_rx: mpsc::Receiver<BftInboundEvent>,
    /// Channel to send P2P messages (broadcast).
    p2p_outbound_tx: mpsc::Sender<OutboundDagEvent>,
    /// Slot interval.
    slot_duration: Duration,
    /// Pending timeouts (sorted by deadline).
    pending_timeouts: VecDeque<PendingTimeout>,
    /// Maximum transactions per block.
    max_txs_per_block: usize,
    /// Staking registry (shared with RPC/lifecycle).
    staking_registry: Arc<RwLock<misaka_consensus::staking::StakingRegistry>>,
    /// Current epoch.
    current_epoch: Arc<RwLock<u64>>,
}

/// Inbound BFT event from P2P layer.
#[derive(Debug, Clone)]
pub struct BftInboundEvent {
    pub peer_id: misaka_p2p::PeerId,
    pub message: BftMessage,
}

impl BftEventLoop {
    /// Create a new BFT event loop.
    ///
    /// Returns `(event_loop, bft_msg_tx)` — the caller sends BFT messages
    /// via `bft_msg_tx` when received from P2P.
    pub fn new(
        bft_state: BftConsensusState,
        dag_state: Arc<RwLock<DagNodeState>>,
        p2p_outbound_tx: mpsc::Sender<OutboundDagEvent>,
        slot_duration: Duration,
        max_txs_per_block: usize,
        staking_registry: Arc<RwLock<misaka_consensus::staking::StakingRegistry>>,
        current_epoch: Arc<RwLock<u64>>,
    ) -> (Self, mpsc::Sender<BftInboundEvent>) {
        let (bft_msg_tx, bft_msg_rx) = mpsc::channel(BFT_CHANNEL_SIZE);

        let event_loop = Self {
            bft_state,
            dag_state,
            bft_msg_rx,
            p2p_outbound_tx,
            slot_duration,
            pending_timeouts: VecDeque::new(),
            max_txs_per_block,
            staking_registry,
            current_epoch,
        };

        (event_loop, bft_msg_tx)
    }

    /// Run the BFT event loop. This is a long-running async task.
    pub async fn run(mut self) {
        let mut slot_ticker = tokio::time::interval(self.slot_duration);
        slot_ticker.tick().await; // Skip initial tick

        info!(
            "BFT event loop started (slot_duration={}s, is_validator={})",
            self.slot_duration.as_secs(),
            self.bft_state.is_validator(),
        );

        loop {
            // Find next timeout deadline
            let next_timeout = self
                .pending_timeouts
                .front()
                .map(|t| t.deadline)
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(3600));

            tokio::select! {
                // ── Slot tick → new BFT round ──
                _ = slot_ticker.tick() => {
                    self.handle_new_slot().await;
                }

                // ── Inbound BFT message from P2P ──
                msg = self.bft_msg_rx.recv() => {
                    match msg {
                        Some(event) => self.handle_bft_message(event).await,
                        None => {
                            info!("BFT event loop: channel closed, shutting down");
                            break;
                        }
                    }
                }

                // ── Timeout ──
                _ = tokio::time::sleep_until(next_timeout) => {
                    self.handle_timeout().await;
                }
            }
        }
    }

    // ─── Slot Handler ───────────────────────────────────────

    async fn handle_new_slot(&mut self) {
        // Build current validator set from DAG state
        let (validator_set, dag_checkpoint, block_hash) = {
            let guard = self.dag_state.read().await;
            let vs = crate::dag_validator_set(&guard);

            // Get current DAG state for proposal
            let checkpoint = guard.latest_checkpoint.as_ref().map(|cp| {
                misaka_types::validator::DagCheckpointTarget {
                    block_hash: cp.block_hash,
                    blue_score: cp.blue_score,
                    utxo_root: cp.utxo_root,
                    total_key_images: cp.total_key_images,
                    total_applied_txs: cp.total_applied_txs,
                }
            });

            // Use the current virtual tip as the block hash for proposal
            let virtual_tip = guard.virtual_state.tip;

            (vs, checkpoint, Some(virtual_tip))
        };

        // Drive BFT state machine
        let actions = bft_driver::on_new_slot(
            &mut self.bft_state,
            &validator_set,
            dag_checkpoint,
            block_hash,
        );

        self.process_actions(actions).await;
    }

    // ─── Message Handler ────────────────────────────────────

    async fn handle_bft_message(&mut self, event: BftInboundEvent) {
        let validator_set = {
            let guard = self.dag_state.read().await;
            crate::dag_validator_set(&guard)
        };

        let actions = bft_driver::on_bft_message(
            &mut self.bft_state,
            event.message,
            &validator_set,
        );

        self.process_actions(actions).await;
    }

    // ─── Timeout Handler ────────────────────────────────────

    async fn handle_timeout(&mut self) {
        let now = Instant::now();

        // Pop all expired timeouts
        let mut expired = Vec::new();
        while let Some(front) = self.pending_timeouts.front() {
            if front.deadline <= now {
                if let Some(timeout) = self.pending_timeouts.pop_front() {
                    expired.push(timeout);
                }
            } else {
                break;
            }
        }

        if expired.is_empty() {
            return;
        }

        let validator_set = {
            let guard = self.dag_state.read().await;
            crate::dag_validator_set(&guard)
        };

        for timeout in expired {
            let actions = bft_driver::on_bft_timeout(
                &mut self.bft_state,
                timeout.slot,
                timeout.round,
                timeout.step,
                &validator_set,
            );
            self.process_actions(actions).await;
        }
    }

    // ─── Action Processor ───────────────────────────────────

    async fn process_actions(&mut self, actions: Vec<BftAction>) {
        for action in actions {
            match action {
                BftAction::BroadcastProposal(proposal) => {
                    debug!(
                        "BFT: broadcasting proposal slot={} round={} block={}",
                        proposal.slot,
                        proposal.round,
                        hex::encode(&proposal.block_hash[..4]),
                    );
                    let payload = match serde_json::to_vec(&proposal) {
                        Ok(p) => p,
                        Err(e) => {
                            error!("Failed to serialize BFT proposal: {}", e);
                            continue;
                        }
                    };
                    let _ = self
                        .p2p_outbound_tx
                        .send(OutboundDagEvent {
                            peer_id: None, // Broadcast
                            message: DagP2pMessage::BftProposal { payload },
                        })
                        .await;
                }

                BftAction::BroadcastPrevote(vote) => {
                    debug!(
                        "BFT: broadcasting prevote slot={} round={} hash={:?}",
                        vote.slot,
                        vote.round,
                        vote.block_hash.map(|h| hex::encode(&h[..4])),
                    );
                    let payload = match serde_json::to_vec(&vote) {
                        Ok(p) => p,
                        Err(e) => {
                            error!("Failed to serialize BFT prevote: {}", e);
                            continue;
                        }
                    };
                    let _ = self
                        .p2p_outbound_tx
                        .send(OutboundDagEvent {
                            peer_id: None,
                            message: DagP2pMessage::BftPrevote { payload },
                        })
                        .await;
                }

                BftAction::BroadcastPrecommit(vote) => {
                    debug!(
                        "BFT: broadcasting precommit slot={} round={} hash={:?}",
                        vote.slot,
                        vote.round,
                        vote.block_hash.map(|h| hex::encode(&h[..4])),
                    );
                    let payload = match serde_json::to_vec(&vote) {
                        Ok(p) => p,
                        Err(e) => {
                            error!("Failed to serialize BFT precommit: {}", e);
                            continue;
                        }
                    };
                    let _ = self
                        .p2p_outbound_tx
                        .send(OutboundDagEvent {
                            peer_id: None,
                            message: DagP2pMessage::BftPrecommit { payload },
                        })
                        .await;
                }

                BftAction::ScheduleTimeout {
                    slot,
                    round,
                    step,
                    timeout_ms,
                } => {
                    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
                    debug!(
                        "BFT: scheduling timeout slot={} round={} step={:?} in {}ms",
                        slot, round, step, timeout_ms,
                    );
                    // Insert sorted by deadline
                    let timeout = PendingTimeout {
                        slot,
                        round,
                        step,
                        deadline,
                    };
                    let pos = self
                        .pending_timeouts
                        .iter()
                        .position(|t| t.deadline > deadline)
                        .unwrap_or(self.pending_timeouts.len());
                    self.pending_timeouts.insert(pos, timeout);
                }

                BftAction::Commit(commit) => {
                    info!(
                        "🎉 BFT COMMIT: slot={} round={} block={} blue_score={}",
                        commit.slot,
                        commit.round,
                        hex::encode(&commit.block_hash[..8]),
                        commit.dag_checkpoint.blue_score,
                    );

                    // The bft_driver::on_bft_commit was already called
                    // by sign_and_collect_actions in bft_driver.
                    // Here we propagate to the DAG state.

                    // Check epoch boundary
                    let epoch = *self.current_epoch.read().await;
                    let epoch_length = misaka_types::constants::EPOCH_LENGTH;
                    if commit.slot % epoch_length == 0 && commit.slot > 0 {
                        let active_count = {
                            let guard = self.dag_state.read().await;
                            guard.known_validators.len() as u64
                        };
                        let mut registry = self.staking_registry.write().await;
                        bft_driver::on_epoch_boundary(
                            &mut self.bft_state,
                            epoch,
                            true, // finalized this epoch (we just committed)
                            active_count,
                            &mut registry,
                        );
                        info!("BFT: epoch boundary processed (epoch={})", epoch);
                    }
                }

                BftAction::ReportEquivocation(evidence) => {
                    warn!(
                        "🚨 BFT EQUIVOCATION: validator {} — broadcasting evidence",
                        hex::encode(evidence.validator_id()),
                    );

                    // Record slash in inactivity tracker
                    self.bft_state
                        .inactivity
                        .record_slash(evidence.validator_id());

                    // Apply slash to staking registry
                    {
                        let mut registry = self.staking_registry.write().await;
                        let epoch = *self.current_epoch.read().await;
                        match registry.slash(
                            evidence.validator_id(),
                            misaka_consensus::staking::SlashSeverity::Severe,
                            epoch,
                        ) {
                            Ok((slashed, reporter_reward)) => {
                                info!(
                                    "Slashed validator {}: amount={} reporter_reward={}",
                                    hex::encode(evidence.validator_id()),
                                    slashed,
                                    reporter_reward,
                                );
                            }
                            Err(e) => {
                                warn!(
                                    "Slash failed for {}: {}",
                                    hex::encode(evidence.validator_id()),
                                    e,
                                );
                            }
                        }
                    }

                    // Broadcast evidence to network
                    let payload = match serde_json::to_vec(&evidence) {
                        Ok(p) => p,
                        Err(e) => {
                            error!("Failed to serialize slash evidence: {}", e);
                            continue;
                        }
                    };
                    let _ = self
                        .p2p_outbound_tx
                        .send(OutboundDagEvent {
                            peer_id: None,
                            message: DagP2pMessage::BftSlashEvidence { payload },
                        })
                        .await;
                }

                BftAction::AdvanceRound { slot, new_round } => {
                    debug!("BFT: advancing to round {} in slot {}", new_round, slot);
                    self.bft_state.bft.advance_round(new_round);

                    // Clear stale timeouts for old rounds
                    self.pending_timeouts
                        .retain(|t| t.slot >= slot && t.round >= new_round);
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  P2P Message Decoding (called from dag_p2p_network)
// ═══════════════════════════════════════════════════════════════

/// Decode a BFT P2P message into a `BftMessage`.
///
/// Called by `dag_p2p_network` when it receives a `DagP2pMessage::Bft*` variant.
pub fn decode_bft_p2p_message(msg: &DagP2pMessage) -> Option<BftMessage> {
    match msg {
        DagP2pMessage::BftProposal { payload } => {
            serde_json::from_slice::<BftProposal>(payload)
                .ok()
                .map(BftMessage::Proposal)
        }
        DagP2pMessage::BftPrevote { payload } => {
            serde_json::from_slice::<BftVote>(payload)
                .ok()
                .map(BftMessage::Prevote)
        }
        DagP2pMessage::BftPrecommit { payload } => {
            serde_json::from_slice::<BftVote>(payload)
                .ok()
                .map(BftMessage::Precommit)
        }
        _ => None,
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_bft_proposal() {
        let proposal = BftProposal {
            slot: 42,
            round: 0,
            proposer: [0x01; 20],
            block_hash: [0xBB; 32],
            dag_checkpoint: misaka_types::validator::DagCheckpointTarget {
                block_hash: [0xBB; 32],
                blue_score: 100,
                utxo_root: [0; 32],
                total_key_images: 0,
                total_applied_txs: 0,
            },
            vrf_proof: VrfOutput {
                proof: vec![0; 3309],
                hash: [0xDD; 32],
            },
            valid_round: u32::MAX,
            signature: misaka_types::validator::ValidatorSignature {
                bytes: vec![0; 3309],
            },
        };
        let payload = serde_json::to_vec(&proposal).unwrap();
        let msg = DagP2pMessage::BftProposal { payload };
        let decoded = decode_bft_p2p_message(&msg).unwrap();
        assert!(matches!(decoded, BftMessage::Proposal(_)));
    }

    #[test]
    fn test_decode_bft_prevote() {
        let vote = BftVote {
            slot: 1,
            round: 0,
            voter: [0x01; 20],
            block_hash: Some([0xAA; 32]),
            signature: misaka_types::validator::ValidatorSignature {
                bytes: vec![0; 3309],
            },
        };
        let payload = serde_json::to_vec(&vote).unwrap();
        let msg = DagP2pMessage::BftPrevote { payload };
        let decoded = decode_bft_p2p_message(&msg).unwrap();
        assert!(matches!(decoded, BftMessage::Prevote(_)));
    }

    #[test]
    fn test_decode_invalid_payload_returns_none() {
        let msg = DagP2pMessage::BftProposal {
            payload: b"not valid json".to_vec(),
        };
        assert!(decode_bft_p2p_message(&msg).is_none());
    }
}
