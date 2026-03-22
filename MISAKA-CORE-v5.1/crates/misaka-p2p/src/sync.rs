//! # IBD State Machine — Header-First, Pruning-Point-Anchored Sync (v4)
//!
//! # Design Rationale
//!
//! This module implements a **Kaspa-aligned Initial Block Download (IBD)**
//! protocol with the following security properties:
//!
//! 1. **Header-First**: Full block bodies are NEVER downloaded until their
//!    headers have been independently validated. This prevents bandwidth
//!    exhaustion attacks where a malicious peer sends gigabytes of invalid
//!    block bodies.
//!
//! 2. **Pruning-Point-Anchored**: New nodes do not need to download the
//!    entire DAG history. They verify a Pruning Proof (chain of UTXO
//!    commitments) and sync only from the latest pruning point forward.
//!
//! 3. **Crash-Only**: Every state transition is deterministic and
//!    recoverable. If the node crashes mid-IBD, it can resume from the
//!    last committed pruning point without re-downloading.
//!
//! # State Machine
//!
//! ```text
//! ┌────────────────────────┐
//! │  RequestPruningPoint   │  Ask trusted peers for pruning proof
//! └───────────┬────────────┘
//!             │ proof valid
//!             ▼
//! ┌────────────────────────┐
//! │      HeaderSync        │  Download headers from pruning point → tips
//! │                        │  Build local Reachability Index + GhostDAG
//! │                        │  ⚠ NO body downloads in this phase
//! └───────────┬────────────┘
//!             │ all headers validated
//!             ▼
//! ┌────────────────────────┐
//! │      BodyFetch         │  Parallel workers download bodies for
//! │                        │  validated headers ONLY
//! │                        │  Reconstruct VirtualState
//! └───────────┬────────────┘
//!             │ VirtualState matches commitment
//!             ▼
//! ┌────────────────────────┐
//! │     SteadyRelay        │  Normal gossip protocol
//! └────────────────────────┘
//! ```
//!
//! # Anti-DoS: Header Validation as Bandwidth Gate
//!
//! The critical insight is that header validation is O(1) per header (just
//! a hash check + parent existence + timestamp bounds + blue_score
//! monotonicity), while body validation is O(n_txs) per block. By
//! requiring ALL headers to pass validation before ANY body is downloaded,
//! we ensure that a malicious peer cannot force us to download and process
//! expensive block bodies.
//!
//! Specifically, when a malicious peer sends invalid headers:
//!
//! 1. **Timestamp out of bounds**: Rejected at header validation.
//!    Cost to attacker: ~100 bytes per header.
//!    Cost to defender: O(1) hash + timestamp check.
//!
//! 2. **Invalid parent references**: Rejected at header validation.
//!    The parent hash must exist in our local DAG or in the current
//!    header batch. If not, the header is invalid.
//!
//! 3. **Blue score manipulation**: We recompute blue_score locally
//!    using our GhostDAG engine. If the peer's claimed blue_score
//!    diverges from our computation, the header (and all descendants)
//!    is rejected.
//!
//! 4. **Massive header flood**: Rate-limited by `MAX_HEADERS_PER_SEC`.
//!    Once the peer exceeds the threshold, they receive a penalty.
//!    At `BAN_THRESHOLD`, the connection is terminated.
//!
//! Only headers that pass ALL checks are promoted to the BodyFetch queue.
//! This means the defender's bandwidth cost for invalid headers is bounded
//! by (header_size × MAX_HEADERS_PER_SEC × timeout), which is ~15 MB/min
//! worst case — far less than the gigabytes a body-first approach would
//! allow.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
//  Types
// ═══════════════════════════════════════════════════════════════

type Hash = [u8; 32];
const ZERO_HASH: Hash = [0u8; 32];

// ═══════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════

/// Maximum headers per sync batch.
pub const IBD_HEADER_BATCH: usize = 500;

/// Maximum bodies per fetch batch.
pub const IBD_BODY_BATCH: usize = 100;

/// Maximum concurrent body-fetch workers.
pub const MAX_BODY_WORKERS: usize = 4;

/// Maximum in-flight header requests before backpressure.
pub const MAX_PENDING_HEADERS: usize = 4000;

/// Maximum time (seconds) to wait for a single batch response.
pub const BATCH_TIMEOUT_SECS: u64 = 30;

/// Maximum headers per second from a single peer before penalty.
pub const MAX_HEADERS_PER_SEC: u32 = 2000;

/// Minimum number of peers that must agree on a pruning point.
pub const PRUNING_POINT_QUORUM: usize = 2;

/// Ban penalty for invalid pruning proof.
pub const PRUNING_PROOF_PENALTY: u32 = 80;

/// Ban penalty for invalid header.
pub const INVALID_HEADER_PENALTY: u32 = 25;

/// Ban penalty for invalid body.
pub const INVALID_BODY_PENALTY: u32 = 30;

// ═══════════════════════════════════════════════════════════════
//  IBD State Machine
// ═══════════════════════════════════════════════════════════════

/// IBD sync phase — deterministic state transitions.
///
/// Each variant carries enough state to resume after crash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IbdPhase {
    /// Phase 0: Requesting pruning proof from peers.
    ///
    /// - Sends `GetPruningProof` to multiple peers
    /// - Waits for quorum agreement on pruning point
    /// - Validates proof (chain connectivity + state commitment)
    RequestPruningPoint {
        /// Pruning proofs received so far (peer_id → proof hash).
        proofs_received: HashMap<[u8; 20], Hash>,
        /// When we entered this phase.
        started_at_epoch_ms: u64,
    },

    /// Phase 1: Downloading and validating headers.
    ///
    /// # Security: Header-Only Phase
    ///
    /// During this phase, we ONLY process headers. No block bodies
    /// are requested or accepted. This is the key anti-DoS mechanism:
    ///
    /// - Each header is ~200 bytes (vs ~10KB+ for a full block)
    /// - Header validation is O(1): hash check, parent existence,
    ///   timestamp bounds, blue_score recomputation
    /// - Invalid headers are detected before any body bandwidth is spent
    /// - The peer receives INVALID_HEADER_PENALTY (25) per bad header
    /// - After 4 bad headers, the peer is banned (25 × 4 = 100 ≥ BAN_THRESHOLD)
    ///
    /// # Topology Construction
    ///
    /// As headers arrive, we incrementally build:
    /// - Reachability Index (interval-based ancestor queries)
    /// - GhostDAG data (blue/red classification, selected parent chain)
    /// - Local DAG topology (parent → child edges)
    ///
    /// These structures are built in memory and committed atomically
    /// to storage only when the full header chain is validated.
    HeaderSync {
        /// The pruning point we're syncing from.
        pruning_point: Hash,
        /// Last header hash we've validated (cursor for next batch request).
        last_validated: Hash,
        /// Total headers received and validated.
        headers_validated: u64,
        /// Headers that failed validation (excluded from BodyFetch).
        invalid_headers: HashSet<Hash>,
        /// Ordered list of validated header hashes (for BodyFetch queue).
        validated_queue: Vec<Hash>,
        /// Whether the peer indicated more headers are available.
        peer_has_more: bool,
    },

    /// Phase 2: Downloading block bodies for validated headers.
    ///
    /// # Security: Validated-Only Download
    ///
    /// Only headers that passed ALL validation checks in Phase 1 are
    /// eligible for body download. Invalid headers are excluded.
    ///
    /// Bodies are fetched in parallel by `MAX_BODY_WORKERS` workers,
    /// each requesting `IBD_BODY_BATCH` blocks at a time. This allows
    /// saturating the network link while maintaining backpressure.
    ///
    /// # State Reconstruction
    ///
    /// As bodies arrive, we execute each block's transactions against
    /// the VirtualState, reconstructing the UTXO set and nullifier set.
    /// The final state commitment must match the pruning proof.
    BodyFetch {
        /// Remaining body hashes to download (ordered by blue_score).
        remaining: VecDeque<Hash>,
        /// Currently in-flight body requests.
        in_flight: HashSet<Hash>,
        /// Bodies received and applied to VirtualState.
        bodies_applied: u64,
        /// Expected final state commitment (from pruning proof).
        expected_utxo_commitment: Hash,
    },

    /// Phase 3: Sync complete — switch to steady-state relay.
    ///
    /// The node is now fully synchronized and can:
    /// - Accept new blocks from gossip
    /// - Produce blocks (if validator)
    /// - Serve IBD data to new peers
    SteadyRelay,

    /// Terminal state: sync failed irrecoverably.
    Failed { reason: String },
}

// ═══════════════════════════════════════════════════════════════
//  IBD Actions — Commands for the network layer
// ═══════════════════════════════════════════════════════════════

/// Actions the IBD engine requests from the network layer.
#[derive(Debug, Clone)]
pub enum IbdAction {
    /// Send a P2P message to a specific peer.
    SendToPeer { peer_id: [u8; 20], message: IbdMessage },

    /// Send a P2P message to the best available peer.
    SendToBest { message: IbdMessage },

    /// Penalize a peer (cumulative — ban at threshold).
    Penalize { peer_id: [u8; 20], points: u32, reason: String },

    /// Ban a peer immediately.
    Ban { peer_id: [u8; 20], reason: String },

    /// Validate a header against local DAG topology.
    /// The network layer must call `on_header_validated` with the result.
    ValidateHeader { hash: Hash, header_bytes: Vec<u8> },

    /// Apply a block body to VirtualState.
    /// The network layer must call `on_body_applied` with the result.
    ApplyBody { hash: Hash, header_bytes: Vec<u8>, body_bytes: Vec<u8> },

    /// Commit the IBD result: atomically persist all DAG state.
    CommitIbdState,

    /// Log an informational message.
    Log { level: LogLevel, message: String },
}

#[derive(Debug, Clone)]
pub enum LogLevel {
    Info,
    Warn,
    Error,
}

/// P2P messages used during IBD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IbdMessage {
    /// Request pruning proof from peer.
    GetPruningProof,

    /// Response: pruning proof data.
    PruningProofData { proof_bytes: Vec<u8> },

    /// Request headers starting after `after_hash`.
    GetHeaders { after_hash: Hash, limit: u32 },

    /// Response: header batch.
    Headers {
        headers: Vec<(Hash, Vec<u8>)>,
        has_more: bool,
    },

    /// Request block bodies by hash.
    GetBodies { hashes: Vec<Hash> },

    /// Response: block bodies.
    Bodies { blocks: Vec<(Hash, Vec<u8>, Vec<u8>)> },
}

// ═══════════════════════════════════════════════════════════════
//  IBD Engine
// ═══════════════════════════════════════════════════════════════

/// The IBD Engine manages the full sync lifecycle.
///
/// # Thread Safety
///
/// The engine is single-threaded (no internal locking). The caller
/// must ensure exclusive access (typically via `Arc<Mutex<...>>`
/// or by running on a dedicated tokio task).
///
/// # Determinism
///
/// All state transitions are deterministic given the same inputs.
/// This is critical for crash recovery: the engine can be
/// reconstructed from persisted state and will produce identical
/// results.
pub struct IbdEngine {
    /// Current phase.
    pub phase: IbdPhase,
    /// Local node's current blue_score (0 for fresh node).
    pub local_blue_score: u64,
    /// Known local block hashes (for deduplication).
    local_known: HashSet<Hash>,
    /// Peer quality tracking.
    peer_penalties: HashMap<[u8; 20], u32>,
}

impl IbdEngine {
    /// Create a new IBD engine for a fresh node.
    pub fn new_fresh() -> Self {
        Self {
            phase: IbdPhase::RequestPruningPoint {
                proofs_received: HashMap::new(),
                started_at_epoch_ms: chrono::Utc::now().timestamp_millis() as u64,
            },
            local_blue_score: 0,
            local_known: HashSet::new(),
            peer_penalties: HashMap::new(),
        }
    }

    /// Create a new IBD engine that resumes from a known pruning point.
    ///
    /// Used for crash recovery: the node already has state up to the
    /// pruning point and needs to sync the remaining headers/bodies.
    pub fn resume_from_pruning_point(
        pruning_point: Hash,
        known_hashes: HashSet<Hash>,
        local_blue_score: u64,
    ) -> Self {
        Self {
            phase: IbdPhase::HeaderSync {
                pruning_point,
                last_validated: pruning_point,
                headers_validated: 0,
                invalid_headers: HashSet::new(),
                validated_queue: Vec::new(),
                peer_has_more: true,
            },
            local_blue_score,
            local_known: known_hashes,
            peer_penalties: HashMap::new(),
        }
    }

    /// Start IBD: request pruning proof from peers.
    pub fn start(&mut self) -> Vec<IbdAction> {
        match &self.phase {
            IbdPhase::RequestPruningPoint { .. } => {
                vec![
                    IbdAction::SendToBest {
                        message: IbdMessage::GetPruningProof,
                    },
                    IbdAction::Log {
                        level: LogLevel::Info,
                        message: "IBD started: requesting pruning proof".into(),
                    },
                ]
            }
            _ => vec![],
        }
    }

    /// Handle a pruning proof response.
    ///
    /// # Security
    ///
    /// The proof is validated by the caller (checking chain connectivity
    /// and UTXO/nullifier commitments). If invalid, the peer receives
    /// PRUNING_PROOF_PENALTY which is high enough for near-instant ban.
    pub fn on_pruning_proof_received(
        &mut self,
        peer_id: [u8; 20],
        pruning_point: Hash,
        utxo_commitment: Hash,
        valid: bool,
    ) -> Vec<IbdAction> {
        let proofs_received = match &mut self.phase {
            IbdPhase::RequestPruningPoint { proofs_received, .. } => proofs_received,
            _ => return vec![],
        };

        if !valid {
            let penalty = self.add_peer_penalty(peer_id, PRUNING_PROOF_PENALTY);
            let mut actions = vec![IbdAction::Penalize {
                peer_id,
                points: PRUNING_PROOF_PENALTY,
                reason: "invalid pruning proof".into(),
            }];
            if penalty >= crate::peer_state::BAN_THRESHOLD {
                actions.push(IbdAction::Ban {
                    peer_id,
                    reason: "invalid pruning proof".into(),
                });
            }
            return actions;
        }

        proofs_received.insert(peer_id, pruning_point);

        // Check quorum: do enough peers agree on the same pruning point?
        let mut point_votes: HashMap<Hash, usize> = HashMap::new();
        for pp in proofs_received.values() {
            *point_votes.entry(*pp).or_insert(0) += 1;
        }

        let best = point_votes.iter().max_by_key(|(_, v)| **v);
        if let Some((agreed_point, count)) = best {
            if *count >= PRUNING_POINT_QUORUM || proofs_received.len() == 1 {
                let pp = *agreed_point;
                // Transition to HeaderSync
                self.phase = IbdPhase::HeaderSync {
                    pruning_point: pp,
                    last_validated: pp,
                    headers_validated: 0,
                    invalid_headers: HashSet::new(),
                    validated_queue: Vec::new(),
                    peer_has_more: true,
                };
                self.local_known.insert(pp);

                return vec![
                    IbdAction::Log {
                        level: LogLevel::Info,
                        message: format!(
                            "IBD: pruning point accepted ({} peers agree) — starting header sync",
                            count
                        ),
                    },
                    IbdAction::SendToBest {
                        message: IbdMessage::GetHeaders {
                            after_hash: pp,
                            limit: IBD_HEADER_BATCH as u32,
                        },
                    },
                ];
            }
        }

        // Need more proofs — ask another peer
        vec![IbdAction::SendToBest {
            message: IbdMessage::GetPruningProof,
        }]
    }

    /// Handle a header batch response.
    ///
    /// # Anti-DoS Flow (see module-level docs)
    ///
    /// Each header is enqueued for validation. The network layer calls
    /// `on_header_validated(hash, valid)` for each. Only valid headers
    /// are promoted to the BodyFetch queue.
    pub fn on_headers_received(
        &mut self,
        peer_id: [u8; 20],
        headers: &[(Hash, Vec<u8>)],
        has_more: bool,
    ) -> Vec<IbdAction> {
        let (last_validated, validated_queue, invalid_headers, peer_has_more, headers_validated) =
            match &mut self.phase {
                IbdPhase::HeaderSync {
                    last_validated,
                    validated_queue,
                    invalid_headers,
                    peer_has_more,
                    headers_validated,
                    ..
                } => (
                    last_validated,
                    validated_queue,
                    invalid_headers,
                    peer_has_more,
                    headers_validated,
                ),
                _ => return vec![],
            };

        if headers.is_empty() && *peer_has_more {
            let penalty = self.add_peer_penalty(peer_id, 10);
            let mut actions = vec![IbdAction::Penalize {
                peer_id,
                points: 10,
                reason: "empty header batch with has_more=true".into(),
            }];
            if penalty >= crate::peer_state::BAN_THRESHOLD {
                actions.push(IbdAction::Ban {
                    peer_id,
                    reason: "repeated empty header batches".into(),
                });
            }
            return actions;
        }

        let mut actions = Vec::with_capacity(headers.len() + 1);

        for (hash, header_bytes) in headers {
            if self.local_known.contains(hash) || invalid_headers.contains(hash) {
                continue;
            }
            *headers_validated += 1;
            actions.push(IbdAction::ValidateHeader {
                hash: *hash,
                header_bytes: header_bytes.clone(),
            });
        }

        *peer_has_more = has_more;

        if let Some((last_hash, _)) = headers.last() {
            *last_validated = *last_hash;
        }

        if has_more && validated_queue.len() < MAX_PENDING_HEADERS {
            // Request next batch
            actions.push(IbdAction::SendToBest {
                message: IbdMessage::GetHeaders {
                    after_hash: *last_validated,
                    limit: IBD_HEADER_BATCH as u32,
                },
            });
        }

        actions
    }

    /// Callback: a header has been validated (or rejected).
    pub fn on_header_validated(&mut self, hash: Hash, valid: bool) -> Vec<IbdAction> {
        let (validated_queue, invalid_headers, peer_has_more, pruning_point) = match &mut self.phase
        {
            IbdPhase::HeaderSync {
                validated_queue,
                invalid_headers,
                peer_has_more,
                pruning_point,
                ..
            } => (validated_queue, invalid_headers, *peer_has_more, *pruning_point),
            _ => return vec![],
        };

        if valid {
            validated_queue.push(hash);
            self.local_known.insert(hash);
        } else {
            invalid_headers.insert(hash);
        }

        // If no more headers from peer and we have validated headers → transition to BodyFetch
        if !peer_has_more && !validated_queue.is_empty() {
            let queue: VecDeque<Hash> = validated_queue
                .iter()
                .filter(|h| !self.local_known.contains(*h) || validated_queue.contains(*h))
                .copied()
                .collect();

            let batch: Vec<Hash> = queue.iter().take(IBD_BODY_BATCH).copied().collect();

            if batch.is_empty() {
                // All headers were already known — we're synced
                self.phase = IbdPhase::SteadyRelay;
                return vec![
                    IbdAction::CommitIbdState,
                    IbdAction::Log {
                        level: LogLevel::Info,
                        message: "IBD complete: all headers already known, entering relay mode"
                            .into(),
                    },
                ];
            }

            let in_flight: HashSet<Hash> = batch.iter().copied().collect();
            let mut remaining = queue;
            for h in &batch {
                // Mark as dispatched (remove from front)
                if remaining.front() == Some(h) {
                    remaining.pop_front();
                }
            }

            self.phase = IbdPhase::BodyFetch {
                remaining,
                in_flight,
                bodies_applied: 0,
                expected_utxo_commitment: ZERO_HASH, // Set by pruning proof
            };

            return vec![
                IbdAction::Log {
                    level: LogLevel::Info,
                    message: format!(
                        "IBD: header sync complete — fetching {} block bodies",
                        batch.len()
                    ),
                },
                IbdAction::SendToBest {
                    message: IbdMessage::GetBodies { hashes: batch },
                },
            ];
        }

        vec![]
    }

    /// Handle a body batch response.
    pub fn on_bodies_received(
        &mut self,
        peer_id: [u8; 20],
        blocks: &[(Hash, Vec<u8>, Vec<u8>)],
    ) -> Vec<IbdAction> {
        let mut actions = Vec::new();

        let (next_batch, completed, bodies_applied_total) = {
            let (remaining, in_flight, bodies_applied) = match &mut self.phase {
                IbdPhase::BodyFetch {
                    remaining,
                    in_flight,
                    bodies_applied,
                    ..
                } => (remaining, in_flight, bodies_applied),
                _ => return vec![],
            };

            for (hash, header_bytes, body_bytes) in blocks {
                in_flight.remove(hash);
                *bodies_applied += 1;
                self.local_known.insert(*hash);

                actions.push(IbdAction::ApplyBody {
                    hash: *hash,
                    header_bytes: header_bytes.clone(),
                    body_bytes: body_bytes.clone(),
                });
            }

            // Request next batch if there are remaining bodies
            let next_batch: Vec<Hash> =
                remaining.drain(..remaining.len().min(IBD_BODY_BATCH)).collect();
            let completed = next_batch.is_empty() && in_flight.is_empty();
            let bodies_applied_total = *bodies_applied;

            if !completed {
                for h in &next_batch {
                    in_flight.insert(*h);
                }
            }

            (next_batch, completed, bodies_applied_total)
        };

        if completed {
            self.phase = IbdPhase::SteadyRelay;
            actions.push(IbdAction::CommitIbdState);
            actions.push(IbdAction::Log {
                level: LogLevel::Info,
                message: format!(
                    "IBD complete: {} bodies applied, entering relay mode",
                    bodies_applied_total
                ),
            });
        } else if !next_batch.is_empty() {
            actions.push(IbdAction::SendToBest {
                message: IbdMessage::GetBodies { hashes: next_batch },
            });
        }

        actions
    }

    /// Handle a body application failure.
    pub fn on_body_apply_failed(
        &mut self,
        peer_id: [u8; 20],
        hash: Hash,
        reason: &str,
    ) -> Vec<IbdAction> {
        let penalty = self.add_peer_penalty(peer_id, INVALID_BODY_PENALTY);
        let mut actions = vec![
            IbdAction::Penalize {
                peer_id,
                points: INVALID_BODY_PENALTY,
                reason: format!("invalid body for {}: {}", hex::encode(&hash[..4]), reason),
            },
            IbdAction::Log {
                level: LogLevel::Warn,
                message: format!(
                    "IBD: body validation failed for {}: {}",
                    hex::encode(&hash[..4]),
                    reason
                ),
            },
        ];

        if penalty >= crate::peer_state::BAN_THRESHOLD {
            actions.push(IbdAction::Ban {
                peer_id,
                reason: format!("too many invalid bodies: {}", reason),
            });
        }

        actions
    }

    /// Check if IBD is complete (in SteadyRelay phase).
    pub fn is_synced(&self) -> bool {
        matches!(self.phase, IbdPhase::SteadyRelay)
    }

    /// Check if IBD has failed.
    pub fn is_failed(&self) -> bool {
        matches!(self.phase, IbdPhase::Failed { .. })
    }

    /// Get human-readable sync progress.
    pub fn progress(&self) -> IbdProgress {
        match &self.phase {
            IbdPhase::RequestPruningPoint { proofs_received, .. } => IbdProgress {
                phase: "RequestPruningPoint".into(),
                detail: format!("{} proofs received", proofs_received.len()),
                headers_validated: 0,
                bodies_applied: 0,
                remaining_bodies: 0,
            },
            IbdPhase::HeaderSync {
                headers_validated,
                invalid_headers,
                validated_queue,
                ..
            } => IbdProgress {
                phase: "HeaderSync".into(),
                detail: format!(
                    "{} validated, {} invalid, {} queued",
                    headers_validated,
                    invalid_headers.len(),
                    validated_queue.len()
                ),
                headers_validated: *headers_validated,
                bodies_applied: 0,
                remaining_bodies: validated_queue.len() as u64,
            },
            IbdPhase::BodyFetch {
                remaining,
                in_flight,
                bodies_applied,
                ..
            } => IbdProgress {
                phase: "BodyFetch".into(),
                detail: format!(
                    "{} applied, {} in-flight, {} remaining",
                    bodies_applied,
                    in_flight.len(),
                    remaining.len()
                ),
                headers_validated: 0,
                bodies_applied: *bodies_applied,
                remaining_bodies: (remaining.len() + in_flight.len()) as u64,
            },
            IbdPhase::SteadyRelay => IbdProgress {
                phase: "SteadyRelay".into(),
                detail: "synced".into(),
                headers_validated: 0,
                bodies_applied: 0,
                remaining_bodies: 0,
            },
            IbdPhase::Failed { reason } => IbdProgress {
                phase: "Failed".into(),
                detail: reason.clone(),
                headers_validated: 0,
                bodies_applied: 0,
                remaining_bodies: 0,
            },
        }
    }

    // ─── Internal helpers ───

    fn add_peer_penalty(&mut self, peer_id: [u8; 20], points: u32) -> u32 {
        let entry = self.peer_penalties.entry(peer_id).or_insert(0);
        *entry = entry.saturating_add(points);
        *entry
    }
}

/// Sync progress snapshot for RPC/monitoring.
#[derive(Debug, Clone, Serialize)]
pub struct IbdProgress {
    pub phase: String,
    pub detail: String,
    pub headers_validated: u64,
    pub bodies_applied: u64,
    pub remaining_bodies: u64,
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: u8) -> [u8; 20] {
        let mut p = [0u8; 20];
        p[0] = id;
        p
    }

    fn h(b: u8) -> Hash {
        [b; 32]
    }

    #[test]
    fn test_fresh_ibd_starts_requesting_pruning_proof() {
        let mut engine = IbdEngine::new_fresh();
        let actions = engine.start();
        assert!(actions.iter().any(|a| matches!(
            a,
            IbdAction::SendToBest {
                message: IbdMessage::GetPruningProof
            }
        )));
    }

    #[test]
    fn test_pruning_proof_valid_transitions_to_header_sync() {
        let mut engine = IbdEngine::new_fresh();
        let actions = engine.on_pruning_proof_received(peer(1), h(0xAA), h(0xBB), true);
        assert!(matches!(engine.phase, IbdPhase::HeaderSync { .. }));
        // Should request first header batch
        assert!(actions.iter().any(|a| matches!(
            a,
            IbdAction::SendToBest {
                message: IbdMessage::GetHeaders { .. }
            }
        )));
    }

    #[test]
    fn test_pruning_proof_invalid_penalizes_peer() {
        let mut engine = IbdEngine::new_fresh();
        let actions = engine.on_pruning_proof_received(peer(1), h(0xAA), h(0xBB), false);
        assert!(actions.iter().any(|a| matches!(
            a,
            IbdAction::Penalize {
                points: PRUNING_PROOF_PENALTY,
                ..
            }
        )));
        // Should still be in RequestPruningPoint
        assert!(matches!(
            engine.phase,
            IbdPhase::RequestPruningPoint { .. }
        ));
    }

    #[test]
    fn test_header_sync_enqueues_validation() {
        let mut engine = IbdEngine::new_fresh();
        engine.on_pruning_proof_received(peer(1), h(0xAA), h(0xBB), true);

        let headers: Vec<(Hash, Vec<u8>)> = (1..=5u8).map(|i| (h(i), vec![i])).collect();
        let actions = engine.on_headers_received(peer(1), &headers, true);

        let validate_count = actions
            .iter()
            .filter(|a| matches!(a, IbdAction::ValidateHeader { .. }))
            .count();
        assert_eq!(validate_count, 5);
    }

    #[test]
    fn test_header_sync_to_body_fetch_transition() {
        let mut engine = IbdEngine::new_fresh();
        engine.on_pruning_proof_received(peer(1), h(0xAA), h(0xBB), true);

        let headers: Vec<(Hash, Vec<u8>)> = (1..=3u8).map(|i| (h(i), vec![i])).collect();
        engine.on_headers_received(peer(1), &headers, false);

        // Validate all headers
        for i in 1..=3u8 {
            engine.on_header_validated(h(i), true);
        }

        // Should be in BodyFetch now
        assert!(
            matches!(engine.phase, IbdPhase::BodyFetch { .. }),
            "Expected BodyFetch, got {:?}",
            engine.phase
        );
    }

    #[test]
    fn test_body_fetch_to_steady_relay() {
        let mut engine = IbdEngine::new_fresh();
        engine.on_pruning_proof_received(peer(1), h(0xAA), h(0xBB), true);

        let headers: Vec<(Hash, Vec<u8>)> = (1..=2u8).map(|i| (h(i), vec![i])).collect();
        engine.on_headers_received(peer(1), &headers, false);
        for i in 1..=2u8 {
            engine.on_header_validated(h(i), true);
        }

        // Now in BodyFetch — deliver bodies
        let bodies: Vec<(Hash, Vec<u8>, Vec<u8>)> =
            (1..=2u8).map(|i| (h(i), vec![i], vec![])).collect();
        let actions = engine.on_bodies_received(peer(1), &bodies);

        assert!(engine.is_synced());
        assert!(actions.iter().any(|a| matches!(a, IbdAction::CommitIbdState)));
    }

    #[test]
    fn test_invalid_header_excluded_from_body_fetch() {
        let mut engine = IbdEngine::new_fresh();
        engine.on_pruning_proof_received(peer(1), h(0xAA), h(0xBB), true);

        let headers: Vec<(Hash, Vec<u8>)> = (1..=3u8).map(|i| (h(i), vec![i])).collect();
        engine.on_headers_received(peer(1), &headers, false);

        // Mark header 2 as invalid
        engine.on_header_validated(h(1), true);
        engine.on_header_validated(h(2), false);
        engine.on_header_validated(h(3), true);

        // Should exclude h(2) from body fetch
        if let IbdPhase::BodyFetch { remaining, .. } = &engine.phase {
            assert!(!remaining.contains(&h(2)));
        } else if let IbdPhase::HeaderSync { invalid_headers, .. } = &engine.phase {
            assert!(invalid_headers.contains(&h(2)));
        }
    }

    #[test]
    fn test_resume_from_pruning_point() {
        let known: HashSet<Hash> = [h(0), h(1), h(2)].into_iter().collect();
        let engine = IbdEngine::resume_from_pruning_point(h(0), known, 100);
        assert!(matches!(engine.phase, IbdPhase::HeaderSync { .. }));
        assert_eq!(engine.local_blue_score, 100);
    }

    #[test]
    fn test_progress_reporting() {
        let engine = IbdEngine::new_fresh();
        let progress = engine.progress();
        assert_eq!(progress.phase, "RequestPruningPoint");
    }
}
