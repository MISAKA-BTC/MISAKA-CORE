//! BFT State Machine — Tendermint/HotStuff hybrid consensus.
//!
//! # State Transitions
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │  Slot S, Round R                                        │
//! │                                                         │
//! │  NewRound ──propose()──► WaitPrevote ──prevote()──►     │
//! │            timeout ↓                  timeout ↓         │
//! │            next round                 next round        │
//! │                                                         │
//! │  WaitPrecommit ──precommit()──► Committed               │
//! │             timeout ↓                                   │
//! │             next round                                  │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # Safety Invariants
//!
//! 1. A validator MUST NOT prevote for two different blocks in the same (slot, round).
//! 2. A validator MUST NOT precommit for two different blocks in the same (slot, round).
//! 3. If a validator has a `locked_value` (from a prevote polka), it MUST prevote
//!    for the locked value in all subsequent rounds (until unlocked by a higher polka).
//! 4. A block is committed ONLY when a precommit QC is formed (2/3+ stake).
//!
//! # Liveness
//!
//! - Timeouts increase exponentially per round (base + round × increment).
//! - Nil votes (timeout without valid proposal) allow round advancement.
//! - A new proposer is elected each round via VRF.

use std::collections::HashMap;

use super::bft_types::*;
use super::validator_set::ValidatorSet;
use misaka_types::validator::{DagCheckpointTarget, ValidatorId, ValidatorSignature};

// ═══════════════════════════════════════════════════════════════
//  BFT Step (phase within a round)
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BftStep {
    /// Waiting for a proposal from the round leader.
    NewRound,
    /// Proposal received, collecting prevotes.
    Prevote,
    /// Prevote polka received, collecting precommits.
    Precommit,
    /// Precommit QC formed, block committed.
    Committed,
}

// ═══════════════════════════════════════════════════════════════
//  Round State
// ═══════════════════════════════════════════════════════════════

/// State for a single (slot, round) in the BFT protocol.
#[derive(Debug, Clone)]
pub struct RoundState {
    pub slot: u64,
    pub round: u32,
    pub step: BftStep,

    /// The proposal received for this round (if any).
    pub proposal: Option<BftProposal>,

    /// Prevotes collected: voter → (block_hash, vote).
    pub prevotes: HashMap<ValidatorId, BftVote>,
    /// Total prevote stake weight.
    pub prevote_weight: u128,
    /// Prevote weight per block_hash.
    pub prevote_by_hash: HashMap<Option<Hash>, u128>,

    /// Precommits collected: voter → (block_hash, vote).
    pub precommits: HashMap<ValidatorId, BftVote>,
    /// Total precommit stake weight.
    pub precommit_weight: u128,
    /// Precommit weight per block_hash.
    pub precommit_by_hash: HashMap<Option<Hash>, u128>,
}

impl RoundState {
    pub fn new(slot: u64, round: u32) -> Self {
        Self {
            slot,
            round,
            step: BftStep::NewRound,
            proposal: None,
            prevotes: HashMap::new(),
            prevote_weight: 0,
            prevote_by_hash: HashMap::new(),
            precommits: HashMap::new(),
            precommit_weight: 0,
            precommit_by_hash: HashMap::new(),
        }
    }

    /// Check if prevote has quorum for any block (including nil).
    pub fn has_prevote_quorum(&self, total_stake: u128) -> Option<Option<Hash>> {
        let threshold = quorum_threshold(total_stake);
        for (hash, weight) in &self.prevote_by_hash {
            if *weight >= threshold {
                return Some(*hash);
            }
        }
        None
    }

    /// Check if precommit has quorum for any block (including nil).
    pub fn has_precommit_quorum(&self, total_stake: u128) -> Option<Option<Hash>> {
        let threshold = quorum_threshold(total_stake);
        for (hash, weight) in &self.precommit_by_hash {
            if *weight >= threshold {
                return Some(*hash);
            }
        }
        None
    }

    /// Check if any 2/3+ of prevotes have been received (for any set of values).
    /// Used to decide whether to advance to precommit timeout.
    pub fn has_prevote_any_quorum(&self, total_stake: u128) -> bool {
        self.prevote_weight >= quorum_threshold(total_stake)
    }

    /// Check if any 2/3+ of precommits have been received.
    pub fn has_precommit_any_quorum(&self, total_stake: u128) -> bool {
        self.precommit_weight >= quorum_threshold(total_stake)
    }
}

/// Compute BFT quorum threshold from total stake.
/// `⌈total_stake × 6667 / 10000⌉` (6667 BPS = 66.67%)
fn quorum_threshold(total_stake: u128) -> u128 {
    let bps = misaka_types::constants::QUORUM_THRESHOLD_BPS as u128;
    (total_stake * bps + 9999) / 10000
}

// ═══════════════════════════════════════════════════════════════
//  BFT State Machine
// ═══════════════════════════════════════════════════════════════

/// Actions emitted by the state machine for the node to execute.
#[derive(Debug, Clone)]
pub enum BftAction {
    /// Broadcast a proposal (we are the leader).
    BroadcastProposal(BftProposal),
    /// Broadcast a prevote.
    BroadcastPrevote(BftVote),
    /// Broadcast a precommit.
    BroadcastPrecommit(BftVote),
    /// Start a timeout timer for the current step.
    ScheduleTimeout {
        slot: u64,
        round: u32,
        step: BftStep,
        timeout_ms: u64,
    },
    /// Block committed — emit finality checkpoint.
    Commit(BftCommit),
    /// Equivocation detected — submit slashing evidence.
    ReportEquivocation(EquivocationEvidence),
    /// Advance to next round.
    AdvanceRound {
        slot: u64,
        new_round: u32,
    },
}

/// The main BFT consensus state machine.
///
/// Each node runs one instance. The state machine is event-driven:
/// it receives messages and timeouts, and emits actions.
///
/// # Thread Safety
///
/// This struct is NOT thread-safe. The caller (node event loop) must
/// serialize access. Actions are collected in a Vec and returned to
/// the caller for execution.
pub struct BftStateMachine {
    /// Our validator ID.
    pub local_id: ValidatorId,
    /// Current slot.
    pub slot: u64,
    /// Current round within the slot.
    pub round: u32,
    /// Per-round state.
    pub round_states: HashMap<u32, RoundState>,
    /// Locked value: if we precommitted in a previous round,
    /// we must re-propose / re-vote for this value.
    pub locked_value: Option<LockedValue>,
    /// Valid value: most recent value we prevoted for with a polka.
    pub valid_value: Option<Hash>,
    /// Valid round: the round in which valid_value was set.
    pub valid_round: Option<u32>,
    /// Last committed slot (to avoid double-commit).
    pub last_committed_slot: u64,
    /// Timeout configuration.
    pub timeout_config: TimeoutConfig,
    /// Epoch randomness for VRF.
    pub epoch_randomness: EpochRandomness,
    /// Historical prevote quorum certificates per round.
    /// Used to verify polka claims when evaluating proposals with valid_round.
    pub historical_prevotes: HashMap<u32, Vec<BftVote>>,
}

/// A locked value from a previous round's polka.
#[derive(Debug, Clone)]
pub struct LockedValue {
    pub block_hash: Hash,
    pub round: u32,
}

impl BftStateMachine {
    pub fn new(
        local_id: ValidatorId,
        start_slot: u64,
        epoch_randomness: EpochRandomness,
    ) -> Self {
        let mut round_states = HashMap::new();
        round_states.insert(0, RoundState::new(start_slot, 0));
        Self {
            local_id,
            slot: start_slot,
            round: 0,
            round_states,
            locked_value: None,
            valid_value: None,
            valid_round: None,
            last_committed_slot: 0,
            timeout_config: TimeoutConfig::default(),
            epoch_randomness,
            historical_prevotes: HashMap::new(),
        }
    }

    /// Record a prevote quorum (polka) at a given round for later verification.
    pub fn record_prevote_quorum(&mut self, round: u32, votes: Vec<BftVote>) {
        self.historical_prevotes.insert(round, votes);
    }

    /// Verify that a polka (2/3+ prevotes) exists at the claimed round for the given block hash.
    fn verify_polka_at_round(&self, block_hash: Hash, round: u32, validator_set: &ValidatorSet) -> bool {
        let Some(prevotes) = self.historical_prevotes.get(&round) else {
            return false;
        };
        // Count prevote stake for this block_hash
        let matching: u128 = prevotes.iter()
            .filter(|v| v.block_hash == Some(block_hash))
            .filter_map(|v| validator_set.get(&v.voter))
            .map(|vi| vi.stake_weight)
            .sum();
        let total: u128 = validator_set.total_stake();
        // Polka requires 2/3+ stake
        matching * 3 > total * 2
    }

    /// Get or create the round state for a given round.
    fn round_state(&mut self, round: u32) -> &mut RoundState {
        self.round_states
            .entry(round)
            .or_insert_with(|| RoundState::new(self.slot, round))
    }

    /// Current step of the current round.
    pub fn current_step(&self) -> BftStep {
        self.round_states
            .get(&self.round)
            .map(|rs| rs.step)
            .unwrap_or(BftStep::NewRound)
    }

    // ─── Event Handlers ─────────────────────────────────────

    /// Called when starting a new round (round 0 or after timeout).
    ///
    /// If we are the proposer, emit a proposal. Otherwise, schedule timeout.
    pub fn on_new_round(
        &mut self,
        am_i_proposer: bool,
        block_hash: Option<Hash>,
        dag_checkpoint: Option<DagCheckpointTarget>,
        vrf_proof: Option<VrfOutput>,
        validator_set: &ValidatorSet,
    ) -> Vec<BftAction> {
        let mut actions = Vec::new();
        let rs = self.round_state(self.round);
        rs.step = BftStep::NewRound;

        if am_i_proposer {
            if let (Some(bh), Some(cp), Some(vrf)) = (block_hash, dag_checkpoint, vrf_proof) {
                // If we have a locked value, we MUST propose it
                let (proposed_hash, valid_round) = if let Some(ref locked) = self.locked_value {
                    (locked.block_hash, locked.round)
                } else {
                    (bh, u32::MAX)
                };

                let proposal = BftProposal {
                    slot: self.slot,
                    round: self.round,
                    proposer: self.local_id,
                    block_hash: proposed_hash,
                    dag_checkpoint: cp,
                    vrf_proof: vrf,
                    valid_round,
                    signature: ValidatorSignature { bytes: vec![] }, // Caller signs
                };
                actions.push(BftAction::BroadcastProposal(proposal));
            }
        }

        // Schedule proposal timeout
        actions.push(BftAction::ScheduleTimeout {
            slot: self.slot,
            round: self.round,
            step: BftStep::NewRound,
            timeout_ms: self.timeout_config.timeout_ms(self.round),
        });

        actions
    }

    /// Called when a proposal is received.
    ///
    /// Validates the proposal and emits a prevote.
    pub fn on_proposal(
        &mut self,
        proposal: BftProposal,
        is_valid_block: bool,
        validator_set: &ValidatorSet,
    ) -> Vec<BftAction> {
        let mut actions = Vec::new();

        // Ignore proposals for wrong slot/round
        if proposal.slot != self.slot || proposal.round != self.round {
            return actions;
        }

        let rs = self.round_state(self.round);

        // Duplicate proposal from same proposer? Check for equivocation
        if let Some(ref existing) = rs.proposal {
            if existing.block_hash != proposal.block_hash {
                actions.push(BftAction::ReportEquivocation(
                    EquivocationEvidence::DoubleProposal {
                        validator_id: proposal.proposer,
                        proposal_a: existing.clone(),
                        proposal_b: proposal.clone(),
                    },
                ));
            }
            return actions; // Already have a proposal for this round
        }

        rs.proposal = Some(proposal.clone());
        rs.step = BftStep::Prevote;

        // Decide prevote value
        let prevote_hash = self.decide_prevote(&proposal, is_valid_block, validator_set);

        let vote = BftVote {
            slot: self.slot,
            round: self.round,
            voter: self.local_id,
            block_hash: prevote_hash,
            signature: ValidatorSignature { bytes: vec![] }, // Caller signs
        };

        actions.push(BftAction::BroadcastPrevote(vote));
        actions.push(BftAction::ScheduleTimeout {
            slot: self.slot,
            round: self.round,
            step: BftStep::Prevote,
            timeout_ms: self.timeout_config.timeout_ms(self.round),
        });

        actions
    }

    /// Decide what to prevote for (Tendermint rules).
    fn decide_prevote(&self, proposal: &BftProposal, is_valid_block: bool, validator_set: &ValidatorSet) -> Option<Hash> {
        if !is_valid_block {
            return None; // nil vote
        }

        // Rule 1: If we have a locked value, only prevote for it
        if let Some(ref locked) = self.locked_value {
            if proposal.block_hash == locked.block_hash {
                return Some(proposal.block_hash);
            }
            // If proposal has a valid_round > locked.round and there's a polka
            // for the proposal at valid_round, we can unlock
            if proposal.valid_round != u32::MAX
                && proposal.valid_round > locked.round
            {
                // Verify polka (2/3+ prevotes) at the claimed valid_round
                if self.verify_polka_at_round(proposal.block_hash, proposal.valid_round, validator_set) {
                    return Some(proposal.block_hash);
                }
                // No verified polka — cannot unlock, nil prevote
                return None;
            }
            return None; // nil — cannot prevote for a different value
        }

        // Rule 2: No lock — prevote for the proposal
        Some(proposal.block_hash)
    }

    /// Called when a prevote is received.
    pub fn on_prevote(
        &mut self,
        vote: BftVote,
        validator_set: &ValidatorSet,
    ) -> Vec<BftAction> {
        let mut actions = Vec::new();

        if vote.slot != self.slot {
            return actions;
        }

        let total_stake = validator_set.total_stake();
        let voter_weight = validator_set
            .get(&vote.voter)
            .map(|v| v.stake_weight)
            .unwrap_or(0);

        let round = vote.round;
        let rs = self.round_state(round);

        // Check for double prevote (equivocation)
        if let Some(existing) = rs.prevotes.get(&vote.voter) {
            if existing.block_hash != vote.block_hash {
                actions.push(BftAction::ReportEquivocation(
                    EquivocationEvidence::DoublePrevote {
                        validator_id: vote.voter,
                        vote_a: existing.clone(),
                        vote_b: vote.clone(),
                    },
                ));
            }
            return actions; // Already counted this voter
        }

        // Record vote
        rs.prevotes.insert(vote.voter, vote.clone());
        rs.prevote_weight += voter_weight;
        *rs.prevote_by_hash.entry(vote.block_hash).or_insert(0) += voter_weight;

        // Check for prevote polka (2/3+ for a specific block)
        if round == self.round {
            if let Some(polka_hash) = rs.has_prevote_quorum(total_stake) {
                if let Some(hash) = polka_hash {
                    // Polka for a block → lock value, move to precommit
                    self.locked_value = Some(LockedValue {
                        block_hash: hash,
                        round,
                    });
                    self.valid_value = Some(hash);
                    self.valid_round = Some(round);

                    let rs = self.round_state(round);
                    if rs.step == BftStep::Prevote {
                        rs.step = BftStep::Precommit;

                        let vote = BftVote {
                            slot: self.slot,
                            round: self.round,
                            voter: self.local_id,
                            block_hash: Some(hash),
                            signature: ValidatorSignature { bytes: vec![] },
                        };
                        actions.push(BftAction::BroadcastPrecommit(vote));
                        actions.push(BftAction::ScheduleTimeout {
                            slot: self.slot,
                            round: self.round,
                            step: BftStep::Precommit,
                            timeout_ms: self.timeout_config.timeout_ms(self.round),
                        });
                    }
                } else {
                    // Nil polka → precommit nil, advance round
                    let rs = self.round_state(round);
                    if rs.step == BftStep::Prevote {
                        rs.step = BftStep::Precommit;

                        let vote = BftVote {
                            slot: self.slot,
                            round: self.round,
                            voter: self.local_id,
                            block_hash: None,
                            signature: ValidatorSignature { bytes: vec![] },
                        };
                        actions.push(BftAction::BroadcastPrecommit(vote));
                    }
                }
            }
        }

        actions
    }

    /// Called when a precommit is received.
    pub fn on_precommit(
        &mut self,
        vote: BftVote,
        validator_set: &ValidatorSet,
    ) -> Vec<BftAction> {
        let mut actions = Vec::new();

        if vote.slot != self.slot {
            return actions;
        }

        let total_stake = validator_set.total_stake();
        let voter_weight = validator_set
            .get(&vote.voter)
            .map(|v| v.stake_weight)
            .unwrap_or(0);

        let round = vote.round;
        let rs = self.round_state(round);

        // Check for double precommit (equivocation)
        if let Some(existing) = rs.precommits.get(&vote.voter) {
            if existing.block_hash != vote.block_hash {
                actions.push(BftAction::ReportEquivocation(
                    EquivocationEvidence::DoublePrecommit {
                        validator_id: vote.voter,
                        vote_a: existing.clone(),
                        vote_b: vote.clone(),
                    },
                ));
            }
            return actions;
        }

        // Record vote
        rs.precommits.insert(vote.voter, vote.clone());
        rs.precommit_weight += voter_weight;
        *rs.precommit_by_hash.entry(vote.block_hash).or_insert(0) += voter_weight;

        // Check for precommit quorum
        if let Some(commit_hash) = rs.has_precommit_quorum(total_stake) {
            if let Some(hash) = commit_hash {
                // COMMIT — block is finalized
                if self.last_committed_slot < self.slot {
                    self.last_committed_slot = self.slot;

                    // Build precommit QC
                    let votes: Vec<BftVote> = rs
                        .precommits
                        .values()
                        .filter(|v| v.block_hash == Some(hash))
                        .cloned()
                        .collect();

                    let qc_weight: u128 = votes
                        .iter()
                        .filter_map(|v| validator_set.get(&v.voter))
                        .map(|vi| vi.stake_weight)
                        .sum();

                    let dag_checkpoint = rs
                        .proposal
                        .as_ref()
                        .map(|p| p.dag_checkpoint.clone())
                        .unwrap_or_else(|| DagCheckpointTarget {
                            block_hash: hash,
                            blue_score: 0,
                            utxo_root: [0; 32],
                            total_key_images: 0,
                            total_applied_txs: 0,
                        });

                    actions.push(BftAction::Commit(BftCommit {
                        slot: self.slot,
                        round,
                        block_hash: hash,
                        dag_checkpoint,
                        precommit_qc: QuorumCertificate {
                            qc_type: QcType::Precommit,
                            slot: self.slot,
                            round,
                            block_hash: Some(hash),
                            votes,
                            total_weight: qc_weight,
                        },
                    }));

                    let rs = self.round_state(round);
                    rs.step = BftStep::Committed;
                }
            } else {
                // Nil precommit quorum → advance round
                actions.push(BftAction::AdvanceRound {
                    slot: self.slot,
                    new_round: self.round + 1,
                });
            }
        }

        actions
    }

    /// Called when a timeout fires for the current round.
    pub fn on_timeout(
        &mut self,
        slot: u64,
        round: u32,
        step: BftStep,
        validator_set: &ValidatorSet,
    ) -> Vec<BftAction> {
        let mut actions = Vec::new();

        // Ignore stale timeouts
        if slot != self.slot || round != self.round {
            return actions;
        }

        match step {
            BftStep::NewRound => {
                // Proposal timeout → prevote nil
                let vote = BftVote {
                    slot: self.slot,
                    round: self.round,
                    voter: self.local_id,
                    block_hash: None,
                    signature: ValidatorSignature { bytes: vec![] },
                };
                actions.push(BftAction::BroadcastPrevote(vote));
                let rs = self.round_state(self.round);
                if rs.step == BftStep::NewRound {
                    rs.step = BftStep::Prevote;
                }
                actions.push(BftAction::ScheduleTimeout {
                    slot: self.slot,
                    round: self.round,
                    step: BftStep::Prevote,
                    timeout_ms: self.timeout_config.timeout_ms(self.round),
                });
            }
            BftStep::Prevote => {
                // Prevote timeout → precommit nil
                let total_stake = validator_set.total_stake();
                let rs = self.round_state(self.round);
                if rs.has_prevote_any_quorum(total_stake) && rs.step == BftStep::Prevote {
                    rs.step = BftStep::Precommit;
                    let vote = BftVote {
                        slot: self.slot,
                        round: self.round,
                        voter: self.local_id,
                        block_hash: None,
                        signature: ValidatorSignature { bytes: vec![] },
                    };
                    actions.push(BftAction::BroadcastPrecommit(vote));
                    actions.push(BftAction::ScheduleTimeout {
                        slot: self.slot,
                        round: self.round,
                        step: BftStep::Precommit,
                        timeout_ms: self.timeout_config.timeout_ms(self.round),
                    });
                }
            }
            BftStep::Precommit => {
                // Precommit timeout → advance round
                let total_stake = validator_set.total_stake();
                let rs = self.round_state(self.round);
                if rs.has_precommit_any_quorum(total_stake) {
                    actions.push(BftAction::AdvanceRound {
                        slot: self.slot,
                        new_round: self.round + 1,
                    });
                }
            }
            BftStep::Committed => {} // No timeout for committed state
        }

        actions
    }

    /// Advance to the next round within the current slot.
    pub fn advance_round(&mut self, new_round: u32) {
        self.round = new_round;
        self.round_states
            .entry(new_round)
            .or_insert_with(|| RoundState::new(self.slot, new_round));
    }

    /// Advance to the next slot (after commit or slot timeout).
    pub fn advance_slot(&mut self, new_slot: u64) {
        self.slot = new_slot;
        self.round = 0;
        self.round_states.clear();
        self.round_states
            .insert(0, RoundState::new(new_slot, 0));
        // locked_value persists across slots if not unlocked
    }

    // ─── Garbage Collection ─────────────────────────────────

    /// Remove round states older than `keep_rounds` rounds.
    pub fn gc_old_rounds(&mut self, keep_rounds: u32) {
        if self.round > keep_rounds {
            let cutoff = self.round - keep_rounds;
            self.round_states.retain(|r, _| *r >= cutoff);
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_crypto::validator_sig::generate_validator_keypair;
    use misaka_types::validator::{ValidatorIdentity, ValidatorPublicKey};

    fn make_vs(n: usize) -> (ValidatorSet, Vec<[u8; 32]>) {
        let mut validators = Vec::new();
        let mut ids = Vec::new();
        for i in 0..n {
            let kp = generate_validator_keypair();
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            validators.push(ValidatorIdentity {
                validator_id: vid,
                stake_weight: 100,
                public_key: ValidatorPublicKey {
                    bytes: kp.public_key.to_bytes(),
                },
                is_active: true,
            });
            ids.push(vid);
        }
        (ValidatorSet::new(validators), ids)
    }

    fn make_vote(slot: u64, round: u32, voter: [u8; 32], hash: Option<Hash>) -> BftVote {
        BftVote {
            slot,
            round,
            voter,
            block_hash: hash,
            signature: ValidatorSignature { bytes: vec![0; 3309] },
        }
    }

    #[test]
    fn test_prevote_quorum_triggers_precommit() {
        let (vs, ids) = make_vs(4);
        let epoch = EpochRandomness::genesis();
        let mut sm = BftStateMachine::new(ids[0], 1, epoch);

        let block = [0xBB; 32];

        // Simulate receiving prevotes from 3/4 validators
        let actions1 = sm.on_prevote(make_vote(1, 0, ids[0], Some(block)), &vs);
        let actions2 = sm.on_prevote(make_vote(1, 0, ids[1], Some(block)), &vs);

        // Need to set step to Prevote first
        sm.round_state(0).step = BftStep::Prevote;

        let actions3 = sm.on_prevote(make_vote(1, 0, ids[2], Some(block)), &vs);

        // 3/4 × 100 = 300 weight, threshold for 400 total = 267 → quorum
        let has_precommit = actions3
            .iter()
            .any(|a| matches!(a, BftAction::BroadcastPrecommit(_)));
        assert!(has_precommit, "Should broadcast precommit after prevote polka");
    }

    #[test]
    fn test_precommit_quorum_triggers_commit() {
        let (vs, ids) = make_vs(4);
        let epoch = EpochRandomness::genesis();
        let mut sm = BftStateMachine::new(ids[0], 1, epoch);

        let block = [0xBB; 32];
        let checkpoint = DagCheckpointTarget {
            block_hash: block,
            blue_score: 100,
            utxo_root: [0xCC; 32],
            total_key_images: 10,
            total_applied_txs: 20,
        };

        // Set up proposal
        sm.round_state(0).proposal = Some(BftProposal {
            slot: 1,
            round: 0,
            proposer: ids[0],
            block_hash: block,
            dag_checkpoint: checkpoint,
            vrf_proof: VrfOutput {
                proof: vec![0; 3309],
                hash: [0xDD; 32],
            },
            valid_round: u32::MAX,
            signature: ValidatorSignature { bytes: vec![0; 3309] },
        });

        // Precommits from 3/4
        sm.on_precommit(make_vote(1, 0, ids[0], Some(block)), &vs);
        sm.on_precommit(make_vote(1, 0, ids[1], Some(block)), &vs);
        let actions = sm.on_precommit(make_vote(1, 0, ids[2], Some(block)), &vs);

        let has_commit = actions.iter().any(|a| matches!(a, BftAction::Commit(_)));
        assert!(has_commit, "Should commit after 2/3+ precommit");
    }

    #[test]
    fn test_double_prevote_reports_equivocation() {
        let (vs, ids) = make_vs(4);
        let epoch = EpochRandomness::genesis();
        let mut sm = BftStateMachine::new(ids[0], 1, epoch);

        let block_a = [0xAA; 32];
        let block_b = [0xBB; 32];

        sm.on_prevote(make_vote(1, 0, ids[1], Some(block_a)), &vs);
        let actions = sm.on_prevote(make_vote(1, 0, ids[1], Some(block_b)), &vs);

        let has_equivocation = actions
            .iter()
            .any(|a| matches!(a, BftAction::ReportEquivocation(_)));
        assert!(
            has_equivocation,
            "Should report equivocation on double prevote"
        );
    }

    #[test]
    fn test_nil_prevote_quorum_advances() {
        let (vs, ids) = make_vs(4);
        let epoch = EpochRandomness::genesis();
        let mut sm = BftStateMachine::new(ids[0], 1, epoch);
        sm.round_state(0).step = BftStep::Prevote;

        // 3/4 nil prevotes
        sm.on_prevote(make_vote(1, 0, ids[0], None), &vs);
        sm.on_prevote(make_vote(1, 0, ids[1], None), &vs);
        let actions = sm.on_prevote(make_vote(1, 0, ids[2], None), &vs);

        let has_nil_precommit = actions
            .iter()
            .any(|a| matches!(a, BftAction::BroadcastPrecommit(v) if v.block_hash.is_none()));
        assert!(
            has_nil_precommit,
            "Nil prevote polka should trigger nil precommit"
        );
    }

    #[test]
    fn test_timeout_proposal_sends_nil_prevote() {
        let (vs, ids) = make_vs(4);
        let epoch = EpochRandomness::genesis();
        let mut sm = BftStateMachine::new(ids[0], 1, epoch);

        let actions = sm.on_timeout(1, 0, BftStep::NewRound, &vs);

        let has_nil_prevote = actions
            .iter()
            .any(|a| matches!(a, BftAction::BroadcastPrevote(v) if v.block_hash.is_none()));
        assert!(
            has_nil_prevote,
            "Proposal timeout should send nil prevote"
        );
    }

    #[test]
    fn test_locked_value_enforced() {
        let (vs, _ids) = make_vs(4);
        let epoch = EpochRandomness::genesis();
        let mut sm = BftStateMachine::new([0x01; 20], 1, epoch);

        let locked_hash = [0xAA; 32];
        sm.locked_value = Some(LockedValue {
            block_hash: locked_hash,
            round: 0,
        });

        let different_proposal = BftProposal {
            slot: 1,
            round: 1,
            proposer: [0x02; 20],
            block_hash: [0xBB; 32], // Different from locked value
            dag_checkpoint: DagCheckpointTarget {
                block_hash: [0xBB; 32],
                blue_score: 100,
                utxo_root: [0; 32],
                total_key_images: 0,
                total_applied_txs: 0,
            },
            vrf_proof: VrfOutput {
                proof: vec![0; 3309],
                hash: [0; 32],
            },
            valid_round: u32::MAX,
            signature: ValidatorSignature { bytes: vec![0; 3309] },
        };

        // decide_prevote should return None because proposal != locked_value
        let result = sm.decide_prevote(&different_proposal, true, &vs);
        assert!(result.is_none(), "Should nil-vote when proposal doesn't match locked value");
    }

    #[test]
    fn test_advance_round_resets_step() {
        let epoch = EpochRandomness::genesis();
        let mut sm = BftStateMachine::new([0x01; 20], 1, epoch);
        sm.round_state(0).step = BftStep::Precommit;
        sm.advance_round(1);
        assert_eq!(sm.round, 1);
        assert_eq!(sm.current_step(), BftStep::NewRound);
    }

    #[test]
    fn test_gc_old_rounds() {
        let epoch = EpochRandomness::genesis();
        let mut sm = BftStateMachine::new([0x01; 20], 1, epoch);
        for r in 0..10u32 {
            sm.round_states.insert(r, RoundState::new(1, r));
        }
        sm.round = 9;
        sm.gc_old_rounds(3);
        assert!(sm.round_states.contains_key(&9));
        assert!(sm.round_states.contains_key(&7));
        assert!(!sm.round_states.contains_key(&5));
    }
}
