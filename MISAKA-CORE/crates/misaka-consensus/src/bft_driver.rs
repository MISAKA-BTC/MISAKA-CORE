//! BFT Consensus Driver — integrates all PoS hardening modules into the DAG node.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  BFT Consensus Driver (this module)                         │
//! │                                                             │
//! │  ┌──────────────┐   ┌─────────────┐   ┌────────────────┐  │
//! │  │ VRF Proposer │──►│ BFT State   │──►│ Fork Choice    │  │
//! │  │ (proposer    │   │ Machine     │   │ (finality      │  │
//! │  │  election)   │   │ (3-phase)   │   │  anchor)       │  │
//! │  └──────────────┘   └──────┬──────┘   └────────────────┘  │
//! │                            │                               │
//! │  ┌──────────────┐   ┌─────▼───────┐   ┌────────────────┐  │
//! │  │ Slash        │◄──│ Message     │   │ Inactivity     │  │
//! │  │ Detector     │   │ Router      │   │ Tracker        │  │
//! │  └──────────────┘   └─────────────┘   └────────────────┘  │
//! │                                                             │
//! │  ┌──────────────┐   ┌─────────────┐   ┌────────────────┐  │
//! │  │ Delegation   │   │ Weak        │   │ Epoch          │  │
//! │  │ Registry     │   │ Subjectivity│   │ Randomness     │  │
//! │  └──────────────┘   └─────────────┘   └────────────────┘  │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Integration with DAG Block Producer
//!
//! The BFT driver does NOT replace the DAG block producer.
//! Instead, it wraps it with consensus protocol:
//!
//! 1. BFT slot timer fires → VRF proposer check
//! 2. If proposer → produce DAG block → BFT Proposal
//! 3. Collect prevotes → precommits → commit
//! 4. On commit → finality checkpoint → fork choice update
//!
//! The existing `run_dag_block_producer` continues to handle
//! DAG mechanics (GhostDAG, state evaluation, UTXO apply).
//! This driver adds the consensus voting layer on top.

use tracing::{error, info, warn};

use crate::bft_state_machine::{BftAction, BftStateMachine, BftStep};
use crate::bft_types::*;
use crate::delegation::DelegationRegistry;
use crate::fork_choice::ForkChoiceState;
use crate::inactivity::InactivityTracker;
use crate::slash_detector::SlashDetector;
use crate::staking::StakingRegistry;
use crate::vrf_proposer;
use crate::weak_subjectivity::WeakSubjectivityGuard;
use crate::validator_set::ValidatorSet;
use misaka_crypto::validator_sig::{validator_sign, ValidatorKeypair, ValidatorPqSecretKey};
use misaka_types::validator::{
    DagCheckpointTarget, ValidatorId, ValidatorIdentity, ValidatorSignature,
};

// ═══════════════════════════════════════════════════════════════
//  BFT Consensus State
// ═══════════════════════════════════════════════════════════════

/// Full BFT consensus state, held alongside the DagNodeState.
pub struct BftConsensusState {
    /// BFT 3-phase state machine (Tendermint-style).
    pub bft: BftStateMachine,
    /// Equivocation detector (passive, observes all messages).
    pub slash_detector: SlashDetector,
    /// Hybrid fork choice (GhostDAG + BFT finality anchor).
    pub fork_choice: ForkChoiceState,
    /// Epoch randomness (RANDAO, accumulated from VRF outputs).
    pub epoch_randomness: EpochRandomness,
    /// Inactivity leak & correlation penalty tracker.
    pub inactivity: InactivityTracker,
    /// Delegation registry (DPoS).
    pub delegation: DelegationRegistry,
    /// Weak subjectivity checkpoint guard.
    pub ws_guard: WeakSubjectivityGuard,
    /// Current slot number.
    pub current_slot: u64,
    /// VRF outputs collected this epoch (for RANDAO).
    pub epoch_vrf_hashes: Vec<Hash>,
    /// Pending BFT actions to execute.
    pub pending_actions: Vec<BftAction>,
    /// Local validator secret key (for signing).
    local_secret_key: Option<ValidatorPqSecretKey>,
}

impl BftConsensusState {
    /// Initialize BFT consensus for a validator node.
    pub fn new_validator(
        local_id: ValidatorId,
        secret_key: ValidatorPqSecretKey,
        genesis_hash: Hash,
        chain_id: u32,
    ) -> Self {
        let epoch_randomness = EpochRandomness::genesis();
        Self {
            bft: BftStateMachine::new(local_id, 0, epoch_randomness.clone()),
            slash_detector: SlashDetector::with_defaults(),
            fork_choice: ForkChoiceState::genesis(genesis_hash),
            epoch_randomness,
            inactivity: InactivityTracker::with_defaults(),
            delegation: if chain_id == 1 {
                DelegationRegistry::mainnet()
            } else {
                DelegationRegistry::testnet()
            },
            ws_guard: WeakSubjectivityGuard::disabled(), // Operator sets checkpoint
            current_slot: 0,
            epoch_vrf_hashes: Vec::new(),
            pending_actions: Vec::new(),
            local_secret_key: Some(secret_key),
        }
    }

    /// Initialize BFT consensus for a non-validator (observer) node.
    pub fn new_observer(genesis_hash: Hash, chain_id: u32) -> Self {
        let epoch_randomness = EpochRandomness::genesis();
        Self {
            bft: BftStateMachine::new([0u8; 32], 0, epoch_randomness.clone()),
            slash_detector: SlashDetector::with_defaults(),
            fork_choice: ForkChoiceState::genesis(genesis_hash),
            epoch_randomness,
            inactivity: InactivityTracker::with_defaults(),
            delegation: if chain_id == 1 {
                DelegationRegistry::mainnet()
            } else {
                DelegationRegistry::testnet()
            },
            ws_guard: WeakSubjectivityGuard::disabled(),
            current_slot: 0,
            epoch_vrf_hashes: Vec::new(),
            pending_actions: Vec::new(),
            local_secret_key: None,
        }
    }

    /// Whether this node is a validator (can produce blocks and vote).
    pub fn is_validator(&self) -> bool {
        self.local_secret_key.is_some()
    }
}

// ═══════════════════════════════════════════════════════════════
//  Slot Event Handler
// ═══════════════════════════════════════════════════════════════

/// Called at the start of each slot (block_time_secs interval).
///
/// This is the main entry point for BFT consensus per slot.
/// It determines proposer via VRF and drives the BFT state machine.
pub fn on_new_slot(
    bft_state: &mut BftConsensusState,
    validator_set: &ValidatorSet,
    dag_checkpoint: Option<DagCheckpointTarget>,
    block_hash: Option<Hash>,
) -> Vec<BftAction> {
    bft_state.current_slot += 1;
    let slot = bft_state.current_slot;

    // Advance BFT to new slot
    bft_state.bft.advance_slot(slot);

    // Determine if we are the proposer via VRF
    let am_i_proposer = if let Some(ref sk) = bft_state.local_secret_key {
        match vrf_proposer::vrf_evaluate(sk, slot, &bft_state.epoch_randomness.randomness) {
            Ok(vrf_output) => {
                let is_proposer =
                    vrf_proposer::am_i_proposer(&bft_state.bft.local_id, validator_set, &vrf_output);

                if is_proposer {
                    // Record VRF hash for RANDAO
                    bft_state.epoch_vrf_hashes.push(vrf_output.hash);
                    info!(
                        "Slot {}: I AM the proposer (VRF hash={})",
                        slot,
                        hex::encode(&vrf_output.hash[..8])
                    );
                }

                // Convert to BFT VRF output
                let bft_vrf = Some(VrfOutput {
                    proof: vrf_output.proof,
                    hash: vrf_output.hash,
                });

                let actions = bft_state.bft.on_new_round(
                    is_proposer,
                    block_hash,
                    dag_checkpoint,
                    bft_vrf,
                    validator_set,
                );

                // Record participation for inactivity tracking
                bft_state
                    .inactivity
                    .record_participation(&bft_state.bft.local_id);

                return sign_and_collect_actions(bft_state, actions);
            }
            Err(e) => {
                warn!("VRF evaluation failed for slot {}: {}", slot, e);
                false
            }
        }
    } else {
        false
    };

    // Non-proposer: just schedule timeout
    let actions =
        bft_state
            .bft
            .on_new_round(false, None, None, None, validator_set);
    sign_and_collect_actions(bft_state, actions)
}

// ═══════════════════════════════════════════════════════════════
//  Message Handler
// ═══════════════════════════════════════════════════════════════

/// Process an incoming BFT message from P2P.
///
/// Routes to the appropriate BFT state machine handler and
/// checks for equivocation via the slash detector.
pub fn on_bft_message(
    bft_state: &mut BftConsensusState,
    msg: BftMessage,
    validator_set: &ValidatorSet,
) -> Vec<BftAction> {
    // Check for equivocation (passive detection)
    if let Some(evidence) = bft_state.slash_detector.check_message(&msg) {
        warn!(
            "Equivocation detected: validator {}",
            hex::encode(evidence.validator_id())
        );
        bft_state
            .pending_actions
            .push(BftAction::ReportEquivocation(evidence));
    }

    // Route to BFT state machine
    let actions = match msg {
        BftMessage::Proposal(proposal) => {
            // Verify VRF proof before accepting proposal
            let is_valid = verify_proposal_vrf(
                &proposal,
                validator_set,
                &bft_state.epoch_randomness.randomness,
            );
            bft_state
                .bft
                .on_proposal(proposal, is_valid, validator_set)
        }
        BftMessage::Prevote(vote) => {
            // Record participation
            bft_state
                .inactivity
                .record_participation(&vote.voter);
            bft_state.bft.on_prevote(vote, validator_set)
        }
        BftMessage::Precommit(vote) => {
            bft_state
                .inactivity
                .record_participation(&vote.voter);
            bft_state.bft.on_precommit(vote, validator_set)
        }
    };

    sign_and_collect_actions(bft_state, actions)
}

/// Process a BFT timeout event.
pub fn on_bft_timeout(
    bft_state: &mut BftConsensusState,
    slot: u64,
    round: u32,
    step: BftStep,
    validator_set: &ValidatorSet,
) -> Vec<BftAction> {
    let actions = bft_state.bft.on_timeout(slot, round, step, validator_set);
    sign_and_collect_actions(bft_state, actions)
}

// ═══════════════════════════════════════════════════════════════
//  Epoch Boundary Handler
// ═══════════════════════════════════════════════════════════════

/// Called at epoch boundary. Handles:
/// - Epoch randomness finalization (RANDAO)
/// - Inactivity leak / correlation penalty computation
/// - Delegation reward distribution
/// - Weak subjectivity checkpoint update
pub fn on_epoch_boundary(
    bft_state: &mut BftConsensusState,
    current_epoch: u64,
    finalized_this_epoch: bool,
    active_validator_count: u64,
    staking_registry: &mut StakingRegistry,
) {
    // 1. Finalize epoch randomness
    let new_randomness =
        EpochRandomness::accumulate(current_epoch, &bft_state.epoch_vrf_hashes);
    bft_state.epoch_randomness = new_randomness;
    bft_state.epoch_vrf_hashes.clear();
    info!(
        "Epoch {}: randomness updated (contributors={})",
        current_epoch,
        bft_state.epoch_randomness.contributor_count
    );

    // 2. Compute inactivity penalties
    let penalties = bft_state
        .inactivity
        .on_epoch_boundary(finalized_this_epoch, active_validator_count);

    if !penalties.inactivity_penalties.is_empty() {
        for penalty in &penalties.inactivity_penalties {
            info!(
                "Epoch {}: inactivity penalty for {} — {}bps (cumulative {}bps, non-finalizing {} epochs)",
                current_epoch,
                hex::encode(penalty.validator_id),
                penalty.penalty_bps,
                penalty.cumulative_bps,
                penalty.non_finalizing_epochs,
            );
            // Apply leak to staking registry
            if penalty.penalty_bps > 0 {
                let _ = staking_registry.slash(
                    &penalty.validator_id,
                    crate::staking::SlashSeverity::Custom(penalty.penalty_bps),
                    current_epoch,
                );
            }
        }
    }

    if !penalties.correlation_penalties.is_empty() {
        for penalty in &penalties.correlation_penalties {
            info!(
                "Epoch {}: correlation penalty for {} — {}bps multiplier ({}/{} slashed)",
                current_epoch,
                hex::encode(penalty.validator_id),
                penalty.multiplier_bps,
                penalty.slashed_count,
                penalty.total_validators,
            );
        }
    }

    // 3. Update weak subjectivity checkpoint
    if let Some(finalized) = bft_state.fork_choice.finalized_checkpoint_ref() {
        let ws_cp =
            crate::weak_subjectivity::WeakSubjectivityCheckpoint::from_finality_checkpoint(
                finalized,
            );
        bft_state.ws_guard.update_checkpoint(ws_cp);
    }
}

// ═══════════════════════════════════════════════════════════════
//  Commit Handler
// ═══════════════════════════════════════════════════════════════

/// Called when BFT commit is achieved.
/// Updates fork choice and creates finality checkpoint.
pub fn on_bft_commit(
    bft_state: &mut BftConsensusState,
    commit: &BftCommit,
) {
    info!(
        "BFT COMMIT: slot={} round={} block={} blue_score={}",
        commit.slot,
        commit.round,
        hex::encode(&commit.block_hash[..8]),
        commit.dag_checkpoint.blue_score,
    );

    // Update fork choice with new finality
    let finality_checkpoint =
        crate::economic_finality::FinalityCheckpoint {
            epoch: commit.slot / misaka_types::constants::EPOCH_LENGTH,
            block_hash: commit.block_hash,
            blue_score: commit.dag_checkpoint.blue_score,
            state_root: commit.dag_checkpoint.utxo_root,
            cumulative_txs: commit.dag_checkpoint.total_applied_txs,
        };

    bft_state
        .fork_choice
        .on_bft_finality(finality_checkpoint);

    // Purge slash detector cache below finalized slot
    bft_state.slash_detector.purge_below_slot(commit.slot);

    // GC old BFT round states
    bft_state.bft.gc_old_rounds(5);
}

// ═══════════════════════════════════════════════════════════════
//  Internal Helpers
// ═══════════════════════════════════════════════════════════════

/// Sign all outgoing BFT messages with the local validator key.
fn sign_and_collect_actions(
    bft_state: &mut BftConsensusState,
    actions: Vec<BftAction>,
) -> Vec<BftAction> {
    let sk = match &bft_state.local_secret_key {
        Some(sk) => sk,
        None => return actions, // Observer — no signing
    };

    let mut signed_actions = Vec::with_capacity(actions.len());

    for action in actions {
        let signed = match action {
            BftAction::BroadcastProposal(mut proposal) => {
                let signing_bytes = proposal.signing_bytes();
                match validator_sign(&signing_bytes, sk) {
                    Ok(sig) => {
                        proposal.signature = ValidatorSignature {
                            bytes: sig.to_bytes(),
                        };
                        BftAction::BroadcastProposal(proposal)
                    }
                    Err(e) => {
                        error!("Failed to sign proposal: {}", e);
                        continue;
                    }
                }
            }
            BftAction::BroadcastPrevote(mut vote) => {
                let signing_bytes = vote.prevote_signing_bytes();
                match validator_sign(&signing_bytes, sk) {
                    Ok(sig) => {
                        vote.signature = ValidatorSignature {
                            bytes: sig.to_bytes(),
                        };
                        BftAction::BroadcastPrevote(vote)
                    }
                    Err(e) => {
                        error!("Failed to sign prevote: {}", e);
                        continue;
                    }
                }
            }
            BftAction::BroadcastPrecommit(mut vote) => {
                let signing_bytes = vote.precommit_signing_bytes();
                match validator_sign(&signing_bytes, sk) {
                    Ok(sig) => {
                        vote.signature = ValidatorSignature {
                            bytes: sig.to_bytes(),
                        };
                        BftAction::BroadcastPrecommit(vote)
                    }
                    Err(e) => {
                        error!("Failed to sign precommit: {}", e);
                        continue;
                    }
                }
            }
            BftAction::Commit(commit) => {
                on_bft_commit(bft_state, &commit);
                BftAction::Commit(commit)
            }
            other => other,
        };
        signed_actions.push(signed);
    }

    // Drain any pending actions (equivocation evidence, etc.)
    signed_actions.append(&mut bft_state.pending_actions);
    signed_actions
}

/// Verify a proposal's VRF proof against the proposer's public key.
fn verify_proposal_vrf(
    proposal: &BftProposal,
    validator_set: &ValidatorSet,
    epoch_randomness: &Hash,
) -> bool {
    let vi = match validator_set.get(&proposal.proposer) {
        Some(vi) => vi,
        None => {
            warn!(
                "Unknown proposer: {}",
                hex::encode(proposal.proposer)
            );
            return false;
        }
    };

    let pk = match misaka_crypto::validator_sig::ValidatorPqPublicKey::from_bytes(
        &vi.public_key.bytes,
    ) {
        Ok(pk) => pk,
        Err(e) => {
            warn!("Invalid proposer public key: {}", e);
            return false;
        }
    };

    // Verify VRF proof
    let vrf_output = vrf_proposer::VrfOutput {
        proof: proposal.vrf_proof.proof.clone(),
        hash: proposal.vrf_proof.hash,
    };

    match vrf_proposer::vrf_verify(&pk, proposal.slot, epoch_randomness, &vrf_output) {
        Ok(()) => {
            // Verify that VRF maps to this proposer
            vrf_proposer::am_i_proposer(&proposal.proposer, validator_set, &vrf_output)
        }
        Err(e) => {
            warn!(
                "VRF verification failed for proposer {}: {}",
                hex::encode(proposal.proposer),
                e
            );
            false
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Effective Stake Computation (DPoS integration)
// ═══════════════════════════════════════════════════════════════

/// Compute effective validator set with delegated stake included.
///
/// This replaces the simple `ValidatorSet` with delegation-weighted stake.
pub fn compute_effective_validator_set(
    identities: &[ValidatorIdentity],
    delegation_registry: &DelegationRegistry,
    staking_registry: &StakingRegistry,
) -> ValidatorSet {
    let effective: Vec<ValidatorIdentity> = identities
        .iter()
        .map(|vi| {
            let self_stake = staking_registry
                .get(&vi.validator_id)
                .map(|a| a.stake_amount as u128)
                .unwrap_or(vi.stake_weight);
            let effective_stake =
                delegation_registry.effective_stake(&vi.validator_id, self_stake as u64);
            ValidatorIdentity {
                stake_weight: effective_stake,
                ..vi.clone()
            }
        })
        .collect();

    ValidatorSet::new(effective)
}

// ═══════════════════════════════════════════════════════════════
//  Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use misaka_crypto::validator_sig::generate_validator_keypair;
    use misaka_types::validator::ValidatorPublicKey;

    fn make_validator_and_state(
        n: usize,
    ) -> (Vec<ValidatorIdentity>, Vec<ValidatorKeypair>, ValidatorSet) {
        let mut vis = Vec::new();
        let mut kps = Vec::new();
        for i in 0..n {
            let kp = generate_validator_keypair();
            let mut vid = [0u8; 32];
            vid[0] = i as u8;
            vis.push(ValidatorIdentity {
                validator_id: vid,
                stake_weight: 100,
                public_key: ValidatorPublicKey {
                    bytes: kp.public_key.to_bytes(),
                },
                is_active: true,
            });
            kps.push(kp);
        }
        let vs = ValidatorSet::new(vis.clone());
        (vis, kps, vs)
    }

    #[test]
    fn test_bft_consensus_state_initialization() {
        let kp = generate_validator_keypair();
        let state = BftConsensusState::new_validator(
            [0x01; 20],
            kp.secret_key,
            [0xAA; 32],
            2,
        );
        assert!(state.is_validator());
        assert_eq!(state.current_slot, 0);
    }

    #[test]
    fn test_observer_state_cannot_produce() {
        let state = BftConsensusState::new_observer([0xBB; 32], 2);
        assert!(!state.is_validator());
    }

    #[test]
    fn test_on_new_slot_advances_slot() {
        let (vis, kps, vs) = make_validator_and_state(4);
        let mut state = BftConsensusState::new_validator(
            vis[0].validator_id,
            kps[0].secret_key.clone(),
            [0xAA; 32],
            2,
        );

        let _actions = on_new_slot(&mut state, &vs, None, None);
        assert_eq!(state.current_slot, 1);

        let _actions = on_new_slot(&mut state, &vs, None, None);
        assert_eq!(state.current_slot, 2);
    }

    #[test]
    fn test_slash_detector_integration() {
        let (vis, kps, vs) = make_validator_and_state(4);
        let mut state = BftConsensusState::new_validator(
            vis[0].validator_id,
            kps[0].secret_key.clone(),
            [0xAA; 32],
            2,
        );

        // Send two different prevotes from same validator for same (slot, round)
        let vote_a = BftVote {
            slot: 1,
            round: 0,
            voter: vis[1].validator_id,
            block_hash: Some([0xAA; 32]),
            signature: ValidatorSignature {
                bytes: vec![0; 3309],
            },
        };
        let vote_b = BftVote {
            slot: 1,
            round: 0,
            voter: vis[1].validator_id,
            block_hash: Some([0xBB; 32]),
            signature: ValidatorSignature {
                bytes: vec![0; 3309],
            },
        };

        state.bft.advance_slot(1);
        let _actions1 = on_bft_message(&mut state, BftMessage::Prevote(vote_a), &vs);
        let actions2 = on_bft_message(&mut state, BftMessage::Prevote(vote_b), &vs);

        let has_equivocation = actions2
            .iter()
            .any(|a| matches!(a, BftAction::ReportEquivocation(_)));
        assert!(
            has_equivocation,
            "Should detect double prevote equivocation"
        );
    }

    #[test]
    fn test_epoch_boundary_updates_randomness() {
        let kp = generate_validator_keypair();
        let mut state = BftConsensusState::new_validator(
            [0x01; 20],
            kp.secret_key,
            [0xAA; 32],
            2,
        );
        let mut registry =
            StakingRegistry::new(crate::staking::StakingConfig::testnet());

        let old_randomness = state.epoch_randomness.randomness;
        state.epoch_vrf_hashes.push([0xDD; 32]);

        on_epoch_boundary(&mut state, 1, true, 10, &mut registry);

        assert_ne!(
            state.epoch_randomness.randomness, old_randomness,
            "Epoch randomness should change after boundary"
        );
        assert!(state.epoch_vrf_hashes.is_empty(), "VRF hashes should be cleared");
    }

    #[test]
    fn test_effective_stake_with_delegation() {
        let (vis, _, _) = make_validator_and_state(2);
        let staking_config = crate::staking::StakingConfig::testnet();
        let staking_registry = StakingRegistry::new(staking_config);
        let mut delegation_registry = DelegationRegistry::testnet();

        // Delegate 5M to validator 0
        delegation_registry
            .delegate(
                [0x01; 32],
                [0xAA; 32],
                vis[0].validator_id,
                5_000_000,
                0,
            )
            .unwrap();

        let effective_vs =
            compute_effective_validator_set(&vis, &delegation_registry, &staking_registry);

        // Validator 0 should have higher effective stake
        let v0 = effective_vs.get(&vis[0].validator_id).unwrap();
        let v1 = effective_vs.get(&vis[1].validator_id).unwrap();
        assert!(
            v0.stake_weight > v1.stake_weight,
            "Delegated validator should have higher effective stake"
        );
    }
}
