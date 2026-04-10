//! On-Chain Governance — Proposal Registry + Stake-Weighted Voting.
//!
//! # Lifecycle
//!
//! ```text
//! ┌──────────┐  submit_proposal()  ┌───────────┐  voting period  ┌───────────┐
//! │ Proposed │ ──────────────────► │  Active   │ ───────────────► │ Tally     │
//! │ (draft)  │                     │ (voting)  │                  │           │
//! └──────────┘                     └───────────┘                  └─────┬─────┘
//!                                                                      │
//!                                                     ┌────────────────┼──────────────┐
//!                                                     ▼                ▼              ▼
//!                                              ┌───────────┐   ┌───────────┐   ┌──────────┐
//!                                              │  Passed   │   │ Rejected  │   │ Expired  │
//!                                              │           │   │(no quorum)│   │(no votes)│
//!                                              └─────┬─────┘   └───────────┘   └──────────┘
//!                                                    │ timelock
//!                                                    ▼
//!                                              ┌───────────┐
//!                                              │ Executed  │
//!                                              └───────────┘
//! ```
//!
//! # Voting Power
//!
//! Voting power = bonded stake in the StakingRegistry at the proposal's
//! snapshot epoch. This prevents stake manipulation during voting.
//!
//! # Parameters (consensus-critical)
//!
//! All parameters are in the `GovernanceParams` struct. Changing them
//! requires a protocol upgrade (hard fork).

use misaka_types::Address;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
//  Parameters
// ═══════════════════════════════════════════════════════════════

/// Governance parameters (consensus-critical).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceParams {
    /// Minimum stake required to submit a proposal (base units).
    pub min_proposer_stake: u64,
    /// Voting period in epochs (blocks).
    pub voting_period_epochs: u64,
    /// Timelock after passing before execution (epochs).
    pub execution_timelock_epochs: u64,
    /// Quorum: minimum fraction of total voting power that must participate (BPS).
    /// 3000 = 30%.
    pub quorum_bps: u64,
    /// Approval threshold: minimum fraction of participating votes that must be Yes (BPS).
    /// 5001 = >50% (simple majority).
    pub approval_threshold_bps: u64,
    /// Maximum active proposals at any time.
    pub max_active_proposals: usize,
    /// Maximum title length (bytes).
    pub max_title_len: usize,
    /// Maximum description length (bytes).
    pub max_description_len: usize,
}

impl Default for GovernanceParams {
    fn default() -> Self {
        Self {
            min_proposer_stake: 100_000_000_000, // 100K MISAKA
            voting_period_epochs: 10_080,        // ~7 days at 60s blocks
            execution_timelock_epochs: 1_440,    // ~1 day
            quorum_bps: 3000,                    // 30%
            approval_threshold_bps: 5001,        // >50%
            max_active_proposals: 10,
            max_title_len: 256,
            max_description_len: 4096,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
//  Types
// ═══════════════════════════════════════════════════════════════

/// Unique proposal identifier (SHA3-256 of proposal content).
pub type ProposalId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    /// Voting is open.
    Active,
    /// Voting period ended, quorum met, majority Yes.
    Passed,
    /// Voting period ended, quorum not met or majority No.
    Rejected,
    /// Voting period ended, no votes cast.
    Expired,
    /// Passed + timelock elapsed + execution confirmed.
    Executed,
    /// Cancelled by proposer before voting ends.
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteChoice {
    Yes,
    No,
    Abstain,
}

/// What the proposal changes if passed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalAction {
    /// Change a consensus parameter (identified by name + new value).
    ParameterChange {
        param_name: String,
        new_value: String,
    },
    /// Schedule a feature activation at a specific height.
    FeatureActivation {
        feature_name: String,
        activation_height: u64,
    },
    /// Transfer treasury funds to an address.
    TreasurySpend {
        recipient: Address,
        amount: u64,
        memo: String,
    },
    /// Free-text signal vote (no automatic execution).
    Signal { text: String },
}

/// A single vote cast by a validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    pub voter: Address,
    pub choice: VoteChoice,
    /// Voting power at snapshot epoch (= bonded stake).
    pub power: u64,
    /// Epoch at which the vote was cast.
    pub cast_at_epoch: u64,
}

/// On-chain governance proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub id: ProposalId,
    pub proposer: Address,
    pub title: String,
    pub description: String,
    pub action: ProposalAction,
    pub status: ProposalStatus,
    /// Epoch at which the proposal was submitted.
    pub submitted_at: u64,
    /// Epoch at which voting starts (= submitted_at).
    pub voting_start: u64,
    /// Epoch at which voting ends.
    pub voting_end: u64,
    /// Snapshot of total voting power at submission time.
    pub total_power_snapshot: u64,
    /// SEC-FIX NH-4/NH-5: Per-voter stake snapshot taken at proposal submission.
    /// Used to cap individual voting power and derived from the staking state.
    pub stake_snapshot: HashMap<Address, u64>,
    /// All votes cast.
    pub votes: HashMap<Address, Vote>,
}

impl Proposal {
    /// Compute proposal ID from content.
    /// SEC-FIX TM-12: Includes action hash to prevent collision between
    /// proposals with the same title but different actions.
    pub fn compute_id(
        proposer: &Address,
        title: &str,
        submitted_at: u64,
        action: &ProposalAction,
    ) -> ProposalId {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA:governance:proposal_id:v2:");
        h.update(proposer);
        h.update(title.as_bytes());
        h.update(submitted_at.to_le_bytes());
        let action_bytes = serde_json::to_vec(action).unwrap_or_default();
        h.update(&action_bytes);
        h.finalize().into()
    }

    /// Tally votes: returns (yes_power, no_power, abstain_power).
    pub fn tally(&self) -> (u64, u64, u64) {
        let (mut y, mut n, mut a) = (0u64, 0u64, 0u64);
        for vote in self.votes.values() {
            match vote.choice {
                VoteChoice::Yes => y = y.saturating_add(vote.power),
                VoteChoice::No => n = n.saturating_add(vote.power),
                VoteChoice::Abstain => a = a.saturating_add(vote.power),
            }
        }
        (y, n, a)
    }

    /// Evaluate the proposal after the voting period ends.
    pub fn evaluate(&mut self, params: &GovernanceParams) {
        if self.status != ProposalStatus::Active {
            return;
        }

        let (yes, no, abstain) = self.tally();
        let total_participated = yes.saturating_add(no).saturating_add(abstain);

        // No votes at all → Expired
        if total_participated == 0 {
            self.status = ProposalStatus::Expired;
            return;
        }

        // Quorum check (yes + no only; abstain counts for participation but not quorum)
        // SEC-FIX M-21: Use u128 intermediate to prevent u64 overflow
        let quorum_required =
            ((self.total_power_snapshot as u128) * (params.quorum_bps as u128) / 10_000) as u64;
        let yes_plus_no = yes.saturating_add(no);
        if yes_plus_no < quorum_required {
            self.status = ProposalStatus::Rejected;
            return;
        }

        // Approval threshold (of yes+no votes, not total)
        // SEC-FIX M-21: Use u128 intermediate to prevent u64 overflow
        let approval_required =
            ((yes_plus_no as u128) * (params.approval_threshold_bps as u128) / 10_000) as u64;
        if yes >= approval_required {
            self.status = ProposalStatus::Passed;
        } else {
            self.status = ProposalStatus::Rejected;
        }
    }

    /// Whether the timelock has elapsed and the proposal can be executed.
    pub fn can_execute(&self, current_epoch: u64, params: &GovernanceParams) -> bool {
        self.status == ProposalStatus::Passed
            && current_epoch >= self.voting_end + params.execution_timelock_epochs
    }
}

// ═══════════════════════════════════════════════════════════════
//  Governance Registry
// ═══════════════════════════════════════════════════════════════

/// On-chain governance state — tracks all proposals.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GovernanceRegistry {
    /// All proposals indexed by ID.
    proposals: HashMap<ProposalId, Proposal>,
    /// Next proposal sequence number (for ordering).
    next_seq: u64,
}

/// Governance errors.
#[derive(Debug, thiserror::Error)]
pub enum GovernanceError {
    #[error("proposer stake {actual} below minimum {required}")]
    InsufficientStake { actual: u64, required: u64 },
    #[error("too many active proposals ({count} >= {max})")]
    TooManyActiveProposals { count: usize, max: usize },
    #[error("title too long ({len} > {max})")]
    TitleTooLong { len: usize, max: usize },
    #[error("description too long ({len} > {max})")]
    DescriptionTooLong { len: usize, max: usize },
    #[error("proposal not found: {0}")]
    ProposalNotFound(String),
    #[error("voting period has ended")]
    VotingEnded,
    #[error("voting period has not ended yet")]
    VotingNotEnded,
    #[error("already voted")]
    AlreadyVoted,
    #[error("voter has no voting power")]
    NoVotingPower,
    #[error("proposal is not in Active status")]
    NotActive,
    #[error("proposal cannot be executed yet")]
    CannotExecute,
    #[error("duplicate proposal ID")]
    DuplicateProposal,
}

impl GovernanceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn active_count(&self) -> usize {
        self.proposals
            .values()
            .filter(|p| p.status == ProposalStatus::Active)
            .count()
    }

    pub fn get(&self, id: &ProposalId) -> Option<&Proposal> {
        self.proposals.get(id)
    }

    /// Submit a new proposal.
    ///
    /// SEC-FIX NH-4: `validator_stakes` is the authoritative stake snapshot
    /// taken from the staking registry at proposal submission time. The
    /// `total_power_snapshot` is derived internally (not caller-supplied)
    /// to prevent quorum manipulation.
    pub fn submit_proposal(
        &mut self,
        proposer: Address,
        title: String,
        description: String,
        action: ProposalAction,
        proposer_stake: u64,
        current_epoch: u64,
        validator_stakes: &HashMap<Address, u64>,
        params: &GovernanceParams,
    ) -> Result<ProposalId, GovernanceError> {
        // Validation
        if proposer_stake < params.min_proposer_stake {
            return Err(GovernanceError::InsufficientStake {
                actual: proposer_stake,
                required: params.min_proposer_stake,
            });
        }
        if self.active_count() >= params.max_active_proposals {
            return Err(GovernanceError::TooManyActiveProposals {
                count: self.active_count(),
                max: params.max_active_proposals,
            });
        }
        if title.len() > params.max_title_len {
            return Err(GovernanceError::TitleTooLong {
                len: title.len(),
                max: params.max_title_len,
            });
        }
        if description.len() > params.max_description_len {
            return Err(GovernanceError::DescriptionTooLong {
                len: description.len(),
                max: params.max_description_len,
            });
        }

        let id = Proposal::compute_id(&proposer, &title, current_epoch, &action);
        if self.proposals.contains_key(&id) {
            return Err(GovernanceError::DuplicateProposal);
        }

        // SEC-FIX NH-4: Derive total_power from the actual stake snapshot
        let total_voting_power: u64 = validator_stakes
            .values()
            .fold(0u64, |acc, s| acc.saturating_add(*s));

        let proposal = Proposal {
            id,
            proposer,
            title,
            description,
            action,
            status: ProposalStatus::Active,
            submitted_at: current_epoch,
            voting_start: current_epoch,
            voting_end: current_epoch + params.voting_period_epochs,
            total_power_snapshot: total_voting_power,
            stake_snapshot: validator_stakes.clone(),
            votes: HashMap::new(),
        };

        self.proposals.insert(id, proposal);
        self.next_seq += 1;
        Ok(id)
    }

    /// Cast a vote on an active proposal.
    pub fn cast_vote(
        &mut self,
        proposal_id: &ProposalId,
        voter: Address,
        choice: VoteChoice,
        voting_power: u64,
        current_epoch: u64,
    ) -> Result<(), GovernanceError> {
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| GovernanceError::ProposalNotFound(hex::encode(proposal_id)))?;

        if proposal.status != ProposalStatus::Active {
            return Err(GovernanceError::NotActive);
        }
        if current_epoch > proposal.voting_end {
            return Err(GovernanceError::VotingEnded);
        }
        if proposal.votes.contains_key(&voter) {
            return Err(GovernanceError::AlreadyVoted);
        }
        if voting_power == 0 {
            return Err(GovernanceError::NoVotingPower);
        }

        // SEC-FIX NH-5: Cap voting power at the voter's individual stake
        // from the proposal's stake snapshot. Falls back to 0 if the voter
        // had no stake at the time of proposal submission.
        let snapshot_stake = proposal.stake_snapshot.get(&voter).copied().unwrap_or(0);
        if snapshot_stake == 0 {
            return Err(GovernanceError::NoVotingPower);
        }
        let capped_power = voting_power.min(snapshot_stake);

        proposal.votes.insert(
            voter,
            Vote {
                voter,
                choice,
                power: capped_power,
                cast_at_epoch: current_epoch,
            },
        );
        Ok(())
    }

    /// Finalize proposals whose voting period has ended.
    /// Called once per epoch by the block producer.
    pub fn finalize_expired(&mut self, current_epoch: u64, params: &GovernanceParams) {
        let ids: Vec<ProposalId> = self
            .proposals
            .iter()
            .filter(|(_, p)| p.status == ProposalStatus::Active && current_epoch > p.voting_end)
            .map(|(id, _)| *id)
            .collect();

        for id in ids {
            if let Some(proposal) = self.proposals.get_mut(&id) {
                proposal.evaluate(params);
            }
        }

        // SEC-FIX NM-16 + TM-11: Prune terminal AND stale Passed proposals.
        // Passed proposals that have not been executed within retention_epochs
        // are also pruned to prevent unbounded growth.
        let retention_epochs = params.voting_period_epochs * 2 + params.execution_timelock_epochs;
        self.proposals.retain(|_, p| match p.status {
            ProposalStatus::Active => true,
            ProposalStatus::Passed => {
                current_epoch.saturating_sub(p.voting_end) <= retention_epochs
            }
            _ => current_epoch.saturating_sub(p.voting_end) <= retention_epochs,
        });
    }

    /// Mark a passed proposal as executed.
    pub fn mark_executed(
        &mut self,
        proposal_id: &ProposalId,
        current_epoch: u64,
        params: &GovernanceParams,
    ) -> Result<&ProposalAction, GovernanceError> {
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| GovernanceError::ProposalNotFound(hex::encode(proposal_id)))?;

        if !proposal.can_execute(current_epoch, params) {
            return Err(GovernanceError::CannotExecute);
        }

        proposal.status = ProposalStatus::Executed;
        Ok(&proposal.action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_params() -> GovernanceParams {
        GovernanceParams {
            min_proposer_stake: 100,
            voting_period_epochs: 10,
            execution_timelock_epochs: 5,
            quorum_bps: 3000,
            approval_threshold_bps: 5001,
            max_active_proposals: 3,
            max_title_len: 256,
            max_description_len: 4096,
        }
    }

    fn test_stakes() -> HashMap<Address, u64> {
        let mut m = HashMap::new();
        m.insert([1; 32], 600);
        m.insert([2; 32], 400);
        m
    }

    #[test]
    fn test_submit_and_vote_pass() {
        let params = default_params();
        let mut gov = GovernanceRegistry::new();
        let stakes = test_stakes();

        let id = gov
            .submit_proposal(
                [1; 32],
                "Test Proposal".into(),
                "Description".into(),
                ProposalAction::Signal {
                    text: "test".into(),
                },
                1000,
                100,
                &stakes,
                &params,
            )
            .unwrap();

        // 60% Yes, 10% No → passes (quorum=30%, threshold=50%)
        gov.cast_vote(&id, [1; 32], VoteChoice::Yes, 600, 105)
            .unwrap();
        gov.cast_vote(&id, [2; 32], VoteChoice::No, 100, 105)
            .unwrap();

        gov.finalize_expired(111, &params); // epoch > voting_end (100+10)
        assert_eq!(gov.get(&id).unwrap().status, ProposalStatus::Passed);
    }

    #[test]
    fn test_quorum_not_met() {
        let params = default_params();
        let mut gov = GovernanceRegistry::new();
        let stakes = test_stakes();

        let id = gov
            .submit_proposal(
                [1; 32],
                "Low Turnout".into(),
                "".into(),
                ProposalAction::Signal { text: "".into() },
                1000,
                0,
                &stakes,
                &params,
            )
            .unwrap();

        // Only 20% voted → quorum not met
        gov.cast_vote(&id, [1; 32], VoteChoice::Yes, 200, 5)
            .unwrap();

        gov.finalize_expired(11, &params);
        assert_eq!(gov.get(&id).unwrap().status, ProposalStatus::Rejected);
    }

    #[test]
    fn test_no_votes_expired() {
        let params = default_params();
        let mut gov = GovernanceRegistry::new();
        let stakes = test_stakes();

        let id = gov
            .submit_proposal(
                [1; 32],
                "Ghost Proposal".into(),
                "".into(),
                ProposalAction::Signal { text: "".into() },
                1000,
                0,
                &stakes,
                &params,
            )
            .unwrap();

        gov.finalize_expired(11, &params);
        assert_eq!(gov.get(&id).unwrap().status, ProposalStatus::Expired);
    }

    #[test]
    fn test_execution_timelock() {
        let params = default_params();
        let mut gov = GovernanceRegistry::new();
        let stakes = test_stakes();

        let id = gov
            .submit_proposal(
                [1; 32],
                "Execute Me".into(),
                "".into(),
                ProposalAction::Signal { text: "".into() },
                1000,
                0,
                &stakes,
                &params,
            )
            .unwrap();

        gov.cast_vote(&id, [1; 32], VoteChoice::Yes, 500, 5)
            .unwrap();
        gov.finalize_expired(11, &params);
        assert_eq!(gov.get(&id).unwrap().status, ProposalStatus::Passed);

        // Cannot execute before timelock
        assert!(gov.mark_executed(&id, 14, &params).is_err());

        // Can execute after timelock (voting_end=10, timelock=5 → epoch 15)
        let action = gov.mark_executed(&id, 15, &params).unwrap();
        assert!(matches!(action, ProposalAction::Signal { .. }));
        assert_eq!(gov.get(&id).unwrap().status, ProposalStatus::Executed);
    }

    #[test]
    fn test_duplicate_vote_rejected() {
        let params = default_params();
        let mut gov = GovernanceRegistry::new();
        let stakes = test_stakes();

        let id = gov
            .submit_proposal(
                [1; 32],
                "Dup Vote".into(),
                "".into(),
                ProposalAction::Signal { text: "".into() },
                1000,
                0,
                &stakes,
                &params,
            )
            .unwrap();

        gov.cast_vote(&id, [1; 32], VoteChoice::Yes, 500, 3)
            .unwrap();
        assert!(gov.cast_vote(&id, [1; 32], VoteChoice::No, 500, 4).is_err());
    }

    #[test]
    fn test_max_active_proposals() {
        let params = default_params(); // max=3
        let mut gov = GovernanceRegistry::new();
        let stakes = test_stakes();

        for i in 0..3u8 {
            gov.submit_proposal(
                [i; 32],
                format!("Proposal {}", i),
                "".into(),
                ProposalAction::Signal { text: "".into() },
                1000,
                i as u64,
                &stakes,
                &params,
            )
            .unwrap();
        }

        // 4th should fail
        let result = gov.submit_proposal(
            [3; 32],
            "Overflow".into(),
            "".into(),
            ProposalAction::Signal { text: "".into() },
            1000,
            3,
            &stakes,
            &params,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_nh5_voter_power_capped_at_individual_stake() {
        let params = default_params();
        let mut gov = GovernanceRegistry::new();
        let stakes = test_stakes(); // [1;32] → 600, [2;32] → 400

        let id = gov
            .submit_proposal(
                [1; 32],
                "NH5 Test".into(),
                "".into(),
                ProposalAction::Signal { text: "".into() },
                1000,
                0,
                &stakes,
                &params,
            )
            .unwrap();

        // Voter [2;32] tries to vote with 9999 power but should be capped to 400
        gov.cast_vote(&id, [2; 32], VoteChoice::Yes, 9999, 3)
            .unwrap();
        let vote = gov.get(&id).unwrap().votes.get(&[2; 32]).unwrap();
        assert_eq!(
            vote.power, 400,
            "voting power should be capped at snapshot stake"
        );
    }
}
