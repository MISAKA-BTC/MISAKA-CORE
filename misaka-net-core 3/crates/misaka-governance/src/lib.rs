//! Governance (Spec 11 + 12): Proposals, voting, evaluation.
use std::collections::HashMap;
use misaka_types::Address;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalStatus { Active, Passed, Rejected, Executed }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteChoice { Yes, No, Abstain }

#[derive(Debug, Clone)]
pub struct Proposal {
    pub id: u64,
    pub proposer: Address,
    pub title: String,
    pub description: String,
    pub status: ProposalStatus,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub votes: HashMap<Address, (VoteChoice, u64)>,
}

impl Proposal {
    pub fn tally(&self) -> (u64, u64, u64) {
        let (mut y, mut n, mut a) = (0u64, 0u64, 0u64);
        for (_, (choice, power)) in &self.votes {
            match choice {
                VoteChoice::Yes => y += power,
                VoteChoice::No => n += power,
                VoteChoice::Abstain => a += power,
            }
        }
        (y, n, a)
    }

    pub fn evaluate(&mut self, quorum_bps: u64, total_power: u64) {
        let (y, n, _) = self.tally();
        let total_voted = y + n;
        let quorum = total_power * quorum_bps / 10000;
        if total_voted < quorum {
            self.status = ProposalStatus::Rejected;
        } else if y > n {
            self.status = ProposalStatus::Passed;
        } else {
            self.status = ProposalStatus::Rejected;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_proposal_pass() {
        let mut p = Proposal {
            id: 1, proposer: [0; 20], title: "Test".into(), description: "".into(),
            status: ProposalStatus::Active, start_epoch: 0, end_epoch: 100,
            votes: HashMap::new(),
        };
        p.votes.insert([1; 20], (VoteChoice::Yes, 300));
        p.votes.insert([2; 20], (VoteChoice::No, 100));
        p.evaluate(3000, 1000); // 30% quorum
        assert_eq!(p.status, ProposalStatus::Passed);
    }
}
