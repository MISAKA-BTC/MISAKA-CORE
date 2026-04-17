// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 MISAKA Foundation

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::aggregator::QuorumAggregator;
use crate::client::AuthorityClient;
use crate::committee::{AuthorityIndex, SimpleStakeCommittee, StakeCommittee, StakeWeight};
use crate::error::{AuthorityError, QuorumError};
use crate::policy::AggregationPolicy;
use crate::reducer::{QuorumReducer, ReduceAction};

// ── Test helpers ────────────────────────────────────────────────

/// Per-authority behavior for MockClient.
#[derive(Clone)]
enum MockBehavior {
    /// Respond OK after optional delay.
    Ok { delay: Duration, value: u64 },
    /// Time out (never respond within timeout).
    Timeout,
    /// Return an error immediately.
    Reject,
}

/// Mock client configurable per-authority.
struct MockClient {
    behaviors: HashMap<AuthorityIndex, MockBehavior>,
}

impl MockClient {
    fn new(behaviors: HashMap<AuthorityIndex, MockBehavior>) -> Self {
        Self { behaviors }
    }
}

#[async_trait::async_trait]
impl AuthorityClient<(), u64> for MockClient {
    async fn request(
        &self,
        authority_index: AuthorityIndex,
        _req: (),
    ) -> Result<u64, AuthorityError> {
        let behavior = self
            .behaviors
            .get(&authority_index)
            .cloned()
            .unwrap_or(MockBehavior::Timeout);

        match behavior {
            MockBehavior::Ok { delay, value } => {
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                Ok(value)
            }
            MockBehavior::Timeout => {
                // Sleep longer than any reasonable timeout
                tokio::time::sleep(Duration::from_secs(600)).await;
                unreachable!()
            }
            MockBehavior::Reject => Err(AuthorityError::Rejected {
                authority: authority_index,
                reason: "byzantine".to_string(),
            }),
        }
    }
}

/// Simple reducer: accumulates responses, returns EarlyReturn when
/// accumulated stake reaches the threshold.
struct SimpleReducer {
    threshold: StakeWeight,
    accumulated_stake: StakeWeight,
    responses: Vec<(AuthorityIndex, u64)>,
    rejected_stake: StakeWeight,
}

impl SimpleReducer {
    fn new(threshold: StakeWeight) -> Self {
        Self {
            threshold,
            accumulated_stake: 0,
            responses: Vec::new(),
            rejected_stake: 0,
        }
    }
}

impl QuorumReducer<u64, Vec<(AuthorityIndex, u64)>> for SimpleReducer {
    fn reduce(
        &mut self,
        authority: AuthorityIndex,
        stake: StakeWeight,
        response: u64,
    ) -> ReduceAction<Vec<(AuthorityIndex, u64)>> {
        self.responses.push((authority, response));
        self.accumulated_stake = self.accumulated_stake.saturating_add(stake);

        if self.accumulated_stake >= self.threshold {
            ReduceAction::EarlyReturn(self.responses.clone())
        } else {
            ReduceAction::Continue
        }
    }

    fn finalize(self) -> Option<Vec<(AuthorityIndex, u64)>> {
        if self.responses.is_empty() {
            None
        } else {
            Some(self.responses)
        }
    }
}

/// Reducer that rejects responses from specific authorities.
struct RejectingReducer {
    reject_set: std::collections::HashSet<AuthorityIndex>,
    threshold: StakeWeight,
    accumulated_stake: StakeWeight,
    responses: Vec<(AuthorityIndex, u64)>,
}

impl RejectingReducer {
    fn new(reject_set: std::collections::HashSet<AuthorityIndex>, threshold: StakeWeight) -> Self {
        Self {
            reject_set,
            threshold,
            accumulated_stake: 0,
            responses: Vec::new(),
        }
    }
}

impl QuorumReducer<u64, Vec<(AuthorityIndex, u64)>> for RejectingReducer {
    fn reduce(
        &mut self,
        authority: AuthorityIndex,
        stake: StakeWeight,
        response: u64,
    ) -> ReduceAction<Vec<(AuthorityIndex, u64)>> {
        if self.reject_set.contains(&authority) {
            return ReduceAction::Reject;
        }
        self.responses.push((authority, response));
        self.accumulated_stake = self.accumulated_stake.saturating_add(stake);
        if self.accumulated_stake >= self.threshold {
            ReduceAction::EarlyReturn(self.responses.clone())
        } else {
            ReduceAction::Continue
        }
    }

    fn finalize(self) -> Option<Vec<(AuthorityIndex, u64)>> {
        if self.responses.is_empty() {
            None
        } else {
            Some(self.responses)
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────

/// (a) 21 authorities, 14 OK + 7 timeout. Quorum = 15. 14 < 15 → no EarlyReturn.
/// finalize() returns the partial set.
#[tokio::test]
async fn test_14_ok_7_timeout() {
    let committee = SimpleStakeCommittee::uniform(21, 1);
    // Q = 21 - floor(20/3) = 21 - 6 = 15

    let mut behaviors = HashMap::new();
    for i in 0..14u32 {
        behaviors.insert(
            i,
            MockBehavior::Ok {
                delay: Duration::ZERO,
                value: i as u64,
            },
        );
    }
    for i in 14..21u32 {
        behaviors.insert(i, MockBehavior::Timeout);
    }

    let client = Arc::new(MockClient::new(behaviors));
    let reducer = SimpleReducer::new(15);
    let policy = AggregationPolicy {
        per_authority_timeout: Duration::from_millis(100),
        total_timeout: Duration::from_secs(5),
        ..Default::default()
    };

    let result = QuorumAggregator::aggregate(&committee, client, (), reducer, &policy).await;

    // 14 ok + 7 timeout → accumulated=14 < threshold=15 → QuorumImpossible
    match result {
        Err(QuorumError::QuorumImpossible {
            accumulated_stake,
            threshold,
            ..
        }) => {
            assert_eq!(accumulated_stake, 14);
            assert_eq!(threshold, 15);
        }
        other => panic!("expected QuorumImpossible, got: {other:?}"),
    }
}

/// (b) 21 authorities, 7 byzantine (reducer rejects) + 14 OK.
/// 14 ok_stake < Q(15) → QuorumImpossible when remaining runs out.
#[tokio::test]
async fn test_7_byzantine_reject() {
    let committee = SimpleStakeCommittee::uniform(21, 1);
    let mut behaviors = HashMap::new();
    for i in 0..21u32 {
        behaviors.insert(
            i,
            MockBehavior::Ok {
                delay: Duration::ZERO,
                value: i as u64,
            },
        );
    }

    let client = Arc::new(MockClient::new(behaviors));
    let reject_set: std::collections::HashSet<AuthorityIndex> = (0..7).collect();
    let reducer = RejectingReducer::new(reject_set, 15);
    let policy = AggregationPolicy {
        per_authority_timeout: Duration::from_secs(1),
        total_timeout: Duration::from_secs(5),
        ..Default::default()
    };

    let result = QuorumAggregator::aggregate(&committee, client, (), reducer, &policy).await;

    // 7 rejected + 14 ok → max possible accumulated = 14 < Q(15) → QuorumImpossible
    // The check fires as soon as it's determined that quorum is unreachable,
    // which may be before all responses arrive (early abort).
    match result {
        Err(QuorumError::QuorumImpossible { threshold, .. }) => {
            assert_eq!(
                threshold, 15,
                "threshold should be 15 (quorum for 21 uniform)"
            );
        }
        other => panic!("expected QuorumImpossible, got: {other:?}"),
    }
}

/// (c) 21 authorities, 6 byzantine + 14 OK + 1 timeout.
/// After 14 OK + 6 rejects arrive: accumulated=14, remaining=1.
/// 14+1=15 >= threshold, so NOT impossible yet. Then timeout → impossible.
#[tokio::test]
async fn test_6_byzantine_14_ok_1_timeout() {
    let committee = SimpleStakeCommittee::uniform(21, 1);
    let mut behaviors = HashMap::new();
    for i in 0..6u32 {
        behaviors.insert(
            i,
            MockBehavior::Ok {
                delay: Duration::ZERO,
                value: i as u64,
            },
        );
    }
    for i in 6..20u32 {
        behaviors.insert(
            i,
            MockBehavior::Ok {
                delay: Duration::ZERO,
                value: i as u64,
            },
        );
    }
    // Authority 20 times out
    behaviors.insert(20, MockBehavior::Timeout);

    let client = Arc::new(MockClient::new(behaviors));
    let reject_set: std::collections::HashSet<AuthorityIndex> = (0..6).collect();
    let reducer = RejectingReducer::new(reject_set, 15);
    let policy = AggregationPolicy {
        per_authority_timeout: Duration::from_millis(100),
        total_timeout: Duration::from_secs(5),
        ..Default::default()
    };

    let result = QuorumAggregator::aggregate(&committee, client, (), reducer, &policy).await;

    // After all fast responses: 6 rejected + 14 ok + 1 timeout
    // accumulated=14, remaining=0 after timeout → QuorumImpossible
    match result {
        Err(QuorumError::QuorumImpossible {
            accumulated_stake, ..
        }) => {
            assert_eq!(accumulated_stake, 14);
        }
        other => panic!("expected QuorumImpossible, got: {other:?}"),
    }
}

/// (d) 4 authorities, Q=3. First 3 respond immediately → EarlyReturn.
/// 4th is slow (1s delay). Verify early return before 4th arrives.
#[tokio::test]
async fn test_early_return_drops_pending() {
    let committee = SimpleStakeCommittee::uniform(4, 1);
    // Q = 4 - floor(3/3) = 4 - 1 = 3

    let mut behaviors = HashMap::new();
    for i in 0..3u32 {
        behaviors.insert(
            i,
            MockBehavior::Ok {
                delay: Duration::ZERO,
                value: i as u64,
            },
        );
    }
    behaviors.insert(
        3,
        MockBehavior::Ok {
            delay: Duration::from_secs(10),
            value: 3,
        },
    );

    let client = Arc::new(MockClient::new(behaviors));
    let reducer = SimpleReducer::new(3);
    let policy = AggregationPolicy {
        per_authority_timeout: Duration::from_secs(30),
        total_timeout: Duration::from_secs(30),
        ..Default::default()
    };

    let start = std::time::Instant::now();
    let result = QuorumAggregator::aggregate(&committee, client, (), reducer, &policy).await;
    let elapsed = start.elapsed();

    // Should complete in well under 1 second (4th authority has 10s delay)
    assert!(
        elapsed < Duration::from_secs(2),
        "early return should be fast, took {elapsed:?}"
    );

    let result = result.expect("should succeed with EarlyReturn");
    assert!(
        result.output.is_some(),
        "should have output from EarlyReturn"
    );
    assert_eq!(result.success_count, 3);
}

/// (e) Skewed stake: [40, 20, 20, 10, 10]. Total=100, f=33, Q=67.
/// Authorities 0 (40) and 1 (20) respond → 60 < 67 → need one more.
/// Authority 2 (20) responds → 80 ≥ 67 → EarlyReturn.
#[tokio::test]
async fn test_skewed_stake() {
    let committee = SimpleStakeCommittee::new(vec![40, 20, 20, 10, 10]);
    // total=100, f=33, Q=67

    assert_eq!(committee.quorum_threshold(), 67);
    assert_eq!(committee.fault_tolerance(), 33);

    let mut behaviors = HashMap::new();
    // All respond OK, authority 3 and 4 are slow
    behaviors.insert(
        0,
        MockBehavior::Ok {
            delay: Duration::ZERO,
            value: 40,
        },
    );
    behaviors.insert(
        1,
        MockBehavior::Ok {
            delay: Duration::from_millis(10),
            value: 20,
        },
    );
    behaviors.insert(
        2,
        MockBehavior::Ok {
            delay: Duration::from_millis(20),
            value: 20,
        },
    );
    behaviors.insert(
        3,
        MockBehavior::Ok {
            delay: Duration::from_secs(10),
            value: 10,
        },
    );
    behaviors.insert(
        4,
        MockBehavior::Ok {
            delay: Duration::from_secs(10),
            value: 10,
        },
    );

    let client = Arc::new(MockClient::new(behaviors));
    let reducer = SimpleReducer::new(67);
    let policy = AggregationPolicy::default();

    let result = QuorumAggregator::aggregate(&committee, client, (), reducer, &policy)
        .await
        .expect("should succeed");

    assert!(result.output.is_some());
    // Should only need 3 responses (40+20+20=80 >= 67)
    assert!(
        result.success_count <= 3,
        "should reach quorum with <=3 responses, got {}",
        result.success_count
    );
}

/// (f) 7 authorities, all slow (10s delay), total_timeout=100ms.
/// Should return TotalTimeout quickly.
#[tokio::test]
async fn test_total_timeout_partial() {
    let committee = SimpleStakeCommittee::uniform(7, 1);

    let mut behaviors = HashMap::new();
    for i in 0..7u32 {
        behaviors.insert(
            i,
            MockBehavior::Ok {
                delay: Duration::from_secs(10),
                value: i as u64,
            },
        );
    }

    let client = Arc::new(MockClient::new(behaviors));
    let reducer = SimpleReducer::new(5);
    let policy = AggregationPolicy {
        per_authority_timeout: Duration::from_secs(30),
        total_timeout: Duration::from_millis(100),
        ..Default::default()
    };

    let start = std::time::Instant::now();
    let result = QuorumAggregator::aggregate(&committee, client, (), reducer, &policy).await;
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(1),
        "should timeout quickly, took {elapsed:?}"
    );
    match result {
        Err(QuorumError::TotalTimeout {
            responses_received, ..
        }) => {
            assert_eq!(responses_received, 0, "no responses should have arrived");
        }
        other => panic!("expected TotalTimeout, got: {other:?}"),
    }
}
