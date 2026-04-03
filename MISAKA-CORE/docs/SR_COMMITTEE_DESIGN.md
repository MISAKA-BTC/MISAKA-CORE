# MISAKA SR Committee Design — SR15 → SR21 Expansion Path

## Why Mainnet Starts with SR15

- Early mainnet has lower market cap and fewer high-quality node operators
- A smaller, higher-quality committee is safer than a larger weak committee
- Stability matters more than headline decentralization at launch
- The system scales committee size only when operator quality justifies it

## Committee Policy Parameters

All thresholds derive from `CommitteePolicy` (single source of truth):

| Parameter | SR15 | SR18 | SR21 | Formula |
|-----------|------|------|------|---------|
| committee_size | 15 | 18 | 21 | N |
| max_faults (f) | 4 | 5 | 6 | floor((N-1)/3) |
| quorum_threshold | 9 | 11 | 13 | 2f+1 |
| finality_threshold | 9 | 11 | 13 | = quorum |
| public_sr_min | 10 | 12 | 14 | ~2N/3 |
| local_sr_max | 5 | 6 | 7 | N - public_sr_min |
| max_replacements/epoch | 2 | 2 | 3 | max(1, N/7) |
| leader_public_preference | 80% | 80% | 80% | configurable |

## BFT Safety Proof

For any committee size N:
- f = floor((N-1)/3) tolerated faults
- N >= 3f + 1 (BFT prerequisite)
- quorum = 2f + 1 (majority of honest nodes)
- Any two quorums overlap by at least 1 honest node

Verification for SR15: N=15, f=4, 3f+1=13, 15>=13 check. quorum=9, 15-4=11>=9 check.

## Expansion Path

### Safe Committee Expansion (epoch boundary only)

```
Epoch K:     committee_size = 15, quorum = 9
            ↓ governance proposal accepted
Epoch K+1:  committee_size = 18, quorum = 11
            ↓ governance proposal accepted
Epoch K+2:  committee_size = 21, quorum = 13
```

### Expansion Rules

1. Maximum +3 seats per epoch (gradual, not all at once)
2. Expansion only at epoch boundaries (never mid-epoch)
3. Prior finalized checkpoints remain valid
4. All nodes must agree on committee_size before activation
5. Mismatch in committee_size = fail-closed (node rejects blocks)
6. public_sr_min can only increase during expansion
7. Rollback: if expansion fails before activation, revert to previous epoch's policy

### Operator Checklist for Expansion

1. Verify all current SRs have updated software
2. Propose expansion via governance (off-chain coordination for now)
3. At epoch boundary, update `max_validators` in config
4. New candidate nodes must already be synced and scoring
5. Monitor finality continuity for 100 blocks after expansion
6. If finality stalls, emergency rollback via governance

## Solana Bridge Compatibility

The bridge program uses `MAX_COMMITTEE_SIZE = 21` (array capacity) and stores the actual `member_count` and `threshold` in the `BridgeCommittee` PDA. During expansion:

1. `sync_sr_committee()` updates `member_count` and `threshold`
2. Bridge threshold is recomputed: `2 * floor((N-1)/3) + 1`
3. No bridge program redeployment needed for expansion

## Residual Risks of Starting with SR15

| Risk | Severity | Mitigation |
|------|----------|-----------|
| 4 fault tolerance (vs 6 for SR21) | Medium | Smaller attack surface; fewer operators to compromise |
| Higher per-node influence (1/15 vs 1/21) | Medium | Stake-weighted voting reduces individual power |
| Fewer independent operators | Low | Quality > quantity at launch |
| Perception of "less decentralized" | Low | Clear expansion roadmap published |

## Answer

**Can MISAKA safely start with SR15 and later expand to SR21 without architectural redesign?**

**YES.** `CommitteePolicy` is the single source of truth for all committee parameters. All quorum calculations, fault tolerance bounds, seat caps, and replacement limits derive from it. The Solana bridge already supports up to 21 members in its PDA layout. Expansion requires only a config change at epoch boundary — no code changes, no protocol redesign, no bridge redeployment.
