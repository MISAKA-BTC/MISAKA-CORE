# Round Tracking — Responsibility Separation

## Components

| Component | File | Responsibility |
|-----------|------|---------------|
| **ThresholdClock** | threshold_clock.rs | Advances local round when quorum stake reached at current round |
| **LeaderTimeout** | leader_timeout.rs | Timer for leader block arrival; exponential backoff on timeout |
| **RoundProber** | round_prober.rs | Network queries: asks peers for their highest accepted rounds |
| **RoundTracker** | round_tracker.rs | Local aggregation of round state, quorum round, metrics export |

## Data flow

```
Block accepted ──> ThresholdClock.observe()
                     │
                     ▼ (round advanced?)
                   RoundTracker.on_round_advance()
                     │
                     ├── updates current_round
                     ├── records propagation delay
                     └── resets per-round timeout counter

Block accepted ──> RoundTracker.on_block_accepted()
                     │
                     ├── updates per-authority highest round
                     └── recomputes quorum_round

Leader timeout ──> RoundTracker.on_leader_timeout()
                     │
                     └── increments timeout counters

Block proposed ──> RoundTracker.on_block_proposed()
                     │
                     └── updates last_proposed_round
```

## Key invariants

1. **ThresholdClock owns round advancement.** RoundTracker only observes.
2. **RoundTracker never triggers state changes** in other components.
   It is a read-aggregation layer.
3. **Quorum round** is computed from local accepted-round data only
   (not from RoundProber network queries). RoundProber provides a
   separate network-wide view.
4. **Propagation delay** = last_proposed_round - quorum_round.
   High values indicate our blocks are slow to reach quorum.

## PQ relevance

ML-DSA-65 blocks are ~50x larger than Ed25519 blocks. This affects:

- **Propagation delay**: larger blocks take longer to transmit.
  RoundTracker.avg_propagation_delay() tracks the smoothed average.
- **Quorum round lag**: under high load, quorum round may fall behind
  current round. RoundTracker.num_lagging() counts straggler authorities.
- **Timeout tuning**: LeaderTimeout backoff should account for PQ
  transmission time. RoundTracker.timeouts_at_current_round() feeds
  adaptive timeout logic (future Phase).

## Peer classification

| Status | Gap | Meaning |
|--------|-----|---------|
| Synced | 0 | At or above quorum round |
| SlightlyBehind | 1-2 | Minor lag, likely transient |
| Lagging | 3+ | Significant lag, may need sync help |
| Unknown | N/A | No blocks received yet |

Used by AncestorSelector to bias parent selection toward synced peers.

## Epoch boundary

RoundTracker.reset_for_epoch() clears all round state but preserves
cumulative metrics (round_advancements, total_timeouts). This matches
the Sui pattern where per-epoch state is transient but observability
counters are monotonic.
