# MISAKA Bridge Operations Runbook

## Overview

The MISAKA bridge connects Layer 1 (MISAKA) to Layer 2 (Solana).
All bridge operations require threshold committee approval.

## Committee Structure

- **Committee size**: 5 members (configurable)
- **Threshold**: 3/5 (ceil(2/3)) for normal operations
- **Emergency pause**: 1/5 (any single member)
- **Unpause**: 3/5 (threshold)

## Withdrawal Processing

### Automatic (amount <= auto_approve_limit)

1. User submits withdrawal request on L1
2. Relayer picks up request
3. Safety checks (fail-closed):
   - Circuit breaker: is bridge paused?
   - Nullifier: has this withdrawal been processed before?
   - Rate limit: per-address and global
   - Amount: below auto-approve threshold?
4. If all pass → execute withdrawal
5. Nullifier recorded to disk (crash-safe)

### Manual Approval (amount > auto_approve_limit)

1. Withdrawal queued in `ManualApprovalQueue`
2. Committee members notified (via monitoring)
3. Each member reviews and calls `approve(withdrawal_id, member_id)`
4. When approvals >= threshold → execute withdrawal
5. Queue has max size (1000) for DoS protection

### Rate Limits

| Parameter | Default | Description |
|-----------|---------|-------------|
| per_address_limit | 10,000 MISAKA | Max per address per window |
| global_limit | 100,000 MISAKA | Max total per window |
| anomaly_threshold | 50% | Single withdrawal > 50% of global = blocked |
| auto_approve_limit | 1,000 MISAKA | Above this → manual approval |

## Emergency Procedures

### Pause the Bridge

**When**: Suspicious activity detected, exploit reported, anomaly triggered

```bash
# Any committee member can pause
misaka-bridge-cli pause --reason "Anomaly: large withdrawal pattern detected"
```

**Effect**: ALL withdrawals immediately rejected. Deposits still accepted.

### Unpause the Bridge

**Requires**: 3/5 committee signatures

```bash
# Each member signs
misaka-bridge-cli unpause-sign --member-id alice
misaka-bridge-cli unpause-sign --member-id bob
misaka-bridge-cli unpause-sign --member-id charlie

# Submit unpause with threshold signatures
misaka-bridge-cli unpause --signatures alice.sig,bob.sig,charlie.sig
```

### Key Rotation

**When**: Committee member compromised or scheduled rotation

1. Generate new ML-DSA-65 keypair
2. Submit key rotation proposal (threshold approval)
3. Old key enters 7-day sunset period
4. New key becomes active

## Monitoring Alerts

| Alert | Trigger | Action |
|-------|---------|--------|
| Rate limit hit | >80% of global limit used | Investigate traffic pattern |
| Anomaly detected | Single withdrawal >50% of limit | Manual review required |
| Approval queue full | Queue at max capacity | Clear stale entries |
| Nullifier collision | Replay attempt | Block + investigate source |
| Circuit breaker triggered | Emergency pause | Assess situation |

## Recovery After Restart

1. `WithdrawalNullifierSet` loads from disk automatically
2. `ReplayGuard` nonce state loads from persistence file
3. `ManualApprovalQueue` is in-memory (pending approvals lost)
   - Committee must re-submit pending approvals after restart
4. `WithdrawalRateLimiter` resets (window-based, self-healing)

## Audit Trail

All bridge operations logged with:
- Timestamp (UTC)
- Operation type (withdraw, pause, unpause, approve)
- Committee member ID (for authenticated ops)
- Amount and recipient (for withdrawals)
- Success/failure status
