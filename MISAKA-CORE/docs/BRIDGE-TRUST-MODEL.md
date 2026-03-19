# MISAKA-Solana Bridge — Trust Model

**Version:** v2 (Committee-Operated)
**Date:** 2026-03-18

---

## Architecture

```
MISAKA Network                         Solana
┌──────────────┐                       ┌──────────────┐
│ User locks   │ ──── Relayer ────▶    │ Committee    │
│ tokens       │    (transport)        │ signs unlock │
│              │                       │ on-chain     │
│ Finalized in │                       │              │
│ block        │                       │ Program      │
│              │                       │ verifies     │
│              │                       │ M-of-N sigs  │
└──────────────┘                       └──────────────┘
```

## This Is NOT a Trustless Bridge

This bridge is a **committee-operated bridge**, not a trust-minimized or
trustless bridge. The distinction matters:

| Property | Trustless | Committee-Operated (ours) |
|----------|-----------|--------------------------|
| Trust assumption | Math only (ZK/SPV) | M-of-N committee honest |
| Verification | On-chain proof of source finality | Committee attestation |
| Compromise threshold | None (math) | ≥M committee members |
| Complexity | Very high | Moderate |
| Latency | Higher (proof generation) | Lower (signatures) |

## Trust Assumptions

1. **At least M of N committee members are honest.** If ≥M members collude
   or are compromised, they can authorize arbitrary unlocks.

2. **Committee members verify source chain finality off-chain.** The Solana
   program does NOT verify Misaka block finality. Committee members are
   responsible for checking that the source transaction is finalized on
   Misaka before signing.

3. **Relayer is transport-only.** The relayer (payer) submits the transaction
   but has NO authority over fund movement. A compromised relayer cannot
   steal funds — it can only refuse to relay (liveness, not safety).

4. **Request ID is recomputed on-chain.** The unlock instruction does NOT
   trust the request_id argument. It recomputes:
   ```
   request_id = H(chain_id || source_tx || asset_id || recipient || amount || nonce)
   ```
   This prevents parameter substitution attacks.

## Committee Signing Model

Committee members sign the **Solana transaction** that includes the
unlock instruction. They do NOT sign an abstract message that gets
verified separately. This means:

- The committee authorizes the entire transaction context
- Signers appear in `remaining_accounts` with `is_signer = true`
- The program counts valid committee member signatures
- Duplicate signers are deduplicated

**Limitation:** Committee members approve the transaction as a whole.
There is no separate "authorization payload" signed over just the
unlock parameters. A future improvement would use Ed25519 instruction
introspection to verify committee signatures over a specific message digest.

## What Committee Members Sign

When a committee member co-signs an unlock transaction, they are implicitly
approving all of the following (bound by the instruction parameters):

| Field | Source | Verified |
|-------|--------|----------|
| amount | Instruction arg | ✅ On-chain |
| recipient | Account | ✅ Mint match |
| source_tx_hash | Instruction arg | ⚠️ Off-chain only |
| asset_id | Asset mapping PDA | ✅ On-chain |
| nonce | Instruction arg | ✅ Replay protection |

## Rotation and Incident Response

### Committee Rotation
```
admin → update_committee(new_threshold, new_members)
```
- Only admin can rotate
- Old committee is immediately replaced
- In-flight unlocks with old committee signatures will fail

### Incident Response
1. **Pause bridge:** `admin → pause_bridge()` — blocks all locks AND unlocks
2. **Rotate committee:** Replace compromised members
3. **Unpause:** Resume operations with new committee

### Threshold Guidelines
| Committee Size (N) | Recommended Threshold (M) | Compromise Tolerance |
|---------------------|---------------------------|---------------------|
| 3 | 2 | 1 member |
| 5 | 3 | 2 members |
| 7 | 5 | 2 members |
| 10 | 7 | 3 members |

## Event Logging

All unlocks emit `TokensUnlocked` with full authorization details:

```rust
TokensUnlocked {
    recipient,
    amount,
    request_id,       // Recomputed on-chain
    committee_sigs,   // Number of valid committee signatures
    source_tx_hash,   // Misaka source transaction
    asset_id,         // Asset identifier
    unlock_nonce,     // Unique per unlock
}
```

This enables off-chain monitoring to detect anomalous unlocks.

## Future Improvements (P2+)

1. **Ed25519 instruction introspection**: Verify committee signatures over
   a specific message digest rather than just transaction co-signing.
2. **Source finality proof**: Verify Misaka block Merkle root on Solana
   to prove the source transaction is finalized (trust-minimized model).
3. **Time-locked unlocks**: Add a delay period where unlocks can be
   challenged before execution.
4. **Multi-asset vault separation**: Per-asset committee thresholds.
