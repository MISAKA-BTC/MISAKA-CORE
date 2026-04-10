# Consensus Architecture — Layer Separation

## Two Crates, Two Responsibilities

```
misaka-dag (narwhal_dag/)           misaka-consensus
├─ Block production & proposal      ├─ Validator set & quorum
├─ DAG state & block acceptance     ├─ Staking & rewards
├─ Commit decisions (Bullshark)     ├─ Economic finality
├─ Transaction certification        ├─ Finality proof verification
├─ Leader scoring & rotation        ├─ Epoch rotation
├─ Round prober & ancestor          ├─ TX validation
├─ Leader timeout                   ├─ State root computation
├─ Block verification (ML-DSA-65)   ├─ Equivocation detector
├─ Commit finalizer                 ├─ Block validation pipeline
├─ Network & sync                   ├─ Checkpoint accumulator
└─ BFT checkpoint voting            └─ ZKP budget management
```

## Decision Flow for New Code

Q: Does this module produce or verify **DAG blocks/votes**?
→ YES: Put in `misaka-dag/narwhal_dag/`
→ NO: Continue

Q: Does this module manage **stake, rewards, or validator economics**?
→ YES: Put in `misaka-consensus/`
→ NO: Continue

Q: Does this module verify **transactions** (UTXO, signatures)?
→ YES: Put in `misaka-consensus/processes/`

## NEVER Create Same-Named Files in Both Crates

Phase 23 deleted 10,081 lines of dead code from misaka-consensus:
- Pass 1: 7,387 lines (DAG duplicates of narwhal_dag modules)
- Pass 2: 2,694 lines (orphan modules: delegation, fork_choice,
  role_scoring, unified_node, vrf_proposer, weak_subjectivity)
This caused Phase 12-22 audit blind spots where fixes to one copy
missed the other.

Rule: If a module exists in narwhal_dag, do NOT create a same-name module
in misaka-consensus. If you need to reference it, use `misaka_dag::` import.
