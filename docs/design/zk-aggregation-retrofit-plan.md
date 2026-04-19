# ZK Aggregation Retrofit Plan

Status: **DESIGN ONLY — no code in this commit.** Phase 3a Prompt B
final deliverable (memo §26 in `memory/project_phase3a_prompt.md`).
Cross-references: `docs/design/v091_phase3a_cert_v2.md` for the
`CertificateV2` / `AggregationProof` / `ProofSystem::ReservedV1`
shape that this plan targets.

## 0. Why this document exists

Phase 3a shipped a ZK-forward-compatible Cert V2 shape. The
`CertificateV2::aggregation_slot: Option<AggregationProof>` field
is present but **rejected** by the verify path (`VerifyError::
AggregationSlotNotYetAccepted` at `crates/misaka-dag/src/narwhal_finality/cert_v2.rs`).
The `ProofSystem` enum has one variant (`ReservedV1 = 0x01`), also
a placeholder.

This document records:

1. What problem aggregation actually solves (§1).
2. Which proof systems are candidates (§2).
3. A sketch of the circuit an honest validator would prove (§3).
4. Whether a hardfork is required to activate (§4).
5. A concrete step-by-step retrofit plan split across phases (§5).
6. Open questions that must be answered before code lands (§6).

The goal is to make Phase 3b implementation a matter of execution
rather than design. Decisions taken here are informed by the
`aggregation_slot` digest-exclusion invariant already in the
codebase (§7 of `v091_phase3a_cert_v2.md`), which was chosen
specifically so this retrofit can happen without breaking
digest-stable DAG references.

## 1. What problem aggregation solves

### 1.1 Status quo (Phase 3a)

Each `CertificateV2` carries:
- `header: CheckpointDigest` — what's being attested.
- `vote_refs: VoteCommitment` with a bit-packed participation
  vector + a Blake3 merkle root over the voter public keys.
- `epoch: u64`.
- `aggregation_slot: None` (enforced).

Signatures for the underlying `CheckpointVote`s are **externalised**
to a separate CF (`narwhal_votes` per A.1) — each vote row
carries its own ML-DSA-65 signature (~3 KiB). For a 21-validator
committee, finalising one checkpoint persists roughly 21 × 3 KiB
= 63 KiB of signatures plus the cert itself.

### 1.2 The win aggregation would unlock

A single aggregated proof that:

- every bit set in `vote_refs.voters` corresponds to a validator
  who produced a valid signature over `header`,
- the proof is short (1–64 KiB depending on system),

replaces the ~63 KiB per-cert signature payload with a ~10 KiB
proof (exact number depends on the system — see §2). Over a day
at 8 640 commits/node/24h (post-v0.8.9 cadence), that's:

- Raw signatures: 63 KiB × 8 640 ≈ **530 MiB/day**.
- Aggregated proof: 10 KiB × 8 640 ≈ **85 MiB/day**.

Savings of ~440 MiB/day per node align with the Phase 3a memo's
"10–20 % over archival" + "5–10× idle" targets — aggregation is
the primary lever after Phase 2's compression.

### 1.3 Non-goals for aggregation

- **Not replacing** the individual signatures on the wire — each
  validator still gossips its own ML-DSA-65 signature. The
  aggregation is a post-hoc compaction applied by the proposer
  or by a dedicated aggregator role.
- **Not replacing** equivocation evidence. Double-signing
  detection continues to need the raw signatures; they can be
  prunable past an unbonding window but the aggregated proof
  alone is insufficient for slashing.
- **Not changing consensus**. Aggregation verifies a property
  of an existing finalised cert; it does not alter quorum rules.

## 2. Proof system candidates

### 2.1 Criteria

1. **Prover time**: must complete within one epoch (wall-clock ≤
   24 h is the trivial bound; target is seconds so aggregation
   happens per-commit).
2. **Verifier time**: must be faster than verifying N individual
   ML-DSA-65 signatures (the thing we're replacing). For N = 21
   that's ~210 ms today on a modern CPU.
3. **Proof size**: target ≤ 16 KiB so the net-on-disk win holds
   even with metadata.
4. **Trusted setup**: prefer none. Misaka is permissionless;
   a post-genesis ceremony is politically expensive.
5. **PQ security**: Misaka's signature stack is ML-DSA-65 (PQ).
   A retrofit that relies on an elliptic-curve-DLog hardness
   assumption introduces a new quantum-vulnerable component.
   Prefer hash-based or lattice-based systems.
6. **Library maturity**: an actively maintained Rust
   implementation with audit history.
7. **Circuit language**: compatible with the aggregation circuit
   in §3 (ML-DSA-65 signature verification inside the circuit).

### 2.2 Candidates

| System | Prover | Verifier | Proof size | Trusted setup | PQ | Rust crate | Notes |
|---|---|---|---|---|---|---|---|
| **Groth16** | fast | ~2 ms | 192 B | yes (per-circuit) | no | `bellman`, `arkworks-groth16` | Smallest proofs, but per-circuit trusted setup is a political non-starter for a permissionless chain. Also not PQ. |
| **PLONK (KZG)** | medium | ~10 ms | ~500 B | yes (universal) | no | `plonky2` (non-KZG), `halo2` (non-KZG) | Universal setup is less controversial than per-circuit, but still a ceremony. Not PQ. |
| **Halo2 (IPA)** | medium | ~30 ms | ~5 KiB | **none** | no | `halo2_proofs` | No trusted setup. Not PQ, but the setup-freeness is attractive. Heavy prover; large circuits may not fit commit cadence. |
| **STARK** | slow | ~50 ms | ~100 KiB | **none** | **yes (hash-based)** | `winterfell`, `stone-prover` | PQ-safe, setup-free. Proofs are large — blows past our 16 KiB target. |
| **Plonky2** | fast | ~50 ms | ~45 KiB | **none** | **yes (hash-based)** | `plonky2` | PQ-safe, setup-free, aggressively optimised. Proof size still 3× our target but the PQ property may be worth it. |
| **Plonky3** | fast | ~20 ms | varies | **none** | **yes** | `plonky3` (early) | Newer, smaller proofs than Plonky2, but the library is pre-1.0 as of 2026-04. Worth re-evaluating when it hits stable. |

### 2.3 Recommendation

**Primary: Plonky2** (for Phase 3b initial activation).
- PQ-safe (criterion 5) matches Misaka's signature stack choice.
- Setup-free (criterion 4) avoids the ceremony headache.
- Rust-native, well-audited.
- Prover fast enough to run per-commit.

**Proof size tradeoff**: Plonky2's ~45 KiB proof is larger than
the 16 KiB target, but:
- It replaces ~63 KiB of raw signatures (net **still a win**,
  just smaller than the Groth16 scenario).
- BlobDB on the `narwhal_votes` CF already absorbs large values
  well (min_blob_size = 1024 per A.1); 45 KiB per proof compresses
  and lives out of the LSM hot path.

**Secondary: Plonky3** (for Phase 3b+ if library matures).
Same security properties, potentially smaller proofs, re-check
maturity before commit.

**Rejected**: Groth16 (trusted setup), PLONK-KZG (trusted setup,
non-PQ), STARK (100 KiB blows the budget), Halo2-IPA (non-PQ
outweighs the setup-freeness win).

## 3. Circuit sketch

The circuit takes public inputs and witnesses and outputs a
proof that the caller signed over them correctly.

### 3.1 Public inputs

Everything the cert verifier already has:

```
public:
  header_digest       : [u8; 32]          // CertificateV2::header
  voters              : BitVec<N>         // VoteCommitment::voters
  voter_commitment    : [u8; 32]          // VoteCommitment::root
  epoch               : u64               // CertificateV2::epoch
  committee_root      : [u8; 32]          // merkle root over the epoch's
                                           // authority set (must equal
                                           // what the verifier pins)
```

### 3.2 Private witnesses

The raw material the proposer/aggregator has:

```
witness:
  voter_pks           : Vec<ML-DSA-65 public key>   // N × 1952 B
  voter_signatures    : Vec<ML-DSA-65 signature>    // N × 3309 B
  voter_authority_ix  : Vec<u32>                    // position in committee
```

### 3.3 Circuit statements (proved)

1. For every `i` where `voters[i] == 1`:
   - `ML-DSA-65.verify(voter_pks[i], header_digest, voter_signatures[i])`
     returns `true`.
2. `Blake3MerkleV1(voter_pks where voters[i] == 1)` equals
   `voter_commitment`.
3. Each `voter_pks[i]` appears in the committee merkle tree rooted
   at `committee_root` at index `voter_authority_ix[i]`.

That's three independent proofs welded together. (3) pins the
proof to the epoch's committee; (2) pins it to the cert's voter
commitment; (1) does the heavy lifting — N ML-DSA-65 verifications
inside the circuit.

### 3.4 Heaviest sub-circuit: ML-DSA-65 verification

ML-DSA-65 verification (in the circuit) involves:

- Keccak-based hash-to-point,
- Polynomial multiplication over a 13-bit modulus (q = 8380417),
- Number-theoretic transforms (NTT),
- Bit-decomposition (for `w_1`, `h`, `z` decoding).

In Plonky2 terms: on the order of 2^22 gates for one ML-DSA-65
verification. For N = 21 that's 2^22 × 21 ≈ 2^26 gates per proof.
Prover ~seconds-to-minutes on modern hardware.

**Implication for per-commit aggregation**: this is too heavy for
the sub-second cadence. The realistic deployment is:

- Per-commit: raw signatures only (Phase 3a status quo).
- Per-epoch (24 h): one aggregated proof covering all
  `FinalizedCheckpoint`s in that epoch. Prover runs async; the
  proof lands on-chain in the following epoch's audit log and
  replaces the per-cert signatures in the CF via a GC pass.

This "lazy aggregation" shape fits Misaka's operational budget
and is an acceptable compromise: disk pressure from signatures
builds up within an epoch, then deflates when the proof lands.

### 3.5 Alternative: BLS signature aggregation (non-PQ)

If Misaka later adds a BLS-over-BLS12-381 signature pathway, BLS
aggregation reduces N signatures to one 96-byte signature with
trivial verification. The `ProofSystem` enum would gain a
`BlsAggregation` variant and the `AggregationProof::proof` field
would carry the 96-byte aggregate. This is materially smaller
and faster than any SNARK but introduces non-PQ crypto — a
policy decision outside this doc's scope. Flagged here so the
`ProofSystem` enum design doesn't accidentally foreclose it.

## 4. Hardfork necessity assessment

### 4.1 What changes with aggregation

| Surface | Changes? | Rationale |
|---|---|---|
| `CertificateV2` struct shape | **no** | `aggregation_slot` is already present. Only the verify-path behaviour changes. |
| `CertificateV2::digest()` output | **no** | Digest already excludes `aggregation_slot` (per §7 of `v091_phase3a_cert_v2.md`). |
| Cert V2 wire format | **no** | Phase 3a is storage-layer only; wire stays V1. Phase 3b wire changes are orthogonal. |
| Verify path | **yes** | `VerifyError::AggregationSlotNotYetAccepted` becomes a `VerifyError::AggregationProofInvalid` and the verifier runs real proof verification. Semantic change. |
| Cert acceptance rules | **case-dependent** | See §4.2. |

### 4.2 Are consensus acceptance rules changing?

**This depends entirely on how aggregation is deployed.**

- **Mode A — backfill-only**: aggregated proofs are stored but
  certs are still finalised by the existing 2/3 stake quorum on
  raw signatures. The proof is an **archival compaction**, not a
  consensus replacement.
  - Verifier rule: *if* `aggregation_slot` is `Some` and the
    proof verifies, the proof is archival; the raw signatures
    can be deleted after `unbonding_window_epochs`.
  - **No hardfork.** This is a storage-format evolution that
    every validator adopts independently. Old nodes that don't
    understand the proof simply see `aggregation_slot = Some(_)`
    and (after Phase 3b) accept it based on a feature flag that
    gates the new verify path on.
  - Feature-flag rollout: `NodeRuntimeConfig::accept_aggregation_slot`
    with a 2-release window.
  - **Recommended initial mode.**

- **Mode B — consensus replacement**: a cert with
  `aggregation_slot = Some(_)` is accepted without any raw
  signatures (they may be absent from the wire entirely).
  - Verifier rule: `vote_refs.voter_count >= quorum` AND the
    proof verifies.
  - **Requires a hardfork.** Old nodes cannot verify the proof
    and will reject every new cert. A coordinated upgrade is
    mandatory.
  - Adds wire V2 to the Phase 3b scope.
  - **Deferred to a future phase** (3c or later).

### 4.3 Migration hazards for Mode A

Even the no-hardfork path has gotchas:

1. **Proof system version pinning**: `ProofSystem` must be
   extensible without breaking cert digests. Already handled —
   the enum is represented as a 1-byte tag and the digest
   excludes `aggregation_slot` in full.
2. **Committee drift**: a proof generated by an old aggregator
   must verify under a new node's committee view. The proof's
   public input `committee_root` pins this — verify against the
   epoch's historical root, not the current one.
3. **Proof rejection cascade**: a malformed proof must not
   invalidate the underlying cert. Treat proof verification
   independently from cert validity; a bad proof is discarded,
   the cert remains fine via its raw signatures.
4. **Aggregator trust**: in Mode A, a dishonest aggregator can
   withhold or delay a proof. This is a liveness cost, not a
   safety cost — raw signatures keep finality working.

## 5. Retrofit plan (step-by-step)

All steps assume the codebase's Phase 3a store layer is live
and the Part B+C runtime integrations have landed (separate
work from this doc). Each step is a standalone commit.

### Step 1 — `ProofSystem::Plonky2V1 = 0x02` — SHIPPED

Shipped in this branch's Phase 3b first commit. Changes:

- `crates/misaka-dag/src/narwhal_finality/cert_v2.rs` —
  `ProofSystem::Plonky2V1 = 0x02` variant added. Rustdoc
  specifies the phase gating: Phase 3a + Phase 3b Step 1 still
  reject any cert with `aggregation_slot = Some(_)` regardless
  of tag; Step 6+ activates real verification.
- `AggregationProof::new_plonky2_v1(proof, public_inputs,
  generated_at)` constructor. Does not validate contents —
  that's the verifier's job in Step 6+.
- `VerifyError::UnknownProofSystem { tag: u8 }` variant added
  as *foreshadowing*. Won't fire in Step 1 because the
  `AggregationSlotNotYetAccepted` arm still catches all
  `Some(_)` cases before the tag is ever checked. Exists so the
  error shape is stable across the Step 2-6 rollout.
- 5 new unit tests: `proof_system_plonky2_v1_tag_is_two`,
  `proof_system_variants_are_distinct_and_serde_stable`,
  `aggregation_proof_new_plonky2_v1_constructor`,
  `aggregation_proof_plonky2_v1_still_rejected_in_phase_3b_step1`
  (pins the "still rejected" invariant explicitly so Step 6
  has to delete this test by hand — catches accidental
  invariant loss), `verify_error_unknown_proof_system_variant_exists`.
- `cargo test -p misaka-dag --lib`: 524/524 pass (519 prior + 5).

No consensus change, no circuit — just the type extension.

### Step 2 — Plonky2 dep + proof-system interface

- Add `plonky2 = "0.x"` to `crates/misaka-dag/Cargo.toml`.
- Trait `AggregationProver { fn prove(inputs) -> AggregationProof; }`
  and `AggregationVerifier { fn verify(proof, public) -> Result<(),
  ProofError>; }`.
- Initial impls: `Plonky2V1Prover`, `Plonky2V1Verifier` with
  **dummy circuits** (e.g. prove knowledge of `voters.len() > 0`).
  This lets us wire the end-to-end plumbing without the heavy
  ML-DSA-65 circuit.

Still no real aggregation; the pipeline now exists.

### Step 3 — Committee-membership sub-circuit

- Circuit proves: "`voter_pks[i]` appears in committee merkle
  tree at `voter_authority_ix[i]`".
- Small circuit (~2^14 gates), testable in isolation.
- Unit tests against a fixed committee vector.

### Step 4 — Voter-commitment sub-circuit

- Circuit proves: "`Blake3MerkleV1(voter_pks where voters[i]==1)
  == voter_commitment`".
- Uses the same merkle-scheme semantics as the storage path (same
  leaf/internal/root hash domains).

### Step 5 — ML-DSA-65 verification sub-circuit

- **The heavy one**. Circuit proves: "for each `i` where
  `voters[i]==1`, `ML-DSA-65.verify(voter_pks[i], header_digest,
  voter_signatures[i])` succeeds".
- Expect several commits inside Step 5: NTT sub-circuit,
  hash-to-point sub-circuit, bit-decomposition gadgets, final
  assembly.
- Benchmarks: measure prover time on 21-validator committee,
  target < 10 minutes on a modern server.

### Step 6 — End-to-end aggregation prover

- Stitch Steps 3 + 4 + 5 into one circuit.
- Implement `Plonky2V1Prover::prove` properly.
- Integration test: produce a real proof on a simulated 21-voter
  cert, verify it, assert `VerifyError::AggregationProofInvalid`
  fires on tampered inputs.

### Step 7 — Async aggregation scheduler

- Background task in `start_narwhal_node`: at each epoch boundary,
  gather the epoch's `FinalizedCheckpoint`s, spawn a prover job,
  persist the resulting proof under `narwhal_votes`
  (replacing/annotating each cert's entry with its proof).
- Config: `aggregation_mode: { Off, ArchivalOnly(Plonky2V1) }`
  — first two variants only, matches §4.2 Mode A.
- Metrics: prover latency, proof size, proof verification
  failures.

### Step 8 — Archival GC

- Once a cert has a verified aggregation proof, its per-vote raw
  signatures become archival. After the unbonding window,
  `gc_below_round` (already present) can delete them from
  `narwhal_blocks` while `narwhal_votes` keeps the proof and the
  voter bit-vector.
- Pruned-mode nodes skip the raw-signature drain entirely.

### Step 9 — 7-day smoke (Phase 3a Part E becomes reachable)

- 4 nodes: 2 archival, 2 pruned.
- Measure: total disk at T+7d, proof count, proof verification
  latency, aggregator uptime.
- Success: disk savings ≥ the §1.2 targets, no proof rejections
  outside expected (~0) noise.

### Step 10 — (future) Mode B deployment

Out of Phase 3 scope. Listed for completeness:

- Hardfork / wire V2.
- Old nodes retire or upgrade.
- Raw signatures disappear from the hot wire path entirely;
  the proof is the sole attestation.

## 6. Open questions

Flagged here so they don't ambush implementation:

1. **Circuit versioning**. If the ML-DSA-65 sub-circuit has a
   bug, how do we ship a fix? Options:
   - Bump to `ProofSystem::Plonky2V2 = 0x03`, leave V1 verifiable
     in perpetuity (archival). Clean; grows the enum.
   - Hardfork to force all new proofs to use V2. Cleaner on-disk;
     coordinated upgrade.

   **Tentative answer**: version-bump + keep-verifying. Proof
   systems are on-disk-stable forever.

2. **Aggregator selection**. Who produces the proof?
   - The leader of the last round in the epoch?
   - A dedicated "aggregator" validator role?
   - Anyone (permissionless)?

   **Tentative answer**: permissionless — any validator can
   submit a proof; first one accepted wins. Liveness from the
   "any" plural; safety from the proof itself.

3. **Proof rejection and blame**. If a proof fails to verify,
   is the aggregator slashed? This dips into "aggregator
   misbehaviour" tokenomics.

   **Tentative answer**: no slashing in Mode A — the aggregator
   is liveness-only, not safety-critical. Revisit in Mode B.

4. **Quantum safety claim**. Plonky2 uses Poseidon as its hash.
   Is Poseidon considered quantum-safe? **Yes** as of 2026
   consensus, but this is an evolving area. The plan reserves
   the right to switch to Keccak-based STARKs if Poseidon's
   PQ-ness is questioned.

5. **Library turnover**. Plonky2 was "fast Rust zk-SNARK library
   of 2024-2026". Library maintenance halt is a real risk. The
   retrofit plan should assume Step 2's `AggregationProver` trait
   is the indirection point — swapping libraries means rewriting
   Step 2 + Step 5 only.

6. **State-rent for stale proofs**. Very old proofs might be
   cheaper to delete than to store. Aggregation saves space; GC
   of proofs beyond, say, `10 × unbonding_window` could save
   even more. Punt — orthogonal to retrofit design.

## 7. What this plan commits to

Implementable via Steps 1-9. Estimated effort:

| Step | LoC | Sessions | Risk |
|---|---|---|---|
| 1 | ~50 | 0.25 | trivial |
| 2 | ~200 | 1 | low (dep add + traits) |
| 3 | ~300 | 1-2 | medium (first circuit) |
| 4 | ~200 | 1 | low (mirrors storage) |
| 5 | ~2000 | **5-10** | **high** (ML-DSA-65 in-circuit) |
| 6 | ~300 | 1-2 | medium (integration) |
| 7 | ~500 | 2 | medium (async + metrics) |
| 8 | ~100 | 1 | low (GC reuses existing) |
| 9 | ~0 | operational | high (live smoke) |
| **Total** | **~3 650 LoC** | **~13-20 sessions** | — |

Most of the risk is concentrated in Step 5. Before committing,
prototype ML-DSA-65-in-Plonky2 as a PoC benchmark and only
commit to Step 5 if the prover benchmarks meet the §3.4 budget.

## 8. What this plan does NOT commit to

- Wire V2 (Phase 3c+).
- Non-PQ signature schemes (e.g. BLS aggregation) — flagged as
  an option in §3.5 but not the recommended path.
- Removing `CheckpointVote` raw signatures from the wire —
  they stay in Phase 3b Mode A.
- Anything hardfork-requiring.

## 9. Cross-references

- `docs/design/v091_phase3a_cert_v2.md` §7 — digest exclusion
  invariant (load-bearing for this retrofit).
- `docs/design/v090_phase2_cf_split.md` §11.3 — `PruneMode` +
  GC machinery that Step 8 reuses.
- `crates/misaka-dag/src/narwhal_finality/cert_v2.rs` —
  `CertificateV2`, `AggregationProof`, `ProofSystem`, verify path.
- `memory/project_phase3a_prompt.md` — source memos for this
  plan (Prompt B §26).
