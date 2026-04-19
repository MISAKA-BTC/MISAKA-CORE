# v0.9.1 Phase 3a — Certificate V2 (ZK-forward-compatible foundation)

Status: **FOUNDATION shipping in this commit (types + scheme). Follow-up sessions wire write/read + adaptive rate + epoch adjustment.**

Stacked on: PR #13 (`feature/v090-cf-split-pruning`) which is stacked on PR #11 (`feature/v090-cf-enum-foundation`). Merge order: #11 → #13 → this PR.

Source memos (captured in `memory/project_phase3a_prompt.md`): two prompts that the user delivered in one burst. Reconciliation below.

---

## 1. Reconciliation of Prompt A and Prompt B

The two source prompts describe overlapping but not identical Cert V2 shapes.

| Field              | Prompt A (signature externalization)                 | Prompt B (ZK-forward)                                            | Chosen |
|--------------------|------------------------------------------------------|------------------------------------------------------------------|--------|
| `header` binding   | `header_digest: [u8; 32]`                            | `header: CheckpointDigest` (full digest type)                    | **B** — use the typed `CheckpointDigest` that already exists in `narwhal_finality/mod.rs`. Prompt A's raw `[u8; 32]` is the same 32 bytes but typed. |
| Vote carrier       | `vote_refs: BitVec`                                  | `vote_refs: VoteCommitment { voters: BitVec, root, scheme }`     | **B** — Prompt B wraps Prompt A's `BitVec` with a merkle-root + scheme tag. Extra fields default to `Blake3MerkleV1` with root computed from `voters`. Phase 3b can swap the scheme without shape change. |
| Epoch field        | `epoch: u64`                                         | (not present)                                                    | **Added** — Prompt A's `epoch` carries over. Lives at `CertificateV2::epoch`; not inside `VoteCommitment`. |
| Aggregation slot   | (not present)                                        | `aggregation_slot: Option<AggregationProof>`                     | **B** — Phase 3a populates `None` only; `ProofSystem::ReservedV1` is the sole variant and a cert with `Some(_)` is rejected. |
| Cert digest input  | implicit (probably everything)                       | explicit: digest excludes `aggregation_slot`                     | **B** — the exclusion is load-bearing: it lets a later hardfork retrofit proofs without changing every DAG reference. |

### Chosen shape (this commit)

```rust
pub struct CertificateV2 {
    pub header: CheckpointDigest,
    pub vote_refs: VoteCommitment,
    pub epoch: u64,
    pub aggregation_slot: Option<AggregationProof>,
}

pub enum Certificate {
    V1(FinalizedCheckpoint),   // existing — placeholder name for the current "cert"
    V2(CertificateV2),
}
```

Where `V1` aliases the existing `FinalizedCheckpoint` — no new V1 struct is created, and no migration is attempted in this foundation commit. The enum lets callers match on the variant when Prompt A's read path lands.

## 2. VoteCommitmentScheme

```rust
pub trait VoteCommitmentScheme {
    fn leaf(voter_id: &[u8; 32], signature_or_nothing: &[u8]) -> [u8; 32];
    fn internal(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32];
    fn root(leaves: &[[u8; 32]]) -> [u8; 32];
    fn scheme_tag() -> CommitmentScheme;
}
```

One impl this session: `Blake3MerkleV1`.

- **Domain separation**: distinct blake3 prefix per kind to prevent collisions across leaf / internal / root. Concretely: `b"MISAKA:cert_v2:leaf:v1"`, `b"MISAKA:cert_v2:internal:v1"`, `b"MISAKA:cert_v2:root:v1"`.
- **Hash choice**: blake3 rather than SHA-2-256 to match the existing `Checkpoint::compute_digest` convention at `narwhal_finality/mod.rs:35`. The memo called this scheme "Sha256MerkleV1"; renamed to `Blake3MerkleV1` so the scheme tag accurately labels the function. Tag byte stays `0x01` — this is the first persisted scheme either way.
- **Determinism**: the `root()` impl sorts leaves by voter_id ascending before hashing, so two validators computing the same commitment from the same voter set always agree.
- **Padding**: for non-power-of-two leaf counts, duplicate the last leaf up to the next power of two (Bitcoin-style). Avoids second-preimage on odd heights.
- **Scheme tag**: `CommitmentScheme::Blake3MerkleV1 = 0x01` reserved byte; future Poseidon etc. take 0x02+.

## 3. AggregationProof

```rust
pub enum ProofSystem {
    ReservedV1 = 0x01,  // no proofs accepted in Phase 3a
}

pub struct AggregationProof {
    pub system: ProofSystem,
    pub proof: Vec<u8>,
    pub public_inputs: Vec<u8>,
    pub generated_at: u64,
}
```

Phase 3a invariant (enforced on verify path when wired): any `AggregationProof { system: _, ... }` — regardless of contents — is rejected. The field exists so that Phase 3b can drop in a real proof system without shape change.

## 4. Cert digest — what's in, what's out

`CertificateV2::digest()` hashes:

```
MISAKA:cert_v2:digest:v1 ||
  header_digest (32) ||
  epoch (8 LE) ||
  vote_refs.scheme_tag (1) ||
  vote_refs.voters.len (8 LE) ||
  vote_refs.voters (packed bits, length-prefixed) ||
  vote_refs.root (32)
```

**Explicitly NOT included**: `aggregation_slot`. Rationale per Prompt B: a later hardfork may retrofit a proof into existing certificates without breaking every DAG reference that cites them by digest. If the proof contents were inside the digest, retrofit would require re-signing every historical cert's downstream references.

## 5. Progress log

### 5.1 Foundation — 9a88656 (2026-04-19 early)

Cert V2 types + design doc (this file). See commit for details.

### 5.2 Part A.1-A.3 — this commit (2026-04-19 later)

- **A.1 — `votes` CF**: added `NarwhalCf::Votes = "narwhal_votes"`
  variant. CF descriptor in `open_with_sync`: compression off +
  BlobDB with `min_blob_size = 1024`. `cf_votes()` accessor +
  `CF_VOTES` const. `NarwhalCf::ALL` updated to 9 variants; the
  exhaustiveness test's `EXPECTED_COUNT` bumped accordingly.
- **A.2 — write path**: `RocksDbConsensusStore::put_cert_v2_votes(
  cert_digest, &VoteCommitment, &Option<AggregationProof>)`.
  Serde-JSON encoding for day-1 consistency with the other narwhal
  value encodings (borsh migration deferred — needs manual impls to
  preserve `#[repr(u8)]` tags on `CommitmentScheme` / `ProofSystem`).
  Intentionally accepts `aggregation_slot = Some(_)` at the store
  layer — the verify path (not yet wired) owns the Phase 3a "reject
  Some" invariant.
- **A.3 — read path**: `get_cert_v2_votes(cert_digest) ->
  Result<Option<(VoteCommitment, Option<AggregationProof>)>, _>`.
  Returns `Ok(None)` on missing key; propagates serde errors.
- 7 new unit tests in `rocksdb_store::tests`:
  `a1_votes_cf_is_registered_on_open`,
  `a2_a3_put_then_get_roundtrips_without_agg`,
  `a2_a3_put_then_get_roundtrips_with_agg`,
  `a3_get_on_missing_key_returns_none`,
  `a2_put_overwrites_previous_value`,
  `a1_write_to_votes_does_not_affect_tx_index`,
  `a3_roundtrip_preserves_scheme_tag`.
- 1 new assertion in `columns::tests::names_match_pre_refactor_literals`
  and 1 update to `all_is_exhaustive_and_unique::EXPECTED_COUNT`.

Totals: `cargo test -p misaka-dag --lib` 462/462 (455 prior + 7).
`cargo check --workspace --lib --bins` clean.

## 6. Out of scope for this session

Deferred to follow-up commits:

- **A.4 — verify path**: reject any `CertificateV2` with
  `aggregation_slot = Some(_)` and (later) verify merkle root against
  the persisted voters list.
- **A.5 — cert v1 ↔ v2 mapping CF** for one-epoch compatibility.
- **A.6 — migrate `--from 2 --to 3`**: extends the R6-a CLI to stage
  v2 stubs for every existing finalized cert.
- **Adaptive round rate** (Prompt A Part B): new `RoundScheduler`,
  `next_round_interval` linear interp, `tokio::select!` on sleep vs
  mempool.
- **Epoch-boundary config adjustment** (Prompt A Part C):
  `adjust_round_config` deterministic from previous-epoch stats.
- **ZK-aggregation retrofit plan**:
  `docs/design/zk-aggregation-retrofit-plan.md` (Prompt B final item).
- **7-day smoke**: deploy after the above lands. Prereq is also
  Phase 2's pending 24h smoke.

All of the above reference this design doc so the reconciliation is
stable across sessions.

## 7. Hard boundaries (unchanged from memory memo)

- Phase 3a = **storage layer only**. Wire stays V1 compatible. No hardfork.
- Phase 3b (hardfork, wire V2) = separate work, NOT in Phase 3a scope.
- No actual ZK proof verification in Phase 3a; `ProofSystem::ReservedV1` only.

## 8. Verification plan (when full Phase 3a lands)

- `cargo test -p misaka-dag` passes all of the new cert_v2 tests.
- Every round-trip: encode(cert) → decode → re-encode yields byte-identical output.
- Determinism test: two validators computing `VoteCommitment::new(voters, scheme)` from the same `voters` set produce identical `root`s regardless of insertion order.
- Aggregation rejection test: any cert with `aggregation_slot = Some(_)` rejected by the verify path.
- 7-day 4-node smoke: disk savings 10–20 % over Phase 2 archival, 5–10× reduction at idle — per Prompt A's target.
