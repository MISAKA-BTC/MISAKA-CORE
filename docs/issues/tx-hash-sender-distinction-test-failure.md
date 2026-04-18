# Issue: `misaka-types` tx_hash does not distinguish distinct senders

## Status

- **Priority**: MEDIUM (test failure, possible logic bug in signing payload)
- **Blocking**: no (unrelated to `hotfix/peer-replay-window`; this is a
  `misaka-types` issue, hotfix scope is `misaka-dag` + consensus)
- **Discovered**: 2026-04-18, during final validation run of
  `hotfix/peer-replay-window` (B3-a integration smoke)

## Symptom

Test `misaka-types::transaction::tests::test_different_sender_tx_hash_differs`
panics with `assertion left != right failed` — two `Transaction` values
constructed with different `sender` pubkey bytes (and different `signature`
bytes) produce **identical** `tx_hash()` outputs.

Observed digest (both sides):

```
[9, 140, 43, 125, 44, 152, 213, 121, 248, 178, 21, 243, 47, 168, 81, 45,
 253, 17, 55, 76, 241, 203, 57, 244, 126, 174, 123, 4, 70, 234, 140, 169]
```

## Reproducer

```bash
cargo test -p misaka-types --lib test_different_sender_tx_hash_differs
```

Expected: pass (`tx_hash()` should differ for different senders).
Actual: fail (hashes equal).

## Pre-existing confirmation

Checked out `1146a3e` (the parent commit of the B3-a fix `73ad43e`) and
re-ran the test — the same failure reproduces. The failure is **not
introduced by this PR** (`hotfix/peer-replay-window`).

```bash
git checkout 1146a3e
cargo test -p misaka-types --lib test_different_sender_tx_hash_differs
# → FAILED (same assertion)
```

## Probable root cause (not yet investigated)

`crates/misaka-types/src/transaction.rs:103-108` — `Transaction::tx_hash`
hashes `signing_payload()`, which on line 115 calls
`self.sender.mcs1_encode(&mut buf)`. If `MisakaPublicKey::mcs1_encode`
serialises only the `scheme` field and omits the `bytes` field, two
senders that share a scheme but differ in key bytes would collide — which
matches the observed behaviour (both test senders use `SignatureScheme::MlDsa65`).

Needs confirmation by reading `MisakaPublicKey::mcs1_encode` and tracing
whether `self.bytes` is written to the MCS-1 buffer.

## Security implication (if confirmed)

If `tx_hash()` truly ignores sender pubkey bytes, two distinct signed
transactions with the same {inputs, actions, fee, epoch, expiration}
skeleton but different senders would share a `tx_hash`. This is a
**consensus-level concern** (transaction deduplication, mempool indexing,
double-spend detection may all key on `tx_hash`). MUST be investigated
and fixed before mainnet TGE.

## Fix path (separate PR)

1. Read `MisakaPublicKey::mcs1_encode` and confirm whether `bytes` is
   included in the encoded form.
2. If not, include `bytes` (length-prefixed) in the MCS-1 encoding.
3. Re-run `test_different_sender_tx_hash_differs` → expect pass.
4. Audit all other call sites that serialise `MisakaPublicKey` for the
   same omission (signature verification, address derivation).
5. Add a property test: for random `MisakaPublicKey` pairs `a != b`,
   `mcs1_encode(a) != mcs1_encode(b)`.

## Out of scope for this hotfix

`hotfix/peer-replay-window` targets consensus liveness (peer replay,
suspended blocks, self-equivocation false-positive). Transaction hashing
is in a different crate, the failure is pre-existing, and attempting
to fix it here would expand the blast radius of what must already be a
focused cherry-pickable hotfix.
