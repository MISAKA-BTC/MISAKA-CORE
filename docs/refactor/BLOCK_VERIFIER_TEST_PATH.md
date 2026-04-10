# Block Verifier Test Path — CR-1 Fix (Phase 29)

## Problem

`StructuralVerifier` accepted ANY non-empty signature in test builds.
`DummySigner` produced fake signatures (`vec![0xAA; 64]`).

This meant test builds never exercised real ML-DSA-65 verification,
creating a fail-open path in `#[cfg(test)]` that could propagate to
production via `#[cfg(any(test, feature = "..."))]` additions.

## Solution: Option A — Same verify path in test and production

All tests now use:
- `MlDsa65Verifier` (production verifier) for signature checking
- `MlDsa65TestSigner` (real ML-DSA-65 keypair) for block signing
- `TestValidatorSet` (N real keypairs + committee builder)

No structural-only verifier exists. No fake signatures.

## Deleted types
- `StructuralVerifier` — accepted any non-empty sig (FAIL-OPEN)
- `DummySigner` — produced `vec![0xAA; 64]` (FAKE)

## New types (cfg(any(test, feature = "test-utils")))
- `MlDsa65TestSigner` — signs with real ML-DSA-65 keypair
- `TestValidatorSet` — generates N real keypairs, builds Committee + Verifier

## Test pattern

```rust
let tvs = TestValidatorSet::new(4);
let committee = tvs.committee();
let verifier = tvs.verifier(0);
let signer = tvs.signer(0); // Arc<dyn BlockSigner>

let mut engine = CoreEngine::new(0, 0, committee, signer, verifier);
```

## Regression tests (block_verifier.rs)

1. `cr1_arbitrary_bytes_signature_rejected` — garbage bytes at correct length
2. `cr1_impersonation_with_attacker_key_rejected` — signed with unknown key
3. `cr1_wrong_author_signature_rejected` — signed by validator 1, claimed as 0
4. `cr1_legitimate_signature_accepted` — properly signed block passes

## Future: Option B (type-level separation)

If stronger guarantees are needed, split into:
- `BlockVerifierProd` — production, no test bypass possible
- `BlockVerifierTest` — test, still uses real crypto but separate type

This is not needed for v1.0 since Option A already eliminates fail-open.
