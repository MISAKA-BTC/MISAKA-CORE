# R4 Audit Regression Guard

All 4 CRITICALs + HIGHs from R4 have regression tests that would
have failed before the fix.

## CR-1: BlockVerifier cfg(test) fail-open (Phase 29)

**Root cause**: StructuralVerifier accepted any non-empty signature.
**Fix**: Deleted StructuralVerifier/DummySigner, all tests use real ML-DSA-65.
**Regression tests** (block_verifier.rs):
- `cr1_arbitrary_bytes_signature_rejected` — garbage sig rejected
- `cr1_impersonation_with_attacker_key_rejected` — wrong key rejected
- `cr1_wrong_author_signature_rejected` — sig from validator 1 claiming to be 0
- `cr1_legitimate_signature_accepted` — positive case

## CR-2: compute_hash missing chain_id/genesis_hash (Phase 30)

**Root cause**: Block digest had no chain context binding.
**Fix**: `Block::signing_digest(chain_ctx)` includes ChainContext digest.
**Regression tests** (block_verifier.rs):
- `cr2_testnet_block_rejected_on_mainnet` — chain_id=2 sig fails on chain_id=1
- `cr2_fork_block_rejected_on_main_chain` — same chain_id, different genesis
- `cr2_same_chain_context_verifies` — positive case

## CR-3: EquivocationDetector payload_digest-only comparison (Phase 31)

**Root cause**: Same payload + different parents was classified as Duplicate.
**Fix**: Compare on `block_id` (canonical hash including parents).
**Regression tests** (equivocation_detector.rs):
- `cr3_same_payload_different_parents_detected_as_equivocation`
  Before fix: Duplicate (BUG). After fix: Equivocation.
- `cr3_same_block_id_is_duplicate` — idempotency preserved
- `cr3_different_payload_different_block_id_detected` — baseline

## CR-4: Bridge tests reference deleted ml_dsa_sign_raw (Phase 32)

**Root cause**: Phase 19 deleted raw API but missed bridge test grep.
**Fix**: Replaced with `ml_dsa_sign_with_domain(sk, BRIDGE_AUTH_DOMAIN, msg)`.
**CI gate**: feature-safety.yml grep for ml_dsa_sign_raw returns 0 hits.

## HI-4: MAX_PARENTS bound check (Phase 32)

**Fix**: `MAX_ANCESTORS = 1024`, early reject in check_ancestors().

## HI-8: Timestamp past drift (Phase 32)

**Fix**: `MAX_TIMESTAMP_PAST_DRIFT_MS = 60_000`, reject in check_timestamp().
