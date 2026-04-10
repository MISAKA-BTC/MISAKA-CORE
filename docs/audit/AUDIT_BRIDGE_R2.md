# Bridge Audit R2

## Scope: crates/misaka-bridge/src/ (1,933 lines, 7 files)

## CRITICAL

### C1: Nonce replay across request IDs
- **File:** lib.rs:111, verifier.rs:206
- **Problem:** `proof.nonce` is used in signature but NOT validated as monotonic. Same nonce replayed with different `request_id` bypasses replay protection.
- **Attack:** Replay old authorization proof against new request_id.
- **Fix:** Include `proof.nonce` in replay set, or enforce monotonic nonce per authorization context.

### C2: No permission model for mint/burn
- **File:** lib.rs:102-142
- **Problem:** `process_lock_event()` accepts any caller with valid committee signature. `request.sender` is not verified against proof identity. `identity_commitment` field is unused.
- **Attack:** Committee member mints for any recipient with any amount.
- **Fix:** Bind authorization proof to (sender, recipient, amount) tuple. Verify sender identity.

### C3: Signature nonce not bound to request_id
- **File:** request.rs:48-60, verifier.rs:155-206
- **Problem:** Request hash and signing message use separate nonce values. Signature for (request_A, nonce=1) can verify against (request_B, nonce=1).
- **Fix:** Include request_id in signing message, or derive proof nonce from request nonce.

## HIGH

### H1: CumulativeState zeros on restart (circuit_breaker.rs:200-216)
### H2: identity_commitment unused (verifier.rs:26)
### H3: Committee verifier doesn't validate scheme (verifier.rs:106-152)
### H4: Domain tags defined in bridge logic, not enforced by verifier (lib.rs:36-40)
### H5: Replay protection unbounded growth (replay.rs:102-104)

## MEDIUM

### M1: MockVerifier feature gate not compile_error in release (verifier.rs:53)
### M2: DurableReplayProtection no file locking (replay.rs:108-116)
### M3: request_id not validated for uniqueness (lib.rs:111)
### M4: AssetRegistry has no access control (registry.rs:26-54)

## LOW

### L1: No bounds on request amount (request.rs:33)
### L2: identity_commitment is dead field (verifier.rs:26)
### L3: Test doesn't call validate_verifier_for_production (lib.rs:277)
