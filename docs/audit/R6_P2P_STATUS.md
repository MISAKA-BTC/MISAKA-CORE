# R6 P2P Audit — Status and Findings

## Phase 36 Fixes Applied

### C-T6-1: Scaffolding deletion (3,409 lines)

7 files deleted — all were identical 487-line CRUD templates with no P2P functionality:
- relay_service.rs
- peer_discovery.rs
- message_router.rs
- flow_registry.rs
- flow_dispatcher.rs
- block_locator.rs
- address_exchange.rs

### C-T6-2: sync.rs (IBD state machine) — disabled

983-line Header-First IBD state machine exists but was never wired into production.
Module declaration commented out until Header-First sync is implemented.

### C-T6-3: SyncEngine — already cfg-gated

misaka-node/src/sync.rs is behind `#[cfg(not(feature = "dag"))]`.
Default build (dag feature) does NOT compile it. Not a production issue.

### HIGH-T6-1: Handshake identity binding

build_transcript with ValidatorPqPublicKey::zero() is flagged — validation added
to reject zero public keys.

### TOFU protection

allow-tofu feature has compile_error in release builds.

## Remaining issues for v1.1

- Handshake protocol v4: proper initiator identity binding (Noise IK pattern)
- IPv6 /56 subnet grouping for eclipse defense
- Per-peer bandwidth token bucket in secure_transport
- Half-open slot_id should be random, not sequential
- Nonce replay detection in responder (parallel handshake defense)
