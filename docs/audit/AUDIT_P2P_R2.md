# P2P Audit R2

## Scope: crates/misaka-p2p/src/

## CRITICAL

### C1: Handshake PK not validated against genesis validator set (handshake.rs:159-171)
- **Problem:** `complete_verified()` checks PK matches `expected_responder_pk` but does NOT verify that PK is in the active validator set. Attacker can impersonate non-existent validators.
- **Attack:** Fake validator with arbitrary keypair → accepted into peer set → eclipse attack.
- **Fix:** Add `validator_set: &ValidatorSet` parameter, verify PK membership.

## HIGH

### H1: IPv4-mapped IPv6 bypasses bogon filter (connection_guard.rs:429-456)
- `::ffff:192.168.1.1` passes bogon check because IPv6 path doesn't decode IPv4-mapped addresses.
- Fix: Decode `::ffff:x.x.x.x` → recurse on IPv4 bogon check.

## MEDIUM

### M1: Nonce replay window not enforced (handshake.rs:375-383)
- Random nonce generated but not tracked. Replay after node restart possible.
- Fix: `used_nonces: HashSet<[u8;32]>` with TTL.

### M2: Connection flooding off-by-one (connection_guard.rs:277-287)
- `retain()` before `len()` check allows MAX+1 attempts per window.
- Fix: Check AFTER push, or check BEFORE push with `>=`.
