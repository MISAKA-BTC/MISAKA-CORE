# P2P Audit R3

## Verified Fixes
- ✅ IPv4-mapped IPv6 bogon filter: subnet.rs:73-75 decodes correctly
- ✅ Connection flooding defense: 3-layer (per-IP, global, per-subnet)

## CRITICAL
- **C2** secure_transport.rs:189 — Frame nonce replay within MAX_NONCE_GAP window.
  Out-of-order frames accepted → duplicate block processing → consensus divergence.
  Fix: Application-level idempotency for consensus messages + bind frame nonce to handshake.

## LOW
- **L3** handshake.rs:117 — verify_initiator Result not enforced by type system.
