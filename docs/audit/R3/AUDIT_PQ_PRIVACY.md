# PQ Privacy Audit R3

## Verified
- ✅ Nullifier algebraic soundness (nullifier.rs): Σ-protocol + Fiat-Shamir correct
- ✅ Key image proof strong binding (ki_proof.rs): dual-statement verified
- ✅ Canonical key image (canonical_ki.rs): scheme-independent

## HIGH
- **H4** stealth_v2.rs:102 — HKDF salt misuse. tx_context used as salt instead of
  fixed protocol identifier. Collision risk if serialization changes.
  Fix: Use fixed salt `b"MISAKA_STEALTH_V2_SALT"`, move tx_context to info parameter.
