# Hybrid Signature Design — Task 5.2

## Decision Required

ML-DSA-65 signature verification is the hot-path bottleneck in MISAKA.
This document compares two approaches. **The decision is deferred to the lead developer.**

## Option A: ML-DSA-65 Only (Current)

**Pro:**
- Pure post-quantum — no classical crypto dependency
- Single signature per block (3,309 bytes)
- Simple verification pipeline
- No migration complexity

**Con:**
- ML-DSA-65 verify: ~1ms per signature (vs Ed25519 ~0.05ms)
- 20x slower than classical signatures
- TPS ceiling: ~1,000 sig verifications/sec on single core
- Block processing becomes CPU-bound at high TPS

**Mitigation:**
- Task 5.1 batch verification with rayon parallelism
- 4-core system: ~4,000 verifications/sec
- Sufficient for v1.0 with < 1,000 TPS target

## Option B: Hybrid (ML-DSA-65 + Ed25519)

**Pro:**
- Hot path uses Ed25519 (0.05ms) for immediate verification
- ML-DSA-65 verified asynchronously after commit
- 20x throughput improvement on verify-bound workloads
- Graceful degradation: if quantum computer appears, Ed25519 fails
  but ML-DSA-65 still holds → safety preserved

**Con:**
- Double signature per block (3,309 + 64 = 3,373 bytes, ~2% overhead)
- Two key pairs per validator (Ed25519 + ML-DSA-65)
- Complex verification pipeline (fast path + deferred path)
- Ed25519 is quantum-vulnerable — if used for ordering decisions before
  ML-DSA verify completes, a quantum attacker can forge ordering
- Migration complexity: existing validators need Ed25519 key generation

**Architecture (if chosen):**
```
Block arrives → Ed25519 verify (fast, 0.05ms) → Accept into DAG
                                                      ↓
                                         Async ML-DSA verify queue
                                                      ↓
                                         Verified? → Commit
                                         Failed?  → Rollback from DAG
```

## Option C: ML-DSA-65 with SIMD/Batch Optimization

**Pro:**
- Pure PQ, no classical dependency
- NTT (Number Theoretic Transform) in ML-DSA is SIMD-friendly
- AVX2/NEON could reduce verify to ~0.3ms
- pqcrypto-dilithium may already use SIMD internally

**Con:**
- Depends on hardware support
- Still 6x slower than Ed25519
- Custom optimization needed (or wait for upstream)

## Recommendation

For v1.0, **Option A** is sufficient:
- Target TPS < 1,000
- 4-core rayon parallelism gives 4,000 verifies/sec headroom
- No quantum migration risk

For v1.1+, evaluate Option C (SIMD optimization) if TPS target increases.
Option B should only be considered if TPS > 10,000 is required.

## Decision

**[ ] Option A — ML-DSA-65 only (recommended for v1.0)**
[ ] Option B — Hybrid ML-DSA-65 + Ed25519
[ ] Option C — ML-DSA-65 with SIMD batch optimization
