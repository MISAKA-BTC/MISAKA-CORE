# ChipmunkRing Parameter Audit — MISAKA Network

**Status: UNAUDITED — Requires external cryptographic review before mainnet.**

## Parameter Set (Production Candidate)

| Parameter | Symbol | Value | Description |
|-----------|--------|-------|-------------|
| Ring modulus | q | 12,289 | NTT-friendly prime (14-bit) |
| Poly degree | n | 256 | R_q = Z_q[X]/(X^256+1) |
| Secret bound | η | 2 | s_i ∈ {-2, -1, 0, 1, 2} |
| Challenge weight | τ | 46 | # nonzero ±1 in challenge |
| Masking bound | γ | 8,192 | y_i ∈ [-γ+1, γ-1] |
| Rejection threshold | β | 8,100 | γ − τ·η = 8192 − 92 |
| Min ring size | | 4 | |
| Max ring size | | 32 | |
| Max sign attempts | | 512 | |

## Security Analysis

### Challenge Space
- C(256, 46) · 2^46 ≈ 2^198 >> 2^128
- Sufficient for 128-bit security

### Rejection Sampling
- Acceptance probability: Pr[‖z‖_∞ < β] ≈ (β/γ)^n ≈ (8100/8192)^256 ≈ 0.93
- Expected attempts: ~1.07 (very efficient)
- No timing side-channel from iteration count (inherent to lattice rejection sampling)

### Norm Bounds
- Response norm: ‖z‖_∞ < 8100 (strict less-than, enforced in code)
- Masking norm: ‖y‖_∞ ≤ 8191
- Secret norm: ‖s‖_∞ ≤ 2
- Challenge·secret: ‖c·s‖_∞ ≤ τ·η = 92

### γ/τη Margin
- γ/(τ·η) = 8192/92 ≈ 89x
- This is the critical ratio — larger means better security margin
- For comparison: Dilithium-II uses ~120x

### Known Limitations

1. **Polynomial multiplication** uses NTT which is not constant-time for all implementations.
   Current code uses schoolbook multiplication via `Poly::mul()`.

2. **Rejection sampling loop count** leaks via timing. This is inherent to
   lattice Σ-protocols and accepted in practice (same as Dilithium).

3. **No batch verification** implemented yet. Individual verification only.

## Items Requiring External Review

- [ ] Verify η=2 provides sufficient security margin for n=256, q=12289
- [ ] Verify γ/τη ratio is adequate (currently ~89x)
- [ ] Review challenge generation for collision resistance
- [ ] Review response norm checking for fail-open conditions
- [ ] Verify ring signature composition (hash-chain) is sound
- [ ] Review KI proof Σ-protocol for zero-knowledge property
- [ ] Assess side-channel resistance of polynomial operations
- [ ] Verify domain separation tags are unique and sufficient

## Code Locations

| Component | File | Function |
|-----------|------|----------|
| Parameter struct | `chipmunk.rs` | `ChipmunkParams`, `PARAMS_PRODUCTION` |
| Compile-time validation | `chipmunk.rs` | `const _: () = assert!(...)` |
| Challenge generation | `chipmunk.rs` | `cr_hash_to_challenge()` |
| Masking sampling | `chipmunk.rs` | `cr_sample_masking()` |
| Response sampling | `chipmunk.rs` | `cr_sample_response()` |
| Sign | `chipmunk.rs` | `chipmunk_ring_sign()` |
| Verify | `chipmunk.rs` | `chipmunk_ring_verify()` |
| Norm check | `chipmunk.rs` | `sig.responses[i].norm_inf() >= CR_BETA` |
| KI proof | `chipmunk.rs` | `chipmunk_prove_ki()` / `chipmunk_verify_ki()` |
| Boundary tests | `chipmunk.rs` | `test_response_norm_at_boundary` etc. |

## Test Coverage

| Test | Purpose |
|------|---------|
| `test_production_params_valid` | Compile-time + runtime param consistency |
| `test_beta_equals_gamma_minus_tau_eta` | β = γ − τη identity |
| `test_gamma_margin_over_tau_eta` | γ >> τη security margin |
| `test_ring_too_small_rejected` | min ring size enforcement |
| `test_ring_too_large_rejected` | max ring size enforcement |
| `test_signer_index_oob_rejected` | index bounds |
| `test_tampered_response_rejected` | forgery detection |
| `test_tampered_c0_rejected` | challenge forgery detection |
| `test_response_norm_at_boundary` | boundary value: norm = β rejected |
| `test_malformed_sig_bytes_rejected` | deserialization safety |
| `test_malformed_ki_proof_bytes_rejected` | KI proof deserialization safety |

---

*Document version: 0.4.1*
*Last updated: 2025*
*Status: Pre-audit*
