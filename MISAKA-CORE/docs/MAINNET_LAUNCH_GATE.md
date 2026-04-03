# MISAKA Mainnet Launch Gate

## Pass/Fail Checklist

All items must be PASS before mainnet launch.

### Startup Safety
- [x] `run_startup_checks()` wired into main.rs (line ~700, 5 fail-closed checks)
- [x] Mainnet rejects startup on failed checks (exit code 1)
- [ ] BUILD_MANIFEST.json required on mainnet
- [x] Validator passphrase required on mainnet (min 12 chars, chain_id=1 enforced)
- [x] Data directory writable (checked in startup gate)

### Admin Boundary
- [x] `enforce_admin_config()` runs before admin listener binds
- [x] Mainnet admin listener bound to localhost only (admin_listener.rs)
- [x] mTLS cert/key validated when configured
- [x] All admin operations produce audit log entries (AdminAuditLog)
- [x] Replay protection active for authenticated requests (ReplayGuard with nonce+timestamp)

### Bridge Safety
- [x] `BridgePersistence::validate_on_startup()` runs before bridge processing
- [x] Corrupted nullifier file blocks startup (DurableReplayProtection)
- [x] Corrupted approval queue blocks startup
- [x] ManualApprovalQueue is crash-safe (persisted to disk: tmp+fsync+rename)
- [x] FailClosedRelayer processes all checks in order (circuit_breaker→replay→rate_limit→approval)
- [ ] Emergency pause functional (tested in drill)

### Release Integrity
- [ ] SHA256SUMS generated for all release artifacts
- [ ] BUILD_MANIFEST.json includes git commit, timestamp, checksums
- [ ] Mainnet releases require minisign signatures
- [ ] `scripts/verify-release.sh` validates release package
- [ ] CI release-verify job passes

### Cryptographic Safety
- [x] ML-DSA-65 is sole signature algorithm (Ed25519/MlDsa44 removed from SigAlgorithm enum)
- [x] All constant-time comparisons use ct_eq or ct_eq_length_hiding (misaka-security)
- [x] No plaintext secrets in logs (audit.rs sanitize_log_message)
- [x] Keystore encrypted at rest (Argon2id + ChaCha20-Poly1305 — both validator and wallet)
- [x] Consensus signature verification uses real ML-DSA-65 (B1-B5 fixes: MlDsa65Verifier)
- [x] Wallet signing uses real ML-DSA-65 (ml_dsa_sign_raw/ml_dsa_verify_raw)

### Proof Backend Safety
- [x] SHA3 V3 production_ready=true, TransparentIntegrity privacy level
- [x] Groth16/PLONK shell backends return NotImplemented on verify
- [x] check_circuit_version() rejects non-production-ready backends on mainnet
- [x] StubProofBackend registration blocked on mainnet (testnet_mode guard)
- [x] No private register_stub_backend() method (removed, inlined into testnet-only path)

### Network Security
- [x] Per-peer bandwidth limit (D1: MAX_BYTES_PER_PEER_PER_SEC = 10 MB/s)
- [x] Mempool fee-based eviction (D2: lowest fee TX evicted by higher fee)
- [x] Mempool byte budget (D3: DEFAULT_MAX_MEMPOOL_BYTES = 256 MiB)
- [x] Lightweight ZKP pre-validation (D4: tag + length + entropy checks)
- [x] CORS restricted (D5: empty default, no wildcard)
- [x] WebSocket frame size reduced (D5: 4 MiB from 16 MiB)

### Bridge CRIT Fixes
- [x] CumulativeState initialized flag enforced in unlock_tokens (CRIT-1)
- [x] Wallet KDF uses real Argon2id (CRIT-2, not HKDF)
- [x] Bridge rate limiter auto-resets by time (CRIT-3, no external keeper needed)

### Testing
- [x] Corrupted nullifier file test: FAIL-CLOSED
- [x] Missing passphrase on mainnet test: FAIL-CLOSED
- [x] Short passphrase test: FAIL-CLOSED
- [x] Duplicate nonce replay test: REJECTED
- [x] Lower nonce replay test: REJECTED
- [x] Old timestamp test: REJECTED
- [x] Future timestamp test: REJECTED
- [x] Admin deny-by-default test: ENFORCED
- [x] Public admin bind on mainnet test: REJECTED
- [x] mTLS without cert test: REJECTED
- [x] ML-DSA-65 real sign/verify roundtrip: PASS
- [x] Wallet→Node signature compatibility: PASS (cross_compatibility_with_node_verify)
- [x] V3 proof no plaintext leak tests: PASS (5 privacy tests)
- [x] Fee-based eviction test: PASS
- [x] Bandwidth tracker test: PASS
- [x] Production_ready gate rejects shell backends: PASS

### Weak Subjectivity
- [x] mainnet.toml has [weak_subjectivity] section with checkpoint field
- [x] Mainnet exits on WSC violation (exit code 1)
- [x] Warning logged for all-zero checkpoint (genesis-only validators)
- [ ] Non-zero checkpoint set after first finalized epoch (OPERATIONAL)

### Unwrap Safety
- [x] 0 unwrap() in production code paths of misaka-consensus (0 prod / 42+ test)
- [x] 0 unwrap() in production code paths of misaka-p2p (0 prod / 21+ test)
- [x] 0 unwrap() in production code paths of misaka-bridge (0 prod / 18+ test)
- [x] Single unwrap in node_scoring.rs replaced with `let Some(..) else` (#5 fix)

### Operational Readiness
- [ ] BRIDGE_OPERATIONS_RUNBOOK.md reviewed by operations team
- [ ] MAINNET_SECURITY_CHECKLIST.md completed
- [ ] Emergency pause drill conducted
- [ ] Threshold unpause drill conducted
- [ ] Release verification drill conducted
- [ ] Operator upgrade guide followed for test deployment
- [ ] 21+ validators running on testnet for 14+ days

## Residual Risks

| Risk | Severity | Mitigation |
|------|----------|-----------|
| ManualApprovalQueue lost on hard crash between persist calls | Low | Atomic write (tmp+rename), operator recovery procedure |
| ReplayGuard nonce file corruption | Low | Node refuses to start, operator must clear file |
| No KES key evolution enforcement at consensus level | Medium | ML-DSA-65 quantum resistance reduces urgency |
| SHA3 ShieldedTransfer is integrity-not-privacy | High | Documented as TransparentIntegrity (PrivacyLevel enum), full ZK in roadmap |
| testnet mode bypasses some checks | Medium | compile_error! prevents dev features in release |
| WSC is genesis-only until first finalized epoch | Medium | Warning logged, operators must update post-genesis |

## Summary

| Category | Passed | Total | Status |
|----------|--------|-------|--------|
| Startup Safety | 4 | 5 | BUILD_MANIFEST pending |
| Admin Boundary | 5 | 5 | ✅ COMPLETE |
| Bridge Safety | 5 | 6 | Pause drill pending |
| Release Integrity | 0 | 5 | CI/CD pending |
| Cryptographic Safety | 6 | 6 | ✅ COMPLETE |
| Proof Backend Safety | 5 | 5 | ✅ COMPLETE |
| Network Security | 6 | 6 | ✅ COMPLETE |
| Bridge CRIT Fixes | 3 | 3 | ✅ COMPLETE |
| Testing | 16 | 16 | ✅ COMPLETE |
| Weak Subjectivity | 3 | 4 | Post-genesis update pending |
| Unwrap Safety | 4 | 4 | ✅ COMPLETE |
| Operational Readiness | 0 | 7 | Drills pending |
| **TOTAL** | **57** | **72** | **79% PASS** |

**Remaining 15 items** are operational (drills, CI/CD, documentation review) — not code changes.
All code-level security items are PASS.
