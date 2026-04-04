# MISAKA Security Advisories

## Active Advisories (2026-04-04)

### ADV-1: tracing-subscriber 0.2.25 (RUSTSEC-2025-0055)

**Severity:** High (advisory) / Low (actual risk)
**Component:** Root Cargo.lock — transitive dependency via `ark-std` (arkworks)
**Issue:** ANSI escape code injection in log output
**Status:** MITIGATED — 0.2.25 is compiled but never initialized as the active
tracing subscriber. MISAKA uses `tracing-subscriber 0.3.23` as the active subscriber.
The 0.2.25 version is pulled in by `ark-std` which is used by the optional
Groth16/PLONK verifier backends (currently Shell status, not active in production).
**Resolution:** Will be resolved when arkworks upgrades their `tracing-subscriber`
dependency. No action required from MISAKA operators.

### ADV-2: curve25519-dalek 3.2.1 (RUSTSEC-2024-0344)

**Severity:** High (advisory) / Low (actual risk for MISAKA)
**Component:** solana-bridge/Cargo.lock — transitive via Solana SDK 1.18.x
**Issue:** Timing side-channel in Ed25519 verification
**Status:** ACCEPTED — This affects the Solana bridge's Ed25519 precompile path,
which is a Solana-native operation. The MISAKA L1 chain uses ML-DSA-65 (post-quantum)
and is not affected. Bridge operations go through Solana's Ed25519 precompile
which has its own implementation separate from this library.
**Resolution:** Upgrade to Solana SDK 2.x / Anchor 0.33+ when available.

### ADV-3: ed25519-dalek 1.0.1 (RUSTSEC-2022-0093)

**Severity:** High (advisory) / Low (actual risk for MISAKA)
**Component:** solana-bridge/Cargo.lock — transitive via Solana SDK 1.18.x
**Issue:** Double public key signing oracle
**Status:** ACCEPTED — Same as ADV-2. Solana SDK dependency, not directly used by MISAKA.
**Resolution:** Upgrade with Solana SDK.

### ADV-4: npm audit high x5 (solana-bridge)

**Severity:** High (advisory) / Medium (actual risk)
**Component:** solana-bridge/package-lock.json
**Issues:**
- `bigint-buffer` via `@solana/spl-token` — prototype pollution
- `serialize-javascript` via `mocha` — code injection in test runner
**Status:** ACCEPTED — `mocha` is dev-only (test runner, not production).
`bigint-buffer` is used at build time only, not in the deployed Solana program.
**Resolution:** Do NOT run `npm audit fix --force` — this breaks Anchor compatibility.
Upgrade when Anchor 0.33+ is released with updated dependencies.

## Resolved Advisories

### [RESOLVED] Command injection in generate-l1-key.js

**Fixed:** 2026-04-04
**Issue:** `execSync` with string concatenation allowed shell metacharacter injection
via `--name` and `--data-dir` arguments.
**Fix:** Replaced all `execSync` with `execFileSync` (array arguments, no shell).

### [RESOLVED] Command injection in start-validator.js

**Fixed:** 2026-04-04
**Issue:** Binary existence check used `execSync` with template string.
**Fix:** Replaced with `execFileSync(p, ["--version"])`.
