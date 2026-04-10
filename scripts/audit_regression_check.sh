#!/usr/bin/env bash
# audit_regression_check.sh -- D5: Regression guard for security audit fixes.
#
# Exits non-zero on the first failed check so CI breaks immediately.
# Run from the repository root: ./scripts/audit_regression_check.sh

set -euo pipefail

PASS=0
FAIL=0
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

pass() { PASS=$((PASS + 1)); echo "  PASS  $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  FAIL  $1"; }

echo "=== MISAKA-CORE audit regression checks ==="
echo ""

# ── A1: No crypto stub files ────────────────────────────────────
echo "[A1] No crypto stub files"
STUBS=$(find "$ROOT/crates/misaka-crypto/src" "$ROOT/crates/misaka-pqc/src" \
        -name '*stub*' -o -name '*dummy*' -o -name '*mock_crypto*' 2>/dev/null || true)
if [ -z "$STUBS" ]; then
    pass "no crypto stub files found"
else
    fail "crypto stub files exist: $STUBS"
fi

# ── A2: Zero pubkey check in pq_sign.rs ─────────────────────────
echo "[A2] Zero pubkey check in pq_sign.rs"
if grep -q 'all(|&b| b == 0)' "$ROOT/crates/misaka-pqc/src/pq_sign.rs"; then
    pass "pq_sign.rs rejects zero pubkey"
else
    fail "pq_sign.rs missing zero pubkey rejection"
fi

# ── A3: Zero pubkey check in validator_sig.rs ────────────────────
echo "[A3] Zero pubkey check in validator_sig.rs"
if grep -q 'zero pubkey forbidden' "$ROOT/crates/misaka-crypto/src/validator_sig.rs"; then
    pass "validator_sig.rs rejects zero pubkey in from_bytes"
else
    fail "validator_sig.rs missing zero pubkey rejection in from_bytes"
fi

# ── B1a: apply_transaction_anonymous must not exist ──────────────
echo "[B1a] apply_transaction_anonymous removed"
if grep -rq 'fn apply_transaction_anonymous' "$ROOT/crates/misaka-storage/src/utxo_set.rs"; then
    fail "apply_transaction_anonymous still exists"
else
    pass "apply_transaction_anonymous removed"
fi

# ── B1b: apply_transaction exists ────────────────────────────────
echo "[B1b] apply_transaction exists"
if grep -q 'fn apply_transaction' "$ROOT/crates/misaka-storage/src/utxo_set.rs"; then
    pass "apply_transaction present"
else
    fail "apply_transaction missing"
fi

# ── B1c: delta.spent populated (remove_output called) ───────────
echo "[B1c] delta.spent populated via remove_output"
if grep -q 'remove_output' "$ROOT/crates/misaka-storage/src/utxo_set.rs"; then
    pass "remove_output called in utxo_set (delta.spent populated)"
else
    fail "remove_output not found in utxo_set.rs"
fi

# ── B3: mempool spent_inputs exists ──────────────────────────────
echo "[B3] mempool spent_inputs"
if grep -rq 'spent_inputs' "$ROOT/crates/misaka-mempool/src/"; then
    pass "mempool tracks spent_inputs"
else
    fail "mempool spent_inputs missing"
fi

# ── B4: executor input dedup (seen_outrefs) ──────────────────────
echo "[B4] executor input dedup (seen_outrefs)"
if grep -rq 'seen_outrefs' "$ROOT/crates/misaka-node/src/utxo_executor.rs"; then
    pass "executor deduplicates input outrefs"
else
    fail "executor seen_outrefs dedup missing"
fi

# ── B5: utxos_spent not hardcoded to 0 ──────────────────────────
echo "[B5] utxos_spent not hardcoded to 0"
if grep -Eq 'utxos_spent[[:space:]]*[:=][[:space:]]*0' "$ROOT/crates/misaka-execution/src/block_apply.rs"; then
    fail "utxos_spent hardcoded to 0"
else
    pass "utxos_spent not hardcoded to 0"
fi

# ── D1: tx_sig used in attestation_digest ────────────────────────
echo "[D1] tx_sig not unused in attestation_digest"
if grep -A 20 'fn attestation_digest' "$ROOT/relayer/src/attestation.rs" | grep -q 'tx_sig'; then
    pass "tx_sig is used inside attestation_digest"
else
    fail "tx_sig appears unused in attestation_digest"
fi

# ── Summary ──────────────────────────────────────────────────────
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    echo "REGRESSION DETECTED -- fix before merge."
    exit 1
fi

echo "All audit regression checks passed."
exit 0
