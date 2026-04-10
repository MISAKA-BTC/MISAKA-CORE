#!/usr/bin/env bash
# Phase 2c-B D10: CI grep invariants
# Checks that deleted symbols, files, and patterns do not reappear.
# Exit non-zero on first violation.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FAIL=0

check_absent() {
    local pattern="$1"
    local description="$2"
    local scope="${3:-crates/ relayer/ wallet/}"
    # shellcheck disable=SC2086
    if grep -rn --include='*.rs' "$pattern" $scope 2>/dev/null; then
        echo "FAIL: $description"
        FAIL=1
    fi
}

check_absent_toml() {
    local pattern="$1"
    local description="$2"
    local scope="${3:-crates/ relayer/ wallet/}"
    # shellcheck disable=SC2086
    if grep -rn --include='*.toml' "$pattern" $scope 2>/dev/null; then
        echo "FAIL: $description"
        FAIL=1
    fi
}

cd "$ROOT"

echo "=== Phase 2c-B grep invariants ==="

# D5: Domain separation symbols deleted
check_absent "DOMAIN_NARWHAL_BLOCK"       "DOMAIN_NARWHAL_BLOCK must be deleted"
check_absent "DOMAIN_TX_SIGN"             "DOMAIN_TX_SIGN must be deleted"
check_absent "DOMAIN_PROPOSER_VRF"        "DOMAIN_PROPOSER_VRF must be deleted"
check_absent "DOMAIN_HEADER"              "DOMAIN_HEADER must be deleted"
check_absent "DOMAIN_CHECKPOINT_VOTE"     "DOMAIN_CHECKPOINT_VOTE must be deleted"
check_absent "DOMAIN_BRIDGE_AUTH"         "DOMAIN_BRIDGE_AUTH must be deleted"
check_absent "DOMAIN_VALIDATOR_REGISTER"  "DOMAIN_VALIDATOR_REGISTER must be deleted"
check_absent "DOMAIN_COMMIT_VOTE"         "DOMAIN_COMMIT_VOTE must be deleted"
check_absent "DOMAIN_FINALITY_ATTEST"     "DOMAIN_FINALITY_ATTEST must be deleted"
check_absent "DOMAIN_TXSCRIPT_CHECKSIG"   "DOMAIN_TXSCRIPT_CHECKSIG must be deleted"
check_absent "DOMAIN_BFT_PREVOTE"         "DOMAIN_BFT_PREVOTE must be deleted"
check_absent "DOMAIN_BFT_PRECOMMIT"       "DOMAIN_BFT_PRECOMMIT must be deleted"
check_absent "ml_dsa_sign_with_domain"    "ml_dsa_sign_with_domain must be deleted"
check_absent "ml_dsa_verify_with_domain"  "ml_dsa_verify_with_domain must be deleted"
check_absent "misaka_pqc::domains"        "misaka_pqc::domains module must be deleted"

# D5d: domains.rs file must not exist
if [ -f "crates/misaka-pqc/src/domains.rs" ]; then
    echo "FAIL: crates/misaka-pqc/src/domains.rs must be deleted"
    FAIL=1
fi

# D8: allow-tofu feature deleted
check_absent  "allow.tofu"  "allow-tofu feature must be deleted"
check_absent_toml "allow-tofu" "allow-tofu feature must be deleted from Cargo.toml"

# Verify cross_protocol_replay test deleted
if [ -f "crates/misaka-pqc/tests/cross_protocol_replay.rs" ]; then
    echo "FAIL: cross_protocol_replay.rs must be deleted"
    FAIL=1
fi

if [ "$FAIL" -eq 0 ]; then
    echo "ALL INVARIANTS PASSED"
else
    echo "INVARIANT VIOLATIONS FOUND"
    exit 1
fi
