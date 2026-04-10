#!/usr/bin/env bash
# Phase 2c-B D11: Binary surface scan
# Checks release binaries for forbidden strings that should not appear
# in production artifacts (debug remnants, deleted domain tags, etc.).
# Run after `cargo build --workspace --release`.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TARGET_DIR="${ROOT}/target/release"
FAIL=0

FORBIDDEN_STRINGS=(
    "DOMAIN_NARWHAL_BLOCK"
    "DOMAIN_TX_SIGN"
    "DOMAIN_PROPOSER_VRF"
    "DOMAIN_CHECKPOINT_VOTE"
    "DOMAIN_BRIDGE_AUTH"
    "DOMAIN_VALIDATOR_REGISTER"
    "DOMAIN_COMMIT_VOTE"
    "DOMAIN_FINALITY_ATTEST"
    "DOMAIN_TXSCRIPT_CHECKSIG"
    "DOMAIN_BFT_PREVOTE"
    "DOMAIN_BFT_PRECOMMIT"
    "ml_dsa_sign_with_domain"
    "ml_dsa_verify_with_domain"
    "allow-tofu"
    "PermissiveVerifier"
)

BINARIES=(
    "misaka-node"
    "misaka-cli"
)

echo "=== Phase 2c-B binary surface scan ==="

for bin in "${BINARIES[@]}"; do
    bin_path="${TARGET_DIR}/${bin}"
    if [ ! -f "$bin_path" ]; then
        echo "SKIP: ${bin} not found at ${bin_path}"
        continue
    fi
    echo "Scanning: ${bin}"
    for pattern in "${FORBIDDEN_STRINGS[@]}"; do
        if strings "$bin_path" | grep -q "$pattern"; then
            echo "  FAIL: found forbidden string '${pattern}' in ${bin}"
            FAIL=1
        fi
    done
done

if [ "$FAIL" -eq 0 ]; then
    echo "ALL BINARIES CLEAN"
else
    echo "FORBIDDEN STRINGS FOUND IN BINARIES"
    exit 1
fi
