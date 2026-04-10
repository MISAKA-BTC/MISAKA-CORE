#!/bin/bash
# CI lint: Verify no protocol constants are redefined outside misaka-protocol-config.
#
# This script greps for literal values that should ONLY be defined in
# misaka-protocol-config. If any are found in other crates (excluding
# re-exports and references to the config), the build fails.
#
# Usage: ./scripts/check_no_scattered_constants.sh
# Exit code: 0 = clean, 1 = scattered constants found

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROTOCOL_CONFIG="crates/misaka-protocol-config"
VIOLATIONS=0

echo "=== Checking for scattered protocol constants ==="

# Check for ML-DSA size literals defined as consts outside protocol-config
for pattern in "1952" "4032" "3309" "1184" "1088"; do
    hits=$(grep -rn "const.*=.*${pattern}" "$REPO_ROOT/crates/" --include="*.rs" \
        | grep -v "$PROTOCOL_CONFIG" \
        | grep -v "target/" \
        | grep -v "// re-export\|// from protocol-config\|protocol_config" \
        | grep -v "test\|Test\|#\[test\]" \
        || true)
    if [ -n "$hits" ]; then
        echo "VIOLATION: ML-DSA/KEM size constant $pattern defined outside protocol-config:"
        echo "$hits"
        VIOLATIONS=$((VIOLATIONS + 1))
    fi
done

# Check for BFT threshold defined as literal
hits=$(grep -rn "6667\|const.*QUORUM.*BPS" "$REPO_ROOT/crates/" --include="*.rs" \
    | grep -v "$PROTOCOL_CONFIG" \
    | grep -v "target/" \
    | grep -v "// \|///\|test\|Test" \
    || true)
if [ -n "$hits" ]; then
    echo "VIOLATION: BFT quorum threshold defined outside protocol-config:"
    echo "$hits"
    VIOLATIONS=$((VIOLATIONS + 1))
fi

echo ""
if [ "$VIOLATIONS" -gt 0 ]; then
    echo "FAILED: $VIOLATIONS scattered constant violation(s) found."
    echo "Move these to crates/misaka-protocol-config/src/lib.rs"
    exit 1
else
    echo "PASSED: No scattered protocol constants found."
    exit 0
fi
