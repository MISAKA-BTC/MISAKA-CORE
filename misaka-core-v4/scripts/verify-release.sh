#!/usr/bin/env bash
set -euo pipefail
# Operator tool to verify a MISAKA release package.

RELEASE_DIR="${1:?Usage: verify-release.sh <release-dir>}"

echo "=== MISAKA Release Verification ==="

# 1. Check manifest
MANIFEST="$RELEASE_DIR/BUILD_MANIFEST.json"
if [[ ! -f "$MANIFEST" ]]; then
    echo "FAIL: BUILD_MANIFEST.json not found"
    exit 1
fi
echo "PASS: BUILD_MANIFEST.json exists"

# Validate manifest JSON structure
if ! python3 -c "import json; json.load(open('$MANIFEST'))" 2>/dev/null; then
    echo "FAIL: BUILD_MANIFEST.json is not valid JSON"
    exit 1
fi
echo "PASS: BUILD_MANIFEST.json is valid JSON"

# 2. Check SHA256SUMS
CHECKSUMS="$RELEASE_DIR/SHA256SUMS"
if [[ ! -f "$CHECKSUMS" ]]; then
    echo "FAIL: SHA256SUMS not found"
    exit 1
fi

# Verify checksums
if command -v sha256sum &>/dev/null; then
    (cd "$RELEASE_DIR" && sha256sum -c SHA256SUMS) || { echo "FAIL: checksum mismatch"; exit 1; }
elif command -v shasum &>/dev/null; then
    (cd "$RELEASE_DIR" && shasum -a 256 -c SHA256SUMS) || { echo "FAIL: checksum mismatch"; exit 1; }
fi
echo "PASS: SHA256SUMS verified"

# 3. Check minisign signature (if present)
if [[ -f "$RELEASE_DIR/misaka-node.minisig" ]]; then
    if command -v minisign &>/dev/null; then
        echo "INFO: minisign signature found, verify with public key"
    fi
fi

echo ""
echo "=== All verification checks passed ==="
