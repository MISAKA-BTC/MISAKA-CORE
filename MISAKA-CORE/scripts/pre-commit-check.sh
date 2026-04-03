#!/usr/bin/env bash
set -euo pipefail

# Pre-commit secret scanner for MISAKA Network.
# Install: cp scripts/pre-commit-check.sh .git/hooks/pre-commit

echo "[pre-commit] Scanning staged files for secrets..."

STAGED=$(git diff --cached --name-only --diff-filter=ACM)

for file in $STAGED; do
    if [[ "$file" == *.rs ]] || [[ "$file" == *.toml ]] || [[ "$file" == *.json ]]; then
        # Check for hardcoded secrets
        if grep -nE 'PRIVATE_KEY\s*=|BEGIN.*PRIVATE.*KEY|sk_live_|password\s*=\s*"[^"]{8,}"' "$file" 2>/dev/null | grep -v 'test\|mock\|example'; then
            echo "BLOCKED: Potential secret in $file"
            exit 1
        fi
    fi
done

echo "[pre-commit] No secrets detected."
