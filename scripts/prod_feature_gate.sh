#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# P0-4: Production Feature Gate — CI/CD Script
# ═══════════════════════════════════════════════════════════════
#
# Ensures dangerous dev-only features are NOT enabled in production
# builds. Run this BEFORE releasing any binary.
#
# Exit codes:
#   0 = PASS (all checks green)
#   1 = FAIL (dangerous features detected)
#
# Usage:
#   ./scripts/prod_feature_gate.sh                # default profile (release)
#   ./scripts/prod_feature_gate.sh --profile dev  # check dev profile (should warn)
#
# What this catches:
#   - `dev-rpc` feature (exposes get_address_outputs → privacy leak)
#   - `dev` feature (enables complete_unverified_for_dev → MITM)
#   - `faucet` feature (enables faucet endpoint on node RPC)
#   - `swagger-cdn` feature (loads JS from external CDN)
#   - `stark-stub` feature (mock ZKP verifier → accepts any proof)
#   - `experimental-privacy` feature (dev alias that currently enables stub path)
#   - malformed Groth16/PLONK VK artifacts when explicit VK paths are configured
#   - real backend bootstrap requested before production adapters exist

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROFILE="${1:-release}"

echo "═══════════════════════════════════════════════════════════"
echo " P0-4: Production Feature Gate Check"
echo " Profile: $PROFILE"
echo " Repo: $REPO_ROOT"
echo "═══════════════════════════════════════════════════════════"
echo ""

FAIL=0

# ── 1. Check Cargo.toml default features ──
echo "── [1/5] Checking workspace default features ──"

DANGEROUS_FEATURES=("dev-rpc" "dev" "faucet" "swagger-cdn" "stark-stub" "experimental-privacy")

for toml_file in $(find "$REPO_ROOT/crates" "$REPO_ROOT/relayer" -name "Cargo.toml" -maxdepth 2 2>/dev/null); do
    crate_name=$(basename "$(dirname "$toml_file")")

    for feat in "${DANGEROUS_FEATURES[@]}"; do
        # Check if the feature is in [features] default = [...]
        if grep -qP '^\s*default\s*=\s*\[.*"'"$feat"'"' "$toml_file" 2>/dev/null; then
            echo -e "  ${RED}FAIL${NC}: $crate_name has '$feat' in default features!"
            FAIL=1
        fi
    done
done

if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}PASS${NC}: No dangerous features in default profiles"
fi

# ── 2. Check for #[cfg(not(feature = "dev"))] guard on sensitive functions ──
echo ""
echo "── [2/5] Checking dev-guard on sensitive functions ──"

# complete_unverified_for_dev must be behind #[cfg(feature = "dev")]
DEV_FN_FILE=$(grep -rl "fn complete_unverified_for_dev" "$REPO_ROOT/crates/" --include="*.rs" | head -1)
if [ -n "$DEV_FN_FILE" ]; then
    DEV_FN_LINE=$(grep -n "fn complete_unverified_for_dev" "$DEV_FN_FILE" | head -1 | cut -d: -f1)
    PREV_LINE=$((DEV_FN_LINE - 1))
    CFG_CHECK=$(sed -n "${PREV_LINE}p" "$DEV_FN_FILE" | grep '#\[cfg(feature.*dev')
    if [ -z "$CFG_CHECK" ]; then
        echo -e "  ${RED}FAIL${NC}: complete_unverified_for_dev() NOT behind cfg(feature = \"dev\")"
        echo "        $DEV_FN_FILE:$DEV_FN_LINE"
        FAIL=1
    else
        echo -e "  ${GREEN}PASS${NC}: complete_unverified_for_dev() is properly feature-gated"
    fi
else
    echo -e "  ${GREEN}PASS${NC}: complete_unverified_for_dev() not found (removed)"
fi

# get_address_outputs must be behind #[cfg(feature = "dev-rpc")]
ADDR_FILES=$(grep -rl "get_address_outputs" "$REPO_ROOT/crates/" --include="*.rs" 2>/dev/null)
ADDR_UNGUARDED=0
for f in $ADDR_FILES; do
    # Check each occurrence — look at the 3 lines above for cfg(feature
    while IFS=: read -r line_num _; do
        CONTEXT=$(sed -n "$((line_num > 3 ? line_num - 3 : 1)),${line_num}p" "$f")
        if echo "$CONTEXT" | grep -q '#\[cfg(feature.*dev-rpc'; then
            : # guarded, OK
        elif echo "$CONTEXT" | grep -q '// \|/// \|#\[test\]\|mod tests'; then
            : # comment or test, OK
        else
            echo -e "  ${RED}FAIL${NC}: get_address_outputs at $f:$line_num NOT behind cfg(feature = \"dev-rpc\")"
            ADDR_UNGUARDED=1
        fi
    done < <(grep -n "get_address_outputs" "$f" | grep "route\|fn ")
done
if [ "$ADDR_UNGUARDED" -eq 0 ]; then
    echo -e "  ${GREEN}PASS${NC}: get_address_outputs is properly feature-gated"
else
    FAIL=1
fi

# ── 3. Check for placeholder/test addresses in production code ──
echo ""
echo "── [3/5] Checking for placeholder addresses ──"

PLACEHOLDERS=$(grep -rn '\[0x01; 32\]\|\[0x02; 32\]\|"xxxxxxx"\|"XXXXXXX"\|TODO.*mainnet\|FIXME.*mainnet' \
    "$REPO_ROOT/crates/" "$REPO_ROOT/relayer/src/" \
    --include="*.rs" \
    | grep -v "#\[cfg(test)\]" \
    | grep -v "mod tests" \
    | grep -v "// test" \
    | grep -v "#[test]" \
    | head -10)

if [ -n "$PLACEHOLDERS" ]; then
    echo -e "  ${YELLOW}WARN${NC}: Potential placeholder values found:"
    echo "$PLACEHOLDERS" | while read -r line; do
        echo "        $line"
    done
else
    echo -e "  ${GREEN}PASS${NC}: No placeholder addresses detected"
fi

# ── 4. Check for external CDN URLs in non-gated code ──
echo ""
echo "── [4/5] Checking for ungated external CDN references ──"

CDN_FAIL=0
for src_file in $(grep -rl "unpkg.com\|cdnjs.cloudflare\|cdn.jsdelivr" "$REPO_ROOT/crates/" --include="*.rs" 2>/dev/null); do
    while IFS=: read -r line_num line_content; do
        # Skip comment lines (// or //!)
        stripped=$(echo "$line_content" | sed 's/^[[:space:]]*//')
        if [[ "$stripped" == //* ]]; then
            continue
        fi
        # Check 20 lines above for the cfg gate (the block can be several lines up)
        START=$((line_num > 20 ? line_num - 20 : 1))
        CONTEXT=$(sed -n "${START},${line_num}p" "$src_file")
        if echo "$CONTEXT" | grep -q '#\[cfg(feature.*swagger-cdn'; then
            : # guarded, OK
        else
            echo -e "  ${RED}FAIL${NC}: Ungated CDN at $src_file:$line_num"
            CDN_FAIL=1
        fi
    done < <(grep -n "unpkg.com\|cdnjs.cloudflare\|cdn.jsdelivr" "$src_file")
done

if [ "$CDN_FAIL" -ne 0 ]; then
    FAIL=1
else
    echo -e "  ${GREEN}PASS${NC}: All CDN references are feature-gated"
fi

# ── 5. Check for unwrap/expect on network-input paths ──
echo ""
echo "── [5/5] Checking for unsafe unwrap on network input paths ──"

# Count unwrap/expect in P2P and RPC paths (informational, not blocking)
UNWRAP_COUNT=$(grep -rn '\.unwrap()\|\.expect(' \
    "$REPO_ROOT/crates/misaka-node/src/dag_p2p_transport.rs" \
    "$REPO_ROOT/crates/misaka-node/src/dag_p2p_network.rs" \
    "$REPO_ROOT/crates/misaka-node/src/rpc_server.rs" \
    "$REPO_ROOT/crates/misaka-node/src/dag_rpc.rs" \
    2>/dev/null \
    | grep -v "#\[cfg(test)\]" \
    | grep -v "mod tests" \
    | grep -v "expect(\"static" \
    | wc -l)

if [ "$UNWRAP_COUNT" -gt 20 ]; then
    echo -e "  ${YELLOW}WARN${NC}: $UNWRAP_COUNT unwrap/expect calls in network-facing code (review recommended)"
else
    echo -e "  ${GREEN}INFO${NC}: $UNWRAP_COUNT unwrap/expect calls in network-facing code"
fi

# ── 6. Check configured shielded VK artifacts (optional) ──
echo ""
echo "── [6/6] Checking configured shielded VK artifacts ──"

if [ -n "${MISAKA_SHIELDED_GROTH16_VK_PATH:-}" ] || [ -n "${MISAKA_SHIELDED_PLONK_VK_PATH:-}" ]; then
    VK_INSPECT_DIR="${MISAKA_SHIELDED_VK_INSPECT_DIR:-$REPO_ROOT/.tmp/shielded-vk-artifact-inspect-prod-gate}"
    if MISAKA_SHIELDED_VK_INSPECT_DIR="$VK_INSPECT_DIR" \
        MISAKA_SHIELDED_GROTH16_VK_PATH="${MISAKA_SHIELDED_GROTH16_VK_PATH:-}" \
        MISAKA_SHIELDED_PLONK_VK_PATH="${MISAKA_SHIELDED_PLONK_VK_PATH:-}" \
        bash "$REPO_ROOT/scripts/shielded_vk_artifact_inspect.sh" >/dev/null; then
        echo -e "  ${GREEN}PASS${NC}: Configured shielded VK artifacts passed preflight"
        echo "        artifact: $VK_INSPECT_DIR/result.json"
    else
        echo -e "  ${RED}FAIL${NC}: Configured shielded VK artifacts failed preflight"
        echo "        artifact: $VK_INSPECT_DIR/result.json"
        FAIL=1
    fi
else
    echo -e "  ${GREEN}INFO${NC}: No explicit shielded VK artifact paths configured"
fi

REAL_BACKEND_BOOTSTRAP="${MISAKA_SHIELDED_REAL_BACKEND_BOOTSTRAP:-0}"
case "$REAL_BACKEND_BOOTSTRAP" in
    1|true|TRUE|yes|YES|on|ON)
        AUTHORITATIVE_TARGET="${MISAKA_SHIELDED_AUTHORITATIVE_TARGET:-groth16_or_plonk}"
        case "$AUTHORITATIVE_TARGET" in
            groth16)
                if [ -z "${MISAKA_SHIELDED_GROTH16_VK_PATH:-}" ]; then
                    echo -e "  ${RED}FAIL${NC}: real backend bootstrap for groth16 requires MISAKA_SHIELDED_GROTH16_VK_PATH"
                    FAIL=1
                else
                    echo -e "  ${GREEN}INFO${NC}: real backend bootstrap requested for groth16; startup/runtime will enforce compiled adapter availability"
                fi
                ;;
            plonk)
                if [ -z "${MISAKA_SHIELDED_PLONK_VK_PATH:-}" ]; then
                    echo -e "  ${RED}FAIL${NC}: real backend bootstrap for plonk requires MISAKA_SHIELDED_PLONK_VK_PATH"
                    FAIL=1
                else
                    echo -e "  ${GREEN}INFO${NC}: real backend bootstrap requested for plonk; startup/runtime will enforce compiled adapter availability"
                fi
                ;;
            groth16_or_plonk|"")
                if [ -z "${MISAKA_SHIELDED_GROTH16_VK_PATH:-}" ] && [ -z "${MISAKA_SHIELDED_PLONK_VK_PATH:-}" ]; then
                    echo -e "  ${RED}FAIL${NC}: real backend bootstrap requires at least one explicit Groth16 or PLONK VK path"
                    FAIL=1
                else
                    echo -e "  ${GREEN}INFO${NC}: real backend bootstrap requested for groth16_or_plonk; startup/runtime will enforce adapter and policy contract"
                fi
                ;;
            *)
                echo -e "  ${RED}FAIL${NC}: invalid MISAKA_SHIELDED_AUTHORITATIVE_TARGET='${AUTHORITATIVE_TARGET}'"
                FAIL=1
                ;;
        esac
        ;;
    *)
        echo -e "  ${GREEN}INFO${NC}: Shielded real backend bootstrap is disabled"
        ;;
esac

# ── Summary ──
echo ""
echo "═══════════════════════════════════════════════════════════"
if [ "$FAIL" -ne 0 ]; then
    echo -e "  ${RED}RESULT: FAIL${NC} — Fix the issues above before releasing"
    exit 1
else
    echo -e "  ${GREEN}RESULT: PASS${NC} — Production feature gate checks passed"
    exit 0
fi
