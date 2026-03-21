#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
# dag_release_gate.sh — CI gate for DAG mainnet release
#
# This script MUST pass in CI before any tagged release that
# includes the experimental_dag feature. It replaces the old
# compile_error!("experimental_dag is not ready for release").
#
# Exit Codes:
#   0 — All checks passed, DAG is release-ready
#   1 — One or more checks failed
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

check() {
    local name="$1"
    shift
    echo -n "  [$name] "
    if "$@" > /dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}FAIL${NC}"
        FAIL=$((FAIL + 1))
    fi
}

echo "═══════════════════════════════════════════════════════════"
echo "  MISAKA DAG Release Gate"
echo "═══════════════════════════════════════════════════════════"
echo ""

# ── Phase 1: Compile check ──
echo "Phase 1: Compilation"
check "dag-debug-build" \
    cargo build -p misaka-dag --all-features

check "node-dag-build" \
    cargo build -p misaka-node --features experimental_dag

# ── Phase 2: Unit tests ──
echo ""
echo "Phase 2: Unit Tests"
check "dag-unit-tests" \
    cargo test -p misaka-dag --lib

check "dag-p2p-tests" \
    cargo test -p misaka-dag --lib dag_p2p

check "storage-wal-tests" \
    cargo test -p misaka-storage --lib wal

check "p2p-sync-tests" \
    cargo test -p misaka-p2p --lib sync

# ── Phase 3: Multi-Node Chaos Tests (CRITICAL) ──
echo ""
echo "Phase 3: Multi-Node Chaos Tests (CRITICAL)"
check "same-order-convergence" \
    cargo test -p misaka-dag --test multi_node_chaos test_same_order_convergence

check "random-order-convergence" \
    cargo test -p misaka-dag --test multi_node_chaos test_random_order_convergence

check "crash-and-catchup" \
    cargo test -p misaka-dag --test multi_node_chaos test_crash_and_catchup

check "wide-dag-convergence" \
    cargo test -p misaka-dag --test multi_node_chaos test_wide_dag_convergence

check "selected-tip-determinism" \
    cargo test -p misaka-dag --test multi_node_chaos test_selected_tip_determinism

# ── Phase 4: Integration ──
echo ""
echo "Phase 4: Integration"
check "dag-integration" \
    cargo test -p misaka-dag --tests

# ── Summary ──
echo ""
echo "═══════════════════════════════════════════════════════════"
TOTAL=$((PASS + FAIL))
if [ "$FAIL" -eq 0 ]; then
    echo -e "  ${GREEN}ALL $TOTAL CHECKS PASSED${NC} — DAG is release-ready"
    echo "═══════════════════════════════════════════════════════════"
    exit 0
else
    echo -e "  ${RED}$FAIL/$TOTAL CHECKS FAILED${NC} — DAG is NOT release-ready"
    echo ""
    echo "  The following must be fixed before DAG mainnet release:"
    echo "  - Run failing tests locally: cargo test -p misaka-dag --test multi_node_chaos"
    echo "  - Fix all failures"
    echo "  - Re-run this script"
    echo "═══════════════════════════════════════════════════════════"
    exit 1
fi
