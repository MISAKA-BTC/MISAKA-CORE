#!/usr/bin/env bash
# PC-B test runner for Phase 1-1 (lightweight deterministic simulator)
#
# Usage:
#   ./scripts/test-pc-b.sh
#
# This script runs ALL tests including the heavy ones that are #[ignore]
# on PC-A. Expected wall clock: 10-40 minutes.

set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

DATE=$(date +%Y%m%d-%H%M%S)
LOGDIR="test-results/${DATE}"
mkdir -p "${LOGDIR}"

echo "=== Phase 1-1: PC-B Test Suite ==="
echo "Date: $(date -u)"
echo "Commit: $(git rev-parse HEAD)"
echo "Log dir: ${LOGDIR}"
echo ""

# Step 1: Clean build of affected crates
echo "--- Step 1: Clean build ---"
cargo clean -p misaka-dag -p misaka-simulator -p misaka-test-cluster 2>&1
cargo build -p misaka-simulator 2>&1

# Step 2: Standard tests (non-ignored)
echo ""
echo "--- Step 2: Standard tests (non-ignored) ---"
cargo test -p misaka-dag --lib -- --nocapture 2>&1 | tee "${LOGDIR}/misaka-dag.log"
cargo test -p misaka-simulator -- --nocapture 2>&1 | tee "${LOGDIR}/simulator-standard.log"
cargo test -p misaka-test-cluster -- --nocapture 2>&1 | tee "${LOGDIR}/test-cluster.log"

# Step 3: HEAVY test — 21 nodes × 100 rounds × 100 repeats determinism
echo ""
echo "--- Step 3: Heavy determinism test (21×100×100) ---"
echo "Expected: ~30 minutes"
START_HEAVY=$(date +%s)
cargo test -p misaka-simulator -- --ignored --nocapture test_a_deterministic_full 2>&1 \
  | tee "${LOGDIR}/determinism-full.log"
END_HEAVY=$(date +%s)
HEAVY_SECS=$((END_HEAVY - START_HEAVY))
echo "Heavy test wall clock: ${HEAVY_SECS}s"

# Step 4: Generate summary report
echo ""
echo "--- Step 4: Summary ---"
{
  echo "# Phase 1-1 PC-B Test Results"
  echo ""
  echo "- Date: $(date -u)"
  echo "- Commit: $(git rev-parse HEAD)"
  echo "- PC: PC-B"
  echo ""
  echo "## misaka-dag (lib)"
  grep "test result" "${LOGDIR}/misaka-dag.log" || echo "MISSING"
  echo ""
  echo "## misaka-simulator (standard, non-ignored)"
  grep "test result" "${LOGDIR}/simulator-standard.log" || echo "MISSING"
  echo ""
  echo "## misaka-test-cluster"
  grep "test result" "${LOGDIR}/test-cluster.log" || echo "MISSING"
  echo ""
  echo "## Heavy: 21×100×100 determinism"
  grep "test result" "${LOGDIR}/determinism-full.log" || echo "MISSING"
  grep "\[test_a\]" "${LOGDIR}/determinism-full.log" || echo "(no timing output)"
  echo "Wall clock: ${HEAVY_SECS}s"
  echo ""
  echo "## Failed tests"
  grep "FAILED" "${LOGDIR}"/*.log || echo "None"
  echo ""
  echo "## ML-DSA-65 benchmark"
  grep "\[bench\]" "${LOGDIR}/simulator-standard.log" || echo "(no bench output)"
  echo ""
  echo "## Individual test timings"
  grep "\[test_" "${LOGDIR}/simulator-standard.log" || echo "(no test timings)"
} > test-results/latest.md

cat test-results/latest.md

echo ""
echo "=== Results saved to test-results/latest.md ==="
echo "To push: git add test-results/ && git commit -m 'test: phase-1-1 PC-B results' && git push"
