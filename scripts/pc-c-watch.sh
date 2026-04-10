#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 MISAKA Foundation
#
# PC-C Heavy Verification Watcher (macOS)
#
# Runs sequential heavy tests against Phase boundary commits,
# then switches to polling main for future Phases.
#
# Usage:
#   cd ~/MISAKA-CORE-SHARE   # or wherever the repo is cloned
#   bash scripts/pc-c-watch.sh
#
# The script will:
#   1. Check which boundary commits are already verified (pc-c-verified.txt)
#   2. For each unverified boundary, checkout → build → heavy test
#   3. On PASS: record in verified.txt, push results, continue to next
#   4. On FAIL: record failure, push results, STOP (human intervention)
#   5. Once all boundaries pass, poll main every 5 min for new commits

set -euo pipefail

# ═══════════════════════════════════════════════════════════
#  Configuration
# ═══════════════════════════════════════════════════════════

REPO_DIR="${REPO_DIR:-$(pwd)}"
RESULTS_DIR="$REPO_DIR/test-results"
VERIFIED_FILE="$RESULTS_DIR/pc-c-verified.txt"
LATEST_FILE="$RESULTS_DIR/pc-c-latest.md"
POLL_INTERVAL=300  # 5 minutes

# Phase boundary commits (in verification order).
# Each entry: "commit_hash:phase_id"
BOUNDARY_COMMITS=(
    "d9dcb08:phase-1-1"
    "b01145a:phase-2-1"
    "73662f9:phase-2-2"
    "de25b45:phase-2-3"
)

# Timeouts (seconds)
BUILD_TIMEOUT=1800        # 30 min
HEAVY_TEST_TIMEOUT=3600   # 60 min (21n × 100r × 100rep)
WORKSPACE_TEST_TIMEOUT=1800  # 30 min

# ═══════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════

log() {
    echo "[pc-c $(date -u '+%Y-%m-%dT%H:%M:%SZ')] $*"
}

is_verified() {
    local commit="$1"
    if [[ -f "$VERIFIED_FILE" ]]; then
        grep -qF "$commit" "$VERIFIED_FILE" 2>/dev/null
    else
        return 1
    fi
}

mark_verified() {
    local commit="$1"
    echo "$commit" >> "$VERIFIED_FILE"
}

push_results() {
    cd "$REPO_DIR"
    # Stash any non-results changes, switch to main, push results only
    local original_branch
    original_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "detached")

    git stash --include-untracked 2>/dev/null || true
    git checkout main 2>/dev/null || true
    git pull --rebase origin main 2>/dev/null || true

    git add test-results/ 2>/dev/null || true
    if git diff --cached --quiet 2>/dev/null; then
        log "No results to push"
    else
        git commit -m "test(pc-c): heavy verification results [skip ci]" 2>/dev/null || true
        git push origin main 2>/dev/null || log "WARN: push failed (will retry)"
    fi

    # Return to previous state
    if [[ "$original_branch" != "detached" && "$original_branch" != "main" ]]; then
        git checkout "$original_branch" 2>/dev/null || true
    fi
    git stash pop 2>/dev/null || true
}

write_result() {
    local phase_id="$1"
    local commit="$2"
    local verdict="$3"
    local details="$4"
    local wall_clock="$5"

    local phase_file="$RESULTS_DIR/pc-c-${phase_id}-heavy.md"

    cat > "$phase_file" <<RESULT_EOF
# PC-C Heavy Verification: ${phase_id}

- commit: ${commit}
- date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
- OS: $(uname -s) $(uname -r) ($(uname -m))
- host: $(hostname)

## verdict

${verdict}

## wall clock

${wall_clock}

## details

${details}
RESULT_EOF

    # Also update latest
    cp "$phase_file" "$LATEST_FILE"

    log "Result written: $phase_file (verdict: $verdict)"
}

# ═══════════════════════════════════════════════════════════
#  Verification runner
# ═══════════════════════════════════════════════════════════

run_verification() {
    local commit="$1"
    local phase_id="$2"

    log "════════════════════════════════════════"
    log "Verifying ${phase_id} at commit ${commit}"
    log "════════════════════════════════════════"

    cd "$REPO_DIR"

    # Checkout the boundary commit
    git fetch origin main 2>/dev/null || true
    git checkout "$commit" 2>/dev/null
    if [[ $? -ne 0 ]]; then
        write_result "$phase_id" "$commit" "FAIL" "git checkout failed" "0s"
        return 1
    fi

    # Step 1: Build
    log "Step 1/3: cargo build --release -p misaka-simulator"
    local build_start=$SECONDS
    local build_log
    build_log=$(mktemp)
    if ! timeout "$BUILD_TIMEOUT" cargo build --release -p misaka-simulator 2>&1 | tee "$build_log"; then
        local build_time=$(( SECONDS - build_start ))
        write_result "$phase_id" "$commit" "FAIL" \
            "Build failed (${build_time}s):\n$(tail -20 "$build_log")" \
            "${build_time}s"
        rm -f "$build_log"
        push_results
        return 1
    fi
    local build_time=$(( SECONDS - build_start ))
    log "Build OK (${build_time}s)"
    rm -f "$build_log"

    # Step 2: Heavy determinism test (21 nodes × 100 rounds × 100 repeats)
    log "Step 2/3: test_a_deterministic_full (timeout: ${HEAVY_TEST_TIMEOUT}s)"
    local heavy_start=$SECONDS
    local heavy_log
    heavy_log=$(mktemp)
    if ! timeout "$HEAVY_TEST_TIMEOUT" cargo test --release -p misaka-simulator --lib \
        -- --ignored test_a_deterministic_full --nocapture 2>&1 | tee "$heavy_log"; then
        local heavy_time=$(( SECONDS - heavy_start ))
        local exit_code=$?
        local fail_reason="FAIL"
        if [[ $exit_code -eq 124 ]]; then
            fail_reason="TIMEOUT"
        fi
        write_result "$phase_id" "$commit" "$fail_reason" \
            "test_a_deterministic_full ${fail_reason} (${heavy_time}s):\n$(tail -30 "$heavy_log")" \
            "${heavy_time}s"
        rm -f "$heavy_log"
        push_results
        return 1
    fi
    local heavy_time=$(( SECONDS - heavy_start ))
    local heavy_output
    heavy_output=$(grep -E "^\[test_a\]|^test result:" "$heavy_log" | tail -5)
    log "Heavy test OK (${heavy_time}s)"
    rm -f "$heavy_log"

    # Step 3: Workspace regression test
    log "Step 3/3: cargo test --release --workspace --lib (timeout: ${WORKSPACE_TEST_TIMEOUT}s)"
    local ws_start=$SECONDS
    local ws_log
    ws_log=$(mktemp)
    if ! timeout "$WORKSPACE_TEST_TIMEOUT" cargo test --release --workspace --lib \
        -- --test-threads=1 2>&1 | tee "$ws_log"; then
        local ws_time=$(( SECONDS - ws_start ))
        write_result "$phase_id" "$commit" "FAIL" \
            "workspace test FAIL (${ws_time}s):\n$(tail -30 "$ws_log")" \
            "build=${build_time}s heavy=${heavy_time}s ws=${ws_time}s"
        rm -f "$ws_log"
        push_results
        return 1
    fi
    local ws_time=$(( SECONDS - ws_start ))
    local ws_summary
    ws_summary=$(grep "^test result:" "$ws_log" | tail -5)
    log "Workspace test OK (${ws_time}s)"
    rm -f "$ws_log"

    # All passed
    local total_time=$(( build_time + heavy_time + ws_time ))
    write_result "$phase_id" "$commit" "PASS" \
        "build: ${build_time}s
heavy (21n×100r×100rep): ${heavy_time}s
${heavy_output}
workspace: ${ws_time}s
${ws_summary}" \
        "total=${total_time}s (build=${build_time}s heavy=${heavy_time}s ws=${ws_time}s)"

    mark_verified "$commit"
    push_results

    log "${phase_id} PASS (total ${total_time}s)"
    return 0
}

# ═══════════════════════════════════════════════════════════
#  Main loop
# ═══════════════════════════════════════════════════════════

main() {
    log "PC-C Heavy Verification Watcher starting"
    log "Repo: $REPO_DIR"
    log "Boundary commits: ${#BOUNDARY_COMMITS[@]}"

    mkdir -p "$RESULTS_DIR"
    touch "$VERIFIED_FILE"

    cd "$REPO_DIR"
    git fetch origin main 2>/dev/null || true

    # Phase 1: Process boundary commits sequentially
    local all_boundaries_pass=true
    for entry in "${BOUNDARY_COMMITS[@]}"; do
        local commit="${entry%%:*}"
        local phase_id="${entry##*:}"

        if is_verified "$commit"; then
            log "SKIP ${phase_id} (${commit}) — already verified"
            continue
        fi

        log "NEXT: ${phase_id} (${commit})"
        if ! run_verification "$commit" "$phase_id"; then
            log "STOP: ${phase_id} FAILED — human intervention required"
            all_boundaries_pass=false
            break
        fi
    done

    if ! $all_boundaries_pass; then
        log "Watcher stopped due to failure. Fix the issue and re-run."
        exit 1
    fi

    log "All boundary commits verified. Switching to main polling mode."

    # Phase 2: Poll main for new commits
    cd "$REPO_DIR"
    git checkout main 2>/dev/null || true
    git pull --rebase origin main 2>/dev/null || true
    local last_verified_main
    last_verified_main=$(git rev-parse HEAD)

    while true; do
        sleep "$POLL_INTERVAL"

        cd "$REPO_DIR"
        git fetch origin main 2>/dev/null || true
        local current_main
        current_main=$(git rev-parse origin/main)

        if [[ "$current_main" == "$last_verified_main" ]]; then
            continue
        fi

        if is_verified "$current_main"; then
            last_verified_main="$current_main"
            continue
        fi

        log "New commit on main: $current_main"
        git pull --rebase origin main 2>/dev/null || true

        # Determine phase from commit message
        local phase_id
        phase_id=$(git log -1 --format="%s" "$current_main" | grep -oE 'phase-[0-9]+-[0-9]+' | head -1)
        if [[ -z "$phase_id" ]]; then
            phase_id="main-$(echo "$current_main" | head -c 7)"
        fi

        if ! run_verification "$current_main" "$phase_id"; then
            log "STOP: main verification FAILED at $current_main"
            exit 1
        fi

        last_verified_main="$current_main"
    done
}

main "$@"
