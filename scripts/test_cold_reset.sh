#!/usr/bin/env bash
# MISAKA cold-reset staggered restart test harness.
#
# Purpose: reproducibly exercise the 4-node atomic reset + staggered
# restart procedure that triggered the v0.8.8 cold-reset halt, then
# collect logs + metrics into a tagged directory so multiple runs
# (baseline vs hotfix) can be diff-compared.
#
# Usage: scripts/test_cold_reset.sh <tag>
#   <tag>  — free-form label (e.g. "baseline_w3" or "hotfix_w100")
#            included in the output directory name.
#
# Typical:
#   scripts/test_cold_reset.sh baseline_w3
#   # swap the binary on each node
#   scripts/test_cold_reset.sh hotfix_w100
#
# Requires: SSH key ~/.ssh/claude_key, and the misaka-node binary
# already in place on each node (this script does NOT deploy binaries).
#
# Order of authority indexes: 0=27, 1=51, 2=150, 3=208. Starts in
# that order with 30 s gap after 0, then 15 s between 1, 2, 3.
# This mirrors the Option A staggered flow that avoided the initial
# bootstrap race.

set -euo pipefail

TAG="${1:?usage: $0 <tag>}"
SSH_KEY="${HOME}/.ssh/claude_key"
SMOKE_SEC="${SMOKE_SEC:-300}"  # override with env var for longer runs

OUT_DIR="/tmp/cold_reset_${TAG}_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${OUT_DIR}"

# Node list: (ip, layout, start_script, remote_log, data_dir)
# layout is "cluster4" for 27 (uses /tmp/cluster-4) or "v09dev" for the rest.
NODES=(
    "163.43.225.27|cluster4|/tmp/cluster-4/start27.sh|/tmp/cluster-4/node27.log|/tmp/cluster-4/data"
    "133.167.126.51|v09dev|/tmp/start51.sh|/home/ubuntu/node.log|/home/ubuntu/v0.9.0-dev/data"
    "163.43.142.150|v09dev|/tmp/start150.sh|/home/ubuntu/node.log|/home/ubuntu/v0.9.0-dev/data"
    "163.43.208.209|v09dev|/tmp/start208209.sh|/home/ubuntu/node.log|/home/ubuntu/v0.9.0-dev/data"
)

ssh_exec() {
    local ip="$1"
    local cmd="$2"
    ssh -i "${SSH_KEY}" -o BatchMode=yes -o ConnectTimeout=10 "ubuntu@${ip}" "LC_ALL=C; ${cmd}" 2>&1 | grep -v "locale\|LC_ALL\|setlocale" || true
}

record() {
    local msg="$1"
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) ${msg}" | tee -a "${OUT_DIR}/timeline.txt"
}

wipe_node() {
    local ip="$1"
    local data_dir="$2"
    local log_path="$3"
    ssh_exec "${ip}" "cd ${data_dir} && rm -rf narwhal_consensus narwhal_consensus.atomic-* narwhal_consensus.bak* narwhal_consensus.dl-* narwhal_consensus.smt-* narwhal_consensus.unstuck-* && rm -f narwhal_utxo_snapshot.json validator_lifecycle_chain_2.json validator_lifecycle_chain_2.json.bak-* validator_lifecycle_chain_2.bak.json.bak-* peer_scores.json && : > ${log_path} && ls"
}

start_node() {
    local ip="$1"
    local script="$2"
    local log="$3"
    # `disown` and `</dev/null` prevent SSH from holding the channel open
    ssh -i "${SSH_KEY}" -o BatchMode=yes -o ConnectTimeout=10 "ubuntu@${ip}" \
        "nohup bash ${script} > ${log} 2>&1 </dev/null & disown" &
    SSH_BG=$!
    sleep 2
    kill "${SSH_BG}" 2>/dev/null || true
}

# ───────────────────────────────────────────────
# Phase 1: stop all
# ───────────────────────────────────────────────
record "phase=stop"
for entry in "${NODES[@]}"; do
    IFS='|' read -r ip _ _ _ _ <<< "${entry}"
    ssh_exec "${ip}" "pkill -9 -f misaka-node 2>/dev/null; sleep 2; pgrep -c misaka-node || true" > "${OUT_DIR}/stop_${ip//./_}.txt" &
done
wait

# ───────────────────────────────────────────────
# Phase 2: wipe all
# ───────────────────────────────────────────────
record "phase=wipe"
for entry in "${NODES[@]}"; do
    IFS='|' read -r ip _ _ log data <<< "${entry}"
    wipe_node "${ip}" "${data}" "${log}" > "${OUT_DIR}/wipe_${ip//./_}.txt" &
done
wait

# ───────────────────────────────────────────────
# Phase 3: staggered start
#   27 alone → +30s → 51 → +15s → 150 → +15s → 208
# ───────────────────────────────────────────────
T0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
record "T0=${T0}"

IFS='|' read -r ip27 _ script27 log27 _ <<< "${NODES[0]}"
start_node "${ip27}" "${script27}" "${log27}"
record "started=27 (${ip27})"
sleep 30

IFS='|' read -r ip51 _ script51 log51 _ <<< "${NODES[1]}"
start_node "${ip51}" "${script51}" "${log51}"
record "started=51 (${ip51})"
sleep 15

IFS='|' read -r ip150 _ script150 log150 _ <<< "${NODES[2]}"
start_node "${ip150}" "${script150}" "${log150}"
record "started=150 (${ip150})"
sleep 15

IFS='|' read -r ip208 _ script208 log208 _ <<< "${NODES[3]}"
start_node "${ip208}" "${script208}" "${log208}"
record "started=208 (${ip208})"

# ───────────────────────────────────────────────
# Phase 4: smoke
# ───────────────────────────────────────────────
record "phase=smoke duration=${SMOKE_SEC}s"
sleep "${SMOKE_SEC}"
record "phase=smoke_end"

# ───────────────────────────────────────────────
# Phase 5: collect logs
# ───────────────────────────────────────────────
record "phase=collect"
for entry in "${NODES[@]}"; do
    IFS='|' read -r ip _ _ log _ <<< "${entry}"
    scp -i "${SSH_KEY}" -o BatchMode=yes "ubuntu@${ip}:${log}" "${OUT_DIR}/node_${ip//./_}.log" || true
done

# ───────────────────────────────────────────────
# Phase 6: metrics summary
# ───────────────────────────────────────────────
record "phase=summary"
{
    echo "=== Summary: ${TAG} ==="
    echo "T0=${T0}"
    echo
    printf "%-16s %-10s %-12s %-12s %-8s %-12s %-12s\n" \
        "node" "procs" "commits" "last_round" "quar" "replays" "epoch_chg"
    for entry in "${NODES[@]}"; do
        IFS='|' read -r ip _ _ _ _ <<< "${entry}"
        LOG="${OUT_DIR}/node_${ip//./_}.log"
        if [[ ! -f "${LOG}" ]]; then continue; fi
        procs=$(ssh_exec "${ip}" "pgrep -c misaka-node || echo 0" | head -1)
        commits=$(grep -c 'Committed: index=' "${LOG}" 2>/dev/null || echo 0)
        last_r=$(grep 'Proposed block: round=' "${LOG}" 2>/dev/null | tail -1 | grep -oE 'round=[0-9]+' | head -1 | cut -d= -f2)
        quar=$(grep -c 'Author quarantined' "${LOG}" 2>/dev/null || echo 0)
        replays=$(grep -c 'narwhal_peer_replay authority=' "${LOG}" 2>/dev/null || echo 0)
        epoch_chg=$(grep -c 'Epoch change' "${LOG}" 2>/dev/null || echo 0)
        printf "%-16s %-10s %-12s %-12s %-8s %-12s %-12s\n" \
            "${ip}" "${procs:-?}" "${commits:-0}" "${last_r:-0}" "${quar:-0}" "${replays:-0}" "${epoch_chg:-0}"
    done
    echo
    echo "=== Replay log details (first 20 across all nodes) ==="
    grep -h 'narwhal_peer_replay authority=' "${OUT_DIR}"/node_*.log 2>/dev/null | head -20
    echo
    echo "=== Quarantine events (all) ==="
    grep -h 'Author quarantined' "${OUT_DIR}"/node_*.log 2>/dev/null
    echo
    echo "=== Epoch change events (all) ==="
    grep -h 'Epoch change' "${OUT_DIR}"/node_*.log 2>/dev/null
} | tee "${OUT_DIR}/summary.txt"

record "phase=done tag=${TAG} out=${OUT_DIR}"
echo
echo "Full output directory: ${OUT_DIR}"
