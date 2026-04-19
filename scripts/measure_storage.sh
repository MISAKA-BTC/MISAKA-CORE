#!/usr/bin/env bash
# MISAKA storage footprint reporter (v0.8.9 BLOCKER M / Phase 1).
#
# Usage: scripts/measure_storage.sh <data_dir>
#
# Typical:
#   scripts/measure_storage.sh /home/ubuntu/v0.9.0-dev/data
#   scripts/measure_storage.sh /tmp/cluster-4/data
#
# Prints:
#   - Total on-disk size (du -sh)
#   - Breakdown by RocksDB artifact extension (.sst / .blob / .log /
#     MANIFEST / OPTIONS / LOG)
#   - Per-CF approximate-size table (requires `ldb` in PATH;
#     falls back to a warning if `ldb` is unavailable).
#
# Intended to be run BEFORE and AFTER a v0.8.9 binary swap so the PR
# description can attach the baseline → post-change delta.

set -euo pipefail

DATA_DIR="${1:?usage: $0 <data_dir>}"
if [[ ! -d "${DATA_DIR}" ]]; then
    echo "ERROR: ${DATA_DIR} is not a directory" >&2
    exit 1
fi

# The actual RocksDB lives in <data_dir>/narwhal_consensus on the
# testnet layout; handle both conventions transparently.
if [[ -d "${DATA_DIR}/narwhal_consensus" ]]; then
    DB_DIR="${DATA_DIR}/narwhal_consensus"
else
    DB_DIR="${DATA_DIR}"
fi

echo "=== Target ==="
echo "  data_dir: ${DATA_DIR}"
echo "  db_dir  : ${DB_DIR}"
echo "  host    : $(hostname)"
echo "  date    : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo

echo "=== Total ==="
du -sh "${DB_DIR}"
du -sh "${DATA_DIR}"
echo

echo "=== Breakdown by extension ==="
for ext in sst blob log; do
    total=$(find "${DB_DIR}" -maxdepth 2 -type f -name "*.${ext}" -printf '%s\n' 2>/dev/null \
        | awk '{s+=$1} END {print (s?s:0)}')
    count=$(find "${DB_DIR}" -maxdepth 2 -type f -name "*.${ext}" 2>/dev/null | wc -l)
    human=$(numfmt --to=iec --suffix=B "${total}" 2>/dev/null || echo "${total}B")
    printf "  *.%-5s  %10s  (%d file(s))\n" "${ext}" "${human}" "${count}"
done

# MANIFEST / OPTIONS / IDENTITY / CURRENT are tiny but worth showing
for name in MANIFEST OPTIONS IDENTITY CURRENT; do
    total=$(find "${DB_DIR}" -maxdepth 2 -type f -name "${name}*" -printf '%s\n' 2>/dev/null \
        | awk '{s+=$1} END {print (s?s:0)}')
    count=$(find "${DB_DIR}" -maxdepth 2 -type f -name "${name}*" 2>/dev/null | wc -l)
    human=$(numfmt --to=iec --suffix=B "${total}" 2>/dev/null || echo "${total}B")
    printf "  %-8s  %10s  (%d file(s))\n" "${name}" "${human}" "${count}"
done
echo

echo "=== Per-CF approximate size ==="
if command -v ldb >/dev/null 2>&1; then
    CFS=$(ldb --db="${DB_DIR}" list_column_families 2>/dev/null || true)
    if [[ -n "${CFS}" ]]; then
        for cf in ${CFS}; do
            size=$(ldb --db="${DB_DIR}" --column_family="${cf}" approxsize 2>/dev/null | tail -1 || echo "-")
            printf "  %-28s %s\n" "${cf}" "${size}"
        done
    else
        echo "  ldb list_column_families returned no output"
    fi
else
    echo "  (install rocksdb-tools: \`apt install rocksdb-tools\` or \`cargo install ldb\`)"
fi
echo

echo "=== WAL state ==="
WAL_TOTAL=$(find "${DB_DIR}" -maxdepth 2 -type f -name "*.log" -printf '%s\n' 2>/dev/null \
    | awk '{s+=$1} END {print (s?s:0)}')
WAL_HUMAN=$(numfmt --to=iec --suffix=B "${WAL_TOTAL}" 2>/dev/null || echo "${WAL_TOTAL}B")
WAL_COUNT=$(find "${DB_DIR}" -maxdepth 2 -type f -name "*.log" 2>/dev/null | wc -l)
echo "  size: ${WAL_HUMAN}  (${WAL_COUNT} segments)"
echo "  cap : 512 MiB (set by misaka-dag set_max_total_wal_size)"

echo
echo "=== Done ==="
