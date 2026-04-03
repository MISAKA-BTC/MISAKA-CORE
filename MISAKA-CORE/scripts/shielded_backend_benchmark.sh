#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
state_dir="${MISAKA_SHIELDED_BENCHMARK_DIR:-$repo_root/.tmp/shielded-backend-benchmark}"
result_file="$state_dir/result.json"
raw_file="$state_dir/benchmark-raw.json"
comparative_raw_file="$state_dir/comparative-benchmark-raw.json"
inventory_script="$repo_root/scripts/shielded_backend_inventory.sh"
inventory_result="$repo_root/.tmp/shielded-backend-inventory/result.json"
cargo_bin="${MISAKA_CARGO_BIN:-cargo}"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'EOF'
Usage: ./scripts/shielded_backend_benchmark.sh

Runs the current SHA3 / Groth16 / PLONK Layer 4 benchmark slices and combines them with the
shielded backend inventory into:

  .tmp/shielded-backend-benchmark/result.json

Optional env:
  MISAKA_SHIELDED_BENCHMARK_DIR  Override output directory
  MISAKA_CARGO_BIN               Override cargo executable
EOF
  exit 0
fi

mkdir -p "$state_dir"
cd "$repo_root"

write_failure() {
  local message="$1"
  python3 - "$result_file" "$inventory_result" "$message" <<'PY'
import json
import pathlib
import sys

result = pathlib.Path(sys.argv[1])
inventory_result = sys.argv[2]
message = sys.argv[3]

payload = {
    "status": "failed",
    "inventoryArtifact": inventory_result,
    "error": message,
}
result.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n")
PY
}

bash "$inventory_script" >/dev/null

if ! MISAKA_SHIELDED_BENCHMARK_RESULT="$raw_file" \
  "$cargo_bin" test -p misaka-shielded layer4_benchmark_emits_current_sha3_baseline -- --exact --nocapture >/dev/null; then
  write_failure "failed to run shielded Layer4 benchmark test"
  exit 1
fi

if ! MISAKA_SHIELDED_COMPARATIVE_BENCHMARK_RESULT="$comparative_raw_file" \
  "$cargo_bin" test -p misaka-node --bin misaka-node \
    --features shielded-groth16-verifier,shielded-plonk-verifier \
    shielded_verifier_adapters::tests::compiled_verifier_benchmark_emits_current_groth16_plonk_baselines -- --exact --nocapture >/dev/null; then
  write_failure "failed to run compiled Groth16/PLONK comparative benchmark test"
  exit 1
fi

python3 - "$raw_file" "$comparative_raw_file" "$inventory_result" "$result_file" <<'PY'
import json
import pathlib
import sys

raw = json.loads(pathlib.Path(sys.argv[1]).read_text())
comparative = json.loads(pathlib.Path(sys.argv[2]).read_text())
inventory_path = pathlib.Path(sys.argv[3])
result_file = pathlib.Path(sys.argv[4])
inventory = json.loads(inventory_path.read_text()) if inventory_path.exists() else None

comparative_benchmarks = comparative.get("benchmarks") if isinstance(comparative, dict) else None
benchmarks_by_backend = {}
if isinstance(raw.get("benchmark"), dict):
    benchmarks_by_backend[raw["benchmark"].get("backendId", "sha3-transfer-v2")] = raw["benchmark"]
if isinstance(comparative_benchmarks, list):
    for item in comparative_benchmarks:
        if isinstance(item, dict) and item.get("backendId"):
            benchmarks_by_backend[item["backendId"]] = item

payload = {
    "status": "passed",
    "inventoryArtifact": str(inventory_path),
    "inventorySummary": inventory.get("summary") if inventory else None,
    "benchmarkSummary": raw.get("benchmark"),
    "comparativeBenchmarkSummary": comparative_benchmarks,
    "benchmarkSummaries": benchmarks_by_backend,
    "compiledCatalog": raw.get("compiledCatalog"),
    "rawBenchmarkArtifact": str(pathlib.Path(sys.argv[1])),
    "rawComparativeBenchmarkArtifact": str(pathlib.Path(sys.argv[2])),
}
result_file.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n")
PY

printf 'wrote %s\n' "$result_file"
