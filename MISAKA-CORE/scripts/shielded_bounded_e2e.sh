#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
state_dir="${MISAKA_SHIELDED_BOUNDED_E2E_DIR:-$repo_root/.tmp/shielded-bounded-e2e}"
result_file="${MISAKA_SHIELDED_BOUNDED_E2E_RESULT:-$state_dir/result.json}"
log_file="$state_dir/cargo-test.log"
target_dir="${MISAKA_CARGO_TARGET_DIR:-$repo_root/.tmp/shielded-bounded-e2e-target}"

if [[ "$state_dir" != /* ]]; then
  state_dir="$repo_root/$state_dir"
fi
if [[ "$result_file" != /* ]]; then
  result_file="$repo_root/$result_file"
fi
if [[ "$target_dir" != /* ]]; then
  target_dir="$repo_root/$target_dir"
fi
log_file="$state_dir/cargo-test.log"

usage() {
  cat <<'EOF'
Usage: ./scripts/shielded_bounded_e2e.sh

Runs the current bounded shielded DAG RPC E2E regression and writes:

  .tmp/shielded-bounded-e2e/result.json

Optional env:
  MISAKA_SHIELDED_BOUNDED_E2E_DIR=/custom/output/dir
  MISAKA_SHIELDED_BOUNDED_E2E_RESULT=/custom/result.json
  MISAKA_CARGO_TARGET_DIR=/custom/target/dir
  BINDGEN_EXTRA_CLANG_ARGS=...
  CC=...
  CXX=...
EOF
}

write_failure() {
  local reason="$1"
  python3 - "$result_file" "$reason" <<'PY'
import json
import pathlib
import sys

result_path = pathlib.Path(sys.argv[1])
reason = sys.argv[2]
result_path.parent.mkdir(parents=True, exist_ok=True)
payload = {
    "status": "failed",
    "reason": reason,
}
result_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
PY
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi

mkdir -p "$state_dir"

if ! command -v cargo >/dev/null 2>&1; then
  write_failure "cargo command is not available"
  exit 1
fi

if [[ -z "${BINDGEN_EXTRA_CLANG_ARGS:-}" ]] && command -v gcc >/dev/null 2>&1; then
  export BINDGEN_EXTRA_CLANG_ARGS="-I$(gcc -print-file-name=include)"
fi
export CC="${CC:-gcc}"
export CXX="${CXX:-g++}"
export CARGO_TARGET_DIR="$target_dir"
export MISAKA_SHIELDED_BOUNDED_E2E_RESULT="$result_file"

cd "$repo_root"

if ! cargo test -p misaka-node --bin misaka-node \
  shielded_submit_transfer_hash_stays_stable_from_pending_to_confirmed_and_checkpoint_consumer \
  --features qdag_ct -- --nocapture >"$log_file" 2>&1; then
  write_failure "bounded shielded DAG RPC E2E regression failed"
  cat "$log_file" >&2
  exit 1
fi

if [[ ! -f "$result_file" ]]; then
  write_failure "bounded shielded DAG RPC E2E regression passed but did not emit result artifact"
  exit 1
fi

python3 - "$result_file" <<'PY'
import json
import pathlib
import sys

result_path = pathlib.Path(sys.argv[1])
data = json.loads(result_path.read_text(encoding="utf-8"))
required = [
    data.get("status") == "passed",
    isinstance(data.get("txHash"), str) and len(data["txHash"]) == 64,
    data.get("pending", {}).get("status") == "pending",
    data.get("pending", {}).get("admissionPath") == "zeroKnowledge",
    data.get("confirmed", {}).get("status") == "confirmed",
    data.get("summary", {}).get("status") == "confirmed",
    data.get("checkpointConsumer", {}).get("explorerConfirmationLevel") == "checkpointFinalized",
]
if not all(required):
    raise SystemExit("bounded shielded DAG RPC E2E artifact is incomplete")
print(result_path)
PY
