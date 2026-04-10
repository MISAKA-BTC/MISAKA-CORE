#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
state_dir="${MISAKA_NARWHAL_DISSEMINATION_REHEARSAL_DIR:-$repo_root/.tmp/dag-narwhal-dissemination-rehearsal}"
result_file="${MISAKA_NARWHAL_DISSEMINATION_REHEARSAL_RESULT:-$state_dir/result.json}"
target_dir="${MISAKA_CARGO_TARGET_DIR:-$repo_root/.tmp/dag-narwhal-dissemination-target}"
log_file="$state_dir/cargo-test.log"
test_filter="live_narwhal_dissemination_shadow_and_delivered_handoff"

usage() {
  cat <<'EOF'
Usage: ./scripts/dag_narwhal_dissemination_rehearsal.sh

Runs the confined Narwhal dissemination rehearsal and writes:

  .tmp/dag-narwhal-dissemination-rehearsal/result.json

Optional env:
  MISAKA_NARWHAL_DISSEMINATION_REHEARSAL_DIR=/custom/output/dir
  MISAKA_NARWHAL_DISSEMINATION_REHEARSAL_RESULT=/custom/result.json
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

if [[ $# -gt 0 ]]; then
  usage >&2
  exit 1
fi

if [[ "$state_dir" != /* ]]; then
  state_dir="$repo_root/$state_dir"
fi
if [[ "$result_file" != /* ]]; then
  result_file="$repo_root/$result_file"
fi
if [[ "$target_dir" != /* ]]; then
  target_dir="$repo_root/$target_dir"
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
export MISAKA_NARWHAL_DISSEMINATION_REHEARSAL_RESULT="$result_file"
rm -f "$result_file"

cd "$repo_root"

if ! cargo test -p misaka-node --bin misaka-node \
  "$test_filter" \
  -- --nocapture >"$log_file" 2>&1; then
  write_failure "narwhal dissemination rehearsal regression failed"
  cat "$log_file" >&2
  exit 1
fi

if [[ ! -f "$result_file" ]]; then
  write_failure "narwhal dissemination rehearsal passed but did not emit result artifact"
  exit 1
fi

python3 - "$result_file" <<'PY'
import json
import pathlib
import sys

result_path = pathlib.Path(sys.argv[1])
payload = json.loads(result_path.read_text(encoding="utf-8"))

initial = payload.get("initial", {}).get("chainInfo", {})
worker = payload.get("afterWorkerBatchIngress", {}).get("chainInfo", {})
delivered = payload.get("afterDeliveredBatch", {}).get("chainInfo", {})
consistency = payload.get("consistency", {})
architecture = payload.get("consensusArchitecture", {})
errors = []

if payload.get("status") != "passed":
    errors.append(f"status is not passed: {payload.get('status')!r}")
if payload.get("flow") != "live_narwhal_dissemination_shadow_and_delivered_handoff":
    errors.append(f"unexpected flow: {payload.get('flow')!r}")
tx_hashes = payload.get("txHashes")
if not isinstance(tx_hashes, list) or len(tx_hashes) != 2 or len(set(tx_hashes)) != 2:
    errors.append("txHashes must contain two distinct entries")
if initial.get("currentRuntimeQueue", {}).get("queued") != 0:
    errors.append("initial currentRuntimeQueue.queued is not 0")
if worker.get("completionTargetShadowQueue", {}).get("queued") != 2:
    errors.append("worker shadow queue count is not 2")
if worker.get("completionTargetShadowQueue", {}).get("narwhalWorkerBatchIngressQueued") != 2:
    errors.append("worker narwhalWorkerBatchIngressQueued is not 2")
if worker.get("completionTargetShadowQueue", {}).get("stagedOnlyQueued") != 2:
    errors.append("worker stagedOnlyQueued is not 2")
if worker.get("completionTargetDeliveredQueue", {}).get("queued") != 0:
    errors.append("worker delivered queue should still be 0")
if delivered.get("completionTargetDeliveredQueue", {}).get("queued") != 2:
    errors.append("delivered queue count is not 2")
if delivered.get("completionTargetDeliveredQueue", {}).get("fastTransparentQueued") != 1:
    errors.append("delivered fastTransparentQueued is not 1")
if delivered.get("completionTargetDeliveredQueue", {}).get("shieldedQueued") != 1:
    errors.append("delivered shieldedQueued is not 1")
if delivered.get("completionTargetDeliveredQueue", {}).get("live") is not True:
    errors.append("delivered queue is not live")
for key in (
    "serviceBoundThroughout",
    "serviceRunningThroughout",
    "shadowBatchCallerReadyThroughout",
    "deliveredBatchCallerReadyThroughout",
    "currentRuntimeQueueUnaffected",
    "workerBatchVisibleOnlyInShadowBeforeDelivery",
    "deliveredBatchVisibleAfterHandoff",
    "stagedContractReadyThroughout",
    "consensusArchitectureMatchesCompletionPlan",
):
    if consistency.get(key) is not True:
        errors.append(f"consistency flag is not true: {key}")
current_runtime = architecture.get("currentRuntime", {})
completion_target = architecture.get("completionTarget", {})
if current_runtime.get("disseminationStage") != "nativeMempool":
    errors.append("current disseminationStage is not nativeMempool")
if completion_target.get("disseminationStage") != "narwhalBatchDissemination":
    errors.append("completion target disseminationStage is not narwhalBatchDissemination")
if completion_target.get("ordering") != "bullshark":
    errors.append("completion target ordering is not bullshark")
if completion_target.get("checkpointDecisionSource") != "bullsharkCommit":
    errors.append("completion target checkpointDecisionSource is not bullsharkCommit")
if completion_target.get("committee") != "superRepresentative21":
    errors.append("completion target committee is not superRepresentative21")
if completion_target.get("committeeStage") != "sr21EpochRotation":
    errors.append("completion target committeeStage is not sr21EpochRotation")
if completion_target.get("committeeSelection") != "stakeWeightedTop21Election":
    errors.append("completion target committeeSelection is not stakeWeightedTop21Election")
if completion_target.get("committeeSizeCap") != 21:
    errors.append("completion target committeeSizeCap is not 21")

if errors:
    payload["status"] = "failed"
    payload["errors"] = errors
    result_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    raise SystemExit(1)
PY

echo "narwhal dissemination rehearsal passed"
echo "  $result_file"
