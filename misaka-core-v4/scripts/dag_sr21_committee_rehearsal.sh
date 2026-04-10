#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
state_dir="${MISAKA_SR21_COMMITTEE_REHEARSAL_DIR:-$repo_root/.tmp/dag-sr21-committee-rehearsal}"
result_file="${MISAKA_SR21_COMMITTEE_REHEARSAL_RESULT:-$state_dir/result.json}"
target_dir="${MISAKA_CARGO_TARGET_DIR:-$repo_root/.tmp/dag-sr21-committee-target}"
log_file="$state_dir/cargo-test.log"
test_filter="live_sr21_committee_preview_visible_through_rpc_service"

usage() {
  cat <<'EOF'
Usage: ./scripts/dag_sr21_committee_rehearsal.sh

Runs the confined SR21 committee live RPC rehearsal and writes:

  .tmp/dag-sr21-committee-rehearsal/result.json

Optional env:
  MISAKA_SR21_COMMITTEE_REHEARSAL_DIR=/custom/output/dir
  MISAKA_SR21_COMMITTEE_REHEARSAL_RESULT=/custom/result.json
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
export MISAKA_SR21_COMMITTEE_REHEARSAL_RESULT="$result_file"
rm -f "$result_file"

cd "$repo_root"

if ! cargo test -p misaka-node --bin misaka-node \
  "$test_filter" \
  -- --nocapture >"$log_file" 2>&1; then
  write_failure "sr21 committee rehearsal regression failed"
  cat "$log_file" >&2
  exit 1
fi

if [[ ! -f "$result_file" ]]; then
  write_failure "sr21 committee rehearsal passed but did not emit result artifact"
  exit 1
fi

python3 - "$result_file" <<'PY'
import json
import pathlib
import sys

result_path = pathlib.Path(sys.argv[1])
payload = json.loads(result_path.read_text(encoding="utf-8"))

chain_info = payload.get("chainInfo", {}).get("sr21Committee", {})
dag_info = payload.get("dagInfo", {}).get("sr21Committee", {})
consistency = payload.get("consistency", {})
architecture = payload.get("consensusArchitecture", {})
errors = []

if payload.get("status") != "passed":
    errors.append(f"status is not passed: {payload.get('status')!r}")
if payload.get("flow") != "live_sr21_committee_preview_visible_through_rpc_service":
    errors.append(f"unexpected flow: {payload.get('flow')!r}")
if chain_info.get("knownValidatorCount") != 4:
    errors.append("knownValidatorCount is not 4")
if chain_info.get("eligibleValidatorCount") != 3:
    errors.append("eligibleValidatorCount is not 3")
if chain_info.get("activeCount") != 3:
    errors.append("activeCount is not 3")
if chain_info.get("configuredActiveCount") != 3:
    errors.append("configuredActiveCount is not 3")
if chain_info.get("previewQuorumThreshold") != "3":
    errors.append("previewQuorumThreshold is not 3")
if chain_info.get("runtimeQuorumThreshold") != "3":
    errors.append("runtimeQuorumThreshold is not 3")
if chain_info.get("quorumThresholdConsistent") is not True:
    errors.append("quorumThresholdConsistent is not true")
if chain_info.get("currentEpoch") != 0:
    errors.append("currentEpoch is not 0")
if chain_info.get("localValidatorPresent") is not True:
    errors.append("localValidatorPresent is not true")
if chain_info.get("localValidatorInActiveSet") is not True:
    errors.append("localValidatorInActiveSet is not true")
if chain_info.get("previewMatchesRuntime") is not True:
    errors.append("previewMatchesRuntime is not true")
if chain_info.get("runtimeActiveCountConsistent") is not True:
    errors.append("runtimeActiveCountConsistent is not true")
if chain_info.get("localRuntimeSrIndexConsistent") is not True:
    errors.append("localRuntimeSrIndexConsistent is not true")
if chain_info.get("runtimeActiveSetPresent") is not True:
    errors.append("runtimeActiveSetPresent is not true")
if chain_info.get("runtimeActiveSetCount") != 3:
    errors.append("runtimeActiveSetCount is not 3")
if chain_info.get("runtimeActiveSetMatchesPreview") is not True:
    errors.append("runtimeActiveSetMatchesPreview is not true")
active_set = chain_info.get("activeSetPreview")
if not isinstance(active_set, list) or len(active_set) != 3:
    errors.append("activeSetPreview must contain 3 entries")
elif active_set[0].get("isLocal") is not True:
    errors.append("first activeSetPreview entry should be local")
runtime_active_set = chain_info.get("runtimeActiveSet")
if not isinstance(runtime_active_set, list) or len(runtime_active_set) != 3:
    errors.append("runtimeActiveSet must contain 3 entries")
elif runtime_active_set[0].get("isLocal") is not True:
    errors.append("first runtimeActiveSet entry should be local")
if dag_info.get("activeCount") != 3:
    errors.append("dagInfo activeCount is not 3")
if dag_info.get("previewMatchesRuntime") is not True:
    errors.append("dagInfo previewMatchesRuntime is not true")
if dag_info.get("previewQuorumThreshold") != "3":
    errors.append("dagInfo previewQuorumThreshold is not 3")
if dag_info.get("runtimeQuorumThreshold") != "3":
    errors.append("dagInfo runtimeQuorumThreshold is not 3")
if dag_info.get("runtimeActiveSetPresent") is not True:
    errors.append("dagInfo runtimeActiveSetPresent is not true")
if dag_info.get("runtimeActiveSetCount") != 3:
    errors.append("dagInfo runtimeActiveSetCount is not 3")
if dag_info.get("runtimeActiveSetMatchesPreview") is not True:
    errors.append("dagInfo runtimeActiveSetMatchesPreview is not true")

for key in (
    "previewVisibleThroughChainInfo",
    "previewVisibleThroughDagInfo",
    "localValidatorActiveInPreview",
    "activeCountConsistent",
    "runtimeActiveSetApplied",
    "quorumThresholdConsistent",
    "chainDagCommitteeSummaryConsistent",
    "currentRuntimeStillValidatorBreadth",
    "completionTargetMatchesPlan",
):
    if consistency.get(key) is not True:
        errors.append(f"consistency flag is not true: {key}")

current_runtime = architecture.get("currentRuntime", {})
completion_target = architecture.get("completionTarget", {})
if current_runtime.get("committee") != "validatorBreadth":
    errors.append("current runtime committee is not validatorBreadth")
if current_runtime.get("committeeStage") != "validatorBreadthProof":
    errors.append("current runtime committeeStage is not validatorBreadthProof")
if current_runtime.get("committeeSelection") != "validatorBreadthRehearsal":
    errors.append("current runtime committeeSelection is not validatorBreadthRehearsal")
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

echo "sr21 committee rehearsal passed"
echo "  $result_file"
