#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
state_dir="${MISAKA_SR21_SELECTION_REHEARSAL_DIR:-$repo_root/.tmp/dag-sr21-selection-rehearsal}"
result_file="${MISAKA_SR21_SELECTION_REHEARSAL_RESULT:-$state_dir/result.json}"
target_dir="${MISAKA_CARGO_TARGET_DIR:-$repo_root/.tmp/dag-sr21-selection-target}"
log_file="$state_dir/cargo-test.log"
test_filter="live_sr21_top21_selection_epoch_boundary_visible_through_rpc_service"

usage() {
  cat <<'EOF'
Usage: ./scripts/dag_sr21_selection_rehearsal.sh

Runs the confined SR21 top-21 selection live RPC rehearsal and writes:

  .tmp/dag-sr21-selection-rehearsal/result.json

Optional env:
  MISAKA_SR21_SELECTION_REHEARSAL_DIR=/custom/output/dir
  MISAKA_SR21_SELECTION_REHEARSAL_RESULT=/custom/result.json
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
export MISAKA_SR21_SELECTION_REHEARSAL_RESULT="$result_file"
rm -f "$result_file"

cd "$repo_root"

if ! cargo test -p misaka-node --bin misaka-node \
  "$test_filter" \
  -- --nocapture >"$log_file" 2>&1; then
  write_failure "sr21 selection rehearsal regression failed"
  cat "$log_file" >&2
  exit 1
fi

if [[ ! -f "$result_file" ]]; then
  write_failure "sr21 selection rehearsal passed but did not emit result artifact"
  exit 1
fi

python3 - "$result_file" <<'PY'
import json
import pathlib
import sys

result_path = pathlib.Path(sys.argv[1])
payload = json.loads(result_path.read_text(encoding="utf-8"))

boundary = payload.get("selectionBoundary", {})
before_chain = payload.get("beforeApply", {}).get("chainInfo", {}).get("sr21Committee", {})
after_chain = payload.get("afterApply", {}).get("chainInfo", {}).get("sr21Committee", {})
after_dag = payload.get("afterApply", {}).get("dagInfo", {}).get("sr21Committee", {})
consistency = payload.get("consistency", {})
architecture = payload.get("consensusArchitecture", {})
errors = []

if payload.get("status") != "passed":
    errors.append(f"status is not passed: {payload.get('status')!r}")
if payload.get("flow") != "live_sr21_top21_selection_epoch_boundary_visible_through_rpc_service":
    errors.append(f"unexpected flow: {payload.get('flow')!r}")
if payload.get("appliedEpoch") != 1:
    errors.append("appliedEpoch is not 1")

if boundary.get("knownValidatorCount") != 25:
    errors.append("knownValidatorCount is not 25")
if boundary.get("eligibleValidatorCount") != 23:
    errors.append("eligibleValidatorCount is not 23")
if boundary.get("selectedCount") != 21:
    errors.append("selectedCount is not 21")
if boundary.get("droppedCount") != 4:
    errors.append("droppedCount is not 4")
if not isinstance(boundary.get("expectedExcludedEligibleValidatorIds"), list) or len(boundary.get("expectedExcludedEligibleValidatorIds")) != 2:
    errors.append("expectedExcludedEligibleValidatorIds must contain 2 entries")
if not isinstance(boundary.get("expectedExcludedIneligibleValidatorIds"), list) or len(boundary.get("expectedExcludedIneligibleValidatorIds")) != 2:
    errors.append("expectedExcludedIneligibleValidatorIds must contain 2 entries")

if before_chain.get("currentEpoch") != 1:
    errors.append("beforeApply currentEpoch is not 1")
if before_chain.get("knownValidatorCount") != 25:
    errors.append("beforeApply knownValidatorCount is not 25")
if before_chain.get("eligibleValidatorCount") != 23:
    errors.append("beforeApply eligibleValidatorCount is not 23")
if before_chain.get("activeCount") != 21:
    errors.append("beforeApply activeCount is not 21")
if before_chain.get("configuredActiveCount") != 1:
    errors.append("beforeApply configuredActiveCount is not 1")
if before_chain.get("previewQuorumThreshold") != "15":
    errors.append("beforeApply previewQuorumThreshold is not 15")
if before_chain.get("runtimeQuorumThreshold") != "1":
    errors.append("beforeApply runtimeQuorumThreshold is not 1")
if before_chain.get("quorumThresholdConsistent") is not False:
    errors.append("beforeApply quorumThresholdConsistent is not false")
if before_chain.get("droppedCount") != 4:
    errors.append("beforeApply droppedCount is not 4")
if before_chain.get("previewMatchesRuntime") is not False:
    errors.append("beforeApply previewMatchesRuntime is not false")
if before_chain.get("runtimeActiveSetPresent") is not False:
    errors.append("beforeApply runtimeActiveSetPresent is not false")
if before_chain.get("runtimeActiveSetCount") != 0:
    errors.append("beforeApply runtimeActiveSetCount is not 0")
if before_chain.get("runtimeActiveSetMatchesPreview") is not False:
    errors.append("beforeApply runtimeActiveSetMatchesPreview is not false")

if after_chain.get("currentEpoch") != 1:
    errors.append("afterApply currentEpoch is not 1")
if after_chain.get("knownValidatorCount") != 25:
    errors.append("afterApply knownValidatorCount is not 25")
if after_chain.get("eligibleValidatorCount") != 23:
    errors.append("afterApply eligibleValidatorCount is not 23")
if after_chain.get("activeCount") != 21:
    errors.append("afterApply activeCount is not 21")
if after_chain.get("configuredActiveCount") != 21:
    errors.append("afterApply configuredActiveCount is not 21")
if after_chain.get("previewQuorumThreshold") != "15":
    errors.append("afterApply previewQuorumThreshold is not 15")
if after_chain.get("runtimeQuorumThreshold") != "15":
    errors.append("afterApply runtimeQuorumThreshold is not 15")
if after_chain.get("quorumThresholdConsistent") is not True:
    errors.append("afterApply quorumThresholdConsistent is not true")
if after_chain.get("droppedCount") != 4:
    errors.append("afterApply droppedCount is not 4")
if after_chain.get("localValidatorPresent") is not True:
    errors.append("afterApply localValidatorPresent is not true")
if after_chain.get("localValidatorInActiveSet") is not True:
    errors.append("afterApply localValidatorInActiveSet is not true")
if after_chain.get("localPreviewSrIndex") != 20:
    errors.append("afterApply localPreviewSrIndex is not 20")
if after_chain.get("localRuntimeSrIndex") != 20:
    errors.append("afterApply localRuntimeSrIndex is not 20")
if after_chain.get("runtimeActiveCountConsistent") is not True:
    errors.append("afterApply runtimeActiveCountConsistent is not true")
if after_chain.get("localRuntimeSrIndexConsistent") is not True:
    errors.append("afterApply localRuntimeSrIndexConsistent is not true")
if after_chain.get("previewMatchesRuntime") is not True:
    errors.append("afterApply previewMatchesRuntime is not true")
if after_chain.get("runtimeActiveSetPresent") is not True:
    errors.append("afterApply runtimeActiveSetPresent is not true")
if after_chain.get("runtimeActiveSetCount") != 21:
    errors.append("afterApply runtimeActiveSetCount is not 21")
if after_chain.get("runtimeActiveSetMatchesPreview") is not True:
    errors.append("afterApply runtimeActiveSetMatchesPreview is not true")
active_set = after_chain.get("activeSetPreview")
if not isinstance(active_set, list) or len(active_set) != 21:
    errors.append("afterApply activeSetPreview must contain 21 entries")
elif active_set[20].get("isLocal") is not True:
    errors.append("21st activeSetPreview entry should be local")
runtime_active_set = after_chain.get("runtimeActiveSet")
if not isinstance(runtime_active_set, list) or len(runtime_active_set) != 21:
    errors.append("afterApply runtimeActiveSet must contain 21 entries")
elif runtime_active_set[20].get("isLocal") is not True:
    errors.append("21st runtimeActiveSet entry should be local")

if after_dag.get("currentEpoch") != 1:
    errors.append("afterApply dagInfo currentEpoch is not 1")
if after_dag.get("activeCount") != 21:
    errors.append("afterApply dagInfo activeCount is not 21")
if after_dag.get("configuredActiveCount") != 21:
    errors.append("afterApply dagInfo configuredActiveCount is not 21")
if after_dag.get("droppedCount") != 4:
    errors.append("afterApply dagInfo droppedCount is not 4")
if after_dag.get("previewMatchesRuntime") is not True:
    errors.append("afterApply dagInfo previewMatchesRuntime is not true")
if after_dag.get("previewQuorumThreshold") != "15":
    errors.append("afterApply dagInfo previewQuorumThreshold is not 15")
if after_dag.get("runtimeQuorumThreshold") != "15":
    errors.append("afterApply dagInfo runtimeQuorumThreshold is not 15")
if after_dag.get("runtimeActiveSetPresent") is not True:
    errors.append("afterApply dagInfo runtimeActiveSetPresent is not true")
if after_dag.get("runtimeActiveSetCount") != 21:
    errors.append("afterApply dagInfo runtimeActiveSetCount is not 21")
if after_dag.get("runtimeActiveSetMatchesPreview") is not True:
    errors.append("afterApply dagInfo runtimeActiveSetMatchesPreview is not true")

for key in (
    "selectionBoundaryVisibleBeforeApply",
    "runtimeActiveSetMissingBeforeApply",
    "selectionBoundaryApplied",
    "runtimeActiveSetApplied",
    "committeeCapApplied",
    "quorumThresholdApplied",
    "localValidatorSelectedAtBoundary",
    "eligibleOverflowExcludedAfterApply",
    "ineligibleExcludedAfterApply",
    "chainDagCommitteeSummaryConsistentAfterApply",
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

echo "sr21 selection rehearsal passed"
echo "  $result_file"
