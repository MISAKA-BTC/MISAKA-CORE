#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
state_dir="${MISAKA_BULLSHARK_ORDERING_REHEARSAL_DIR:-$repo_root/.tmp/dag-bullshark-ordering-rehearsal}"
result_file="${MISAKA_BULLSHARK_ORDERING_REHEARSAL_RESULT:-$state_dir/result.json}"
target_dir="${MISAKA_CARGO_TARGET_DIR:-$repo_root/.tmp/dag-bullshark-ordering-target}"
log_file="$state_dir/cargo-test.log"
test_filter="live_bullshark_ordering_candidate_and_commit_preview_handoff"

usage() {
  cat <<'EOF'
Usage: ./scripts/dag_bullshark_ordering_rehearsal.sh

Runs the confined Bullshark ordering rehearsal and writes:

  .tmp/dag-bullshark-ordering-rehearsal/result.json

Optional env:
  MISAKA_BULLSHARK_ORDERING_REHEARSAL_DIR=/custom/output/dir
  MISAKA_BULLSHARK_ORDERING_REHEARSAL_RESULT=/custom/result.json
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
export MISAKA_BULLSHARK_ORDERING_REHEARSAL_RESULT="$result_file"
rm -f "$result_file"

cd "$repo_root"

if ! cargo test -p misaka-node --bin misaka-node \
  "$test_filter" \
  -- --nocapture >"$log_file" 2>&1; then
  write_failure "bullshark ordering rehearsal regression failed"
  cat "$log_file" >&2
  exit 1
fi

if [[ ! -f "$result_file" ]]; then
  write_failure "bullshark ordering rehearsal passed but did not emit result artifact"
  exit 1
fi

python3 - "$result_file" <<'PY'
import json
import pathlib
import sys

result_path = pathlib.Path(sys.argv[1])
payload = json.loads(result_path.read_text(encoding="utf-8"))

initial = payload.get("initial", {}).get("chainInfo", {})
delivered = payload.get("afterDeliveredBatch", {}).get("chainInfo", {})
candidate = payload.get("afterCandidatePreview", {}).get("chainInfo", {})
commit = payload.get("afterCommitPreview", {}).get("chainInfo", {})
candidate_runtime_recovery = payload.get("afterCandidatePreview", {}).get("runtimeRecovery", {})
commit_runtime_recovery = payload.get("afterCommitPreview", {}).get("runtimeRecovery", {})
candidate_preview_hashes = payload.get("afterCandidatePreview", {}).get("previewHashes", {})
commit_preview_hashes = payload.get("afterCommitPreview", {}).get("previewHashes", {})
consistency = payload.get("consistency", {})
architecture = payload.get("consensusArchitecture", {})
initial_state = initial.get("completionTargetShadowState", {})
delivered_state = delivered.get("completionTargetShadowState", {})
candidate_state = candidate.get("completionTargetShadowState", {})
commit_state = commit.get("completionTargetShadowState", {})
errors = []

if payload.get("status") != "passed":
    errors.append(f"status is not passed: {payload.get('status')!r}")
if payload.get("flow") != "live_bullshark_ordering_candidate_and_commit_preview_handoff":
    errors.append(f"unexpected flow: {payload.get('flow')!r}")
tx_hashes = payload.get("txHashes")
if not isinstance(tx_hashes, list) or len(tx_hashes) != 2 or len(set(tx_hashes)) != 2:
    errors.append("txHashes must contain two distinct entries")
if initial_state.get("queued") != 0:
    errors.append("initial ordering queued is not 0")
if delivered_state.get("queued") != 2:
    errors.append("delivered ordering queued is not 2")
if delivered_state.get("candidatePreviewQueued") != 0:
    errors.append("delivered candidatePreviewQueued should still be 0")
if candidate_state.get("candidatePreviewQueued") != 2:
    errors.append("candidate preview queue count is not 2")
if candidate_state.get("candidatePreviewFastTransparentQueued") != 1:
    errors.append("candidate preview fastTransparentQueued is not 1")
if candidate_state.get("candidatePreviewShieldedQueued") != 1:
    errors.append("candidate preview shieldedQueued is not 1")
if candidate_state.get("candidatePreviewLive") is not True:
    errors.append("candidate preview is not live")
if commit_state.get("commitPreviewQueued") != 2:
    errors.append("commit preview queue count is not 2")
if commit_state.get("commitPreviewFastTransparentQueued") != 1:
    errors.append("commit preview fastTransparentQueued is not 1")
if commit_state.get("commitPreviewShieldedQueued") != 1:
    errors.append("commit preview shieldedQueued is not 1")
if commit_state.get("commitPreviewLive") is not True:
    errors.append("commit preview is not live")
if candidate_preview_hashes.get("any") != tx_hashes:
    errors.append("candidate preview any hashes do not match txHashes")
if candidate_preview_hashes.get("fastTransparent") is None or len(candidate_preview_hashes.get("fastTransparent")) != 1:
    errors.append("candidate preview fastTransparent hashes should contain one entry")
if candidate_preview_hashes.get("shielded") is None or len(candidate_preview_hashes.get("shielded")) != 1:
    errors.append("candidate preview shielded hashes should contain one entry")
if commit_preview_hashes.get("any") != tx_hashes:
    errors.append("commit preview any hashes do not match txHashes")
if commit_preview_hashes.get("fastTransparent") is None or len(commit_preview_hashes.get("fastTransparent")) != 1:
    errors.append("commit preview fastTransparent hashes should contain one entry")
if commit_preview_hashes.get("shielded") is None or len(commit_preview_hashes.get("shielded")) != 1:
    errors.append("commit preview shielded hashes should contain one entry")
if candidate_runtime_recovery.get("lastBullsharkCandidatePreviewCount") != 2:
    errors.append("runtimeRecovery candidate preview count is not 2")
if candidate_runtime_recovery.get("lastBullsharkCandidatePreviewTxHashes") != tx_hashes:
    errors.append("runtimeRecovery candidate preview hashes do not match txHashes")
if candidate_runtime_recovery.get("bullsharkCandidatePreviewObserved") is not True:
    errors.append("runtimeRecovery candidate preview observed flag is not true")
if commit_runtime_recovery.get("lastBullsharkCommitPreviewCount") != 2:
    errors.append("runtimeRecovery commit preview count is not 2")
if commit_runtime_recovery.get("lastBullsharkCommitPreviewTxHashes") != tx_hashes:
    errors.append("runtimeRecovery commit preview hashes do not match txHashes")
if commit_runtime_recovery.get("bullsharkCommitPreviewObserved") is not True:
    errors.append("runtimeRecovery commit preview observed flag is not true")
orch = commit.get("orchestration", {})
if orch.get("serviceBound") is not True:
    errors.append("ordering orchestration serviceBound is not true")
if orch.get("serviceRunning") is not True:
    errors.append("ordering orchestration serviceRunning is not true")
if orch.get("candidatePreviewCallerReady") is not True:
    errors.append("ordering candidatePreviewCallerReady is not true")
if orch.get("commitPreviewCallerReady") is not True:
    errors.append("ordering commitPreviewCallerReady is not true")
for key in (
    "serviceBoundThroughout",
    "serviceRunningThroughout",
    "candidatePreviewCallerReadyThroughout",
    "commitPreviewCallerReadyThroughout",
    "deliveredVisibleBeforePreview",
    "candidatePreviewVisibleAfterHandoff",
    "commitPreviewVisibleAfterHandoff",
    "producerCandidatePreviewHashesVisibleAfterHandoff",
    "finalityCommitPreviewHashesVisibleAfterHandoff",
    "runtimeRecoveryCandidatePreviewObserved",
    "runtimeRecoveryCommitPreviewObserved",
    "orderingContractReadyThroughout",
    "completionTargetMatchesPlan",
):
    if consistency.get(key) is not True:
        errors.append(f"consistency flag is not true: {key}")
current_runtime = architecture.get("currentRuntime", {})
completion_target = architecture.get("completionTarget", {})
if current_runtime.get("orderingStage") != "ghostdagTotalOrder":
    errors.append("current orderingStage is not ghostdagTotalOrder")
if current_runtime.get("checkpointDecisionSource") != "ghostdagCheckpointBft":
    errors.append("current checkpointDecisionSource is not ghostdagCheckpointBft")
if completion_target.get("orderingStage") != "bullsharkCommitOrder":
    errors.append("completion target orderingStage is not bullsharkCommitOrder")
if completion_target.get("orderingInput") != "narwhalDeliveredBatch":
    errors.append("completion target orderingInput is not narwhalDeliveredBatch")
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

echo "bullshark ordering rehearsal passed"
echo "  $result_file"
