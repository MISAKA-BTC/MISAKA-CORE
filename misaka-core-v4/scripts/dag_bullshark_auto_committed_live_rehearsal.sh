#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
state_dir="${MISAKA_BULLSHARK_AUTO_COMMITTED_LIVE_REHEARSAL_DIR:-$repo_root/.tmp/dag-bullshark-auto-committed-live-rehearsal}"
result_file="${MISAKA_BULLSHARK_AUTO_COMMITTED_LIVE_REHEARSAL_RESULT:-$state_dir/result.json}"
target_dir="${MISAKA_CARGO_TARGET_DIR:-$repo_root/.tmp/dag-bullshark-auto-committed-live-target}"
log_file="$state_dir/cargo-test.log"
test_filter="live_bullshark_commit_auto_visible_through_rpc_service"

usage() {
  cat <<'EOF'
Usage: ./scripts/dag_bullshark_auto_committed_live_rehearsal.sh

Runs the live Bullshark automatic committed rehearsal and writes:

  .tmp/dag-bullshark-auto-committed-live-rehearsal/result.json

Optional env:
  MISAKA_BULLSHARK_AUTO_COMMITTED_LIVE_REHEARSAL_DIR=/custom/output/dir
  MISAKA_BULLSHARK_AUTO_COMMITTED_LIVE_REHEARSAL_RESULT=/custom/result.json
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
export MISAKA_BULLSHARK_AUTO_COMMITTED_LIVE_REHEARSAL_RESULT="$result_file"
rm -f "$result_file"

cd "$repo_root"

if ! cargo test -p misaka-node --bin misaka-node \
  "$test_filter" \
  -- --nocapture >"$log_file" 2>&1; then
  write_failure "bullshark automatic committed live rehearsal regression failed"
  cat "$log_file" >&2
  exit 1
fi

if [[ ! -f "$result_file" ]]; then
  write_failure "bullshark automatic committed live rehearsal passed but did not emit result artifact"
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
delivered_dissemination = payload.get("afterDeliveredBatch", {}).get("txDissemination", {})
committed = payload.get("afterProducerAutoCommit", {}).get("chainInfo", {})
committed_dissemination = payload.get("afterProducerAutoCommit", {}).get("txDissemination", {})
runtime_recovery = payload.get("afterProducerAutoCommit", {}).get("runtimeRecovery", {})
commit_hashes = payload.get("afterProducerAutoCommit", {}).get("commitHashes", {})
after_restart = payload.get("afterRestart", {})
after_restart_chain = after_restart.get("chainInfo", {})
after_restart_dag = after_restart.get("dagInfo", {})
after_restart_commit_hashes = after_restart.get("commitHashes", {})
after_restart_ordering = after_restart_chain.get("orderingContract", {})
after_restart_runtime_recovery = after_restart_chain.get("runtimeRecovery", {})
after_restart_sr21 = after_restart_chain.get("sr21Committee", {})
after_restart_ordering_dag = after_restart_dag.get("orderingContract", {})
after_restart_sr21_dag = after_restart_dag.get("sr21Committee", {})
restart_consistency = payload.get("restartConsistency", {})
sr21_committee = payload.get("sr21Committee", {})
sr21_committee_dag = payload.get("sr21CommitteeDag", {})
consistency = payload.get("consistency", {})
architecture = payload.get("consensusArchitecture", {})
initial_state = initial.get("completionTargetShadowState", {})
delivered_state = delivered.get("completionTargetShadowState", {})
committed_state = committed.get("completionTargetShadowState", {})
after_restart_state = after_restart_ordering.get("completionTargetShadowState", {})
errors = []

if payload.get("status") != "passed":
    errors.append(f"status is not passed: {payload.get('status')!r}")
if payload.get("flow") != "live_bullshark_commit_auto_visible_through_rpc_service":
    errors.append(f"unexpected flow: {payload.get('flow')!r}")
tx_hashes = payload.get("txHashes")
if not isinstance(tx_hashes, list) or len(tx_hashes) != 2 or len(set(tx_hashes)) != 2:
    errors.append("txHashes must contain two distinct entries")
if initial_state.get("committedQueued") != 0:
    errors.append("initial committedQueued should be 0")
if delivered_state.get("queued") != 2:
    errors.append("delivered queued should be 2 before auto commit")
if delivered_state.get("candidatePreviewQueued") != 0:
    errors.append("delivered candidatePreviewQueued should be 0 before auto commit")
if delivered_state.get("commitPreviewQueued") != 0:
    errors.append("delivered commitPreviewQueued should be 0 before auto commit")
if delivered_state.get("committedQueued") != 0:
    errors.append("delivered committedQueued should be 0 before auto commit")
if delivered_dissemination.get("completionTargetDeliveredQueue", {}).get("queued") != 2:
    errors.append("completionTargetDeliveredQueue should be 2 after delivered batch")
if committed_state.get("candidatePreviewQueued") != 2:
    errors.append("candidatePreviewQueued should be 2 after auto commit")
if committed_state.get("candidatePreviewFastTransparentQueued") != 1:
    errors.append("candidatePreviewFastTransparentQueued should be 1")
if committed_state.get("candidatePreviewShieldedQueued") != 1:
    errors.append("candidatePreviewShieldedQueued should be 1")
if committed_state.get("candidatePreviewLive") is not True:
    errors.append("candidatePreviewLive should be true")
if committed_state.get("commitPreviewQueued") != 2:
    errors.append("commitPreviewQueued should be 2 after auto commit")
if committed_state.get("commitPreviewFastTransparentQueued") != 1:
    errors.append("commitPreviewFastTransparentQueued should be 1")
if committed_state.get("commitPreviewShieldedQueued") != 1:
    errors.append("commitPreviewShieldedQueued should be 1")
if committed_state.get("commitPreviewLive") is not True:
    errors.append("commitPreviewLive should be true")
if committed_state.get("committedQueued") != 2:
    errors.append("committedQueued should be 2 after auto commit")
if committed_state.get("committedFastTransparentQueued") != 1:
    errors.append("committedFastTransparentQueued should be 1")
if committed_state.get("committedShieldedQueued") != 1:
    errors.append("committedShieldedQueued should be 1")
if committed_state.get("committedLive") is not True:
    errors.append("committedLive should be true")
if committed_state.get("consistentWithCommitPreview") is not True:
    errors.append("consistentWithCommitPreview should be true")
if committed_dissemination.get("completionTargetDeliveredQueue", {}).get("queued") != 2:
    errors.append("completionTargetDeliveredQueue should remain 2 after auto commit")
if runtime_recovery.get("lastBullsharkCommitCount") != 2:
    errors.append("runtimeRecovery lastBullsharkCommitCount should be 2 after auto commit")
if runtime_recovery.get("lastBullsharkCommitTxHashes") != tx_hashes:
    errors.append("runtimeRecovery lastBullsharkCommitTxHashes should match txHashes")
if runtime_recovery.get("bullsharkCommitObserved") is not True:
    errors.append("runtimeRecovery bullsharkCommitObserved should be true")
if commit_hashes.get("any") != tx_hashes:
    errors.append("commit any hashes do not match txHashes")
if commit_hashes.get("fastTransparent") is None or len(commit_hashes.get("fastTransparent")) != 1:
    errors.append("commit fastTransparent hashes should contain one entry")
if commit_hashes.get("shielded") is None or len(commit_hashes.get("shielded")) != 1:
    errors.append("commit shielded hashes should contain one entry")
if sr21_committee.get("previewMatchesRuntime") is not True:
    errors.append("sr21 previewMatchesRuntime is not true")
if sr21_committee.get("runtimeActiveCountConsistent") is not True:
    errors.append("sr21 runtimeActiveCountConsistent is not true")
if sr21_committee.get("localRuntimeSrIndexConsistent") is not True:
    errors.append("sr21 localRuntimeSrIndexConsistent is not true")
if sr21_committee.get("selection") != "stakeWeightedTop21Election":
    errors.append("sr21 selection is not stakeWeightedTop21Election")
if sr21_committee.get("rotationStage") != "sr21EpochRotation":
    errors.append("sr21 rotationStage is not sr21EpochRotation")
if sr21_committee.get("committeeSizeCap") != 21:
    errors.append("sr21 committeeSizeCap is not 21")
if sr21_committee_dag.get("previewMatchesRuntime") is not True:
    errors.append("sr21 dag previewMatchesRuntime is not true")
if sr21_committee.get("activeCount") != sr21_committee_dag.get("activeCount"):
    errors.append("sr21 chain/dag activeCount mismatch")
if sr21_committee.get("configuredActiveCount") != sr21_committee_dag.get("configuredActiveCount"):
    errors.append("sr21 chain/dag configuredActiveCount mismatch")
if sr21_committee.get("localValidatorPresent") != sr21_committee_dag.get("localValidatorPresent"):
    errors.append("sr21 chain/dag localValidatorPresent mismatch")
if sr21_committee.get("localValidatorInActiveSet") != sr21_committee_dag.get("localValidatorInActiveSet"):
    errors.append("sr21 chain/dag localValidatorInActiveSet mismatch")
orch = committed.get("orchestration", {})
if orch.get("serviceBound") is not True:
    errors.append("ordering orchestration serviceBound is not true")
if orch.get("serviceRunning") is not True:
    errors.append("ordering orchestration serviceRunning is not true")
if orch.get("candidatePreviewCallerReady") is not True:
    errors.append("ordering candidatePreviewCallerReady is not true")
if orch.get("commitPreviewCallerReady") is not True:
    errors.append("ordering commitPreviewCallerReady is not true")
if orch.get("commitCallerReady") is not True:
    errors.append("ordering commitCallerReady is not true")
if after_restart_state.get("candidatePreviewQueued") != 2:
    errors.append("afterRestart candidatePreviewQueued should be 2")
if after_restart_state.get("commitPreviewQueued") != 2:
    errors.append("afterRestart commitPreviewQueued should be 2")
if after_restart_state.get("committedQueued") != 2:
    errors.append("afterRestart committedQueued should be 2")
if after_restart_state.get("committedFastTransparentQueued") != 1:
    errors.append("afterRestart committedFastTransparentQueued should be 1")
if after_restart_state.get("committedShieldedQueued") != 1:
    errors.append("afterRestart committedShieldedQueued should be 1")
if after_restart_state.get("committedLive") is not True:
    errors.append("afterRestart committedLive should be true")
if after_restart_state.get("consistentWithCommitPreview") is not True:
    errors.append("afterRestart consistentWithCommitPreview should be true")
restart_orch = after_restart_ordering.get("orchestration", {})
if restart_orch.get("serviceBound") is not True:
    errors.append("afterRestart ordering orchestration serviceBound is not true")
if restart_orch.get("serviceRunning") is not True:
    errors.append("afterRestart ordering orchestration serviceRunning is not true")
if restart_orch.get("candidatePreviewCallerReady") is not True:
    errors.append("afterRestart candidatePreviewCallerReady is not true")
if restart_orch.get("commitPreviewCallerReady") is not True:
    errors.append("afterRestart commitPreviewCallerReady is not true")
if restart_orch.get("commitCallerReady") is not True:
    errors.append("afterRestart commitCallerReady is not true")
if after_restart_runtime_recovery.get("lastBullsharkCommitCount") != 2:
    errors.append("afterRestart runtimeRecovery lastBullsharkCommitCount should be 2")
if after_restart_runtime_recovery.get("lastBullsharkCommitTxHashes") != tx_hashes:
    errors.append("afterRestart runtimeRecovery lastBullsharkCommitTxHashes should match txHashes")
if after_restart_runtime_recovery.get("bullsharkCommitObserved") is not True:
    errors.append("afterRestart runtimeRecovery bullsharkCommitObserved should be true")
if after_restart_commit_hashes.get("any") != tx_hashes:
    errors.append("afterRestart commit any hashes do not match txHashes")
if after_restart_commit_hashes.get("fastTransparent") is None or len(after_restart_commit_hashes.get("fastTransparent")) != 1:
    errors.append("afterRestart commit fastTransparent hashes should contain one entry")
if after_restart_commit_hashes.get("shielded") is None or len(after_restart_commit_hashes.get("shielded")) != 1:
    errors.append("afterRestart commit shielded hashes should contain one entry")
if after_restart_sr21.get("previewMatchesRuntime") is not True:
    errors.append("afterRestart sr21 previewMatchesRuntime is not true")
if after_restart_sr21.get("runtimeActiveCountConsistent") is not True:
    errors.append("afterRestart sr21 runtimeActiveCountConsistent is not true")
if after_restart_sr21.get("localRuntimeSrIndexConsistent") is not True:
    errors.append("afterRestart sr21 localRuntimeSrIndexConsistent is not true")
if after_restart_sr21.get("activeCount") != after_restart_sr21_dag.get("activeCount"):
    errors.append("afterRestart sr21 chain/dag activeCount mismatch")
if after_restart_sr21.get("configuredActiveCount") != after_restart_sr21_dag.get("configuredActiveCount"):
    errors.append("afterRestart sr21 chain/dag configuredActiveCount mismatch")
if after_restart_sr21.get("previewMatchesRuntime") != after_restart_sr21_dag.get("previewMatchesRuntime"):
    errors.append("afterRestart sr21 chain/dag previewMatchesRuntime mismatch")
if after_restart_ordering.get("completionTargetShadowState") != after_restart_ordering_dag.get("completionTargetShadowState"):
    errors.append("afterRestart chain/dag orderingContract shadow state mismatch")
for key in (
    "serviceBoundThroughout",
    "serviceRunningThroughout",
    "candidatePreviewCallerReadyThroughout",
    "commitPreviewCallerReadyThroughout",
    "commitCallerReadyThroughout",
    "deliveredVisibleBeforeAutoCommit",
    "candidatePreviewVisibleAfterAutoAdvance",
    "commitPreviewVisibleAfterAutoAdvance",
    "commitVisibleAfterAutoAdvance",
    "commitHashesVisibleAfterAutoAdvance",
    "runtimeRecoveryCommitObserved",
    "sr21PreviewVisibleThroughChainInfo",
    "sr21PreviewVisibleThroughDagInfo",
    "sr21LocalPreviewStateConsistent",
    "sr21ActiveCountConsistent",
    "sr21ChainDagCommitteeSummaryConsistent",
    "sr21CurrentRuntimeStillValidatorBreadth",
    "sr21CompletionTargetCommitteeMatchesPlan",
    "orderingContractReadyThroughout",
    "authoritativeCheckpointSourceUnchanged",
    "completionTargetMatchesPlan",
):
    if consistency.get(key) is not True:
        errors.append(f"consistency flag is not true: {key}")
for key in (
    "snapshotArtifactsWritten",
    "serviceRestartContinuity",
    "committedStatePersistedAfterRestart",
    "runtimeRecoveryCommitPersistedAfterRestart",
    "chainDagCommittedSummaryConsistentAfterRestart",
    "committeeStatePersistedAfterRestart",
    "currentRuntimeStillValidatorBreadthAfterRestart",
    "completionTargetMatchesPlanAfterRestart",
):
    if restart_consistency.get(key) is not True:
        errors.append(f"restartConsistency flag is not true: {key}")
if restart_consistency.get("rehydratedAfterRestart") is not False:
    errors.append("restartConsistency rehydratedAfterRestart should remain false")
if not isinstance(restart_consistency.get("startupSnapshotRestoredAfterRestart"), bool):
    errors.append("restartConsistency startupSnapshotRestoredAfterRestart should be a boolean")
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

echo "bullshark automatic committed live rehearsal passed"
echo "  $result_file"
