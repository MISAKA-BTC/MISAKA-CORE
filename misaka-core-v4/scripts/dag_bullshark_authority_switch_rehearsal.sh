#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
state_dir="${MISAKA_BULLSHARK_AUTHORITY_SWITCH_REHEARSAL_DIR:-$repo_root/.tmp/dag-bullshark-authority-switch-rehearsal}"
result_file="${MISAKA_BULLSHARK_AUTHORITY_SWITCH_REHEARSAL_RESULT:-$state_dir/result.json}"
target_dir="${MISAKA_CARGO_TARGET_DIR:-$repo_root/.tmp/dag-bullshark-authority-switch-target}"
log_file="$state_dir/cargo-test.log"
test_filter="live_bullshark_authority_switch_preconditions_visible_through_rpc_service"

usage() {
  cat <<'EOF'
Usage: ./scripts/dag_bullshark_authority_switch_rehearsal.sh

Runs the confined Bullshark authority-switch live RPC rehearsal and writes:

  .tmp/dag-bullshark-authority-switch-rehearsal/result.json

Optional env:
  MISAKA_BULLSHARK_AUTHORITY_SWITCH_REHEARSAL_DIR=/custom/output/dir
  MISAKA_BULLSHARK_AUTHORITY_SWITCH_REHEARSAL_RESULT=/custom/result.json
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
export MISAKA_BULLSHARK_AUTHORITY_SWITCH_REHEARSAL_RESULT="$result_file"
rm -f "$result_file"

cd "$repo_root"

if ! cargo test -p misaka-node --bin misaka-node \
  "$test_filter" \
  -- --nocapture >"$log_file" 2>&1; then
  write_failure "bullshark authority-switch rehearsal regression failed"
  cat "$log_file" >&2
  exit 1
fi

if [[ ! -f "$result_file" ]]; then
  write_failure "bullshark authority-switch rehearsal passed but did not emit result artifact"
  exit 1
fi

python3 - "$result_file" <<'PY'
import json
import pathlib
import sys

result_path = pathlib.Path(sys.argv[1])
payload = json.loads(result_path.read_text(encoding="utf-8"))

before_apply = payload.get("beforeApply", {}).get("chainInfo", {})
after_apply = payload.get("afterApply", {}).get("chainInfo", {})
after_commit_chain = payload.get("afterCommit", {}).get("chainInfo", {})
after_commit_dag = payload.get("afterCommit", {}).get("dagInfo", {})
after_restart_chain = payload.get("afterRestart", {}).get("chainInfo", {})
after_restart_dag = payload.get("afterRestart", {}).get("dagInfo", {})
consistency = payload.get("consistency", {})
restart_consistency = payload.get("restartConsistency", {})
architecture = payload.get("consensusArchitecture", {})
commit_hashes = payload.get("afterCommit", {}).get("commitHashes", {})
restarted_commit_hashes = payload.get("afterRestart", {}).get("commitHashes", {})
errors = []

if payload.get("status") != "passed":
    errors.append(f"status is not passed: {payload.get('status')!r}")
if payload.get("flow") != "live_bullshark_authority_switch_preconditions_visible_through_rpc_service":
    errors.append(f"unexpected flow: {payload.get('flow')!r}")
tx_hashes = payload.get("txHashes")
if not isinstance(tx_hashes, list) or len(tx_hashes) != 2 or len(set(tx_hashes)) != 2:
    errors.append("txHashes must contain two distinct entries")

if before_apply.get("authoritySwitchReadiness", {}).get("ready") is not False:
    errors.append("beforeApply authoritySwitchReadiness.ready should be false")
if after_apply.get("authoritySwitchReadiness", {}).get("committeeSelectionReady") is not True:
    errors.append("afterApply committeeSelectionReady should be true")
if after_apply.get("authoritySwitchReadiness", {}).get("committeeRotationReady") is not True:
    errors.append("afterApply committeeRotationReady should be true")
if after_apply.get("authoritySwitchReadiness", {}).get("committeeQuorumThresholdReady") is not True:
    errors.append("afterApply committeeQuorumThresholdReady should be true")
if after_apply.get("authoritySwitchReadiness", {}).get("committeePreviewQuorumThreshold") != "15":
    errors.append("afterApply committeePreviewQuorumThreshold should be 15")
if after_apply.get("authoritySwitchReadiness", {}).get("committeeRuntimeQuorumThreshold") != "15":
    errors.append("afterApply committeeRuntimeQuorumThreshold should be 15")
if after_apply.get("authoritySwitchReadiness", {}).get("committedReady") is not False:
    errors.append("afterApply committedReady should still be false")
if after_apply.get("authoritySwitchReadiness", {}).get("ready") is not False:
    errors.append("afterApply authoritySwitchReadiness.ready should still be false")

chain_readiness = after_commit_chain.get("authoritySwitchReadiness", {})
dag_readiness = after_commit_dag.get("authoritySwitchReadiness", {})
if chain_readiness.get("ready") is not True:
    errors.append("afterCommit chain authoritySwitchReadiness.ready should be true")
if dag_readiness.get("ready") is not True:
    errors.append("afterCommit dag authoritySwitchReadiness.ready should be true")
if chain_readiness != dag_readiness:
    errors.append("afterCommit chain/dag authoritySwitchReadiness should match")
if chain_readiness.get("candidatePreviewQueued") != 2:
    errors.append("candidatePreviewQueued should be 2")
if chain_readiness.get("commitPreviewQueued") != 2:
    errors.append("commitPreviewQueued should be 2")
if chain_readiness.get("committedQueued") != 2:
    errors.append("committedQueued should be 2")
if chain_readiness.get("runtimeRecoveryCommitObserved") is not True:
    errors.append("runtimeRecoveryCommitObserved should be true")
if chain_readiness.get("runtimeRecoveryCommitCount") != 2:
    errors.append("runtimeRecoveryCommitCount should be 2")
if chain_readiness.get("runtimeRecoveryCommitTxHashes") != tx_hashes:
    errors.append("runtimeRecoveryCommitTxHashes should match txHashes")
if chain_readiness.get("runtimeRecoveryCommitConsistent") is not True:
    errors.append("runtimeRecoveryCommitConsistent should be true")
if chain_readiness.get("currentAuthorityRetained") is not True:
    errors.append("currentAuthorityRetained should be true")
if chain_readiness.get("bullsharkPlanReady") is not True:
    errors.append("bullsharkPlanReady should be true")
if chain_readiness.get("committeePlanReady") is not True:
    errors.append("committeePlanReady should be true")
if chain_readiness.get("committeeQuorumThresholdReady") is not True:
    errors.append("committeeQuorumThresholdReady should be true")
if chain_readiness.get("committeePreviewQuorumThreshold") != "15":
    errors.append("committeePreviewQuorumThreshold should be 15")
if chain_readiness.get("committeeRuntimeQuorumThreshold") != "15":
    errors.append("committeeRuntimeQuorumThreshold should be 15")

sr21 = after_commit_chain.get("sr21Committee", {})
if sr21.get("activeCount") != 21:
    errors.append("afterCommit activeCount should be 21")
if sr21.get("configuredActiveCount") != 21:
    errors.append("afterCommit configuredActiveCount should be 21")
if sr21.get("previewMatchesRuntime") is not True:
    errors.append("afterCommit previewMatchesRuntime should be true")
active_set = sr21.get("activeSetPreview")
if not isinstance(active_set, list) or len(active_set) != 21:
    errors.append("afterCommit activeSetPreview must contain 21 entries")
elif active_set[20].get("isLocal") is not True:
    errors.append("21st activeSetPreview entry should be local")

ordering_contract = after_commit_chain.get("orderingContract", {})
shadow = ordering_contract.get("completionTargetShadowState", {})
if shadow.get("candidatePreviewQueued") != 2:
    errors.append("orderingContract candidatePreviewQueued should be 2")
if shadow.get("commitPreviewQueued") != 2:
    errors.append("orderingContract commitPreviewQueued should be 2")
if shadow.get("committedQueued") != 2:
    errors.append("orderingContract committedQueued should be 2")
if shadow.get("consistentWithCommitPreview") is not True:
    errors.append("orderingContract consistentWithCommitPreview should be true")

if commit_hashes.get("any") != tx_hashes:
    errors.append("commit any hashes do not match txHashes")
if commit_hashes.get("fastTransparent") is None or len(commit_hashes.get("fastTransparent")) != 1:
    errors.append("commit fastTransparent hashes should contain one entry")
if commit_hashes.get("shielded") is None or len(commit_hashes.get("shielded")) != 1:
    errors.append("commit shielded hashes should contain one entry")

restart_readiness = after_restart_chain.get("authoritySwitchReadiness", {})
restart_dag_readiness = after_restart_dag.get("authoritySwitchReadiness", {})
restart_sr21 = after_restart_chain.get("sr21Committee", {})
restart_runtime_recovery = after_restart_chain.get("runtimeRecovery", {})
if restart_readiness != restart_dag_readiness:
    errors.append("afterRestart chain/dag authoritySwitchReadiness should match")
if restart_readiness.get("currentAuthorityRetained") is not True:
    errors.append("afterRestart currentAuthorityRetained should be true")
if restart_readiness.get("bullsharkPlanReady") is not True:
    errors.append("afterRestart bullsharkPlanReady should be true")
if restart_readiness.get("committeePlanReady") is not True:
    errors.append("afterRestart committeePlanReady should be true")
if restart_sr21.get("activeCount") != 21:
    errors.append("afterRestart activeCount should be 21")
if restart_sr21.get("configuredActiveCount") != 21:
    errors.append("afterRestart configuredActiveCount should be 21")
if restart_sr21.get("previewMatchesRuntime") is not True:
    errors.append("afterRestart previewMatchesRuntime should be true")
if restart_sr21.get("runtimeQuorumThreshold") != "15":
    errors.append("afterRestart runtimeQuorumThreshold should be 15")

for key in (
    "selectionAlignedBeforeCommit",
    "deliveredVisibleBeforeCommit",
    "candidatePreviewVisibleAfterAutoAdvance",
    "commitPreviewVisibleAfterAutoAdvance",
    "committedVisibleAfterAutoAdvance",
    "runtimeRecoveryCommitVisibleAfterAutoAdvance",
    "committeeAlignedAfterApply",
    "authoritySwitchReadyAfterCommit",
    "chainDagAuthoritySummaryConsistent",
    "currentAuthorityRetained",
    "completionTargetMatchesPlan",
    "commitHashesVisibleAfterAutoAdvance",
):
    if consistency.get(key) is not True:
        errors.append(f"consistency flag is not true: {key}")

for key in (
    "snapshotArtifactsWritten",
    "chainDagAuthoritySummaryConsistentAfterRestart",
    "authoritySurfaceRetainedAfterRestart",
    "committeeStatePersistedAfterRestart",
    "currentAuthorityRetainedAfterRestart",
    "completionTargetMatchesPlanAfterRestart",
):
    if restart_consistency.get(key) is not True:
        errors.append(f"restartConsistency flag is not true: {key}")

current_runtime = architecture.get("currentRuntime", {})
completion_target = architecture.get("completionTarget", {})
if current_runtime.get("orderingStage") != "ghostdagTotalOrder":
    errors.append("current orderingStage is not ghostdagTotalOrder")
if current_runtime.get("checkpointDecisionSource") != "ghostdagCheckpointBft":
    errors.append("current checkpointDecisionSource is not ghostdagCheckpointBft")
if current_runtime.get("committee") != "validatorBreadth":
    errors.append("current committee is not validatorBreadth")
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

echo "bullshark authority-switch rehearsal passed"
echo "  $result_file"
