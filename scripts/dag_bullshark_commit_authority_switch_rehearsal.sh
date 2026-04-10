#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
state_dir="${MISAKA_BULLSHARK_COMMIT_AUTHORITY_SWITCH_REHEARSAL_DIR:-$repo_root/.tmp/dag-bullshark-commit-authority-switch-rehearsal}"
result_file="${MISAKA_BULLSHARK_COMMIT_AUTHORITY_SWITCH_REHEARSAL_RESULT:-$state_dir/result.json}"
target_dir="${MISAKA_CARGO_TARGET_DIR:-$repo_root/.tmp/dag-bullshark-commit-authority-switch-target}"
log_file="$state_dir/cargo-test.log"
test_filter="live_bullshark_commit_handoff_enables_authority_switch_through_rpc_service"

usage() {
  cat <<'EOF'
Usage: ./scripts/dag_bullshark_commit_authority_switch_rehearsal.sh

Runs the confined Bullshark commit-authority-switch live RPC rehearsal and writes:

  .tmp/dag-bullshark-commit-authority-switch-rehearsal/result.json

Optional env:
  MISAKA_BULLSHARK_COMMIT_AUTHORITY_SWITCH_REHEARSAL_DIR=/custom/output/dir
  MISAKA_BULLSHARK_COMMIT_AUTHORITY_SWITCH_REHEARSAL_RESULT=/custom/result.json
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
export MISAKA_BULLSHARK_COMMIT_AUTHORITY_SWITCH_REHEARSAL_RESULT="$result_file"
rm -f "$result_file"

cd "$repo_root"

if ! cargo test -p misaka-node --bin misaka-node \
  "$test_filter" \
  -- --nocapture >"$log_file" 2>&1; then
  write_failure "bullshark commit authority-switch rehearsal regression failed"
  cat "$log_file" >&2
  exit 1
fi

if [[ ! -f "$result_file" ]]; then
  write_failure "bullshark commit authority-switch rehearsal passed but did not emit result artifact"
  exit 1
fi

python3 - "$result_file" <<'PY'
import json
import pathlib
import sys

result_path = pathlib.Path(sys.argv[1])
payload = json.loads(result_path.read_text(encoding="utf-8"))

def extract_validator_ids(entries):
    if not isinstance(entries, list):
        return []
    validator_ids = []
    for entry in entries:
        if isinstance(entry, dict) and isinstance(entry.get("validatorId"), str):
            validator_ids.append(entry["validatorId"])
    return validator_ids

before_apply = payload.get("beforeApply", {}).get("chainInfo", {})
after_apply = payload.get("afterApply", {}).get("chainInfo", {})
after_delivered = payload.get("afterDeliveredBatch", {}).get("chainInfo", {})
after_delivered_dag = payload.get("afterDeliveredBatch", {}).get("dagInfo", {})
after_candidate = payload.get("afterCandidatePreview", {}).get("chainInfo", {})
after_candidate_dag = payload.get("afterCandidatePreview", {}).get("dagInfo", {})
after_commit_preview = payload.get("afterCommitPreview", {}).get("chainInfo", {})
after_commit_preview_dag = payload.get("afterCommitPreview", {}).get("dagInfo", {})
after_commit_chain = payload.get("afterCommit", {}).get("chainInfo", {})
after_commit_dag = payload.get("afterCommit", {}).get("dagInfo", {})
after_restart_chain = payload.get("afterRestart", {}).get("chainInfo", {})
after_restart_dag = payload.get("afterRestart", {}).get("dagInfo", {})
before_second_apply = payload.get("beforeSecondApply", {}).get("chainInfo", {})
after_second_apply_chain = payload.get("afterSecondApply", {}).get("chainInfo", {})
after_second_apply_dag = payload.get("afterSecondApply", {}).get("dagInfo", {})
runtime_recovery = payload.get("afterCommit", {}).get("runtimeRecovery", {})
commit_hashes = payload.get("afterCommit", {}).get("commitHashes", {})
after_second_commit_hashes = payload.get("afterSecondApply", {}).get("commitHashes", {})
consistency = payload.get("consistency", {})
restart_consistency = payload.get("restartConsistency", {})
architecture = payload.get("consensusArchitecture", {})
second_rotation_provenance = payload.get("secondRotationProvenance", {})
second_rotation_delta = payload.get("secondRotationDelta", {})
errors = []

if payload.get("status") != "passed":
    errors.append(f"status is not passed: {payload.get('status')!r}")
if payload.get("flow") != "live_bullshark_commit_handoff_enables_authority_switch_through_rpc_service":
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
if after_apply.get("authoritySwitchReadiness", {}).get("ready") is not False:
    errors.append("afterApply authoritySwitchReadiness.ready should still be false")
after_apply_sr21 = after_apply.get("sr21Committee", {})
if after_apply_sr21.get("runtimeActiveSetPresent") is not True:
    errors.append("afterApply runtimeActiveSetPresent should be true")
if after_apply_sr21.get("runtimeActiveSetCount") != 21:
    errors.append("afterApply runtimeActiveSetCount should be 21")
if after_apply_sr21.get("runtimeActiveSetMatchesPreview") is not True:
    errors.append("afterApply runtimeActiveSetMatchesPreview should be true")

delivered_state = after_delivered.get("orderingContract", {}).get("completionTargetShadowState", {})
delivered_readiness = after_delivered.get("authoritySwitchReadiness", {})
delivered_dag_readiness = after_delivered_dag.get("authoritySwitchReadiness", {})
candidate_state = after_candidate.get("orderingContract", {}).get("completionTargetShadowState", {})
candidate_readiness = after_candidate.get("authoritySwitchReadiness", {})
candidate_dag_readiness = after_candidate_dag.get("authoritySwitchReadiness", {})
commit_preview_state = after_commit_preview.get("orderingContract", {}).get("completionTargetShadowState", {})
commit_preview_readiness = after_commit_preview.get("authoritySwitchReadiness", {})
commit_preview_dag_readiness = after_commit_preview_dag.get("authoritySwitchReadiness", {})
if delivered_state.get("queued") != 2:
    errors.append("afterDeliveredBatch queued should be 2")
if delivered_state.get("committedQueued") != 0:
    errors.append("afterDeliveredBatch committedQueued should be 0")
if delivered_readiness.get("ready") is not False:
    errors.append("afterDeliveredBatch authoritySwitchReadiness.ready should be false")
if delivered_readiness.get("candidatePreviewReady") is not False:
    errors.append("afterDeliveredBatch candidatePreviewReady should be false")
if delivered_readiness.get("commitPreviewReady") is not False:
    errors.append("afterDeliveredBatch commitPreviewReady should be false")
if delivered_readiness.get("committedReady") is not False:
    errors.append("afterDeliveredBatch committedReady should be false")
if delivered_readiness.get("candidatePreviewQueued") != 0:
    errors.append("afterDeliveredBatch candidatePreviewQueued should be 0")
if delivered_readiness.get("commitPreviewQueued") != 0:
    errors.append("afterDeliveredBatch commitPreviewQueued should be 0")
if delivered_readiness.get("committedQueued") != 0:
    errors.append("afterDeliveredBatch committedQueued should be 0")
if delivered_readiness.get("currentAuthorityRetained") is not True:
    errors.append("afterDeliveredBatch currentAuthorityRetained should be true")
if delivered_readiness.get("bullsharkPlanReady") is not True:
    errors.append("afterDeliveredBatch bullsharkPlanReady should be true")
if delivered_readiness.get("committeePlanReady") is not True:
    errors.append("afterDeliveredBatch committeePlanReady should be true")
if delivered_readiness != delivered_dag_readiness:
    errors.append("afterDeliveredBatch chain/dag authoritySwitchReadiness should match")
if candidate_state.get("candidatePreviewQueued") != 2:
    errors.append("afterCandidatePreview candidatePreviewQueued should be 2")
if candidate_readiness.get("ready") is not False:
    errors.append("afterCandidatePreview authoritySwitchReadiness.ready should be false")
if candidate_readiness.get("candidatePreviewReady") is not True:
    errors.append("afterCandidatePreview candidatePreviewReady should be true")
if candidate_readiness.get("commitPreviewReady") is not False:
    errors.append("afterCandidatePreview commitPreviewReady should be false")
if candidate_readiness.get("committedReady") is not False:
    errors.append("afterCandidatePreview committedReady should be false")
if candidate_readiness.get("candidatePreviewQueued") != 2:
    errors.append("afterCandidatePreview authoritySwitchReadiness candidatePreviewQueued should be 2")
if candidate_readiness.get("commitPreviewQueued") != 0:
    errors.append("afterCandidatePreview authoritySwitchReadiness commitPreviewQueued should be 0")
if candidate_readiness.get("committedQueued") != 0:
    errors.append("afterCandidatePreview authoritySwitchReadiness committedQueued should be 0")
if candidate_readiness != candidate_dag_readiness:
    errors.append("afterCandidatePreview chain/dag authoritySwitchReadiness should match")
if commit_preview_state.get("commitPreviewQueued") != 2:
    errors.append("afterCommitPreview commitPreviewQueued should be 2")
if commit_preview_readiness.get("ready") is not False:
    errors.append("afterCommitPreview authoritySwitchReadiness.ready should be false")
if commit_preview_readiness.get("candidatePreviewReady") is not True:
    errors.append("afterCommitPreview candidatePreviewReady should be true")
if commit_preview_readiness.get("commitPreviewReady") is not True:
    errors.append("afterCommitPreview commitPreviewReady should be true")
if commit_preview_readiness.get("committedReady") is not False:
    errors.append("afterCommitPreview committedReady should be false")
if commit_preview_readiness.get("candidatePreviewQueued") != 2:
    errors.append("afterCommitPreview authoritySwitchReadiness candidatePreviewQueued should be 2")
if commit_preview_readiness.get("commitPreviewQueued") != 2:
    errors.append("afterCommitPreview authoritySwitchReadiness commitPreviewQueued should be 2")
if commit_preview_readiness.get("committedQueued") != 0:
    errors.append("afterCommitPreview authoritySwitchReadiness committedQueued should be 0")
if commit_preview_readiness != commit_preview_dag_readiness:
    errors.append("afterCommitPreview chain/dag authoritySwitchReadiness should match")

chain_readiness = after_commit_chain.get("authoritySwitchReadiness", {})
dag_readiness = after_commit_dag.get("authoritySwitchReadiness", {})
if chain_readiness.get("ready") is not True:
    errors.append("afterCommit chain authoritySwitchReadiness.ready should be true")
if dag_readiness.get("ready") is not True:
    errors.append("afterCommit dag authoritySwitchReadiness.ready should be true")
if chain_readiness != dag_readiness:
    errors.append("afterCommit chain/dag authoritySwitchReadiness should match")
if chain_readiness.get("candidatePreviewQueued") != 2:
    errors.append("afterCommit candidatePreviewQueued should be 2")
if chain_readiness.get("commitPreviewQueued") != 2:
    errors.append("afterCommit commitPreviewQueued should be 2")
if chain_readiness.get("committedQueued") != 2:
    errors.append("afterCommit committedQueued should be 2")
if chain_readiness.get("committeeActiveCount") != 21:
    errors.append("afterCommit committeeActiveCount should be 21")
if chain_readiness.get("committeeConfiguredActiveCount") != 21:
    errors.append("afterCommit committeeConfiguredActiveCount should be 21")
if chain_readiness.get("committeeQuorumThresholdReady") is not True:
    errors.append("afterCommit committeeQuorumThresholdReady should be true")
if chain_readiness.get("committeePreviewQuorumThreshold") != "15":
    errors.append("afterCommit committeePreviewQuorumThreshold should be 15")
if chain_readiness.get("committeeRuntimeQuorumThreshold") != "15":
    errors.append("afterCommit committeeRuntimeQuorumThreshold should be 15")
if chain_readiness.get("currentAuthorityRetained") is not True:
    errors.append("currentAuthorityRetained should be true")

ordering_contract = after_commit_chain.get("orderingContract", {})
shadow = ordering_contract.get("completionTargetShadowState", {})
if shadow.get("committedQueued") != 2:
    errors.append("orderingContract committedQueued should be 2")
if shadow.get("consistentWithCommitPreview") is not True:
    errors.append("orderingContract consistentWithCommitPreview should be true")

sr21 = after_commit_chain.get("sr21Committee", {})
if sr21.get("activeCount") != 21:
    errors.append("afterCommit activeCount should be 21")
if sr21.get("configuredActiveCount") != 21:
    errors.append("afterCommit configuredActiveCount should be 21")
if sr21.get("previewMatchesRuntime") is not True:
    errors.append("afterCommit previewMatchesRuntime should be true")
if sr21.get("runtimeActiveSetPresent") is not True:
    errors.append("afterCommit runtimeActiveSetPresent should be true")
if sr21.get("runtimeActiveSetCount") != 21:
    errors.append("afterCommit runtimeActiveSetCount should be 21")
if sr21.get("runtimeActiveSetMatchesPreview") is not True:
    errors.append("afterCommit runtimeActiveSetMatchesPreview should be true")
active_set = sr21.get("activeSetPreview")
if not isinstance(active_set, list) or len(active_set) != 21:
    errors.append("afterCommit activeSetPreview must contain 21 entries")
elif active_set[20].get("isLocal") is not True:
    errors.append("21st activeSetPreview entry should be local")

if runtime_recovery.get("lastBullsharkCommitCount") != 2:
    errors.append("runtimeRecovery lastBullsharkCommitCount should be 2")
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
if restart_sr21.get("runtimeActiveSetPresent") is not True:
    errors.append("afterRestart runtimeActiveSetPresent should be true")
if restart_sr21.get("runtimeActiveSetCount") != 21:
    errors.append("afterRestart runtimeActiveSetCount should be 21")
if restart_sr21.get("runtimeActiveSetMatchesPreview") is not True:
    errors.append("afterRestart runtimeActiveSetMatchesPreview should be true")
if restart_sr21.get("runtimeQuorumThreshold") != "15":
    errors.append("afterRestart runtimeQuorumThreshold should be 15")
if not isinstance(restart_runtime_recovery.get("startupSnapshotRestored"), bool):
    errors.append("afterRestart startupSnapshotRestored should be a boolean")
if restart_runtime_recovery.get("lastBullsharkCommitCount") != 2:
    errors.append("afterRestart runtimeRecovery lastBullsharkCommitCount should be 2")
if restart_runtime_recovery.get("lastBullsharkCommitTxHashes") != tx_hashes:
    errors.append("afterRestart runtimeRecovery lastBullsharkCommitTxHashes should match txHashes")
if restart_runtime_recovery.get("bullsharkCommitObserved") is not True:
    errors.append("afterRestart runtimeRecovery bullsharkCommitObserved should be true")
restart_ordering_contract = after_restart_chain.get("orderingContract", {})
restart_shadow = restart_ordering_contract.get("completionTargetShadowState", {})
restart_dag_shadow = (
    after_restart_dag.get("orderingContract", {}).get("completionTargetShadowState", {})
)
if restart_shadow.get("candidatePreviewQueued") != 2:
    errors.append("afterRestart candidatePreviewQueued should be 2")
if restart_shadow.get("commitPreviewQueued") != 2:
    errors.append("afterRestart commitPreviewQueued should be 2")
if restart_shadow.get("committedQueued") != 2:
    errors.append("afterRestart committedQueued should be 2")
if restart_shadow.get("candidatePreviewFastTransparentQueued") != 1:
    errors.append("afterRestart candidatePreviewFastTransparentQueued should be 1")
if restart_shadow.get("candidatePreviewShieldedQueued") != 1:
    errors.append("afterRestart candidatePreviewShieldedQueued should be 1")
if restart_shadow.get("commitPreviewFastTransparentQueued") != 1:
    errors.append("afterRestart commitPreviewFastTransparentQueued should be 1")
if restart_shadow.get("commitPreviewShieldedQueued") != 1:
    errors.append("afterRestart commitPreviewShieldedQueued should be 1")
if restart_shadow.get("committedFastTransparentQueued") != 1:
    errors.append("afterRestart committedFastTransparentQueued should be 1")
if restart_shadow.get("committedShieldedQueued") != 1:
    errors.append("afterRestart committedShieldedQueued should be 1")
if restart_shadow.get("candidatePreviewLive") is not True:
    errors.append("afterRestart candidatePreviewLive should be true")
if restart_shadow.get("commitPreviewLive") is not True:
    errors.append("afterRestart commitPreviewLive should be true")
if restart_shadow.get("committedLive") is not True:
    errors.append("afterRestart committedLive should be true")
if restart_shadow.get("consistentWithCommitPreview") is not True:
    errors.append("afterRestart consistentWithCommitPreview should be true")
if restart_shadow != restart_dag_shadow:
    errors.append("afterRestart chain/dag orderingContract completionTargetShadowState should match")
restart_commit_hashes = payload.get("afterRestart", {}).get("commitHashes", {})
if restart_commit_hashes.get("any") != tx_hashes:
    errors.append("afterRestart commit any hashes do not match txHashes")
if restart_commit_hashes.get("fastTransparent") is None or len(restart_commit_hashes.get("fastTransparent")) != 1:
    errors.append("afterRestart commit fastTransparent hashes should contain one entry")
if restart_commit_hashes.get("shielded") is None or len(restart_commit_hashes.get("shielded")) != 1:
    errors.append("afterRestart commit shielded hashes should contain one entry")

before_second_sr21 = before_second_apply.get("sr21Committee", {})
before_second_readiness = before_second_apply.get("authoritySwitchReadiness", {})
after_second_sr21 = after_second_apply_chain.get("sr21Committee", {})
after_second_readiness = after_second_apply_chain.get("authoritySwitchReadiness", {})
after_second_dag_readiness = after_second_apply_dag.get("authoritySwitchReadiness", {})
after_second_runtime_recovery = after_second_apply_chain.get("runtimeRecovery", {})
after_second_shadow = (
    after_second_apply_chain.get("orderingContract", {}).get("completionTargetShadowState", {})
)
after_second_dag_shadow = (
    after_second_apply_dag.get("orderingContract", {}).get("completionTargetShadowState", {})
)
before_second_preview_ids = extract_validator_ids(before_second_sr21.get("activeSetPreview"))
before_second_runtime_ids = extract_validator_ids(before_second_sr21.get("runtimeActiveSet"))
after_second_preview_ids = extract_validator_ids(after_second_sr21.get("activeSetPreview"))
after_second_runtime_ids = extract_validator_ids(after_second_sr21.get("runtimeActiveSet"))
preview_added_validator_ids = [
    validator_id
    for validator_id in after_second_preview_ids
    if validator_id not in before_second_preview_ids
]
preview_removed_validator_ids = [
    validator_id
    for validator_id in before_second_preview_ids
    if validator_id not in after_second_preview_ids
]
runtime_added_validator_ids = [
    validator_id
    for validator_id in after_second_runtime_ids
    if validator_id not in before_second_runtime_ids
]
runtime_removed_validator_ids = [
    validator_id
    for validator_id in before_second_runtime_ids
    if validator_id not in after_second_runtime_ids
]
if second_rotation_provenance.get("epochBoundaryReachedFromFinalizedCheckpoint") is not True:
    errors.append("secondRotationProvenance epochBoundaryReachedFromFinalizedCheckpoint should be true")
if before_second_sr21.get("previewMatchesRuntime") is not False:
    errors.append("beforeSecondApply previewMatchesRuntime should be false")
if before_second_sr21.get("runtimeActiveSetPresent") is not True:
    errors.append("beforeSecondApply runtimeActiveSetPresent should be true")
if before_second_sr21.get("runtimeActiveSetMatchesPreview") is not False:
    errors.append("beforeSecondApply runtimeActiveSetMatchesPreview should be false")
if before_second_readiness.get("ready") is not False:
    errors.append("beforeSecondApply authoritySwitchReadiness.ready should be false")
if before_second_readiness.get("candidatePreviewReady") is not True:
    errors.append("beforeSecondApply candidatePreviewReady should be true")
if before_second_readiness.get("commitPreviewReady") is not True:
    errors.append("beforeSecondApply commitPreviewReady should be true")
if before_second_readiness.get("committedReady") is not True:
    errors.append("beforeSecondApply committedReady should be true")
if before_second_readiness.get("candidatePreviewQueued") != 2:
    errors.append("beforeSecondApply candidatePreviewQueued should be 2")
if before_second_readiness.get("commitPreviewQueued") != 2:
    errors.append("beforeSecondApply commitPreviewQueued should be 2")
if before_second_readiness.get("committedQueued") != 2:
    errors.append("beforeSecondApply committedQueued should be 2")
if before_second_readiness.get("committeePreviewReady") is not False:
    errors.append("beforeSecondApply committeePreviewReady should be false")
if before_second_readiness.get("committeeSelectionReady") is not True:
    errors.append("beforeSecondApply committeeSelectionReady should be true")
if before_second_readiness.get("committeeRotationReady") is not False:
    errors.append("beforeSecondApply committeeRotationReady should be false")
if before_second_readiness.get("committeeQuorumThresholdReady") is not True:
    errors.append("beforeSecondApply committeeQuorumThresholdReady should be true")
if before_second_readiness.get("committeePreviewQuorumThreshold") != "15":
    errors.append("beforeSecondApply committeePreviewQuorumThreshold should be 15")
if before_second_readiness.get("committeeRuntimeQuorumThreshold") != "15":
    errors.append("beforeSecondApply committeeRuntimeQuorumThreshold should be 15")
if before_second_readiness.get("currentAuthorityRetained") is not True:
    errors.append("beforeSecondApply currentAuthorityRetained should be true")
if before_second_readiness.get("bullsharkPlanReady") is not True:
    errors.append("beforeSecondApply bullsharkPlanReady should be true")
if before_second_readiness.get("committeePlanReady") is not True:
    errors.append("beforeSecondApply committeePlanReady should be true")
if before_second_readiness.get("orchestrationReady") is not True:
    errors.append("beforeSecondApply orchestrationReady should be true")
if before_second_readiness.get("runtimeRecoveryCommitConsistent") is not True:
    errors.append("beforeSecondApply runtimeRecoveryCommitConsistent should be true")
if before_second_readiness.get("runtimeRecoveryCommitCount") != 2:
    errors.append("beforeSecondApply runtimeRecoveryCommitCount should be 2")
if before_second_readiness.get("runtimeRecoveryCommitTxHashes") != tx_hashes:
    errors.append("beforeSecondApply runtimeRecoveryCommitTxHashes should match txHashes")
if before_second_readiness.get("runtimeRecoveryCommitObserved") is not True:
    errors.append("beforeSecondApply runtimeRecoveryCommitObserved should be true")
if before_second_sr21.get("localPreviewSrIndex") == before_second_sr21.get("localRuntimeSrIndex"):
    errors.append("beforeSecondApply local preview/runtime indices should diverge")
if after_second_readiness != after_second_dag_readiness:
    errors.append("afterSecondApply chain/dag authoritySwitchReadiness should match")
if after_second_readiness.get("ready") is not True:
    errors.append("afterSecondApply authoritySwitchReadiness.ready should be true")
if after_second_readiness.get("currentAuthorityRetained") is not True:
    errors.append("afterSecondApply currentAuthorityRetained should be true")
if after_second_readiness.get("candidatePreviewReady") is not True:
    errors.append("afterSecondApply candidatePreviewReady should be true")
if after_second_readiness.get("commitPreviewReady") is not True:
    errors.append("afterSecondApply commitPreviewReady should be true")
if after_second_readiness.get("committedReady") is not True:
    errors.append("afterSecondApply committedReady should be true")
if after_second_readiness.get("committeePreviewReady") is not True:
    errors.append("afterSecondApply committeePreviewReady should be true")
if after_second_readiness.get("committeeSelectionReady") is not True:
    errors.append("afterSecondApply committeeSelectionReady should be true")
if after_second_readiness.get("committeeRotationReady") is not True:
    errors.append("afterSecondApply committeeRotationReady should be true")
if after_second_readiness.get("committeeQuorumThresholdReady") is not True:
    errors.append("afterSecondApply committeeQuorumThresholdReady should be true")
if after_second_readiness.get("committeePreviewQuorumThreshold") != "15":
    errors.append("afterSecondApply committeePreviewQuorumThreshold should be 15")
if after_second_readiness.get("committeeRuntimeQuorumThreshold") != "15":
    errors.append("afterSecondApply committeeRuntimeQuorumThreshold should be 15")
if after_second_readiness.get("bullsharkPlanReady") is not True:
    errors.append("afterSecondApply bullsharkPlanReady should be true")
if after_second_readiness.get("committeePlanReady") is not True:
    errors.append("afterSecondApply committeePlanReady should be true")
if after_second_readiness.get("orchestrationReady") is not True:
    errors.append("afterSecondApply orchestrationReady should be true")
if after_second_readiness.get("runtimeRecoveryCommitConsistent") is not True:
    errors.append("afterSecondApply runtimeRecoveryCommitConsistent should be true")
if after_second_readiness.get("runtimeRecoveryCommitCount") != 2:
    errors.append("afterSecondApply runtimeRecoveryCommitCount should be 2")
if after_second_readiness.get("runtimeRecoveryCommitTxHashes") != tx_hashes:
    errors.append("afterSecondApply runtimeRecoveryCommitTxHashes should match txHashes")
if after_second_readiness.get("runtimeRecoveryCommitObserved") is not True:
    errors.append("afterSecondApply runtimeRecoveryCommitObserved should be true")
if after_second_sr21.get("runtimeActiveSetPresent") is not True:
    errors.append("afterSecondApply runtimeActiveSetPresent should be true")
if after_second_sr21.get("runtimeActiveSetCount") != 21:
    errors.append("afterSecondApply runtimeActiveSetCount should be 21")
if after_second_sr21.get("runtimeActiveSetMatchesPreview") is not True:
    errors.append("afterSecondApply runtimeActiveSetMatchesPreview should be true")
if after_second_sr21.get("previewMatchesRuntime") is not True:
    errors.append("afterSecondApply previewMatchesRuntime should be true")
if after_second_sr21.get("localPreviewSrIndex") != after_second_sr21.get("localRuntimeSrIndex"):
    errors.append("afterSecondApply local preview/runtime indices should match")
if after_second_shadow.get("candidatePreviewQueued") != 2:
    errors.append("afterSecondApply candidatePreviewQueued should be 2")
if after_second_shadow.get("commitPreviewQueued") != 2:
    errors.append("afterSecondApply commitPreviewQueued should be 2")
if after_second_shadow.get("committedQueued") != 2:
    errors.append("afterSecondApply committedQueued should be 2")
if after_second_shadow.get("committedLive") is not True:
    errors.append("afterSecondApply committedLive should be true")
if after_second_shadow.get("consistentWithCommitPreview") is not True:
    errors.append("afterSecondApply consistentWithCommitPreview should be true")
if after_second_shadow != after_second_dag_shadow:
    errors.append("afterSecondApply chain/dag orderingContract completionTargetShadowState should match")
if after_second_runtime_recovery.get("lastBullsharkCommitCount") != 2:
    errors.append("afterSecondApply runtimeRecovery lastBullsharkCommitCount should be 2")
if after_second_runtime_recovery.get("lastBullsharkCommitTxHashes") != tx_hashes:
    errors.append("afterSecondApply runtimeRecovery lastBullsharkCommitTxHashes should match txHashes")
if after_second_runtime_recovery.get("bullsharkCommitObserved") is not True:
    errors.append("afterSecondApply runtimeRecovery bullsharkCommitObserved should be true")
if after_second_commit_hashes.get("any") != tx_hashes:
    errors.append("afterSecondApply commit any hashes do not match txHashes")
if after_second_commit_hashes.get("fastTransparent") is None or len(after_second_commit_hashes.get("fastTransparent")) != 1:
    errors.append("afterSecondApply commit fastTransparent hashes should contain one entry")
if after_second_commit_hashes.get("shielded") is None or len(after_second_commit_hashes.get("shielded")) != 1:
    errors.append("afterSecondApply commit shielded hashes should contain one entry")
if len(second_rotation_delta.get("addedValidatorIds", [])) != 1:
    errors.append("secondRotationDelta addedValidatorIds must contain one entry")
if len(second_rotation_delta.get("removedValidatorIds", [])) != 1:
    errors.append("secondRotationDelta removedValidatorIds must contain one entry")
if preview_added_validator_ids:
    errors.append("preview set delta should already be converged before second apply")
if preview_removed_validator_ids:
    errors.append("preview removal delta should already be converged before second apply")
if before_second_preview_ids != after_second_preview_ids:
    errors.append("preview set should remain stable across second apply")
if runtime_added_validator_ids != second_rotation_delta.get("addedValidatorIds", []):
    errors.append("secondRotationDelta addedValidatorIds should match runtime set delta")
if runtime_removed_validator_ids != second_rotation_delta.get("removedValidatorIds", []):
    errors.append("secondRotationDelta removedValidatorIds should match runtime set delta")
if second_rotation_delta.get("localRuntimeIndexBefore") == second_rotation_delta.get("localRuntimeIndexAfter"):
    errors.append("secondRotationDelta local runtime index should rotate")

for key in (
    "selectionAlignedBeforeExplicitCommit",
    "runtimeActiveSetAppliedAfterApply",
    "deliveredVisibleBeforeExplicitCommit",
    "authoritySummaryVisibleAfterDeliveredBatch",
    "chainDagAuthoritySummaryConsistentAfterDeliveredBatch",
    "candidatePreviewVisibleAfterExplicitHandoff",
    "authoritySummaryVisibleAfterCandidatePreview",
    "chainDagAuthoritySummaryConsistentAfterCandidatePreview",
    "commitPreviewVisibleAfterExplicitHandoff",
    "authoritySummaryVisibleAfterCommitPreview",
    "chainDagAuthoritySummaryConsistentAfterCommitPreview",
    "committedVisibleAfterExplicitHandoff",
    "commitHashesVisibleAfterExplicitCommit",
    "runtimeRecoveryCommitObservedAfterExplicitHandoff",
    "committeeAlignedAfterApply",
    "authoritySwitchReadyAfterExplicitCommit",
    "chainDagAuthoritySummaryConsistent",
    "currentAuthorityRetained",
    "completionTargetMatchesPlan",
    "secondEpochBoundaryVisibleBeforeSecondApply",
    "secondEpochBoundaryReachedAfterRestart",
    "staleSecondRotationVisibleBeforeSecondApply",
    "committeeRotationOnlyBlockerBeforeSecondApply",
    "secondRotationAppliedAfterRestart",
    "secondRotationChangedMembershipAfterRestart",
    "secondRuntimeIndexRotatedAfterRestart",
    "secondCheckpointProvenanceRetainedAfterApply",
    "authoritySwitchReadyLiftedOnlyByCommitteeCatchupAfterSecondApply",
    "authoritySwitchReadyLiftMatchesSecondRotationRuntimeCatchupAfterSecondApply",
    "authoritySwitchReadyLiftPreservedSecondEpochBoundaryLineageAfterSecondApply",
    "authoritySwitchReadyLiftMatchesSecondRotationProvenanceAfterSecondApply",
    "authoritySwitchExecutionLineMonotonicThroughSecondApply",
    "authoritySwitchSurfaceRetainedAfterSecondApply",
    "chainDagAuthoritySummaryConsistentAfterSecondApply",
    "chainDagOrderingStateConsistentAfterSecondApply",
    "committedStateRetainedAfterSecondApply",
    "commitHashesRetainedAfterSecondApply",
    "runtimeRecoveryCommitRetainedAfterSecondApply",
    "currentAuthorityRetainedAfterSecondApply",
    "completionTargetMatchesPlanAfterSecondApply",
):
    if consistency.get(key) is not True:
        errors.append(f"consistency flag is not true: {key}")

for key in (
    "snapshotArtifactsWritten",
    "serviceRestartContinuity",
    "authoritySurfaceRetainedAfterRestart",
    "chainDagAuthoritySummaryConsistentAfterRestart",
    "chainDagOrderingStateConsistentAfterRestart",
    "committeeStatePersistedAfterRestart",
    "committedStateRetainedAfterRestart",
    "commitHashesRetainedAfterRestart",
    "runtimeRecoveryCommitRetainedAfterRestart",
    "currentAuthorityRetainedAfterRestart",
    "completionTargetMatchesPlanAfterRestart",
):
    if restart_consistency.get(key) is not True:
        errors.append(f"restartConsistency flag is not true: {key}")

if restart_consistency.get("rehydratedAfterRestart") is not False:
    errors.append("restartConsistency flag should keep rehydratedAfterRestart=false")
if restart_consistency.get("startupSnapshotRestoredAfterRestart") is not False:
    errors.append(
        "restartConsistency flag should keep startupSnapshotRestoredAfterRestart=false for service-restart continuity"
    )

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

echo "bullshark commit authority-switch rehearsal passed"
echo "  $result_file"
