#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
state_dir="${MISAKA_SR21_ROTATION_REHEARSAL_DIR:-$repo_root/.tmp/dag-sr21-rotation-rehearsal}"
result_file="${MISAKA_SR21_ROTATION_REHEARSAL_RESULT:-$state_dir/result.json}"
target_dir="${MISAKA_CARGO_TARGET_DIR:-$repo_root/.tmp/dag-sr21-rotation-target}"
log_file="$state_dir/cargo-test.log"
test_filter="live_sr21_election_epoch_boundary_sync_visible_through_rpc_service"

usage() {
  cat <<'EOF'
Usage: ./scripts/dag_sr21_rotation_rehearsal.sh

Runs the confined SR21 epoch-boundary live RPC rehearsal and writes:

  .tmp/dag-sr21-rotation-rehearsal/result.json

Optional env:
  MISAKA_SR21_ROTATION_REHEARSAL_DIR=/custom/output/dir
  MISAKA_SR21_ROTATION_REHEARSAL_RESULT=/custom/result.json
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
export MISAKA_SR21_ROTATION_REHEARSAL_RESULT="$result_file"
rm -f "$result_file"

cd "$repo_root"

if ! cargo test -p misaka-node --bin misaka-node \
  "$test_filter" \
  -- --nocapture >"$log_file" 2>&1; then
  write_failure "sr21 rotation rehearsal regression failed"
  cat "$log_file" >&2
  exit 1
fi

if [[ ! -f "$result_file" ]]; then
  write_failure "sr21 rotation rehearsal passed but did not emit result artifact"
  exit 1
fi

python3 - "$result_file" <<'PY'
import json
import pathlib
import sys

result_path = pathlib.Path(sys.argv[1])
payload = json.loads(result_path.read_text(encoding="utf-8"))

rotation_provenance = payload.get("rotationProvenance", {})
second_rotation_provenance = payload.get("secondRotationProvenance", {})
before_chain = payload.get("beforeApply", {}).get("chainInfo", {}).get("sr21Committee", {})
before_attestation = payload.get("beforeApply", {}).get("chainInfo", {}).get("validatorAttestation", {})
before_runtime_recovery = payload.get("beforeApply", {}).get("chainInfo", {}).get("runtimeRecovery", {})
before_lifecycle = payload.get("beforeApply", {}).get("chainInfo", {}).get("validatorLifecycleRecovery", {})
after_chain = payload.get("afterApply", {}).get("chainInfo", {}).get("sr21Committee", {})
after_attestation = payload.get("afterApply", {}).get("chainInfo", {}).get("validatorAttestation", {})
after_runtime_recovery = payload.get("afterApply", {}).get("chainInfo", {}).get("runtimeRecovery", {})
after_lifecycle = payload.get("afterApply", {}).get("chainInfo", {}).get("validatorLifecycleRecovery", {})
after_dag = payload.get("afterApply", {}).get("dagInfo", {}).get("sr21Committee", {})
after_dag_attestation = payload.get("afterApply", {}).get("dagInfo", {}).get("validatorAttestation", {})
after_dag_runtime_recovery = payload.get("afterApply", {}).get("dagInfo", {}).get("runtimeRecovery", {})
after_dag_lifecycle = payload.get("afterApply", {}).get("dagInfo", {}).get("validatorLifecycleRecovery", {})
after_restart_chain = payload.get("afterRestart", {}).get("chainInfo", {}).get("sr21Committee", {})
after_restart_attestation = payload.get("afterRestart", {}).get("chainInfo", {}).get("validatorAttestation", {})
after_restart_dag = payload.get("afterRestart", {}).get("dagInfo", {}).get("sr21Committee", {})
after_restart_dag_attestation = payload.get("afterRestart", {}).get("dagInfo", {}).get("validatorAttestation", {})
after_restart_runtime_recovery = payload.get("afterRestart", {}).get("chainInfo", {}).get("runtimeRecovery", {})
after_restart_lifecycle = payload.get("afterRestart", {}).get("chainInfo", {}).get("validatorLifecycleRecovery", {})
after_restart_dag_lifecycle = payload.get("afterRestart", {}).get("dagInfo", {}).get("validatorLifecycleRecovery", {})
before_second_chain = payload.get("beforeSecondApply", {}).get("chainInfo", {}).get("sr21Committee", {})
before_second_attestation = payload.get("beforeSecondApply", {}).get("chainInfo", {}).get("validatorAttestation", {})
before_second_runtime_recovery = payload.get("beforeSecondApply", {}).get("chainInfo", {}).get("runtimeRecovery", {})
before_second_lifecycle = payload.get("beforeSecondApply", {}).get("chainInfo", {}).get("validatorLifecycleRecovery", {})
after_second_chain = payload.get("afterSecondApply", {}).get("chainInfo", {}).get("sr21Committee", {})
after_second_attestation = payload.get("afterSecondApply", {}).get("chainInfo", {}).get("validatorAttestation", {})
after_second_runtime_recovery = payload.get("afterSecondApply", {}).get("chainInfo", {}).get("runtimeRecovery", {})
after_second_lifecycle = payload.get("afterSecondApply", {}).get("chainInfo", {}).get("validatorLifecycleRecovery", {})
after_second_dag = payload.get("afterSecondApply", {}).get("dagInfo", {}).get("sr21Committee", {})
after_second_dag_attestation = payload.get("afterSecondApply", {}).get("dagInfo", {}).get("validatorAttestation", {})
after_second_dag_runtime_recovery = payload.get("afterSecondApply", {}).get("dagInfo", {}).get("runtimeRecovery", {})
after_second_dag_lifecycle = payload.get("afterSecondApply", {}).get("dagInfo", {}).get("validatorLifecycleRecovery", {})
second_rotation_delta = payload.get("secondRotationDelta", {})
consistency = payload.get("consistency", {})
restart_consistency = payload.get("restartConsistency", {})
architecture = payload.get("consensusArchitecture", {})
errors = []

if payload.get("status") != "passed":
    errors.append(f"status is not passed: {payload.get('status')!r}")
if payload.get("flow") != "live_sr21_election_epoch_boundary_sync_visible_through_rpc_service":
    errors.append(f"unexpected flow: {payload.get('flow')!r}")
if payload.get("appliedEpoch") != 1:
    errors.append("appliedEpoch is not 1")
if rotation_provenance.get("checkpointInterval") != 6:
    errors.append("rotationProvenance checkpointInterval is not 6")
if rotation_provenance.get("previousFinalizedCheckpointBlueScore") != 6:
    errors.append("rotationProvenance previousFinalizedCheckpointBlueScore is not 6")
if rotation_provenance.get("appliedFinalizedCheckpointBlueScore") != 12:
    errors.append("rotationProvenance appliedFinalizedCheckpointBlueScore is not 12")
if rotation_provenance.get("lifecycleEpochBeforeApply") != 0:
    errors.append("rotationProvenance lifecycleEpochBeforeApply is not 0")
if rotation_provenance.get("lifecycleEpochAfterApply") != 1:
    errors.append("rotationProvenance lifecycleEpochAfterApply is not 1")
if rotation_provenance.get("epochBoundaryReachedFromFinalizedCheckpoint") is not True:
    errors.append("rotationProvenance epochBoundaryReachedFromFinalizedCheckpoint is not true")
if second_rotation_provenance.get("checkpointInterval") != 6:
    errors.append("secondRotationProvenance checkpointInterval is not 6")
if second_rotation_provenance.get("previousFinalizedCheckpointBlueScore") != 12:
    errors.append("secondRotationProvenance previousFinalizedCheckpointBlueScore is not 12")
if second_rotation_provenance.get("appliedFinalizedCheckpointBlueScore") != 18:
    errors.append("secondRotationProvenance appliedFinalizedCheckpointBlueScore is not 18")
if second_rotation_provenance.get("lifecycleEpochBeforeApply") != 1:
    errors.append("secondRotationProvenance lifecycleEpochBeforeApply is not 1")
if second_rotation_provenance.get("lifecycleEpochAfterApply") != 2:
    errors.append("secondRotationProvenance lifecycleEpochAfterApply is not 2")
if second_rotation_provenance.get("epochBoundaryReachedFromFinalizedCheckpoint") is not True:
    errors.append("secondRotationProvenance epochBoundaryReachedFromFinalizedCheckpoint is not true")

if before_chain.get("currentEpoch") != 1:
    errors.append("beforeApply currentEpoch is not 1")
if before_chain.get("configuredActiveCount") != 1:
    errors.append("beforeApply configuredActiveCount is not 1")
if before_chain.get("previewQuorumThreshold") != "3":
    errors.append("beforeApply previewQuorumThreshold is not 3")
if before_chain.get("runtimeQuorumThreshold") != "1":
    errors.append("beforeApply runtimeQuorumThreshold is not 1")
if before_chain.get("quorumThresholdConsistent") is not False:
    errors.append("beforeApply quorumThresholdConsistent is not false")
if before_chain.get("previewMatchesRuntime") is not False:
    errors.append("beforeApply previewMatchesRuntime is not false")
if before_chain.get("runtimeActiveCountConsistent") is not False:
    errors.append("beforeApply runtimeActiveCountConsistent is not false")
if before_chain.get("localRuntimeSrIndexConsistent") is not False:
    errors.append("beforeApply localRuntimeSrIndexConsistent is not false")
if before_chain.get("runtimeActiveSetPresent") is not False:
    errors.append("beforeApply runtimeActiveSetPresent is not false")
if before_chain.get("runtimeActiveSetCount") != 0:
    errors.append("beforeApply runtimeActiveSetCount is not 0")
if before_chain.get("runtimeActiveSetMatchesPreview") is not False:
    errors.append("beforeApply runtimeActiveSetMatchesPreview is not false")
if before_attestation.get("latestCheckpointFinality", {}).get("target", {}).get("blueScore") != 12:
    errors.append("beforeApply finality blue score is not 12")
if before_runtime_recovery.get("lastCheckpointFinalityBlueScore") != 12:
    errors.append("beforeApply runtimeRecovery lastCheckpointFinalityBlueScore is not 12")
if before_runtime_recovery.get("lastCheckpointDecisionSource") != "ghostdagCheckpointBft":
    errors.append("beforeApply runtimeRecovery lastCheckpointDecisionSource is not ghostdagCheckpointBft")
if before_lifecycle.get("checkpointFinalized") is not True:
    errors.append("beforeApply validatorLifecycleRecovery checkpointFinalized is not true")
if before_lifecycle.get("lastCheckpointFinalityBlueScore") != 12:
    errors.append("beforeApply validatorLifecycleRecovery lastCheckpointFinalityBlueScore is not 12")
if before_lifecycle.get("lastCheckpointDecisionSource") != "ghostdagCheckpointBft":
    errors.append("beforeApply validatorLifecycleRecovery lastCheckpointDecisionSource is not ghostdagCheckpointBft")

if after_chain.get("currentEpoch") != 1:
    errors.append("afterApply currentEpoch is not 1")
if after_chain.get("activeCount") != 3:
    errors.append("afterApply activeCount is not 3")
if after_chain.get("configuredActiveCount") != 3:
    errors.append("afterApply configuredActiveCount is not 3")
if after_chain.get("previewQuorumThreshold") != "3":
    errors.append("afterApply previewQuorumThreshold is not 3")
if after_chain.get("runtimeQuorumThreshold") != "3":
    errors.append("afterApply runtimeQuorumThreshold is not 3")
if after_chain.get("quorumThresholdConsistent") is not True:
    errors.append("afterApply quorumThresholdConsistent is not true")
if after_chain.get("localValidatorPresent") is not True:
    errors.append("afterApply localValidatorPresent is not true")
if after_chain.get("localValidatorInActiveSet") is not True:
    errors.append("afterApply localValidatorInActiveSet is not true")
if after_chain.get("localPreviewSrIndex") != 2:
    errors.append("afterApply localPreviewSrIndex is not 2")
if after_chain.get("localRuntimeSrIndex") != 2:
    errors.append("afterApply localRuntimeSrIndex is not 2")
if after_chain.get("runtimeActiveCountConsistent") is not True:
    errors.append("afterApply runtimeActiveCountConsistent is not true")
if after_chain.get("localRuntimeSrIndexConsistent") is not True:
    errors.append("afterApply localRuntimeSrIndexConsistent is not true")
if after_chain.get("previewMatchesRuntime") is not True:
    errors.append("afterApply previewMatchesRuntime is not true")
if after_chain.get("runtimeActiveSetPresent") is not True:
    errors.append("afterApply runtimeActiveSetPresent is not true")
if after_chain.get("runtimeActiveSetCount") != 3:
    errors.append("afterApply runtimeActiveSetCount is not 3")
if after_chain.get("runtimeActiveSetMatchesPreview") is not True:
    errors.append("afterApply runtimeActiveSetMatchesPreview is not true")
active_set = after_chain.get("activeSetPreview")
if not isinstance(active_set, list) or len(active_set) != 3:
    errors.append("afterApply activeSetPreview must contain 3 entries")
elif active_set[2].get("isLocal") is not True:
    errors.append("third activeSetPreview entry should be local")
runtime_active_set = after_chain.get("runtimeActiveSet")
if not isinstance(runtime_active_set, list) or len(runtime_active_set) != 3:
    errors.append("afterApply runtimeActiveSet must contain 3 entries")
elif runtime_active_set[2].get("isLocal") is not True:
    errors.append("third runtimeActiveSet entry should be local")
if after_attestation.get("latestCheckpointFinality", {}).get("target", {}).get("blueScore") != 12:
    errors.append("afterApply chainInfo finality blue score is not 12")
if after_runtime_recovery.get("lastCheckpointFinalityBlueScore") != 12:
    errors.append("afterApply chainInfo runtimeRecovery lastCheckpointFinalityBlueScore is not 12")
if after_runtime_recovery.get("lastCheckpointDecisionSource") != "ghostdagCheckpointBft":
    errors.append("afterApply chainInfo runtimeRecovery lastCheckpointDecisionSource is not ghostdagCheckpointBft")
if after_lifecycle.get("checkpointFinalized") is not True:
    errors.append("afterApply chainInfo validatorLifecycleRecovery checkpointFinalized is not true")
if after_lifecycle.get("lastCheckpointFinalityBlueScore") != 12:
    errors.append("afterApply chainInfo validatorLifecycleRecovery lastCheckpointFinalityBlueScore is not 12")
if after_lifecycle.get("lastCheckpointDecisionSource") != "ghostdagCheckpointBft":
    errors.append("afterApply chainInfo validatorLifecycleRecovery lastCheckpointDecisionSource is not ghostdagCheckpointBft")

if after_dag.get("currentEpoch") != 1:
    errors.append("afterApply dagInfo currentEpoch is not 1")
if after_dag.get("activeCount") != 3:
    errors.append("afterApply dagInfo activeCount is not 3")
if after_dag.get("configuredActiveCount") != 3:
    errors.append("afterApply dagInfo configuredActiveCount is not 3")
if after_dag.get("previewMatchesRuntime") is not True:
    errors.append("afterApply dagInfo previewMatchesRuntime is not true")
if after_dag.get("previewQuorumThreshold") != "3":
    errors.append("afterApply dagInfo previewQuorumThreshold is not 3")
if after_dag.get("runtimeQuorumThreshold") != "3":
    errors.append("afterApply dagInfo runtimeQuorumThreshold is not 3")
if after_dag.get("runtimeActiveSetPresent") is not True:
    errors.append("afterApply dagInfo runtimeActiveSetPresent is not true")
if after_dag.get("runtimeActiveSetCount") != 3:
    errors.append("afterApply dagInfo runtimeActiveSetCount is not 3")
if after_dag.get("runtimeActiveSetMatchesPreview") is not True:
    errors.append("afterApply dagInfo runtimeActiveSetMatchesPreview is not true")
if after_dag_attestation.get("latestCheckpointFinality", {}).get("target", {}).get("blueScore") != 12:
    errors.append("afterApply dagInfo finality blue score is not 12")
if after_dag_runtime_recovery.get("lastCheckpointFinalityBlueScore") != 12:
    errors.append("afterApply dagInfo runtimeRecovery lastCheckpointFinalityBlueScore is not 12")
if after_dag_runtime_recovery.get("lastCheckpointDecisionSource") != "ghostdagCheckpointBft":
    errors.append("afterApply dagInfo runtimeRecovery lastCheckpointDecisionSource is not ghostdagCheckpointBft")
if after_dag_lifecycle.get("checkpointFinalized") is not True:
    errors.append("afterApply dagInfo validatorLifecycleRecovery checkpointFinalized is not true")
if after_dag_lifecycle.get("lastCheckpointFinalityBlueScore") != 12:
    errors.append("afterApply dagInfo validatorLifecycleRecovery lastCheckpointFinalityBlueScore is not 12")
if after_dag_lifecycle.get("lastCheckpointDecisionSource") != "ghostdagCheckpointBft":
    errors.append("afterApply dagInfo validatorLifecycleRecovery lastCheckpointDecisionSource is not ghostdagCheckpointBft")

if after_restart_chain.get("currentEpoch") != 1:
    errors.append("afterRestart currentEpoch is not 1")
if after_restart_chain.get("activeCount") != 3:
    errors.append("afterRestart activeCount is not 3")
if after_restart_chain.get("configuredActiveCount") != 3:
    errors.append("afterRestart configuredActiveCount is not 3")
if after_restart_chain.get("previewMatchesRuntime") is not True:
    errors.append("afterRestart previewMatchesRuntime is not true")
if after_restart_chain.get("previewQuorumThreshold") != "3":
    errors.append("afterRestart previewQuorumThreshold is not 3")
if after_restart_chain.get("runtimeQuorumThreshold") != "3":
    errors.append("afterRestart runtimeQuorumThreshold is not 3")
if after_restart_chain.get("runtimeActiveSetPresent") is not True:
    errors.append("afterRestart runtimeActiveSetPresent is not true")
if after_restart_chain.get("runtimeActiveSetCount") != 3:
    errors.append("afterRestart runtimeActiveSetCount is not 3")
if after_restart_chain.get("runtimeActiveSetMatchesPreview") is not True:
    errors.append("afterRestart runtimeActiveSetMatchesPreview is not true")
if after_restart_chain.get("localRuntimeSrIndex") != 2:
    errors.append("afterRestart localRuntimeSrIndex is not 2")
if after_restart_chain.get("localRuntimeSrIndexConsistent") is not True:
    errors.append("afterRestart localRuntimeSrIndexConsistent is not true")
if after_restart_attestation.get("latestCheckpointFinality", {}).get("target", {}).get("blueScore") != 12:
    errors.append("afterRestart chainInfo finality blue score is not 12")
if after_restart_lifecycle.get("checkpointFinalized") is not True:
    errors.append("afterRestart chainInfo validatorLifecycleRecovery checkpointFinalized is not true")
if after_restart_lifecycle.get("lastCheckpointDecisionSource") != "ghostdagCheckpointBft":
    errors.append("afterRestart chainInfo validatorLifecycleRecovery lastCheckpointDecisionSource is not ghostdagCheckpointBft")
if after_restart_dag.get("activeCount") != 3:
    errors.append("afterRestart dagInfo activeCount is not 3")
if after_restart_dag.get("configuredActiveCount") != 3:
    errors.append("afterRestart dagInfo configuredActiveCount is not 3")
if after_restart_dag.get("previewMatchesRuntime") is not True:
    errors.append("afterRestart dagInfo previewMatchesRuntime is not true")
if after_restart_dag.get("runtimeActiveSetPresent") is not True:
    errors.append("afterRestart dagInfo runtimeActiveSetPresent is not true")
if after_restart_dag.get("runtimeActiveSetCount") != 3:
    errors.append("afterRestart dagInfo runtimeActiveSetCount is not 3")
if after_restart_dag.get("runtimeActiveSetMatchesPreview") is not True:
    errors.append("afterRestart dagInfo runtimeActiveSetMatchesPreview is not true")
if after_restart_dag_attestation.get("latestCheckpointFinality", {}).get("target", {}).get("blueScore") != 12:
    errors.append("afterRestart dagInfo finality blue score is not 12")
if after_restart_dag_lifecycle.get("checkpointFinalized") is not True:
    errors.append("afterRestart dagInfo validatorLifecycleRecovery checkpointFinalized is not true")
if after_restart_dag_lifecycle.get("lastCheckpointDecisionSource") != "ghostdagCheckpointBft":
    errors.append("afterRestart dagInfo validatorLifecycleRecovery lastCheckpointDecisionSource is not ghostdagCheckpointBft")
if not isinstance(after_restart_runtime_recovery.get("startupSnapshotRestored"), bool):
    errors.append("afterRestart runtimeRecovery startupSnapshotRestored should be a boolean")
if before_second_chain.get("currentEpoch") != 2:
    errors.append("beforeSecondApply currentEpoch is not 2")
if before_second_chain.get("previewMatchesRuntime") is not False:
    errors.append("beforeSecondApply previewMatchesRuntime is not false")
if before_second_chain.get("runtimeActiveSetPresent") is not True:
    errors.append("beforeSecondApply runtimeActiveSetPresent is not true")
if before_second_chain.get("runtimeActiveSetCount") != 3:
    errors.append("beforeSecondApply runtimeActiveSetCount is not 3")
if before_second_chain.get("runtimeActiveSetMatchesPreview") is not False:
    errors.append("beforeSecondApply runtimeActiveSetMatchesPreview is not false")
if before_second_chain.get("localPreviewSrIndex") != 0:
    errors.append("beforeSecondApply localPreviewSrIndex is not 0")
if before_second_chain.get("localRuntimeSrIndex") != 2:
    errors.append("beforeSecondApply localRuntimeSrIndex is not 2")
if before_second_attestation.get("latestCheckpointFinality", {}).get("target", {}).get("blueScore") != 18:
    errors.append("beforeSecondApply finality blue score is not 18")
if before_second_runtime_recovery.get("lastCheckpointFinalityBlueScore") != 18:
    errors.append("beforeSecondApply runtimeRecovery lastCheckpointFinalityBlueScore is not 18")
if before_second_runtime_recovery.get("lastCheckpointDecisionSource") != "ghostdagCheckpointBft":
    errors.append("beforeSecondApply runtimeRecovery lastCheckpointDecisionSource is not ghostdagCheckpointBft")
if before_second_lifecycle.get("checkpointFinalized") is not True:
    errors.append("beforeSecondApply validatorLifecycleRecovery checkpointFinalized is not true")
if before_second_lifecycle.get("lastCheckpointFinalityBlueScore") != 18:
    errors.append("beforeSecondApply validatorLifecycleRecovery lastCheckpointFinalityBlueScore is not 18")
if before_second_lifecycle.get("lastCheckpointDecisionSource") != "ghostdagCheckpointBft":
    errors.append("beforeSecondApply validatorLifecycleRecovery lastCheckpointDecisionSource is not ghostdagCheckpointBft")

if after_second_chain.get("currentEpoch") != 2:
    errors.append("afterSecondApply currentEpoch is not 2")
if after_second_chain.get("activeCount") != 3:
    errors.append("afterSecondApply activeCount is not 3")
if after_second_chain.get("configuredActiveCount") != 3:
    errors.append("afterSecondApply configuredActiveCount is not 3")
if after_second_chain.get("previewMatchesRuntime") is not True:
    errors.append("afterSecondApply previewMatchesRuntime is not true")
if after_second_chain.get("runtimeActiveSetPresent") is not True:
    errors.append("afterSecondApply runtimeActiveSetPresent is not true")
if after_second_chain.get("runtimeActiveSetCount") != 3:
    errors.append("afterSecondApply runtimeActiveSetCount is not 3")
if after_second_chain.get("runtimeActiveSetMatchesPreview") is not True:
    errors.append("afterSecondApply runtimeActiveSetMatchesPreview is not true")
if after_second_chain.get("localPreviewSrIndex") != 0:
    errors.append("afterSecondApply localPreviewSrIndex is not 0")
if after_second_chain.get("localRuntimeSrIndex") != 0:
    errors.append("afterSecondApply localRuntimeSrIndex is not 0")
if after_second_attestation.get("latestCheckpointFinality", {}).get("target", {}).get("blueScore") != 18:
    errors.append("afterSecondApply chainInfo finality blue score is not 18")
if after_second_runtime_recovery.get("lastCheckpointFinalityBlueScore") != 18:
    errors.append("afterSecondApply chainInfo runtimeRecovery lastCheckpointFinalityBlueScore is not 18")
if after_second_runtime_recovery.get("lastCheckpointDecisionSource") != "ghostdagCheckpointBft":
    errors.append("afterSecondApply chainInfo runtimeRecovery lastCheckpointDecisionSource is not ghostdagCheckpointBft")
if after_second_lifecycle.get("checkpointFinalized") is not True:
    errors.append("afterSecondApply chainInfo validatorLifecycleRecovery checkpointFinalized is not true")
if after_second_lifecycle.get("lastCheckpointFinalityBlueScore") != 18:
    errors.append("afterSecondApply chainInfo validatorLifecycleRecovery lastCheckpointFinalityBlueScore is not 18")
if after_second_lifecycle.get("lastCheckpointDecisionSource") != "ghostdagCheckpointBft":
    errors.append("afterSecondApply chainInfo validatorLifecycleRecovery lastCheckpointDecisionSource is not ghostdagCheckpointBft")
if after_second_dag.get("currentEpoch") != 2:
    errors.append("afterSecondApply dagInfo currentEpoch is not 2")
if after_second_dag.get("activeCount") != 3:
    errors.append("afterSecondApply dagInfo activeCount is not 3")
if after_second_dag.get("configuredActiveCount") != 3:
    errors.append("afterSecondApply dagInfo configuredActiveCount is not 3")
if after_second_dag.get("previewMatchesRuntime") is not True:
    errors.append("afterSecondApply dagInfo previewMatchesRuntime is not true")
if after_second_dag.get("runtimeActiveSetPresent") is not True:
    errors.append("afterSecondApply dagInfo runtimeActiveSetPresent is not true")
if after_second_dag.get("runtimeActiveSetCount") != 3:
    errors.append("afterSecondApply dagInfo runtimeActiveSetCount is not 3")
if after_second_dag.get("runtimeActiveSetMatchesPreview") is not True:
    errors.append("afterSecondApply dagInfo runtimeActiveSetMatchesPreview is not true")
if after_second_dag_attestation.get("latestCheckpointFinality", {}).get("target", {}).get("blueScore") != 18:
    errors.append("afterSecondApply dagInfo finality blue score is not 18")
if after_second_dag_runtime_recovery.get("lastCheckpointFinalityBlueScore") != 18:
    errors.append("afterSecondApply dagInfo runtimeRecovery lastCheckpointFinalityBlueScore is not 18")
if after_second_dag_runtime_recovery.get("lastCheckpointDecisionSource") != "ghostdagCheckpointBft":
    errors.append("afterSecondApply dagInfo runtimeRecovery lastCheckpointDecisionSource is not ghostdagCheckpointBft")
if after_second_dag_lifecycle.get("checkpointFinalized") is not True:
    errors.append("afterSecondApply dagInfo validatorLifecycleRecovery checkpointFinalized is not true")
if after_second_dag_lifecycle.get("lastCheckpointFinalityBlueScore") != 18:
    errors.append("afterSecondApply dagInfo validatorLifecycleRecovery lastCheckpointFinalityBlueScore is not 18")
if after_second_dag_lifecycle.get("lastCheckpointDecisionSource") != "ghostdagCheckpointBft":
    errors.append("afterSecondApply dagInfo validatorLifecycleRecovery lastCheckpointDecisionSource is not ghostdagCheckpointBft")

if second_rotation_delta.get("localRuntimeIndexBefore") != 2:
    errors.append("secondRotationDelta localRuntimeIndexBefore is not 2")
if second_rotation_delta.get("localRuntimeIndexAfter") != 0:
    errors.append("secondRotationDelta localRuntimeIndexAfter is not 0")
if second_rotation_delta.get("addedValidatorIds") is None or len(second_rotation_delta.get("addedValidatorIds")) != 1:
    errors.append("secondRotationDelta addedValidatorIds must contain 1 entry")
if second_rotation_delta.get("removedValidatorIds") is None or len(second_rotation_delta.get("removedValidatorIds")) != 1:
    errors.append("secondRotationDelta removedValidatorIds must contain 1 entry")

for key in (
    "staleRuntimeVisibleBeforeApply",
    "runtimeActiveSetMissingBeforeApply",
    "epochBoundaryVisibleBeforeApply",
    "finalizedCheckpointVisibleBeforeApply",
    "epochBoundaryReachedFromFinalizedCheckpoint",
    "runtimeAlignedAfterApply",
    "runtimeActiveSetApplied",
    "finalizedCheckpointProvenanceRetainedAfterApply",
    "activeCountApplied",
    "localRuntimeIndexApplied",
    "quorumThresholdApplied",
    "chainDagCommitteeSummaryConsistentAfterApply",
    "currentRuntimeStillValidatorBreadth",
    "completionTargetMatchesPlan",
    "secondEpochBoundaryVisibleBeforeApply",
    "secondEpochBoundaryReachedFromFinalizedCheckpoint",
    "staleSecondRotationVisibleBeforeApply",
    "secondRotationAppliedAfterRestart",
    "secondRotationChangedMembershipAfterRestart",
    "secondRuntimeIndexRotatedAfterRestart",
    "secondCheckpointProvenanceRetainedAfterApply",
    "chainDagCommitteeSummaryConsistentAfterSecondApply",
    "currentRuntimeStillValidatorBreadthAfterSecondApply",
    "completionTargetMatchesPlanAfterSecondApply",
):
    if consistency.get(key) is not True:
        errors.append(f"consistency flag is not true: {key}")

for key in (
    "snapshotArtifactsWritten",
    "serviceRestartContinuity",
    "chainDagCommitteeSummaryConsistentAfterRestart",
    "finalizedCheckpointProvenanceRetainedAfterRestart",
    "committeeStatePersistedAfterRestart",
    "runtimeActiveSetPersistedAfterRestart",
    "currentRuntimeStillValidatorBreadthAfterRestart",
    "completionTargetMatchesPlanAfterRestart",
):
    if restart_consistency.get(key) is not True:
        errors.append(f"restartConsistency flag is not true: {key}")

if not isinstance(restart_consistency.get("startupSnapshotRestoredAfterRestart"), bool):
    errors.append("restartConsistency startupSnapshotRestoredAfterRestart should be a boolean")

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

echo "sr21 rotation rehearsal passed"
echo "  $result_file"
