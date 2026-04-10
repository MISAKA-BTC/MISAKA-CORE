#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

run_root="${MISAKA_RELEASE_GATE_DIR:-$repo_root/.tmp/dag-release-gate}"
logs_dir="$run_root/logs"
summary_file="$run_root/summary.txt"
result_file="$run_root/result.json"
steps_file="$run_root/steps.txt"
current_step="preflight"

mkdir -p "$run_root" "$logs_dir"
: >"$steps_file"
{
  echo "repo_root=$repo_root"
  echo "run_root=$run_root"
  echo "timestamp_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
} >"$summary_file"

write_summary_line() {
  printf '%s\n' "$1" >>"$summary_file"
}

path_within_repo() {
  local path="$1"
  if [[ "$path" == "$repo_root" ]]; then
    printf '.\n'
  elif [[ "$path" == "$repo_root/"* ]]; then
    printf '%s\n' "${path#"$repo_root"/}"
  else
    printf '%s\n' "$path"
  fi
}

host_artifact_path() {
  local path="$1"
  if [[ -z "$path" ]]; then
    printf '\n'
  elif [[ "$path" == /* ]]; then
    printf '%s\n' "$path"
  else
    printf '%s/%s\n' "$repo_root" "$path"
  fi
}

validate_shielded_vk_manifest_result() {
  local manifest_json="$1"
  local include_bounded_sha3="${2:-0}"
  local include_bounded_groth16="${3:-0}"
  local include_bounded_plonk="${4:-0}"
  local include_bounded_plonk_three_validator="${5:-0}"
  local include_bounded_sha3_three_validator="${6:-0}"
  local include_bounded_groth16_three_validator="${7:-0}"
  local include_full_path_sha3="${8:-0}"
  local include_full_path_groth16="${9:-0}"
  local include_full_path_plonk="${10:-0}"
  local include_full_path_plonk_three_validator="${11:-0}"
  local include_full_path_plonk_four_validator="${12:-0}"
  local include_full_path_sha3_three_validator="${13:-0}"
  local include_full_path_groth16_three_validator="${14:-0}"
  local include_full_path_sha3_four_validator="${15:-0}"
  local include_full_path_groth16_four_validator="${16:-0}"
  local include_full_path_sha3_three_validator_sequence="${17:-0}"
  local include_full_path_groth16_three_validator_sequence="${18:-0}"
  local include_full_path_plonk_three_validator_sequence="${19:-0}"
  local include_full_path_sha3_four_validator_sequence="${20:-0}"
  local include_full_path_groth16_four_validator_sequence="${21:-0}"
  local include_full_path_plonk_four_validator_sequence="${22:-0}"
  local include_runtime_comparison="${23:-0}"
  local include_full_path_sha3_six_validator="${24:-0}"
  local include_full_path_groth16_six_validator="${25:-0}"
  local include_full_path_plonk_six_validator="${26:-0}"
  local include_full_path_sha3_six_validator_sequence="${27:-0}"
  local include_full_path_groth16_six_validator_sequence="${28:-0}"
  local include_full_path_plonk_six_validator_sequence="${29:-0}"
  local include_full_path_sha3_seven_validator="${30:-0}"
  local include_full_path_groth16_seven_validator="${31:-0}"
  local include_full_path_plonk_seven_validator="${32:-0}"
  local include_full_path_sha3_seven_validator_sequence="${33:-0}"
  local include_full_path_groth16_seven_validator_sequence="${34:-0}"
  local include_full_path_plonk_seven_validator_sequence="${35:-0}"
  local include_full_path_sha3_eight_validator="${36:-0}"
  local include_full_path_groth16_eight_validator="${37:-0}"
  local include_full_path_plonk_eight_validator="${38:-0}"
  local include_full_path_sha3_eight_validator_sequence="${39:-0}"
  local include_full_path_groth16_eight_validator_sequence="${40:-0}"
  local include_full_path_plonk_eight_validator_sequence="${41:-0}"
  local include_full_path_sha3_nine_validator="${42:-0}"
  local include_full_path_groth16_nine_validator="${43:-0}"
  local include_full_path_plonk_nine_validator="${44:-0}"
  local include_full_path_sha3_nine_validator_sequence="${45:-0}"
  local include_full_path_groth16_nine_validator_sequence="${46:-0}"
  local include_full_path_plonk_nine_validator_sequence="${47:-0}"
  if [[ ! -f "$manifest_json" ]]; then
    fail "shielded VK manifest result is missing: ${manifest_json}"
  fi
  python3 - "$manifest_json" "$include_bounded_sha3" "$include_bounded_groth16" "$include_bounded_plonk" "$include_bounded_plonk_three_validator" "$include_bounded_sha3_three_validator" "$include_bounded_groth16_three_validator" "$include_full_path_sha3" "$include_full_path_groth16" "$include_full_path_plonk" "$include_full_path_plonk_three_validator" "$include_full_path_plonk_four_validator" "$include_full_path_sha3_three_validator" "$include_full_path_groth16_three_validator" "$include_full_path_sha3_four_validator" "$include_full_path_groth16_four_validator" "$include_full_path_sha3_three_validator_sequence" "$include_full_path_groth16_three_validator_sequence" "$include_full_path_plonk_three_validator_sequence" "$include_full_path_sha3_four_validator_sequence" "$include_full_path_groth16_four_validator_sequence" "$include_full_path_plonk_four_validator_sequence" "$include_runtime_comparison" "$include_full_path_sha3_six_validator" "$include_full_path_groth16_six_validator" "$include_full_path_plonk_six_validator" "$include_full_path_sha3_six_validator_sequence" "$include_full_path_groth16_six_validator_sequence" "$include_full_path_plonk_six_validator_sequence" "$include_full_path_sha3_seven_validator" "$include_full_path_groth16_seven_validator" "$include_full_path_plonk_seven_validator" "$include_full_path_sha3_seven_validator_sequence" "$include_full_path_groth16_seven_validator_sequence" "$include_full_path_plonk_seven_validator_sequence" "$include_full_path_sha3_eight_validator" "$include_full_path_groth16_eight_validator" "$include_full_path_plonk_eight_validator" "$include_full_path_sha3_eight_validator_sequence" "$include_full_path_groth16_eight_validator_sequence" "$include_full_path_plonk_eight_validator_sequence" "$include_full_path_sha3_nine_validator" "$include_full_path_groth16_nine_validator" "$include_full_path_plonk_nine_validator" "$include_full_path_sha3_nine_validator_sequence" "$include_full_path_groth16_nine_validator_sequence" "$include_full_path_plonk_nine_validator_sequence" <<'PY'
import json
import pathlib
import sys

manifest_path = pathlib.Path(sys.argv[1])
include_bounded_sha3 = sys.argv[2] == "1"
include_bounded_groth16 = sys.argv[3] == "1"
include_bounded_plonk = sys.argv[4] == "1"
include_bounded_plonk_three_validator = sys.argv[5] == "1"
include_bounded_sha3_three_validator = sys.argv[6] == "1"
include_bounded_groth16_three_validator = sys.argv[7] == "1"
include_full_path_sha3 = sys.argv[8] == "1"
include_full_path_groth16 = sys.argv[9] == "1"
include_full_path_plonk = sys.argv[10] == "1"
include_full_path_plonk_three_validator = sys.argv[11] == "1"
include_full_path_plonk_four_validator = sys.argv[12] == "1"
include_full_path_sha3_three_validator = sys.argv[13] == "1"
include_full_path_groth16_three_validator = sys.argv[14] == "1"
include_full_path_sha3_four_validator = sys.argv[15] == "1"
include_full_path_groth16_four_validator = sys.argv[16] == "1"
include_full_path_sha3_three_validator_sequence = sys.argv[17] == "1"
include_full_path_groth16_three_validator_sequence = sys.argv[18] == "1"
include_full_path_plonk_three_validator_sequence = sys.argv[19] == "1"
include_full_path_sha3_four_validator_sequence = sys.argv[20] == "1"
include_full_path_groth16_four_validator_sequence = sys.argv[21] == "1"
include_full_path_plonk_four_validator_sequence = sys.argv[22] == "1"
include_runtime_comparison = sys.argv[23] == "1"
include_full_path_sha3_six_validator = sys.argv[24] == "1"
include_full_path_groth16_six_validator = sys.argv[25] == "1"
include_full_path_plonk_six_validator = sys.argv[26] == "1"
include_full_path_sha3_six_validator_sequence = sys.argv[27] == "1"
include_full_path_groth16_six_validator_sequence = sys.argv[28] == "1"
include_full_path_plonk_six_validator_sequence = sys.argv[29] == "1"
include_full_path_sha3_seven_validator = sys.argv[30] == "1"
include_full_path_groth16_seven_validator = sys.argv[31] == "1"
include_full_path_plonk_seven_validator = sys.argv[32] == "1"
include_full_path_sha3_seven_validator_sequence = sys.argv[33] == "1"
include_full_path_groth16_seven_validator_sequence = sys.argv[34] == "1"
include_full_path_plonk_seven_validator_sequence = sys.argv[35] == "1"
include_full_path_sha3_eight_validator = sys.argv[36] == "1"
include_full_path_groth16_eight_validator = sys.argv[37] == "1"
include_full_path_plonk_eight_validator = sys.argv[38] == "1"
include_full_path_sha3_eight_validator_sequence = sys.argv[39] == "1"
include_full_path_groth16_eight_validator_sequence = sys.argv[40] == "1"
include_full_path_plonk_eight_validator_sequence = sys.argv[41] == "1"
include_full_path_sha3_nine_validator = sys.argv[42] == "1"
include_full_path_groth16_nine_validator = sys.argv[43] == "1"
include_full_path_plonk_nine_validator = sys.argv[44] == "1"
include_full_path_sha3_nine_validator_sequence = sys.argv[45] == "1"
include_full_path_groth16_nine_validator_sequence = sys.argv[46] == "1"
include_full_path_plonk_nine_validator_sequence = sys.argv[47] == "1"

payload = json.loads(manifest_path.read_text(encoding="utf-8"))
artifacts = payload.get("artifacts") if isinstance(payload.get("artifacts"), dict) else {}
runbook = payload.get("runbookReadiness") if isinstance(payload.get("runbookReadiness"), dict) else {}
errors = []

if payload.get("status") != "passed":
    errors.append(f"manifest status is not passed: {payload.get('status')!r}")

def check_host_artifact(label: str, key: str) -> None:
    value = artifacts.get(key)
    if not isinstance(value, str) or not value:
        errors.append(f"{label} artifact is missing")
        return
    if value.startswith("/work/"):
        errors.append(f"{label} artifact still points at container path: {value}")
        return
    path = pathlib.Path(value)
    if not path.is_absolute():
        errors.append(f"{label} artifact is not an absolute host path: {value}")
        return
    if not path.exists():
        errors.append(f"{label} artifact path does not exist: {value}")

def check_flag(label: str, key: str, expected: bool) -> None:
    if runbook.get(key) is not expected:
        errors.append(f"{label} flag drift: expected {expected}, got {runbook.get(key)!r}")

requested_bounded = any((
    include_bounded_sha3,
    include_bounded_groth16,
    include_bounded_plonk,
    include_bounded_plonk_three_validator,
    include_bounded_sha3_three_validator,
    include_bounded_groth16_three_validator,
))
requested_full_path = any((
    include_full_path_sha3,
    include_full_path_groth16,
    include_full_path_plonk,
    include_full_path_plonk_three_validator,
    include_full_path_plonk_four_validator,
    include_full_path_plonk_six_validator,
    include_full_path_plonk_seven_validator,
    include_full_path_sha3_three_validator,
    include_full_path_groth16_three_validator,
    include_full_path_sha3_six_validator,
    include_full_path_groth16_six_validator,
    include_full_path_sha3_seven_validator,
    include_full_path_groth16_seven_validator,
    include_full_path_sha3_three_validator_sequence,
    include_full_path_groth16_three_validator_sequence,
    include_full_path_plonk_three_validator_sequence,
    include_full_path_sha3_four_validator_sequence,
    include_full_path_groth16_four_validator_sequence,
    include_full_path_plonk_four_validator_sequence,
    include_full_path_sha3_six_validator_sequence,
    include_full_path_groth16_six_validator_sequence,
    include_full_path_plonk_six_validator_sequence,
    include_full_path_sha3_seven_validator_sequence,
    include_full_path_groth16_seven_validator_sequence,
    include_full_path_plonk_seven_validator_sequence,
    include_full_path_sha3_eight_validator,
    include_full_path_groth16_eight_validator,
    include_full_path_plonk_eight_validator,
    include_full_path_sha3_eight_validator_sequence,
    include_full_path_groth16_eight_validator_sequence,
    include_full_path_plonk_eight_validator_sequence,
    include_full_path_sha3_nine_validator,
    include_full_path_groth16_nine_validator,
    include_full_path_plonk_nine_validator,
    include_full_path_sha3_nine_validator_sequence,
    include_full_path_groth16_nine_validator_sequence,
    include_full_path_plonk_nine_validator_sequence,
    include_full_path_sha3_four_validator,
    include_full_path_groth16_four_validator,
))

check_flag("boundedSha3Included", "boundedSha3Included", include_bounded_sha3)
check_flag("boundedGroth16Included", "boundedGroth16Included", include_bounded_groth16)
check_flag("boundedPlonkIncluded", "boundedPlonkIncluded", include_bounded_plonk)
check_flag(
    "boundedPlonkThreeValidatorIncluded",
    "boundedPlonkThreeValidatorIncluded",
    include_bounded_plonk_three_validator,
)
check_flag(
    "boundedSha3ThreeValidatorIncluded",
    "boundedSha3ThreeValidatorIncluded",
    include_bounded_sha3_three_validator,
)
check_flag(
    "boundedGroth16ThreeValidatorIncluded",
    "boundedGroth16ThreeValidatorIncluded",
    include_bounded_groth16_three_validator,
)
check_flag("fullPathSha3Included", "fullPathSha3Included", include_full_path_sha3)
check_flag("fullPathGroth16Included", "fullPathGroth16Included", include_full_path_groth16)
check_flag("fullPathPlonkIncluded", "fullPathPlonkIncluded", include_full_path_plonk)
check_flag(
    "fullPathPlonkThreeValidatorIncluded",
    "fullPathPlonkThreeValidatorIncluded",
    include_full_path_plonk_three_validator,
)
check_flag(
    "fullPathPlonkFourValidatorIncluded",
    "fullPathPlonkFourValidatorIncluded",
    include_full_path_plonk_four_validator,
)
check_flag(
    "fullPathSha3ThreeValidatorIncluded",
    "fullPathSha3ThreeValidatorIncluded",
    include_full_path_sha3_three_validator,
)
check_flag(
    "fullPathGroth16ThreeValidatorIncluded",
    "fullPathGroth16ThreeValidatorIncluded",
    include_full_path_groth16_three_validator,
)
check_flag(
    "fullPathSha3ThreeValidatorSequenceIncluded",
    "fullPathSha3ThreeValidatorSequenceIncluded",
    include_full_path_sha3_three_validator_sequence,
)
check_flag(
    "fullPathGroth16ThreeValidatorSequenceIncluded",
    "fullPathGroth16ThreeValidatorSequenceIncluded",
    include_full_path_groth16_three_validator_sequence,
)
check_flag(
    "fullPathPlonkThreeValidatorSequenceIncluded",
    "fullPathPlonkThreeValidatorSequenceIncluded",
    include_full_path_plonk_three_validator_sequence,
)
check_flag(
    "fullPathSha3FourValidatorSequenceIncluded",
    "fullPathSha3FourValidatorSequenceIncluded",
    include_full_path_sha3_four_validator_sequence,
)
check_flag(
    "fullPathGroth16FourValidatorSequenceIncluded",
    "fullPathGroth16FourValidatorSequenceIncluded",
    include_full_path_groth16_four_validator_sequence,
)
check_flag(
    "fullPathPlonkFourValidatorSequenceIncluded",
    "fullPathPlonkFourValidatorSequenceIncluded",
    include_full_path_plonk_four_validator_sequence,
)
check_flag(
    "fullPathSha3FourValidatorIncluded",
    "fullPathSha3FourValidatorIncluded",
    include_full_path_sha3_four_validator,
)
check_flag(
    "fullPathGroth16FourValidatorIncluded",
    "fullPathGroth16FourValidatorIncluded",
    include_full_path_groth16_four_validator,
)
check_flag(
    "fullPathSha3SixValidatorIncluded",
    "fullPathSha3SixValidatorIncluded",
    include_full_path_sha3_six_validator,
)
check_flag(
    "fullPathSha3SevenValidatorIncluded",
    "fullPathSha3SevenValidatorIncluded",
    include_full_path_sha3_seven_validator,
)
check_flag(
    "fullPathGroth16SixValidatorIncluded",
    "fullPathGroth16SixValidatorIncluded",
    include_full_path_groth16_six_validator,
)
check_flag(
    "fullPathGroth16SevenValidatorIncluded",
    "fullPathGroth16SevenValidatorIncluded",
    include_full_path_groth16_seven_validator,
)
check_flag(
    "fullPathPlonkSixValidatorIncluded",
    "fullPathPlonkSixValidatorIncluded",
    include_full_path_plonk_six_validator,
)
check_flag(
    "fullPathPlonkSevenValidatorIncluded",
    "fullPathPlonkSevenValidatorIncluded",
    include_full_path_plonk_seven_validator,
)
check_flag(
    "fullPathSha3EightValidatorIncluded",
    "fullPathSha3EightValidatorIncluded",
    include_full_path_sha3_eight_validator,
)
check_flag(
    "fullPathGroth16EightValidatorIncluded",
    "fullPathGroth16EightValidatorIncluded",
    include_full_path_groth16_eight_validator,
)
check_flag(
    "fullPathPlonkEightValidatorIncluded",
    "fullPathPlonkEightValidatorIncluded",
    include_full_path_plonk_eight_validator,
)
check_flag(
    "fullPathSha3NineValidatorIncluded",
    "fullPathSha3NineValidatorIncluded",
    include_full_path_sha3_nine_validator,
)
check_flag(
    "fullPathGroth16NineValidatorIncluded",
    "fullPathGroth16NineValidatorIncluded",
    include_full_path_groth16_nine_validator,
)
check_flag(
    "fullPathPlonkNineValidatorIncluded",
    "fullPathPlonkNineValidatorIncluded",
    include_full_path_plonk_nine_validator,
)
check_flag(
    "fullPathSha3SixValidatorSequenceIncluded",
    "fullPathSha3SixValidatorSequenceIncluded",
    include_full_path_sha3_six_validator_sequence,
)
check_flag(
    "fullPathSha3SevenValidatorSequenceIncluded",
    "fullPathSha3SevenValidatorSequenceIncluded",
    include_full_path_sha3_seven_validator_sequence,
)
check_flag(
    "fullPathGroth16SixValidatorSequenceIncluded",
    "fullPathGroth16SixValidatorSequenceIncluded",
    include_full_path_groth16_six_validator_sequence,
)
check_flag(
    "fullPathGroth16SevenValidatorSequenceIncluded",
    "fullPathGroth16SevenValidatorSequenceIncluded",
    include_full_path_groth16_seven_validator_sequence,
)
check_flag(
    "fullPathPlonkSixValidatorSequenceIncluded",
    "fullPathPlonkSixValidatorSequenceIncluded",
    include_full_path_plonk_six_validator_sequence,
)
check_flag(
    "fullPathPlonkSevenValidatorSequenceIncluded",
    "fullPathPlonkSevenValidatorSequenceIncluded",
    include_full_path_plonk_seven_validator_sequence,
)
check_flag(
    "fullPathSha3EightValidatorSequenceIncluded",
    "fullPathSha3EightValidatorSequenceIncluded",
    include_full_path_sha3_eight_validator_sequence,
)
check_flag(
    "fullPathGroth16EightValidatorSequenceIncluded",
    "fullPathGroth16EightValidatorSequenceIncluded",
    include_full_path_groth16_eight_validator_sequence,
)
check_flag(
    "fullPathPlonkEightValidatorSequenceIncluded",
    "fullPathPlonkEightValidatorSequenceIncluded",
    include_full_path_plonk_eight_validator_sequence,
)
check_flag(
    "fullPathSha3NineValidatorSequenceIncluded",
    "fullPathSha3NineValidatorSequenceIncluded",
    include_full_path_sha3_nine_validator_sequence,
)
check_flag(
    "fullPathGroth16NineValidatorSequenceIncluded",
    "fullPathGroth16NineValidatorSequenceIncluded",
    include_full_path_groth16_nine_validator_sequence,
)
check_flag(
    "fullPathPlonkNineValidatorSequenceIncluded",
    "fullPathPlonkNineValidatorSequenceIncluded",
    include_full_path_plonk_nine_validator_sequence,
)
check_flag(
    "runtimeComparisonIncluded",
    "runtimeComparisonIncluded",
    include_runtime_comparison,
)

if requested_bounded:
    check_flag(
        "boundedLiveConsistentWithManifest",
        "boundedLiveConsistentWithManifest",
        True,
    )
if requested_full_path:
    check_flag(
        "fullPathLiveConsistentWithManifest",
        "fullPathLiveConsistentWithManifest",
        True,
    )
if include_runtime_comparison:
    check_flag(
        "runtimeComparisonConsistentWithManifest",
        "runtimeComparisonConsistentWithManifest",
        True,
    )
    check_flag(
        "runtimeComparisonRuntimeCommitteePlanReady",
        "runtimeComparisonRuntimeCommitteePlanReady",
        True,
    )
    check_flag(
        "runtimeComparisonRuntimeCommitteeStateReady",
        "runtimeComparisonRuntimeCommitteeStateReady",
        True,
    )
    check_flag(
        "runtimeComparisonTxDisseminationContractReady",
        "runtimeComparisonTxDisseminationContractReady",
        True,
    )
    check_flag(
        "runtimeComparisonRuntimeDisseminationStageReady",
        "runtimeComparisonRuntimeDisseminationStageReady",
        True,
    )
    check_flag(
        "runtimeComparisonRuntimeCheckpointDecisionSourceReady",
        "runtimeComparisonRuntimeCheckpointDecisionSourceReady",
        True,
    )
if any((include_full_path_groth16, include_full_path_groth16_three_validator, include_full_path_groth16_three_validator_sequence, include_full_path_groth16_four_validator, include_full_path_groth16_four_validator_sequence, include_full_path_groth16_six_validator, include_full_path_groth16_six_validator_sequence, include_full_path_groth16_seven_validator, include_full_path_groth16_seven_validator_sequence, include_full_path_groth16_eight_validator, include_full_path_groth16_eight_validator_sequence, include_full_path_groth16_nine_validator, include_full_path_groth16_nine_validator_sequence)):
    check_flag(
        "fullPathGroth16LiveConsistentWithManifest",
        "fullPathGroth16LiveConsistentWithManifest",
        True,
    )
if any((include_full_path_plonk, include_full_path_plonk_three_validator, include_full_path_plonk_three_validator_sequence, include_full_path_plonk_four_validator, include_full_path_plonk_four_validator_sequence, include_full_path_plonk_six_validator, include_full_path_plonk_six_validator_sequence, include_full_path_plonk_seven_validator, include_full_path_plonk_seven_validator_sequence, include_full_path_plonk_eight_validator, include_full_path_plonk_eight_validator_sequence, include_full_path_plonk_nine_validator, include_full_path_plonk_nine_validator_sequence)):
    check_flag(
        "fullPathPlonkLiveConsistentWithManifest",
        "fullPathPlonkLiveConsistentWithManifest",
        True,
    )

if include_bounded_sha3:
    check_host_artifact("boundedSha3", "boundedSha3Artifact")
if include_bounded_groth16:
    check_host_artifact("boundedGroth16", "boundedGroth16Artifact")
if include_bounded_plonk:
    check_host_artifact("boundedPlonk", "boundedPlonkArtifact")
if include_bounded_plonk_three_validator:
    check_host_artifact("boundedPlonkThreeValidator", "boundedPlonkThreeValidatorArtifact")
if include_bounded_sha3_three_validator:
    check_host_artifact("boundedSha3ThreeValidator", "boundedSha3ThreeValidatorArtifact")
if include_bounded_groth16_three_validator:
    check_host_artifact("boundedGroth16ThreeValidator", "boundedGroth16ThreeValidatorArtifact")
if include_full_path_sha3:
    check_host_artifact("fullPathSha3", "fullPathSha3Artifact")
if include_full_path_groth16:
    check_host_artifact("fullPathGroth16", "fullPathGroth16Artifact")
if include_full_path_plonk:
    check_host_artifact("fullPathPlonk", "fullPathPlonkArtifact")
if include_full_path_plonk_three_validator:
    check_host_artifact("fullPathPlonkThreeValidator", "fullPathPlonkThreeValidatorArtifact")
if include_full_path_plonk_four_validator:
    check_host_artifact("fullPathPlonkFourValidator", "fullPathPlonkFourValidatorArtifact")
if include_full_path_sha3_three_validator:
    check_host_artifact("fullPathSha3ThreeValidator", "fullPathSha3ThreeValidatorArtifact")
if include_full_path_groth16_three_validator:
    check_host_artifact("fullPathGroth16ThreeValidator", "fullPathGroth16ThreeValidatorArtifact")
if include_full_path_sha3_three_validator_sequence:
    check_host_artifact("fullPathSha3ThreeValidatorSequence", "fullPathSha3ThreeValidatorSequenceArtifact")
if include_full_path_groth16_three_validator_sequence:
    check_host_artifact("fullPathGroth16ThreeValidatorSequence", "fullPathGroth16ThreeValidatorSequenceArtifact")
if include_full_path_plonk_three_validator_sequence:
    check_host_artifact("fullPathPlonkThreeValidatorSequence", "fullPathPlonkThreeValidatorSequenceArtifact")
if include_full_path_sha3_four_validator_sequence:
    check_host_artifact("fullPathSha3FourValidatorSequence", "fullPathSha3FourValidatorSequenceArtifact")
if include_full_path_groth16_four_validator_sequence:
    check_host_artifact("fullPathGroth16FourValidatorSequence", "fullPathGroth16FourValidatorSequenceArtifact")
if include_full_path_plonk_four_validator_sequence:
    check_host_artifact("fullPathPlonkFourValidatorSequence", "fullPathPlonkFourValidatorSequenceArtifact")
if include_full_path_sha3_six_validator_sequence:
    check_host_artifact("fullPathSha3SixValidatorSequence", "fullPathSha3SixValidatorSequenceArtifact")
if include_full_path_groth16_six_validator_sequence:
    check_host_artifact("fullPathGroth16SixValidatorSequence", "fullPathGroth16SixValidatorSequenceArtifact")
if include_full_path_plonk_six_validator_sequence:
    check_host_artifact("fullPathPlonkSixValidatorSequence", "fullPathPlonkSixValidatorSequenceArtifact")
if include_full_path_sha3_seven_validator_sequence:
    check_host_artifact("fullPathSha3SevenValidatorSequence", "fullPathSha3SevenValidatorSequenceArtifact")
if include_full_path_groth16_seven_validator_sequence:
    check_host_artifact("fullPathGroth16SevenValidatorSequence", "fullPathGroth16SevenValidatorSequenceArtifact")
if include_full_path_plonk_seven_validator_sequence:
    check_host_artifact("fullPathPlonkSevenValidatorSequence", "fullPathPlonkSevenValidatorSequenceArtifact")
if include_full_path_sha3_eight_validator_sequence:
    check_host_artifact("fullPathSha3EightValidatorSequence", "fullPathSha3EightValidatorSequenceArtifact")
if include_full_path_groth16_eight_validator_sequence:
    check_host_artifact("fullPathGroth16EightValidatorSequence", "fullPathGroth16EightValidatorSequenceArtifact")
if include_full_path_plonk_eight_validator_sequence:
    check_host_artifact("fullPathPlonkEightValidatorSequence", "fullPathPlonkEightValidatorSequenceArtifact")
if include_full_path_sha3_nine_validator_sequence:
    check_host_artifact("fullPathSha3NineValidatorSequence", "fullPathSha3NineValidatorSequenceArtifact")
if include_full_path_groth16_nine_validator_sequence:
    check_host_artifact("fullPathGroth16NineValidatorSequence", "fullPathGroth16NineValidatorSequenceArtifact")
if include_full_path_plonk_nine_validator_sequence:
    check_host_artifact("fullPathPlonkNineValidatorSequence", "fullPathPlonkNineValidatorSequenceArtifact")
if include_full_path_sha3_four_validator:
    check_host_artifact("fullPathSha3FourValidator", "fullPathSha3FourValidatorArtifact")
if include_full_path_groth16_four_validator:
    check_host_artifact("fullPathGroth16FourValidator", "fullPathGroth16FourValidatorArtifact")
if include_full_path_sha3_six_validator:
    check_host_artifact("fullPathSha3SixValidator", "fullPathSha3SixValidatorArtifact")
if include_full_path_groth16_six_validator:
    check_host_artifact("fullPathGroth16SixValidator", "fullPathGroth16SixValidatorArtifact")
if include_full_path_plonk_six_validator:
    check_host_artifact("fullPathPlonkSixValidator", "fullPathPlonkSixValidatorArtifact")
if include_full_path_sha3_seven_validator:
    check_host_artifact("fullPathSha3SevenValidator", "fullPathSha3SevenValidatorArtifact")
if include_full_path_groth16_seven_validator:
    check_host_artifact("fullPathGroth16SevenValidator", "fullPathGroth16SevenValidatorArtifact")
if include_full_path_plonk_seven_validator:
    check_host_artifact("fullPathPlonkSevenValidator", "fullPathPlonkSevenValidatorArtifact")
if include_full_path_sha3_eight_validator:
    check_host_artifact("fullPathSha3EightValidator", "fullPathSha3EightValidatorArtifact")
if include_full_path_groth16_eight_validator:
    check_host_artifact("fullPathGroth16EightValidator", "fullPathGroth16EightValidatorArtifact")
if include_full_path_plonk_eight_validator:
    check_host_artifact("fullPathPlonkEightValidator", "fullPathPlonkEightValidatorArtifact")
if include_full_path_sha3_nine_validator:
    check_host_artifact("fullPathSha3NineValidator", "fullPathSha3NineValidatorArtifact")
if include_full_path_groth16_nine_validator:
    check_host_artifact("fullPathGroth16NineValidator", "fullPathGroth16NineValidatorArtifact")
if include_full_path_plonk_nine_validator:
    check_host_artifact("fullPathPlonkNineValidator", "fullPathPlonkNineValidatorArtifact")
if include_runtime_comparison:
    check_host_artifact("runtimeComparison", "runtimeComparisonArtifact")

if errors:
    raise SystemExit("\n".join(errors))
PY
}

write_normalized_json_copy() {
  local source_json="$1"
  local dest_json="$2"
  local container_root="${3:-/work}"
  if [[ ! -f "$source_json" ]]; then
    return 0
  fi
  python3 - "$source_json" "$dest_json" "$container_root" "$repo_root" <<'PY'
import json
import pathlib
import sys

source_json = pathlib.Path(sys.argv[1])
dest_json = pathlib.Path(sys.argv[2])
container_root = sys.argv[3].rstrip("/")
host_root = sys.argv[4].rstrip("/")

def rewrite(value):
    if isinstance(value, dict):
        return {k: rewrite(v) for k, v in value.items()}
    if isinstance(value, list):
        return [rewrite(v) for v in value]
    if isinstance(value, str):
        if value == container_root:
            return host_root
        if value.startswith(container_root + "/"):
            return host_root + value[len(container_root):]
    return value

data = json.loads(source_json.read_text(encoding="utf-8"))
dest_json.parent.mkdir(parents=True, exist_ok=True)
dest_json.write_text(json.dumps(rewrite(data), ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
PY
}

require_repo_portable_path() {
  local label="$1"
  local path="$2"
  if [[ "$path" == /* && "$path" != "$repo_root" && "$path" != "$repo_root/"* ]]; then
    fail "${label} must stay under repo root when docker fallback is active: ${path}"
  fi
}

write_result_json() {
  local status="$1"
  local failure_step="${2:-}"
  local failure_reason="${3:-}"
  local release_profile="${MISAKA_RELEASE_GATE_PROFILE:-default}"
  local recovery_restart_result="${MISAKA_RECOVERY_RESTART_DIR:-$repo_root/.tmp/recovery-restart-proof}/result.json"
  local recovery_multinode_result="${MISAKA_RECOVERY_HARNESS_DIR:-$repo_root/.tmp/recovery-multinode-proof}/result.json"
  local narwhal_dissemination_rehearsal_result="${MISAKA_NARWHAL_DISSEMINATION_REHEARSAL_RESULT:-$repo_root/.tmp/dag-narwhal-dissemination-rehearsal/result.json}"
  local sr21_committee_rehearsal_result="${MISAKA_SR21_COMMITTEE_REHEARSAL_RESULT:-$repo_root/.tmp/dag-sr21-committee-rehearsal/result.json}"
  local sr21_rotation_rehearsal_result="${MISAKA_SR21_ROTATION_REHEARSAL_RESULT:-$repo_root/.tmp/dag-sr21-rotation-rehearsal/result.json}"
  local sr21_selection_rehearsal_result="${MISAKA_SR21_SELECTION_REHEARSAL_RESULT:-$repo_root/.tmp/dag-sr21-selection-rehearsal/result.json}"
  local release_support_rehearsal_result="${MISAKA_RELEASE_SUPPORT_REHEARSAL_RESULT:-$repo_root/.tmp/dag-release-support-rehearsal/result.json}"
  local bullshark_auto_candidate_rehearsal_result="${MISAKA_BULLSHARK_AUTO_CANDIDATE_REHEARSAL_RESULT:-$repo_root/.tmp/dag-bullshark-auto-candidate-rehearsal/result.json}"
  local bullshark_auto_commit_rehearsal_result="${MISAKA_BULLSHARK_AUTO_COMMIT_REHEARSAL_RESULT:-$repo_root/.tmp/dag-bullshark-auto-commit-rehearsal/result.json}"
  local bullshark_auto_commit_live_rehearsal_result="${MISAKA_BULLSHARK_AUTO_COMMIT_LIVE_REHEARSAL_RESULT:-$repo_root/.tmp/dag-bullshark-auto-commit-live-rehearsal/result.json}"
  local bullshark_auto_committed_rehearsal_result="${MISAKA_BULLSHARK_AUTO_COMMITTED_REHEARSAL_RESULT:-$repo_root/.tmp/dag-bullshark-auto-committed-rehearsal/result.json}"
  local bullshark_auto_committed_live_rehearsal_result="${MISAKA_BULLSHARK_AUTO_COMMITTED_LIVE_REHEARSAL_RESULT:-$repo_root/.tmp/dag-bullshark-auto-committed-live-rehearsal/result.json}"
  local bullshark_commit_rehearsal_result="${MISAKA_BULLSHARK_COMMIT_REHEARSAL_RESULT:-$repo_root/.tmp/dag-bullshark-commit-rehearsal/result.json}"
  local bullshark_commit_authority_switch_rehearsal_result="${MISAKA_BULLSHARK_COMMIT_AUTHORITY_SWITCH_REHEARSAL_RESULT:-$repo_root/.tmp/dag-bullshark-commit-authority-switch-rehearsal/result.json}"
  local bullshark_authority_switch_rehearsal_result="${MISAKA_BULLSHARK_AUTHORITY_SWITCH_REHEARSAL_RESULT:-$repo_root/.tmp/dag-bullshark-authority-switch-rehearsal/result.json}"
  local bullshark_ordering_rehearsal_result="${MISAKA_BULLSHARK_ORDERING_REHEARSAL_RESULT:-$repo_root/.tmp/dag-bullshark-ordering-rehearsal/result.json}"
  local natural_restart_result=""
  local three_validator_result=""
  local shielded_vk_manifest_result=""
  if [[ "${MISAKA_SKIP_NATURAL_DURABLE_RESTART:-0}" != "1" ]]; then
    natural_restart_result="${MISAKA_HARNESS_DIR:-$repo_root/.tmp/dag-natural-restart-harness}/result.json"
  fi
  if [[ "${MISAKA_RUN_THREE_VALIDATOR_RESTART:-0}" == "1" ]]; then
    if [[ -n "${MISAKA_HARNESS_DIR:-}" ]]; then
      three_validator_result="${MISAKA_HARNESS_DIR}/result.json"
    else
      three_validator_result="$repo_root/.tmp/dag-three-validator-recovery-harness/result.json"
    fi
  fi
  if [[ "${MISAKA_RUN_SHIELDED_VK_MANIFEST:-0}" == "1" ]]; then
    shielded_vk_manifest_result="${MISAKA_SHIELDED_VK_MANIFEST_HOST_RESULT:-$(host_artifact_path "${MISAKA_SHIELDED_VK_MANIFEST_DIR:-$run_root/shielded-vk-manifest}/result.json")}"
  fi

  python3 - "$steps_file" "$result_file" "$summary_file" "$logs_dir" "$status" "$failure_step" "$failure_reason" "$release_profile" "$recovery_restart_result" "$recovery_multinode_result" "$narwhal_dissemination_rehearsal_result" "$sr21_committee_rehearsal_result" "$sr21_rotation_rehearsal_result" "$sr21_selection_rehearsal_result" "$release_support_rehearsal_result" "$bullshark_auto_candidate_rehearsal_result" "$bullshark_ordering_rehearsal_result" "$natural_restart_result" "$three_validator_result" "$shielded_vk_manifest_result" "$bullshark_auto_commit_rehearsal_result" "$bullshark_auto_commit_live_rehearsal_result" "$bullshark_auto_committed_rehearsal_result" "$bullshark_auto_committed_live_rehearsal_result" "$bullshark_commit_rehearsal_result" "$bullshark_commit_authority_switch_rehearsal_result" "$bullshark_authority_switch_rehearsal_result" <<'PY'
import json
import pathlib
import sys

(steps_file, result_file, summary_file, logs_dir, status, failure_step, failure_reason,
 release_profile, recovery_restart_result, recovery_multinode_result,
 narwhal_dissemination_rehearsal_result, sr21_committee_rehearsal_result,
 sr21_rotation_rehearsal_result, sr21_selection_rehearsal_result,
 release_support_rehearsal_result,
 bullshark_auto_candidate_rehearsal_result, bullshark_ordering_rehearsal_result,
 natural_restart_result, three_validator_result,
 shielded_vk_manifest_result, bullshark_auto_commit_rehearsal_result,
 bullshark_auto_commit_live_rehearsal_result,
 bullshark_auto_committed_rehearsal_result,
 bullshark_auto_committed_live_rehearsal_result,
 bullshark_commit_rehearsal_result,
 bullshark_commit_authority_switch_rehearsal_result,
 bullshark_authority_switch_rehearsal_result) = sys.argv[1:28]

steps = []
steps_path = pathlib.Path(steps_file)
if steps_path.exists():
    for raw in steps_path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if raw:
            steps.append({"slug": raw, "status": "passed", "log": str(pathlib.Path(logs_dir) / f"{raw}.log")})

payload = {
    "status": status,
    "profile": release_profile,
    "failure": {
        "step": failure_step or None,
        "reason": failure_reason or None,
    },
    "steps": steps,
    "artifacts": {
        "summary": summary_file,
        "logsDir": logs_dir,
        "recoveryRestartResult": recovery_restart_result,
        "recoveryMultinodeResult": recovery_multinode_result,
        "narwhalDisseminationRehearsalResult": narwhal_dissemination_rehearsal_result,
        "sr21CommitteeRehearsalResult": sr21_committee_rehearsal_result,
        "sr21RotationRehearsalResult": sr21_rotation_rehearsal_result,
        "sr21SelectionRehearsalResult": sr21_selection_rehearsal_result,
        "releaseSupportRehearsalResult": release_support_rehearsal_result,
        "bullsharkAutomaticCandidatePreviewRehearsalResult": bullshark_auto_candidate_rehearsal_result,
        "bullsharkAutomaticCommitPreviewRehearsalResult": bullshark_auto_commit_rehearsal_result,
        "bullsharkAutomaticCommitPreviewLiveRehearsalResult": bullshark_auto_commit_live_rehearsal_result,
        "bullsharkAutomaticCommittedRehearsalResult": bullshark_auto_committed_rehearsal_result,
        "bullsharkAutomaticCommittedLiveRehearsalResult": bullshark_auto_committed_live_rehearsal_result,
        "bullsharkCommitRehearsalResult": bullshark_commit_rehearsal_result,
        "bullsharkCommitAuthoritySwitchRehearsalResult": bullshark_commit_authority_switch_rehearsal_result,
        "bullsharkAuthoritySwitchRehearsalResult": bullshark_authority_switch_rehearsal_result,
        "bullsharkOrderingRehearsalResult": bullshark_ordering_rehearsal_result,
        "naturalRestartResult": natural_restart_result or None,
        "threeValidatorRestartResult": three_validator_result or None,
        "shieldedVkManifestResult": shielded_vk_manifest_result or None,
    },
}
pathlib.Path(result_file).write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
PY
}

fail() {
  local message="$1"
  trap - ERR
  set +e
  echo "$message" >&2
  write_summary_line "result=failed"
  write_summary_line "failed_step=${current_step}"
  write_summary_line "failure_reason=${message}"
  write_summary_line "completed_at_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  write_result_json "failed" "$current_step" "$message"
  exit 1
}

trap 'fail "command failed: ${BASH_COMMAND}"' ERR

if ! command -v cargo >/dev/null 2>&1; then
  fail "cargo is required to run the release gate"
fi

if ! command -v docker >/dev/null 2>&1; then
  fail "docker is required to validate the node compose surface"
fi

if ! docker compose version >/dev/null 2>&1; then
  fail "docker compose plugin is required to validate the node compose surface"
fi

has_native_c_toolchain() {
  command -v clang >/dev/null 2>&1 &&
    printf '#include <stdbool.h>\nint main(void){return 0;}\n' | clang -x c -fsyntax-only - >/dev/null 2>&1
}

run_cargo_step() {
  if has_native_c_toolchain; then
    "$@"
    return 0
  fi

  local cargo_home="${CARGO_HOME:-${HOME:-}/.cargo}"
  local docker_args=(
    --rm
    -v "$repo_root:/work"
    -w /work
  )
  if [[ -d "$cargo_home/registry" ]]; then
    docker_args+=(-v "$cargo_home/registry:/usr/local/cargo/registry")
  fi
  if [[ -d "$cargo_home/git" ]]; then
    docker_args+=(-v "$cargo_home/git:/usr/local/cargo/git")
  fi

  local docker_env_args=()
  local forward_var
  for forward_var in \
    MISAKA_HARNESS_DIR \
    MISAKA_CARGO_TARGET_DIR \
    MISAKA_INITIAL_WAIT_ATTEMPTS \
    MISAKA_RESTART_WAIT_ATTEMPTS \
    MISAKA_POLL_INTERVAL_SECS \
    MISAKA_DAG_CHECKPOINT_INTERVAL \
    MISAKA_THREE_VALIDATOR_CHECKPOINT_INTERVAL \
    MISAKA_NODE_A_RPC_PORT \
    MISAKA_NODE_B_RPC_PORT \
    MISAKA_NODE_C_RPC_PORT \
    MISAKA_NODE_A_P2P_PORT \
    MISAKA_NODE_B_P2P_PORT \
    MISAKA_NODE_C_P2P_PORT
  do
    if [[ -n "${!forward_var:-}" ]]; then
      docker_env_args+=(-e "${forward_var}=${!forward_var}")
    fi
  done

  local shell_cmd
  shell_cmd="$(printf '%q ' "$@")"
  docker run \
    "${docker_args[@]}" \
    "${docker_env_args[@]}" \
    rust:1.89-bookworm \
    bash -lc "set -euo pipefail; \
      export PATH=/usr/local/cargo/bin:\$PATH; \
      apt-get update -qq >/dev/null && \
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clang libclang-dev build-essential cmake pkg-config >/dev/null && \
      export CARGO_TARGET_DIR=/work/target && \
      export BINDGEN_EXTRA_CLANG_ARGS=\"-isystem \$(gcc -print-file-name=include)\" && \
      ${shell_cmd}"
}

run_harness_step() {
  "$@"
}

run_step() {
  local label="$1"
  local slug="$2"
  shift 2
  local log_file="$logs_dir/${slug}.log"
  current_step="$slug"
  echo "[gate] ${label}"
  {
    echo "== ${label} =="
    echo "cmd: $*"
    echo
    "$@"
  } | tee "$log_file"
  printf '%s\n' "$slug" >>"$steps_file"
  write_summary_line "step=${slug}:passed"
}

tmp_env="$(mktemp "${TMPDIR:-/tmp}/misaka-node-env.XXXXXX")"
trap 'rm -f "$tmp_env"' EXIT
cp scripts/node.env.example "$tmp_env"

echo "[gate] validating operator shell surfaces"
run_step "validating operator shell surfaces" "shell_preflight" \
  bash -lc 'bash -n scripts/node-bootstrap.sh && bash -n scripts/recovery_restart_proof.sh && bash -n scripts/recovery_multinode_proof.sh && bash -n scripts/dag_natural_restart_harness.sh && bash -n scripts/dag_three_validator_recovery_harness.sh && bash -n scripts/dag_narwhal_dissemination_rehearsal.sh && bash -n scripts/dag_sr21_committee_rehearsal.sh && bash -n scripts/dag_sr21_rotation_rehearsal.sh && bash -n scripts/dag_sr21_selection_rehearsal.sh && bash -n scripts/dag_release_support_rehearsal.sh && bash -n scripts/build-release.sh && bash -n scripts/verify-release.sh && bash -n scripts/dag_bullshark_auto_candidate_rehearsal.sh && bash -n scripts/dag_bullshark_auto_commit_rehearsal.sh && bash -n scripts/dag_bullshark_auto_commit_live_rehearsal.sh && bash -n scripts/dag_bullshark_auto_committed_rehearsal.sh && bash -n scripts/dag_bullshark_auto_committed_live_rehearsal.sh && bash -n scripts/dag_bullshark_commit_rehearsal.sh && bash -n scripts/dag_bullshark_commit_authority_switch_rehearsal.sh && bash -n scripts/dag_bullshark_authority_switch_rehearsal.sh && bash -n scripts/dag_bullshark_ordering_rehearsal.sh && bash -n scripts/dag_release_gate_extended.sh && bash -n scripts/shielded_vk_artifact_inspect.sh && bash -n scripts/shielded_vk_runbook_manifest.sh && bash -n scripts/shielded_bounded_e2e.sh && bash -n scripts/shielded_live_bounded_e2e.sh && bash -n scripts/shielded_live_bounded_e2e_groth16.sh && bash -n scripts/shielded_live_bounded_e2e_plonk.sh && bash -n scripts/shielded_live_full_path_e2e.sh && bash -n scripts/shielded_live_full_path_e2e_groth16.sh && bash -n scripts/shielded_live_full_path_e2e_plonk.sh && sh -n docker/node-entrypoint.sh'

run_step "rehearsing node bootstrap config" "bootstrap_config" \
  bash -lc "MISAKA_NODE_ENV_FILE='$tmp_env' bash scripts/node-bootstrap.sh config >/dev/null"

run_step "running narwhal dissemination rehearsal" "narwhal_dissemination_rehearsal" \
  run_cargo_step bash scripts/dag_narwhal_dissemination_rehearsal.sh

run_step "running sr21 committee rehearsal" "sr21_committee_rehearsal" \
  run_cargo_step bash scripts/dag_sr21_committee_rehearsal.sh

run_step "running sr21 rotation rehearsal" "sr21_rotation_rehearsal" \
  run_cargo_step bash scripts/dag_sr21_rotation_rehearsal.sh

run_step "running sr21 selection rehearsal" "sr21_selection_rehearsal" \
  run_cargo_step bash scripts/dag_sr21_selection_rehearsal.sh

run_step "running bullshark automatic candidate rehearsal" "bullshark_auto_candidate_rehearsal" \
  run_cargo_step bash scripts/dag_bullshark_auto_candidate_rehearsal.sh

run_step "running bullshark automatic commit rehearsal" "bullshark_auto_commit_rehearsal" \
  run_cargo_step bash scripts/dag_bullshark_auto_commit_rehearsal.sh

run_step "running bullshark automatic live commit rehearsal" "bullshark_auto_commit_live_rehearsal" \
  run_cargo_step bash scripts/dag_bullshark_auto_commit_live_rehearsal.sh

run_step "running bullshark automatic committed rehearsal" "bullshark_auto_committed_rehearsal" \
  run_cargo_step bash scripts/dag_bullshark_auto_committed_rehearsal.sh

run_step "running bullshark automatic committed live rehearsal" "bullshark_auto_committed_live_rehearsal" \
  run_cargo_step bash scripts/dag_bullshark_auto_committed_live_rehearsal.sh

run_step "running bullshark commit rehearsal" "bullshark_commit_rehearsal" \
  run_cargo_step bash scripts/dag_bullshark_commit_rehearsal.sh

run_step "running bullshark commit authority-switch rehearsal" "bullshark_commit_authority_switch_rehearsal" \
  run_cargo_step bash scripts/dag_bullshark_commit_authority_switch_rehearsal.sh

run_step "running bullshark authority-switch rehearsal" "bullshark_authority_switch_rehearsal" \
  run_cargo_step bash scripts/dag_bullshark_authority_switch_rehearsal.sh

run_step "running bullshark ordering rehearsal" "bullshark_ordering_rehearsal" \
  run_cargo_step bash scripts/dag_bullshark_ordering_rehearsal.sh

run_step "running restart proof" "restart_proof" \
  run_cargo_step bash scripts/recovery_restart_proof.sh

run_step "running multi-node recovery proof" "multinode_recovery_proof" \
  run_cargo_step bash scripts/recovery_multinode_proof.sh

run_step "building release node binary for restart harnesses" "build_release_node" \
  run_cargo_step cargo build -p misaka-node --release --locked

run_step "running release support rehearsal" "release_support_rehearsal" \
  run_cargo_step bash scripts/dag_release_support_rehearsal.sh

if [ "${MISAKA_SKIP_NATURAL_DURABLE_RESTART:-0}" = "1" ]; then
  echo "[gate] skipping natural durable restart harness (explicit extended rehearsal path)"
else
  run_step "running natural durable restart harness" "natural_restart_harness" \
    run_harness_step env \
      MISAKA_SKIP_BUILD=1 \
      MISAKA_BIN=target/release/misaka-node \
      MISAKA_DAG_CHECKPOINT_INTERVAL="${MISAKA_DAG_CHECKPOINT_INTERVAL:-12}" \
      MISAKA_INITIAL_WAIT_ATTEMPTS="${MISAKA_INITIAL_WAIT_ATTEMPTS:-140}" \
      MISAKA_RESTART_WAIT_ATTEMPTS="${MISAKA_RESTART_WAIT_ATTEMPTS:-140}" \
      bash scripts/dag_natural_restart_harness.sh
fi

if [ "${MISAKA_RUN_THREE_VALIDATOR_RESTART:-0}" = "1" ]; then
  run_step "running 3-validator durable restart harness" "three_validator_restart_harness" \
    run_harness_step env \
      MISAKA_SKIP_BUILD=1 \
      MISAKA_BIN=target/release/misaka-node \
      MISAKA_DAG_CHECKPOINT_INTERVAL="${MISAKA_THREE_VALIDATOR_CHECKPOINT_INTERVAL:-12}" \
      MISAKA_INITIAL_WAIT_ATTEMPTS="${MISAKA_INITIAL_WAIT_ATTEMPTS:-140}" \
      MISAKA_RESTART_WAIT_ATTEMPTS="${MISAKA_RESTART_WAIT_ATTEMPTS:-140}" \
      bash scripts/dag_three_validator_recovery_harness.sh
fi

if [ "${MISAKA_RUN_SHIELDED_VK_MANIFEST:-0}" = "1" ]; then
  shielded_vk_manifest_dir="${MISAKA_SHIELDED_VK_MANIFEST_DIR:-$run_root/shielded-vk-manifest}"
  shielded_vk_manifest_dir_for_step="$shielded_vk_manifest_dir"
  if ! has_native_c_toolchain; then
    require_repo_portable_path "shielded VK manifest dir" "$shielded_vk_manifest_dir"
    shielded_vk_manifest_dir_for_step="$(path_within_repo "$shielded_vk_manifest_dir")"
  fi
  run_step "building shielded VK/operator manifest" "shielded_vk_manifest" \
    run_cargo_step env \
      MISAKA_SHIELDED_VK_MANIFEST_DIR="${shielded_vk_manifest_dir_for_step}" \
      MISAKA_SHIELDED_INCLUDE_BOUNDED_SHA3="${MISAKA_SHIELDED_INCLUDE_BOUNDED_SHA3:-1}" \
      MISAKA_SHIELDED_INCLUDE_BOUNDED_GROTH16="${MISAKA_SHIELDED_INCLUDE_BOUNDED_GROTH16:-0}" \
      MISAKA_SHIELDED_INCLUDE_BOUNDED_PLONK="${MISAKA_SHIELDED_INCLUDE_BOUNDED_PLONK:-0}" \
      MISAKA_SHIELDED_INCLUDE_BOUNDED_PLONK_THREE_VALIDATOR="${MISAKA_SHIELDED_INCLUDE_BOUNDED_PLONK_THREE_VALIDATOR:-0}" \
      MISAKA_SHIELDED_INCLUDE_BOUNDED_SHA3_THREE_VALIDATOR="${MISAKA_SHIELDED_INCLUDE_BOUNDED_SHA3_THREE_VALIDATOR:-0}" \
      MISAKA_SHIELDED_INCLUDE_BOUNDED_GROTH16_THREE_VALIDATOR="${MISAKA_SHIELDED_INCLUDE_BOUNDED_GROTH16_THREE_VALIDATOR:-0}" \
      MISAKA_SHIELDED_REFRESH_BOUNDED_LIVE="${MISAKA_SHIELDED_REFRESH_BOUNDED_LIVE:-1}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_THREE_VALIDATOR="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_THREE_VALIDATOR:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_FOUR_VALIDATOR="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_FOUR_VALIDATOR:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_SIX_VALIDATOR="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_SIX_VALIDATOR:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_SEVEN_VALIDATOR="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_SEVEN_VALIDATOR:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_EIGHT_VALIDATOR="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_EIGHT_VALIDATOR:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_NINE_VALIDATOR="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_NINE_VALIDATOR:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_THREE_VALIDATOR="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_THREE_VALIDATOR:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_THREE_VALIDATOR="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_THREE_VALIDATOR:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_SIX_VALIDATOR="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_SIX_VALIDATOR:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_SIX_VALIDATOR="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_SIX_VALIDATOR:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_SEVEN_VALIDATOR="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_SEVEN_VALIDATOR:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_SEVEN_VALIDATOR="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_SEVEN_VALIDATOR:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_EIGHT_VALIDATOR="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_EIGHT_VALIDATOR:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_EIGHT_VALIDATOR="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_EIGHT_VALIDATOR:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_NINE_VALIDATOR="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_NINE_VALIDATOR:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_NINE_VALIDATOR="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_NINE_VALIDATOR:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_THREE_VALIDATOR_SEQUENCE="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_THREE_VALIDATOR_SEQUENCE:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_THREE_VALIDATOR_SEQUENCE="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_THREE_VALIDATOR_SEQUENCE:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_THREE_VALIDATOR_SEQUENCE="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_THREE_VALIDATOR_SEQUENCE:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_FOUR_VALIDATOR_SEQUENCE="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_FOUR_VALIDATOR_SEQUENCE:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_FOUR_VALIDATOR_SEQUENCE="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_FOUR_VALIDATOR_SEQUENCE:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_FOUR_VALIDATOR_SEQUENCE="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_FOUR_VALIDATOR_SEQUENCE:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_SIX_VALIDATOR_SEQUENCE="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_SIX_VALIDATOR_SEQUENCE:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_SIX_VALIDATOR_SEQUENCE="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_SIX_VALIDATOR_SEQUENCE:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_SIX_VALIDATOR_SEQUENCE="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_SIX_VALIDATOR_SEQUENCE:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_SEVEN_VALIDATOR_SEQUENCE="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_SEVEN_VALIDATOR_SEQUENCE:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_SEVEN_VALIDATOR_SEQUENCE="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_SEVEN_VALIDATOR_SEQUENCE:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_SEVEN_VALIDATOR_SEQUENCE="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_SEVEN_VALIDATOR_SEQUENCE:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_EIGHT_VALIDATOR_SEQUENCE="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_EIGHT_VALIDATOR_SEQUENCE:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_EIGHT_VALIDATOR_SEQUENCE="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_EIGHT_VALIDATOR_SEQUENCE:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_EIGHT_VALIDATOR_SEQUENCE="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_EIGHT_VALIDATOR_SEQUENCE:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_NINE_VALIDATOR_SEQUENCE="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_NINE_VALIDATOR_SEQUENCE:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_NINE_VALIDATOR_SEQUENCE="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_NINE_VALIDATOR_SEQUENCE:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_NINE_VALIDATOR_SEQUENCE="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_NINE_VALIDATOR_SEQUENCE:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_FOUR_VALIDATOR="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_FOUR_VALIDATOR:-0}" \
      MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_FOUR_VALIDATOR="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_FOUR_VALIDATOR:-0}" \
      MISAKA_SHIELDED_INCLUDE_RUNTIME_COMPARISON="${MISAKA_SHIELDED_INCLUDE_RUNTIME_COMPARISON:-0}" \
      MISAKA_SHIELDED_REFRESH_FULL_PATH="${MISAKA_SHIELDED_REFRESH_FULL_PATH:-1}" \
      MISAKA_SHIELDED_REFRESH_RUNTIME_COMPARISON="${MISAKA_SHIELDED_REFRESH_RUNTIME_COMPARISON:-0}" \
      bash scripts/shielded_vk_runbook_manifest.sh
  if ! has_native_c_toolchain; then
    shielded_vk_manifest_source="$(host_artifact_path "${MISAKA_SHIELDED_VK_MANIFEST_DIR:-$run_root/shielded-vk-manifest}/result.json")"
    shielded_vk_manifest_host_dir="$run_root/shielded-vk-manifest-host"
    shielded_vk_manifest_host_result="$shielded_vk_manifest_host_dir/result.json"
    write_normalized_json_copy "$shielded_vk_manifest_source" "$shielded_vk_manifest_host_result" "/work"
    export MISAKA_SHIELDED_VK_MANIFEST_HOST_RESULT="$shielded_vk_manifest_host_result"
  fi
  validate_shielded_vk_manifest_result \
    "${MISAKA_SHIELDED_VK_MANIFEST_HOST_RESULT:-$(host_artifact_path "${MISAKA_SHIELDED_VK_MANIFEST_DIR:-$run_root/shielded-vk-manifest}/result.json")}" \
    "${MISAKA_SHIELDED_INCLUDE_BOUNDED_SHA3:-1}" \
    "${MISAKA_SHIELDED_INCLUDE_BOUNDED_GROTH16:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_BOUNDED_PLONK:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_BOUNDED_PLONK_THREE_VALIDATOR:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_BOUNDED_SHA3_THREE_VALIDATOR:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_BOUNDED_GROTH16_THREE_VALIDATOR:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_THREE_VALIDATOR:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_FOUR_VALIDATOR:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_THREE_VALIDATOR:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_THREE_VALIDATOR:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_FOUR_VALIDATOR:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_FOUR_VALIDATOR:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_THREE_VALIDATOR_SEQUENCE:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_THREE_VALIDATOR_SEQUENCE:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_THREE_VALIDATOR_SEQUENCE:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_FOUR_VALIDATOR_SEQUENCE:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_FOUR_VALIDATOR_SEQUENCE:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_FOUR_VALIDATOR_SEQUENCE:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_RUNTIME_COMPARISON:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_SIX_VALIDATOR:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_SIX_VALIDATOR:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_SIX_VALIDATOR:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_SIX_VALIDATOR_SEQUENCE:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_SIX_VALIDATOR_SEQUENCE:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_SIX_VALIDATOR_SEQUENCE:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_SEVEN_VALIDATOR:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_SEVEN_VALIDATOR:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_SEVEN_VALIDATOR:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_SEVEN_VALIDATOR_SEQUENCE:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_SEVEN_VALIDATOR_SEQUENCE:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_SEVEN_VALIDATOR_SEQUENCE:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_EIGHT_VALIDATOR:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_EIGHT_VALIDATOR:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_EIGHT_VALIDATOR:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_EIGHT_VALIDATOR_SEQUENCE:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_EIGHT_VALIDATOR_SEQUENCE:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_EIGHT_VALIDATOR_SEQUENCE:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_NINE_VALIDATOR:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_NINE_VALIDATOR:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_NINE_VALIDATOR:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_NINE_VALIDATOR_SEQUENCE:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_NINE_VALIDATOR_SEQUENCE:-0}" \
    "${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_NINE_VALIDATOR_SEQUENCE:-0}"
fi

run_step "validating node docker compose config" "compose_config" \
  docker compose --env-file scripts/node.env.example -f docker/node-compose.yml config

run_step "building relayer release binary" "build_release_relayer" \
  run_cargo_step cargo build --manifest-path relayer/Cargo.toml --release --locked

write_summary_line "result=passed"
write_summary_line "completed_at_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
write_result_json "passed"
echo "[gate] release gate passed"
echo "[gate] artifacts: $result_file"
