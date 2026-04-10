#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
state_dir="${MISAKA_RELEASE_SUPPORT_REHEARSAL_DIR:-$repo_root/.tmp/dag-release-support-rehearsal}"
result_file="${MISAKA_RELEASE_SUPPORT_REHEARSAL_RESULT:-$state_dir/result.json}"
log_file="$state_dir/release-support.log"
release_dir="$repo_root/dist/release"
sbom_dir="$repo_root/dist/sbom"
target_dir="${MISAKA_RELEASE_SUPPORT_REHEARSAL_TARGET_DIR:-$repo_root/.tmp/dag-release-support-target}"
workflow_file="$repo_root/.github/workflows/ci.yaml"
build_script="$repo_root/scripts/build-release.sh"
verify_script="$repo_root/scripts/verify-release.sh"
release_guide="$repo_root/docs/RELEASE_SIGNING_AND_VERIFICATION.ja.md"
launch_gate_guide="$repo_root/docs/MAINNET_LAUNCH_GATE.ja.md"
security_checklist_guide="$repo_root/docs/MAINNET_SECURITY_CHECKLIST.ja.md"
build_version="${MISAKA_RELEASE_SUPPORT_REHEARSAL_VERSION:-0.0.0-testnetready}"
build_commit="${MISAKA_RELEASE_SUPPORT_REHEARSAL_COMMIT:-release-support-rehearsal}"
backup_dir=""

usage() {
  cat <<'EOF'
Usage: ./scripts/dag_release_support_rehearsal.sh

Builds a bounded unsigned release package, verifies it with the local
operator tool, and writes:

  .tmp/dag-release-support-rehearsal/result.json

Optional env:
  MISAKA_RELEASE_SUPPORT_REHEARSAL_DIR=/custom/output/dir
  MISAKA_RELEASE_SUPPORT_REHEARSAL_RESULT=/custom/result.json
  MISAKA_RELEASE_SUPPORT_REHEARSAL_TARGET_DIR=/custom/target
  MISAKA_RELEASE_SUPPORT_REHEARSAL_VERSION=0.1.0-rc1
  MISAKA_RELEASE_SUPPORT_REHEARSAL_COMMIT=<git-or-snapshot-id>
  BINDGEN_EXTRA_CLANG_ARGS=...
  CC=...
  CXX=...
EOF
}

write_result() {
  local status="$1"
  local reason="${2:-}"
  python3 - "$result_file" "$status" "$reason" "$release_dir" "$sbom_dir" "$workflow_file" "$build_script" "$verify_script" "$release_guide" "$launch_gate_guide" "$security_checklist_guide" "$build_version" "$build_commit" <<'PY'
import json
import pathlib
import sys

(result_file, status, reason, release_dir, sbom_dir, workflow_file, build_script,
 verify_script, release_guide, launch_gate_guide, security_checklist_guide,
 build_version, build_commit) = sys.argv[1:14]

release_dir_path = pathlib.Path(release_dir)
sbom_dir_path = pathlib.Path(sbom_dir)
workflow_path = pathlib.Path(workflow_file)
build_script_path = pathlib.Path(build_script)
verify_script_path = pathlib.Path(verify_script)
release_guide_path = pathlib.Path(release_guide)
launch_gate_guide_path = pathlib.Path(launch_gate_guide)
security_checklist_guide_path = pathlib.Path(security_checklist_guide)
result_path = pathlib.Path(result_file)

payload = {
    "status": status,
    "flow": "release_support_build_and_verify",
    "reason": reason or None,
    "buildVersion": build_version,
    "buildCommit": build_commit,
    "releaseDir": str(release_dir_path),
    "sbomDir": str(sbom_dir_path) if sbom_dir_path.exists() else None,
    "workflowPath": str(workflow_path),
    "buildScriptPath": str(build_script_path),
    "verifyScriptPath": str(verify_script_path),
    "releaseGuidePath": str(release_guide_path),
    "mainnetLaunchGateGuidePath": str(launch_gate_guide_path),
    "mainnetSecurityChecklistGuidePath": str(security_checklist_guide_path),
}
result_path.parent.mkdir(parents=True, exist_ok=True)
result_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
PY
}

write_failure() {
  local reason="$1"
  write_result "failed" "$reason"
}

restore_dist_dirs() {
  rm -rf "$release_dir" "$sbom_dir"
  if [[ -n "$backup_dir" ]]; then
    if [[ -d "$backup_dir/release" ]]; then
      mkdir -p "$(dirname "$release_dir")"
      mv "$backup_dir/release" "$release_dir"
    fi
    if [[ -d "$backup_dir/sbom" ]]; then
      mkdir -p "$(dirname "$sbom_dir")"
      mv "$backup_dir/sbom" "$sbom_dir"
    fi
    rm -rf "$backup_dir"
  fi
}

trap restore_dist_dirs EXIT

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
mkdir -p "$target_dir"
rm -f "$result_file"
: >"$log_file"

for required in "$workflow_file" "$build_script" "$verify_script" "$release_guide" "$launch_gate_guide" "$security_checklist_guide"; do
  if [[ ! -f "$required" ]]; then
    write_failure "required support file is missing: $required"
    exit 1
  fi
done

if ! command -v cargo >/dev/null 2>&1; then
  write_failure "cargo command is not available"
  exit 1
fi

if [[ -z "${BINDGEN_EXTRA_CLANG_ARGS:-}" ]] && command -v gcc >/dev/null 2>&1; then
  export BINDGEN_EXTRA_CLANG_ARGS="-I$(gcc -print-file-name=include)"
fi
export CC="${CC:-gcc}"
export CXX="${CXX:-g++}"

backup_dir="$(mktemp -d "${state_dir}/dist-backup.XXXXXX")"
if [[ -d "$release_dir" ]]; then
  mv "$release_dir" "$backup_dir/release"
fi
if [[ -d "$sbom_dir" ]]; then
  mv "$sbom_dir" "$backup_dir/sbom"
fi
mkdir -p "$repo_root/dist"

(
  cd "$repo_root"
  export MISAKA_BUILD_VERSION="$build_version"
  export MISAKA_BUILD_COMMIT="$build_commit"
  export CARGO_TARGET_DIR="$target_dir"
  bash "$build_script"
  bash "$verify_script" "$release_dir"
) >"$log_file" 2>&1 || {
  write_failure "release support rehearsal build/verify failed"
  cat "$log_file" >&2
  exit 1
}

python3 - "$result_file" "$release_dir" "$sbom_dir" "$workflow_file" "$build_script" "$verify_script" "$release_guide" "$launch_gate_guide" "$security_checklist_guide" "$build_version" "$build_commit" <<'PY'
import json
import pathlib
import sys

(result_file, release_dir, sbom_dir, workflow_file, build_script, verify_script,
 release_guide, launch_gate_guide, security_checklist_guide,
 build_version, build_commit) = sys.argv[1:12]

result_path = pathlib.Path(result_file)
release_dir_path = pathlib.Path(release_dir)
sbom_dir_path = pathlib.Path(sbom_dir)
workflow_path = pathlib.Path(workflow_file)
build_script_path = pathlib.Path(build_script)
verify_script_path = pathlib.Path(verify_script)
release_guide_path = pathlib.Path(release_guide)
launch_gate_guide_path = pathlib.Path(launch_gate_guide)
security_checklist_guide_path = pathlib.Path(security_checklist_guide)

manifest_path = release_dir_path / "BUILD_MANIFEST.json"
checksums_path = release_dir_path / "SHA256SUMS"
binary_path = release_dir_path / "misaka-node"

workflow_text = workflow_path.read_text(encoding="utf-8")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
signature_status = manifest.get("signature", {}).get("status")
sbom_status = manifest.get("sbom", {}).get("status")

payload = {
    "status": "passed",
    "flow": "release_support_build_and_verify",
    "buildVersion": build_version,
    "buildCommit": build_commit,
    "releaseDir": str(release_dir_path),
    "sbomDir": str(sbom_dir_path) if sbom_dir_path.exists() else None,
    "workflowPath": str(workflow_path),
    "buildScriptPath": str(build_script_path),
    "verifyScriptPath": str(verify_script_path),
    "releaseGuidePath": str(release_guide_path),
    "mainnetLaunchGateGuidePath": str(launch_gate_guide_path),
    "mainnetSecurityChecklistGuidePath": str(security_checklist_guide_path),
    "artifacts": {
        "manifestPath": str(manifest_path),
        "checksumsPath": str(checksums_path),
        "binaryPath": str(binary_path),
    },
    "ci": {
        "workflowPresent": workflow_path.exists(),
        "releaseVerifyJobPresent": "release-verify:" in workflow_text,
        "buildReleaseReferenced": "bash scripts/build-release.sh" in workflow_text,
        "verifyReleaseReferenced": "bash scripts/verify-release.sh dist/release" in workflow_text,
        "manifestCheckReferenced": (
            "dist/release/BUILD_MANIFEST.json" in workflow_text
            or "bash scripts/verify-release.sh dist/release" in workflow_text
        ),
    },
    "docs": {
        "releaseVerificationGuidePresent": release_guide_path.exists(),
        "mainnetLaunchGateGuidePresent": launch_gate_guide_path.exists(),
        "mainnetSecurityChecklistGuidePresent": security_checklist_guide_path.exists(),
    },
    "manifest": {
        "schemaVersion": manifest.get("schema_version"),
        "version": manifest.get("version"),
        "gitCommit": manifest.get("git_commit"),
        "chainTarget": manifest.get("chain_target"),
        "signatureStatus": signature_status,
        "sbomStatus": sbom_status,
    },
}

consistency = {
    "manifestPresent": manifest_path.exists(),
    "checksumsPresent": checksums_path.exists(),
    "binaryPresent": binary_path.exists(),
    "manifestVersionMatchesInput": manifest.get("version") == build_version,
    "manifestCommitMatchesInput": manifest.get("git_commit") == build_commit,
    "verifyScriptPassed": True,
    "checksumVerified": True,
    "signatureStatusAcceptable": signature_status in {"unsigned", "minisign"},
    "ciWorkflowReady": all(
        payload["ci"][key]
        for key in (
            "workflowPresent",
            "releaseVerifyJobPresent",
            "buildReleaseReferenced",
            "verifyReleaseReferenced",
            "manifestCheckReferenced",
        )
    ),
    "docsReady": all(
        payload["docs"][key] is True
        for key in (
            "releaseVerificationGuidePresent",
            "mainnetLaunchGateGuidePresent",
            "mainnetSecurityChecklistGuidePresent",
        )
    ),
}
consistency["releaseSupportReady"] = all(consistency.values())
payload["consistency"] = consistency

errors = [key for key, value in consistency.items() if value is not True]
if errors:
    payload["status"] = "failed"
    payload["errors"] = errors

result_path.parent.mkdir(parents=True, exist_ok=True)
result_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
if errors:
    raise SystemExit(1)
PY

echo "release support rehearsal passed"
echo "  $result_file"
