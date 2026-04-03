#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

state_dir="${MISAKA_SHIELDED_VK_MANIFEST_DIR:-$repo_root/.tmp/shielded-vk-runbook-manifest}"
result_file="$state_dir/result.json"

inventory_script="$repo_root/scripts/shielded_backend_inventory.sh"
benchmark_script="$repo_root/scripts/shielded_backend_benchmark.sh"
inspect_script="$repo_root/scripts/shielded_vk_artifact_inspect.sh"
snapshot_script="$repo_root/scripts/shielded_module_status_snapshot.sh"
bounded_sha3_script="$repo_root/scripts/shielded_live_bounded_e2e.sh"
bounded_groth16_script="$repo_root/scripts/shielded_live_bounded_e2e_groth16.sh"
bounded_plonk_script="$repo_root/scripts/shielded_live_bounded_e2e_plonk.sh"
full_path_sha3_script="$repo_root/scripts/shielded_live_full_path_e2e.sh"
full_path_groth16_script="$repo_root/scripts/shielded_live_full_path_e2e_groth16.sh"
full_path_plonk_script="$repo_root/scripts/shielded_live_full_path_e2e_plonk.sh"
runtime_comparison_script="$repo_root/scripts/shielded_runtime_comparison.sh"

inventory_result="${MISAKA_BACKEND_INVENTORY_RESULT:-$repo_root/.tmp/shielded-backend-inventory/result.json}"
inventory_dir_override=""
if [[ -n "${MISAKA_BACKEND_INVENTORY_RESULT:-}" ]]; then
  inventory_dir_override="$(dirname "$inventory_result")"
fi

benchmark_result="${MISAKA_SHIELDED_BENCHMARK_RESULT:-$repo_root/.tmp/shielded-backend-benchmark/result.json}"
benchmark_dir_override=""
if [[ -n "${MISAKA_SHIELDED_BENCHMARK_RESULT:-}" ]]; then
  benchmark_dir_override="$(dirname "$benchmark_result")"
fi
refresh_benchmark="${MISAKA_SHIELDED_REFRESH_BENCHMARK:-0}"

vk_inspect_result="${MISAKA_SHIELDED_VK_INSPECT_RESULT:-$repo_root/.tmp/shielded-vk-artifact-inspect/result.json}"
snapshot_result="${MISAKA_SHIELDED_STATUS_RESULT:-$repo_root/.tmp/shielded-module-status-snapshot/result.json}"
bounded_sha3_result="${MISAKA_SHIELDED_LIVE_BOUNDED_E2E_RESULT:-$repo_root/.tmp/shielded-live-bounded-e2e/result.json}"
bounded_groth16_result="${MISAKA_SHIELDED_LIVE_GROTH16_E2E_RESULT:-$repo_root/.tmp/shielded-live-bounded-e2e-groth16/result.json}"
bounded_plonk_result="${MISAKA_SHIELDED_BOUNDED_PLONK_E2E_RESULT:-$repo_root/.tmp/shielded-live-bounded-e2e-plonk/result.json}"
bounded_plonk_three_validator_result="${MISAKA_SHIELDED_BOUNDED_PLONK_THREE_VALIDATOR_RESULT:-$repo_root/.tmp/shielded-live-bounded-e2e-plonk-3v/result.json}"
bounded_sha3_three_validator_result="${MISAKA_SHIELDED_LIVE_BOUNDED_E2E_THREE_VALIDATOR_RESULT:-$repo_root/.tmp/shielded-live-bounded-e2e-3v/result.json}"
bounded_groth16_three_validator_result="${MISAKA_SHIELDED_LIVE_GROTH16_E2E_THREE_VALIDATOR_RESULT:-$repo_root/.tmp/shielded-live-bounded-e2e-groth16-3v/result.json}"
full_path_sha3_result="${MISAKA_SHIELDED_FULL_PATH_E2E_RESULT:-$repo_root/.tmp/shielded-full-path-e2e/result.json}"
full_path_groth16_result="${MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-groth16/result.json}"
full_path_plonk_result="${MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-plonk/result.json}"
full_path_plonk_three_validator_result="${MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_THREE_VALIDATOR_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-plonk-3v/result.json}"
full_path_plonk_four_validator_result="${MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_FOUR_VALIDATOR_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-plonk-4v/result.json}"
full_path_plonk_six_validator_result="${MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_SIX_VALIDATOR_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-plonk-6v/result.json}"
full_path_sha3_three_validator_result="${MISAKA_SHIELDED_FULL_PATH_E2E_THREE_VALIDATOR_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-3v/result.json}"
full_path_groth16_three_validator_result="${MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_THREE_VALIDATOR_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-groth16-3v/result.json}"
full_path_sha3_four_validator_result="${MISAKA_SHIELDED_FULL_PATH_E2E_FOUR_VALIDATOR_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-4v/result.json}"
full_path_groth16_four_validator_result="${MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_FOUR_VALIDATOR_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-groth16-4v/result.json}"
full_path_sha3_six_validator_result="${MISAKA_SHIELDED_FULL_PATH_E2E_SIX_VALIDATOR_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-6v/result.json}"
full_path_groth16_six_validator_result="${MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_SIX_VALIDATOR_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-groth16-6v/result.json}"
full_path_sha3_three_validator_sequence_result="${MISAKA_SHIELDED_FULL_PATH_E2E_THREE_VALIDATOR_SEQUENCE_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-3v-seq/result.json}"
full_path_groth16_three_validator_sequence_result="${MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_THREE_VALIDATOR_SEQUENCE_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-groth16-3v-seq/result.json}"
full_path_plonk_three_validator_sequence_result="${MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_THREE_VALIDATOR_SEQUENCE_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-plonk-3v-seq/result.json}"
full_path_sha3_four_validator_sequence_result="${MISAKA_SHIELDED_FULL_PATH_E2E_FOUR_VALIDATOR_SEQUENCE_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-4v-seq/result.json}"
full_path_groth16_four_validator_sequence_result="${MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_FOUR_VALIDATOR_SEQUENCE_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-groth16-4v-seq/result.json}"
full_path_plonk_four_validator_sequence_result="${MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_FOUR_VALIDATOR_SEQUENCE_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-plonk-4v-seq/result.json}"
full_path_sha3_six_validator_sequence_result="${MISAKA_SHIELDED_FULL_PATH_E2E_SIX_VALIDATOR_SEQUENCE_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-6v-seq/result.json}"
full_path_groth16_six_validator_sequence_result="${MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_SIX_VALIDATOR_SEQUENCE_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-groth16-6v-seq/result.json}"
full_path_plonk_six_validator_sequence_result="${MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_SIX_VALIDATOR_SEQUENCE_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-plonk-6v-seq/result.json}"
runtime_comparison_result="${MISAKA_SHIELDED_RUNTIME_COMPARISON_RESULT:-$repo_root/.tmp/shielded-runtime-comparison/result.json}"

authoritative_target="${MISAKA_SHIELDED_AUTHORITATIVE_TARGET:-}"
groth16_policy="${MISAKA_SHIELDED_GROTH16_VK_POLICY:-}"
plonk_policy="${MISAKA_SHIELDED_PLONK_VK_POLICY:-}"
groth16_path="${MISAKA_SHIELDED_GROTH16_VK_PATH:-}"
plonk_path="${MISAKA_SHIELDED_PLONK_VK_PATH:-}"
real_backend_bootstrap="${MISAKA_SHIELDED_REAL_BACKEND_BOOTSTRAP:-0}"
include_live_snapshot="${MISAKA_SHIELDED_INCLUDE_LIVE_SNAPSHOT:-0}"
include_bounded_sha3="${MISAKA_SHIELDED_INCLUDE_BOUNDED_SHA3:-0}"
include_bounded_groth16="${MISAKA_SHIELDED_INCLUDE_BOUNDED_GROTH16:-0}"
include_bounded_plonk="${MISAKA_SHIELDED_INCLUDE_BOUNDED_PLONK:-0}"
include_bounded_plonk_three_validator="${MISAKA_SHIELDED_INCLUDE_BOUNDED_PLONK_THREE_VALIDATOR:-0}"
include_bounded_sha3_three_validator="${MISAKA_SHIELDED_INCLUDE_BOUNDED_SHA3_THREE_VALIDATOR:-0}"
include_bounded_groth16_three_validator="${MISAKA_SHIELDED_INCLUDE_BOUNDED_GROTH16_THREE_VALIDATOR:-0}"
include_full_path_sha3="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3:-0}"
include_full_path_groth16="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16:-0}"
include_full_path_plonk="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK:-0}"
include_full_path_plonk_three_validator="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_THREE_VALIDATOR:-0}"
include_full_path_plonk_four_validator="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_FOUR_VALIDATOR:-0}"
include_full_path_plonk_six_validator="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_SIX_VALIDATOR:-0}"
include_full_path_sha3_three_validator="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_THREE_VALIDATOR:-0}"
include_full_path_groth16_three_validator="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_THREE_VALIDATOR:-0}"
include_full_path_sha3_six_validator="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_SIX_VALIDATOR:-0}"
include_full_path_groth16_six_validator="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_SIX_VALIDATOR:-0}"
include_full_path_sha3_three_validator_sequence="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_THREE_VALIDATOR_SEQUENCE:-0}"
include_full_path_groth16_three_validator_sequence="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_THREE_VALIDATOR_SEQUENCE:-0}"
include_full_path_plonk_three_validator_sequence="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_THREE_VALIDATOR_SEQUENCE:-0}"
include_full_path_sha3_four_validator_sequence="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_FOUR_VALIDATOR_SEQUENCE:-0}"
include_full_path_groth16_four_validator_sequence="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_FOUR_VALIDATOR_SEQUENCE:-0}"
include_full_path_plonk_four_validator_sequence="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_FOUR_VALIDATOR_SEQUENCE:-0}"
include_full_path_sha3_six_validator_sequence="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_SIX_VALIDATOR_SEQUENCE:-0}"
include_full_path_groth16_six_validator_sequence="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_SIX_VALIDATOR_SEQUENCE:-0}"
include_full_path_plonk_six_validator_sequence="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_SIX_VALIDATOR_SEQUENCE:-0}"
include_full_path_sha3_four_validator="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_FOUR_VALIDATOR:-0}"
include_full_path_groth16_four_validator="${MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_FOUR_VALIDATOR:-0}"
include_runtime_comparison="${MISAKA_SHIELDED_INCLUDE_RUNTIME_COMPARISON:-0}"
refresh_bounded_live="${MISAKA_SHIELDED_REFRESH_BOUNDED_LIVE:-0}"
refresh_full_path="${MISAKA_SHIELDED_REFRESH_FULL_PATH:-0}"
refresh_runtime_comparison="${MISAKA_SHIELDED_REFRESH_RUNTIME_COMPARISON:-0}"
node_base="${MISAKA_NODE_RPC_BASE:-http://127.0.0.1:8080}"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'EOF'
Usage: ./scripts/shielded_vk_runbook_manifest.sh

Builds a single operator-facing manifest for the current shielded VK contract by
combining:

  - shielded backend inventory
  - current SHA3 benchmark baseline
  - VK artifact preflight (when explicit paths are configured)
  - effective authoritative target / VK policy resolution
  - optional live module_status snapshot
  - optional live bounded E2E artifacts (SHA3 / Groth16-first)

Output:
  .tmp/shielded-vk-runbook-manifest/result.json

Optional env:
  MISAKA_SHIELDED_VK_MANIFEST_DIR      Override output directory
  MISAKA_BACKEND_INVENTORY_RESULT      Override inventory result path
  MISAKA_SHIELDED_BENCHMARK_RESULT     Override benchmark result path
  MISAKA_SHIELDED_REFRESH_BENCHMARK=1  Force benchmark artifact refresh
  MISAKA_SHIELDED_VK_INSPECT_RESULT    Override VK inspect result path
  MISAKA_SHIELDED_STATUS_RESULT        Override live snapshot result path
  MISAKA_SHIELDED_AUTHORITATIVE_TARGET groth16|plonk|groth16_or_plonk
  MISAKA_SHIELDED_GROTH16_VK_POLICY    disabled|observe|require
  MISAKA_SHIELDED_PLONK_VK_POLICY      disabled|observe|require
  MISAKA_SHIELDED_GROTH16_VK_PATH      Optional Groth16 VK artifact path
  MISAKA_SHIELDED_PLONK_VK_PATH        Optional PLONK VK artifact path
  MISAKA_SHIELDED_REAL_BACKEND_BOOTSTRAP=1
                                       Explicit real backend registration gate
  MISAKA_SHIELDED_INCLUDE_LIVE_SNAPSHOT=1
                                       Also fetch /api/shielded/module_status
  MISAKA_SHIELDED_INCLUDE_BOUNDED_SHA3=1
                                       Include current SHA3 live bounded E2E artifact
  MISAKA_SHIELDED_INCLUDE_BOUNDED_GROTH16=1
                                       Include Groth16-first live bounded E2E artifact
  MISAKA_SHIELDED_INCLUDE_BOUNDED_PLONK=1
                                       Include PLONK-first live bounded E2E artifact
  MISAKA_SHIELDED_INCLUDE_BOUNDED_PLONK_THREE_VALIDATOR=1
                                       Include 3-validator PLONK live bounded E2E artifact
  MISAKA_SHIELDED_INCLUDE_BOUNDED_SHA3_THREE_VALIDATOR=1
                                       Include 3-validator SHA3 live bounded E2E artifact
  MISAKA_SHIELDED_INCLUDE_BOUNDED_GROTH16_THREE_VALIDATOR=1
                                       Include 3-validator Groth16-first live bounded E2E artifact
  MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3=1
                                       Include the full-path restart continuity SHA3 artifact
  MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16=1
                                       Include the Groth16-first full-path restart continuity artifact
  MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK=1
                                       Include the PLONK-first full-path restart continuity artifact
  MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_THREE_VALIDATOR=1
                                       Include the 3-validator PLONK-first full-path restart continuity artifact
  MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_FOUR_VALIDATOR=1
                                       Include the 4-validator PLONK-first full-path restart continuity artifact
  MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_SIX_VALIDATOR=1
                                       Include the 6-validator PLONK-first full-path restart continuity artifact
  MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_THREE_VALIDATOR=1
                                       Include the 3-validator SHA3 full-path restart continuity artifact
  MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_THREE_VALIDATOR=1
                                       Include the 3-validator Groth16-first full-path restart continuity artifact
  MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_SIX_VALIDATOR=1
                                       Include the 6-validator SHA3 full-path restart continuity artifact
  MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_SIX_VALIDATOR=1
                                       Include the 6-validator Groth16-first full-path restart continuity artifact
  MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_THREE_VALIDATOR_SEQUENCE=1
                                       Include the 3-validator SHA3 sequence-depth full-path artifact
  MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_THREE_VALIDATOR_SEQUENCE=1
                                       Include the 3-validator Groth16-first sequence-depth full-path artifact
  MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_THREE_VALIDATOR_SEQUENCE=1
                                       Include the 3-validator PLONK-first sequence-depth full-path artifact
  MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_FOUR_VALIDATOR_SEQUENCE=1
                                       Include the 4-validator SHA3 sequence-depth full-path artifact
  MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_FOUR_VALIDATOR_SEQUENCE=1
                                       Include the 4-validator Groth16-first sequence-depth full-path artifact
  MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_FOUR_VALIDATOR_SEQUENCE=1
                                       Include the 4-validator PLONK-first sequence-depth full-path artifact
  MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_SIX_VALIDATOR_SEQUENCE=1
                                       Include the 6-validator SHA3 sequence-depth full-path artifact
  MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_SIX_VALIDATOR_SEQUENCE=1
                                       Include the 6-validator Groth16-first sequence-depth full-path artifact
  MISAKA_SHIELDED_INCLUDE_FULL_PATH_PLONK_SIX_VALIDATOR_SEQUENCE=1
                                       Include the 6-validator PLONK-first sequence-depth full-path artifact
  MISAKA_SHIELDED_INCLUDE_FULL_PATH_SHA3_FOUR_VALIDATOR=1
                                       Include the 4-validator SHA3 full-path restart continuity artifact
  MISAKA_SHIELDED_INCLUDE_FULL_PATH_GROTH16_FOUR_VALIDATOR=1
                                       Include the 4-validator Groth16-first full-path restart continuity artifact
  MISAKA_SHIELDED_INCLUDE_RUNTIME_COMPARISON=1
                                       Include the comparative runtime artifact
  MISAKA_SHIELDED_REFRESH_BOUNDED_LIVE=1
                                       Rerun included bounded live scripts before reading artifacts
  MISAKA_SHIELDED_REFRESH_FULL_PATH=1   Rerun the included full-path restart continuity script before reading artifacts
  MISAKA_SHIELDED_REFRESH_RUNTIME_COMPARISON=1
                                       Rerun the comparative runtime artifact before reading it
  MISAKA_NODE_RPC_BASE                 Node base URL for live snapshot
EOF
  exit 0
fi

mkdir -p "$state_dir"

inventory_rc=0
if [[ -n "$inventory_dir_override" ]]; then
  MISAKA_SHIELDED_INVENTORY_DIR="$inventory_dir_override" bash "$inventory_script" >/dev/null || inventory_rc=$?
else
  bash "$inventory_script" >/dev/null || inventory_rc=$?
fi

benchmark_rc=0
if [[ "$refresh_benchmark" == "1" || ! -f "$benchmark_result" ]]; then
  if [[ -n "$benchmark_dir_override" ]]; then
    MISAKA_SHIELDED_BENCHMARK_DIR="$benchmark_dir_override" bash "$benchmark_script" >/dev/null || benchmark_rc=$?
  else
    bash "$benchmark_script" >/dev/null || benchmark_rc=$?
  fi
fi

inspect_requested=0
inspect_rc=0
if [[ -n "$groth16_path" || -n "$plonk_path" ]]; then
  inspect_requested=1
  MISAKA_SHIELDED_VK_INSPECT_DIR="$(dirname "$vk_inspect_result")" \
  MISAKA_SHIELDED_GROTH16_VK_PATH="$groth16_path" \
  MISAKA_SHIELDED_PLONK_VK_PATH="$plonk_path" \
  bash "$inspect_script" >/dev/null || inspect_rc=$?
fi

snapshot_requested=0
snapshot_rc=0
if [[ "$include_live_snapshot" == "1" ]]; then
  snapshot_requested=1
  MISAKA_SHIELDED_STATUS_DIR="$(dirname "$snapshot_result")" \
  MISAKA_SHIELDED_VK_INSPECT_RESULT="$vk_inspect_result" \
  MISAKA_BACKEND_INVENTORY_RESULT="$inventory_result" \
  MISAKA_NODE_RPC_BASE="$node_base" \
  MISAKA_SHIELDED_GROTH16_VK_PATH="$groth16_path" \
  MISAKA_SHIELDED_PLONK_VK_PATH="$plonk_path" \
  bash "$snapshot_script" >/dev/null || snapshot_rc=$?
fi

bounded_sha3_requested=0
bounded_sha3_rc=0
if [[ "$include_bounded_sha3" == "1" ]]; then
  bounded_sha3_requested=1
  if [[ "$refresh_bounded_live" == "1" || ! -f "$bounded_sha3_result" ]]; then
    bash "$bounded_sha3_script" >/dev/null || bounded_sha3_rc=$?
  fi
fi

bounded_groth16_requested=0
bounded_groth16_rc=0
if [[ "$include_bounded_groth16" == "1" ]]; then
  bounded_groth16_requested=1
  if [[ "$refresh_bounded_live" == "1" || ! -f "$bounded_groth16_result" ]]; then
    bash "$bounded_groth16_script" >/dev/null || bounded_groth16_rc=$?
  fi
fi

bounded_plonk_requested=0
bounded_plonk_rc=0
if [[ "$include_bounded_plonk" == "1" ]]; then
  bounded_plonk_requested=1
  if [[ "$refresh_bounded_live" == "1" || ! -f "$bounded_plonk_result" ]]; then
    MISAKA_SHIELDED_BOUNDED_PLONK_E2E_DIR="$(dirname "$bounded_plonk_result")" \
    MISAKA_SHIELDED_BOUNDED_PLONK_E2E_RESULT="$bounded_plonk_result" \
    bash "$bounded_plonk_script" >/dev/null || bounded_plonk_rc=$?
  fi
fi

bounded_plonk_three_validator_requested=0
bounded_plonk_three_validator_rc=0
if [[ "$include_bounded_plonk_three_validator" == "1" ]]; then
  bounded_plonk_three_validator_requested=1
  if [[ "$refresh_bounded_live" == "1" || ! -f "$bounded_plonk_three_validator_result" ]]; then
    MISAKA_SHIELDED_BOUNDED_PLONK_E2E_DIR="$(dirname "$bounded_plonk_three_validator_result")" \
    MISAKA_SHIELDED_BOUNDED_PLONK_E2E_RESULT="$bounded_plonk_three_validator_result" \
    bash "$bounded_plonk_script" --three-validator >/dev/null || bounded_plonk_three_validator_rc=$?
  fi
fi

bounded_sha3_three_validator_requested=0
bounded_sha3_three_validator_rc=0
if [[ "$include_bounded_sha3_three_validator" == "1" ]]; then
  bounded_sha3_three_validator_requested=1
  if [[ "$refresh_bounded_live" == "1" || ! -f "$bounded_sha3_three_validator_result" ]]; then
    MISAKA_SHIELDED_LIVE_BOUNDED_E2E_DIR="$(dirname "$bounded_sha3_three_validator_result")" \
    MISAKA_SHIELDED_LIVE_BOUNDED_E2E_RESULT="$bounded_sha3_three_validator_result" \
    bash "$bounded_sha3_script" --three-validator >/dev/null || bounded_sha3_three_validator_rc=$?
  fi
fi

bounded_groth16_three_validator_requested=0
bounded_groth16_three_validator_rc=0
if [[ "$include_bounded_groth16_three_validator" == "1" ]]; then
  bounded_groth16_three_validator_requested=1
  if [[ "$refresh_bounded_live" == "1" || ! -f "$bounded_groth16_three_validator_result" ]]; then
    MISAKA_SHIELDED_LIVE_GROTH16_E2E_DIR="$(dirname "$bounded_groth16_three_validator_result")" \
    MISAKA_SHIELDED_LIVE_GROTH16_E2E_RESULT="$bounded_groth16_three_validator_result" \
    bash "$bounded_groth16_script" --three-validator >/dev/null || bounded_groth16_three_validator_rc=$?
  fi
fi

full_path_sha3_requested=0
full_path_sha3_rc=0
if [[ "$include_full_path_sha3" == "1" ]]; then
  full_path_sha3_requested=1
  if [[ "$refresh_full_path" == "1" || ! -f "$full_path_sha3_result" ]]; then
    bash "$full_path_sha3_script" >/dev/null || full_path_sha3_rc=$?
  fi
fi

full_path_groth16_requested=0
full_path_groth16_rc=0
if [[ "$include_full_path_groth16" == "1" ]]; then
  full_path_groth16_requested=1
  if [[ "$refresh_full_path" == "1" || ! -f "$full_path_groth16_result" ]]; then
    MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_DIR="$(dirname "$full_path_groth16_result")" \
    MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_RESULT="$full_path_groth16_result" \
    bash "$full_path_groth16_script" --groth16-first >/dev/null || full_path_groth16_rc=$?
  fi
fi

full_path_plonk_requested=0
full_path_plonk_rc=0
if [[ "$include_full_path_plonk" == "1" ]]; then
  full_path_plonk_requested=1
  if [[ "$refresh_full_path" == "1" || ! -f "$full_path_plonk_result" ]]; then
    MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_DIR="$(dirname "$full_path_plonk_result")" \
    MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_RESULT="$full_path_plonk_result" \
    bash "$full_path_plonk_script" >/dev/null || full_path_plonk_rc=$?
  fi
fi

full_path_plonk_three_validator_requested=0
full_path_plonk_three_validator_rc=0
if [[ "$include_full_path_plonk_three_validator" == "1" ]]; then
  full_path_plonk_three_validator_requested=1
  if [[ "$refresh_full_path" == "1" || ! -f "$full_path_plonk_three_validator_result" ]]; then
    MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_DIR="$(dirname "$full_path_plonk_three_validator_result")" \
    MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_RESULT="$full_path_plonk_three_validator_result" \
    bash "$full_path_plonk_script" --three-validator >/dev/null || full_path_plonk_three_validator_rc=$?
  fi
fi

full_path_plonk_four_validator_requested=0
full_path_plonk_four_validator_rc=0
if [[ "$include_full_path_plonk_four_validator" == "1" ]]; then
  full_path_plonk_four_validator_requested=1
  if [[ "$refresh_full_path" == "1" || ! -f "$full_path_plonk_four_validator_result" ]]; then
    MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_DIR="$(dirname "$full_path_plonk_four_validator_result")" \
    MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_RESULT="$full_path_plonk_four_validator_result" \
    bash "$full_path_plonk_script" --four-validator >/dev/null || full_path_plonk_four_validator_rc=$?
  fi
fi

full_path_plonk_six_validator_requested=0
full_path_plonk_six_validator_rc=0
if [[ "$include_full_path_plonk_six_validator" == "1" ]]; then
  full_path_plonk_six_validator_requested=1
  if [[ "$refresh_full_path" == "1" || ! -f "$full_path_plonk_six_validator_result" ]]; then
    MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_DIR="$(dirname "$full_path_plonk_six_validator_result")" \
    MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_RESULT="$full_path_plonk_six_validator_result" \
    bash "$full_path_plonk_script" --six-validator >/dev/null || full_path_plonk_six_validator_rc=$?
  fi
fi

full_path_sha3_three_validator_requested=0
full_path_sha3_three_validator_rc=0
if [[ "$include_full_path_sha3_three_validator" == "1" ]]; then
  full_path_sha3_three_validator_requested=1
  if [[ "$refresh_full_path" == "1" || ! -f "$full_path_sha3_three_validator_result" ]]; then
    MISAKA_SHIELDED_FULL_PATH_E2E_DIR="$(dirname "$full_path_sha3_three_validator_result")" \
    MISAKA_SHIELDED_FULL_PATH_E2E_RESULT="$full_path_sha3_three_validator_result" \
    bash "$full_path_sha3_script" --three-validator >/dev/null || full_path_sha3_three_validator_rc=$?
  fi
fi

full_path_groth16_three_validator_requested=0
full_path_groth16_three_validator_rc=0
if [[ "$include_full_path_groth16_three_validator" == "1" ]]; then
  full_path_groth16_three_validator_requested=1
  if [[ "$refresh_full_path" == "1" || ! -f "$full_path_groth16_three_validator_result" ]]; then
    MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_DIR="$(dirname "$full_path_groth16_three_validator_result")" \
    MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_RESULT="$full_path_groth16_three_validator_result" \
    bash "$full_path_groth16_script" --three-validator >/dev/null || full_path_groth16_three_validator_rc=$?
  fi
fi

full_path_sha3_six_validator_requested=0
full_path_sha3_six_validator_rc=0
if [[ "$include_full_path_sha3_six_validator" == "1" ]]; then
  full_path_sha3_six_validator_requested=1
  if [[ "$refresh_full_path" == "1" || ! -f "$full_path_sha3_six_validator_result" ]]; then
    MISAKA_SHIELDED_FULL_PATH_E2E_DIR="$(dirname "$full_path_sha3_six_validator_result")" \
    MISAKA_SHIELDED_FULL_PATH_E2E_RESULT="$full_path_sha3_six_validator_result" \
    bash "$full_path_sha3_script" --six-validator >/dev/null || full_path_sha3_six_validator_rc=$?
  fi
fi

full_path_groth16_six_validator_requested=0
full_path_groth16_six_validator_rc=0
if [[ "$include_full_path_groth16_six_validator" == "1" ]]; then
  full_path_groth16_six_validator_requested=1
  if [[ "$refresh_full_path" == "1" || ! -f "$full_path_groth16_six_validator_result" ]]; then
    MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_DIR="$(dirname "$full_path_groth16_six_validator_result")" \
    MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_RESULT="$full_path_groth16_six_validator_result" \
    bash "$full_path_groth16_script" --six-validator >/dev/null || full_path_groth16_six_validator_rc=$?
  fi
fi

full_path_sha3_three_validator_sequence_requested=0
full_path_sha3_three_validator_sequence_rc=0
if [[ "$include_full_path_sha3_three_validator_sequence" == "1" ]]; then
  full_path_sha3_three_validator_sequence_requested=1
  if [[ "$refresh_full_path" == "1" || ! -f "$full_path_sha3_three_validator_sequence_result" ]]; then
    MISAKA_SHIELDED_FULL_PATH_E2E_DIR="$(dirname "$full_path_sha3_three_validator_sequence_result")" \
    MISAKA_SHIELDED_FULL_PATH_E2E_RESULT="$full_path_sha3_three_validator_sequence_result" \
    bash "$full_path_sha3_script" --three-validator-sequence >/dev/null || full_path_sha3_three_validator_sequence_rc=$?
  fi
fi

full_path_groth16_three_validator_sequence_requested=0
full_path_groth16_three_validator_sequence_rc=0
if [[ "$include_full_path_groth16_three_validator_sequence" == "1" ]]; then
  full_path_groth16_three_validator_sequence_requested=1
  if [[ "$refresh_full_path" == "1" || ! -f "$full_path_groth16_three_validator_sequence_result" ]]; then
    MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_DIR="$(dirname "$full_path_groth16_three_validator_sequence_result")" \
    MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_RESULT="$full_path_groth16_three_validator_sequence_result" \
    bash "$full_path_groth16_script" --three-validator-sequence >/dev/null || full_path_groth16_three_validator_sequence_rc=$?
  fi
fi

full_path_plonk_three_validator_sequence_requested=0
full_path_plonk_three_validator_sequence_rc=0
if [[ "$include_full_path_plonk_three_validator_sequence" == "1" ]]; then
  full_path_plonk_three_validator_sequence_requested=1
  if [[ "$refresh_full_path" == "1" || ! -f "$full_path_plonk_three_validator_sequence_result" ]]; then
    MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_DIR="$(dirname "$full_path_plonk_three_validator_sequence_result")" \
    MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_RESULT="$full_path_plonk_three_validator_sequence_result" \
    bash "$full_path_plonk_script" --three-validator-sequence >/dev/null || full_path_plonk_three_validator_sequence_rc=$?
  fi
fi

full_path_sha3_four_validator_requested=0
full_path_sha3_four_validator_rc=0
if [[ "$include_full_path_sha3_four_validator" == "1" ]]; then
  full_path_sha3_four_validator_requested=1
  if [[ "$refresh_full_path" == "1" || ! -f "$full_path_sha3_four_validator_result" ]]; then
    MISAKA_SHIELDED_FULL_PATH_E2E_DIR="$(dirname "$full_path_sha3_four_validator_result")" \
    MISAKA_SHIELDED_FULL_PATH_E2E_RESULT="$full_path_sha3_four_validator_result" \
    bash "$full_path_sha3_script" --four-validator >/dev/null || full_path_sha3_four_validator_rc=$?
  fi
fi

full_path_sha3_four_validator_sequence_requested=0
full_path_sha3_four_validator_sequence_rc=0
if [[ "$include_full_path_sha3_four_validator_sequence" == "1" ]]; then
  full_path_sha3_four_validator_sequence_requested=1
  if [[ "$refresh_full_path" == "1" || ! -f "$full_path_sha3_four_validator_sequence_result" ]]; then
    MISAKA_SHIELDED_FULL_PATH_E2E_DIR="$(dirname "$full_path_sha3_four_validator_sequence_result")" \
    MISAKA_SHIELDED_FULL_PATH_E2E_RESULT="$full_path_sha3_four_validator_sequence_result" \
    bash "$full_path_sha3_script" --four-validator-sequence >/dev/null || full_path_sha3_four_validator_sequence_rc=$?
  fi
fi

full_path_groth16_four_validator_sequence_requested=0
full_path_groth16_four_validator_sequence_rc=0
if [[ "$include_full_path_groth16_four_validator_sequence" == "1" ]]; then
  full_path_groth16_four_validator_sequence_requested=1
  if [[ "$refresh_full_path" == "1" || ! -f "$full_path_groth16_four_validator_sequence_result" ]]; then
    MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_DIR="$(dirname "$full_path_groth16_four_validator_sequence_result")" \
    MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_RESULT="$full_path_groth16_four_validator_sequence_result" \
    bash "$full_path_groth16_script" --four-validator-sequence >/dev/null || full_path_groth16_four_validator_sequence_rc=$?
  fi
fi

full_path_plonk_four_validator_sequence_requested=0
full_path_plonk_four_validator_sequence_rc=0
if [[ "$include_full_path_plonk_four_validator_sequence" == "1" ]]; then
  full_path_plonk_four_validator_sequence_requested=1
  if [[ "$refresh_full_path" == "1" || ! -f "$full_path_plonk_four_validator_sequence_result" ]]; then
    MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_DIR="$(dirname "$full_path_plonk_four_validator_sequence_result")" \
    MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_RESULT="$full_path_plonk_four_validator_sequence_result" \
    bash "$full_path_plonk_script" --four-validator-sequence >/dev/null || full_path_plonk_four_validator_sequence_rc=$?
  fi
fi

full_path_sha3_six_validator_sequence_requested=0
full_path_sha3_six_validator_sequence_rc=0
if [[ "$include_full_path_sha3_six_validator_sequence" == "1" ]]; then
  full_path_sha3_six_validator_sequence_requested=1
  if [[ "$refresh_full_path" == "1" || ! -f "$full_path_sha3_six_validator_sequence_result" ]]; then
    MISAKA_SHIELDED_FULL_PATH_E2E_DIR="$(dirname "$full_path_sha3_six_validator_sequence_result")" \
    MISAKA_SHIELDED_FULL_PATH_E2E_RESULT="$full_path_sha3_six_validator_sequence_result" \
    bash "$full_path_sha3_script" --six-validator-sequence >/dev/null || full_path_sha3_six_validator_sequence_rc=$?
  fi
fi

full_path_groth16_six_validator_sequence_requested=0
full_path_groth16_six_validator_sequence_rc=0
if [[ "$include_full_path_groth16_six_validator_sequence" == "1" ]]; then
  full_path_groth16_six_validator_sequence_requested=1
  if [[ "$refresh_full_path" == "1" || ! -f "$full_path_groth16_six_validator_sequence_result" ]]; then
    MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_DIR="$(dirname "$full_path_groth16_six_validator_sequence_result")" \
    MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_RESULT="$full_path_groth16_six_validator_sequence_result" \
    bash "$full_path_groth16_script" --six-validator-sequence >/dev/null || full_path_groth16_six_validator_sequence_rc=$?
  fi
fi

full_path_plonk_six_validator_sequence_requested=0
full_path_plonk_six_validator_sequence_rc=0
if [[ "$include_full_path_plonk_six_validator_sequence" == "1" ]]; then
  full_path_plonk_six_validator_sequence_requested=1
  if [[ "$refresh_full_path" == "1" || ! -f "$full_path_plonk_six_validator_sequence_result" ]]; then
    MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_DIR="$(dirname "$full_path_plonk_six_validator_sequence_result")" \
    MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_RESULT="$full_path_plonk_six_validator_sequence_result" \
    bash "$full_path_plonk_script" --six-validator-sequence >/dev/null || full_path_plonk_six_validator_sequence_rc=$?
  fi
fi

full_path_groth16_four_validator_requested=0
full_path_groth16_four_validator_rc=0
if [[ "$include_full_path_groth16_four_validator" == "1" ]]; then
  full_path_groth16_four_validator_requested=1
  if [[ "$refresh_full_path" == "1" || ! -f "$full_path_groth16_four_validator_result" ]]; then
    MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_DIR="$(dirname "$full_path_groth16_four_validator_result")" \
    MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_RESULT="$full_path_groth16_four_validator_result" \
    bash "$full_path_groth16_script" --four-validator >/dev/null || full_path_groth16_four_validator_rc=$?
  fi
fi

runtime_comparison_requested=0
runtime_comparison_rc=0
if [[ "$include_runtime_comparison" == "1" ]]; then
  runtime_comparison_requested=1
  comparison_refresh_inputs=0
  if [[ "$refresh_runtime_comparison" == "1" || "$refresh_benchmark" == "1" || "$refresh_bounded_live" == "1" || "$refresh_full_path" == "1" ]]; then
    comparison_refresh_inputs=1
  fi
  if [[ "$comparison_refresh_inputs" == "1" || ! -f "$runtime_comparison_result" ]]; then
    MISAKA_SHIELDED_RUNTIME_COMPARISON_DIR="$(dirname "$runtime_comparison_result")" \
    MISAKA_SHIELDED_RUNTIME_COMPARISON_RESULT="$runtime_comparison_result" \
    MISAKA_SHIELDED_REFRESH_COMPARISON_INPUTS="$comparison_refresh_inputs" \
    bash "$runtime_comparison_script" >/dev/null || runtime_comparison_rc=$?
  fi
fi

export MISAKA_MANIFEST_FULL_PATH_PLONK_SIX_VALIDATOR_RESULT="$full_path_plonk_six_validator_result"
export MISAKA_MANIFEST_FULL_PATH_SHA3_SIX_VALIDATOR_RESULT="$full_path_sha3_six_validator_result"
export MISAKA_MANIFEST_FULL_PATH_GROTH16_SIX_VALIDATOR_RESULT="$full_path_groth16_six_validator_result"
export MISAKA_MANIFEST_FULL_PATH_SHA3_SIX_VALIDATOR_SEQUENCE_RESULT="$full_path_sha3_six_validator_sequence_result"
export MISAKA_MANIFEST_FULL_PATH_GROTH16_SIX_VALIDATOR_SEQUENCE_RESULT="$full_path_groth16_six_validator_sequence_result"
export MISAKA_MANIFEST_FULL_PATH_PLONK_SIX_VALIDATOR_SEQUENCE_RESULT="$full_path_plonk_six_validator_sequence_result"
export MISAKA_MANIFEST_INCLUDE_FULL_PATH_PLONK_SIX_VALIDATOR="$include_full_path_plonk_six_validator"
export MISAKA_MANIFEST_INCLUDE_FULL_PATH_SHA3_SIX_VALIDATOR="$include_full_path_sha3_six_validator"
export MISAKA_MANIFEST_INCLUDE_FULL_PATH_GROTH16_SIX_VALIDATOR="$include_full_path_groth16_six_validator"
export MISAKA_MANIFEST_INCLUDE_FULL_PATH_SHA3_SIX_VALIDATOR_SEQUENCE="$include_full_path_sha3_six_validator_sequence"
export MISAKA_MANIFEST_INCLUDE_FULL_PATH_GROTH16_SIX_VALIDATOR_SEQUENCE="$include_full_path_groth16_six_validator_sequence"
export MISAKA_MANIFEST_INCLUDE_FULL_PATH_PLONK_SIX_VALIDATOR_SEQUENCE="$include_full_path_plonk_six_validator_sequence"
export MISAKA_MANIFEST_FULL_PATH_PLONK_SIX_VALIDATOR_REQUESTED="$full_path_plonk_six_validator_requested"
export MISAKA_MANIFEST_FULL_PATH_SHA3_SIX_VALIDATOR_REQUESTED="$full_path_sha3_six_validator_requested"
export MISAKA_MANIFEST_FULL_PATH_GROTH16_SIX_VALIDATOR_REQUESTED="$full_path_groth16_six_validator_requested"
export MISAKA_MANIFEST_FULL_PATH_SHA3_SIX_VALIDATOR_SEQUENCE_REQUESTED="$full_path_sha3_six_validator_sequence_requested"
export MISAKA_MANIFEST_FULL_PATH_GROTH16_SIX_VALIDATOR_SEQUENCE_REQUESTED="$full_path_groth16_six_validator_sequence_requested"
export MISAKA_MANIFEST_FULL_PATH_PLONK_SIX_VALIDATOR_SEQUENCE_REQUESTED="$full_path_plonk_six_validator_sequence_requested"
export MISAKA_MANIFEST_FULL_PATH_PLONK_SIX_VALIDATOR_RC="$full_path_plonk_six_validator_rc"
export MISAKA_MANIFEST_FULL_PATH_SHA3_SIX_VALIDATOR_RC="$full_path_sha3_six_validator_rc"
export MISAKA_MANIFEST_FULL_PATH_GROTH16_SIX_VALIDATOR_RC="$full_path_groth16_six_validator_rc"
export MISAKA_MANIFEST_FULL_PATH_SHA3_SIX_VALIDATOR_SEQUENCE_RC="$full_path_sha3_six_validator_sequence_rc"
export MISAKA_MANIFEST_FULL_PATH_GROTH16_SIX_VALIDATOR_SEQUENCE_RC="$full_path_groth16_six_validator_sequence_rc"
export MISAKA_MANIFEST_FULL_PATH_PLONK_SIX_VALIDATOR_SEQUENCE_RC="$full_path_plonk_six_validator_sequence_rc"

python3 - \
  "$result_file" \
  "$inventory_result" \
  "$benchmark_result" \
  "$vk_inspect_result" \
  "$snapshot_result" \
  "$bounded_sha3_result" \
  "$bounded_groth16_result" \
  "$bounded_plonk_result" \
  "$bounded_sha3_three_validator_result" \
  "$bounded_groth16_three_validator_result" \
  "$full_path_sha3_result" \
  "$full_path_groth16_result" \
  "$full_path_plonk_result" \
  "$full_path_sha3_three_validator_result" \
  "$full_path_groth16_three_validator_result" \
  "$full_path_sha3_four_validator_result" \
  "$full_path_groth16_four_validator_result" \
  "$authoritative_target" \
  "$groth16_policy" \
  "$plonk_policy" \
  "$groth16_path" \
  "$plonk_path" \
  "$real_backend_bootstrap" \
  "$include_live_snapshot" \
  "$include_bounded_sha3" \
  "$include_bounded_groth16" \
  "$include_bounded_plonk" \
  "$include_bounded_sha3_three_validator" \
  "$include_bounded_groth16_three_validator" \
  "$include_full_path_sha3" \
  "$include_full_path_groth16" \
  "$include_full_path_plonk" \
  "$include_full_path_sha3_three_validator" \
  "$include_full_path_groth16_three_validator" \
  "$include_full_path_sha3_four_validator" \
  "$include_full_path_groth16_four_validator" \
  "$refresh_bounded_live" \
  "$refresh_full_path" \
  "$node_base" \
  "$inventory_rc" \
  "$benchmark_rc" \
  "$inspect_requested" \
  "$inspect_rc" \
  "$snapshot_requested" \
  "$snapshot_rc" \
  "$bounded_sha3_requested" \
  "$bounded_sha3_rc" \
  "$bounded_groth16_requested" \
  "$bounded_groth16_rc" \
  "$bounded_plonk_requested" \
  "$bounded_plonk_rc" \
  "$bounded_sha3_three_validator_requested" \
  "$bounded_sha3_three_validator_rc" \
  "$bounded_groth16_three_validator_requested" \
  "$bounded_groth16_three_validator_rc" \
  "$full_path_sha3_requested" \
  "$full_path_sha3_rc" \
  "$full_path_groth16_requested" \
  "$full_path_groth16_rc" \
  "$full_path_plonk_requested" \
  "$full_path_plonk_rc" \
  "$full_path_sha3_three_validator_requested" \
  "$full_path_sha3_three_validator_rc" \
  "$full_path_groth16_three_validator_requested" \
  "$full_path_groth16_three_validator_rc" \
  "$full_path_sha3_four_validator_requested" \
  "$full_path_sha3_four_validator_rc" \
  "$full_path_groth16_four_validator_requested" \
  "$full_path_groth16_four_validator_rc" \
  "$bounded_plonk_three_validator_requested" \
  "$bounded_plonk_three_validator_rc" \
  "$full_path_plonk_three_validator_requested" \
  "$full_path_plonk_three_validator_rc" \
  "$full_path_plonk_four_validator_requested" \
  "$full_path_plonk_four_validator_rc" \
  "$include_bounded_plonk_three_validator" \
  "$include_full_path_plonk_three_validator" \
  "$include_full_path_plonk_four_validator" \
  "$bounded_plonk_three_validator_result" \
  "$full_path_plonk_three_validator_result" \
  "$full_path_plonk_four_validator_result" \
  "$full_path_sha3_three_validator_sequence_result" \
  "$full_path_groth16_three_validator_sequence_result" \
  "$full_path_plonk_three_validator_sequence_result" \
  "$full_path_sha3_four_validator_sequence_result" \
  "$full_path_groth16_four_validator_sequence_result" \
  "$full_path_plonk_four_validator_sequence_result" \
  "$include_full_path_sha3_three_validator_sequence" \
  "$include_full_path_groth16_three_validator_sequence" \
  "$include_full_path_plonk_three_validator_sequence" \
  "$include_full_path_sha3_four_validator_sequence" \
  "$include_full_path_groth16_four_validator_sequence" \
  "$include_full_path_plonk_four_validator_sequence" \
  "$full_path_sha3_three_validator_sequence_requested" \
  "$full_path_sha3_three_validator_sequence_rc" \
  "$full_path_groth16_three_validator_sequence_requested" \
  "$full_path_groth16_three_validator_sequence_rc" \
  "$full_path_plonk_three_validator_sequence_requested" \
  "$full_path_plonk_three_validator_sequence_rc" \
  "$full_path_sha3_four_validator_sequence_requested" \
  "$full_path_sha3_four_validator_sequence_rc" \
  "$full_path_groth16_four_validator_sequence_requested" \
  "$full_path_groth16_four_validator_sequence_rc" \
  "$full_path_plonk_four_validator_sequence_requested" \
  "$full_path_plonk_four_validator_sequence_rc" \
  "$runtime_comparison_result" \
  "$include_runtime_comparison" \
  "$runtime_comparison_requested" \
  "$runtime_comparison_rc" <<'PY'
import json
import os
import pathlib
import sys

result_file = pathlib.Path(sys.argv[1])
inventory_path = pathlib.Path(sys.argv[2])
benchmark_path = pathlib.Path(sys.argv[3])
vk_inspect_path = pathlib.Path(sys.argv[4])
snapshot_path = pathlib.Path(sys.argv[5])
bounded_sha3_path = pathlib.Path(sys.argv[6])
bounded_groth16_path = pathlib.Path(sys.argv[7])
bounded_plonk_path = pathlib.Path(sys.argv[8])
bounded_sha3_three_validator_path = pathlib.Path(sys.argv[9])
bounded_groth16_three_validator_path = pathlib.Path(sys.argv[10])
full_path_sha3_path = pathlib.Path(sys.argv[11])
full_path_groth16_path = pathlib.Path(sys.argv[12])
full_path_plonk_path = pathlib.Path(sys.argv[13])
full_path_sha3_three_validator_path = pathlib.Path(sys.argv[14])
full_path_groth16_three_validator_path = pathlib.Path(sys.argv[15])
full_path_sha3_four_validator_path = pathlib.Path(sys.argv[16])
full_path_groth16_four_validator_path = pathlib.Path(sys.argv[17])
authoritative_target_raw = sys.argv[18]
groth16_policy_raw = sys.argv[19]
plonk_policy_raw = sys.argv[20]
groth16_path = sys.argv[21]
plonk_path = sys.argv[22]
real_backend_bootstrap = sys.argv[23] in ("1", "true", "TRUE", "yes", "YES", "on", "ON")
include_live_snapshot = sys.argv[24] == "1"
include_bounded_sha3 = sys.argv[25] == "1"
include_bounded_groth16 = sys.argv[26] == "1"
include_bounded_plonk = sys.argv[27] == "1"
include_bounded_sha3_three_validator = sys.argv[28] == "1"
include_bounded_groth16_three_validator = sys.argv[29] == "1"
include_full_path_sha3 = sys.argv[30] == "1"
include_full_path_groth16 = sys.argv[31] == "1"
include_full_path_plonk = sys.argv[32] == "1"
include_full_path_sha3_three_validator = sys.argv[33] == "1"
include_full_path_groth16_three_validator = sys.argv[34] == "1"
include_full_path_sha3_four_validator = sys.argv[35] == "1"
include_full_path_groth16_four_validator = sys.argv[36] == "1"
refresh_bounded_live = sys.argv[37] == "1"
refresh_full_path = sys.argv[38] == "1"
node_base = sys.argv[39]
inventory_rc = int(sys.argv[40])
benchmark_rc = int(sys.argv[41])
inspect_requested = sys.argv[42] == "1"
inspect_rc = int(sys.argv[43])
snapshot_requested = sys.argv[44] == "1"
snapshot_rc = int(sys.argv[45])
bounded_sha3_requested = sys.argv[46] == "1"
bounded_sha3_rc = int(sys.argv[47])
bounded_groth16_requested = sys.argv[48] == "1"
bounded_groth16_rc = int(sys.argv[49])
bounded_plonk_requested = sys.argv[50] == "1"
bounded_plonk_rc = int(sys.argv[51])
bounded_sha3_three_validator_requested = sys.argv[52] == "1"
bounded_sha3_three_validator_rc = int(sys.argv[53])
bounded_groth16_three_validator_requested = sys.argv[54] == "1"
bounded_groth16_three_validator_rc = int(sys.argv[55])
full_path_sha3_requested = sys.argv[56] == "1"
full_path_sha3_rc = int(sys.argv[57])
full_path_groth16_requested = sys.argv[58] == "1"
full_path_groth16_rc = int(sys.argv[59])
full_path_plonk_requested = sys.argv[60] == "1"
full_path_plonk_rc = int(sys.argv[61])
full_path_sha3_three_validator_requested = sys.argv[62] == "1"
full_path_sha3_three_validator_rc = int(sys.argv[63])
full_path_groth16_three_validator_requested = sys.argv[64] == "1"
full_path_groth16_three_validator_rc = int(sys.argv[65])
full_path_sha3_four_validator_requested = sys.argv[66] == "1"
full_path_sha3_four_validator_rc = int(sys.argv[67])
full_path_groth16_four_validator_requested = sys.argv[68] == "1"
full_path_groth16_four_validator_rc = int(sys.argv[69])
bounded_plonk_three_validator_requested = sys.argv[70] == "1"
bounded_plonk_three_validator_rc = int(sys.argv[71])
full_path_plonk_three_validator_requested = sys.argv[72] == "1"
full_path_plonk_three_validator_rc = int(sys.argv[73])
full_path_plonk_four_validator_requested = sys.argv[74] == "1"
full_path_plonk_four_validator_rc = int(sys.argv[75])
include_bounded_plonk_three_validator = sys.argv[76] == "1"
include_full_path_plonk_three_validator = sys.argv[77] == "1"
include_full_path_plonk_four_validator = sys.argv[78] == "1"
bounded_plonk_three_validator_path = pathlib.Path(sys.argv[79])
full_path_plonk_three_validator_path = pathlib.Path(sys.argv[80])
full_path_plonk_four_validator_path = pathlib.Path(sys.argv[81])
full_path_sha3_three_validator_sequence_path = pathlib.Path(sys.argv[82])
full_path_groth16_three_validator_sequence_path = pathlib.Path(sys.argv[83])
full_path_plonk_three_validator_sequence_path = pathlib.Path(sys.argv[84])
full_path_sha3_four_validator_sequence_path = pathlib.Path(sys.argv[85])
full_path_groth16_four_validator_sequence_path = pathlib.Path(sys.argv[86])
full_path_plonk_four_validator_sequence_path = pathlib.Path(sys.argv[87])
include_full_path_sha3_three_validator_sequence = sys.argv[88] == "1"
include_full_path_groth16_three_validator_sequence = sys.argv[89] == "1"
include_full_path_plonk_three_validator_sequence = sys.argv[90] == "1"
include_full_path_sha3_four_validator_sequence = sys.argv[91] == "1"
include_full_path_groth16_four_validator_sequence = sys.argv[92] == "1"
include_full_path_plonk_four_validator_sequence = sys.argv[93] == "1"
full_path_sha3_three_validator_sequence_requested = sys.argv[94] == "1"
full_path_sha3_three_validator_sequence_rc = int(sys.argv[95])
full_path_groth16_three_validator_sequence_requested = sys.argv[96] == "1"
full_path_groth16_three_validator_sequence_rc = int(sys.argv[97])
full_path_plonk_three_validator_sequence_requested = sys.argv[98] == "1"
full_path_plonk_three_validator_sequence_rc = int(sys.argv[99])
full_path_sha3_four_validator_sequence_requested = sys.argv[100] == "1"
full_path_sha3_four_validator_sequence_rc = int(sys.argv[101])
full_path_groth16_four_validator_sequence_requested = sys.argv[102] == "1"
full_path_groth16_four_validator_sequence_rc = int(sys.argv[103])
full_path_plonk_four_validator_sequence_requested = sys.argv[104] == "1"
full_path_plonk_four_validator_sequence_rc = int(sys.argv[105])
runtime_comparison_path = pathlib.Path(sys.argv[106])
include_runtime_comparison = sys.argv[107] == "1"
runtime_comparison_requested = sys.argv[108] == "1"
runtime_comparison_rc = int(sys.argv[109])


def env_bool(name: str) -> bool:
    return os.environ.get(name, "0") == "1"


def env_int(name: str) -> int:
    return int(os.environ.get(name, "0"))


full_path_plonk_six_validator_path = pathlib.Path(
    os.environ["MISAKA_MANIFEST_FULL_PATH_PLONK_SIX_VALIDATOR_RESULT"]
)
full_path_sha3_six_validator_path = pathlib.Path(
    os.environ["MISAKA_MANIFEST_FULL_PATH_SHA3_SIX_VALIDATOR_RESULT"]
)
full_path_groth16_six_validator_path = pathlib.Path(
    os.environ["MISAKA_MANIFEST_FULL_PATH_GROTH16_SIX_VALIDATOR_RESULT"]
)
full_path_sha3_six_validator_sequence_path = pathlib.Path(
    os.environ["MISAKA_MANIFEST_FULL_PATH_SHA3_SIX_VALIDATOR_SEQUENCE_RESULT"]
)
full_path_groth16_six_validator_sequence_path = pathlib.Path(
    os.environ["MISAKA_MANIFEST_FULL_PATH_GROTH16_SIX_VALIDATOR_SEQUENCE_RESULT"]
)
full_path_plonk_six_validator_sequence_path = pathlib.Path(
    os.environ["MISAKA_MANIFEST_FULL_PATH_PLONK_SIX_VALIDATOR_SEQUENCE_RESULT"]
)
include_full_path_plonk_six_validator = env_bool(
    "MISAKA_MANIFEST_INCLUDE_FULL_PATH_PLONK_SIX_VALIDATOR"
)
include_full_path_sha3_six_validator = env_bool(
    "MISAKA_MANIFEST_INCLUDE_FULL_PATH_SHA3_SIX_VALIDATOR"
)
include_full_path_groth16_six_validator = env_bool(
    "MISAKA_MANIFEST_INCLUDE_FULL_PATH_GROTH16_SIX_VALIDATOR"
)
include_full_path_sha3_six_validator_sequence = env_bool(
    "MISAKA_MANIFEST_INCLUDE_FULL_PATH_SHA3_SIX_VALIDATOR_SEQUENCE"
)
include_full_path_groth16_six_validator_sequence = env_bool(
    "MISAKA_MANIFEST_INCLUDE_FULL_PATH_GROTH16_SIX_VALIDATOR_SEQUENCE"
)
include_full_path_plonk_six_validator_sequence = env_bool(
    "MISAKA_MANIFEST_INCLUDE_FULL_PATH_PLONK_SIX_VALIDATOR_SEQUENCE"
)
full_path_plonk_six_validator_requested = env_bool(
    "MISAKA_MANIFEST_FULL_PATH_PLONK_SIX_VALIDATOR_REQUESTED"
)
full_path_sha3_six_validator_requested = env_bool(
    "MISAKA_MANIFEST_FULL_PATH_SHA3_SIX_VALIDATOR_REQUESTED"
)
full_path_groth16_six_validator_requested = env_bool(
    "MISAKA_MANIFEST_FULL_PATH_GROTH16_SIX_VALIDATOR_REQUESTED"
)
full_path_sha3_six_validator_sequence_requested = env_bool(
    "MISAKA_MANIFEST_FULL_PATH_SHA3_SIX_VALIDATOR_SEQUENCE_REQUESTED"
)
full_path_groth16_six_validator_sequence_requested = env_bool(
    "MISAKA_MANIFEST_FULL_PATH_GROTH16_SIX_VALIDATOR_SEQUENCE_REQUESTED"
)
full_path_plonk_six_validator_sequence_requested = env_bool(
    "MISAKA_MANIFEST_FULL_PATH_PLONK_SIX_VALIDATOR_SEQUENCE_REQUESTED"
)
full_path_plonk_six_validator_rc = env_int(
    "MISAKA_MANIFEST_FULL_PATH_PLONK_SIX_VALIDATOR_RC"
)
full_path_sha3_six_validator_rc = env_int(
    "MISAKA_MANIFEST_FULL_PATH_SHA3_SIX_VALIDATOR_RC"
)
full_path_groth16_six_validator_rc = env_int(
    "MISAKA_MANIFEST_FULL_PATH_GROTH16_SIX_VALIDATOR_RC"
)
full_path_sha3_six_validator_sequence_rc = env_int(
    "MISAKA_MANIFEST_FULL_PATH_SHA3_SIX_VALIDATOR_SEQUENCE_RC"
)
full_path_groth16_six_validator_sequence_rc = env_int(
    "MISAKA_MANIFEST_FULL_PATH_GROTH16_SIX_VALIDATOR_SEQUENCE_RC"
)
full_path_plonk_six_validator_sequence_rc = env_int(
    "MISAKA_MANIFEST_FULL_PATH_PLONK_SIX_VALIDATOR_SEQUENCE_RC"
)


def read_json(path: pathlib.Path):
    if not path.exists():
        return None
    return json.loads(path.read_text())


def resolve_target(raw: str) -> str:
    if raw in ("", "groth16_or_plonk"):
        return "groth16_or_plonk"
    if raw in {"groth16", "plonk"}:
        return raw
    raise ValueError(
        f"invalid shielded authoritative target '{raw}': expected groth16|plonk|groth16_or_plonk"
    )


def resolve_policy(label: str, raw: str, path: str) -> str:
    if raw == "":
        return "require" if path else "disabled"
    if raw not in {"disabled", "observe", "require"}:
        raise ValueError(
            f"invalid {label} verifying key policy '{raw}': expected disabled|observe|require"
        )
    if raw == "disabled" and path:
        raise ValueError(
            f"{label} verifying key path is set while policy=disabled; remove the path or use observe/require"
        )
    if raw == "require" and not path:
        raise ValueError(f"{label} verifying key is required but no path was provided")
    return raw


inventory = read_json(inventory_path)
benchmark = read_json(benchmark_path)
vk_inspection = read_json(vk_inspect_path)
live_snapshot = read_json(snapshot_path) if snapshot_requested else None
bounded_sha3 = read_json(bounded_sha3_path) if bounded_sha3_requested else None
bounded_groth16 = read_json(bounded_groth16_path) if bounded_groth16_requested else None
bounded_plonk = read_json(bounded_plonk_path) if bounded_plonk_requested else None
bounded_plonk_three_validator = (
    read_json(bounded_plonk_three_validator_path)
    if bounded_plonk_three_validator_requested
    else None
)
bounded_sha3_three_validator = (
    read_json(bounded_sha3_three_validator_path)
    if bounded_sha3_three_validator_requested
    else None
)
bounded_groth16_three_validator = (
    read_json(bounded_groth16_three_validator_path)
    if bounded_groth16_three_validator_requested
    else None
)
full_path_sha3 = read_json(full_path_sha3_path) if full_path_sha3_requested else None
full_path_groth16 = (
    read_json(full_path_groth16_path) if full_path_groth16_requested else None
)
full_path_plonk = (
    read_json(full_path_plonk_path) if full_path_plonk_requested else None
)
full_path_plonk_three_validator = (
    read_json(full_path_plonk_three_validator_path)
    if full_path_plonk_three_validator_requested
    else None
)
full_path_plonk_four_validator = (
    read_json(full_path_plonk_four_validator_path)
    if full_path_plonk_four_validator_requested
    else None
)
full_path_plonk_six_validator = (
    read_json(full_path_plonk_six_validator_path)
    if full_path_plonk_six_validator_requested
    else None
)
full_path_sha3_three_validator = (
    read_json(full_path_sha3_three_validator_path)
    if full_path_sha3_three_validator_requested
    else None
)
full_path_groth16_three_validator = (
    read_json(full_path_groth16_three_validator_path)
    if full_path_groth16_three_validator_requested
    else None
)
full_path_sha3_four_validator = (
    read_json(full_path_sha3_four_validator_path)
    if full_path_sha3_four_validator_requested
    else None
)
full_path_groth16_four_validator = (
    read_json(full_path_groth16_four_validator_path)
    if full_path_groth16_four_validator_requested
    else None
)
full_path_sha3_six_validator = (
    read_json(full_path_sha3_six_validator_path)
    if full_path_sha3_six_validator_requested
    else None
)
full_path_groth16_six_validator = (
    read_json(full_path_groth16_six_validator_path)
    if full_path_groth16_six_validator_requested
    else None
)
full_path_sha3_three_validator_sequence = (
    read_json(full_path_sha3_three_validator_sequence_path)
    if full_path_sha3_three_validator_sequence_requested
    else None
)
full_path_groth16_three_validator_sequence = (
    read_json(full_path_groth16_three_validator_sequence_path)
    if full_path_groth16_three_validator_sequence_requested
    else None
)
full_path_plonk_three_validator_sequence = (
    read_json(full_path_plonk_three_validator_sequence_path)
    if full_path_plonk_three_validator_sequence_requested
    else None
)
full_path_sha3_four_validator_sequence = (
    read_json(full_path_sha3_four_validator_sequence_path)
    if full_path_sha3_four_validator_sequence_requested
    else None
)
full_path_groth16_four_validator_sequence = (
    read_json(full_path_groth16_four_validator_sequence_path)
    if full_path_groth16_four_validator_sequence_requested
    else None
)
full_path_plonk_four_validator_sequence = (
    read_json(full_path_plonk_four_validator_sequence_path)
    if full_path_plonk_four_validator_sequence_requested
    else None
)
full_path_sha3_six_validator_sequence = (
    read_json(full_path_sha3_six_validator_sequence_path)
    if full_path_sha3_six_validator_sequence_requested
    else None
)
full_path_groth16_six_validator_sequence = (
    read_json(full_path_groth16_six_validator_sequence_path)
    if full_path_groth16_six_validator_sequence_requested
    else None
)
full_path_plonk_six_validator_sequence = (
    read_json(full_path_plonk_six_validator_sequence_path)
    if full_path_plonk_six_validator_sequence_requested
    else None
)
runtime_comparison = (
    read_json(runtime_comparison_path) if runtime_comparison_requested else None
)

errors = []
try:
    target = resolve_target(authoritative_target_raw)
    groth16_policy = resolve_policy("groth16", groth16_policy_raw, groth16_path)
    plonk_policy = resolve_policy("plonk", plonk_policy_raw, plonk_path)
except ValueError as exc:
    errors.append(str(exc))
    target = None
    groth16_policy = None
    plonk_policy = None

if inventory_rc != 0 or inventory is None:
    errors.append("failed to build shielded backend inventory")

if benchmark_rc != 0 or benchmark is None:
    errors.append("failed to build shielded benchmark artifact")
if runtime_comparison_requested and (runtime_comparison_rc != 0 or runtime_comparison is None):
    errors.append("failed to build shielded runtime comparison artifact")

if inspect_requested:
    if inspect_rc != 0 or not isinstance(vk_inspection, dict) or vk_inspection.get("status") != "passed":
        errors.append("configured shielded VK artifacts failed preflight")

if snapshot_requested:
    if snapshot_rc != 0 or not isinstance(live_snapshot, dict) or live_snapshot.get("status") != "passed":
        errors.append("failed to build live shielded snapshot artifact")

if bounded_sha3_requested:
    if bounded_sha3_rc != 0 or not isinstance(bounded_sha3, dict) or bounded_sha3.get("status") != "passed":
        errors.append("failed to build live SHA3 bounded E2E artifact")

if bounded_groth16_requested:
    if bounded_groth16_rc != 0 or not isinstance(bounded_groth16, dict) or bounded_groth16.get("status") != "passed":
        errors.append("failed to build live Groth16 bounded E2E artifact")

if bounded_plonk_requested:
    if bounded_plonk_rc != 0 or not isinstance(bounded_plonk, dict) or bounded_plonk.get("status") != "passed":
        errors.append("failed to build live PLONK bounded E2E artifact")

if bounded_plonk_three_validator_requested:
    if bounded_plonk_three_validator_rc != 0 or not isinstance(bounded_plonk_three_validator, dict) or bounded_plonk_three_validator.get("status") != "passed":
        errors.append("failed to build live PLONK 3-validator bounded E2E artifact")

if bounded_sha3_three_validator_requested:
    if bounded_sha3_three_validator_rc != 0 or not isinstance(bounded_sha3_three_validator, dict) or bounded_sha3_three_validator.get("status") != "passed":
        errors.append("failed to build live SHA3 3-validator bounded E2E artifact")

if bounded_groth16_three_validator_requested:
    if bounded_groth16_three_validator_rc != 0 or not isinstance(bounded_groth16_three_validator, dict) or bounded_groth16_three_validator.get("status") != "passed":
        errors.append("failed to build live Groth16 3-validator bounded E2E artifact")

if full_path_sha3_requested:
    if full_path_sha3_rc != 0 or not isinstance(full_path_sha3, dict) or full_path_sha3.get("status") != "passed":
        errors.append("failed to build live shielded full-path restart continuity artifact")

if full_path_groth16_requested:
    if full_path_groth16_rc != 0 or not isinstance(full_path_groth16, dict) or full_path_groth16.get("status") != "passed":
        errors.append("failed to build Groth16-first full-path restart continuity artifact")

if full_path_plonk_requested:
    if full_path_plonk_rc != 0 or not isinstance(full_path_plonk, dict) or full_path_plonk.get("status") != "passed":
        errors.append("failed to build PLONK-first full-path restart continuity artifact")

if full_path_plonk_three_validator_requested:
    if full_path_plonk_three_validator_rc != 0 or not isinstance(full_path_plonk_three_validator, dict) or full_path_plonk_three_validator.get("status") != "passed":
        errors.append("failed to build 3-validator PLONK-first full-path restart continuity artifact")

if full_path_plonk_four_validator_requested:
    if full_path_plonk_four_validator_rc != 0 or not isinstance(full_path_plonk_four_validator, dict) or full_path_plonk_four_validator.get("status") != "passed":
        errors.append("failed to build 4-validator PLONK-first full-path restart continuity artifact")

if full_path_plonk_six_validator_requested:
    if full_path_plonk_six_validator_rc != 0 or not isinstance(full_path_plonk_six_validator, dict) or full_path_plonk_six_validator.get("status") != "passed":
        errors.append("failed to build 6-validator PLONK-first full-path restart continuity artifact")

if full_path_sha3_three_validator_requested:
    if full_path_sha3_three_validator_rc != 0 or not isinstance(full_path_sha3_three_validator, dict) or full_path_sha3_three_validator.get("status") != "passed":
        errors.append("failed to build 3-validator SHA3 full-path restart continuity artifact")

if full_path_groth16_three_validator_requested:
    if full_path_groth16_three_validator_rc != 0 or not isinstance(full_path_groth16_three_validator, dict) or full_path_groth16_three_validator.get("status") != "passed":
        errors.append("failed to build 3-validator Groth16-first full-path restart continuity artifact")

if full_path_sha3_four_validator_requested:
    if full_path_sha3_four_validator_rc != 0 or not isinstance(full_path_sha3_four_validator, dict) or full_path_sha3_four_validator.get("status") != "passed":
        errors.append("failed to build 4-validator SHA3 full-path restart continuity artifact")

if full_path_groth16_four_validator_requested:
    if full_path_groth16_four_validator_rc != 0 or not isinstance(full_path_groth16_four_validator, dict) or full_path_groth16_four_validator.get("status") != "passed":
        errors.append("failed to build 4-validator Groth16-first full-path restart continuity artifact")

if full_path_sha3_six_validator_requested:
    if full_path_sha3_six_validator_rc != 0 or not isinstance(full_path_sha3_six_validator, dict) or full_path_sha3_six_validator.get("status") != "passed":
        errors.append("failed to build 6-validator SHA3 full-path restart continuity artifact")

if full_path_groth16_six_validator_requested:
    if full_path_groth16_six_validator_rc != 0 or not isinstance(full_path_groth16_six_validator, dict) or full_path_groth16_six_validator.get("status") != "passed":
        errors.append("failed to build 6-validator Groth16-first full-path restart continuity artifact")

if full_path_sha3_three_validator_sequence_requested:
    if full_path_sha3_three_validator_sequence_rc != 0 or not isinstance(full_path_sha3_three_validator_sequence, dict) or full_path_sha3_three_validator_sequence.get("status") != "passed":
        errors.append("failed to build 3-validator SHA3 sequence-depth full-path artifact")

if full_path_groth16_three_validator_sequence_requested:
    if full_path_groth16_three_validator_sequence_rc != 0 or not isinstance(full_path_groth16_three_validator_sequence, dict) or full_path_groth16_three_validator_sequence.get("status") != "passed":
        errors.append("failed to build 3-validator Groth16-first sequence-depth full-path artifact")

if full_path_plonk_three_validator_sequence_requested:
    if full_path_plonk_three_validator_sequence_rc != 0 or not isinstance(full_path_plonk_three_validator_sequence, dict) or full_path_plonk_three_validator_sequence.get("status") != "passed":
        errors.append("failed to build 3-validator PLONK-first sequence-depth full-path artifact")

if full_path_sha3_four_validator_sequence_requested:
    if full_path_sha3_four_validator_sequence_rc != 0 or not isinstance(full_path_sha3_four_validator_sequence, dict) or full_path_sha3_four_validator_sequence.get("status") != "passed":
        errors.append("failed to build 4-validator SHA3 sequence-depth full-path artifact")

if full_path_groth16_four_validator_sequence_requested:
    if full_path_groth16_four_validator_sequence_rc != 0 or not isinstance(full_path_groth16_four_validator_sequence, dict) or full_path_groth16_four_validator_sequence.get("status") != "passed":
        errors.append("failed to build 4-validator Groth16-first sequence-depth full-path artifact")

if full_path_plonk_four_validator_sequence_requested:
    if full_path_plonk_four_validator_sequence_rc != 0 or not isinstance(full_path_plonk_four_validator_sequence, dict) or full_path_plonk_four_validator_sequence.get("status") != "passed":
        errors.append("failed to build 4-validator PLONK-first sequence-depth full-path artifact")

if full_path_sha3_six_validator_sequence_requested:
    if full_path_sha3_six_validator_sequence_rc != 0 or not isinstance(full_path_sha3_six_validator_sequence, dict) or full_path_sha3_six_validator_sequence.get("status") != "passed":
        errors.append("failed to build 6-validator SHA3 sequence-depth full-path artifact")

if full_path_groth16_six_validator_sequence_requested:
    if full_path_groth16_six_validator_sequence_rc != 0 or not isinstance(full_path_groth16_six_validator_sequence, dict) or full_path_groth16_six_validator_sequence.get("status") != "passed":
        errors.append("failed to build 6-validator Groth16-first sequence-depth full-path artifact")

if full_path_plonk_six_validator_sequence_requested:
    if full_path_plonk_six_validator_sequence_rc != 0 or not isinstance(full_path_plonk_six_validator_sequence, dict) or full_path_plonk_six_validator_sequence.get("status") != "passed":
        errors.append("failed to build 6-validator PLONK-first sequence-depth full-path artifact")

inventory_summary = inventory.get("summary") if isinstance(inventory, dict) else None
benchmark_summary = benchmark.get("benchmarkSummary") if isinstance(benchmark, dict) else None
comparative_benchmark_summary = (
    benchmark.get("comparativeBenchmarkSummary") if isinstance(benchmark, dict) else None
)
benchmark_summaries = benchmark.get("benchmarkSummaries") if isinstance(benchmark, dict) else None
compiled_catalog = benchmark.get("compiledCatalog") if isinstance(benchmark, dict) else None
runtime_comparison_summary = (
    runtime_comparison.get("runtimeComparisonSummary")
    if isinstance(runtime_comparison, dict)
    else None
)
runtime_comparison_operator_summary = (
    runtime_comparison.get("operatorSummary")
    if isinstance(runtime_comparison, dict)
    else None
)
runtime_comparison_runbook = (
    runtime_comparison.get("runbookReadiness")
    if isinstance(runtime_comparison, dict)
    else None
)
verifier_contract_summary = (
    live_snapshot.get("verifierContractSummary") if isinstance(live_snapshot, dict) else None
)
authoritative_ready_inventory = (
    inventory_summary.get("authoritativeGroth16PlonkReady")
    if isinstance(inventory_summary, dict)
    else None
)

if real_backend_bootstrap and authoritative_ready_inventory is not True:
    errors.append(
        "real backend bootstrap requested but authoritative Groth16/PLONK backend is not ready"
    )

artifacts = {}
if isinstance(vk_inspection, dict) and isinstance(vk_inspection.get("artifacts"), list):
    for item in vk_inspection["artifacts"]:
        label = item.get("label")
        if label:
            artifacts[label] = item


def policy_ready(policy: str | None, path: str, label: str) -> bool | None:
    if policy is None:
        return None
    if policy == "disabled":
        return True
    if not path:
        return False
    return artifacts.get(label) is not None


target_policy_consistent = None
live_manifest_consistency_errors = []
if target is not None and groth16_policy is not None and plonk_policy is not None:
    if target == "groth16":
        target_policy_consistent = groth16_policy != "disabled"
    elif target == "plonk":
        target_policy_consistent = plonk_policy != "disabled"
    else:
        target_policy_consistent = (
            groth16_policy != "disabled" or plonk_policy != "disabled"
        )

if isinstance(verifier_contract_summary, dict) and target is not None:
    if verifier_contract_summary.get("authoritativeTarget") != target:
        live_manifest_consistency_errors.append(
            "live authoritativeTarget does not match manifest"
        )
    if verifier_contract_summary.get("groth16VkPolicy") != groth16_policy:
        live_manifest_consistency_errors.append(
            "live groth16VkPolicy does not match manifest"
        )
    if verifier_contract_summary.get("plonkVkPolicy") != plonk_policy:
        live_manifest_consistency_errors.append(
            "live plonkVkPolicy does not match manifest"
        )

    def compare_vk_runtime(label: str, artifact: dict | None):
        if not artifact:
            return
        prefix = label
        expected_schema = artifact.get("schemaVersion")
        expected_algo = artifact.get("fingerprintAlgorithm")
        expected_payload_length = artifact.get("payloadLength")
        if verifier_contract_summary.get(f"{prefix}VkArtifactSchema") != expected_schema:
            live_manifest_consistency_errors.append(
                f"live {prefix}VkArtifactSchema does not match VK artifact"
            )
        if (
            verifier_contract_summary.get(f"{prefix}VkFingerprintAlgorithm")
            != expected_algo
        ):
            live_manifest_consistency_errors.append(
                f"live {prefix}VkFingerprintAlgorithm does not match VK artifact"
            )
        if (
            verifier_contract_summary.get(f"{prefix}VkArtifactPayloadLength")
            != expected_payload_length
        ):
            live_manifest_consistency_errors.append(
                f"live {prefix}VkArtifactPayloadLength does not match VK artifact"
            )

    compare_vk_runtime("groth16", artifacts.get("groth16"))
    compare_vk_runtime("plonk", artifacts.get("plonk"))

if live_manifest_consistency_errors:
    errors.extend(live_manifest_consistency_errors)

bounded_consistency_errors = []

def expected_quorum_threshold_from_artifact(artifact: dict) -> str | None:
    quorum = artifact.get("quorum", {})
    validator_count = quorum.get("validatorCount")
    vote_count = quorum.get("voteCount")
    if isinstance(validator_count, int) and validator_count >= 4:
        return str(validator_count - 1)
    if isinstance(validator_count, int) and validator_count >= 2:
        return str(validator_count)
    if isinstance(vote_count, int) and vote_count >= 2:
        return str(vote_count - 1) if vote_count >= 4 else str(vote_count)
    return None

for label, artifact in (
    ("sha3", bounded_sha3 if isinstance(bounded_sha3, dict) else None),
    ("groth16", bounded_groth16 if isinstance(bounded_groth16, dict) else None),
    ("plonk", bounded_plonk if isinstance(bounded_plonk, dict) else None),
    ("plonkThreeValidator", bounded_plonk_three_validator if isinstance(bounded_plonk_three_validator, dict) else None),
    ("sha3ThreeValidator", bounded_sha3_three_validator if isinstance(bounded_sha3_three_validator, dict) else None),
    ("groth16ThreeValidator", bounded_groth16_three_validator if isinstance(bounded_groth16_three_validator, dict) else None),
):
    if not artifact:
        continue
    expected_vote_count = artifact.get("quorum", {}).get("voteCount")
    if artifact.get("quorum", {}).get("quorumReached") is not True:
        bounded_consistency_errors.append(f"{label} bounded artifact quorum is not reached")
    if not isinstance(expected_vote_count, int) or expected_vote_count < 2:
        bounded_consistency_errors.append(f"{label} bounded artifact vote count is malformed")
    expected_quorum_threshold = expected_quorum_threshold_from_artifact(artifact)
    if str(artifact.get("quorum", {}).get("quorumThreshold")) != str(expected_quorum_threshold):
        bounded_consistency_errors.append(f"{label} bounded artifact quorumThreshold drift")
    if artifact.get("quorum", {}).get("validatorCount") != expected_vote_count:
        bounded_consistency_errors.append(f"{label} bounded artifact validatorCount drift")
    if artifact.get("checkpointConsumer", {}).get("explorerConfirmationLevel") != "checkpointFinalized":
        bounded_consistency_errors.append(f"{label} bounded artifact checkpoint consumer is not finalized")
    committed_block_hash = artifact.get("committed", {}).get("txStatus", {}).get("blockHash")
    committed_block_blue_score = artifact.get("committed", {}).get("txStatus", {}).get("blockBlueScore")
    if artifact.get("attestation", {}).get("finalityBlockHash") != committed_block_hash:
        bounded_consistency_errors.append(f"{label} bounded artifact finality blockHash drift")
    if artifact.get("attestation", {}).get("finalityBlueScore") != committed_block_blue_score:
        bounded_consistency_errors.append(f"{label} bounded artifact finality blueScore drift")
    if artifact.get("attestation", {}).get("finalityCommitCount") != expected_vote_count:
        bounded_consistency_errors.append(f"{label} bounded artifact finality commit count drift")
    if artifact.get("attestation", {}).get("voteVoterCount") != expected_vote_count:
        bounded_consistency_errors.append(f"{label} bounded artifact vote voter count drift")
    if artifact.get("attestation", {}).get("knownValidatorCount") != expected_vote_count:
        bounded_consistency_errors.append(f"{label} bounded artifact known validator count drift")
    if artifact.get("runtimeRecovery", {}).get("lastCheckpointBlockHash") != committed_block_hash:
        bounded_consistency_errors.append(f"{label} bounded artifact runtimeRecovery blockHash drift")
    if artifact.get("runtimeRecovery", {}).get("lastCheckpointFinalityBlueScore") != committed_block_blue_score:
        bounded_consistency_errors.append(f"{label} bounded artifact runtimeRecovery finality blueScore drift")
    if artifact.get("consumerSurfaces", {}).get("chainInfo", {}).get("dataAvailability", {}).get("consumerReadiness") != "ready":
        bounded_consistency_errors.append(f"{label} bounded artifact chainInfo DA surface is not ready")
    if artifact.get("consumerSurfaces", {}).get("dagInfo", {}).get("lightClient", {}).get("txLookupKey") != "txHash":
        bounded_consistency_errors.append(f"{label} bounded artifact dagInfo lightClient txLookupKey drift")
    if artifact.get("virtualChain", {}).get("acceptedTxHash") != artifact.get("txHash"):
        bounded_consistency_errors.append(f"{label} bounded artifact virtualChain txHash drift")
    if artifact.get("incrementalVirtualChain", {}).get("virtualTip") != committed_block_hash:
        bounded_consistency_errors.append(f"{label} bounded artifact incremental virtualTip drift")
    if artifact.get("incrementalVirtualChain", {}).get("addedChainHashes") != []:
        bounded_consistency_errors.append(f"{label} bounded artifact incremental addedChainHashes not empty")
    if artifact.get("incrementalVirtualChain", {}).get("removedChainHashes") != []:
        bounded_consistency_errors.append(f"{label} bounded artifact incremental removedChainHashes not empty")
    try:
        if int(artifact.get("virtualState", {}).get("blocksApplied", 0)) < 1:
            bounded_consistency_errors.append(f"{label} bounded artifact virtualState blocksApplied < 1")
    except Exception:
        bounded_consistency_errors.append(f"{label} bounded artifact virtualState blocksApplied malformed")
    if artifact.get("virtualState", {}).get("tip") != committed_block_hash:
        bounded_consistency_errors.append(f"{label} bounded artifact virtualState tip drift")
    if artifact.get("virtualState", {}).get("tipScore") != committed_block_blue_score:
        bounded_consistency_errors.append(f"{label} bounded artifact virtualState tipScore drift")
    if artifact.get("virtualState", {}).get("reorgs") != 0:
        bounded_consistency_errors.append(f"{label} bounded artifact virtualState reorgs drift")
    if artifact.get("virtualState", {}).get("deepestReorg") != 0:
        bounded_consistency_errors.append(f"{label} bounded artifact virtualState deepestReorg drift")

if bounded_consistency_errors:
    errors.extend(bounded_consistency_errors)

full_path_consistency_errors = []
full_path_groth16_consistency_errors = []
for label, artifact in (
    ("sha3", full_path_sha3 if isinstance(full_path_sha3, dict) else None),
    ("groth16", full_path_groth16 if isinstance(full_path_groth16, dict) else None),
    ("plonk", full_path_plonk if isinstance(full_path_plonk, dict) else None),
    ("plonkThreeValidator", full_path_plonk_three_validator if isinstance(full_path_plonk_three_validator, dict) else None),
    ("plonkFourValidator", full_path_plonk_four_validator if isinstance(full_path_plonk_four_validator, dict) else None),
    ("plonkSixValidator", full_path_plonk_six_validator if isinstance(full_path_plonk_six_validator, dict) else None),
    ("sha3ThreeValidator", full_path_sha3_three_validator if isinstance(full_path_sha3_three_validator, dict) else None),
    ("groth16ThreeValidator", full_path_groth16_three_validator if isinstance(full_path_groth16_three_validator, dict) else None),
    ("sha3FourValidator", full_path_sha3_four_validator if isinstance(full_path_sha3_four_validator, dict) else None),
    ("groth16FourValidator", full_path_groth16_four_validator if isinstance(full_path_groth16_four_validator, dict) else None),
    ("sha3SixValidator", full_path_sha3_six_validator if isinstance(full_path_sha3_six_validator, dict) else None),
    ("groth16SixValidator", full_path_groth16_six_validator if isinstance(full_path_groth16_six_validator, dict) else None),
):
    if not artifact:
        continue
    label_errors = []
    post_restart = artifact.get("postRestart", {})
    committed_status = artifact.get("preRestart", {}).get("committed", {}).get("txStatus", {})
    committed_block_hash = committed_status.get("blockHash")
    committed_block_blue_score = committed_status.get("blockBlueScore")
    expected_vote_count = post_restart.get("quorum", {}).get("voteCount")
    if post_restart.get("quorum", {}).get("quorumReached") is not True:
        label_errors.append(f"{label} full-path artifact quorum is not reached")
    if not isinstance(expected_vote_count, int) or expected_vote_count < 2:
        label_errors.append(f"{label} full-path artifact vote count is malformed")
    expected_quorum_threshold = expected_quorum_threshold_from_artifact(post_restart)
    if str(post_restart.get("quorum", {}).get("quorumThreshold")) != str(expected_quorum_threshold):
        label_errors.append(f"{label} full-path artifact quorumThreshold drift")
    if post_restart.get("quorum", {}).get("validatorCount") != expected_vote_count:
        label_errors.append(f"{label} full-path artifact validatorCount drift")
    if post_restart.get("checkpointConsumer", {}).get("explorerConfirmationLevel") != "checkpointFinalized":
        label_errors.append(f"{label} full-path artifact checkpoint consumer is not finalized")
    if post_restart.get("attestation", {}).get("finalityBlockHash") != committed_block_hash:
        label_errors.append(f"{label} full-path artifact finality blockHash drift")
    if post_restart.get("attestation", {}).get("finalityBlueScore") != committed_block_blue_score:
        label_errors.append(f"{label} full-path artifact finality blueScore drift")
    if post_restart.get("runtimeRecovery", {}).get("lastCheckpointBlockHash") != committed_block_hash:
        label_errors.append(f"{label} full-path artifact runtimeRecovery blockHash drift")
    if post_restart.get("runtimeRecovery", {}).get("lastCheckpointFinalityBlueScore") != committed_block_blue_score:
        label_errors.append(f"{label} full-path artifact runtimeRecovery finality blueScore drift")
    if post_restart.get("validatorLifecycleRecovery", {}).get("summary") != "ready":
        label_errors.append(f"{label} full-path artifact validatorLifecycleRecovery summary drift")
    if post_restart.get("validatorLifecycleRecovery", {}).get("restartReady") is not True:
        label_errors.append(f"{label} full-path artifact validatorLifecycleRecovery restartReady drift")
    if post_restart.get("validatorLifecycleRecovery", {}).get("checkpointPersisted") is not True:
        label_errors.append(f"{label} full-path artifact validatorLifecycleRecovery checkpointPersisted drift")
    if post_restart.get("validatorLifecycleRecovery", {}).get("checkpointFinalized") is not True:
        label_errors.append(f"{label} full-path artifact validatorLifecycleRecovery checkpointFinalized drift")
    if post_restart.get("consumerSurfaces", {}).get("chainInfo", {}).get("dataAvailability", {}).get("consumerReadiness") != "ready":
        label_errors.append(f"{label} full-path artifact chainInfo DA surface is not ready")
    if post_restart.get("consumerSurfaces", {}).get("dagInfo", {}).get("lightClient", {}).get("txLookupKey") != "txHash":
        label_errors.append(f"{label} full-path artifact dagInfo lightClient txLookupKey drift")
    if artifact.get("continuity", {}).get("sameTxHash") is not True:
        label_errors.append(f"{label} full-path artifact txHash continuity drift")
    if artifact.get("continuity", {}).get("sameFinalityBlockHash") is not True:
        label_errors.append(f"{label} full-path artifact finality blockHash continuity drift")
    if artifact.get("continuity", {}).get("sameFinalityBlueScore") is not True:
        label_errors.append(f"{label} full-path artifact finality blueScore continuity drift")
    if artifact.get("continuity", {}).get("sameNullifierSpent") is not True:
        label_errors.append(f"{label} full-path artifact nullifier continuity drift")
    if artifact.get("continuity", {}).get("sameEncryptedNoteTxHash") is not True:
        label_errors.append(f"{label} full-path artifact encrypted note continuity drift")
    if artifact.get("continuity", {}).get("sameVirtualTip") is not True:
        label_errors.append(f"{label} full-path artifact virtual tip continuity drift")
    if artifact.get("continuity", {}).get("reloadedFromSnapshot") is not True:
        label_errors.append(f"{label} full-path artifact snapshot reload continuity drift")
    if post_restart.get("virtualState", {}).get("tip") != committed_block_hash:
        label_errors.append(f"{label} full-path artifact virtualState tip drift")
    if post_restart.get("virtualState", {}).get("tipScore") != committed_block_blue_score:
        label_errors.append(f"{label} full-path artifact virtualState tipScore drift")
    full_path_consistency_errors.extend(label_errors)
    if label.startswith("groth16"):
        full_path_groth16_consistency_errors.extend(label_errors)

for label, artifact in (
    ("sha3ThreeValidatorSequence", full_path_sha3_three_validator_sequence if isinstance(full_path_sha3_three_validator_sequence, dict) else None),
    ("groth16ThreeValidatorSequence", full_path_groth16_three_validator_sequence if isinstance(full_path_groth16_three_validator_sequence, dict) else None),
    ("plonkThreeValidatorSequence", full_path_plonk_three_validator_sequence if isinstance(full_path_plonk_three_validator_sequence, dict) else None),
    ("sha3FourValidatorSequence", full_path_sha3_four_validator_sequence if isinstance(full_path_sha3_four_validator_sequence, dict) else None),
    ("groth16FourValidatorSequence", full_path_groth16_four_validator_sequence if isinstance(full_path_groth16_four_validator_sequence, dict) else None),
    ("plonkFourValidatorSequence", full_path_plonk_four_validator_sequence if isinstance(full_path_plonk_four_validator_sequence, dict) else None),
    ("sha3SixValidatorSequence", full_path_sha3_six_validator_sequence if isinstance(full_path_sha3_six_validator_sequence, dict) else None),
    ("groth16SixValidatorSequence", full_path_groth16_six_validator_sequence if isinstance(full_path_groth16_six_validator_sequence, dict) else None),
    ("plonkSixValidatorSequence", full_path_plonk_six_validator_sequence if isinstance(full_path_plonk_six_validator_sequence, dict) else None),
):
    if not artifact:
        continue
    label_errors = []
    post_restart = artifact.get("postRestart", {})
    tx_hashes = artifact.get("txHashes")
    sequence = post_restart.get("sequence")
    if artifact.get("sequenceDepth") != 2:
        label_errors.append(f"{label} sequence full-path artifact sequenceDepth drift")
    if not isinstance(tx_hashes, list) or len(tx_hashes) != 2:
        label_errors.append(f"{label} sequence full-path artifact txHashes length drift")
    elif len(set(tx_hashes)) != 2:
        label_errors.append(f"{label} sequence full-path artifact txHashes are not distinct")
    if not isinstance(sequence, list) or len(sequence) != 2:
        label_errors.append(f"{label} sequence full-path artifact sequence length drift")
        sequence = []
    expected_vote_count = post_restart.get("quorum", {}).get("voteCount")
    if post_restart.get("quorum", {}).get("quorumReached") is not True:
        label_errors.append(f"{label} sequence full-path artifact quorum is not reached")
    if not isinstance(expected_vote_count, int) or expected_vote_count < 2:
        label_errors.append(f"{label} sequence full-path artifact vote count is malformed")
    expected_quorum_threshold = expected_quorum_threshold_from_artifact(post_restart)
    if str(post_restart.get("quorum", {}).get("quorumThreshold")) != str(expected_quorum_threshold):
        label_errors.append(f"{label} sequence full-path artifact quorumThreshold drift")
    if post_restart.get("quorum", {}).get("validatorCount") != expected_vote_count:
        label_errors.append(f"{label} sequence full-path artifact validatorCount drift")
    if post_restart.get("checkpointConsumer", {}).get("explorerConfirmationLevel") != "checkpointFinalized":
        label_errors.append(f"{label} sequence full-path artifact checkpoint consumer is not finalized")
    if post_restart.get("validatorLifecycleRecovery", {}).get("summary") != "ready":
        label_errors.append(f"{label} sequence full-path artifact validatorLifecycleRecovery summary drift")
    if post_restart.get("validatorLifecycleRecovery", {}).get("restartReady") is not True:
        label_errors.append(f"{label} sequence full-path artifact validatorLifecycleRecovery restartReady drift")
    if post_restart.get("validatorLifecycleRecovery", {}).get("checkpointPersisted") is not True:
        label_errors.append(f"{label} sequence full-path artifact validatorLifecycleRecovery checkpointPersisted drift")
    if post_restart.get("validatorLifecycleRecovery", {}).get("checkpointFinalized") is not True:
        label_errors.append(f"{label} sequence full-path artifact validatorLifecycleRecovery checkpointFinalized drift")
    if post_restart.get("runtimeRecovery", {}).get("operatorRestartReady") is not True:
        label_errors.append(f"{label} sequence full-path artifact runtimeRecovery operatorRestartReady drift")
    if post_restart.get("runtimeRecovery", {}).get("startupSnapshotRestored") is not True:
        label_errors.append(f"{label} sequence full-path artifact runtimeRecovery startupSnapshotRestored drift")
    if post_restart.get("consumerSurfaces", {}).get("chainInfo", {}).get("dataAvailability", {}).get("consumerReadiness") != "ready":
        label_errors.append(f"{label} sequence full-path artifact chainInfo DA surface is not ready")
    if post_restart.get("consumerSurfaces", {}).get("dagInfo", {}).get("lightClient", {}).get("txLookupKey") != "txHash":
        label_errors.append(f"{label} sequence full-path artifact dagInfo lightClient txLookupKey drift")
    continuity = artifact.get("continuity", {})
    if continuity.get("sameTxHashes") is not True:
        label_errors.append(f"{label} sequence full-path artifact txHash continuity drift")
    if continuity.get("sameFinalityBlockHash") is not True:
        label_errors.append(f"{label} sequence full-path artifact finality blockHash continuity drift")
    if continuity.get("sameFinalityBlueScore") is not True:
        label_errors.append(f"{label} sequence full-path artifact finality blueScore continuity drift")
    if continuity.get("bothNullifiersSpent") is not True:
        label_errors.append(f"{label} sequence full-path artifact nullifier continuity drift")
    if continuity.get("bothEncryptedNoteTxHashes") is not True:
        label_errors.append(f"{label} sequence full-path artifact encrypted note continuity drift")
    if continuity.get("acceptedSequenceDepth") is not True:
        label_errors.append(f"{label} sequence full-path artifact acceptedSequenceDepth drift")
    if continuity.get("distinctCommittedBlocks") is not True:
        label_errors.append(f"{label} sequence full-path artifact distinctCommittedBlocks drift")
    if continuity.get("sameVirtualTip") is not True:
        label_errors.append(f"{label} sequence full-path artifact virtual tip continuity drift")
    if continuity.get("reloadedFromSnapshot") is not True:
        label_errors.append(f"{label} sequence full-path artifact snapshot reload continuity drift")
    if not label_errors and sequence:
        for index, entry in enumerate(sequence, start=1):
            if entry.get("index") != index:
                label_errors.append(f"{label} sequence entry index drift at position {index}")
            expected_tx_hash = tx_hashes[index - 1] if isinstance(tx_hashes, list) and len(tx_hashes) == 2 else None
            if entry.get("lookup", {}).get("txHash") != expected_tx_hash:
                label_errors.append(f"{label} sequence entry lookup txHash drift at position {index}")
            if entry.get("summary", {}).get("txHash") != expected_tx_hash:
                label_errors.append(f"{label} sequence entry summary txHash drift at position {index}")
            if entry.get("nullifierStatus", {}).get("spent") is not True:
                label_errors.append(f"{label} sequence entry nullifier spent drift at position {index}")
            if entry.get("nullifierStatus", {}).get("tx_hash") != expected_tx_hash:
                label_errors.append(f"{label} sequence entry nullifier txHash drift at position {index}")
        accepted_tx_hashes = post_restart.get("shieldedReadPlane", {}).get("acceptedTxHashes")
        if accepted_tx_hashes != tx_hashes:
            label_errors.append(f"{label} sequence full-path artifact acceptedTxHashes drift")
        if post_restart.get("shieldedReadPlane", {}).get("encryptedNoteOrder") != [1, 2]:
            label_errors.append(f"{label} sequence full-path artifact encryptedNoteOrder drift")
    full_path_consistency_errors.extend(label_errors)
    if label.startswith("groth16"):
        full_path_groth16_consistency_errors.extend(label_errors)

if full_path_consistency_errors:
    errors.extend(full_path_consistency_errors)

if runtime_comparison_requested:
    if not isinstance(runtime_comparison, dict) or runtime_comparison.get("status") != "passed":
        errors.append("runtime comparison artifact status is not passed")
    elif not isinstance(runtime_comparison_summary, dict) or runtime_comparison_summary.get("comparisonReady") is not True:
        errors.append("runtime comparison artifact comparisonReady is not true")
    elif (
        runtime_comparison_summary.get("fullPathSixValidator", {}).get("parityReady")
        is not True
    ):
        errors.append("runtime comparison fullPathSixValidator parity is not true")
    elif (
        runtime_comparison_summary.get("sequenceSixValidator", {}).get("parityReady")
        is not True
    ):
        errors.append("runtime comparison sequenceSixValidator parity is not true")
    elif (
        not isinstance(runtime_comparison_operator_summary, dict)
        or runtime_comparison_operator_summary.get("operatorDecisionReady") is not True
    ):
        errors.append("runtime comparison operator summary operatorDecisionReady is not true")
    elif (
        runtime_comparison_operator_summary.get("sharedBreadth", {}).get("fullPathValidatorCount", 0) < 6
    ):
        errors.append("runtime comparison operator summary fullPathValidatorCount is below 6")
    elif (
        runtime_comparison_operator_summary.get("sharedBreadth", {}).get("sequenceValidatorCount", 0) < 6
    ):
        errors.append("runtime comparison operator summary sequenceValidatorCount is below 6")

recommended_next_action = "implement actual verifier body"
if errors:
    recommended_next_action = "fix VK configuration or live snapshot failure"
elif verifier_contract_summary and verifier_contract_summary.get("authoritativeTargetReady") is True:
    recommended_next_action = "extend shielded full-path E2E"
elif any((
    include_bounded_sha3,
    include_bounded_groth16,
    include_bounded_plonk,
    include_bounded_plonk_three_validator,
    include_bounded_sha3_three_validator,
    include_bounded_groth16_three_validator,
)):
    recommended_next_action = "extend bounded live proof to broader multi-validator path"
elif target_policy_consistent is False:
    recommended_next_action = "align authoritative target and VK policy before rollout"
elif not groth16_path and not plonk_path:
    recommended_next_action = "prepare authoritative VK artifact and rerun preflight"

payload = {
    "status": "failed" if errors else "passed",
    "operatorReadOrder": [
        "inventory",
        "benchmark_baseline",
        "vk_artifact_preflight",
        "optional_live_snapshot",
        "optional_full_path_restart_continuity",
    ],
    "effectiveConfig": {
        "authoritativeTarget": target,
        "groth16VkPolicy": groth16_policy,
        "plonkVkPolicy": plonk_policy,
        "groth16VkConfigured": bool(groth16_path),
        "plonkVkConfigured": bool(plonk_path),
        "realBackendBootstrap": real_backend_bootstrap,
        "includeLiveSnapshot": include_live_snapshot,
        "nodeBase": node_base if include_live_snapshot else None,
    },
    "artifacts": {
        "inventoryArtifact": str(inventory_path),
        "benchmarkArtifact": str(benchmark_path),
        "runtimeComparisonArtifact": (
            str(runtime_comparison_path) if runtime_comparison_requested else None
        ),
        "vkArtifactInspectionArtifact": str(vk_inspect_path) if inspect_requested else None,
        "liveSnapshotArtifact": str(snapshot_path) if snapshot_requested else None,
        "boundedSha3Artifact": str(bounded_sha3_path) if bounded_sha3_requested else None,
        "boundedGroth16Artifact": str(bounded_groth16_path) if bounded_groth16_requested else None,
        "boundedPlonkArtifact": str(bounded_plonk_path) if bounded_plonk_requested else None,
        "boundedPlonkThreeValidatorArtifact": (
            str(bounded_plonk_three_validator_path)
            if bounded_plonk_three_validator_requested
            else None
        ),
        "boundedSha3ThreeValidatorArtifact": (
            str(bounded_sha3_three_validator_path)
            if bounded_sha3_three_validator_requested
            else None
        ),
        "boundedGroth16ThreeValidatorArtifact": (
            str(bounded_groth16_three_validator_path)
            if bounded_groth16_three_validator_requested
            else None
        ),
        "fullPathSha3Artifact": str(full_path_sha3_path) if full_path_sha3_requested else None,
        "fullPathGroth16Artifact": str(full_path_groth16_path) if full_path_groth16_requested else None,
        "fullPathPlonkArtifact": str(full_path_plonk_path) if full_path_plonk_requested else None,
        "fullPathPlonkThreeValidatorArtifact": (
            str(full_path_plonk_three_validator_path)
            if full_path_plonk_three_validator_requested
            else None
        ),
        "fullPathPlonkFourValidatorArtifact": (
            str(full_path_plonk_four_validator_path)
            if full_path_plonk_four_validator_requested
            else None
        ),
        "fullPathPlonkSixValidatorArtifact": (
            str(full_path_plonk_six_validator_path)
            if full_path_plonk_six_validator_requested
            else None
        ),
        "fullPathSha3ThreeValidatorArtifact": (
            str(full_path_sha3_three_validator_path)
            if full_path_sha3_three_validator_requested
            else None
        ),
        "fullPathGroth16ThreeValidatorArtifact": (
            str(full_path_groth16_three_validator_path)
            if full_path_groth16_three_validator_requested
            else None
        ),
        "fullPathSha3SixValidatorArtifact": (
            str(full_path_sha3_six_validator_path)
            if full_path_sha3_six_validator_requested
            else None
        ),
        "fullPathGroth16SixValidatorArtifact": (
            str(full_path_groth16_six_validator_path)
            if full_path_groth16_six_validator_requested
            else None
        ),
        "fullPathSha3ThreeValidatorSequenceArtifact": (
            str(full_path_sha3_three_validator_sequence_path)
            if full_path_sha3_three_validator_sequence_requested
            else None
        ),
        "fullPathGroth16ThreeValidatorSequenceArtifact": (
            str(full_path_groth16_three_validator_sequence_path)
            if full_path_groth16_three_validator_sequence_requested
            else None
        ),
        "fullPathPlonkThreeValidatorSequenceArtifact": (
            str(full_path_plonk_three_validator_sequence_path)
            if full_path_plonk_three_validator_sequence_requested
            else None
        ),
        "fullPathSha3FourValidatorSequenceArtifact": (
            str(full_path_sha3_four_validator_sequence_path)
            if full_path_sha3_four_validator_sequence_requested
            else None
        ),
        "fullPathGroth16FourValidatorSequenceArtifact": (
            str(full_path_groth16_four_validator_sequence_path)
            if full_path_groth16_four_validator_sequence_requested
            else None
        ),
        "fullPathPlonkFourValidatorSequenceArtifact": (
            str(full_path_plonk_four_validator_sequence_path)
            if full_path_plonk_four_validator_sequence_requested
            else None
        ),
        "fullPathSha3SixValidatorSequenceArtifact": (
            str(full_path_sha3_six_validator_sequence_path)
            if full_path_sha3_six_validator_sequence_requested
            else None
        ),
        "fullPathGroth16SixValidatorSequenceArtifact": (
            str(full_path_groth16_six_validator_sequence_path)
            if full_path_groth16_six_validator_sequence_requested
            else None
        ),
        "fullPathPlonkSixValidatorSequenceArtifact": (
            str(full_path_plonk_six_validator_sequence_path)
            if full_path_plonk_six_validator_sequence_requested
            else None
        ),
        "fullPathSha3FourValidatorArtifact": (
            str(full_path_sha3_four_validator_path)
            if full_path_sha3_four_validator_requested
            else None
        ),
        "fullPathGroth16FourValidatorArtifact": (
            str(full_path_groth16_four_validator_path)
            if full_path_groth16_four_validator_requested
            else None
        ),
    },
    "inventorySummary": inventory_summary,
    "benchmarkSummary": benchmark_summary,
    "comparativeBenchmarkSummary": comparative_benchmark_summary,
    "benchmarkSummaries": benchmark_summaries,
    "compiledCatalog": compiled_catalog,
    "runtimeComparisonSummary": runtime_comparison_summary,
    "runtimeComparisonOperatorSummary": runtime_comparison_operator_summary,
    "runtimeComparisonRunbookReadiness": runtime_comparison_runbook,
    "vkArtifactInspectionSummary": vk_inspection if inspect_requested else None,
    "liveSnapshotSummary": live_snapshot if snapshot_requested else None,
    "boundedLiveSummary": {
        "sha3": bounded_sha3 if bounded_sha3_requested else None,
        "groth16": bounded_groth16 if bounded_groth16_requested else None,
        "plonk": bounded_plonk if bounded_plonk_requested else None,
        "plonkThreeValidator": (
            bounded_plonk_three_validator if bounded_plonk_three_validator_requested else None
        ),
        "sha3ThreeValidator": (
            bounded_sha3_three_validator if bounded_sha3_three_validator_requested else None
        ),
        "groth16ThreeValidator": (
            bounded_groth16_three_validator
            if bounded_groth16_three_validator_requested
            else None
        ),
        "fullPathSha3": full_path_sha3 if full_path_sha3_requested else None,
        "fullPathGroth16": full_path_groth16 if full_path_groth16_requested else None,
        "fullPathPlonk": full_path_plonk if full_path_plonk_requested else None,
        "fullPathPlonkThreeValidator": (
            full_path_plonk_three_validator if full_path_plonk_three_validator_requested else None
        ),
        "fullPathPlonkFourValidator": (
            full_path_plonk_four_validator if full_path_plonk_four_validator_requested else None
        ),
        "fullPathPlonkSixValidator": (
            full_path_plonk_six_validator if full_path_plonk_six_validator_requested else None
        ),
        "fullPathSha3ThreeValidator": (
            full_path_sha3_three_validator
            if full_path_sha3_three_validator_requested
            else None
        ),
        "fullPathGroth16ThreeValidator": (
            full_path_groth16_three_validator
            if full_path_groth16_three_validator_requested
            else None
        ),
        "fullPathSha3SixValidator": (
            full_path_sha3_six_validator
            if full_path_sha3_six_validator_requested
            else None
        ),
        "fullPathGroth16SixValidator": (
            full_path_groth16_six_validator
            if full_path_groth16_six_validator_requested
            else None
        ),
        "fullPathSha3ThreeValidatorSequence": (
            full_path_sha3_three_validator_sequence
            if full_path_sha3_three_validator_sequence_requested
            else None
        ),
        "fullPathGroth16ThreeValidatorSequence": (
            full_path_groth16_three_validator_sequence
            if full_path_groth16_three_validator_sequence_requested
            else None
        ),
        "fullPathPlonkThreeValidatorSequence": (
            full_path_plonk_three_validator_sequence
            if full_path_plonk_three_validator_sequence_requested
            else None
        ),
        "fullPathSha3FourValidatorSequence": (
            full_path_sha3_four_validator_sequence
            if full_path_sha3_four_validator_sequence_requested
            else None
        ),
        "fullPathGroth16FourValidatorSequence": (
            full_path_groth16_four_validator_sequence
            if full_path_groth16_four_validator_sequence_requested
            else None
        ),
        "fullPathPlonkFourValidatorSequence": (
            full_path_plonk_four_validator_sequence
            if full_path_plonk_four_validator_sequence_requested
            else None
        ),
        "fullPathSha3SixValidatorSequence": (
            full_path_sha3_six_validator_sequence
            if full_path_sha3_six_validator_sequence_requested
            else None
        ),
        "fullPathGroth16SixValidatorSequence": (
            full_path_groth16_six_validator_sequence
            if full_path_groth16_six_validator_sequence_requested
            else None
        ),
        "fullPathPlonkSixValidatorSequence": (
            full_path_plonk_six_validator_sequence
            if full_path_plonk_six_validator_sequence_requested
            else None
        ),
        "fullPathSha3FourValidator": (
            full_path_sha3_four_validator
            if full_path_sha3_four_validator_requested
            else None
        ),
        "fullPathGroth16FourValidator": (
            full_path_groth16_four_validator
            if full_path_groth16_four_validator_requested
            else None
        ),
    },
    "verifierContractSummary": verifier_contract_summary,
    "runbookReadiness": {
        "defaultPathRegistersStub": (
            inventory_summary.get("defaultPathRegistersStub")
            if isinstance(inventory_summary, dict)
            else None
        ),
        "authoritativeTargetSurfacePresent": (
            inventory_summary.get("authoritativeTargetSurfacePresent")
            if isinstance(inventory_summary, dict)
            else None
        ),
        "realBackendBootstrapSurfacePresent": (
            inventory_summary.get("realBackendBootstrapSurfacePresent")
            if isinstance(inventory_summary, dict)
            else None
        ),
        "prodFeatureGateCoversVkArtifactPreflight": (
            inventory_summary.get("prodFeatureGateCoversVkArtifactPreflight")
            if isinstance(inventory_summary, dict)
            else None
        ),
        "prodFeatureGateCoversRealBackendBootstrap": (
            inventory_summary.get("prodFeatureGateCoversRealBackendBootstrap")
            if isinstance(inventory_summary, dict)
            else None
        ),
        "releaseCompileGuardPresent": (
            inventory_summary.get("releaseCompileGuardPresent")
            if isinstance(inventory_summary, dict)
            else None
        ),
        "groth16VkPolicyReady": policy_ready(groth16_policy, groth16_path, "groth16"),
        "plonkVkPolicyReady": policy_ready(plonk_policy, plonk_path, "plonk"),
        "authoritativeGroth16PlonkReady": authoritative_ready_inventory,
        "realBackendBootstrapRequested": real_backend_bootstrap,
        "realBackendBootstrapAllowed": (
            authoritative_ready_inventory is True if real_backend_bootstrap else True
        ),
        "runtimeComparisonIncluded": runtime_comparison_requested,
        "boundedSha3Included": bounded_sha3_requested,
        "boundedGroth16Included": bounded_groth16_requested,
        "boundedPlonkIncluded": bounded_plonk_requested,
        "boundedPlonkThreeValidatorIncluded": bounded_plonk_three_validator_requested,
        "boundedSha3ThreeValidatorIncluded": bounded_sha3_three_validator_requested,
        "boundedGroth16ThreeValidatorIncluded": bounded_groth16_three_validator_requested,
        "fullPathSha3Included": full_path_sha3_requested,
        "fullPathGroth16Included": full_path_groth16_requested,
        "fullPathPlonkIncluded": full_path_plonk_requested,
        "fullPathPlonkThreeValidatorIncluded": full_path_plonk_three_validator_requested,
        "fullPathPlonkFourValidatorIncluded": full_path_plonk_four_validator_requested,
        "fullPathPlonkSixValidatorIncluded": full_path_plonk_six_validator_requested,
        "fullPathSha3ThreeValidatorIncluded": full_path_sha3_three_validator_requested,
        "fullPathGroth16ThreeValidatorIncluded": full_path_groth16_three_validator_requested,
        "fullPathSha3SixValidatorIncluded": full_path_sha3_six_validator_requested,
        "fullPathGroth16SixValidatorIncluded": full_path_groth16_six_validator_requested,
        "fullPathSha3ThreeValidatorSequenceIncluded": full_path_sha3_three_validator_sequence_requested,
        "fullPathGroth16ThreeValidatorSequenceIncluded": full_path_groth16_three_validator_sequence_requested,
        "fullPathPlonkThreeValidatorSequenceIncluded": full_path_plonk_three_validator_sequence_requested,
        "fullPathSha3FourValidatorSequenceIncluded": full_path_sha3_four_validator_sequence_requested,
        "fullPathGroth16FourValidatorSequenceIncluded": full_path_groth16_four_validator_sequence_requested,
        "fullPathPlonkFourValidatorSequenceIncluded": full_path_plonk_four_validator_sequence_requested,
        "fullPathSha3SixValidatorSequenceIncluded": full_path_sha3_six_validator_sequence_requested,
        "fullPathGroth16SixValidatorSequenceIncluded": full_path_groth16_six_validator_sequence_requested,
        "fullPathPlonkSixValidatorSequenceIncluded": full_path_plonk_six_validator_sequence_requested,
        "fullPathSha3FourValidatorIncluded": full_path_sha3_four_validator_requested,
        "fullPathGroth16FourValidatorIncluded": full_path_groth16_four_validator_requested,
        "boundedLiveRefreshed": refresh_bounded_live if (bounded_sha3_requested or bounded_groth16_requested or bounded_plonk_requested or bounded_plonk_three_validator_requested or bounded_sha3_three_validator_requested or bounded_groth16_three_validator_requested) else None,
        "fullPathLiveRefreshed": refresh_full_path if (full_path_sha3_requested or full_path_groth16_requested or full_path_plonk_requested or full_path_plonk_three_validator_requested or full_path_plonk_four_validator_requested or full_path_plonk_six_validator_requested or full_path_sha3_three_validator_requested or full_path_groth16_three_validator_requested or full_path_sha3_six_validator_requested or full_path_groth16_six_validator_requested or full_path_sha3_three_validator_sequence_requested or full_path_groth16_three_validator_sequence_requested or full_path_plonk_three_validator_sequence_requested or full_path_sha3_four_validator_requested or full_path_groth16_four_validator_requested or full_path_sha3_four_validator_sequence_requested or full_path_groth16_four_validator_sequence_requested or full_path_plonk_four_validator_sequence_requested or full_path_sha3_six_validator_sequence_requested or full_path_groth16_six_validator_sequence_requested or full_path_plonk_six_validator_sequence_requested) else None,
        "authoritativeTargetPolicyConsistent": target_policy_consistent,
        "authoritativeTargetReadyRuntime": (
            verifier_contract_summary.get("authoritativeTargetReady")
            if isinstance(verifier_contract_summary, dict)
            else None
        ),
        "boundedLiveConsistentWithManifest": (
            False
            if bounded_consistency_errors
            else (
                True
                if (
                    bounded_sha3_requested
                    or bounded_groth16_requested
                    or bounded_plonk_requested
                    or bounded_plonk_three_validator_requested
                    or bounded_sha3_three_validator_requested
                    or bounded_groth16_three_validator_requested
                )
                else None
            )
        ),
        "fullPathLiveConsistentWithManifest": (
            False if full_path_consistency_errors else (True if (full_path_sha3_requested or full_path_groth16_requested or full_path_plonk_requested or full_path_plonk_three_validator_requested or full_path_plonk_four_validator_requested or full_path_plonk_six_validator_requested or full_path_sha3_three_validator_requested or full_path_groth16_three_validator_requested or full_path_sha3_six_validator_requested or full_path_groth16_six_validator_requested or full_path_sha3_three_validator_sequence_requested or full_path_groth16_three_validator_sequence_requested or full_path_plonk_three_validator_sequence_requested or full_path_sha3_four_validator_requested or full_path_groth16_four_validator_requested or full_path_sha3_four_validator_sequence_requested or full_path_groth16_four_validator_sequence_requested or full_path_plonk_four_validator_sequence_requested or full_path_sha3_six_validator_sequence_requested or full_path_groth16_six_validator_sequence_requested or full_path_plonk_six_validator_sequence_requested) else None)
        ),
        "fullPathGroth16LiveConsistentWithManifest": (
            False if full_path_groth16_consistency_errors else (True if (full_path_groth16_requested or full_path_groth16_three_validator_requested or full_path_groth16_three_validator_sequence_requested or full_path_groth16_four_validator_requested or full_path_groth16_four_validator_sequence_requested or full_path_groth16_six_validator_requested or full_path_groth16_six_validator_sequence_requested) else None)
        ),
        "fullPathPlonkLiveConsistentWithManifest": (
            False
            if any(
                error.startswith(("plonk", "plonkThreeValidator", "plonkFourValidator"))
                for error in full_path_consistency_errors
            )
            else (
                True
                if (
                    full_path_plonk_requested
                    or full_path_plonk_three_validator_requested
                    or full_path_plonk_three_validator_sequence_requested
                    or full_path_plonk_four_validator_requested
                    or full_path_plonk_four_validator_sequence_requested
                    or full_path_plonk_six_validator_requested
                    or full_path_plonk_six_validator_sequence_requested
                )
                else None
            )
        ),
        "runtimeComparisonRefreshed": (
            runtime_comparison_runbook.get("refreshedInputs")
            if runtime_comparison_requested and isinstance(runtime_comparison_runbook, dict)
            else (False if runtime_comparison_requested else None)
        ),
        "runtimeComparisonOperatorSummaryReady": (
            runtime_comparison_operator_summary.get("operatorDecisionReady")
            if runtime_comparison_requested and isinstance(runtime_comparison_operator_summary, dict)
            else (False if runtime_comparison_requested else None)
        ),
        "runtimeComparisonFullPathSixValidatorReady": (
            runtime_comparison_summary.get("fullPathSixValidator", {}).get("parityReady")
            if runtime_comparison_requested and isinstance(runtime_comparison_summary, dict)
            else (False if runtime_comparison_requested else None)
        ),
        "runtimeComparisonSequenceSixValidatorReady": (
            runtime_comparison_summary.get("sequenceSixValidator", {}).get("parityReady")
            if runtime_comparison_requested and isinstance(runtime_comparison_summary, dict)
            else (False if runtime_comparison_requested else None)
        ),
        "runtimeComparisonConsistentWithManifest": (
            False
            if runtime_comparison_requested and (
                not isinstance(runtime_comparison_summary, dict)
                or runtime_comparison_summary.get("comparisonReady") is not True
                or runtime_comparison_summary.get("fullPathSixValidator", {}).get("parityReady") is not True
                or runtime_comparison_summary.get("sequenceSixValidator", {}).get("parityReady") is not True
                or not isinstance(runtime_comparison_operator_summary, dict)
                or runtime_comparison_operator_summary.get("operatorDecisionReady") is not True
                or runtime_comparison_operator_summary.get("sharedBreadth", {}).get("fullPathValidatorCount", 0) < 6
                or runtime_comparison_operator_summary.get("sharedBreadth", {}).get("sequenceValidatorCount", 0) < 6
            )
            else (True if runtime_comparison_requested else None)
        ),
        "liveSnapshotConsistentWithManifest": (
            False
            if live_manifest_consistency_errors
            else (True if isinstance(verifier_contract_summary, dict) else None)
        ),
    },
    "recommendedNextAction": recommended_next_action,
}

if errors:
    payload["errors"] = errors
if live_manifest_consistency_errors:
    payload["liveManifestConsistencyErrors"] = live_manifest_consistency_errors
if bounded_consistency_errors:
    payload["boundedLiveConsistencyErrors"] = bounded_consistency_errors
if full_path_consistency_errors:
    payload["fullPathLiveConsistencyErrors"] = full_path_consistency_errors

result_file.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n")
sys.exit(1 if errors else 0)
PY

printf 'wrote %s\n' "$result_file"
