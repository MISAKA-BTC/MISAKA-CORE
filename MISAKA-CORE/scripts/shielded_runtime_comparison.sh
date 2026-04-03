#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

state_dir="${MISAKA_SHIELDED_RUNTIME_COMPARISON_DIR:-$repo_root/.tmp/shielded-runtime-comparison}"
result_file="${MISAKA_SHIELDED_RUNTIME_COMPARISON_RESULT:-$state_dir/result.json}"

benchmark_script="$repo_root/scripts/shielded_backend_benchmark.sh"
bounded_sha3_script="$repo_root/scripts/shielded_live_bounded_e2e.sh"
bounded_groth16_script="$repo_root/scripts/shielded_live_bounded_e2e_groth16.sh"
bounded_plonk_script="$repo_root/scripts/shielded_live_bounded_e2e_plonk.sh"
full_path_sha3_script="$repo_root/scripts/shielded_live_full_path_e2e.sh"
full_path_groth16_script="$repo_root/scripts/shielded_live_full_path_e2e_groth16.sh"
full_path_plonk_script="$repo_root/scripts/shielded_live_full_path_e2e_plonk.sh"

benchmark_result="${MISAKA_SHIELDED_BENCHMARK_RESULT:-$repo_root/.tmp/shielded-backend-benchmark/result.json}"
bounded_sha3_result="${MISAKA_SHIELDED_LIVE_BOUNDED_E2E_RESULT:-$repo_root/.tmp/shielded-live-bounded-e2e/result.json}"
bounded_groth16_result="${MISAKA_SHIELDED_LIVE_GROTH16_E2E_RESULT:-$repo_root/.tmp/shielded-live-bounded-e2e-groth16/result.json}"
bounded_plonk_result="${MISAKA_SHIELDED_BOUNDED_PLONK_E2E_RESULT:-$repo_root/.tmp/shielded-live-bounded-e2e-plonk/result.json}"
full_path_sha3_result="${MISAKA_SHIELDED_FULL_PATH_E2E_RESULT:-$repo_root/.tmp/shielded-full-path-e2e/result.json}"
full_path_groth16_result="${MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-groth16/result.json}"
full_path_plonk_result="${MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-plonk/result.json}"
full_path_sha3_four_validator_result="${MISAKA_SHIELDED_FULL_PATH_E2E_FOUR_VALIDATOR_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-4v/result.json}"
full_path_groth16_four_validator_result="${MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_FOUR_VALIDATOR_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-groth16-4v/result.json}"
full_path_plonk_four_validator_result="${MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_FOUR_VALIDATOR_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-plonk-4v/result.json}"
full_path_sha3_six_validator_result="${MISAKA_SHIELDED_FULL_PATH_E2E_SIX_VALIDATOR_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-6v/result.json}"
full_path_groth16_six_validator_result="${MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_SIX_VALIDATOR_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-groth16-6v/result.json}"
full_path_plonk_six_validator_result="${MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_SIX_VALIDATOR_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-plonk-6v/result.json}"
sequence_sha3_result="${MISAKA_SHIELDED_FULL_PATH_E2E_THREE_VALIDATOR_SEQUENCE_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-3v-seq/result.json}"
sequence_groth16_result="${MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_THREE_VALIDATOR_SEQUENCE_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-groth16-3v-seq/result.json}"
sequence_plonk_result="${MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_THREE_VALIDATOR_SEQUENCE_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-plonk-3v-seq/result.json}"
sequence_sha3_four_validator_result="${MISAKA_SHIELDED_FULL_PATH_E2E_FOUR_VALIDATOR_SEQUENCE_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-4v-seq/result.json}"
sequence_groth16_four_validator_result="${MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_FOUR_VALIDATOR_SEQUENCE_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-groth16-4v-seq/result.json}"
sequence_plonk_four_validator_result="${MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_FOUR_VALIDATOR_SEQUENCE_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-plonk-4v-seq/result.json}"
sequence_sha3_six_validator_result="${MISAKA_SHIELDED_FULL_PATH_E2E_SIX_VALIDATOR_SEQUENCE_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-6v-seq/result.json}"
sequence_groth16_six_validator_result="${MISAKA_SHIELDED_FULL_PATH_GROTH16_E2E_SIX_VALIDATOR_SEQUENCE_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-groth16-6v-seq/result.json}"
sequence_plonk_six_validator_result="${MISAKA_SHIELDED_FULL_PATH_PLONK_E2E_SIX_VALIDATOR_SEQUENCE_RESULT:-$repo_root/.tmp/shielded-full-path-e2e-plonk-6v-seq/result.json}"

refresh_inputs="${MISAKA_SHIELDED_REFRESH_COMPARISON_INPUTS:-0}"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'EOF'
Usage: ./scripts/shielded_runtime_comparison.sh

Build a comparative runtime artifact by combining current actual shielded slices:

  - benchmark baseline (`SHA3 / Groth16 / PLONK`)
  - bounded live E2E parity (`2-validator`)
  - full-path restart continuity parity (`2-validator`)
  - full-path restart continuity breadth parity (`4-validator`)
  - full-path restart continuity breadth parity (`6-validator`)
  - full-path sequence-depth parity (`3-validator`)
  - full-path sequence-depth breadth parity (`4-validator`)
  - full-path sequence-depth breadth parity (`6-validator`)

Output:
  .tmp/shielded-runtime-comparison/result.json

Optional env:
  MISAKA_SHIELDED_RUNTIME_COMPARISON_DIR
  MISAKA_SHIELDED_RUNTIME_COMPARISON_RESULT
  MISAKA_SHIELDED_REFRESH_COMPARISON_INPUTS=1
    Force-refresh benchmark + bounded + full-path + sequence source artifacts
EOF
  exit 0
fi

mkdir -p "$state_dir"
cd "$repo_root"

write_failure() {
  local message="$1"
  python3 - "$result_file" "$message" <<'PY'
import json
import pathlib
import sys

result = pathlib.Path(sys.argv[1])
message = sys.argv[2]
result.parent.mkdir(parents=True, exist_ok=True)
payload = {
    "status": "failed",
    "error": message,
}
result.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n")
PY
}

if [[ "$refresh_inputs" == "1" || ! -f "$benchmark_result" ]]; then
  bash "$benchmark_script" >/dev/null || {
    write_failure "failed to refresh benchmark artifact"
    exit 1
  }
fi

if [[ "$refresh_inputs" == "1" || ! -f "$bounded_sha3_result" ]]; then
  bash "$bounded_sha3_script" >/dev/null || {
    write_failure "failed to refresh SHA3 bounded artifact"
    exit 1
  }
fi

if [[ "$refresh_inputs" == "1" || ! -f "$bounded_groth16_result" ]]; then
  bash "$bounded_groth16_script" >/dev/null || {
    write_failure "failed to refresh Groth16 bounded artifact"
    exit 1
  }
fi

if [[ "$refresh_inputs" == "1" || ! -f "$bounded_plonk_result" ]]; then
  bash "$bounded_plonk_script" >/dev/null || {
    write_failure "failed to refresh PLONK bounded artifact"
    exit 1
  }
fi

if [[ "$refresh_inputs" == "1" || ! -f "$full_path_sha3_result" ]]; then
  bash "$full_path_sha3_script" --sha3 >/dev/null || {
    write_failure "failed to refresh SHA3 full-path artifact"
    exit 1
  }
fi

if [[ "$refresh_inputs" == "1" || ! -f "$full_path_groth16_result" ]]; then
  bash "$full_path_groth16_script" --groth16-first >/dev/null || {
    write_failure "failed to refresh Groth16 full-path artifact"
    exit 1
  }
fi

if [[ "$refresh_inputs" == "1" || ! -f "$full_path_plonk_result" ]]; then
  bash "$full_path_plonk_script" --plonk-first >/dev/null || {
    write_failure "failed to refresh PLONK full-path artifact"
    exit 1
  }
fi

if [[ "$refresh_inputs" == "1" || ! -f "$full_path_sha3_four_validator_result" ]]; then
  bash "$full_path_sha3_script" --four-validator >/dev/null || {
    write_failure "failed to refresh SHA3 4-validator full-path artifact"
    exit 1
  }
fi

if [[ "$refresh_inputs" == "1" || ! -f "$full_path_groth16_four_validator_result" ]]; then
  bash "$full_path_groth16_script" --four-validator >/dev/null || {
    write_failure "failed to refresh Groth16 4-validator full-path artifact"
    exit 1
  }
fi

if [[ "$refresh_inputs" == "1" || ! -f "$full_path_plonk_four_validator_result" ]]; then
  bash "$full_path_plonk_script" --four-validator >/dev/null || {
    write_failure "failed to refresh PLONK 4-validator full-path artifact"
    exit 1
  }
fi

if [[ "$refresh_inputs" == "1" || ! -f "$full_path_sha3_six_validator_result" ]]; then
  bash "$full_path_sha3_script" --six-validator >/dev/null || {
    write_failure "failed to refresh SHA3 6-validator full-path artifact"
    exit 1
  }
fi

if [[ "$refresh_inputs" == "1" || ! -f "$full_path_groth16_six_validator_result" ]]; then
  bash "$full_path_groth16_script" --six-validator >/dev/null || {
    write_failure "failed to refresh Groth16 6-validator full-path artifact"
    exit 1
  }
fi

if [[ "$refresh_inputs" == "1" || ! -f "$full_path_plonk_six_validator_result" ]]; then
  bash "$full_path_plonk_script" --six-validator >/dev/null || {
    write_failure "failed to refresh PLONK 6-validator full-path artifact"
    exit 1
  }
fi

if [[ "$refresh_inputs" == "1" || ! -f "$sequence_sha3_result" ]]; then
  bash "$full_path_sha3_script" --three-validator-sequence >/dev/null || {
    write_failure "failed to refresh SHA3 sequence artifact"
    exit 1
  }
fi

if [[ "$refresh_inputs" == "1" || ! -f "$sequence_groth16_result" ]]; then
  bash "$full_path_groth16_script" --three-validator-sequence >/dev/null || {
    write_failure "failed to refresh Groth16 sequence artifact"
    exit 1
  }
fi

if [[ "$refresh_inputs" == "1" || ! -f "$sequence_plonk_result" ]]; then
  bash "$full_path_plonk_script" --three-validator-sequence >/dev/null || {
    write_failure "failed to refresh PLONK sequence artifact"
    exit 1
  }
fi

if [[ "$refresh_inputs" == "1" || ! -f "$sequence_sha3_four_validator_result" ]]; then
  bash "$full_path_sha3_script" --four-validator-sequence >/dev/null || {
    write_failure "failed to refresh SHA3 4-validator sequence artifact"
    exit 1
  }
fi

if [[ "$refresh_inputs" == "1" || ! -f "$sequence_groth16_four_validator_result" ]]; then
  bash "$full_path_groth16_script" --four-validator-sequence >/dev/null || {
    write_failure "failed to refresh Groth16 4-validator sequence artifact"
    exit 1
  }
fi

if [[ "$refresh_inputs" == "1" || ! -f "$sequence_plonk_four_validator_result" ]]; then
  bash "$full_path_plonk_script" --four-validator-sequence >/dev/null || {
    write_failure "failed to refresh PLONK 4-validator sequence artifact"
    exit 1
  }
fi

if [[ "$refresh_inputs" == "1" || ! -f "$sequence_sha3_six_validator_result" ]]; then
  bash "$full_path_sha3_script" --six-validator-sequence >/dev/null || {
    write_failure "failed to refresh SHA3 6-validator sequence artifact"
    exit 1
  }
fi

if [[ "$refresh_inputs" == "1" || ! -f "$sequence_groth16_six_validator_result" ]]; then
  bash "$full_path_groth16_script" --six-validator-sequence >/dev/null || {
    write_failure "failed to refresh Groth16 6-validator sequence artifact"
    exit 1
  }
fi

if [[ "$refresh_inputs" == "1" || ! -f "$sequence_plonk_six_validator_result" ]]; then
  bash "$full_path_plonk_script" --six-validator-sequence >/dev/null || {
    write_failure "failed to refresh PLONK 6-validator sequence artifact"
    exit 1
  }
fi

python3 - \
  "$result_file" \
  "$benchmark_result" \
  "$bounded_sha3_result" \
  "$bounded_groth16_result" \
  "$bounded_plonk_result" \
  "$full_path_sha3_result" \
  "$full_path_groth16_result" \
  "$full_path_plonk_result" \
  "$full_path_sha3_four_validator_result" \
  "$full_path_groth16_four_validator_result" \
  "$full_path_plonk_four_validator_result" \
  "$full_path_sha3_six_validator_result" \
  "$full_path_groth16_six_validator_result" \
  "$full_path_plonk_six_validator_result" \
  "$sequence_sha3_result" \
  "$sequence_groth16_result" \
  "$sequence_plonk_result" \
  "$sequence_sha3_four_validator_result" \
  "$sequence_groth16_four_validator_result" \
  "$sequence_plonk_four_validator_result" \
  "$sequence_sha3_six_validator_result" \
  "$sequence_groth16_six_validator_result" \
  "$sequence_plonk_six_validator_result" \
  "$refresh_inputs" <<'PY'
import json
import pathlib
import sys

result_file = pathlib.Path(sys.argv[1])
benchmark_path = pathlib.Path(sys.argv[2])
bounded_sha3_path = pathlib.Path(sys.argv[3])
bounded_groth16_path = pathlib.Path(sys.argv[4])
bounded_plonk_path = pathlib.Path(sys.argv[5])
full_path_sha3_path = pathlib.Path(sys.argv[6])
full_path_groth16_path = pathlib.Path(sys.argv[7])
full_path_plonk_path = pathlib.Path(sys.argv[8])
full_path_sha3_four_validator_path = pathlib.Path(sys.argv[9])
full_path_groth16_four_validator_path = pathlib.Path(sys.argv[10])
full_path_plonk_four_validator_path = pathlib.Path(sys.argv[11])
full_path_sha3_six_validator_path = pathlib.Path(sys.argv[12])
full_path_groth16_six_validator_path = pathlib.Path(sys.argv[13])
full_path_plonk_six_validator_path = pathlib.Path(sys.argv[14])
sequence_sha3_path = pathlib.Path(sys.argv[15])
sequence_groth16_path = pathlib.Path(sys.argv[16])
sequence_plonk_path = pathlib.Path(sys.argv[17])
sequence_sha3_four_validator_path = pathlib.Path(sys.argv[18])
sequence_groth16_four_validator_path = pathlib.Path(sys.argv[19])
sequence_plonk_four_validator_path = pathlib.Path(sys.argv[20])
sequence_sha3_six_validator_path = pathlib.Path(sys.argv[21])
sequence_groth16_six_validator_path = pathlib.Path(sys.argv[22])
sequence_plonk_six_validator_path = pathlib.Path(sys.argv[23])
refresh_inputs = sys.argv[24] == "1"


def read_json(path: pathlib.Path):
    if not path.exists():
        return None
    return json.loads(path.read_text())


def ensure_passed(errors, label, payload):
    if not isinstance(payload, dict):
        errors.append(f"{label} artifact is missing or malformed")
        return False
    if payload.get("status") != "passed":
        errors.append(f"{label} artifact status is not passed")
        return False
    return True


def summarize_bounded(label, payload, expected_backend):
    quorum = payload.get("quorum", {})
    checkpoint = payload.get("checkpointConsumer", {})
    chain_info = payload.get("consumerSurfaces", {}).get("chainInfo", {})
    dag_info = payload.get("consumerSurfaces", {}).get("dagInfo", {})
    return {
        "backend": payload.get("backend"),
        "expectedBackend": expected_backend,
        "txHash": payload.get("txHash"),
        "voteCount": quorum.get("voteCount"),
        "validatorCount": quorum.get("validatorCount"),
        "quorumThreshold": quorum.get("quorumThreshold"),
        "quorumReached": quorum.get("quorumReached"),
        "checkpointFinalized": checkpoint.get("explorerConfirmationLevel") == "checkpointFinalized",
        "chainInfoDaReady": chain_info.get("dataAvailability", {}).get("consumerReadiness") == "ready",
        "dagInfoLightClientReady": dag_info.get("lightClient", {}).get("consumerReadiness") == "ready",
        "runtimeRecoveryReady": payload.get("runtimeRecovery", {}).get("operatorRestartReady") is True,
        "backendMatches": payload.get("backend") == expected_backend,
    }


def summarize_full_path(label, payload, expected_backend):
    post_restart = payload.get("postRestart", {})
    quorum = post_restart.get("quorum", {})
    checkpoint = post_restart.get("checkpointConsumer", {})
    chain_info = post_restart.get("consumerSurfaces", {}).get("chainInfo", {})
    dag_info = post_restart.get("consumerSurfaces", {}).get("dagInfo", {})
    continuity = payload.get("continuity", {})
    return {
        "backend": payload.get("backend"),
        "expectedBackend": expected_backend,
        "flow": payload.get("flow"),
        "voteCount": quorum.get("voteCount"),
        "validatorCount": quorum.get("validatorCount"),
        "quorumThreshold": quorum.get("quorumThreshold"),
        "quorumReached": quorum.get("quorumReached"),
        "checkpointFinalized": checkpoint.get("explorerConfirmationLevel") == "checkpointFinalized",
        "validatorLifecycleReady": post_restart.get("validatorLifecycleRecovery", {}).get("summary") == "ready",
        "runtimeRecoveryReady": post_restart.get("runtimeRecovery", {}).get("operatorRestartReady") is True,
        "chainInfoDaReady": chain_info.get("dataAvailability", {}).get("consumerReadiness") == "ready",
        "dagInfoLightClientReady": dag_info.get("lightClient", {}).get("consumerReadiness") == "ready",
        "sameTxHash": continuity.get("sameTxHash") is True,
        "sameFinalityBlockHash": continuity.get("sameFinalityBlockHash") is True,
        "sameFinalityBlueScore": continuity.get("sameFinalityBlueScore") is True,
        "sameNullifierSpent": continuity.get("sameNullifierSpent") is True,
        "sameEncryptedNoteTxHash": continuity.get("sameEncryptedNoteTxHash") is True,
        "sameVirtualTip": continuity.get("sameVirtualTip") is True,
        "reloadedFromSnapshot": continuity.get("reloadedFromSnapshot") is True,
        "backendMatches": payload.get("backend") == expected_backend,
    }


def summarize_sequence(label, payload, expected_backend):
    post_restart = payload.get("postRestart", {})
    quorum = post_restart.get("quorum", {})
    checkpoint = post_restart.get("checkpointConsumer", {})
    chain_info = post_restart.get("consumerSurfaces", {}).get("chainInfo", {})
    dag_info = post_restart.get("consumerSurfaces", {}).get("dagInfo", {})
    continuity = payload.get("continuity", {})
    tx_hashes = payload.get("txHashes")
    return {
        "backend": payload.get("backend"),
        "expectedBackend": expected_backend,
        "flow": payload.get("flow"),
        "sequenceDepth": payload.get("sequenceDepth"),
        "txHashCount": len(tx_hashes) if isinstance(tx_hashes, list) else None,
        "voteCount": quorum.get("voteCount"),
        "validatorCount": quorum.get("validatorCount"),
        "quorumThreshold": quorum.get("quorumThreshold"),
        "quorumReached": quorum.get("quorumReached"),
        "checkpointFinalized": checkpoint.get("explorerConfirmationLevel") == "checkpointFinalized",
        "validatorLifecycleReady": post_restart.get("validatorLifecycleRecovery", {}).get("summary") == "ready",
        "runtimeRecoveryReady": post_restart.get("runtimeRecovery", {}).get("operatorRestartReady") is True,
        "chainInfoDaReady": chain_info.get("dataAvailability", {}).get("consumerReadiness") == "ready",
        "dagInfoLightClientReady": dag_info.get("lightClient", {}).get("consumerReadiness") == "ready",
        "sameTxHashes": continuity.get("sameTxHashes") is True,
        "sameFinalityBlockHash": continuity.get("sameFinalityBlockHash") is True,
        "sameFinalityBlueScore": continuity.get("sameFinalityBlueScore") is True,
        "bothNullifiersSpent": continuity.get("bothNullifiersSpent") is True,
        "bothEncryptedNoteTxHashes": continuity.get("bothEncryptedNoteTxHashes") is True,
        "acceptedSequenceDepth": continuity.get("acceptedSequenceDepth") is True,
        "distinctCommittedBlocks": continuity.get("distinctCommittedBlocks") is True,
        "sameVirtualTip": continuity.get("sameVirtualTip") is True,
        "reloadedFromSnapshot": continuity.get("reloadedFromSnapshot") is True,
        "backendMatches": payload.get("backend") == expected_backend,
    }


def all_true(entries, keys):
    return all(bool(entry.get(key)) for entry in entries for key in keys)


benchmark = read_json(benchmark_path)
bounded_sha3 = read_json(bounded_sha3_path)
bounded_groth16 = read_json(bounded_groth16_path)
bounded_plonk = read_json(bounded_plonk_path)
full_path_sha3 = read_json(full_path_sha3_path)
full_path_groth16 = read_json(full_path_groth16_path)
full_path_plonk = read_json(full_path_plonk_path)
full_path_sha3_four_validator = read_json(full_path_sha3_four_validator_path)
full_path_groth16_four_validator = read_json(full_path_groth16_four_validator_path)
full_path_plonk_four_validator = read_json(full_path_plonk_four_validator_path)
full_path_sha3_six_validator = read_json(full_path_sha3_six_validator_path)
full_path_groth16_six_validator = read_json(full_path_groth16_six_validator_path)
full_path_plonk_six_validator = read_json(full_path_plonk_six_validator_path)
sequence_sha3 = read_json(sequence_sha3_path)
sequence_groth16 = read_json(sequence_groth16_path)
sequence_plonk = read_json(sequence_plonk_path)
sequence_sha3_four_validator = read_json(sequence_sha3_four_validator_path)
sequence_groth16_four_validator = read_json(sequence_groth16_four_validator_path)
sequence_plonk_four_validator = read_json(sequence_plonk_four_validator_path)
sequence_sha3_six_validator = read_json(sequence_sha3_six_validator_path)
sequence_groth16_six_validator = read_json(sequence_groth16_six_validator_path)
sequence_plonk_six_validator = read_json(sequence_plonk_six_validator_path)

errors = []
ensure_passed(errors, "benchmark", benchmark)
ensure_passed(errors, "bounded SHA3", bounded_sha3)
ensure_passed(errors, "bounded Groth16", bounded_groth16)
ensure_passed(errors, "bounded PLONK", bounded_plonk)
ensure_passed(errors, "full-path SHA3", full_path_sha3)
ensure_passed(errors, "full-path Groth16", full_path_groth16)
ensure_passed(errors, "full-path PLONK", full_path_plonk)
ensure_passed(errors, "full-path 4-validator SHA3", full_path_sha3_four_validator)
ensure_passed(errors, "full-path 4-validator Groth16", full_path_groth16_four_validator)
ensure_passed(errors, "full-path 4-validator PLONK", full_path_plonk_four_validator)
ensure_passed(errors, "full-path 6-validator SHA3", full_path_sha3_six_validator)
ensure_passed(errors, "full-path 6-validator Groth16", full_path_groth16_six_validator)
ensure_passed(errors, "full-path 6-validator PLONK", full_path_plonk_six_validator)
ensure_passed(errors, "sequence SHA3", sequence_sha3)
ensure_passed(errors, "sequence Groth16", sequence_groth16)
ensure_passed(errors, "sequence PLONK", sequence_plonk)
ensure_passed(errors, "sequence 4-validator SHA3", sequence_sha3_four_validator)
ensure_passed(errors, "sequence 4-validator Groth16", sequence_groth16_four_validator)
ensure_passed(errors, "sequence 4-validator PLONK", sequence_plonk_four_validator)
ensure_passed(errors, "sequence 6-validator SHA3", sequence_sha3_six_validator)
ensure_passed(errors, "sequence 6-validator Groth16", sequence_groth16_six_validator)
ensure_passed(errors, "sequence 6-validator PLONK", sequence_plonk_six_validator)

bounded_entries = [
    summarize_bounded("sha3", bounded_sha3, "sha3"),
    summarize_bounded("groth16", bounded_groth16, "groth16-first"),
    summarize_bounded("plonk", bounded_plonk, "plonk-first"),
]
full_path_entries = [
    summarize_full_path("sha3", full_path_sha3, "sha3"),
    summarize_full_path("groth16", full_path_groth16, "groth16-first"),
    summarize_full_path("plonk", full_path_plonk, "plonk-first"),
]
full_path_four_validator_entries = [
    summarize_full_path("sha3", full_path_sha3_four_validator, "sha3"),
    summarize_full_path("groth16", full_path_groth16_four_validator, "groth16-first"),
    summarize_full_path("plonk", full_path_plonk_four_validator, "plonk-first"),
]
full_path_six_validator_entries = [
    summarize_full_path("sha3", full_path_sha3_six_validator, "sha3"),
    summarize_full_path("groth16", full_path_groth16_six_validator, "groth16-first"),
    summarize_full_path("plonk", full_path_plonk_six_validator, "plonk-first"),
]
sequence_entries = [
    summarize_sequence("sha3", sequence_sha3, "sha3"),
    summarize_sequence("groth16", sequence_groth16, "groth16-first"),
    summarize_sequence("plonk", sequence_plonk, "plonk-first"),
]
sequence_four_validator_entries = [
    summarize_sequence("sha3", sequence_sha3_four_validator, "sha3"),
    summarize_sequence("groth16", sequence_groth16_four_validator, "groth16-first"),
    summarize_sequence("plonk", sequence_plonk_four_validator, "plonk-first"),
]
sequence_six_validator_entries = [
    summarize_sequence("sha3", sequence_sha3_six_validator, "sha3"),
    summarize_sequence("groth16", sequence_groth16_six_validator, "groth16-first"),
    summarize_sequence("plonk", sequence_plonk_six_validator, "plonk-first"),
]

bounded_parity_ready = (
    all(entry.get("backendMatches") for entry in bounded_entries)
    and all(entry.get("voteCount") == 2 for entry in bounded_entries)
    and all(entry.get("validatorCount") == 2 for entry in bounded_entries)
    and all(str(entry.get("quorumThreshold")) == "2" for entry in bounded_entries)
    and all_true(bounded_entries, ("quorumReached", "checkpointFinalized", "chainInfoDaReady", "dagInfoLightClientReady"))
)

full_path_parity_ready = (
    all(entry.get("backendMatches") for entry in full_path_entries)
    and all(entry.get("voteCount") == 2 for entry in full_path_entries)
    and all(entry.get("validatorCount") == 2 for entry in full_path_entries)
    and all(str(entry.get("quorumThreshold")) == "2" for entry in full_path_entries)
    and all_true(full_path_entries, (
        "quorumReached",
        "checkpointFinalized",
        "validatorLifecycleReady",
        "runtimeRecoveryReady",
        "chainInfoDaReady",
        "dagInfoLightClientReady",
        "sameTxHash",
        "sameFinalityBlockHash",
        "sameFinalityBlueScore",
        "sameNullifierSpent",
        "sameEncryptedNoteTxHash",
        "sameVirtualTip",
        "reloadedFromSnapshot",
    ))
)

full_path_four_validator_parity_ready = (
    all(entry.get("backendMatches") for entry in full_path_four_validator_entries)
    and all(entry.get("voteCount") == 4 for entry in full_path_four_validator_entries)
    and all(entry.get("validatorCount") == 4 for entry in full_path_four_validator_entries)
    and all(str(entry.get("quorumThreshold")) == "3" for entry in full_path_four_validator_entries)
    and all_true(full_path_four_validator_entries, (
        "quorumReached",
        "checkpointFinalized",
        "validatorLifecycleReady",
        "runtimeRecoveryReady",
        "chainInfoDaReady",
        "dagInfoLightClientReady",
        "sameTxHash",
        "sameFinalityBlockHash",
        "sameFinalityBlueScore",
        "sameNullifierSpent",
        "sameEncryptedNoteTxHash",
        "sameVirtualTip",
        "reloadedFromSnapshot",
    ))
)

full_path_six_validator_parity_ready = (
    all(entry.get("backendMatches") for entry in full_path_six_validator_entries)
    and all(entry.get("voteCount") == 6 for entry in full_path_six_validator_entries)
    and all(entry.get("validatorCount") == 6 for entry in full_path_six_validator_entries)
    and all(str(entry.get("quorumThreshold")) == "5" for entry in full_path_six_validator_entries)
    and all_true(full_path_six_validator_entries, (
        "quorumReached",
        "checkpointFinalized",
        "validatorLifecycleReady",
        "runtimeRecoveryReady",
        "chainInfoDaReady",
        "dagInfoLightClientReady",
        "sameTxHash",
        "sameFinalityBlockHash",
        "sameFinalityBlueScore",
        "sameNullifierSpent",
        "sameEncryptedNoteTxHash",
        "sameVirtualTip",
        "reloadedFromSnapshot",
    ))
)

sequence_parity_ready = (
    all(entry.get("backendMatches") for entry in sequence_entries)
    and all(entry.get("sequenceDepth") == 2 for entry in sequence_entries)
    and all(entry.get("txHashCount") == 2 for entry in sequence_entries)
    and all(entry.get("voteCount") == 3 for entry in sequence_entries)
    and all(entry.get("validatorCount") == 3 for entry in sequence_entries)
    and all(str(entry.get("quorumThreshold")) == "3" for entry in sequence_entries)
    and all_true(sequence_entries, (
        "quorumReached",
        "checkpointFinalized",
        "validatorLifecycleReady",
        "runtimeRecoveryReady",
        "chainInfoDaReady",
        "dagInfoLightClientReady",
        "sameTxHashes",
        "sameFinalityBlockHash",
        "sameFinalityBlueScore",
        "bothNullifiersSpent",
        "bothEncryptedNoteTxHashes",
        "acceptedSequenceDepth",
        "distinctCommittedBlocks",
        "sameVirtualTip",
        "reloadedFromSnapshot",
    ))
)

sequence_four_validator_parity_ready = (
    all(entry.get("backendMatches") for entry in sequence_four_validator_entries)
    and all(entry.get("sequenceDepth") == 2 for entry in sequence_four_validator_entries)
    and all(entry.get("txHashCount") == 2 for entry in sequence_four_validator_entries)
    and all(entry.get("voteCount") == 4 for entry in sequence_four_validator_entries)
    and all(entry.get("validatorCount") == 4 for entry in sequence_four_validator_entries)
    and all(str(entry.get("quorumThreshold")) == "3" for entry in sequence_four_validator_entries)
    and all_true(sequence_four_validator_entries, (
        "quorumReached",
        "checkpointFinalized",
        "validatorLifecycleReady",
        "runtimeRecoveryReady",
        "chainInfoDaReady",
        "dagInfoLightClientReady",
        "sameTxHashes",
        "sameFinalityBlockHash",
        "sameFinalityBlueScore",
        "bothNullifiersSpent",
        "bothEncryptedNoteTxHashes",
        "acceptedSequenceDepth",
        "distinctCommittedBlocks",
        "sameVirtualTip",
        "reloadedFromSnapshot",
    ))
)

sequence_six_validator_parity_ready = (
    all(entry.get("backendMatches") for entry in sequence_six_validator_entries)
    and all(entry.get("sequenceDepth") == 2 for entry in sequence_six_validator_entries)
    and all(entry.get("txHashCount") == 2 for entry in sequence_six_validator_entries)
    and all(entry.get("voteCount") == 6 for entry in sequence_six_validator_entries)
    and all(entry.get("validatorCount") == 6 for entry in sequence_six_validator_entries)
    and all(str(entry.get("quorumThreshold")) == "5" for entry in sequence_six_validator_entries)
    and all_true(sequence_six_validator_entries, (
        "quorumReached",
        "checkpointFinalized",
        "validatorLifecycleReady",
        "runtimeRecoveryReady",
        "chainInfoDaReady",
        "dagInfoLightClientReady",
        "sameTxHashes",
        "sameFinalityBlockHash",
        "sameFinalityBlueScore",
        "bothNullifiersSpent",
        "bothEncryptedNoteTxHashes",
        "acceptedSequenceDepth",
        "distinctCommittedBlocks",
        "sameVirtualTip",
        "reloadedFromSnapshot",
    ))
)

comparison_ready = (
    not errors
    and bounded_parity_ready
    and full_path_parity_ready
    and full_path_four_validator_parity_ready
    and full_path_six_validator_parity_ready
    and sequence_parity_ready
    and sequence_four_validator_parity_ready
    and sequence_six_validator_parity_ready
)


def benchmark_entry(backend_id):
    benchmark_summaries = benchmark.get("benchmarkSummaries") if isinstance(benchmark, dict) else None
    if not isinstance(benchmark_summaries, dict):
        return {}
    entry = benchmark_summaries.get(backend_id)
    return entry if isinstance(entry, dict) else {}


def build_operator_entry(
    benchmark_id,
    bounded_entry,
    full_path_entry,
    full_path_four_validator_entry,
    full_path_six_validator_entry,
    sequence_entry,
    sequence_four_validator_entry,
    sequence_six_validator_entry,
):
    benchmark_summary = benchmark_entry(benchmark_id)
    benchmark_ready = bool(benchmark_summary) and benchmark_summary.get("verificationPassed") is True
    bounded_ready = all(bool(bounded_entry.get(key)) for key in (
        "backendMatches",
        "quorumReached",
        "checkpointFinalized",
        "chainInfoDaReady",
        "dagInfoLightClientReady",
    ))
    full_path_ready = all(bool(full_path_entry.get(key)) for key in (
        "backendMatches",
        "quorumReached",
        "checkpointFinalized",
        "validatorLifecycleReady",
        "runtimeRecoveryReady",
        "chainInfoDaReady",
        "dagInfoLightClientReady",
        "sameTxHash",
        "sameFinalityBlockHash",
        "sameFinalityBlueScore",
        "sameNullifierSpent",
        "sameEncryptedNoteTxHash",
        "sameVirtualTip",
        "reloadedFromSnapshot",
    ))
    full_path_four_validator_ready = all(bool(full_path_four_validator_entry.get(key)) for key in (
        "backendMatches",
        "quorumReached",
        "checkpointFinalized",
        "validatorLifecycleReady",
        "runtimeRecoveryReady",
        "chainInfoDaReady",
        "dagInfoLightClientReady",
        "sameTxHash",
        "sameFinalityBlockHash",
        "sameFinalityBlueScore",
        "sameNullifierSpent",
        "sameEncryptedNoteTxHash",
        "sameVirtualTip",
        "reloadedFromSnapshot",
    ))
    full_path_six_validator_ready = all(bool(full_path_six_validator_entry.get(key)) for key in (
        "backendMatches",
        "quorumReached",
        "checkpointFinalized",
        "validatorLifecycleReady",
        "runtimeRecoveryReady",
        "chainInfoDaReady",
        "dagInfoLightClientReady",
        "sameTxHash",
        "sameFinalityBlockHash",
        "sameFinalityBlueScore",
        "sameNullifierSpent",
        "sameEncryptedNoteTxHash",
        "sameVirtualTip",
        "reloadedFromSnapshot",
    ))
    sequence_ready = all(bool(sequence_entry.get(key)) for key in (
        "backendMatches",
        "quorumReached",
        "checkpointFinalized",
        "validatorLifecycleReady",
        "runtimeRecoveryReady",
        "chainInfoDaReady",
        "dagInfoLightClientReady",
        "sameTxHashes",
        "sameFinalityBlockHash",
        "sameFinalityBlueScore",
        "bothNullifiersSpent",
        "bothEncryptedNoteTxHashes",
        "acceptedSequenceDepth",
        "distinctCommittedBlocks",
        "sameVirtualTip",
        "reloadedFromSnapshot",
    ))
    sequence_four_validator_ready = all(bool(sequence_four_validator_entry.get(key)) for key in (
        "backendMatches",
        "quorumReached",
        "checkpointFinalized",
        "validatorLifecycleReady",
        "runtimeRecoveryReady",
        "chainInfoDaReady",
        "dagInfoLightClientReady",
        "sameTxHashes",
        "sameFinalityBlockHash",
        "sameFinalityBlueScore",
        "bothNullifiersSpent",
        "bothEncryptedNoteTxHashes",
        "acceptedSequenceDepth",
        "distinctCommittedBlocks",
        "sameVirtualTip",
        "reloadedFromSnapshot",
    ))
    sequence_six_validator_ready = all(bool(sequence_six_validator_entry.get(key)) for key in (
        "backendMatches",
        "quorumReached",
        "checkpointFinalized",
        "validatorLifecycleReady",
        "runtimeRecoveryReady",
        "chainInfoDaReady",
        "dagInfoLightClientReady",
        "sameTxHashes",
        "sameFinalityBlockHash",
        "sameFinalityBlueScore",
        "bothNullifiersSpent",
        "bothEncryptedNoteTxHashes",
        "acceptedSequenceDepth",
        "distinctCommittedBlocks",
        "sameVirtualTip",
        "reloadedFromSnapshot",
    ))

    max_validator_count_proven = 0
    if full_path_six_validator_ready or sequence_six_validator_ready:
        max_validator_count_proven = 6
    elif full_path_four_validator_ready or sequence_four_validator_ready:
        max_validator_count_proven = 4
    elif sequence_ready:
        max_validator_count_proven = 3
    elif full_path_ready or bounded_ready:
        max_validator_count_proven = 2

    return {
        "benchmarkId": benchmark_id,
        "benchmarkReady": benchmark_ready,
        "boundedTwoValidatorReady": bounded_ready,
        "fullPathTwoValidatorReady": full_path_ready,
        "fullPathFourValidatorReady": full_path_four_validator_ready,
        "fullPathSixValidatorReady": full_path_six_validator_ready,
        "sequenceThreeValidatorReady": sequence_ready,
        "sequenceFourValidatorReady": sequence_four_validator_ready,
        "sequenceSixValidatorReady": sequence_six_validator_ready,
        "maxValidatorCountProven": max_validator_count_proven,
        "maxSequenceDepthProven": 2 if sequence_ready else 1 if full_path_ready else 0,
        "proofBytes": benchmark_summary.get("proofBytes"),
        "proofSizeLimit": benchmark_summary.get("proofSizeLimit"),
        "buildMicros": benchmark_summary.get("buildMicros"),
        "verifyMicros": benchmark_summary.get("verifyMicros"),
        "operatorParityReady": (
            benchmark_ready
            and bounded_ready
            and full_path_ready
            and full_path_four_validator_ready
            and full_path_six_validator_ready
            and sequence_ready
            and sequence_four_validator_ready
            and sequence_six_validator_ready
        ),
    }


operator_entries = {
    "sha3": build_operator_entry(
        "sha3-transfer-v2",
        bounded_entries[0],
        full_path_entries[0],
        full_path_four_validator_entries[0],
        full_path_six_validator_entries[0],
        sequence_entries[0],
        sequence_four_validator_entries[0],
        sequence_six_validator_entries[0],
    ),
    "groth16": build_operator_entry(
        "groth16-v1",
        bounded_entries[1],
        full_path_entries[1],
        full_path_four_validator_entries[1],
        full_path_six_validator_entries[1],
        sequence_entries[1],
        sequence_four_validator_entries[1],
        sequence_six_validator_entries[1],
    ),
    "plonk": build_operator_entry(
        "plonk-v1",
        bounded_entries[2],
        full_path_entries[2],
        full_path_four_validator_entries[2],
        full_path_six_validator_entries[2],
        sequence_entries[2],
        sequence_four_validator_entries[2],
        sequence_six_validator_entries[2],
    ),
}


def rank_entries(metric):
    ranked = []
    for label, entry in operator_entries.items():
        value = entry.get(metric)
        if isinstance(value, int):
            ranked.append((label, value))
    ranked.sort(key=lambda item: item[1])
    return [label for label, _ in ranked]


shared_full_path_validator_count = (
    6 if all(entry.get("fullPathSixValidatorReady") for entry in operator_entries.values())
    else
    4 if all(entry.get("fullPathFourValidatorReady") for entry in operator_entries.values())
    else 2 if all(entry.get("fullPathTwoValidatorReady") for entry in operator_entries.values())
    else 0
)
shared_sequence_validator_count = (
    6 if all(entry.get("sequenceSixValidatorReady") for entry in operator_entries.values())
    else
    4 if all(entry.get("sequenceFourValidatorReady") for entry in operator_entries.values())
    else 3 if all(entry.get("sequenceThreeValidatorReady") for entry in operator_entries.values())
    else 0
)
shared_sequence_depth = (
    2 if all(entry.get("maxSequenceDepthProven") >= 2 for entry in operator_entries.values()) else 0
)
operator_decision_ready = comparison_ready and all(
    entry.get("operatorParityReady") for entry in operator_entries.values()
)

payload = {
    "status": "failed" if errors else "passed",
    "artifacts": {
        "benchmarkArtifact": str(benchmark_path),
        "boundedSha3Artifact": str(bounded_sha3_path),
        "boundedGroth16Artifact": str(bounded_groth16_path),
        "boundedPlonkArtifact": str(bounded_plonk_path),
        "fullPathSha3Artifact": str(full_path_sha3_path),
        "fullPathGroth16Artifact": str(full_path_groth16_path),
        "fullPathPlonkArtifact": str(full_path_plonk_path),
        "fullPathSha3FourValidatorArtifact": str(full_path_sha3_four_validator_path),
        "fullPathGroth16FourValidatorArtifact": str(full_path_groth16_four_validator_path),
        "fullPathPlonkFourValidatorArtifact": str(full_path_plonk_four_validator_path),
        "fullPathSha3SixValidatorArtifact": str(full_path_sha3_six_validator_path),
        "fullPathGroth16SixValidatorArtifact": str(full_path_groth16_six_validator_path),
        "fullPathPlonkSixValidatorArtifact": str(full_path_plonk_six_validator_path),
        "sequenceSha3Artifact": str(sequence_sha3_path),
        "sequenceGroth16Artifact": str(sequence_groth16_path),
        "sequencePlonkArtifact": str(sequence_plonk_path),
        "sequenceFourValidatorSha3Artifact": str(sequence_sha3_four_validator_path),
        "sequenceFourValidatorGroth16Artifact": str(sequence_groth16_four_validator_path),
        "sequenceFourValidatorPlonkArtifact": str(sequence_plonk_four_validator_path),
        "sequenceSha3FourValidatorArtifact": str(sequence_sha3_four_validator_path),
        "sequenceGroth16FourValidatorArtifact": str(sequence_groth16_four_validator_path),
        "sequencePlonkFourValidatorArtifact": str(sequence_plonk_four_validator_path),
        "sequenceSha3SixValidatorArtifact": str(sequence_sha3_six_validator_path),
        "sequenceGroth16SixValidatorArtifact": str(sequence_groth16_six_validator_path),
        "sequencePlonkSixValidatorArtifact": str(sequence_plonk_six_validator_path),
    },
    "benchmarkSummary": benchmark.get("benchmarkSummary") if isinstance(benchmark, dict) else None,
    "comparativeBenchmarkSummary": benchmark.get("comparativeBenchmarkSummary") if isinstance(benchmark, dict) else None,
    "benchmarkSummaries": benchmark.get("benchmarkSummaries") if isinstance(benchmark, dict) else None,
    "runtimeComparisonSummary": {
        "bounded": {
            "entries": {
                "sha3": bounded_entries[0],
                "groth16": bounded_entries[1],
                "plonk": bounded_entries[2],
            },
            "parityReady": bounded_parity_ready,
        },
        "fullPath": {
            "entries": {
                "sha3": full_path_entries[0],
                "groth16": full_path_entries[1],
                "plonk": full_path_entries[2],
            },
            "parityReady": full_path_parity_ready,
        },
        "fullPathFourValidator": {
            "entries": {
                "sha3": full_path_four_validator_entries[0],
                "groth16": full_path_four_validator_entries[1],
                "plonk": full_path_four_validator_entries[2],
            },
            "parityReady": full_path_four_validator_parity_ready,
        },
        "fullPathSixValidator": {
            "entries": {
                "sha3": full_path_six_validator_entries[0],
                "groth16": full_path_six_validator_entries[1],
                "plonk": full_path_six_validator_entries[2],
            },
            "parityReady": full_path_six_validator_parity_ready,
        },
        "sequenceThreeValidator": {
            "entries": {
                "sha3": sequence_entries[0],
                "groth16": sequence_entries[1],
                "plonk": sequence_entries[2],
            },
            "parityReady": sequence_parity_ready,
        },
        "sequenceFourValidator": {
            "entries": {
                "sha3": sequence_four_validator_entries[0],
                "groth16": sequence_four_validator_entries[1],
                "plonk": sequence_four_validator_entries[2],
            },
            "parityReady": sequence_four_validator_parity_ready,
        },
        "sequenceSixValidator": {
            "entries": {
                "sha3": sequence_six_validator_entries[0],
                "groth16": sequence_six_validator_entries[1],
                "plonk": sequence_six_validator_entries[2],
            },
            "parityReady": sequence_six_validator_parity_ready,
        },
        "comparisonReady": comparison_ready,
        "refreshedInputs": refresh_inputs,
    },
    "operatorSummary": {
        "backends": operator_entries,
        "sharedBreadth": {
            "boundedValidatorCount": 2 if bounded_parity_ready else 0,
            "fullPathValidatorCount": shared_full_path_validator_count,
            "sequenceValidatorCount": shared_sequence_validator_count,
            "sequenceDepth": shared_sequence_depth,
        },
        "rankings": {
            "proofBytesAscending": rank_entries("proofBytes"),
            "buildMicrosAscending": rank_entries("buildMicros"),
            "verifyMicrosAscending": rank_entries("verifyMicros"),
        },
        "comparisonReady": comparison_ready,
        "operatorDecisionReady": operator_decision_ready,
        "recommendedNextAction": (
            "advance broader integration beyond six-validator parity"
            if operator_decision_ready
            else "fix missing or drifted backend parity before operator comparison"
        ),
    },
    "runbookReadiness": {
        "boundedParityReady": bounded_parity_ready,
        "fullPathParityReady": full_path_parity_ready,
        "fullPathFourValidatorParityReady": full_path_four_validator_parity_ready,
        "fullPathSixValidatorParityReady": full_path_six_validator_parity_ready,
        "sequenceParityReady": sequence_parity_ready,
        "sequenceThreeValidatorParityReady": sequence_parity_ready,
        "sequenceFourValidatorParityReady": sequence_four_validator_parity_ready,
        "sequenceSixValidatorParityReady": sequence_six_validator_parity_ready,
        "comparisonReady": comparison_ready,
        "operatorDecisionReady": operator_decision_ready,
        "refreshedInputs": refresh_inputs,
    },
    "recommendedNextAction": (
        "extend comparative proof beyond six-validator breadth"
        if operator_decision_ready
        else "fix missing or drifted runtime comparison artifacts"
    ),
}

if errors:
    payload["errors"] = errors

result_file.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n")
sys.exit(1 if errors else 0)
PY

printf 'wrote %s\n' "$result_file"
