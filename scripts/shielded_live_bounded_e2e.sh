#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
state_dir="${MISAKA_SHIELDED_LIVE_BOUNDED_E2E_DIR:-$repo_root/.tmp/shielded-live-bounded-e2e}"
result_file="${MISAKA_SHIELDED_LIVE_BOUNDED_E2E_RESULT:-$state_dir/result.json}"
log_file="$state_dir/cargo-test.log"
target_dir="${MISAKA_CARGO_TARGET_DIR:-$repo_root/.tmp/shielded-live-bounded-e2e-target}"
mode="${MISAKA_SHIELDED_LIVE_BOUNDED_E2E_MODE:-sha3}"

if [[ "$state_dir" != /* ]]; then
  state_dir="$repo_root/$state_dir"
fi
if [[ "$result_file" != /* ]]; then
  result_file="$repo_root/$result_file"
fi
if [[ "$target_dir" != /* ]]; then
  target_dir="$repo_root/$target_dir"
fi
log_file="$state_dir/cargo-test.log"

usage() {
  cat <<'EOF'
Usage: ./scripts/shielded_live_bounded_e2e.sh
Usage: ./scripts/shielded_live_bounded_e2e.sh --three-validator

Runs the live in-process shielded DAG RPC bounded E2E and writes:

  .tmp/shielded-live-bounded-e2e/result.json

Optional env:
  MISAKA_SHIELDED_LIVE_BOUNDED_E2E_MODE=sha3|sha3-three-validator
  MISAKA_SHIELDED_LIVE_BOUNDED_E2E_DIR=/custom/output/dir
  MISAKA_SHIELDED_LIVE_BOUNDED_E2E_RESULT=/custom/result.json
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

if [[ "${1:-}" == "--three-validator" ]]; then
  mode="sha3-three-validator"
  shift
elif [[ "${1:-}" == "--sha3" ]]; then
  mode="sha3"
  shift
fi

if [[ $# -gt 0 ]]; then
  usage >&2
  exit 1
fi

case "$mode" in
  sha3)
    test_filter="live_shielded_submit_transfer_tx_hash_continuity_through_real_dag_rpc_commit_and_checkpoint_consumer"
    expected_flow="live_submit_transfer_pending_ordered_confirmed_checkpoint"
    expected_vote_count="2"
    expected_quorum_threshold="2"
    ;;
  sha3-three-validator)
    test_filter="live_shielded_submit_transfer_tx_hash_continuity_through_three_validator_real_dag_rpc_commit_and_checkpoint_consumer"
    expected_flow="live_submit_transfer_three_validator_pending_ordered_confirmed_checkpoint"
    expected_vote_count="3"
    expected_quorum_threshold="3"
    ;;
  *)
    write_failure "unsupported bounded E2E mode: $mode"
    exit 1
    ;;
esac

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
export MISAKA_SHIELDED_BOUNDED_E2E_RESULT="$result_file"
rm -f "$result_file"

cd "$repo_root"

if ! cargo test -p misaka-node --bin misaka-node \
  "$test_filter" \
  -- --nocapture >"$log_file" 2>&1; then
  write_failure "live shielded DAG RPC bounded E2E regression failed ($mode)"
  cat "$log_file" >&2
  exit 1
fi

if [[ ! -f "$result_file" ]]; then
  write_failure "live shielded DAG RPC bounded E2E regression passed but did not emit result artifact ($mode)"
  exit 1
fi

python3 - "$result_file" "$mode" "$expected_flow" "$expected_vote_count" "$expected_quorum_threshold" <<'PY'
import json
import pathlib
import sys

result_path = pathlib.Path(sys.argv[1])
mode = sys.argv[2]
expected_flow = sys.argv[3]
expected_vote_count = int(sys.argv[4])
expected_quorum_threshold = sys.argv[5]
data = json.loads(result_path.read_text(encoding="utf-8"))
tx_hash = data.get("txHash")
artifacts = data.get("artifacts", {})
committed_status = data.get("committed", {}).get("txStatus", {})
committed_block_hash = committed_status.get("blockHash")
committed_block_blue_score = committed_status.get("blockBlueScore")
confirmed_block_height = data.get("summary", {}).get("blockHeight")
required = [
    data.get("status") == "passed",
    data.get("flow") == expected_flow,
    isinstance(tx_hash, str) and len(tx_hash) == 64,
    data.get("pending", {}).get("txHash") == tx_hash,
    data.get("pending", {}).get("txStatus", {}).get("status") == "pending",
    data.get("pending", {}).get("txStatus", {}).get("admissionPath") == "zeroKnowledge",
    data.get("committed", {}).get("txHash") == tx_hash,
    data.get("committed", {}).get("txStatus", {}).get("status") in {"ordered", "finalized"},
    data.get("summary", {}).get("txHash") == tx_hash,
    data.get("summary", {}).get("status") == "confirmed",
    data.get("checkpointConsumer", {}).get("explorerConfirmationLevel") == "checkpointFinalized",
    data.get("quorum", {}).get("voteCount") == expected_vote_count,
    str(data.get("quorum", {}).get("quorumThreshold")) == expected_quorum_threshold,
    data.get("quorum", {}).get("quorumReached") is True,
    data.get("attestation", {}).get("chainInfoLatestCheckpointBlockHash") == committed_block_hash,
    data.get("attestation", {}).get("dagInfoLatestCheckpointBlockHash") == committed_block_hash,
    data.get("attestation", {}).get("finalityBlockHash") == committed_block_hash,
    data.get("attestation", {}).get("chainInfoLatestCheckpointBlueScore") == committed_block_blue_score,
    data.get("attestation", {}).get("dagInfoLatestCheckpointBlueScore") == committed_block_blue_score,
    data.get("attestation", {}).get("finalityBlueScore") == committed_block_blue_score,
    data.get("attestation", {}).get("finalityCommitCount") == expected_vote_count,
    data.get("attestation", {}).get("voteVoterCount") == expected_vote_count,
    data.get("attestation", {}).get("knownValidatorCount") == expected_vote_count,
    data.get("consumerSurfaces", {}).get("chainInfo", {}).get("dataAvailability", {}).get("consumerReadiness") == "ready",
    data.get("consumerSurfaces", {}).get("chainInfo", {}).get("lightClient", {}).get("txLookupKey") == "txHash",
    data.get("consumerSurfaces", {}).get("dagInfo", {}).get("dataAvailability", {}).get("consumerReadiness") == "ready",
    data.get("consumerSurfaces", {}).get("dagInfo", {}).get("lightClient", {}).get("txLookupKey") == "txHash",
    data.get("runtimeRecovery", {}).get("available") is True,
    data.get("runtimeRecovery", {}).get("snapshotExists") is True,
    data.get("runtimeRecovery", {}).get("lastCheckpointBlueScore") == committed_block_blue_score,
    data.get("runtimeRecovery", {}).get("lastCheckpointBlockHash") == committed_block_hash,
    data.get("runtimeRecovery", {}).get("lastCheckpointFinalityBlueScore") == committed_block_blue_score,
    data.get("validatorLifecycleRecovery", {}).get("summary") == "ready",
    data.get("validatorLifecycleRecovery", {}).get("restartReady") is True,
    data.get("validatorLifecycleRecovery", {}).get("checkpointPersisted") is True,
    data.get("validatorLifecycleRecovery", {}).get("checkpointFinalized") is True,
    data.get("validatorLifecycleRecovery", {}).get("startupSnapshotRestored") is True,
    data.get("validatorLifecycleRecovery", {}).get("lastCheckpointBlueScore") == committed_block_blue_score,
    data.get("validatorLifecycleRecovery", {}).get("lastCheckpointBlockHash") == committed_block_hash,
    data.get("validatorLifecycleRecovery", {}).get("lastCheckpointFinalityBlueScore") == committed_block_blue_score,
    data.get("shieldedReadPlane", {}).get("rootBefore", {}).get("root") == data.get("shieldedReadPlane", {}).get("anchorRoot"),
    data.get("shieldedReadPlane", {}).get("rootBefore", {}).get("commitmentCount") == 1,
    data.get("shieldedReadPlane", {}).get("rootBefore", {}).get("nullifierCount") == 0,
    data.get("shieldedReadPlane", {}).get("rootAfter", {}).get("root") != data.get("shieldedReadPlane", {}).get("anchorRoot"),
    data.get("shieldedReadPlane", {}).get("rootAfter", {}).get("commitmentCount") == 2,
    data.get("shieldedReadPlane", {}).get("rootAfter", {}).get("nullifierCount") == 1,
    data.get("shieldedReadPlane", {}).get("nullifierStatusBefore", {}).get("nullifier") == data.get("shieldedReadPlane", {}).get("expectedNullifier"),
    data.get("shieldedReadPlane", {}).get("nullifierStatusBefore", {}).get("spent") is False,
    data.get("shieldedReadPlane", {}).get("nullifierStatusBefore", {}).get("blockHeight") is None,
    data.get("shieldedReadPlane", {}).get("nullifierStatusBefore", {}).get("txHash") is None,
    data.get("shieldedReadPlane", {}).get("nullifierStatusAfter", {}).get("nullifier") == data.get("shieldedReadPlane", {}).get("expectedNullifier"),
    data.get("shieldedReadPlane", {}).get("nullifierStatusAfter", {}).get("spent") is True,
    data.get("shieldedReadPlane", {}).get("nullifierStatusAfter", {}).get("txHash") == tx_hash,
    data.get("shieldedReadPlane", {}).get("nullifierStatusAfter", {}).get("blockHeight") == confirmed_block_height,
    int(data.get("shieldedReadPlane", {}).get("encryptedNotes", {}).get("noteCount", 0)) >= 1,
    data.get("shieldedReadPlane", {}).get("encryptedNotes", {}).get("matchingNoteTxHash") == tx_hash,
    data.get("shieldedReadPlane", {}).get("encryptedNotes", {}).get("matchingNoteBlockHeight") == confirmed_block_height,
    data.get("shieldedReadPlane", {}).get("encryptedNotes", {}).get("hasMore") is False,
    (
        data.get("shieldedReadPlane", {}).get("encryptedNotes", {}).get("nextFromBlock") >= confirmed_block_height + 1
        if isinstance(confirmed_block_height, int)
        and isinstance(data.get("shieldedReadPlane", {}).get("encryptedNotes", {}).get("nextFromBlock"), int)
        else False
    ),
    data.get("virtualChain", {}).get("acceptedTxHash") == tx_hash,
    data.get("virtualChain", {}).get("accepted") is True,
    data.get("virtualChain", {}).get("committedBlockPresent") is True,
    data.get("incrementalVirtualChain", {}).get("virtualTip") == committed_block_hash,
    data.get("incrementalVirtualChain", {}).get("addedChainHashes") == [],
    data.get("incrementalVirtualChain", {}).get("removedChainHashes") == [],
    data.get("incrementalVirtualChain", {}).get("acceptanceData") == [],
    data.get("virtualState", {}).get("tip") == committed_block_hash,
    data.get("virtualState", {}).get("tipScore") == committed_block_blue_score,
    isinstance(data.get("virtualState", {}).get("stateRoot"), str) and len(data.get("virtualState", {}).get("stateRoot")) == 64,
    int(data.get("virtualState", {}).get("blocksApplied", 0)) >= 1,
    int(data.get("virtualState", {}).get("reorgs", -1)) == 0,
    int(data.get("virtualState", {}).get("deepestReorg", -1)) == 0,
    pathlib.Path(artifacts.get("shieldedStateSnapshot", "")).exists(),
    pathlib.Path(artifacts.get("dagRuntimeSnapshot", "")).exists(),
]
if mode == "groth16-first":
    module_status = data.get("moduleStatus", {})
    layer4 = module_status.get("layer4_status", {})
    verifier_contract = layer4.get("verifierContract", {})
    accepted_circuit_versions = module_status.get("accepted_circuit_versions", [])
    required.extend(
        [
            data.get("backend") == "groth16-first",
            100 in accepted_circuit_versions,
            layer4.get("groth16PlonkReady") is True,
            verifier_contract.get("authoritativeTarget") == "groth16",
            verifier_contract.get("authoritativeTargetReady") is True,
            any(
                entry.get("backendId") == "groth16-v1"
                for entry in layer4.get("registeredBackends", [])
            ),
        ]
    )
if not all(required):
    raise SystemExit(f"live shielded DAG RPC bounded E2E artifact is incomplete ({mode})")
print(result_path)
PY
