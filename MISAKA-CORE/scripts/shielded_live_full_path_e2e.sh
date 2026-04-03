#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
state_dir="${MISAKA_SHIELDED_FULL_PATH_E2E_DIR:-}"
result_file="${MISAKA_SHIELDED_FULL_PATH_E2E_RESULT:-}"
target_dir="${MISAKA_CARGO_TARGET_DIR:-$repo_root/.tmp/shielded-full-path-e2e-target}"
mode="${MISAKA_SHIELDED_FULL_PATH_E2E_MODE:-sha3-three-validator}"

if [[ "$target_dir" != /* ]]; then
  target_dir="$repo_root/$target_dir"
fi

usage() {
  cat <<'EOF'
Usage: ./scripts/shielded_live_full_path_e2e.sh
Usage: ./scripts/shielded_live_full_path_e2e.sh --three-validator
Usage: ./scripts/shielded_live_full_path_e2e.sh --three-validator-sequence
Usage: ./scripts/shielded_live_full_path_e2e.sh --four-validator
Usage: ./scripts/shielded_live_full_path_e2e.sh --four-validator-sequence
Usage: ./scripts/shielded_live_full_path_e2e.sh --five-validator
Usage: ./scripts/shielded_live_full_path_e2e.sh --five-validator-sequence
Usage: ./scripts/shielded_live_full_path_e2e.sh --six-validator
Usage: ./scripts/shielded_live_full_path_e2e.sh --six-validator-sequence

Runs the shielded live full-path restart continuity E2E and writes:

  .tmp/shielded-full-path-e2e/result.json

Optional env:
  MISAKA_SHIELDED_FULL_PATH_E2E_MODE=sha3|sha3-three-validator|sha3-three-validator-sequence|sha3-four-validator|sha3-four-validator-sequence|sha3-five-validator|sha3-five-validator-sequence|sha3-six-validator|sha3-six-validator-sequence
  MISAKA_SHIELDED_FULL_PATH_E2E_DIR=/custom/output/dir
  MISAKA_SHIELDED_FULL_PATH_E2E_RESULT=/custom/result.json
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
elif [[ "${1:-}" == "--three-validator-sequence" ]]; then
  mode="sha3-three-validator-sequence"
  shift
elif [[ "${1:-}" == "--four-validator" ]]; then
  mode="sha3-four-validator"
  shift
elif [[ "${1:-}" == "--four-validator-sequence" ]]; then
  mode="sha3-four-validator-sequence"
  shift
elif [[ "${1:-}" == "--five-validator" ]]; then
  mode="sha3-five-validator"
  shift
elif [[ "${1:-}" == "--five-validator-sequence" ]]; then
  mode="sha3-five-validator-sequence"
  shift
elif [[ "${1:-}" == "--six-validator" ]]; then
  mode="sha3-six-validator"
  shift
elif [[ "${1:-}" == "--six-validator-sequence" ]]; then
  mode="sha3-six-validator-sequence"
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
    test_filter="live_shielded_submit_transfer_full_path_restart_continuity_through_real_dag_rpc_commit_and_checkpoint_consumer"
    expected_flow="live_submit_transfer_restart_continuity_full_path"
    expected_vote_count="2"
    expected_quorum_threshold="2"
    ;;
  sha3-three-validator)
    test_filter="live_shielded_submit_transfer_full_path_restart_continuity_through_three_validator_real_dag_rpc_commit_and_checkpoint_consumer"
    expected_flow="live_submit_transfer_three_validator_restart_continuity_full_path"
    expected_vote_count="3"
    expected_quorum_threshold="3"
    ;;
  sha3-three-validator-sequence)
    test_filter="live_shielded_submit_transfer_sequence_full_path_restart_continuity_through_three_validator_real_dag_rpc_commit_and_checkpoint_consumer"
    expected_flow="live_submit_transfer_three_validator_restart_continuity_full_path_sequence"
    expected_vote_count="3"
    expected_quorum_threshold="3"
    ;;
  sha3-four-validator)
    test_filter="live_shielded_submit_transfer_full_path_restart_continuity_through_four_validator_real_dag_rpc_commit_and_checkpoint_consumer"
    expected_flow="live_submit_transfer_four_validator_restart_continuity_full_path"
    expected_vote_count="4"
    expected_quorum_threshold="3"
    ;;
  sha3-four-validator-sequence)
    test_filter="live_shielded_submit_transfer_sequence_full_path_restart_continuity_through_four_validator_real_dag_rpc_commit_and_checkpoint_consumer"
    expected_flow="live_submit_transfer_four_validator_restart_continuity_full_path_sequence"
    expected_vote_count="4"
    expected_quorum_threshold="3"
    ;;
  sha3-five-validator)
    test_filter="live_shielded_submit_transfer_full_path_restart_continuity_through_five_validator_real_dag_rpc_commit_and_checkpoint_consumer"
    expected_flow="live_submit_transfer_five_validator_restart_continuity_full_path"
    expected_vote_count="5"
    expected_quorum_threshold="4"
    ;;
  sha3-five-validator-sequence)
    test_filter="live_shielded_submit_transfer_sequence_full_path_restart_continuity_through_five_validator_real_dag_rpc_commit_and_checkpoint_consumer"
    expected_flow="live_submit_transfer_five_validator_restart_continuity_full_path_sequence"
    expected_vote_count="5"
    expected_quorum_threshold="4"
    ;;
  sha3-six-validator)
    test_filter="live_shielded_submit_transfer_full_path_restart_continuity_through_six_validator_real_dag_rpc_commit_and_checkpoint_consumer"
    expected_flow="live_submit_transfer_six_validator_restart_continuity_full_path"
    expected_vote_count="6"
    expected_quorum_threshold="5"
    ;;
  sha3-six-validator-sequence)
    test_filter="live_shielded_submit_transfer_sequence_full_path_restart_continuity_through_six_validator_real_dag_rpc_commit_and_checkpoint_consumer"
    expected_flow="live_submit_transfer_six_validator_restart_continuity_full_path_sequence"
    expected_vote_count="6"
    expected_quorum_threshold="5"
    ;;
  *)
    write_failure "unsupported full-path E2E mode: $mode"
    exit 1
    ;;
esac

if [[ -z "$state_dir" && -z "$result_file" ]]; then
  case "$mode" in
    sha3)
      state_dir="$repo_root/.tmp/shielded-full-path-e2e"
      ;;
    sha3-three-validator)
      state_dir="$repo_root/.tmp/shielded-full-path-e2e-3v"
      ;;
    sha3-three-validator-sequence)
      state_dir="$repo_root/.tmp/shielded-full-path-e2e-3v-seq"
      ;;
    sha3-four-validator)
      state_dir="$repo_root/.tmp/shielded-full-path-e2e-4v"
      ;;
    sha3-four-validator-sequence)
      state_dir="$repo_root/.tmp/shielded-full-path-e2e-4v-seq"
      ;;
    sha3-five-validator)
      state_dir="$repo_root/.tmp/shielded-full-path-e2e-5v"
      ;;
    sha3-five-validator-sequence)
      state_dir="$repo_root/.tmp/shielded-full-path-e2e-5v-seq"
      ;;
    sha3-six-validator)
      state_dir="$repo_root/.tmp/shielded-full-path-e2e-6v"
      ;;
    sha3-six-validator-sequence)
      state_dir="$repo_root/.tmp/shielded-full-path-e2e-6v-seq"
      ;;
  esac
  result_file="$state_dir/result.json"
elif [[ -z "$state_dir" ]]; then
  state_dir="$(dirname "$result_file")"
elif [[ -z "$result_file" ]]; then
  result_file="$state_dir/result.json"
fi

if [[ "$state_dir" != /* ]]; then
  state_dir="$repo_root/$state_dir"
fi
if [[ "$result_file" != /* ]]; then
  result_file="$repo_root/$result_file"
fi
log_file="$state_dir/cargo-test.log"

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
export MISAKA_SHIELDED_FULL_PATH_E2E_RESULT="$result_file"
rm -f "$result_file"

cd "$repo_root"

if ! cargo test -p misaka-node --bin misaka-node \
  "$test_filter" \
  --features qdag_ct \
  -- --nocapture >"$log_file" 2>&1; then
  write_failure "live shielded DAG RPC full-path E2E regression failed ($mode)"
  cat "$log_file" >&2
  exit 1
fi

if [[ ! -f "$result_file" ]]; then
  write_failure "live shielded DAG RPC full-path E2E regression passed but did not emit result artifact ($mode)"
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
pre_restart = data.get("preRestart", {})
post_restart = data.get("postRestart", {})
artifacts = data.get("artifacts", {})
pre_pending = pre_restart.get("pending", {})
pre_committed = pre_restart.get("committed", {})
pre_committed_status = pre_committed.get("txStatus", {})
post_lookup = post_restart.get("lookup", {})
post_lookup_status = post_lookup.get("txStatus", {})
post_summary = post_restart.get("summary", {})
tx_hash = post_lookup.get("txHash") or post_summary.get("txHash") or pre_pending.get("txHash")
committed_block_hash = post_lookup_status.get("blockHash") or pre_committed_status.get("blockHash")
committed_block_blue_score = post_lookup_status.get("blockBlueScore")
summary_block_height = post_summary.get("blockHeight")
restart_continuity = data.get("continuity", {})
post_shielded = post_restart.get("shieldedReadPlane", {})
post_nullifier_status = post_shielded.get("nullifierStatus", {})
post_encrypted_notes = post_shielded.get("encryptedNotes", {})
matching_note = None
for entry in post_encrypted_notes.get("notes", []):
    if entry.get("tx_hash") == tx_hash and entry.get("block_height") == summary_block_height:
        matching_note = entry
        break
accepted_tx = None
for chain_entry in post_restart.get("virtualChain", {}).get("acceptanceData", []):
    for tx_result in chain_entry.get("txResults", []):
        if tx_result.get("txHash") == tx_hash and tx_result.get("accepted") is True:
            accepted_tx = tx_result
            break
    if accepted_tx is not None:
        break
post_virtual_state = post_restart.get("virtualState", {})
post_virtual_stats = post_virtual_state.get("stats", {})
if mode in {
    "sha3-three-validator-sequence",
    "sha3-four-validator-sequence",
    "sha3-five-validator-sequence",
    "sha3-six-validator-sequence",
}:
    tx_hashes = data.get("txHashes", [])
    pre_sequence = pre_restart.get("sequence", [])
    post_sequence = post_restart.get("sequence", [])
    post_shielded_notes = post_shielded.get("encryptedNotes", {}).get("notes", [])
    post_accepted_hashes = post_shielded.get("acceptedTxHashes", [])
    sequence_indices = []
    for expected_index, (tx_hash, post_item) in enumerate(zip(tx_hashes, post_sequence), start=1):
        summary = post_item.get("summary", {})
        lookup = post_item.get("lookup", {})
        summary_block_height = summary.get("blockHeight")
        match_index = None
        for idx, note in enumerate(post_shielded_notes):
            if note.get("tx_hash") == tx_hash and note.get("block_height") == summary_block_height:
                match_index = idx
                break
        sequence_indices.append(match_index)
    required = [
        data.get("status") == "passed",
        data.get("flow") == expected_flow,
        data.get("sequenceDepth") == 2,
        len(tx_hashes) == 2,
        len(set(tx_hashes)) == 2,
        len(pre_sequence) == 2,
        len(post_sequence) == 2,
        all(item.get("index") == idx for idx, item in enumerate(pre_sequence, start=1)),
        all(item.get("index") == idx for idx, item in enumerate(post_sequence, start=1)),
        all(pre_sequence[idx].get("pending", {}).get("txHash") == tx_hashes[idx] for idx in range(2)),
        all(post_sequence[idx].get("lookup", {}).get("txHash") == tx_hashes[idx] for idx in range(2)),
        all(post_sequence[idx].get("summary", {}).get("txHash") == tx_hashes[idx] for idx in range(2)),
        all(post_sequence[idx].get("summary", {}).get("status") == "confirmed" for idx in range(2)),
        all(post_sequence[idx].get("lookup", {}).get("txStatus", {}).get("status") == "finalized" for idx in range(2)),
        post_restart.get("checkpointConsumer", {}).get("explorerConfirmationLevel") == "checkpointFinalized",
        post_restart.get("quorum", {}).get("voteCount") == expected_vote_count,
        str(post_restart.get("quorum", {}).get("quorumThreshold")) == expected_quorum_threshold,
        post_restart.get("quorum", {}).get("quorumReached") is True,
        post_restart.get("quorum", {}).get("validatorCount") == expected_vote_count,
        post_restart.get("consumerSurfaces", {}).get("chainInfo", {}).get("dataAvailability", {}).get("consumerReadiness") == "ready",
        post_restart.get("consumerSurfaces", {}).get("chainInfo", {}).get("lightClient", {}).get("txLookupKey") == "txHash",
        post_restart.get("consumerSurfaces", {}).get("dagInfo", {}).get("dataAvailability", {}).get("consumerReadiness") == "ready",
        post_restart.get("consumerSurfaces", {}).get("dagInfo", {}).get("lightClient", {}).get("txLookupKey") == "txHash",
        post_restart.get("runtimeRecovery", {}).get("startupSnapshotRestored") is True,
        post_restart.get("runtimeRecovery", {}).get("operatorRestartReady") is True,
        post_restart.get("validatorLifecycleRecovery", {}).get("summary") == "ready",
        post_restart.get("validatorLifecycleRecovery", {}).get("restartReady") is True,
        post_restart.get("validatorLifecycleRecovery", {}).get("checkpointPersisted") is True,
        post_restart.get("validatorLifecycleRecovery", {}).get("checkpointFinalized") is True,
        restart_continuity.get("sameTxHashes") is True,
        restart_continuity.get("sameFinalityBlockHash") is True,
        restart_continuity.get("sameFinalityBlueScore") is True,
        restart_continuity.get("bothNullifiersSpent") is True,
        restart_continuity.get("bothEncryptedNoteTxHashes") is True,
        restart_continuity.get("acceptedSequenceDepth") is True,
        restart_continuity.get("distinctCommittedBlocks") is True,
        restart_continuity.get("sameVirtualTip") is True,
        restart_continuity.get("reloadedFromSnapshot") is True,
        post_accepted_hashes == tx_hashes,
        all(index is not None for index in sequence_indices),
        sequence_indices[0] < sequence_indices[1],
        pathlib.Path(artifacts.get("validatorLifecycleSnapshot", "")).exists(),
    ]
    if not all(required):
        raise SystemExit(f"live shielded DAG RPC full-path E2E artifact is incomplete ({mode})")
    print(result_path)
    raise SystemExit(0)
required = [
    data.get("status") == "passed",
    data.get("flow") == expected_flow,
    isinstance(tx_hash, str) and len(tx_hash) == 64,
    pre_pending.get("txHash") == tx_hash,
    post_lookup.get("txHash") == tx_hash,
    pre_pending.get("txStatus", {}).get("status") == "pending",
    post_summary.get("status") == "confirmed",
    post_restart.get("checkpointConsumer", {}).get("explorerConfirmationLevel") == "checkpointFinalized",
    post_restart.get("quorum", {}).get("voteCount") == expected_vote_count,
    str(post_restart.get("quorum", {}).get("quorumThreshold")) == expected_quorum_threshold,
    post_restart.get("quorum", {}).get("quorumReached") is True,
    post_restart.get("attestation", {}).get("finalityBlockHash") == committed_block_hash,
    post_restart.get("attestation", {}).get("finalityBlueScore") == committed_block_blue_score,
    post_restart.get("consumerSurfaces", {}).get("chainInfo", {}).get("dataAvailability", {}).get("consumerReadiness") == "ready",
    post_restart.get("consumerSurfaces", {}).get("chainInfo", {}).get("lightClient", {}).get("txLookupKey") == "txHash",
    post_restart.get("consumerSurfaces", {}).get("dagInfo", {}).get("dataAvailability", {}).get("consumerReadiness") == "ready",
    post_restart.get("consumerSurfaces", {}).get("dagInfo", {}).get("lightClient", {}).get("txLookupKey") == "txHash",
    post_restart.get("runtimeRecovery", {}).get("startupSnapshotRestored") is True,
    post_restart.get("runtimeRecovery", {}).get("operatorRestartReady") is True,
    post_restart.get("validatorLifecycleRecovery", {}).get("summary") == "ready",
    post_restart.get("validatorLifecycleRecovery", {}).get("restartReady") is True,
    post_restart.get("validatorLifecycleRecovery", {}).get("checkpointPersisted") is True,
    post_restart.get("validatorLifecycleRecovery", {}).get("checkpointFinalized") is True,
    restart_continuity.get("sameTxHash") is True,
    restart_continuity.get("sameFinalityBlockHash") is True,
    restart_continuity.get("sameFinalityBlueScore") is True,
    restart_continuity.get("sameNullifierSpent") is True,
    restart_continuity.get("sameEncryptedNoteTxHash") is True,
    restart_continuity.get("sameVirtualTip") is True,
    restart_continuity.get("reloadedFromSnapshot") is True,
    post_nullifier_status.get("tx_hash") == tx_hash,
    matching_note is not None,
    accepted_tx is not None,
    post_virtual_state.get("tip") == committed_block_hash,
    post_virtual_state.get("tipScore") == committed_block_blue_score,
    isinstance(post_virtual_state.get("stateRoot"), str) and len(post_virtual_state.get("stateRoot")) == 64,
    int(post_virtual_stats.get("reorgs", 0)) >= 0,
    int(post_restart.get("validatorLifecycleRecovery", {}).get("voteCount", expected_vote_count)) == expected_vote_count,
    post_restart.get("runtimeRecovery", {}).get("lastCheckpointBlueScore") == committed_block_blue_score,
    post_restart.get("runtimeRecovery", {}).get("lastCheckpointBlockHash") == committed_block_hash,
    post_restart.get("runtimeRecovery", {}).get("lastCheckpointFinalityBlueScore") == committed_block_blue_score,
    post_lookup.get("txHash") == tx_hash,
    post_lookup_status.get("status") == "finalized",
    summary_block_height is not None,
    pathlib.Path(artifacts.get("validatorLifecycleSnapshot", "")).exists(),
]
if mode == "sha3-three-validator":
    required.extend([
        data.get("postRestart", {}).get("quorum", {}).get("validatorCount") == expected_vote_count,
    ])
elif mode == "sha3-four-validator":
    required.extend([
        data.get("postRestart", {}).get("quorum", {}).get("validatorCount") == expected_vote_count,
    ])
elif mode == "sha3-five-validator":
    required.extend([
        data.get("postRestart", {}).get("quorum", {}).get("validatorCount") == expected_vote_count,
    ])
elif mode == "sha3-six-validator":
    required.extend([
        data.get("postRestart", {}).get("quorum", {}).get("validatorCount") == expected_vote_count,
    ])
if not all(required):
    raise SystemExit(f"live shielded DAG RPC full-path E2E artifact is incomplete ({mode})")
print(result_path)
PY
