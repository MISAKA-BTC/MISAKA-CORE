#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

state_dir="${MISAKA_SHIELDED_STATUS_DIR:-$repo_root/.tmp/shielded-module-status-snapshot}"
result_file="$state_dir/result.json"
node_base="${MISAKA_NODE_RPC_BASE:-http://127.0.0.1:8080}"
inventory_script="$repo_root/scripts/shielded_backend_inventory.sh"
inventory_result="${MISAKA_BACKEND_INVENTORY_RESULT:-$repo_root/.tmp/shielded-backend-inventory/result.json}"
vk_inspect_script="$repo_root/scripts/shielded_vk_artifact_inspect.sh"
vk_inspect_result="${MISAKA_SHIELDED_VK_INSPECT_RESULT:-$repo_root/.tmp/shielded-vk-artifact-inspect/result.json}"
inventory_dir_override=""

if [[ -n "${MISAKA_BACKEND_INVENTORY_RESULT:-}" ]]; then
  inventory_dir_override="$(dirname "$inventory_result")"
fi

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'EOF'
Usage: ./scripts/shielded_module_status_snapshot.sh

Fetches the node's shielded module status and combines it with the local
shielded backend inventory into:

  .tmp/shielded-module-status-snapshot/result.json

Optional env:
  MISAKA_NODE_RPC_BASE             Node base URL (default: http://127.0.0.1:8080)
  MISAKA_SHIELDED_STATUS_DIR       Override output directory
  MISAKA_BACKEND_INVENTORY_RESULT  Override inventory result.json path
                                    (inventory dir is derived from this path)
  MISAKA_SHIELDED_VK_INSPECT_RESULT Override VK inspect result.json path
  MISAKA_SHIELDED_GROTH16_VK_PATH   Optional Groth16 VK artifact path to inspect
  MISAKA_SHIELDED_PLONK_VK_PATH     Optional PLONK VK artifact path to inspect
EOF
  exit 0
fi

mkdir -p "$state_dir"

write_failure() {
  local message="$1"
  python3 - "$result_file" "$node_base" "$inventory_result" "$vk_inspect_result" "$message" <<'PY'
import json
import pathlib
import sys

result = pathlib.Path(sys.argv[1])
node_base = sys.argv[2]
inventory_result = sys.argv[3]
vk_inspect_result = sys.argv[4]
message = sys.argv[5]
vk_inspection_path = pathlib.Path(vk_inspect_result)
vk_inspection = (
    json.loads(vk_inspection_path.read_text()) if vk_inspection_path.exists() else None
)

payload = {
    "status": "failed",
    "nodeBase": node_base,
    "inventoryArtifact": inventory_result,
    "vkArtifactInspectionArtifact": vk_inspect_result,
    "vkArtifactInspectionSummary": vk_inspection,
    "error": message,
}
result.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n")
PY
}

if [[ -n "$inventory_dir_override" ]]; then
  MISAKA_SHIELDED_INVENTORY_DIR="$inventory_dir_override" bash "$inventory_script" >/dev/null
else
  bash "$inventory_script" >/dev/null
fi

local_vk_dir="$(dirname "$vk_inspect_result")"
MISAKA_SHIELDED_VK_INSPECT_DIR="$local_vk_dir" \
MISAKA_SHIELDED_GROTH16_VK_PATH="${MISAKA_SHIELDED_GROTH16_VK_PATH:-}" \
MISAKA_SHIELDED_PLONK_VK_PATH="${MISAKA_SHIELDED_PLONK_VK_PATH:-}" \
bash "$vk_inspect_script" >/dev/null || {
  write_failure "failed to inspect configured shielded VK artifacts"
  exit 1
}

tmp_body="$(mktemp "$state_dir/module-status.XXXXXX.json")"
trap 'rm -f "$tmp_body"' EXIT

if ! curl --fail --silent --show-error "$node_base/api/shielded/module_status" >"$tmp_body"; then
  write_failure "failed to fetch $node_base/api/shielded/module_status"
  exit 1
fi

python3 - "$tmp_body" "$inventory_result" "$vk_inspect_result" "$result_file" "$node_base" <<'PY'
import json
import pathlib
import sys

module_status = json.loads(pathlib.Path(sys.argv[1]).read_text())
inventory_path = pathlib.Path(sys.argv[2])
vk_inspect_path = pathlib.Path(sys.argv[3])
result_file = pathlib.Path(sys.argv[4])
node_base = sys.argv[5]

inventory = json.loads(inventory_path.read_text()) if inventory_path.exists() else None
vk_inspection = json.loads(vk_inspect_path.read_text()) if vk_inspect_path.exists() else None
layer4_status = module_status.get("layer4Status") if isinstance(module_status, dict) else None
verifier_contract = layer4_status.get("verifierContract") if isinstance(layer4_status, dict) else None
catalog_backends = layer4_status.get("catalogBackends") if isinstance(layer4_status, dict) else None

payload = {
    "status": "passed",
    "nodeBase": node_base,
    "moduleStatus": module_status,
    "inventoryArtifact": str(inventory_path),
    "inventorySummary": inventory.get("summary") if inventory else None,
    "vkArtifactInspectionArtifact": str(vk_inspect_path) if vk_inspect_path.exists() else None,
    "vkArtifactInspectionSummary": vk_inspection,
    "verifierContractSummary": verifier_contract,
    "authoritativeTargetSummary": verifier_contract.get("authoritativeTarget") if isinstance(verifier_contract, dict) else None,
    "authoritativeTargetReady": verifier_contract.get("authoritativeTargetReady") if isinstance(verifier_contract, dict) else None,
    "catalogBackendCount": len(catalog_backends) if isinstance(catalog_backends, list) else None,
}

result_file.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n")
PY

printf 'wrote %s\n' "$result_file"
