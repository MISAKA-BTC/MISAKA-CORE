#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
state_dir="${MISAKA_SHIELDED_VK_INSPECT_DIR:-$repo_root/.tmp/shielded-vk-artifact-inspect}"
result_file="$state_dir/result.json"

groth16_path="${MISAKA_SHIELDED_GROTH16_VK_PATH:-}"
plonk_path="${MISAKA_SHIELDED_PLONK_VK_PATH:-}"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'EOF'
Usage: ./scripts/shielded_vk_artifact_inspect.sh

Inspects shielded VK artifact headers for the currently configured Groth16/PLONK
paths and writes a machine-readable summary to:

  .tmp/shielded-vk-artifact-inspect/result.json

Optional env:
  MISAKA_SHIELDED_VK_INSPECT_DIR   Override output directory
  MISAKA_SHIELDED_GROTH16_VK_PATH  Inspect this Groth16 VK artifact
  MISAKA_SHIELDED_PLONK_VK_PATH    Inspect this PLONK VK artifact
EOF
  exit 0
fi

mkdir -p "$state_dir"

python3 - "$result_file" "$groth16_path" "$plonk_path" <<'PY'
import json
import pathlib
import struct
import sys

result_file = pathlib.Path(sys.argv[1])
groth16_path = sys.argv[2]
plonk_path = sys.argv[3]

VK_MAGIC = b"MSVK"
VK_SCHEMA_V1 = 1
VK_FINGERPRINT_ALGO_BLAKE3_V1 = 1
HEADER_LEN = 13

KIND_TO_TAG = {
    "groth16": 1,
    "plonk": 2,
}
EXPECTED_VERSION = {
    "groth16": 100,
    "plonk": 200,
}
TAG_TO_KIND = {
    1: "groth16",
    2: "plonk",
    3: "sha3_merkle",
    4: "sha3_transfer",
    5: "stub",
}
FINGERPRINT_NAME = {
    1: "blake3_v1",
}

artifacts = []

def inspect(label: str, raw_path: str):
    path = pathlib.Path(raw_path)
    if not path.exists():
        raise RuntimeError(f"{label} VK artifact path does not exist: {path}")
    data = path.read_bytes()
    if len(data) < HEADER_LEN + 1:
        raise RuntimeError(f"{label} VK artifact too short")
    if data[:4] != VK_MAGIC:
        raise RuntimeError(f"{label} VK artifact magic mismatch")
    schema = data[4]
    if schema != VK_SCHEMA_V1:
        raise RuntimeError(f"{label} VK artifact schema mismatch: {schema}")
    kind_tag = data[5]
    actual_kind = TAG_TO_KIND.get(kind_tag, "unknown")
    if kind_tag != KIND_TO_TAG[label]:
        raise RuntimeError(
            f"{label} VK artifact backend kind mismatch: expected {label}, got {actual_kind}"
        )
    circuit_version = struct.unpack("<H", data[6:8])[0]
    if circuit_version != EXPECTED_VERSION[label]:
        raise RuntimeError(
            f"{label} VK artifact circuit version mismatch: expected {EXPECTED_VERSION[label]}, got {circuit_version}"
        )
    fingerprint_algo = data[8]
    if fingerprint_algo != VK_FINGERPRINT_ALGO_BLAKE3_V1:
        raise RuntimeError(
            f"{label} VK artifact fingerprint algorithm mismatch: {fingerprint_algo}"
        )
    payload_length = struct.unpack("<I", data[9:13])[0]
    payload = data[13:]
    if len(payload) != payload_length:
        raise RuntimeError(
            f"{label} VK artifact payload length mismatch: declared {payload_length}, actual {len(payload)}"
        )
    if payload_length == 0:
        raise RuntimeError(f"{label} VK artifact payload is empty")
    artifacts.append(
        {
            "label": label,
            "path": str(path),
            "fileBytes": len(data),
            "schemaVersion": schema,
            "backendKind": actual_kind,
            "circuitVersion": circuit_version,
            "fingerprintAlgorithm": fingerprint_algo,
            "fingerprintAlgorithmName": FINGERPRINT_NAME.get(fingerprint_algo, "unknown"),
            "payloadLength": payload_length,
        }
    )

try:
    if groth16_path:
        inspect("groth16", groth16_path)
    if plonk_path:
        inspect("plonk", plonk_path)

    payload = {
        "status": "passed",
        "providedArtifacts": len(artifacts),
        "artifacts": artifacts,
    }
    if not artifacts:
        payload["message"] = "no VK artifact paths provided"
except Exception as exc:
    payload = {
        "status": "failed",
        "providedArtifacts": len(artifacts),
        "artifacts": artifacts,
        "error": str(exc),
    }
    result_file.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n")
    raise SystemExit(1)

result_file.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n")
PY

printf 'wrote %s\n' "$result_file"
