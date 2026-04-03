#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
state_dir="${MISAKA_SHIELDED_INVENTORY_DIR:-$repo_root/.tmp/shielded-backend-inventory}"
result_file="$state_dir/result.json"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  cat <<'EOF'
Usage: ./scripts/shielded_backend_inventory.sh

Scans the latest MISAKA-CORE shielded/proof backend code paths and writes a
machine-readable inventory to:

  .tmp/shielded-backend-inventory/result.json

Optional env:
  MISAKA_SHIELDED_INVENTORY_DIR   Override output directory
EOF
  exit 0
fi

mkdir -p "$state_dir"

tmpdir="$(mktemp -d "$state_dir/run.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

scan_to_file() {
  local output="$1"
  local pattern="$2"
  shift 2
  if command -v rg >/dev/null 2>&1; then
    if ! rg -n --no-heading "$pattern" "$@" >"$output"; then
      : >"$output"
    fi
    return 0
  fi
  if ! grep -RInE -- "$pattern" "$@" >"$output"; then
    : >"$output"
  fi
}

scan_to_file "$tmpdir/stub_feature.txt" \
  "stark-stub|experimental-privacy" \
  "$repo_root/crates/misaka-pqc" \
  "$repo_root/crates/misaka-shielded" \
  "$repo_root/crates/misaka-node"

scan_to_file "$tmpdir/stark_stub_feature.txt" \
  "stark-stub" \
  "$repo_root/crates/misaka-pqc" \
  "$repo_root/crates/misaka-shielded" \
  "$repo_root/crates/misaka-node" \
  "$repo_root/crates/misaka-consensus" \
  "$repo_root/crates/misaka-execution" \
  "$repo_root/crates/misaka-mempool"

scan_to_file "$tmpdir/experimental_privacy_feature.txt" \
  "experimental-privacy" \
  "$repo_root/crates/misaka-pqc" \
  "$repo_root/crates/misaka-node"

scan_to_file "$tmpdir/stub_backend.txt" \
  "StubProofBackend|register_stub_backend|testnet_stub" \
  "$repo_root/crates/misaka-shielded" \
  "$repo_root/crates/misaka-node"

scan_to_file "$tmpdir/shielded_proof_stub.txt" \
  "ShieldedProof::stub\\(" \
  "$repo_root/crates/misaka-shielded" \
  "$repo_root/crates/misaka-node" \
  "$repo_root/crates/misaka-cli" \
  "$repo_root/crates/misaka-mempool"

scan_to_file "$tmpdir/shielded_dev_stub.txt" \
  "ShieldedProof::dev_testnet_stub\\(" \
  "$repo_root/crates/misaka-shielded" \
  "$repo_root/crates/misaka-node" \
  "$repo_root/crates/misaka-cli" \
  "$repo_root/crates/misaka-mempool"

scan_to_file "$tmpdir/groth16_shell.txt" \
  "Groth16Backend|NotImplemented|groth16-shell" \
  "$repo_root/crates/misaka-shielded" \
  "$repo_root/crates/misaka-pqc"

scan_to_file "$tmpdir/plonk.txt" \
  "PLONK|Plonk|plonk" \
  "$repo_root/crates/misaka-shielded" \
  "$repo_root/crates/misaka-pqc"

scan_to_file "$tmpdir/sha3_real.txt" \
  "Sha3MerkleProofBackend|Sha3TransferProofBackend|register_sha3_backend|sha3-transfer-v2|sha3-merkle-v1" \
  "$repo_root/crates/misaka-shielded" \
  "$repo_root/crates/misaka-node"

scan_to_file "$tmpdir/shell_contract.txt" \
  "register_groth16_shell_backend|register_plonk_shell_backend|configure_groth16_shell_contract|configure_plonk_shell_contract" \
  "$repo_root/crates/misaka-shielded" \
  "$repo_root/crates/misaka-node"

scan_to_file "$tmpdir/status_surface.txt" \
  "layer4_status|ShieldedLayer4Status|ProofBackendDescriptor|descriptor\\(|compiled_backend_catalog|runtime_status|ShieldedVerifierContractStatus|verifier_contract|catalog_backends|authoritative_target|authoritative_target_ready|verifier_body_implemented|verifying_key_required|verifying_key_loaded|MISAKA_SHIELDED_AUTHORITATIVE_TARGET|shielded_authoritative_target|MISAKA_SHIELDED_REAL_BACKEND_BOOTSTRAP|shielded_real_backend_bootstrap|resolve_startup_verifier_adapters" \
  "$repo_root/crates/misaka-shielded" \
  "$repo_root/crates/misaka-node"

scan_to_file "$tmpdir/acceptance_surface.txt" \
  "accepted_circuit_versions|accepted_versions\\(|registered_backends|registeredBackends|preferred_production_backend|preferredProductionBackend" \
  "$repo_root/crates/misaka-shielded" \
  "$repo_root/crates/misaka-node" \
  "$repo_root/crates/misaka-cli"

scan_to_file "$tmpdir/prod_gate.txt" \
  "experimental-privacy|stark-stub|swagger-cdn|dev-rpc|faucet|shielded_vk_artifact_inspect|MISAKA_SHIELDED_GROTH16_VK_PATH|MISAKA_SHIELDED_PLONK_VK_PATH|MISAKA_SHIELDED_REAL_BACKEND_BOOTSTRAP|real backend bootstrap|RESULT: PASS" \
  "$repo_root/scripts/prod_feature_gate.sh"

scan_to_file "$tmpdir/release_compile_guard.txt" \
  "compile_error!|feature = \"stark-stub\"|feature = \"experimental-privacy\"" \
  "$repo_root/crates/misaka-node/src/main.rs" \
  "$repo_root/crates/misaka-pqc/src/lib.rs"

python3 - "$tmpdir" "$result_file" "$repo_root" <<'PY'
import json
import pathlib
import sys

tmpdir = pathlib.Path(sys.argv[1])
result_file = pathlib.Path(sys.argv[2])
repo_root = pathlib.Path(sys.argv[3])

def read_lines(name: str):
    path = tmpdir / name
    return [line for line in path.read_text().splitlines() if line.strip()]

def extract_fn_block(source: str, signature: str) -> str:
    idx = source.find(signature)
    if idx == -1:
        return ""
    brace = source.find("{", idx)
    if brace == -1:
        return ""
    depth = 0
    for i in range(brace, len(source)):
        ch = source[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[idx : i + 1]
    return source[idx:]

stub_feature = read_lines("stub_feature.txt")
stark_stub_feature = read_lines("stark_stub_feature.txt")
experimental_privacy_feature = read_lines("experimental_privacy_feature.txt")
stub_backend = read_lines("stub_backend.txt")
shielded_proof_stub = read_lines("shielded_proof_stub.txt")
shielded_dev_stub = read_lines("shielded_dev_stub.txt")
groth16_shell = read_lines("groth16_shell.txt")
plonk = read_lines("plonk.txt")
sha3_real = read_lines("sha3_real.txt")
shell_contract = read_lines("shell_contract.txt")
status_surface = read_lines("status_surface.txt")
acceptance_surface = read_lines("acceptance_surface.txt")
prod_gate = read_lines("prod_gate.txt")
release_compile_guard = read_lines("release_compile_guard.txt")
shielded_state_src = (repo_root / "crates/misaka-shielded/src/shielded_state.rs").read_text()
register_sha3_backend_block = extract_fn_block(
    shielded_state_src, "pub fn register_sha3_backend("
)
register_stub_backend_for_testnet_block = extract_fn_block(
    shielded_state_src, "pub fn register_stub_backend_for_testnet("
)
default_path_registers_stub = any(
    token in register_sha3_backend_block
    for token in ("StubProofBackend", "register_stub_backend", "new_for_testnet")
)
testnet_bootstrap_allows_stub = "register_stub_backend()" in register_stub_backend_for_testnet_block
compiled_catalog_present = any("compiled_backend_catalog" in line for line in status_surface)
verifier_contract_surface_present = any(
    token in line
    for line in status_surface
    for token in (
        "ShieldedVerifierContractStatus",
        "verifier_contract",
        "authoritative_target",
        "authoritative_target_ready",
        "verifier_body_implemented",
        "verifying_key_required",
        "verifying_key_loaded",
    )
)
authoritative_target_surface_present = any(
    token in line
    for line in status_surface
    for token in (
        "ShieldedAuthoritativeBackendTargetTag",
        "authoritative_target",
        "MISAKA_SHIELDED_AUTHORITATIVE_TARGET",
        "shielded_authoritative_target",
    )
)
real_backend_bootstrap_surface_present = any(
    token in line
    for line in status_surface
    for token in (
        "MISAKA_SHIELDED_REAL_BACKEND_BOOTSTRAP",
        "shielded_real_backend_bootstrap",
        "resolve_startup_verifier_adapters",
    )
)
accepted_circuit_surface_present = any(
    "accepted_circuit_versions" in line or "accepted_versions(" in line
    for line in acceptance_surface
)
registered_backends_surface_present = any(
    "registered_backends" in line or "registeredBackends" in line
    for line in acceptance_surface
)
preferred_production_backend_surface_present = any(
    "preferred_production_backend" in line or "preferredProductionBackend" in line
    for line in acceptance_surface
)
prod_feature_gate_present = bool(prod_gate)
prod_feature_gate_covers_stark_stub = any("stark-stub" in line for line in prod_gate)
prod_feature_gate_covers_experimental_privacy = any(
    "experimental-privacy" in line for line in prod_gate
)
prod_feature_gate_covers_vk_artifact_preflight = any(
    token in line
    for line in prod_gate
    for token in (
        "shielded_vk_artifact_inspect.sh",
        "MISAKA_SHIELDED_GROTH16_VK_PATH",
        "MISAKA_SHIELDED_PLONK_VK_PATH",
    )
)
prod_feature_gate_covers_real_backend_bootstrap = any(
    "MISAKA_SHIELDED_REAL_BACKEND_BOOTSTRAP" in line
    or "real backend bootstrap" in line.lower()
    for line in prod_gate
)
release_compile_guard_present = bool(release_compile_guard)
release_compile_guard_covers_stark_stub = any(
    "stark-stub" in line for line in release_compile_guard
)
release_compile_guard_covers_experimental_privacy = any(
    "experimental-privacy" in line for line in release_compile_guard
)
register_stub_backend_raw_direct_callsite_count = sum(
    1 for line in stub_backend if "register_stub_backend()" in line
)
register_stub_backend_helper_body_count = (
    register_stub_backend_for_testnet_block.count("register_stub_backend()")
)
stub_backend_impl_callsite_count = sum(
    1 for line in stub_backend if "StubProofBackend" in line
)
register_stub_backend_direct_callsite_count = max(
    0,
    register_stub_backend_raw_direct_callsite_count
    - register_stub_backend_helper_body_count,
)
register_stub_backend_testnet_helper_callsite_count = sum(
    1 for line in stub_backend if "register_stub_backend_for_testnet()" in line
)
register_stub_backend_surface_count = sum(
    1
    for line in stub_backend
    if any(
        token in line
        for token in ("StubProofBackend", "register_stub_backend", "testnet_stub")
    )
)
shielded_proof_stub_callsite_count = len(shielded_proof_stub)
shielded_explicit_dev_stub_callsite_count = len(shielded_dev_stub)
groth16_shell_callsite_count = len(groth16_shell)
plonk_shell_callsite_count = len(plonk)
sha3_real_backend_callsite_count = len(sha3_real)
shell_contract_callsite_count = len(shell_contract)

data = {
    "status": "ok",
    "summary": {
        "stubPathsPresent": bool(stub_feature or stub_backend),
        "starkStubFeatureSurfaceCount": len(stark_stub_feature),
        "experimentalPrivacyFeatureSurfaceCount": len(experimental_privacy_feature),
        "registerStubBackendDirectCallsiteCount": register_stub_backend_direct_callsite_count,
        "registerStubBackendHelperBodyCount": register_stub_backend_helper_body_count,
        "registerStubBackendTestnetHelperCallsiteCount": register_stub_backend_testnet_helper_callsite_count,
        "registerStubBackendSurfaceCount": register_stub_backend_surface_count,
        "stubBackendImplCallsiteCount": stub_backend_impl_callsite_count,
        "shieldedProofStubCallsiteCount": shielded_proof_stub_callsite_count,
        "shieldedExplicitDevStubCallsiteCount": shielded_explicit_dev_stub_callsite_count,
        "groth16ShellPresent": bool(groth16_shell),
        "groth16ShellReferenceCount": groth16_shell_callsite_count,
        "plonkReferencesPresent": bool(plonk),
        "plonkReferenceCount": plonk_shell_callsite_count,
        "realSha3BackendPresent": bool(sha3_real),
        "realSha3BackendCallsiteCount": sha3_real_backend_callsite_count,
        "defaultPathRegistersStub": default_path_registers_stub,
        "testnetBootstrapAllowsStub": testnet_bootstrap_allows_stub,
        "directRuntimeStubRegistrationPresent": register_stub_backend_direct_callsite_count > 0,
        "shellContractCallsiteCount": shell_contract_callsite_count,
        "layer4StatusSurfacePresent": bool(status_surface),
        "compiledCatalogPresent": compiled_catalog_present,
        "verifierContractSurfacePresent": verifier_contract_surface_present,
        "authoritativeTargetSurfacePresent": authoritative_target_surface_present,
        "realBackendBootstrapSurfacePresent": real_backend_bootstrap_surface_present,
        "acceptedCircuitSurfacePresent": accepted_circuit_surface_present,
        "registeredBackendsSurfacePresent": registered_backends_surface_present,
        "preferredProductionBackendSurfacePresent": preferred_production_backend_surface_present,
        "prodFeatureGatePresent": prod_feature_gate_present,
        "prodFeatureGateCoversStarkStub": prod_feature_gate_covers_stark_stub,
        "prodFeatureGateCoversExperimentalPrivacy": prod_feature_gate_covers_experimental_privacy,
        "prodFeatureGateCoversVkArtifactPreflight": prod_feature_gate_covers_vk_artifact_preflight,
        "prodFeatureGateCoversRealBackendBootstrap": prod_feature_gate_covers_real_backend_bootstrap,
        "releaseCompileGuardPresent": release_compile_guard_present,
        "releaseCompileGuardCoversStarkStub": release_compile_guard_covers_stark_stub,
        "releaseCompileGuardCoversExperimentalPrivacy": release_compile_guard_covers_experimental_privacy,
        "defaultAuthoritativeTarget": "groth16_or_plonk",
        "supportedAuthoritativeTargets": ["groth16", "plonk", "groth16_or_plonk"],
        "authoritativeGroth16PlonkReady": False,
    },
    "nextStep": "Decide SHA3/Groth16/PLONK authoritative role split, then close verifier contract and E2E.",
    "inventories": {
        "stubFeature": stub_feature,
        "starkStubFeature": stark_stub_feature,
        "experimentalPrivacyFeature": experimental_privacy_feature,
        "stubBackend": stub_backend,
        "shieldedProofStub": shielded_proof_stub,
        "shieldedExplicitDevStub": shielded_dev_stub,
        "groth16Shell": groth16_shell,
        "plonk": plonk,
        "sha3Real": sha3_real,
        "shellContract": shell_contract,
        "statusSurface": status_surface,
        "acceptanceSurface": acceptance_surface,
        "prodFeatureGate": prod_gate,
        "releaseCompileGuard": release_compile_guard,
    },
}

result_file.write_text(json.dumps(data, ensure_ascii=True, indent=2) + "\n")
PY

printf 'wrote %s\n' "$result_file"
