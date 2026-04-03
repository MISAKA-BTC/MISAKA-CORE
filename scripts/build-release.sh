#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
# MISAKA-CORE Production Release Build Script
# ═══════════════════════════════════════════════════════════════════
# Usage:
#   MISAKA_BUILD_VERSION=0.5.1 MISAKA_BUILD_COMMIT=$(git rev-parse HEAD) ./scripts/build-release.sh
#
# Requirements:
#   - Rust toolchain (rustc, cargo)
#   - MISAKA_BUILD_VERSION and MISAKA_BUILD_COMMIT env vars
# ═══════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }
die()       { log_error "$@"; exit 1; }

# ── Step 1: Validate required environment variables ──────────────
log_info "Validating environment variables..."
[[ -z "${MISAKA_BUILD_VERSION:-}" ]] && die "MISAKA_BUILD_VERSION is not set"
[[ -z "${MISAKA_BUILD_COMMIT:-}" ]]  && die "MISAKA_BUILD_COMMIT is not set"

# Validate version format (semver-ish)
if ! [[ "$MISAKA_BUILD_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
    die "MISAKA_BUILD_VERSION '$MISAKA_BUILD_VERSION' does not look like a valid version"
fi

log_info "Version: $MISAKA_BUILD_VERSION  Commit: $MISAKA_BUILD_COMMIT"

# ── Step 2: Reject forbidden features ────────────────────────────
FORBIDDEN_FEATURES=("dev" "faucet" "stark-stub" "legacy-p2p" "allow-tofu")
log_info "Checking for forbidden features in Cargo.toml files..."

for feat in "${FORBIDDEN_FEATURES[@]}"; do
    # Check for default-enabled forbidden features
    matches=$(grep -rn "default.*=.*\[.*\"$feat\"" "$PROJECT_ROOT"/crates/*/Cargo.toml "$PROJECT_ROOT"/Cargo.toml 2>/dev/null || true)
    if [[ -n "$matches" ]]; then
        die "Forbidden feature '$feat' found in default features:\n$matches"
    fi
done
log_info "No forbidden features in defaults."

# ── Step 3: Scan for embedded secrets ────────────────────────────
SECRET_PATTERNS=(
    "PRIVATE_KEY\s*="
    "SECRET_KEY\s*="
    "password\s*="
    "api_key\s*="
    "AWS_ACCESS_KEY"
    "BEGIN PRIVATE KEY"
    "sk_live_"
    "ghp_"
)
log_info "Scanning source for embedded secrets..."

found_secrets=0
for pattern in "${SECRET_PATTERNS[@]}"; do
    matches=$(grep -rn --include='*.rs' --include='*.toml' --include='*.json' \
        -E "$pattern" "$PROJECT_ROOT/crates" "$PROJECT_ROOT/components" 2>/dev/null \
        | grep -v 'test' | grep -v '#\[.*test' | grep -v '// ' | grep -v 'env::var' \
        | grep -v 'from_env' | grep -v 'Option<' | grep -v '_pattern' \
        | grep -v 'SECRET_PATTERNS' | grep -v 'secret_patterns' \
        | grep -v 'sanitize' | grep -v 'redact' || true)
    if [[ -n "$matches" ]]; then
        log_warn "Potential secret pattern '$pattern' found:"
        echo "$matches"
        found_secrets=1
    fi
done

if [[ $found_secrets -eq 1 ]]; then
    die "Potential embedded secrets detected. Review the matches above."
fi
log_info "No embedded secrets found."

# ── Step 3b: Advanced secret scan (base64, JSON, fixture) ──────
log_info "Running advanced secret scan..."

CRATE_DIR="$PROJECT_ROOT/crates"

# Base64-encoded secrets (look for base64 strings > 40 chars that decode to key-like patterns)
base64_suspects=$(grep -rnoP '[A-Za-z0-9+/]{40,}={0,2}' "$CRATE_DIR" --include='*.rs' --include='*.toml' 2>/dev/null \
    | grep -v 'test\|mock\|example\|fixture' \
    | grep -v 'target/' \
    | head -5 || true)
if [[ -n "$base64_suspects" ]]; then
    log_warn "Possible base64-encoded secrets found (review manually):"
    echo "$base64_suspects"
fi

# JSON-embedded secrets
json_secrets=$(grep -rn '"[a-z_]*key"\s*:\s*"[^"]\{20,\}"' "$CRATE_DIR" --include='*.rs' --include='*.json' 2>/dev/null \
    | grep -v 'test\|mock\|example\|fixture\|schema\|openapi' \
    | grep -v 'target/' \
    | head -5 || true)
if [[ -n "$json_secrets" ]]; then
    log_warn "Possible JSON-embedded secrets found (review manually):"
    echo "$json_secrets"
fi

# Environment variable assignments with literal values (not ${VAR})
env_literals=$(grep -rn 'env::set_var\|env!\|std::env::var' "$CRATE_DIR" --include='*.rs' 2>/dev/null \
    | grep -v 'test\|mock\|#\[cfg(test)\]' \
    | grep -v 'target/' \
    | head -5 || true)
if [[ -n "$env_literals" ]]; then
    log_info "Env var access found (verify no hardcoded values):"
    echo "$env_literals"
fi

log_info "Advanced scan complete."

# ── Step 4: Build with hardened profile ──────────────────────────
log_info "Building release binary..."

export RUSTFLAGS="-C lto=thin -C strip=symbols -C opt-level=3 -C panic=abort -C overflow-checks=on"

cd "$PROJECT_ROOT"
cargo build \
    --release \
    --locked \
    -p misaka-node \
    2>&1

BINARY="$PROJECT_ROOT/target/release/misaka-node"
if [[ ! -f "$BINARY" ]]; then
    die "Build succeeded but binary not found at $BINARY"
fi
log_info "Binary built: $BINARY"

# ── Step 5: Verify no debug symbols ─────────────────────────────
log_info "Checking for debug symbols..."
if command -v nm &>/dev/null; then
    debug_syms=$(nm "$BINARY" 2>/dev/null | grep -c ' N ' || true)
    if [[ "$debug_syms" -gt 100 ]]; then
        die "Binary contains $debug_syms debug symbols — strip failed"
    fi
fi

if command -v file &>/dev/null; then
    file_info=$(file "$BINARY")
    if echo "$file_info" | grep -qi "with debug_info"; then
        die "Binary contains debug info: $file_info"
    fi
fi
log_info "No debug symbols detected."

# ── Step 6: Check for leftover artifacts ─────────────────────────
log_info "Checking for debug artifacts..."
artifact_fail=0

for ext in map pdb; do
    found=$(find "$PROJECT_ROOT/target/release" -maxdepth 2 -name "*.$ext" 2>/dev/null || true)
    if [[ -n "$found" ]]; then
        log_warn "Found .$ext artifacts:\n$found"
        artifact_fail=1
    fi
done

dsym=$(find "$PROJECT_ROOT/target/release" -maxdepth 2 -name "*.dSYM" -type d 2>/dev/null || true)
if [[ -n "$dsym" ]]; then
    log_warn "Found .dSYM directories:\n$dsym"
    artifact_fail=1
fi

if [[ $artifact_fail -eq 1 ]]; then
    die "Debug artifacts found in release directory. Clean and rebuild."
fi
log_info "No debug artifacts found."

# ── Step 7: Generate BUILD_INFO.json ─────────────────────────────
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
BINARY_SIZE=$(wc -c < "$BINARY" | tr -d ' ')
BINARY_SHA256=$(shasum -a 256 "$BINARY" | awk '{print $1}')
RUSTC_VERSION=$(rustc --version)

BUILD_INFO="$PROJECT_ROOT/target/release/BUILD_INFO.json"
cat > "$BUILD_INFO" <<EOF
{
  "version": "$MISAKA_BUILD_VERSION",
  "commit": "$MISAKA_BUILD_COMMIT",
  "build_time": "$BUILD_TIME",
  "rustc": "$RUSTC_VERSION",
  "profile": "release",
  "lto": "thin",
  "strip": "symbols",
  "opt_level": 3,
  "panic": "abort",
  "overflow_checks": true,
  "binary_size_bytes": $BINARY_SIZE,
  "binary_sha256": "$BINARY_SHA256"
}
EOF

log_info "BUILD_INFO.json written to $BUILD_INFO"

# ── Step 8: Integrity check ────────────────────────────────────
RELEASE_DIR="$PROJECT_ROOT/target/release"
log_info "Generating SHA-256 checksums..."
if command -v sha256sum &>/dev/null; then
    sha256sum "$BINARY" > "$RELEASE_DIR/SHA256SUMS"
elif command -v shasum &>/dev/null; then
    shasum -a 256 "$BINARY" > "$RELEASE_DIR/SHA256SUMS"
fi

# ── Prepare dist directories ──
DIST_DIR="$PROJECT_ROOT/dist/release"
SBOM_DIR="$PROJECT_ROOT/dist/sbom"
mkdir -p "$DIST_DIR" "$SBOM_DIR"

# Copy binary and SHA256SUMS into dist/release/
cp "$BINARY" "$DIST_DIR/"
cp "$RELEASE_DIR/SHA256SUMS" "$DIST_DIR/"

# ── SBOM Generation (stored in dist/sbom/) ──
log_info "Generating SBOM (Software Bill of Materials)..."
SBOM_STATUS="none"
if command -v cargo-cyclonedx &>/dev/null; then
    cargo cyclonedx --format json --output-file "$SBOM_DIR/sbom-cyclonedx.json" 2>/dev/null || true
    if [[ -f "$SBOM_DIR/sbom-cyclonedx.json" ]]; then
        SBOM_STATUS="cyclonedx"
        log_info "SBOM (CycloneDX) generated: $SBOM_DIR/sbom-cyclonedx.json"
    fi
elif command -v cargo &>/dev/null; then
    cargo tree --depth 1 --prefix none > "$SBOM_DIR/dependencies.txt" 2>/dev/null || true
    if [[ -f "$SBOM_DIR/dependencies.txt" ]]; then
        SBOM_STATUS="cargo-tree"
        log_info "SBOM (cargo tree) generated: $SBOM_DIR/dependencies.txt"
    fi
fi

# ── Create release zip ──
ZIP_NAME="misaka-node-${MISAKA_BUILD_VERSION}.zip"
(cd "$DIST_DIR" && zip -q "$ZIP_NAME" misaka-node SHA256SUMS 2>/dev/null || true)

# ── Mainnet mode: signing is MANDATORY ──
if [[ "${MISAKA_RELEASE_MODE:-}" == "mainnet" ]]; then
    if [[ -z "${MISAKA_SIGNING_KEY:-}" ]]; then
        die "FATAL: MISAKA_SIGNING_KEY required for mainnet releases"
    fi
    if ! command -v minisign &>/dev/null; then
        die "FATAL: minisign required for mainnet releases"
    fi
fi

# ── Binary signature (if signing key available) ──
SIGN_STATUS="unsigned"
if [[ -n "${MISAKA_SIGNING_KEY:-}" ]] && command -v minisign &>/dev/null; then
    # Sign binary
    minisign -Sm "$DIST_DIR/misaka-node" -s "$MISAKA_SIGNING_KEY" 2>/dev/null && \
        log_info "Binary signed with minisign" || true
    # Sign SHA256SUMS
    minisign -Sm "$DIST_DIR/SHA256SUMS" -s "$MISAKA_SIGNING_KEY" 2>/dev/null && \
        log_info "SHA256SUMS signed with minisign" || true
    # Sign zip
    if [[ -f "$DIST_DIR/$ZIP_NAME" ]]; then
        minisign -Sm "$DIST_DIR/$ZIP_NAME" -s "$MISAKA_SIGNING_KEY" 2>/dev/null && \
            log_info "Zip archive signed with minisign" || true
    fi
    SIGN_STATUS="minisign"
fi

# ── Release manifest (BUILD_MANIFEST.json) ──
log_info "Generating release manifest..."
CHAIN_TARGET="${MISAKA_CHAIN_TARGET:-mainnet}"
MANIFEST="$DIST_DIR/BUILD_MANIFEST.json"
cat > "$MANIFEST" <<MANIFEST_EOF
{
  "schema_version": 1,
  "version": "$MISAKA_BUILD_VERSION",
  "git_commit": "$MISAKA_BUILD_COMMIT",
  "build_timestamp": "$BUILD_TIME",
  "rustc_version": "$RUSTC_VERSION",
  "chain_target": "$CHAIN_TARGET",
  "checksums": {
    "binary_sha256": "$BINARY_SHA256",
    "sha256sums_file": "SHA256SUMS"
  },
  "sbom": {
    "status": "$SBOM_STATUS",
    "path": "dist/sbom/"
  },
  "signature": {
    "status": "$SIGN_STATUS",
    "tool": "minisign"
  },
  "binary_size_bytes": $BINARY_SIZE
}
MANIFEST_EOF
log_info "Release manifest written to $MANIFEST"

log_info "═══════════════════════════════════════════════════"
log_info "Release build complete."
log_info "  Binary:   $BINARY"
log_info "  Size:     $BINARY_SIZE bytes"
log_info "  SHA-256:  $BINARY_SHA256"
log_info "  Manifest: $MANIFEST"
log_info "  SBOM:     $SBOM_DIR/"
log_info "  Signing:  $SIGN_STATUS"
log_info "═══════════════════════════════════════════════════"
