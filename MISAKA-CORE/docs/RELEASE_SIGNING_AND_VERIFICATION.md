# Release Signing and Verification

How to verify the integrity and authenticity of MISAKA release artifacts.

## Overview

Each MISAKA release includes:
- `misaka-node` -- the compiled binary
- `SHA256SUMS` -- SHA-256 checksums for all release files
- `BUILD_MANIFEST.json` -- machine-readable release metadata
- `dist/sbom/` -- Software Bill of Materials (CycloneDX or cargo tree)
- `*.minisig` -- minisign signatures (when release is signed)

## Step 1: Download Release Artifacts

Download the release archive and signature files from the official release page.

```bash
# Example
curl -LO https://github.com/misaka-network/misaka-core/releases/download/v0.5.1/misaka-node-0.5.1.zip
curl -LO https://github.com/misaka-network/misaka-core/releases/download/v0.5.1/SHA256SUMS
curl -LO https://github.com/misaka-network/misaka-core/releases/download/v0.5.1/SHA256SUMS.minisig
```

## Step 2: Verify SHA256 Checksums

```bash
# On Linux
sha256sum -c SHA256SUMS

# On macOS
shasum -a 256 -c SHA256SUMS
```

Both commands should report `OK` for each file listed.

## Step 3: Verify Minisign Signature

Install minisign if not already available:

```bash
# macOS
brew install minisign

# Linux
apt install minisign
```

Verify the signature using the MISAKA public key:

```bash
minisign -Vm SHA256SUMS -p misaka-release.pub
minisign -Vm misaka-node -p misaka-release.pub
```

The public key (`misaka-release.pub`) is published in the repository root and on the project website.

## Step 4: Inspect BUILD_MANIFEST.json

```bash
cat BUILD_MANIFEST.json | python3 -m json.tool
```

Verify that:
- `git_commit` matches the tagged commit on GitHub
- `chain_target` is `mainnet` for production releases
- `build_timestamp` is reasonable
- `checksums.binary_sha256` matches the SHA256 you computed in Step 2
- `signature.status` is `minisign` for signed releases

## Step 5: Review the SBOM

The Software Bill of Materials lists all dependencies compiled into the binary.

```bash
# CycloneDX format (if available)
cat dist/sbom/sbom-cyclonedx.json | python3 -m json.tool

# Fallback: cargo tree output
cat dist/sbom/dependencies.txt
```

Review for unexpected or known-vulnerable dependencies.

## Troubleshooting

- **Checksum mismatch**: Re-download the file. If still mismatched, do not use the binary.
- **Signature verification failed**: Ensure you have the correct public key. Do not use unsigned binaries on mainnet.
- **Missing BUILD_MANIFEST.json**: The binary may be a development build. Do not use for mainnet.
