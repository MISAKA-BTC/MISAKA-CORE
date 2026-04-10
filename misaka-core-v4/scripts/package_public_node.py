#!/usr/bin/env python3
"""Package MISAKA public node distribution for release."""
from __future__ import annotations

import argparse
import os
import shutil
import stat
import tomllib
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Package MISAKA public node distribution")
    parser.add_argument("--workspace-root", type=Path, required=True)
    parser.add_argument("--binary-dir", type=Path, required=True)
    parser.add_argument("--platform", required=True, choices=["windows", "macos", "linux"])
    parser.add_argument("--arch", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def read_version(workspace_root: Path) -> str:
    cargo_toml = workspace_root / "Cargo.toml"
    with cargo_toml.open("rb") as fh:
        parsed = tomllib.load(fh)
    return parsed["workspace"]["package"]["version"]


def binary_name(base: str, platform: str) -> str:
    return f"{base}.exe" if platform == "windows" else base


def ensure_exec(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


PLATFORM_SCRIPTS = {
    "linux": [
        "start-public-node.sh",
        "start-seed-node.sh",
        "start-self-hosted-testnet.sh",
        "show-network-guide.sh",
    ],
    "macos": [
        "start-public-node.sh",
        "start-public-node.command",
        "start-seed-node.sh",
        "start-seed-node.command",
        "start-self-hosted-testnet.sh",
        "start-self-hosted-testnet.command",
        "show-network-guide.sh",
        "show-network-guide.command",
    ],
    "windows": [
        "start-public-node.bat",
        "start-seed-node.bat",
        "start-self-hosted-testnet.bat",
        "show-network-guide.bat",
    ],
}


def main() -> None:
    args = parse_args()
    version = read_version(args.workspace_root)
    package_name = f"misaka-public-node-v{version}-{args.platform}-{args.arch}"
    staging_root = args.output_dir / package_name
    skeleton_root = args.workspace_root / "distribution" / "public-node"

    if staging_root.exists():
        shutil.rmtree(staging_root)

    # Copy config
    config_dst = staging_root / "config"
    config_src = skeleton_root / "config"
    shutil.copytree(config_src, config_dst)

    # Copy README
    readme_src = skeleton_root / "README.md"
    if readme_src.exists():
        shutil.copy2(readme_src, staging_root / "README.md")

    # Copy platform scripts
    for script in PLATFORM_SCRIPTS.get(args.platform, []):
        src = skeleton_root / script
        if src.exists():
            shutil.copy2(src, staging_root / script)
            if args.platform != "windows":
                ensure_exec(staging_root / script)

    # Copy binary
    src_bin = args.binary_dir / binary_name("misaka-node", args.platform)
    dst_bin = staging_root / binary_name("misaka-node", args.platform)
    if not src_bin.exists():
        raise FileNotFoundError(f"missing binary: {src_bin}")
    shutil.copy2(src_bin, dst_bin)
    if args.platform != "windows":
        ensure_exec(dst_bin)

    # Archive
    archive_base = args.output_dir / package_name
    if args.platform == "windows":
        archive = shutil.make_archive(str(archive_base), "zip", args.output_dir, package_name)
    else:
        archive = shutil.make_archive(str(archive_base), "gztar", args.output_dir, package_name)

    print(f"staging={staging_root}")
    print(f"archive={archive}")


if __name__ == "__main__":
    main()
