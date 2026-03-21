#!/usr/bin/env python3
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


def main() -> None:
    args = parse_args()
    version = read_version(args.workspace_root)
    package_name = f"misaka-public-node-v{version}-{args.platform}-{args.arch}"
    staging_root = args.output_dir / package_name
    skeleton_root = args.workspace_root / "distribution" / "public-node"

    if staging_root.exists():
        shutil.rmtree(staging_root)
    shutil.copytree(skeleton_root, staging_root)

    for base in ("misaka-node", "misaka-launcher"):
        src = args.binary_dir / binary_name(base, args.platform)
        dst = staging_root / binary_name(base, args.platform)
        if not src.exists():
            raise FileNotFoundError(f"missing binary: {src}")
        shutil.copy2(src, dst)
        if args.platform != "windows":
            ensure_exec(dst)

    for rel in ("start-public-node.sh", "start-public-node.command"):
        path = staging_root / rel
        if path.exists():
            ensure_exec(path)

    archive_base = args.output_dir / package_name
    if args.platform == "windows":
        archive = shutil.make_archive(str(archive_base), "zip", args.output_dir, package_name)
    else:
        archive = shutil.make_archive(str(archive_base), "gztar", args.output_dir, package_name)

    print(f"staging={staging_root}")
    print(f"archive={archive}")


if __name__ == "__main__":
    main()
