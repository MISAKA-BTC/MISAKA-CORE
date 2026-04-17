#!/usr/bin/env python3
"""
register_validator_example.py

Observer ノードをバリデータとして登録/解除するサンプル (Python 版)。
依存: requests (pip install requests)

使い方:
  # validator.key から公開鍵を取得
  python3 scripts/register_validator_example.py export-key \
    --key-file ./misaka-data/validator.key

  # 登録
  python3 scripts/register_validator_example.py register \
    --public-key 0xabcdef... \
    --address 203.0.113.10:16110

  # validator.key から直接登録
  python3 scripts/register_validator_example.py register \
    --key-file ./misaka-data/validator.key \
    --address 203.0.113.10:16110

  # 解除 (public_key または address で指定)
  python3 scripts/register_validator_example.py deregister \
    --address 203.0.113.10:16110

  # 環境変数で seed URL を指定可能
  MISAKA_SEED_URL=https://misakascan.com \
    python3 scripts/register_validator_example.py ...
"""

import argparse
import hashlib
import json
import os
import struct
import sys

try:
    import requests
except ImportError:
    print("Error: 'requests' package is required.  pip install requests", file=sys.stderr)
    sys.exit(1)

DEFAULT_SEED_URL = "https://misakascan.com"

# validator.key binary format constants
_KEY_MAGIC = b"MKEY"
_KEY_VERSION = 1
_SK_LEN = 4032
_PK_LEN = 1952
_KEY_FILE_SIZE = 4 + 4 + _SK_LEN + _PK_LEN + 32


def read_pubkey_from_keyfile(path: str) -> str:
    """Read the ML-DSA-65 public key from a validator.key file.

    Returns the 0x-prefixed hex string (3904 hex chars + '0x' prefix).
    """
    data = open(path, "rb").read()
    if len(data) != _KEY_FILE_SIZE:
        raise ValueError(
            f"validator.key has wrong size: expected {_KEY_FILE_SIZE}, got {len(data)}"
        )
    if data[:4] != _KEY_MAGIC:
        raise ValueError("validator.key has invalid magic bytes")
    (version,) = struct.unpack_from("<I", data, 4)
    if version != _KEY_VERSION:
        raise ValueError(f"unsupported key version: {version}")
    pk_bytes = data[8 + _SK_LEN : 8 + _SK_LEN + _PK_LEN]
    stored_fp = data[8 + _SK_LEN + _PK_LEN :]
    computed_fp = hashlib.sha3_256(pk_bytes).digest()
    if stored_fp != computed_fp:
        raise ValueError("validator.key fingerprint mismatch (file corrupt?)")
    return "0x" + pk_bytes.hex()


def register_validator(seed_url: str, public_key: str, network_address: str) -> dict:
    url = f"{seed_url}/api/register_validator"
    payload = {
        "public_key": public_key,
        "network_address": network_address,
    }
    resp = requests.post(url, json=payload, timeout=30)
    resp.raise_for_status()
    return resp.json()


def deregister_validator(
    seed_url: str,
    public_key: str | None = None,
    network_address: str | None = None,
) -> dict:
    url = f"{seed_url}/api/deregister_validator"
    payload = {}
    if public_key:
        payload["public_key"] = public_key
    if network_address:
        payload["network_address"] = network_address
    resp = requests.post(url, json=payload, timeout=30)
    resp.raise_for_status()
    return resp.json()


def get_committee(seed_url: str) -> dict:
    url = f"{seed_url}/api/get_committee"
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return resp.json()


def main():
    parser = argparse.ArgumentParser(description="Register / deregister a MISAKA validator node")
    sub = parser.add_subparsers(dest="command", help="sub-command")

    exp = sub.add_parser("export-key", help="Export public key from validator.key")
    exp.add_argument(
        "--key-file",
        default="./misaka-data/validator.key",
        help="Path to validator.key (default: ./misaka-data/validator.key)",
    )

    reg = sub.add_parser("register", help="Register a validator")
    reg.add_argument("--public-key", default=None, help="0x-prefixed hex public key")
    reg.add_argument(
        "--key-file",
        default=None,
        help="Path to validator.key (reads public key automatically)",
    )
    reg.add_argument("--address", required=True, help="IP:PORT reachable by peers")
    reg.add_argument("--seed-url", default=None, help="Seed node URL (or set MISAKA_SEED_URL)")

    dereg = sub.add_parser("deregister", help="Deregister a validator")
    dereg.add_argument("--public-key", default=None, help="0x-prefixed hex public key")
    dereg.add_argument("--address", default=None, help="IP:PORT to remove")
    dereg.add_argument("--seed-url", default=None, help="Seed node URL (or set MISAKA_SEED_URL)")

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(1)

    if args.command == "export-key":
        try:
            pk = read_pubkey_from_keyfile(args.key_file)
            print(pk)
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
        return

    seed_url = getattr(args, "seed_url", None) or os.environ.get(
        "MISAKA_SEED_URL", DEFAULT_SEED_URL
    )

    if args.command == "register":
        public_key = args.public_key
        if not public_key and args.key_file:
            try:
                public_key = read_pubkey_from_keyfile(args.key_file)
                print(f"Read public key from {args.key_file}")
            except (FileNotFoundError, ValueError) as e:
                print(f"Error reading key file: {e}", file=sys.stderr)
                sys.exit(1)
        if not public_key:
            print(
                "Error: must provide --public-key or --key-file", file=sys.stderr
            )
            sys.exit(1)
        print(f"Registering validator with {seed_url}")
        print(f"  PK:   {public_key[:20]}...{public_key[-8:]}")
        print(f"  Addr: {args.address}")
        print()
        result = register_validator(seed_url, public_key, args.address)
        print(f"Response: {json.dumps(result, indent=2)}")
        if result.get("ok"):
            print("\nSuccess. Fetching committee...")
            committee = get_committee(seed_url)
            print(json.dumps(committee, indent=2))
        else:
            print(f"\nFailed: {result.get('error', 'unknown')}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "deregister":
        if not args.public_key and not args.address:
            print("Error: must provide --public-key and/or --address", file=sys.stderr)
            sys.exit(1)
        print(f"Deregistering validator from {seed_url}")
        if args.public_key:
            print(f"  PK:   {args.public_key[:20]}...{args.public_key[-8:]}")
        if args.address:
            print(f"  Addr: {args.address}")
        print()
        result = deregister_validator(seed_url, args.public_key, args.address)
        print(f"Response: {json.dumps(result, indent=2)}")
        if result.get("ok"):
            print("\nDeregistration successful. Fetching committee...")
            committee = get_committee(seed_url)
            print(json.dumps(committee, indent=2))
        else:
            print(f"\nFailed: {result.get('error', 'unknown')}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
