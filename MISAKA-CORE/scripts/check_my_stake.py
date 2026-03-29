#!/usr/bin/env python3
"""
MISAKA Validator Staking Inspector

Usage:
    cd ~/MISAKA-CORE-v9-fixed6
    python3 scripts/check_my_stake.py

    # L1公開鍵を直接指定
    python3 scripts/check_my_stake.py d54dff7a...

On-chain account layout (Anchor serialization):

  ValidatorRegistration (242 bytes):
    [0..8)     discriminator
    [8..40)    user Pubkey
    [72..104)  l1_public_key (32 raw bytes)
    [104..168) node_name

  ValidatorStake (117 bytes):
    [8..40)    user Pubkey
    [72..80)   amount u64 LE (total staked, 9 decimals)

  StakingPosition (200 bytes):
    [8..40)    user Pubkey
    [96..104)  amount u64 LE (position amount, 9 decimals)
"""

import json, base64, struct, sys, os, subprocess

PROGRAM_ID = "27WjgCAWkkjS4H4jqytkKQoCrAN3qgzjp6f6pXLdP8hG"
SOLANA_RPC = "https://api.mainnet-beta.solana.com"
UNIT = 10 ** 9

ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58(b):
    n = int.from_bytes(b, "big")
    r = []
    while n > 0:
        n, m = divmod(n, 58)
        r.append(ALPHABET[m:m+1])
    for x in b:
        if x == 0: r.append(b"1")
        else: break
    return b"".join(reversed(r)).decode()

def fetch():
    p = json.dumps({"jsonrpc":"2.0","id":1,"method":"getProgramAccounts",
                     "params":[PROGRAM_ID,{"encoding":"base64"}]})
    r = subprocess.run(["curl","-s",SOLANA_RPC,"-X","POST",
                        "-H","Content-Type: application/json","-d",p],
                       capture_output=True, text=True)
    return json.loads(r.stdout).get("result", [])

def main():
    l1_key = None
    if len(sys.argv) > 1:
        l1_key = sys.argv[1]
    else:
        for p in ["data/l1-public-key.json", "../data/l1-public-key.json"]:
            if os.path.exists(p):
                with open(p) as f: l1_key = json.load(f)["l1PublicKey"]
                break
    if not l1_key:
        print("Usage: python3 check_my_stake.py [L1_PUBLIC_KEY]")
        sys.exit(1)

    l1_bytes = bytes.fromhex(l1_key)
    print()
    print("  MISAKA Validator Staking Inspector")
    print("  ==================================")
    print(f"  L1 Key: {l1_key[:24]}...{l1_key[-8:]}")
    print(f"  Fetching from Solana mainnet...")
    print()

    accounts = fetch()
    if not accounts:
        print("  ERROR: No accounts from Solana RPC"); sys.exit(1)

    # 1. Registration (242 bytes) -> find user wallet
    user_bytes = None
    for acc in accounts:
        raw = base64.b64decode(acc["account"]["data"][0])
        if l1_bytes in raw:
            user_bytes = raw[8:40]
            name = raw[104:168].split(b'\x00')[0].decode('utf-8', errors='replace')
            print(f"  Validator Registration: {acc['pubkey']}")
            print(f"  Solana Wallet:          {b58(user_bytes)}")
            print(f"  Node Name:              {name}")
            print(f"  L1 Key:                 {l1_key}")
            break

    if not user_bytes:
        print("  NOT FOUND. Register at misakastake.com first.")
        sys.exit(1)

    # 2. Total stake (117 bytes, offset 72)
    total = 0
    for acc in accounts:
        raw = base64.b64decode(acc["account"]["data"][0])
        if acc["account"]["space"] == 117 and raw[8:40] == user_bytes:
            total = struct.unpack_from("<Q", raw, 72)[0] / UNIT
            break

    # 3. Positions (200 bytes, offset 96)
    positions = []
    for acc in accounts:
        raw = base64.b64decode(acc["account"]["data"][0])
        if acc["account"]["space"] == 200 and raw[8:40] == user_bytes:
            amt = struct.unpack_from("<Q", raw, 96)[0] / UNIT
            positions.append((acc["pubkey"], amt))

    print()
    print(f"  TOTAL STAKED:     {total:>14,.0f} MISAKA")
    if positions:
        print(f"  Positions:")
        for i, (pk, amt) in enumerate(positions):
            print(f"    #{i}: {amt:>14,.4f} MISAKA  ({pk[:20]}...)")
    status = "Active" if total >= 10_000_000 else "BELOW MINIMUM"
    print(f"  Status:           {status}")
    print(f"  Min Required:     10,000,000 MISAKA")
    print()

if __name__ == "__main__":
    main()
