# Validator Identity Design

## Problem (CRITICAL #1)

Node startup generates a fresh ML-DSA-65 keypair every time and fills
other validators' public keys with placeholder bytes `[i; 1952]`.
This means:
- No real validator's block signature can ever verify against the committee
- Node identity changes on every restart (past votes become "someone else's")
- Solana stake binding has no anchor

## Design

### 1. Key File Format

File: `<data_dir>/validator.key`

```
[4 bytes] magic: "MKEY"
[4 bytes] version: 1 (little-endian u32)
[4032 bytes] ML-DSA-65 secret key
[1952 bytes] ML-DSA-65 public key
[32 bytes] SHA3-256 fingerprint of public key
```

Total: 6,020 bytes. Binary format (not hex-encoded).

Permissions: `0o600` (owner read/write only). Node refuses to start if
permissions are more permissive.

### 2. Key Generation Timing

- **First startup**: if `validator.key` does not exist, generate and persist.
- **Subsequent startups**: load from disk. If load fails → error, not regenerate.
- **Never regenerate automatically** — operator must explicitly delete to rotate.

### 3. Key Rotation

Key rotation happens at epoch boundaries:
1. Operator generates a new `validator.key` offline
2. Operator submits a `key_rotation_tx` with old key signing new key's PK
3. At next epoch boundary, the new key takes effect
4. Old key file is renamed to `validator.key.epoch_N.bak`

Until key rotation TX support is implemented, rotation requires:
- Stop node
- Delete validator.key
- Restart (generates new key)
- Update genesis manifest (testnet only)

### 4. Genesis Committee Manifest

File: `genesis_committee.toml`

```toml
[committee]
epoch = 0

[[committee.validators]]
authority_index = 0
public_key = "0x<3904 hex chars = 1952 bytes>"
stake = 1000
network_address = "validator-0.misaka.network:16111"

[[committee.validators]]
authority_index = 1
public_key = "0x<3904 hex chars>"
stake = 1000
network_address = "validator-1.misaka.network:16111"
# ... repeat for all validators
```

Validation rules:
- No duplicate authority_index
- No duplicate public_key
- All public_key are exactly 1952 bytes (3904 hex chars)
- All stake > 0
- authority_index is contiguous from 0

### 5. Manifest Signing

For testnet: unsigned manifest (trust-on-first-use).
For mainnet: manifest signed by a genesis ceremony key (future work).

### 6. Peer Discovery

Current: static peer list from config.
Future: gossip-based PK exchange, validated against genesis manifest.
Genesis manifest is the root of trust. Any PK not in genesis is rejected.

### 7. Solana Stake Binding

Each validator entry in genesis includes an optional `solana_stake_account`.
The relayer uses this to verify that a validator's ML-DSA-65 PK corresponds
to a funded Solana stake account. This is a soft binding (not enforced
on-chain until bridge v2).
