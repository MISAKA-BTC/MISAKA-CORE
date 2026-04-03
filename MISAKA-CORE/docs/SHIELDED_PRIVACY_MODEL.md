# MISAKA Shielded Transfer Privacy Model

## Design: CEX-Compatible Commitment-Based Integrity

MISAKA is a transparent-first chain with opt-in shielded transfers.
Privacy is NOT the default. Exchanges can disable shielded handling.

## ⚠ SHA3 Proofs Are NOT Zero-Knowledge

The SHA3 V3 proof system provides **TransparentIntegrity** — it cryptographically
proves that a shielded transfer is valid without the verifier seeing plaintext values.
However, it is **not a zero-knowledge proof system**:

| Property | ZK (Groth16/PLONK) | SHA3 V3 (Current) |
|----------|--------------------|--------------------|
| Verifier learns nothing beyond validity | YES | NO |
| num_inputs/num_outputs hidden | YES | NO (plaintext) |
| Nullifier patterns hidden | NO (inherent to design) | NO |
| Output commitment patterns hidden | NO (inherent to design) | NO |
| Transaction graph analysis possible | Hard (with padding) | YES |
| Value brute-force resistant | YES (simulated proof) | Relies on 256-bit blinding |
| Mathematical ZK property | Proven (simulation-extractable) | NONE |
| Post-quantum safe | NO (pairing-based) | YES (hash-based) |

**What an observer CAN learn from SHA3 V3 transactions:**
1. Number of inputs and outputs (plaintext in proof header)
2. Nullifiers (public on-chain — marks which notes are spent)
3. Output commitments (public on-chain — tracks new notes)
4. Fee amount (in public inputs)
5. Transaction timing and frequency
6. Shielded pool size

**What an observer CANNOT learn:**
1. Transfer amounts (hidden behind 256-bit blinded commitments)
2. Recipient addresses (encrypted in notes)
3. Randomness / blinding factors
4. Which specific note was spent (only nullifier is visible)

**Upgrade Path:** Groth16/PLONK backends (P1 phase) will provide true ZK when implemented.

## Privacy Perspectives

| Perspective | Description |
|-------------|-------------|
| **Observer** | Any chain reader (explorer, indexer) |
| **Validator** | Block producer processing proofs |
| **Recipient** | Intended receiver with decryption key |
| **FullViewKey** | Auditor/regulator with view access |

## Field Visibility (V3 Shielded Transfer)

| Field | Observer | Validator | Recipient | FullViewKey |
|-------|----------|-----------|-----------|-------------|
| tx_id | yes | yes | yes | yes |
| nullifiers | yes | yes | yes | yes |
| output_commitments | yes | yes | yes | yes |
| anchor | yes | yes | yes | yes |
| fee (V3: committed) | no | no | yes | yes |
| circuit_version | yes | yes | yes | yes |
| encrypted_notes (presence) | yes | yes | yes | yes |
| encrypted_notes (content) | no | no | yes | yes |
| **value** | no | no | yes | yes |
| **recipient_pk** | no | no | yes | yes |
| **rcm (randomness)** | no | no | yes | yes |
| **nk_commit** | no | no | yes | yes |
| **asset_id** | no | no | yes | yes |
| proof_bytes (V3) | yes | yes | yes | yes |
| proof internals (commitments only) | yes | yes | yes | yes |

### V2 vs V3 Comparison

| | V2 (Legacy) | V3 (Private) |
|---|---|---|
| value in proof | yes, plaintext | no, commitment only |
| recipient_pk in proof | yes, plaintext | no, not included |
| rcm in proof | yes, plaintext | no, not included |
| nk_commit in proof | yes, plaintext | no, binding only |
| Validator sees amounts | yes | no |
| Observer sees amounts | yes | no |

### Deposit/Withdraw (Unchanged)

| Field | Visibility |
|-------|-----------|
| deposit.from | Public |
| deposit.amount | Public |
| withdraw.recipient | Public |
| withdraw.amount | Public |

This is intentional for CEX compatibility.

## Selective Disclosure

Holders of FullViewKey (FVK) or IncomingViewKey (IVK) can:
- Decrypt encrypted_notes for their addresses
- Recover value, recipient, memo from notes
- Provide audit trails to regulators
- This does NOT require protocol changes -- view key derives shared secret, then decrypts note

## Residual Limitations

1. Deposit/withdraw remain fully transparent (by design, for CEX)
2. Metadata (timing, tx count, proof size) is still observer-visible
3. Shielded pool size is observable
4. V2 proofs (if still used) expose plaintext to validators
