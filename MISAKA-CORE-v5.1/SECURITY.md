# MISAKA Network — Security Model (v5)

## Cryptographic Primitives

| Layer | Primitive | Standard/Basis | Security |
|-------|-----------|---------------|----------|
| Identity Signature | ML-DSA-65 | FIPS 204 | 128-bit PQ |
| Key Encapsulation | ML-KEM-768 | FIPS 203 | 128-bit PQ |
| Commitment | BDLOP (lattice Pedersen) | Module-SIS/LWE | 128-bit PQ |
| Membership Proof | SIS Merkle + BDLOP committed path | Module-SIS | 128-bit PQ |
| Nullifier | Algebraic (a_null · s) | Module-SIS | 128-bit PQ |
| Range Proof | Lattice bit-decomposition OR | Module-SIS/LWE | 128-bit PQ |
| Balance Proof | Lattice Σ-protocol | Module-SIS | 128-bit PQ |

## Security Audit v5 — Findings & Fixes

### CRITICAL

| ID | Finding | Fix |
|----|---------|-----|
| CRITICAL-001 | **Amount mod-Q aliasing**: `BdlopCommitment::commit()` encoded `amount % Q` (Q=12289), so amount=1 and amount=12290 produced identical commitments — breaking binding and enabling balance forgery. | `commit()` now returns `Result`, rejects `amount ≥ Q`. `MAX_CONFIDENTIAL_AMOUNT = 12288` enforced at all call sites. `compute_balance_diff()` also validates fee < Q. |

### HIGH

| ID | Finding | Fix |
|----|---------|-----|
| HIGH-001 | **Timing side-channels in proof verification**: BDLOP challenge, STARK digest, composite binding_digest, KI proof, and membership root hash compared with `!=` (variable-time). Allows oracle attacks to extract proof/digest bytes. | Centralized `ct_eq()` / `ct_eq_32()` in `secret.rs` using `read_volatile` XOR accumulation. All 10+ verification comparison sites migrated. Local `constant_time_eq` variants in nullifier/stealth removed. |
| HIGH-002 | **RPC API key timing leak**: `rpc_auth.rs` compared Bearer token with `!=` — enables byte-by-byte key extraction via response timing. | Replaced with XOR-accumulation constant-time comparison with length-independent control flow. |
| HIGH-003 | **Witness types missing zeroization**: `PrivateTxWitness`, `InputPrivateWitness`, `OutputPrivateWitness` had no `Drop` impl — secret polynomials, amounts, blinding factors, and Merkle paths persisted in memory after proof generation. | Added `Drop` impls that zeroize all secret fields. |

### MEDIUM

| ID | Finding | Fix |
|----|---------|-----|
| MED-001 | **`MisakaSecretKey` compiler-elided zeroization**: `Drop` used a plain `for b in bytes { *b = 0 }` loop, which the compiler may optimize away as a dead store. | Replaced with `zeroize::Zeroize` crate call. |
| MED-002 | **Production `unwrap()` in DAG parent selection**: `scores.iter().min().unwrap()` could panic on edge cases despite an `is_empty()` guard above. | Replaced with `unwrap_or(0)` for zero-panic compliance. |
| MED-003 | **`MlKemSharedSecret` derives `PartialEq`/`Eq`**: Standard `==` on a shared secret enables timing side-channel. | Removed `PartialEq`/`Eq` derivation, restricted field to `pub(crate)`. |

### Audit Coverage

- **Timing analysis**: All comparison sites in `misaka-pqc` verification paths audited and migrated to constant-time
- **Zeroization**: All secret-holding types (`MlKemSecretKey`, `MlDsaSecretKey`, `ValidatorPqSecretKey`, `MisakaSecretKey`, `SecretPoly`, `BlindingFactor`, `SharedSecret`, `SecretWitness`, `MlKemSharedSecret`, witness types) confirmed to have `Drop` + `Zeroize`
- **Integer safety**: Amount encoding audited for mod-Q aliasing; all `amount % Q` sites hardened with bounds checks
- **Panic safety**: Production `unwrap()`/`expect()` in non-test code audited; DAG parent selection fixed
- **P2P / RPC**: Frame size limits (4MB), concurrency limits (64), body size limits (128KB), API key auth — all confirmed present

## Cryptographic Primitives

| Layer | Primitive | Standard/Basis | Security |
|-------|-----------|---------------|----------|
| Identity Signature | ML-DSA-65 | FIPS 204 | 128-bit PQ |
| Key Encapsulation | ML-KEM-768 | FIPS 203 | 128-bit PQ |
| Commitment | BDLOP (lattice Pedersen) | Module-SIS/LWE | 128-bit PQ |
| Membership Proof | SIS Merkle + BDLOP committed path | Module-SIS | 128-bit PQ |
| Nullifier | Algebraic (a_null · s) | Module-SIS | 128-bit PQ |
| Range Proof | Lattice bit-decomposition OR | Module-SIS/LWE | 128-bit PQ |
| Balance Proof | Lattice Σ-protocol | Module-SIS | 128-bit PQ |

## Privacy Model

### Sender Privacy

The sender is hidden among ALL members of the anonymity set (global UTXO Merkle tree).
The ZKP reveals:
- A nullifier (for double-spend prevention)
- An anonymity root (which Merkle tree was used)
- A membership proof (BDLOP committed — verifier cannot identify the signer)

The verifier CANNOT determine:
- Which UTXO was spent
- Which public key belongs to the spender
- The spender's position in the Merkle tree

### Amount Privacy

All amounts (inputs, outputs, fee) are hidden in BDLOP commitments.
Range proofs ensure non-negativity without revealing values.
Balance excess proof ensures conservation (Σ in = Σ out + fee).

### Receiver Privacy

Outputs use ML-KEM-768 stealth addresses with encrypted amount/blinding delivery.
One-time addresses prevent linking outputs to recipient public keys.

## Double-Spend Prevention

Nullifier = `canonical_nullifier_hash(DeriveParam(output_id, chain_id) · secret)`

Properties:
- **Output-bound**: Same UTXO always produces the same nullifier
- **Ring-independent**: Nullifier does not depend on anonymity set composition
- **Chain-bound**: Cross-chain replay produces different nullifiers
- **Algebraically verified**: ZKP proves correct derivation via dual-relation Σ-protocol

## DoS Protection

| Layer | Mechanism | Constant |
|-------|-----------|----------|
| Mempool | Cheap size gate (pre-crypto) | MAX_TX_SIZE = 2 MiB |
| Mempool | Per-input proof length | MAX_PROOF_BYTES = 256 KiB |
| Mempool | O(1) nullifier conflict | HashSet lookup |
| Block | ZKP verification budget | 5,000 units/block |
| Block | Wall-clock timeout | 10 seconds |
| Block | Proof count cap | 500 proofs/block |
| P2P | Peer scoring + ban | Score < 0 → disconnect + ban |

## Type-Level Safety

The codebase enforces cryptographic safety at compile time:

- `PublicNullifier` ≠ `CommitmentHash` ≠ `TxDigest` (prevents type confusion)
- `SecretWitness` has no `Serialize` or `Clone` (prevents leakage)
- `VerifiedTransactionEnvelope` can only be created by `verify_and_seal()` (prevents unverified state updates)
- `VerifiedNullifier` can only be created by verification functions (prevents forged verification tokens)
