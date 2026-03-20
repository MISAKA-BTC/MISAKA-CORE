# MISAKA Network — Security Model (v4)

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
