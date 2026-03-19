# Security Model — MISAKA CORE v3

## Threat Model

### Protected Against

- **Quantum computers (Grover/Shor)**: All cryptography is lattice-based (ML-DSA-65, ML-KEM-768, BDLOP, NTT). Security reduction to Module-SIS/LWE with 128-bit post-quantum security.
- **Double spending**: Algebraic nullifiers bound to (secret, output_id, chain_id). Ring-independent — same output always produces the same nullifier regardless of ring composition.
- **Amount forgery (inflation)**: Bit-decomposition range proofs with OR-proof soundness. Balance conservation verified homomorphically through BDLOP commitments.
- **Ring member substitution**: Merkle root binding — verifier recomputes root from provided leaves and checks all three: recomputed == declared == proof.merkle_root.
- **Cross-chain replay**: chain_id bound into nullifier derivation, transcript hash, and ring member leaves.
- **Fee manipulation**: Confidential fee with proven range proof + minimum fee proof (fee ≥ MIN_FEE).
- **Proof reuse across transactions**: Unified transcript binds all proofs to the full transaction content.

### Partially Protected (Documented Limitations)

- **Signer identity vs. validators**: Unified ZKP hides Merkle position via OR-proofs. However, the signer's `pk` is included in the proof. A validator can attempt O(n) trial matching against ring members. True hiding requires lattice SNARK (future work).
- **Metadata leakage**: Input count, output count, ring size, and transaction size are visible on-chain. Fee amount is hidden. Timing is observable at the network layer.
- **Decoy selection**: Gamma(19.28, 1.61) distribution matches empirical spend-age patterns. Statistical analysis by a well-resourced adversary may still narrow the anonymity set.

### Not Protected (Out of Scope)

- **Network-layer deanonymization**: No Dandelion++ or mixnet. First broadcaster is identifiable.
- **Side-channel attacks**: No constant-time guarantees beyond write_volatile zeroization.
- **Key management**: Private key storage is the user's responsibility.
- **Formal verification**: No Kani or similar model checking has been performed.

## Cryptographic Assumptions

| Assumption | Used By | Failure Impact |
|------------|---------|----------------|
| Module-SIS hardness | BDLOP binding, nullifier | Commitment forgery |
| Module-LWE hardness | BDLOP hiding, ML-KEM | Amount reveal |
| SHA3 preimage resistance | Nullifier hash, Merkle tree | Nullifier forgery |
| Random Oracle Model | Fiat-Shamir transform | Proof forgery |

## Feature Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `experimental_agg_range` | OFF | Aggregate range proof (soundness unverified) |
| `rocksdb` | OFF | Persistent storage backend |

Production deployments MUST enable `rocksdb`. The `experimental_agg_range` flag MUST NOT be enabled until formal soundness proof is complete.
