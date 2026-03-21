# MISAKA-DAG Architecture (v4 — Lattice ZKP)

## Current Privacy Model

**Lattice-based Membership ZKP + Output-bound Nullifier**

All privacy is achieved through post-quantum cryptographic primitives based on
the hardness of Module-SIS and Module-LWE problems:

1. **BDLOP Commitment** (Module-SIS binding, Module-LWE hiding):
   Hides transaction amounts in lattice polynomial commitments.

2. **SIS Merkle Membership Proof** (collision-resistant lattice hash tree):
   Proves the spender's public key is in the global UTXO set without
   revealing which key (BDLOP committed path + CDS OR-proofs at each level).

3. **Algebraic Nullifier** (`a_null · s`):
   Output-bound, ring-independent, deterministic per (secret, output_id, chain_id).
   Prevents double-spending without revealing which UTXO was spent.

4. **Lattice Range Proofs** (bit-decomposition + lattice OR-proofs):
   Proves each committed amount is in [0, 2^64) without revealing the value.

5. **Balance Excess Σ-proof**:
   Proves Σ inputs = Σ outputs + fee using BDLOP homomorphism.

## DAG Consensus

GhostDAG provides:
- Blue/Red block classification
- Deterministic total ordering
- Fail-soft transaction conflict resolution (nullifier-based)

The DAG state manager applies transactions in total order, using the
`VerifiedTransactionEnvelope` type to ensure only cryptographically
verified transactions can update the UTXO/Nullifier state.

## Module Structure

| Module | Responsibility |
|--------|---------------|
| `dag_block` | Multi-parent block header + GhostDagData |
| `ghostdag` | Blue/Red classification, total ordering |
| `dag_state_manager` | Nullifier conflict resolution, state application |
| `decoy_selection` | Uniform anonymity set selection (no amount/age bias) |
| `qdag_verify` | Full ZKP verification pipeline for v4 transactions |
| `validation_pipeline` | Block-level validation orchestration |

## Removed Components

The following components have been permanently removed:
- LogRing O(log n) ring signatures
- LRS-v1 O(n) ring signatures
- ChipmunkRing research ring signatures
- Same-amount ring denomination matching
- Gamma distribution decoy selection
- Link tag double-spend detection
