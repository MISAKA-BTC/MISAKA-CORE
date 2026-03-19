# MISAKA CORE v3.0.0

Post-Quantum Privacy BlockDAG — Q-DAG-CT + Unified ZKP + ML-DSA-65 + BDLOP

## Architecture

```
                    ┌─────────────────────────────────────┐
                    │          misaka-node (308 lines)     │
                    │  Validator / Observer / Seed node    │
                    └──────────────┬──────────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                     │
    ┌─────────▼──────────┐  ┌─────▼──────┐  ┌──────────▼────────┐
    │   misaka-dag        │  │ dag_rpc    │  │  misaka-p2p       │
    │   (5,600+ lines)    │  │ (316 lines)│  │  wire_protocol    │
    │                     │  └────────────┘  └───────────────────┘
    │  ghostdag.rs     833│  ← Production: O(1) reachability, anti-grinding
    │  reachability    295│  ← Dynamic interval, Kaspa-equivalent
    │  dag_state_mgr   711│
    │  dag_block_prod  403│
    │  dag_store       248│
    │  qdag_verify     252│
    │  val_pipeline    359│  ← Verification order optimization
    │  header_valid    261│  ← Hardened header + VRF tie-break
    │  persistent_store376│
    │  decoy_selection 384│
    │  wire_protocol   339│
    │  dag_finality    292│
    │  dag_block       357│
    └─────────┬───────────┘
              │
    ┌─────────▼───────────┐     ┌────────────────────────┐
    │   misaka-pqc         │     │  misaka-consensus      │
    │   (6,200+ lines)     │     │  block_validation  169 │
    │                      │     │  tx_resolve         75 │
    │  unified_zkp      727│     │  staking_registry  585 │
    │  nullifier        446│     │  validator_set     205 │
    │  bdlop            511│     └────────────────────────┘
    │  range_proof      357│
    │  agg_range_proof  439│
    │  qdag_tx          371│
    │  confidential_fee 226│
    │  conf_stealth     431│
    │  pq_ring          550│
    │  pq_sign          275│
    │  pq_kem           362│
    │  pq_stealth       502│
    │  ntt              250│
    │  privacy          332│
    │  secret           227│
    │  ring_scheme       46│
    └──────────────────────┘
```

### What Was Removed (v3 cleanup)

The following legacy code was deleted — 3,855 lines of dead code:

| Deleted File | Lines | Reason |
|-------------|-------|--------|
| `logring.rs` | 1,244 | Replaced by `unified_zkp.rs` — leaked signer position |
| `zk_membership.rs` | 494 | Superseded by `unified_zkp.rs` |
| `ki_proof.rs` | 531 | Key images replaced by algebraic nullifiers |
| `canonical_ki.rs` | 145 | Legacy key image binding |
| `stealth_v2.rs` | 522 | Replaced by `confidential_stealth.rs` |
| `output_recovery.rs` | 119 | Legacy output recovery |
| `packing.rs` | 13 | LRS serialization remnant |
| `stark_proof.rs` | 382 | Stub — never implemented |
| `tx_codec.rs` | 405 | UtxoTransaction encoding — type removed |

## Cryptographic Stack

| Layer | Primitive | Parameter | Security |
|-------|-----------|-----------|----------|
| Identity | ML-DSA-65 (FIPS 204) | Dilithium-3 | 128-bit PQ |
| Stealth | ML-KEM-768 (FIPS 203) | Kyber-768 | 128-bit PQ |
| Ring membership | Unified ZKP | Lattice Σ + OR-proofs | Position-hiding |
| Nullifier | Algebraic (a_null · s) | Module-SIS | Ring-independent |
| Commitment | BDLOP | R_q = Z_q[X]/(X^256+1) | Module-SIS/LWE |
| Range proof | Bit-decomposition OR | 64-bit amounts | Complete soundness |
| NTT | q=12289, n=256 | ψ verified at runtime | Rejection sampling |

## Transaction Flow

```
Sender:
  1. Select UTXOs from anonymity set (Merkle tree of RingMemberLeaf)
  2. Create BDLOP commitments for each output (hidden amounts)
  3. Generate range proofs per output (v ≥ 0)
  4. Create confidential fee (commitment + range + minimum proofs)
  5. Compute balance excess r_excess = Σ r_in - Σ r_out - r_fee
  6. Generate balance proof (Σ-protocol for r_excess)
  7. Generate Unified ZKP per input:
     - Membership (Merkle OR-proofs, position hidden)
     - Key ownership (pk = a·s, Σ-protocol)
     - Nullifier binding (null_poly = a_null·s, algebraic)
  8. Encrypt (amount, blind) to recipient via ML-KEM stealth

Verifier (qdag_verify):
  0. DoS pre-check (sizes, counts, version)
  1. Root binding (recomputed Merkle root == declared)
  2. Chain ID consistency in ring leaves
  3. Unified ZKP verification per input
  4. Range proofs per output
  5. Confidential fee verification
  6. Balance proof (Σ C_in = Σ C_out + C_fee)
  7. Nullifier uniqueness (DAG state manager)
```

## Consensus

GhostDAG BlockDAG with deterministic total ordering.

```
Block reception → Parent availability check → DAG insertion
  → GhostDAG scoring (blue/red classification)
  → Selected Parent Chain construction
  → Total Order (blue_score ascending, hash tiebreak)
  → Delayed state evaluation (nullifier conflict resolution)
  → UTXO commitment update
```

Conflict resolution: first nullifier in total order wins.
Failed TX stays in DAG (fail-soft) but doesn't affect state.

## Crate Map

| Crate | Purpose | Status |
|-------|---------|--------|
| misaka-pqc | Post-quantum cryptography (ZKP, commitments, proofs) | Active |
| misaka-dag | GhostDAG consensus, state manager, block production | Active |
| misaka-consensus | Header validation, staking registry, validator set | Active |
| misaka-node | Validator/observer node binary | Active |
| misaka-crypto | SHA3, validator signatures (ML-DSA) | Active |
| misaka-types | Core type definitions | Active |
| misaka-storage | UTXO set, block store, crash recovery | Active |
| misaka-p2p | P2P handshake, peer management | Active |
| misaka-rpc | RPC type definitions | Active |
| misaka-bridge | Cross-chain bridge (Lock-and-Mint) | Active |
| misaka-cli | Command-line wallet + keygen | Active |
| misaka-mempool | Transaction mempool | Active |
| misaka-tokenomics | Supply schedule, inflation | Active |
| misaka-governance | On-chain governance | Active |
| misaka-mev | MEV protection | Active |
| misaka-test-vectors | Test vector generation | Active |

## Security Audit Status

| Finding | Severity | Status |
|---------|----------|--------|
| A. NullifierProof algebraic binding | CRITICAL | Fixed (dual-relation Σ) |
| B. AggRangeProof soundness | CRITICAL | Feature-gated |
| C. ConfidentialFee proven proof | HIGH | Fixed (bit-decomposition) |
| G. Stealth atomic verify | CRITICAL | Fixed (try_recover_verified) |
| H. Zeroization | HIGH | write_volatile + SeqCst |
| K. Persistent store fallback | HIGH | Fixed (explicit error) |
| D. Anonymity documentation | MEDIUM | Fixed |
| F. Decoy selection | MEDIUM | Gamma(19.28, 1.61) |

## Running

```bash
# Observer node
cargo run --release --bin misaka-node -- --mode public --chain-id 2

# Validator node
MISAKA_VALIDATOR_SK=<hex> MISAKA_VALIDATOR_PK=<hex> \
  cargo run --release --bin misaka-node -- --mode public --validator --chain-id 2

# Generate keys
cargo run --release --bin misaka-cli -- keygen
```

## License

MIT OR Apache-2.0
