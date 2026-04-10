# MISAKA Mainnet v1.0 — Feature Scope

## Included ✅

- **Consensus**: Mysticeti v2 (Narwhal/Bullshark DAG BFT)
  - Direct/indirect commit, leader skip, equivocation detection
  - Leader timeout with exponential backoff
  - Ancestor scoring and dynamic leader rotation
- **Cryptography**: ML-DSA-65 / ML-KEM-768 (NIST FIPS 204/203)
  - Post-quantum native signatures (no Ed25519 fallback)
  - Domain-separated signing (8 distinct domains)
  - TypedKeypair with compile-time purpose enforcement
- **Transactions**: Transparent UTXO model
  - ML-DSA-65 signature verification on all spending keys
  - Nullifier-based double-spend prevention
- **Networking**: PQ handshake (ML-KEM-768 + ML-DSA-65 mutual auth)
- **Bridge**: Solana bridge with ML-DSA-65 committee verification
  - Nonce binding + monotonicity enforcement
  - Durable replay protection (fsync'd)
  - Circuit breaker (accounting invariant + finality lag)
- **Staking**: 21 Active + unlimited Backup, no-slash (ADA-style)
  - sqrt(stake) reward scaling, monthly rotation
  - Validator identity persistence (genesis manifest)
- **Storage**: RocksDB + WAL + JSON snapshot (crash recovery)

## NOT Included ❌

- **Shielded transfers**: Deferred to v1.1
  - ZKP backends (Groth16/PLONK) are NotImplemented
  - `TxType::ShieldDeposit/ShieldedTransfer/ShieldWithdraw` explicitly rejected
    in `validate_structure()` with "not enabled (v1.0)" error message
  - `shielded` feature gated: module declarations in main.rs behind
    `#[cfg(all(feature = "dag", feature = "shielded"))]`
  - CLI stub functions (derive_stub_commitment/derive_stub_ivk) deleted (Phase 27A)
  - Extension points preserved (StateRoot.vm, NullifierSet.by_block index)
- **Smart contract VM**: Deferred to v1.1+
  - misaka-vm crate deleted (Phase 25)
  - Executor trait + TxType::Vm variant preserved for future
- **Solana Bridge**: Deferred to v1.1 (Phase 35 audit)
  - misaka-bridge crate exists but is NOT imported by misaka-node (orphan)
  - No `/api/bridge/*` endpoints in the node
  - relayer/ has compilation errors and invalid Solana TX construction
  - CommitteeVerifier (M-of-N ML-DSA-65) is production quality but unwired
  - Bridge will be wired as a complete subsystem in v1.1
- **These features can be added without breaking changes**

## v1.1 Roadmap

1. arkworks integration + Groth16 verifier
2. BDLOP/SIS Merkle ZKP real implementation
3. External ZK audit (mandatory before shielded goes live)
4. Solana bridge: wire misaka-bridge into node, fix relayer, E2E test
5. Bridge committee: M-of-N ML-DSA-65 relayer fleet deployment
4. WasmExecutor (optional, TBD)

## Transparent Mode Differentiators

Even without shielded, MISAKA v1.0 is unique:
- First PQ-native L1 with real ML-DSA-65 consensus
- Mysticeti v2 fast-path (sub-second finality potential)
- Solana bridge with PQ committee verification
- UTXO parallelism (no shared-state bottleneck)
