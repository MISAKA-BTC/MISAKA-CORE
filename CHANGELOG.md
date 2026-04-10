# Changelog

All notable changes to the MISAKA-CORE project will be documented in this file.

## [Unreleased]

### BREAKING CHANGES

- **Removed shielded transaction pool and Q-DAG-CT confidential transactions.**
  The shielded path depended on Groth16 (BLS12-381) and dusk-PLONK (BLS12-381),
  both of which rely on pairing-based cryptography and are broken by Shor's
  algorithm. The SHA3-based fallback backend was not zero-knowledge. Rather
  than ship a transitional implementation that contradicts MISAKA's
  "PQ-native" positioning, the entire shielded subsystem was removed.
  Future post-quantum ZK support may be reintroduced via lattice-based SNARKs
  or hash-based STARKs once those ecosystems mature.

### Removed

- `misaka-shielded` crate (9,457 LOC)
- `misaka-pqc` shielded/Q-DAG-CT modules: bdlop, range_proof, unified_zkp,
  composite_proof, qdag_tx, confidential_fee, confidential_stealth, membership,
  nullifier, privacy_*, pq_stealth, stealth_v2, ki_proof, packing, stark_proof,
  zkmp_builder, output_recovery, verified_envelope, zkp_types, ntt, transcript,
  crypto_types, secret, key_purpose, tx_codec (14,570 LOC)
- Pairing dependencies: ark-groth16, ark-bls12-381, ark-ff, ark-snark,
  ark-serialize, ark-std, ark-relations, dusk-plonk, dusk-bytes
- Shielded RPC endpoints: /api/submit_ct_tx, /api/shielded/*
- CLI commands: shielded subcommands, --to-kem-pk, --shielded flags,
  CtTransfer command
- TxType variants: ShieldDeposit (0x07), ShieldedTransfer (0x08),
  ShieldWithdraw (0x09)
- Config sections: [shielded] in mainnet/testnet/devnet TOMLs (replaced
  with deprecation comments)
- Feature flags: shielded, shielded-groth16-verifier, shielded-plonk-verifier,
  stark-stub, qdag-ct, experimental-privacy, stealth-v2, dev-stub-proof
- `misaka-consensus::zkp_budget` module (360 LOC)
- `misaka-dag::qdag_verify` module (325 LOC)
- C-2 fail-closed shielded guard in config_validation.rs (target removed)
- Validation path: Q-DAG-CT composite proof verification in block_validation.rs,
  privacy constraint/statement construction in tx_resolve.rs and block_apply.rs
- 13 shielded test/benchmark scripts
- 5 shielded documentation files
- Total deletion: ~66,000 LOC across 9 refactor steps

### Changed

- `misaka-pqc` reduced from ~16,000 LOC to 1,988 LOC. Remaining modules:
  domains, error, pq_sign (ML-DSA-65), pq_kem (ML-KEM-768), canonical_ki,
  key_derivation
- `pq_ring` module replaced by `key_derivation` (SpendingKeypair, Poly,
  derive_public_param, compute_key_image extracted; ring signature logic
  removed)
- `block_validation.rs` simplified: ML-DSA-65 signature verification is now
  unconditional (previously gated by Transparent backend check). The four
  core verification steps (ML-DSA-65 signature, key_image uniqueness,
  UTXO balance, fee) are preserved and verified intact.
- `nullifier` concept retained in storage/mempool under the same name but now
  exclusively tracks transparent TX `key_image` values for double-spend
  prevention. Renaming to `spent_key_image` / `key_image_set` is deferred to
  a follow-up PR to keep this diff reviewable.

### Deprecated (retained for wire/storage compatibility)

- `SpendUniquenessTag::ShieldedNullifier` variant -- no new writes, retained
  for deserializing historical data
- `Capability::ShieldedScanOnly = 0x0010` -- discriminant reserved, do not reuse
- `PeerCapability::_RESERVED_CT = 0b0001_0000` -- bit position reserved
- Wire type `0x0600` (ShieldedTx), `0x0603` (ShieldedNullifierBroadcast) --
  P2P payload discriminants reserved

### Known Issues (pre-existing, not caused by shielded removal)

- `misaka-dag` byzantine tests `test_bft_split_votes_no_false_commit` and
  `test_equivocating_authority_detected_and_consensus_continues` fail
  (consistent with pre-removal baseline)
- `cargo build --workspace --all-features` fails on a brace mismatch in
  `dag_rpc_legacy.rs` triggered by the combination of `dev-rpc` + `faucet`
  features. Default builds are unaffected. Pre-existing.
- `dag_rpc_legacy.rs` lines 34, 1579, 1637 reference the deleted
  `PrivacyBackendFamily` type inside dead code paths. Reachable only through
  the above broken `--all-features` path. To be cleaned up in the follow-up
  brace-fix PR.
- v1 linear-chain modules (`chain_store.rs`, `block_producer.rs`, v1
  `rpc_server.rs`) gated by `#[cfg(not(feature = "dag"))]` are effectively
  dead -- `dag` is default-enabled everywhere. They still contain
  `PrivacyBackendFamily` references and will not compile under
  `--no-default-features`. These modules should be deleted in a separate
  v1-removal PR.
- Pre-existing `#[deny(clippy::unwrap_used)]` violations in `misaka-security`,
  `misaka-types`, `misaka-governance`, etc. -- unrelated to shielded.
- Pre-existing unused dependencies reported by `cargo machete` in
  `misaka-node`, `misaka-consensus`, `misaka-mev`, `misaka-notify`, etc. --
  unrelated to shielded.

### TODO (follow-up PRs)

- Rename `nullifier` / `key_image` terminology in storage layer to
  `spent_key_image` / `key_image_set` for clarity
- Delete v1 linear-chain modules (`#[cfg(not(feature = "dag"))]` dead code)
- Fix `dag_rpc_legacy.rs` brace mismatch under `--all-features`
- Remove `PrivacyBackendFamily` dead references from dag_rpc_legacy.rs
