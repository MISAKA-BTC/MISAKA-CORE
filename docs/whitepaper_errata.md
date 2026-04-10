# MISAKA Whitepaper Errata

This document lists corrections and retractions relative to `misaka_whitepaper_ja.pdf`.

## v1.0 — Shielded Transaction Removal

**Affected sections**: Q-DAG-CT, Confidential Transfers, Shielded Pool,
BDLOP Commitment, Stealth Addresses, Zero-Knowledge Privacy

**Status**: REMOVED from implementation.

### Technical rationale

The whitepaper describes a shielded transaction subsystem built on:
- Groth16 proofs over BLS12-381 (pairing-based)
- dusk-PLONK proofs over BLS12-381 (pairing-based)
- A transitional SHA3-based hash commitment backend

Both pairing-based systems are broken by Shor's algorithm running on a
sufficiently large quantum computer. Retaining them contradicts the
whitepaper's central claim of post-quantum native design. The SHA3
alternative was found to be non-zero-knowledge: proof bytes contain
plaintext amounts and asset IDs, providing only integrity and not
confidentiality.

Rather than ship a configuration that the whitepaper's own threat model
would reject, the entire shielded subsystem was removed from the
implementation before mainnet launch.

### What the implementation actually provides

- **Transparent transactions only**: ML-DSA-65 (FIPS 204) signatures,
  ML-KEM-768 (FIPS 203) P2P key exchange, SHA3-256 hashing throughout
- **Key image double-spend prevention**: canonical_key_image derived from
  the spending keypair; identical UTXOs produce identical key images,
  enabling detection without revealing the spender's identity to a third
  party (though sender and receiver are visible on-chain)
- **BDLOP, ring signatures, stealth addresses, nullifier commitments,
  zero-knowledge membership proofs**: NOT IMPLEMENTED

### What may return in a future release

Post-quantum zero-knowledge proof systems are an active research area.
Candidates being monitored:

- Lattice-based SNARKs: LaBRADOR, Greyhound, Lantern
- Hash-based STARKs: Plonky2, RISC Zero, Winterfell, Aurora, Fractal

Reintroduction requires: (1) a production-ready reference implementation,
(2) proof/VK sizes compatible with MISAKA's block budget, (3) an
independent security audit, (4) a migration path that does not compromise
the transparent chain's soundness.

No timeline is committed.

### Scope of the removal

See [CHANGELOG.md](../CHANGELOG.md) for the full list of deleted modules,
RPC endpoints, CLI commands, TX type variants, feature flags, and
dependencies. Total removal: approximately 66,000 lines of code across
9 refactor steps.
