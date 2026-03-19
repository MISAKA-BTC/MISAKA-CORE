# MISAKA Network — Security Policy

## Supported Versions

| Version | Status |
|---------|--------|
| mainnet-final | ✅ Active security support |
| mainnet-p0 | ⚠️ Superseded |
| testnet-v0.4.1 | ❌ Known critical issues |

## Cryptographic Primitives

| Component | Algorithm | Standard | PQ Security |
|-----------|-----------|----------|-------------|
| Signatures | ML-DSA-65 (Dilithium3) | FIPS 204 | Category III |
| KEM | ML-KEM-768 (Kyber768) | FIPS 203 | Category III |
| Ring Sig (default) | LogRing-v1 | Entropy 2026 | O(log n) |
| Ring Sig (legacy) | LRS-v1 | Lyubashevsky Σ | O(n) |
| Hash | SHA3-256 / SHA3-512 | FIPS 202 | 128-bit PQ |
| KDF | HKDF-SHA3-256 | RFC 5869 variant | — |

## Current Trust Assumptions

### Ring Signatures — Same-Amount Ring (Interim Measure)

The current protocol enforces **same-amount rings**: all UTXO members in
a ring must have identical amounts. This is an **interim privacy measure**
to prevent amount-inflation attacks where high-value decoys inflate
spendable amounts.

**Trade-off:** Same-amount rings limit the anonymity set to UTXOs of
exactly the same denomination. A future upgrade to committed amount
proofs (Bulletproofs/STARK-based) would remove this restriction.

**This is currently classified as an interim specification, not a
permanent design decision.** It will be revisited when range proof
infrastructure matures.

### Key Image / Link Tag Binding

**LogRing (mainnet default):** The link_tag is cryptographically bound to
the secret key within the ring signature Fiat-Shamir transcript. A valid
LogRing signature proves that the link_tag was derived from the correct
secret. **No separate KI proof is needed.**

**LRS (legacy) — Strong Binding KI Proof (v2):** The KI proof uses an
**algebraic dual-statement Σ-protocol**:

```
Statement 1: pk      = a    · s     (public key)
Statement 2: ki_poly = h_pk · s     (key image, h_pk = HashToPoly(pk))
```

The verifier **reconstructs both commitments** from the single response `z`:
```
w_pk' = a    · z - c · pk
w_ki' = h_pk · z - c · ki_poly
```

If `ki_poly ≠ h_pk · s`, then `w_ki'` is algebraically wrong, and the
recomputed challenge does not match. This is genuine Strong Binding:
the verifier checks the KI relation directly via algebra, not just
transcript inclusion.

The 32-byte nullifier: `key_image = SHA3-256(DST || ki_poly.to_bytes())`

### Block Validation

- **Proposer Signature**: Mandatory ML-DSA-65 verification
- **Block Hash Binding**: `proposal.block_hash` must match the canonical
  hash computed from (height, slot, parent_hash, tx_root)
- **Slot Binding**: `proposal.slot == block.slot` enforced

### Bridge (Solana)

The bridge is a **committee-operated bridge**, NOT trustless.
It does NOT perform SPV or ZK-Proof verification of Misaka chain state.
See `docs/BRIDGE-TRUST-MODEL.md` for the full trust analysis.

Key assumptions:
- At least M-of-N committee members must be honest
- Committee members verify source chain finality off-chain
- Request ID is recomputed on-chain (not trusted from args)
- Relayer is transport-only (no authority over funds)
- If ≥M committee members collude, arbitrary unlocks are possible

**Future roadmap (P1+):** Migrate to trust-minimized model via Light Client
verification or ZK-Bridge (verifying Misaka block finality proofs on Solana).

### Storage Model

- **Nullifier-based spending**: Only key_image/link_tag is recorded.
  The validator does not know which ring member was spent.
- **No real_input_refs**: The legacy API has been permanently removed.
  There is no code path that reveals which UTXO was consumed.

## Reporting Vulnerabilities

Please report security issues to: security@misakanetwork.com

Do NOT open public issues for security vulnerabilities.

## Known Limitations

| Priority | Limitation | Risk | Status |
|----------|-----------|------|--------|
| P1 | Storage not atomic (crash → corruption) | Data loss | Open |
| P1 | Same-amount ring limits anonymity set | Privacy | Interim (auto-denomination UX added) |
| P1 | Bridge is committee-operated, not trustless | Trust | Documented (BRIDGE-TRUST-MODEL.md) |
| P1 | Peer scoring not implemented | DoS | Open |
| P2 | STARK range proofs are stubs | Full privacy | Future |
| P2 | Bridge has no source finality proof | Trust model | Documented |
| P2 | No fuzz/property testing | Edge cases | Open |
