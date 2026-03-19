# MISAKA Network — Chain Specification v0.4.2

**Post-Quantum Native Privacy Blockchain**

---

## 1. Overview

MISAKA Network is a Layer 1 blockchain with two core design principles:

- **Post-Quantum Security** — All cryptographic primitives are lattice-based (NIST PQC standards). No ECC anywhere in the protocol.
- **Privacy by Default** — Ring signatures for sender anonymity, stealth addresses for receiver anonymity.

### Key Properties

| Property | Value |
|----------|-------|
| Block Time | 60 seconds |
| Consensus | BFT with hybrid Ed25519 + ML-DSA-65 signatures |
| Transaction Model | UTXO |
| Sender Privacy | Ring signatures (LRS-v1 or ChipmunkRing-v1) |
| Receiver Privacy | ML-KEM-768 Stealth Addresses (v1 or v2) |
| Amounts | Public |
| Ring Size | 4–16 (LRS-v1) / 4–32 (ChipmunkRing-v1) |
| Key Image | Canonical, scheme-independent |
| Hash Function | SHA3-256 / SHA3-512 |
| Max TXs per Block | 1,000 |
| Chain ID (Mainnet) | 1 |
| Chain ID (Testnet) | 2 |

---

## 2. Cryptographic Primitives

### 2.1 ML-DSA-65 (FIPS 204)

Validator signatures, block proposals, committee votes.

| Parameter | Size |
|-----------|------|
| Public Key | 1,952 bytes |
| Secret Key | 4,032 bytes |
| Signature | 3,309 bytes |
| Security | NIST Level 3 |

### 2.2 ML-KEM-768 (FIPS 203)

Stealth address key exchange (receiver privacy).

| Parameter | Size |
|-----------|------|
| Public Key | 1,184 bytes |
| Secret Key | 2,400 bytes |
| Ciphertext | 1,088 bytes |
| Shared Secret | 32 bytes |
| Security | NIST Level 3 |

### 2.3 Hybrid Validator Signatures

Both Ed25519 and ML-DSA-65 must verify. Domain tag: `MISAKA-HYBRID-SIG:v1:`.

| Component | Size |
|-----------|------|
| Hybrid PK | 1,984 bytes (32 + 1,952) |
| Hybrid Sig | 3,373 bytes (64 + 3,309) |

### 2.4 Ring Signatures

Two schemes available, selected per-transaction via `ring_scheme` field:

#### LRS-v1 (Lyubashevsky lattice Σ-protocol)

| Parameter | Value |
|-----------|-------|
| q | 12,289 |
| n | 256 |
| η | 1 |
| τ | 46 |
| γ | 6,000 |
| β | 5,954 |
| Ring Size | 4–16 |
| TX Version | 0x01 |
| Scheme Tag | 0x01 |

#### ChipmunkRing-v1 (extended lattice ring signature)

| Parameter | Value |
|-----------|-------|
| q | 12,289 |
| n | 256 |
| η | 2 |
| τ | 46 |
| γ | 8,192 |
| β | 8,100 |
| Ring Size | 4–32 |
| TX Version | 0x02 |
| Scheme Tag | 0x02 |
| Status | ⚠ Pre-audit |

Both schemes share the same `RingScheme` trait interface and produce identical canonical key images from the same spending secret.

### 2.5 Canonical Key Image

Scheme-independent, deterministic. Prevents cross-scheme double-spend attacks.

```
KI = SHA3-256("MISAKA_KI_V1:" || SHA3-512(s.to_bytes()))
```

The canonical DST `MISAKA_KI_V1:` replaces the old scheme-specific DSTs. Both LRS and ChipmunkRing adapters use this canonical derivation.

### 2.6 Key Image Correctness Proof (Σ-Protocol)

Each scheme has its own KI proof format but proves knowledge of the same canonical key image derivation.

**LRS KI proof:** 576 bytes (32 challenge + 512 response + 32 commitment).
**ChipmunkRing KI proof:** 576 bytes (same structure, different parameters).

---

## 3. Transaction Model

### 3.1 UTXO Transaction

```
UtxoTransaction {
    version:      u8,     // 0x01 (LRS) or 0x02 (ChipmunkRing)
    ring_scheme:  u8,     // 0x01 (LRS) or 0x02 (ChipmunkRing)
    inputs:       Vec<RingInput>,
    outputs:      Vec<TxOutput>,
    fee:          u64,
    extra:        Vec<u8>,  // up to 1,024 bytes
}
```

### 3.2 Ring Input

```
RingInput {
    ring_members:   Vec<OutputRef>,  // 4–32 UTXO references
    ring_signature: Vec<u8>,         // scheme-dependent
    key_image:      [u8; 32],        // canonical, deterministic
    ki_proof:       Vec<u8>,         // scheme-dependent, REQUIRED
}
```

### 3.3 Transaction Output

```
TxOutput {
    amount:           u64,
    one_time_address: [u8; 20],
    pq_stealth:       Option<PqStealthData>,  // v1 (0x01) or v2 (0x02)
}
```

### 3.4 Privacy Properties

| Property | Mechanism | Status |
|----------|-----------|--------|
| Sender anonymity | Ring signatures (4–32 decoys) | ✅ |
| Receiver anonymity | ML-KEM-768 stealth addresses | ✅ |
| Amount privacy | — | ❌ Public (by design) |
| Double-spend prevention | Canonical key images | ✅ |
| Cross-scheme double-spend | Canonical KI DST | ✅ |

### 3.5 Stealth Address Protocol

**v1** — Original ML-KEM + HKDF + XChaCha20-Poly1305.
**v2** — Enhanced with versioned domain separation, optimized scan_tag, address commitment, optional encrypted memo.

Stealth v2 on-chain data:
```
StealthPayloadV2 {
    version:     0x02,
    kem_ct:      [u8; 1088],   // ML-KEM-768 ciphertext
    scan_tag:    [u8; 16],     // fast-rejection (constant-time)
    addr_commit: [u8; 20],     // one-time address commitment
    amount_ct:   Vec<u8>,      // AEAD encrypted amount (24 bytes)
    memo_ct:     Option<Vec<u8>>,  // AEAD encrypted memo
}
```

Domain labels (all v2-prefixed):
- `MISAKA_STEALTH_V2:root`
- `MISAKA_STEALTH_V2:address`
- `MISAKA_STEALTH_V2:scan`
- `MISAKA_STEALTH_V2:amount`
- `MISAKA_STEALTH_V2:memo`
- `MISAKA_STEALTH_V2:nonce`
- `MISAKA_STEALTH_V2:addr_commit`

Scan flow: quick_scan (scan_tag only) → full recover (AEAD decrypt).

---

## 4. Consensus

| Parameter | Value |
|-----------|-------|
| Block time | 60 seconds |
| Quorum threshold | 2/3 + 1 (6,667 bps) |
| Minimum validators | 4 |
| Epoch length | 720 checkpoints (~12 hours) |
| Proposer selection | Round-robin by slot |

Block validation dispatches ring signature verification by `tx.ring_scheme`:
- 0x01 → LRS verify + LRS KI proof
- 0x02 → ChipmunkRing verify + ChipmunkRing KI proof

Both check canonical key image uniqueness against the same spent-set.

---

## 5. Tokenomics

| Parameter | Value |
|-----------|-------|
| Genesis supply | 10,000,000,000 MISAKA |
| Initial inflation | 5% annual |
| Decay | -0.5% per year |
| Floor | 1% annual |
| Fee: Validator | 1.5% |
| Fee: Admin | 1.0% |
| Fee: Archive | 0.5% |

---

## 6. Network Architecture

### 6.1 Node Modes

| Property | Public | Hidden | Seed |
|----------|:------:|:------:|:----:|
| Inbound connections | ✅ | ❌ | ✅ |
| IP advertised | ✅ | ❌ | ✅ |
| Block production | ✅ | ✅ | ❌ |
| Peer discovery | ✅ | ❌ | ✅ |
| Max inbound | 48 | 0 | 128 |
| Max outbound | 16 | 16 | 32 |

**Use cases:**
- Seed Node → `--mode seed` (bootstrap)
- Explorer / Relay → `--mode public`
- Validator / Wallet → `--mode hidden`

Hidden nodes: TCP listener disabled, `listen_addr: None` in Hello, never in GetPeers.

### 6.2 P2P Messages

Hello, NewBlock, NewTx, GetPeers, Peers, RequestBlock, Ping/Pong.
Length-prefixed JSON over TCP, max 1 MB.

---

## 7. Cross-Chain Bridge (Solana)

### 7.1 Architecture

```
Solana (lock/unlock) ←→ Relayer ←→ Misaka (mint/burn + ZK-ACE authorization)
```

### 7.2 Misaka Side

- `BridgeVerifier` trait: pluggable authorization (MockVerifier dev-only, CommitteeVerifier production)
- `BridgeRequest` / `BridgeReceipt` with domain-separated `authorization_hash`
- `AssetRegistry` for registered bridgeable tokens
- `ReplayProtection` (nullifier set)
- Domain tags: `MISAKA_BRIDGE_MINT:v1:`, `MISAKA_BRIDGE_BURN:v1:`, `MISAKA_BRIDGE_RELEASE:v1:`

MockVerifier gated behind `#[cfg(feature = "dev-bridge-mock")]`. Default builds use CommitteeVerifier only.

### 7.3 Solana Anchor Program

PDA seeds (centralized constants, `misaka-bridge-` prefix):

| Account | Seeds |
|---------|-------|
| Config | `["misaka-bridge-config"]` |
| Vault Authority | `["misaka-bridge-vault-auth"]` |
| Vault | `["misaka-bridge-vault", mint]` |
| Asset Mapping | `["misaka-bridge-asset", asset_id]` |
| Lock Receipt | `["misaka-bridge-receipt", nonce]` |
| Nonce State | `["misaka-bridge-nonce", request_id]` |

Instructions: `initialize_bridge`, `register_asset`, `lock_tokens`, `unlock_tokens`, `pause_bridge`, `unpause_bridge`, `rotate_relayer`.

### 7.4 Relayer

- Bidirectional polling (Solana locks → Misaka mints, Misaka burns → Solana unlocks)
- Persistent processed-message store (JSON file)
- Deterministic idempotency keys: `SHA3-256(domain || tx_hash || amount || recipient)`
- Multi-instance safe via shared volume
- Docker Compose + systemd deployment

---

## 8. RPC Interface

14 endpoints: `get_chain_info`, `get_latest_blocks`, `get_block_by_height`, `get_block_by_hash`, `get_latest_txs`, `get_tx_by_hash`, `get_validator_set`, `get_validator_by_id`, `get_block_production`, `get_address_outputs`, `search`, `submit_tx`, `faucet`, `health`.

---

## 9. Crate Architecture

```
misaka-net-core/
  crates/
    misaka-types/         TX model, stealth, validator types, genesis
    misaka-crypto/        Hybrid signatures (Ed25519 + ML-DSA-65)
    misaka-pqc/           PQ crypto: LRS, ChipmunkRing, KI proof, stealth v1/v2,
                          RingScheme trait, canonical KI, NTT, wire codec
    misaka-storage/       UTXO Set with rollback
    misaka-mempool/       TX pool with scheme-aware PQ verification
    misaka-consensus/     BFT, block validation (scheme dispatch), proposer
    misaka-execution/     Block execution engine
    misaka-tokenomics/    Supply, inflation, fee distribution
    misaka-bridge/        Cross-chain bridge (ZK-ACE verifier trait)
    misaka-node/          Validator node (P2P, RPC, block producer)
    misaka-cli/           CLI tools (keygen, genesis, transfer)
    misaka-test-vectors/  Protocol test vectors
  solana-bridge/          Anchor program (lock/unlock/vault)
  relayer/                Bridge relayer (bidirectional, idempotent)
  docs/                   CHIPMUNK-AUDIT.md, chain spec
```

**Total:** ~13,600 lines Rust, 170+ tests, 17 crates.

---

## 10. Security Model

### Post-Quantum Security
All public-key crypto uses NIST PQC standards. Hybrid validator sigs include Ed25519 for performance; security relies on ML-DSA-65.

### Privacy Guarantees
- **Strong computational privacy** for sender (ring anonymity set 4–32)
- **Stealth address unlinkability** for recipient
- **Canonical key image determinism** prevents double-spend across signature schemes
- Amounts are public (design choice for auditability)

### Bridge Security
- MockVerifier completely gated behind dev feature flag
- CommitteeVerifier with M-of-N threshold, deduplication, domain separation
- Replay protection via nullifier set (Misaka) + PDA nonce state (Solana)
- PDA seeds prefixed to prevent cross-program collision

### Audit Status

| Component | Status |
|-----------|--------|
| LRS-v1 ring signature | Implemented, in production use |
| ChipmunkRing-v1 | ⚠ Pre-audit (see docs/CHIPMUNK-AUDIT.md) |
| Canonical Key Image | Implemented, tested cross-scheme |
| Stealth v2 | Implemented, 16 tests |
| Bridge MockVerifier | ✅ Dev-only gated |
| Bridge CommitteeVerifier | ⚠ Ed25519 sig verification pending |
| Solana PDA seeds | ✅ Prefixed, centralized |
| Relayer idempotency | ✅ Persistent store |

---

*MISAKA Network — Post-Quantum Native Privacy Blockchain*
*Specification version 0.4.2*
