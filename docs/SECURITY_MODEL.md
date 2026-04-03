# MISAKA Network Security Model

## Fundamental Assumption: All Code Is Public

MISAKA operates under the principle that **all source code, build scripts, and
configuration templates are assumed to be public knowledge**. Security does NOT
depend on obscurity of any algorithm, protocol rule, or implementation detail.

## Security Depends Only on Cryptographic Hardness

| Primitive | Purpose | Standard |
|-----------|---------|----------|
| ML-DSA-65 (Dilithium) | Digital signatures, committee attestations | FIPS 204 (NIST PQC) |
| ML-KEM-768 (Kyber) | Key encapsulation for encrypted channels | FIPS 203 (NIST PQC) |
| BFT 2/3 threshold | Consensus and bridge finality | Classical BFT |
| SHA3-256 | Hashing, domain separation, commitment | FIPS 202 |
| HKDF-SHA3 | Key derivation | RFC 5869 |
| ChaCha20-Poly1305 | Authenticated encryption | RFC 8439 |

All security guarantees reduce to the computational hardness of the above
primitives. No "security through obscurity" is employed.

## What Attackers CANNOT Do

Even with full access to the source code, an attacker **cannot**:

1. **Forge ML-DSA-65 signatures** without possessing the corresponding private
   key. This protects transaction authorization, block proposals, and bridge
   committee attestations.

2. **Recover private keys** from public keys, signatures, or encrypted traffic.
   ML-DSA-65 and ML-KEM-768 are believed to be resistant to both classical and
   quantum attacks.

3. **Bypass the 2/3 BFT threshold** for consensus or bridge operations. An
   attacker must compromise at least 2/3 of the committee members to forge a
   quorum, which requires independently compromising multiple independent keys.

4. **Replay bridge transactions**. Every bridge operation carries a unique
   nullifier that is persisted and checked before processing.

5. **Decrypt past traffic** even if a long-term key is later compromised,
   thanks to ephemeral key agreement (forward secrecy via ML-KEM-768).

6. **Exploit timing side-channels** in key comparison or signature verification.
   All sensitive comparisons use constant-time operations.

## What Attackers CAN Do

With access to the source code, an attacker **can**:

1. **Read all protocol rules** including consensus logic, bridge verification
   thresholds, and fee calculations.

2. **Build the exact same binary** from source. The build is reproducible.

3. **Run their own node** and participate in the network as a peer.

4. **Analyze the codebase** for potential vulnerabilities and submit them via
   responsible disclosure.

5. **Observe all on-chain data** including transactions, blocks, and bridge
   events (shielded transactions excepted).

## Security Boundary Table

| Boundary | Trust Assumption | Failure Mode |
|----------|-----------------|--------------|
| Node operator key | Operator keeps private key secret | Node impersonation |
| Validator committee (2/3) | Fewer than 1/3 of validators are Byzantine | Consensus safety violation |
| Bridge committee (2/3) | Fewer than 1/3 of bridge signers compromised | Unauthorized bridge withdrawal |
| RPC API key | Operator configures and protects API key | Unauthorized write access to node |
| P2P transport (ML-KEM-768) | KEM is computationally hard | Traffic decryption |
| Shielded pool (ZK proofs) | ZK circuit is sound | Privacy breach |
| Rate limiting | Configured per-deployment | DoS amplification |

## Defense-in-Depth Layers

1. **Cryptographic**: ML-DSA-65, ML-KEM-768, SHA3-256
2. **Protocol**: BFT 2/3, replay protection, domain separation
3. **Application**: Rate limiting, circuit breakers, anomaly detection
4. **Operational**: Log sanitization, secret management, binary hardening
5. **CI/CD**: Secret scanning, feature gating, dependency auditing
