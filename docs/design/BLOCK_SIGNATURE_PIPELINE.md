# Block Signature Pipeline Design

## CR-1: block_manager.rs verifier was a stub accepting any non-empty bytes

## What is signed

```
block_id = SHA3("MISAKA-BLOCK-ID:v2:" || author || round || parents_hash || payload_len || payload || timestamp_ms)
signature = ML-DSA-65.sign_with_domain(sk, DOMAIN_NARWHAL_BLOCK, block_id)
```

The block_id is computed from `compute_hash()` (already canonical in block_manager.rs).
The signature covers the block_id, NOT the raw bytes.

## Verification pipeline

```
RawBlock received
    │
    ├─ 1. Author range check
    ├─ 2. Timestamp drift check
    ├─ 3. Parent structure check
    ├─ 4. Hash integrity (recompute from fields)
    ├─ 5. ★ ML-DSA-65 signature verification ★  ← THIS WAS STUB
    │      │
    │      ├─ Look up author's PK from ValidatorSet
    │      ├─ ml_dsa_verify_with_domain(pk, DOMAIN_NARWHAL_BLOCK, block_id, sig)
    │      └─ Reject if verification fails
    │
    └─ VerifiedBlock
```

## Why `compute_hash` is the signing message

`BlockVerifier::compute_hash()` already produces a canonical, deterministic
hash of (author, round, parents, payload, timestamp). The signing message
IS this hash — `header.signing_message() = compute_hash(...)`.

Signer and verifier share the same `compute_hash()` function, ensuring
the signed message is identical on both sides.

## HI-2: canonical encoding

`compute_hash()` uses a hand-written encoding with length-prefixed fields.
This is not ideal (bcs would be better) but is DETERMINISTIC:
- Fixed-width integers in little-endian
- Length-prefixed arrays
- No optional fields
- Parent order preserved as-is (sorted by caller)

Changing to bcs would be a wire format breaking change. Deferred to v2.

## Signature NOT included in block_id

The block_id = hash(header fields). The signature is NOT hashed.
This is correct: block_id identifies CONTENT, signature proves AUTHORSHIP.
