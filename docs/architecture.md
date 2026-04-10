# MISAKA Network Architecture (v2)

One source of truth for the v2 refactoring. All implementation
decisions MUST reference this document.

Status: **FINAL** — all design decisions are locked. Changes to this
document require an explicit architectural review and a version bump
of this file.

---

## 1. Layer Stack

```
+-------------------------------------------------------------+
|                     RPC / API (axum)                         |
+-------------------------------------------------------------+
|              UtxoExecutor  (single tx gate)                  |
|  - borsh decode                                              |
|  - validate_structure                                        |
|  - expiry check                                              |
|  - UTXO existence + pubkey match                             |
|  - IntentMessage + ML-DSA-65 verify                          |
|  - amount balance                                            |
|  - UTXO delta + MuHash update                                |
+-------------------------------------------------------------+
|          Narwhal / Bullshark  (BFT consensus)                |
|  CoreEngine -> Linearizer -> commit_rx                       |
|  BlockVerifier: sig, ancestors (distinct-author), timestamp  |
+-------------------------------------------------------------+
|          NarwhalMempoolIngress  (admission)                   |
|  - structural pre-check only                                 |
|  - NO signature verification (deferred to UtxoExecutor)      |
+-------------------------------------------------------------+
|          P2P Transport (ML-KEM-768 + ML-DSA-65)              |
|  - PK allowlist on responder                                 |
|  - read_lp strict sizes (1952 / 3309)                        |
+-------------------------------------------------------------+
|          Storage (RocksDB)                                   |
|  - RocksBlockStore (fsync: mainnet only)                     |
|  - UtxoSet + MuHash state_root                               |
|  - Narwhal RocksDbConsensusStore (WAL)                       |
+-------------------------------------------------------------+
```

Product identity:
  **"PQ-native DAG-BFT UTXO L1 — the first production UTXO chain
  with Narwhal/Bullshark consensus and ML-DSA-65 signatures."**

---

## 2. Core Types (borsh-serialized)

### 2.1 AppId

Uniquely identifies a MISAKA network instance. Embedded in every
IntentMessage to prevent cross-chain/cross-app replay.

```rust
#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq)]
pub struct AppId {
    /// Chain identifier.
    ///   mainnet  = 1
    ///   testnet  = 2
    ///   devnet   = 3
    ///   localnet = 100
    ///   simnet   = 255
    pub chain_id: u32,
    /// SHA3-256 of genesis committee manifest (deterministic).
    pub genesis_hash: [u8; 32],
}
```

### 2.2 IntentScope

```rust
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy)]
#[repr(u8)]
pub enum IntentScope {
    TransparentTransfer = 0,
    SystemEmission      = 1,
    Faucet              = 2,
    StakeDeposit        = 3,
    StakeWithdraw       = 4,
    SlashEvidence       = 5,
    NarwhalBlock        = 10,
    BftPrevote          = 11,
    BftPrecommit        = 12,
    CheckpointVote      = 13,
    BridgeAttestation   = 20,
    ValidatorRegister   = 21,
}
```

Note: `IntentScope::Coinbase` was removed. Per-block coinbase subsidy
does not exist in v2; validator compensation is delivered via
`SystemEmission` transactions at epoch boundaries.

### 2.3 IntentMessage

Replaces all ad-hoc domain-separation strings. Every ML-DSA-65
signature in the system signs an IntentMessage.

```rust
#[derive(BorshSerialize, BorshDeserialize)]
pub struct IntentMessage {
    /// What kind of action is being signed.
    pub scope: IntentScope,
    /// Which network instance this intent belongs to.
    pub app_id: AppId,
    /// Scope-specific payload (borsh-serialized inner struct).
    pub payload: Vec<u8>,
}

impl IntentMessage {
    /// Canonical signing digest.
    /// SHA3-256("MISAKA-INTENT:v1:" || borsh(self))
    pub fn signing_digest(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA-INTENT:v1:");
        h.update(&borsh::to_vec(self).expect("borsh"));
        h.finalize().into()
    }
}
```

### 2.4 TxKind

```rust
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TxKind {
    TransparentTransfer = 0,
    SystemEmission      = 1,   // epoch inflation payout (system-generated)
    Faucet              = 2,   // testnet/devnet only, rejected on mainnet
    StakeDeposit        = 3,
    StakeWithdraw       = 4,
    SlashEvidence       = 5,
}
```

Removed in v2:
- `Transfer` (ring-signed)
- `QDagCt`
- `Coinbase` (replaced by `SystemEmission`)

### 2.5 TxInput

```rust
#[derive(BorshSerialize, BorshDeserialize, Clone)]
pub struct TxInput {
    /// Reference to the UTXO being spent.
    pub previous_outpoint: Outpoint,
    /// ML-DSA-65 signature (3309 bytes) over IntentMessage.
    pub signature: Vec<u8>,
    /// Signer's ML-DSA-65 public key (1952 bytes).
    /// Must match the script_pubkey_hash of the referenced UTXO.
    pub pubkey: Vec<u8>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, PartialEq, Eq, Hash)]
pub struct Outpoint {
    pub tx_id: [u8; 32],
    pub index: u32,
}
```

### 2.6 TxOutput

```rust
#[derive(BorshSerialize, BorshDeserialize, Clone)]
pub struct TxOutput {
    /// Amount in base units (1 MISAKA = 10^9 base units).
    pub amount: u64,
    /// SHA3-256 hash of the recipient's ML-DSA-65 public key.
    /// P2PKH model: full PK is only revealed at spending time.
    pub script_pubkey_hash: [u8; 32],
}
```

Design note: v1 stored raw 1952-byte PK in `script_public_key`.
v2 uses P2PKH (hash-only) to reduce chain bloat from ~2KB to 32B
per output and protect unspent UTXOs from harvest-now-decrypt-later.

### 2.7 TxData

```rust
#[derive(BorshSerialize, BorshDeserialize, Clone)]
pub struct TxData {
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub fee: u64,
    /// Block height after which this tx is invalid.
    pub expiry: u64,
}
```

### 2.8 UtxoTransaction

```rust
#[derive(BorshSerialize, BorshDeserialize, Clone)]
pub struct UtxoTransaction {
    pub version: u8,         // = 2
    pub kind: TxKind,
    pub data: TxData,
}

impl UtxoTransaction {
    /// Canonical transaction ID.
    pub fn tx_id(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(b"MISAKA-TX-ID:v2:");
        h.update(&borsh::to_vec(self).expect("borsh"));
        h.finalize().into()
    }

    /// Validates structural invariants (no crypto).
    pub fn validate_structure(&self) -> Result<(), TxValidationError> {
        // - version == 2
        // - inputs.len() > 0  (except SystemEmission/Faucet)
        // - outputs.len() > 0
        // - fee >= 0
        // - each signature.len() == 3309  (except SystemEmission)
        // - each pubkey.len() == 1952     (except SystemEmission)
        // - no duplicate outpoints in inputs
        // - expiry > 0
    }
}
```

---

## 3. Wire Format (borsh)

All consensus-path serialization uses borsh. `serde_json` is NOT
permitted in consensus/executor code paths.

```
UtxoTransaction (borsh):
  [1B version][1B kind]
  [4B inputs_len]
    [32B tx_id][4B index][4B sig_len][sig_bytes][4B pk_len][pk_bytes]
    ...
  [4B outputs_len]
    [8B amount][32B script_pubkey_hash]
    ...
  [8B fee]
  [8B expiry]
```

Maximum transaction size: 1 MB (enforced at mempool admission).

---

## 4. UtxoExecutor Validation Pipeline

`crates/misaka-node/src/utxo_executor.rs` is the SOLE entry point
for applying committed transactions to state.

### 4.1 Input: LinearizedOutput from Narwhal

```rust
pub struct UtxoExecutor {
    app_id: AppId,
    utxo_set: UtxoSet,
    height: u64,
    muhash: MuHash,
    epoch_state: EpochState,  // for SystemEmission verification
}
```

### 4.2 Per-Transaction Validation (fixed order)

```
1. borsh::from_slice::<UtxoTransaction>(raw)?
2. tx.validate_structure()?
3. Dispatch by tx.kind:
   - SystemEmission -> validate_system_emission()  (see 4.3)
   - Faucet         -> reject if mainnet; else accept with limits
   - Others         -> continue to step 4
4. tx.data.expiry >= self.height   (reject expired)
5. For each input:
   a. utxo_set.get(input.previous_outpoint)        (UTXO must exist)
   b. SHA3-256(input.pubkey) == utxo.script_pubkey_hash  (pubkey match)
   c. If utxo was created by SystemEmission, enforce 300-block maturity
6. Build IntentMessage {
       scope:   IntentScope::TransparentTransfer,  (or matching kind)
       app_id:  self.app_id,
       payload: borsh(tx.data),
   }
7. For each input:
   verify_intent(&input.pubkey, &input.signature, &intent_msg)?
   (= ml_dsa_verify(pk, intent_msg.signing_digest(), sig))
8. sum(input_amounts) >= sum(output_amounts) + tx.data.fee
9. Apply UTXO delta atomically:
   - Remove spent UTXOs
   - Insert new UTXOs keyed by tx_id + output index
   - Update MuHash incrementally
10. self.height += 1  (after full batch)
```

### 4.3 SystemEmission Rules

`SystemEmission` is the only way new tokens enter circulation in v2.
It is a system-generated transaction inserted by the Narwhal block
producer at epoch boundaries.

```
Constraints (enforced by every validator):

- tx.data.inputs MUST be empty.
- At most 1 SystemEmission tx per committed batch.
- SystemEmission MUST appear exactly once per epoch, in the first
  committed block of the new epoch.
- sum(outputs.amount) MUST equal the expected epoch_emission for the
  current epoch (strict equality — not >=, not <=).
- Signature verification is skipped (no inputs to sign).
- Output distribution MUST follow stake-weighted allocation across
  the active validator set (see 5.4).
- Any deviation from expected_emission or stake-weighted distribution
  causes the executor to panic (state divergence signal).
```

### 4.4 Coinbase Maturity

Outputs created by `SystemEmission` transactions are subject to a
maturity period of **300 blocks** (~30 seconds at 10 BPS).

```
maturity_height = utxo.created_height + 300
if self.height < maturity_height {
    reject with CoinbaseNotMature
}
```

Rationale: Narwhal/Bullshark provides BFT finality so reorg-based
maturity is not strictly necessary, but 300 blocks gives operators
a 30-second monitoring window to detect and respond to divergence
or anomalous validator behavior before emission funds become
spendable.

Regular `TransparentTransfer` outputs have zero maturity.

### 4.5 Faucet Rules

- Mainnet (`chain_id == 1`): **Faucet txs MUST be rejected**.
  The faucet code path is compile-time excluded via
  `#[cfg(feature = "faucet")]`, and the feature is incompatible
  with `mainnet` build profile.
- Testnet / Devnet: Faucet txs accepted with per-address and
  per-day rate limits enforced at RPC layer.

### 4.6 Failure Semantics

If ANY transaction in a committed batch fails validation,
the node MUST panic. This is intentional: committed transactions
have passed BFT consensus, so a validation failure indicates
state divergence between validators — an unrecoverable condition
that must be detected immediately.

```rust
if let Err(e) = self.validate_and_apply(tx) {
    panic!(
        "FATAL: committed tx failed validation at height {}: {}. \
         This indicates state divergence — shutting down.",
        self.height, e
    );
}
```

---

## 5. Emission Schedule

### 5.1 No Per-Block Subsidy

**v2 has NO per-block coinbase subsidy.** The `block_reward(height)`
function is always zero. Validator compensation comes exclusively
from two sources:

1. Per-epoch inflation emission (via `SystemEmission` tx)
2. Per-block transaction fees (via proposer share)

Rationale: halving schedules are a PoW-era artifact. In PoS BFT
chains, halving creates periodic "security budget cliffs" that
drive validators to unstake when rewards drop below their
opportunity cost. A smooth annual-decay inflation model preserves
security incentives and is simpler to reason about.

### 5.2 Annual Inflation (decaying)

```
initial_rate = 500 bps (5.00%)
annual_decay = 50 bps per year
floor_rate   = 100 bps (1.00%)  — reached at year 8 and held thereafter

emission_rate(year) = max(floor_rate, initial_rate - annual_decay * year)

# Year-by-year table:
# year 0:  5.00%
# year 1:  4.50%
# year 2:  4.00%
# year 3:  3.50%
# year 4:  3.00%
# year 5:  2.50%
# year 6:  2.00%
# year 7:  1.50%
# year 8+: 1.00%  (floor, held indefinitely)
```

### 5.3 Epoch Emission

```
epoch_duration   = 24 hours  (configurable per network)
epochs_per_year  = 365
current_year     = (current_epoch / epochs_per_year)

epoch_emission = circulating_supply
               * emission_rate(current_year)
               / 10_000          // bps -> fraction
               / epochs_per_year
```

Where `circulating_supply` is the MuHash-verified sum of all UTXO
amounts at the start of the epoch (excluding burned/treasury-held
funds as defined by protocol config).

### 5.4 SystemEmission Distribution

Epoch emission is distributed stake-weighted across the active
validator set:

```
for each validator v in active_committee:
    validator_share = epoch_emission * stake(v) / total_stake()
    outputs.push(TxOutput {
        amount: validator_share,
        script_pubkey_hash: v.reward_address_hash,
    })

# Invariant: sum(outputs) == epoch_emission (strict)
# Rounding residuals are sent to the protocol treasury address.
```

### 5.5 Fee Distribution (per-block)

```
proposer_share  = 50%   # immediate to block proposer
treasury_share  = 10%   # immediate to treasury address
burn_share      = 40%   # destroyed (not emitted as any output)
```

Burn is implemented by simply not creating corresponding outputs —
the `burn_share` amount is deducted from circulating supply.

### 5.6 Supply Cap

```
MAX_SUPPLY = 10,000,000,000 MISAKA  (asymptotic)
DECIMALS   = 9  (base units: 10^18 max)
```

The 1% floor rate means supply approaches but never exceeds the
asymptotic cap. Burn from fees (40% of fees) provides a
counterweight that, under realistic fee volume, keeps net inflation
below the nominal rate.

---

## 6. State Commitment (MuHash)

### 6.1 Incremental Update

MuHash provides O(1) per-element state commitment updates:

```
On UTXO creation:
  muhash.add_element(borsh(outpoint || utxo_entry))

On UTXO spend:
  muhash.remove_element(borsh(outpoint || utxo_entry))

state_root = muhash.finalize()  // [u8; 32]
```

### 6.2 Block Header Integration

After each committed batch, `state_root` is included in the
next Narwhal block's metadata:

```rust
// In propose loop:
let state_root = executor.state_root();
propose_ctx.set_state_root(state_root);
```

BlockVerifier checks state_root continuity:
- Block at round R must reference the state_root produced by
  applying all transactions in the committed sub-DAG up to round R-1.

### 6.3 Snapshot

Full state snapshots for new node sync:
- Serialize entire UtxoSet + MuHash state to RocksDB checkpoint
- Verify snapshot by recomputing MuHash from scratch
- Frequency: every 10,000 blocks

---

## 7. Bridge Design (Solana)

### 7.1 Architecture

```
Solana Program  <-->  Relayer(s)  <-->  MISAKA Validator(s)
     |                    |                    |
  Burn event        Multi-RPC verify      Mint attestation
  (SPL burn)        Consensus check       Burn attestation
```

MISAKA uses a **burn-mint** bridge model: tokens burned on Solana
trigger a corresponding mint on MISAKA, and vice versa. There is
no custody pool on either side.

### 7.2 N-of-M Attestation

```
N = 2   (minimum attestations required)
M = 3   (total authorized relayers)
```

Design rationale:
- **N=1 is forbidden.** A single relayer is a single point of trust:
  one lying relayer could fabricate a burn event and trigger an
  unauthorized mint. N=1 MUST be rejected at compile time for any
  non-dev build (`compile_error!` in release builds).
- **N=M (unanimity) is not required.** Burn-mint has no custody
  secret to protect, so full agreement is unnecessary and hurts
  liveness (one relayer downtime halts the bridge).
- **N=2, M=3 is the floor.** Two independent relayers must agree
  on any burn/mint event, tolerating one faulty or compromised
  relayer. A 2-of-3 threshold is the smallest configuration that
  provides meaningful byzantine fault tolerance while remaining
  operationally feasible for a small team.
- Future expansion path: N=3, M=5 for decentralized operation.

### 7.3 Relayer Independence Requirements

The security of N-of-M collapses if the M relayers share
correlated failure modes. Operators MUST enforce:

1. Each relayer runs on a **physically distinct host** (separate
   VPS, separate cloud provider, or separate hardware).
2. Each relayer uses a **distinct Solana RPC provider**
   (e.g., Helius + QuickNode + self-hosted Solana full node).
   Multiple endpoints from the same provider do NOT count.
3. **At least one relayer MUST run a self-hosted Solana full node**
   as its RPC source. This guarantees that a simultaneous outage or
   compromise of all commercial RPC providers does not halt the bridge.
4. Each relayer's ML-DSA-65 signing key is stored on an
   **independent HSM or independent encrypted volume**. Key material
   MUST NOT be aggregated in a single git-secrets or vault instance.

### 7.4 Attestation Format

Each attestation signs an IntentMessage:

```rust
IntentMessage {
    scope: IntentScope::BridgeAttestation,
    app_id: AppId { chain_id, genesis_hash },
    payload: borsh(BurnAttestationPayload {
        burn_id: [u8; 32],              // SHA3-256(solana_tx_sig)
        solana_tx_signature: String,
        burn_amount: u64,
        burn_slot: u64,                 // Solana slot for finality check
        wallet_address: String,         // Solana burner
        misaka_receive_address: [u8; 32],
        nonce: u64,                     // replay protection
    }),
}
```

Signatures MUST use ML-DSA-65 (not SHA3-HMAC or any other scheme).
The mock `sha3(pk || msg)` verifier from v1 is explicitly deleted.

### 7.5 Multi-RPC Verification

Before signing an attestation, each relayer MUST independently
verify the Solana burn event against K >= 2 independent Solana
RPC endpoints:

```
1. Query getTransaction from RPC-1 at commitment=finalized
2. Query getTransaction from RPC-2 at commitment=finalized
3. (optional) Query from self-hosted Solana full node
4. Compare tuples: (amount, burner, mint, slot)
5. Only sign attestation if ALL queried RPCs agree exactly.
6. If any RPC returns a mismatching or missing result, REJECT
   and emit an alert — do NOT retry with a different RPC set.
```

Finality check:
- Solana slot MUST be at least 32 slots old when the attestation
  is created (matches Solana's "finalized" commitment level).

### 7.6 Replay Protection

- Each burn is keyed by `burn_id = SHA3-256(solana_tx_signature)`.
- MISAKA validators maintain a `processed_burns` set in state.
- Any mint attempt with a `burn_id` already in the set is rejected.
- `processed_burns` is pruned only by protocol-level garbage
  collection (>1 year old), never by user action.

---

## 8. Network / Chain ID Registry

| Network   | chain_id | chain_id (hex) | Notes             |
|-----------|----------|----------------|-------------------|
| Mainnet   | 1        | 0x4D534B01     | Production        |
| Testnet   | 2        | 0x4D534B02     | Public testnet    |
| Devnet    | 3        | 0x4D534B03     | SR6 Sakura VPS    |
| Localnet  | 100      | -              | Local dev only    |
| Simnet    | 255      | 0x4D534BFF     | Simulation        |

Configuration files:
- `configs/mainnet.toml` — `chain_id = 1`
- `configs/testnet.toml` — `chain_id = 2`
- `configs/devnet.toml`  — `chain_id = 3`

Cross-network replay is prevented by embedding `chain_id` in
every `AppId`, which is included in every `IntentMessage`
signing digest.

---

## 9. Deleted / Deprecated Features (v2)

The following are **REMOVED** in v2 and MUST NOT appear in
any production code. These are permanent deletions — there is
no v3 revival path for shielded/ring features.

| Feature | Reason |
|---------|--------|
| `TxType::Transfer` (ring-signed)         | Ring lattice ZKP not production-ready; permanent removal |
| `TxType::QDagCt`                         | Deprecated shielded variant |
| `TxKind::Coinbase`                       | Replaced by epoch-based `SystemEmission` |
| Block-level halving schedule             | Replaced by smooth inflation-only model |
| `proof_scheme` field                     | v2 is transparent-only |
| `key_image` / `ki_proof`                 | Ring nullifier model removed |
| `pq_stealth` / `one_time_address`        | Stealth addresses removed |
| `zk_proof` / `ZeroKnowledgeProofCarrier` | ZKP removed |
| Ring signature code                      | `LegacyProofData`, `ring_sign`, `ring_verify`, `MIN/MAX_ANONYMITY_SET` |
| `view_key` / `scan_tag`                  | Stealth scanning removed |
| `nullifier` / `shielded_pool`            | No shielded pool in v2 |
| `serde_json` in consensus path           | Replaced by borsh |
| `BodyProcessor`                          | Dead code; replaced by UtxoExecutor |
| `tx_validation_in_utxo_context.rs`       | Dead code; replaced by UtxoExecutor |
| `narwhal_tx_executor.rs`                 | Renamed to `utxo_executor.rs` |
| `PermissiveVerifier` (test-utils)        | Restricted to `#[cfg(test)]`, not feature-gated |
| `signing_digest()` (chain-less)          | Replaced by `IntentMessage::signing_digest()` |
| `signing_digest_with_chain()`            | Replaced by `IntentMessage::signing_digest()` |
| `compute_stored_tx_id()`                 | Replaced by `UtxoTransaction::tx_id()` |
| `StructuralVerifier` / `DummySigner`     | Fail-open stubs, permanently deleted |
| `DOMAIN_TX_SIGN` and ad-hoc domains      | Replaced by `IntentScope` enum |

Product positioning implications:
- The whitepaper MUST be updated to remove all references to
  shielded transactions, ring signatures, stealth addresses,
  and ZKP-based privacy.
- Replacement tagline: "PQ-native DAG-BFT UTXO L1 — the first
  production UTXO chain with Narwhal/Bullshark consensus."
- No "future work" section should mention shielded revival.

---

## 10. v2 Roadmap

### Phase 0: Architecture document (this file) — COMPLETE

### Phase 1: CRITICAL stop-gap (1-2 weeks)

Minimal changes to existing code to block audit CRITICAL findings.
No type changes, no borsh migration.

Deliverables:
- Replace `signing_digest()` with `signing_digest_with_chain()` at all call sites
- Add amount upper-bound check to `apply_coinbase`
- Remove `TxType::Transfer` (ring) from `execute_committed` allow list
- Replace bridge `verify_signature` SHA3-fake with real ML-DSA-65
- Change bridge default to N=2 / M=3, reject N=1 at compile time
- Fix `Committee::quorum_threshold` empty-committee panic
- Add distinct-author check to `BlockVerifier::check_ancestors`

Exit criteria: All 5 session-3 CRITICAL findings demonstrably fixed
in a testnet running Phase 1 code for at least 1 week without
new critical alerts.

### Phase 2: Structural unification (3-4 weeks)

Full type migration. The large refactor that this document was
written to enable.

Deliverables:
- Introduce `IntentMessage` / `IntentScope` / `AppId` types
- Migrate all signature paths to borsh + IntentMessage
- Delete `serde_json` from consensus path
- Replace `UtxoTransaction` with v2 types (P2PKH)
- Replace `TxKind::Coinbase` with `TxKind::SystemEmission`
- Implement epoch inflation emission logic
- Physically delete ring / shielded / ZK code
- Delete `BodyProcessor` and `tx_validation_in_utxo_context.rs`
- Rename `narwhal_tx_executor.rs` -> `utxo_executor.rs` and rewrite
- Unify quorum comparison to `>=` (single `reached_quorum` helper)
- Wire `RocksBlockStore` from `misaka-node/main.rs`
- Convert `BlockVerifier::check_timestamp` to parent-relative MTP

Exit criteria: External independent audit passes on Phase 2 code.

### Phase 3: State commitment + bridge hardening (2-3 weeks)

Deliverables:
- Integrate MuHash into UtxoSet, update per commit
- Include `state_root` in Narwhal block headers
- Implement bridge multi-RPC verification (K >= 2)
- Implement burn replay protection (`processed_burns` set)
- Migrate relayer API to axum, bind to 127.0.0.1 by default
- Add `subtle::ConstantTimeEq` to admin secret comparison
- Enforce relayer independence at startup (warn if configs share providers)

### Phase 4: Mainnet preparation (1-2 weeks)

Deliverables:
- Add P2P responder `allowed_initiator_pks` for validator ports
- Tighten `read_lp` bounds to exact ML-DSA sizes
- Flip RPC auth default to fail-closed
- Move `PermissiveVerifier` to `#[cfg(test)]` only
- CI: binary surface scan (no test-only strings in release)
- CI: grep invariants from Section 11
- Finalize genesis / chain_id / staking contract addresses
- Mainnet dry-run on devnet with production config

---

## 11. CI Invariants

The following MUST be enforced in CI. Any failure blocks merge:

```
# Serialization invariants
 1. grep -rn "serde_json" crates/misaka-node/src/utxo_executor.rs
    -> expect: 0 matches
 2. grep -rn "serde_json" crates/misaka-consensus/
    -> expect: 0 matches

# Signing invariants
 3. grep -rn "fn signing_digest\b\|signing_digest_with_chain"
        crates/ --include="*.rs" | grep -v "intent.rs"
    -> expect: 0 matches outside intent.rs
 4. grep -rn "ml_dsa_sign_raw\|ml_dsa_verify_raw" crates/
    -> expect: only inside crates/misaka-types/src/intent.rs

# Deleted feature invariants
 5. grep -rn "ring_verify\|ring_sign\|LegacyProofData\|key_image\
             \|pq_stealth\|one_time_address\|zk_proof\|proof_scheme\
             \|view_key\|scan_tag\|ZeroKnowledgeProofCarrier" crates/
    -> expect: 0 matches
 6. grep -rn "TxType::Transfer\b\|TxType::QDagCt\|TxKind::Coinbase" crates/
    -> expect: 0 matches
 7. grep -rn "halving\|HALVING\|halving_interval\|block_reward(" crates/
    -> expect: 0 matches (block_reward function must not exist)
 8. grep -rn "shielded\|stealth\|nullifier" crates/
    -> expect: 0 matches

# Dead code invariants
 9. cargo clippy --all-targets -- -D dead_code
    -> expect: 0 warnings
10. Every function matching pattern "fn (verify|validate|check)_"
    has at least one non-test caller (script-enforced)

# Release binary invariants
11. Release binary `strings` output contains none of:
      "PermissiveVerifier"
      "StructuralVerifier"
      "DummySigner"
      "simple HMAC-like scheme"
      "TODO(L2): Replace with real ML-DSA-65"
      "test-skip-scripts"

# Network binding invariants
12. No "0.0.0.0" literal in default config paths without an
    explicit --bind-all flag or MISAKA_ALLOW_PUBLIC_BIND=1 gate.

# Bridge invariants
13. Relayer build with N=1 must produce compile_error in non-dev profile.
14. Bridge attestation verification MUST call verify_intent().
```

---

## 12. Document Version

- **v2.0.0** (this document) — Finalized after Phase 0 review.

Final design decisions locked in this version:
- coinbase maturity: **300 blocks** (~30s at 10 BPS)
- halving model: **removed** — inflation-only emission
- bridge N-of-M: **2-of-3** with independence requirements
- shielded / ring / ZK: **permanent removal**, no v3 revival

Changes to this document require:
1. Version bump (semver)
2. Architectural review note appended to this section
3. Corresponding CI invariant updates in Section 11
