# BUG: mainnet unbonding_epochs = 10,080 → 27.6 years

**Severity**: HIGH (economic, not safety) — no validator can ever exit mainnet.
**Status**: Open. Discovered 2026-04-18 during Phase 0.5b investigation.
**Not caused by**: the 10s block-time change (this is pre-existing).

## Evidence

- `crates/misaka-consensus/src/staking.rs:115`
  ```rust
  impl Default for StakingConfig {
      fn default() -> Self {
          Self {
              // ...
              unbonding_epochs: 10_080,   // ← THIS LINE
              // ...
          }
      }
  }
  ```
- `crates/misaka-types/src/constants.rs:93-94`
  ```rust
  pub const EPOCH_TIME_SECS: u64 = TIME_24_HOURS;            // 86_400
  pub const EPOCH_LENGTH: u64 = fast_depth(EPOCH_TIME_SECS); // 43_200 blocks = 24h
  ```
- Unbonding gate at `staking.rs:261`, `staking.rs:637`:
  ```rust
  current_epoch >= exit_epoch + config.unbonding_epochs
  a.unlock_epoch = Some(current_epoch + self.config.unbonding_epochs);
  ```
  `current_epoch` advances once per `EPOCH_LENGTH` committed slots
  (`bft_event_loop.rs:397-398`), so each unit of `unbonding_epochs` is
  one wall-clock day.

- `crates/misaka-config/src/node_config.rs:79`:
  `staking_unbonding_period: 43200` (NodeConfig override applied via
  `staking_config_builder.rs:53`) — also wrong; 43,200 epochs × 24h
  = 118 years. Likely the author entered a block count believing the
  field was in blocks.

## Industry comparison

| Chain | Unbonding |
|---|---|
| Cosmos Hub | 21 days |
| Ethereum (withdrawal queue) | ~days |
| Sui | 24h |
| Solana | ~1 epoch (~2 days) |
| **MISAKA mainnet (current)** | **10,080 days (27.6 years)** |

## Recommended fix (separate PR — DO NOT fold into v0.8.9)

```rust
// staking.rs
impl Default for StakingConfig {  // mainnet default
    fn default() -> Self {
        Self {
            unbonding_epochs: 21,   // 21 days, matches Cosmos Hub
            // ...
        }
    }
}
pub fn testnet() -> Self {
    Self {
        unbonding_epochs: 3,        // 3 days, fast testnet iteration
        // ...
    }
}
```

```rust
// node_config.rs — make the override meaningful
pub staking_unbonding_period: u64,  // EPOCHS, not blocks
// default stays 0 (let StakingConfig decide) OR set 21 for clarity
staking_unbonding_period: 0,
```

Also consider renaming the field `staking_unbonding_period` →
`staking_unbonding_epochs` so the unit is in the name.

## Why not fix now

- v0.8.9 combined PR (`feature/v089-storage-and-interval`) is scoped
  to storage + 10s timing only. User explicitly: "本 PR の scope 外
  として issue list に記録".
- This is a config-value fix, atomic reset-safe, and fits a
  staking/reward system PR cleanly.
- Mainnet has never launched with this config, so no real users are
  stuck — there is no emergency timeline.

## Related files to audit in the fix PR

- `crates/misaka-types/src/validator_stake_tx.rs:37` — `MIN_UNBONDING_EPOCHS: u64 = 100` — this floor must be lowered below 21 or it will reject any sane mainnet config.
- `crates/misaka-consensus/src/staking.rs:135` — testnet override.
- `crates/misaka-node/src/staking_config_builder.rs:68-116` — tests assert the current wrong values; update alongside the fix.
