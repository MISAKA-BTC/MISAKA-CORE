# Tokenomics Audit R2

## Scope: crates/misaka-tokenomics/ + misaka-consensus/src/staking.rs + reward_epoch.rs + validator_rewards.rs

## CRITICAL

### C1: Treasury send path lacks consensus verification (distribution.rs + reward_epoch.rs)
- **Problem:** Reward distribution computes treasury amount but no consensus-level check verifies that funds actually go to the official treasury address. Validator can route to personal address.
- **Attack:** Modified node sends treasury share to attacker address. Other validators don't verify destination. 10% of all fees siphoned per epoch.
- **Fix:** Add treasury address to consensus state. Block validation verifies treasury output exists with correct amount and address.

## HIGH

### H1: u128 overflow in reward weight × pool (reward.rs:226)
- `validator_pool_total * weight` can overflow u128 with extreme stake/score values.
- Fix: Use `checked_mul()` with cap at pool total.

## MEDIUM

### M1: Stake weight clamping breaks proportionality (reward.rs:127-133)
- `linear_stake_weight()` clamps to u64::MAX. Validators above threshold get identical weight regardless of 10x stake difference.
- Fix: Use u128 throughout weight calculation.

### M2: Fee burn rounding not formally specified (distribution.rs:40-42)
- Floor rounding with dust-to-burn is correct but undocumented. Cross-implementation disagreement causes fork.
- Fix: Document rounding direction. Add assertion `proposer + treasury + burned == total`.
