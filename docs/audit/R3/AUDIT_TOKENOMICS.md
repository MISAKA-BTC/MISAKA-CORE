# Tokenomics Audit R3

## HIGH
- **H3** reward.rs:155 — Validator self-reward not limited. 51% staker gets 51% of fees
  with no cap. Fix: Add proposer reward cap or BFT proposer selection enforcement.

## MEDIUM
- **M9** distribution.rs:40 — total_fee * BPS can overflow u64. Fix: saturating_mul.
- **M10** reward.rs:179 — u128 overflow in weight calculation. Fix: checked_mul.
- **M11** distribution.rs:42 — Rounding dust to burn undocumented. Fix: add assertion.
- **M12** reward.rs:170 — ValidatorRewardInput.validator_id not format-validated.

## LOW
- **L4** reward.rs:88 — validator_id is String with no format check.
