# Configs Audit R3

## HIGH
- **H2** mainnet.toml:87 — Weak subjectivity checkpoint is all-zeros placeholder.
  Fix: Update to real genesis hash before launch.

## MEDIUM
- **M7** mainnet.toml:38 — RPC port 3001 not documented as requiring firewall.
- **M8** mainnet.toml:32 — Session lifetime 24h. Validators should enforce 4h max.
