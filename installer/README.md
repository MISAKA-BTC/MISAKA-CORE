# MISAKA One-Click Node Installer

Join the MISAKA Network with a single click.

## Quick Start

```bash
# Option 1: Run the installer script directly
curl -sSL https://install.misaka.network | bash

# Option 2: Clone and run
git clone https://github.com/user/MISAKA-CORE.git
cd MISAKA-CORE/installer
./install.sh
```

## Supported Roles

| Role | Difficulty | Resources | One-Click |
|------|-----------|-----------|-----------|
| **Observer** | Easy | Minimal (2GB RAM, 10GB disk) | Yes |
| **Candidate** | Easy | Moderate (4GB RAM, 50GB disk) | Yes |
| **Archive** | Medium | High (8GB RAM, 500GB+ disk) | Yes |
| **Relay** | Medium | Moderate + public IP | Yes |
| **SR (Testnet)** | Advanced | High (8GB+ RAM, public IP) | Testnet only |
| **SR (Mainnet)** | Expert | 16GB RAM, dedicated server | Manual only |

## Architecture

```
installer/
  install.sh          — Cross-platform bootstrap script
  src/
    main.rs           — Tauri app entry point
    config_gen.rs     — Auto-config generation per role
    system_check.rs   — Hardware/network requirement checks
    ui/
      index.html      — Main UI (single-page app)
```

## Security

- Binary checksums verified via SHA256SUMS
- Signatures verified via minisign (when available)
- Admin interfaces bound to localhost only
- SR mode disabled on mainnet in one-click flow
- Outbound-only networking by default for local users
