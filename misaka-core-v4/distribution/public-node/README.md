# MISAKA Public Node

This package is the end-user build for joining the MISAKA testnet as a public node.

## Quick start

### Windows

Double-click `misaka-launcher.exe`.

### macOS

Double-click `start-public-node.command`.

### Linux

Run `./start-public-node.sh`.

## What can be edited later

- `config/seeds.txt`
  Replace the published seed list here if the original bootstrap node goes down.
- `config/public-node.toml`
  Change ports, data directory, advertise address, or log level here.

## Included profiles

- `config/public-node.toml`
- `config/seed-node.toml`
- `config/validator-node.toml`

Advanced users can launch a different profile manually:

```bash
./misaka-launcher --profile seed
./misaka-launcher --profile validator
```

On Windows:

```bat
misaka-launcher.exe --profile seed
misaka-launcher.exe --profile validator
```

## Notes

- The launcher starts `misaka-node` with `--config`.
- Seed updates are reloaded from `config/seeds.txt` every 30 seconds.
- The packaged default uses a fixed genesis timestamp so nodes agree on the same network bootstrap block.
