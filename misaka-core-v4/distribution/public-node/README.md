# MISAKA Public Node

This package is the end-user build for joining the MISAKA testnet as a public node.

## Quick start

### Windows

Double-click `misaka-launcher.exe`.

### macOS

Double-click `start-public-node.command`.

### Linux

Run `./start-public-node.sh`.

## If the published seed is down

Use the packaged local bootstrap flow instead of waiting on the shared VPS.

### Windows

Double-click `start-self-hosted-testnet.bat`.

### macOS

Double-click `start-self-hosted-testnet.command`.

### Linux

Run `./start-self-hosted-testnet.sh`.

That starts:

- one local seed node on `6690`
- one public node on `6691`
- the public node pointed at `127.0.0.1:6690`

The local seed log is written to `logs/self-host-seed.log`.

## Port guide

Run the packaged doctor command when you need to know whether port forwarding is actually required.

```bash
./misaka-launcher doctor --profile public
./misaka-launcher doctor --profile seed
```

On Windows:

```bat
misaka-launcher.exe doctor --profile public
misaka-launcher.exe doctor --profile seed
```

`show-network-guide.*` runs the same check for the public profile.

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
./misaka-launcher self-host
```

On Windows:

```bat
misaka-launcher.exe --profile seed
misaka-launcher.exe --profile validator
misaka-launcher.exe self-host
```

## Notes

- The launcher starts `misaka-node` with `--config`.
- Seed updates are reloaded from `config/seeds.txt` every 30 seconds.
- The packaged default uses a fixed genesis timestamp so nodes agree on the same network bootstrap block.
- Joining as a plain public node does not require router port forwarding. Port forwarding matters when you want other peers to discover your node directly.
