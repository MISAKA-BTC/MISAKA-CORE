# Cargo config

This directory contains platform-specific cargo configuration templates.

## Linux (Sakura VPS, Ubuntu with gcc/g++)

If you need the Linux build defaults for librocksdb-sys bindgen:

```bash
cp .cargo/config.linux.toml.example .cargo/config.toml
```

Do NOT commit this `config.toml` — it forces `CC=gcc` which breaks
macOS (clang) and Windows (MSVC) builds.

## macOS / Windows

No cargo config needed. Default toolchain auto-detection works.
