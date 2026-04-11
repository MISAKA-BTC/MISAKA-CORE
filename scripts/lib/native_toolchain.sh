#!/usr/bin/env bash

# Shared helpers for native build dependencies and bindgen header discovery.
# Source this file from operator/startup scripts before invoking cargo build.

misaka_native_toolchain_packages() {
  printf '%s\n' build-essential pkg-config libssl-dev clang libclang-dev cmake
}

misaka_prepare_native_toolchain() {
  if ! command -v apt-get >/dev/null 2>&1; then
    return 0
  fi

  sudo apt-get update -qq
  sudo apt-get install -y -qq $(misaka_native_toolchain_packages) >/dev/null
}

misaka_resolve_bindgen_extra_clang_args() {
  if [[ -n "${BINDGEN_EXTRA_CLANG_ARGS:-}" ]]; then
    printf '%s\n' "$BINDGEN_EXTRA_CLANG_ARGS"
    return 0
  fi

  if command -v gcc >/dev/null 2>&1; then
    local gcc_include
    gcc_include="$(gcc -print-file-name=include)"
    if [[ -n "$gcc_include" && -d "$gcc_include" ]]; then
      printf '%s\n' "-isystem $gcc_include"
      return 0
    fi
  fi

  if command -v clang >/dev/null 2>&1; then
    local clang_include
    clang_include="$(clang -print-resource-dir 2>/dev/null)/include"
    if [[ -n "$clang_include" && -d "$clang_include" ]]; then
      printf '%s\n' "-isystem $clang_include"
      return 0
    fi
  fi

  printf '%s\n' ""
}

misaka_export_bindgen_env() {
  local resolved
  resolved="$(misaka_resolve_bindgen_extra_clang_args)"
  if [[ -n "$resolved" ]]; then
    export BINDGEN_EXTRA_CLANG_ARGS="$resolved"
  fi
}
