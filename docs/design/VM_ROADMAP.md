# VM Roadmap

## Current State (Phase 25)

MISAKA does NOT have a VM layer. The old `misaka-vm` crate (568 lines,
wasmtime shell with `Ok(vec![])` placeholder) was deleted in Phase 25.

## Extension Points (Phase 0 design, preserved)

- `Executor` trait: `crates/misaka-execution/src/executor_trait.rs`
- `StateRoot { native, vm, combined }`: vm field is `Hash::ZERO` until VM is added
- `Transaction::tx_type::Vm(u32)`: currently rejected with `VmNotEnabled`

## v1.1 Plan (if VM is desired)

1. Create new crate `misaka-vm-wasm`
2. Add `wasmtime` dependency (WASI preview2)
3. Implement `WasmExecutor: Executor`
4. Wire into `misaka-node` Builder
5. Route `TxType::Vm(0)` to WasmExecutor
6. StateRoot combines `native` + `vm` roots

## Why Not Now

- Solo developer: VM is months of work
- Current strategy: PQ-native L1 + Mysticeti + Solana bridge
- VM is a v1.1 feature, not a launch blocker
- Transparent UTXO mode is sufficient for launch
