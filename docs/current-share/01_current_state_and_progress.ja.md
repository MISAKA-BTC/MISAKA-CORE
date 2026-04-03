# Current State And Progress

最終更新: 2026-04-01  
対象: `MISAKA-CORE-share-20260401`

## このコードベースが何を進めたものか

この share copy は、`MISAKA-CORE` の current local authoritative line を共有用に軽量化したものです。

主題は次です。

- shielded verifier line の実装前進
- multi-validator runtime proof / full-path proof の拡張
- operator / manifest / release gate の fail-closed 契約整理
- `MISAKA-CORE (1)` からの confined salvage

つまり、GitHub latest を別物にした fork ではなく、current local で completion に向けて積み上げている integration line です。

## いま何が進んでいるか

current line では、`SHA3 / Groth16-first / PLONK-first` の 3 backend について次が揃っています。

- bounded proof
- full-path restart continuity
- sequence-depth restart continuity
- startup/bootstrap verifier seam
- operator-readable runtime comparison
- manifest / release gate 側の fail-closed contract

multi-validator breadth も広がっていて、`2-validator / 3-validator / 4-validator / 5-validator / 6-validator` の full-path / sequence slices を current line で扱います。

特に current line の重要な到達点は次です。

- `6-validator full-path / 6-validator sequence-depth` が `SHA3 / Groth16-first / PLONK-first` の 3 backend で actual
- `shielded_runtime_comparison.sh` が `6-validator` breadth を operator summary として返す
- `shielded_vk_runbook_manifest.sh` が `6-validator` breadth を fail-closed で読む
- release gate / extended gate script contract も同じ `6-validator` line に追随
- broader integration proof の clean shutdown orchestration に `DagRpcServerService` が入っている
- `MISAKA-CORE (1)` 由来の import は wholesale merge ではなく confined salvage で入れている

## current signal

latest local line では次を基準 signal として扱っています。

- `cargo test -p misaka-node --bin misaka-node --quiet`
- `cargo test -p misaka-node --bin misaka-node --features shielded-plonk-verifier --quiet`
- `shielded_runtime_comparison.sh`
- `shielded_vk_runbook_manifest.sh`
- `dag_release_gate.sh`
- `dag_release_gate_extended.sh`

share copy には build artifact や `.tmp` は含めていません。  
そのため proof/gate の actual result は zip 内には同梱せず、コードと最小 docs だけに絞っています。

## completion の観点で見た current state

completion の正本は current local 側にありますが、この share copy で読むべき要点は次です。

- `5-validator` authoritative line は既に通過済み
- current line では `6-validator` も comparative / manifest / operator breadth に上がっている
- main gap は `>6-validator` broader integration、wider comparative evaluation、residual seam cleanup

要するに、基盤を作っている段階ではなく、completion に向けた最後の重い stop line を詰めている段階です。
