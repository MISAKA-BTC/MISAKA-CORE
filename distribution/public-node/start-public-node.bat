@echo off
REM ===============================================================
REM   MISAKA Testnet - Public Node (Windows)
REM   Double-click to run.
REM ===============================================================

chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion
title MISAKA Testnet - Public Node

echo ===============================================================
echo   MISAKA Testnet - Public Node  (Windows)
echo   PQ Signature: ML-DSA-65 (FIPS 204)
echo   Consensus:    Mysticeti-equivalent DAG (Bullshark)
echo ===============================================================
echo.

set "SCRIPT_DIR=%~dp0"
set "BINARY=%SCRIPT_DIR%misaka-node.exe"
set "CONFIG=%SCRIPT_DIR%config\public-node.toml"
set "GENESIS=%SCRIPT_DIR%config\genesis_committee.toml"
set "SEEDS_FILE=%SCRIPT_DIR%config\seeds.txt"
set "SEED_PUBKEYS_FILE=%SCRIPT_DIR%config\seed-pubkeys.txt"
set "DATA_DIR=%SCRIPT_DIR%misaka-data"

REM --- Pre-flight checks -----------------------------------------
if not exist "%BINARY%" (
    echo [ERROR] misaka-node.exe が見つかりません:
    echo    %BINARY%
    echo    アーカイブを正しく展開してから再度実行してください。
    echo.
    pause
    exit /b 1
)
if not exist "%CONFIG%" (
    echo [ERROR] 設定ファイルが見つかりません: config\public-node.toml
    pause
    exit /b 1
)
if not exist "%GENESIS%" (
    echo [ERROR] genesis_committee.toml が見つかりません
    pause
    exit /b 1
)

REM --- First-run setup -------------------------------------------
REM v0.5.7: bundled-validator.key has been REMOVED. Each install now
REM generates a fresh ephemeral validator.key on first run and runs in
REM OBSERVER mode (key is not in the genesis committee).
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%DATA_DIR%\validator.key" (
    echo 初回起動: ephemeral observer key を生成します (validator.key)
)

REM --- Read seeds + pubkeys (both required or both skipped) ------
REM Narwhal relay は ML-DSA-65 PK-pinning 必須。両方揃っているときだけ
REM --seeds + --seed-pubkeys を渡します。揃わないときは seed を一切渡さず
REM solo mode で起動します (FATAL で落ちないように)。
set "SEEDS="
set /a SEEDS_COUNT=0
if exist "%SEEDS_FILE%" (
    for /f "usebackq eol=# tokens=*" %%a in ("%SEEDS_FILE%") do (
        set "TRIMMED=%%a"
        if not "!TRIMMED!"=="" (
            if defined SEEDS (
                set "SEEDS=!SEEDS!,%%a"
            ) else (
                set "SEEDS=%%a"
            )
            set /a SEEDS_COUNT+=1
        )
    )
)

set "SEED_PUBKEYS="
set /a PUBKEYS_COUNT=0
if exist "%SEED_PUBKEYS_FILE%" (
    for /f "usebackq eol=# tokens=*" %%a in ("%SEED_PUBKEYS_FILE%") do (
        set "TRIMMED=%%a"
        if not "!TRIMMED!"=="" (
            if defined SEED_PUBKEYS (
                set "SEED_PUBKEYS=!SEED_PUBKEYS!,%%a"
            ) else (
                set "SEED_PUBKEYS=%%a"
            )
            set /a PUBKEYS_COUNT+=1
        )
    )
)

set "USE_SEEDS=0"
if !SEEDS_COUNT! GTR 0 (
    if !SEEDS_COUNT! EQU !PUBKEYS_COUNT! (
        set "USE_SEEDS=1"
    ) else (
        echo [WARN] seeds.txt (!SEEDS_COUNT! entries) と seed-pubkeys.txt (!PUBKEYS_COUNT! entries) が揃いません。
        echo [WARN] Narwhal relay は PK-pinning 必須のため、seed 接続を skip して solo mode で起動します。
        echo        config\seed-pubkeys.txt に同じ数の ML-DSA-65 公開鍵を追加すると接続を試みます。
    )
)

echo 起動パラメータ
echo   Config : %CONFIG%
echo   Genesis: %GENESIS%
if "!USE_SEEDS!"=="1" (
    echo   Seeds  : !SEEDS! (with !PUBKEYS_COUNT! pinned pubkey^(s^))
) else (
    echo   Seeds  : (none — solo self-host mode^)
)
echo   Data   : %DATA_DIR%
echo   RPC    : http://localhost:3001
echo   P2P    : 6691
echo.
echo ^> ノードを起動します...
echo   (停止するには Ctrl+C または このウインドウを閉じる)
echo.

set MISAKA_RPC_AUTH_MODE=open

if "!USE_SEEDS!"=="1" (
    "%BINARY%" --config "%CONFIG%" --data-dir "%DATA_DIR%" --genesis-path "%GENESIS%" --seeds "!SEEDS!" --seed-pubkeys "!SEED_PUBKEYS!" --chain-id 2
) else (
    "%BINARY%" --config "%CONFIG%" --data-dir "%DATA_DIR%" --genesis-path "%GENESIS%" --chain-id 2
)

echo.
echo --- 終了しました ---
endlocal
pause
