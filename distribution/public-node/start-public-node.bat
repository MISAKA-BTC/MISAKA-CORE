@echo off
REM ===============================================================
REM   MISAKA Testnet - Public Node (Windows)
REM   Double-click to run.
REM ===============================================================

chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion
title MISAKA Testnet - Public Node

echo ===============================================================
echo   MISAKA Testnet - Public Node  ^(Windows^)
echo   PQ Signature: ML-DSA-65 ^(FIPS 204^)
echo   Consensus:    Mysticeti-equivalent DAG ^(Bullshark^)
echo ===============================================================
echo.

set "SCRIPT_DIR=%~dp0"
set "BINARY=!SCRIPT_DIR!misaka-node.exe"
set "CONFIG=!SCRIPT_DIR!config\public-node.toml"
set "GENESIS=!SCRIPT_DIR!config\genesis_committee.toml"
set "SEEDS_FILE=!SCRIPT_DIR!config\seeds.txt"
set "SEED_PUBKEYS_FILE=!SCRIPT_DIR!config\seed-pubkeys.txt"
set "DATA_DIR=!SCRIPT_DIR!misaka-data"

REM --- Pre-flight checks -----------------------------------------
if not exist "!BINARY!" (
    echo [ERROR] misaka-node.exe not found:
    echo    !BINARY!
    echo    Extract the release archive and try again.
    echo.
    pause
    exit /b 1
)
if not exist "!CONFIG!" (
    echo [ERROR] Config not found: config\public-node.toml
    pause
    exit /b 1
)
if not exist "!GENESIS!" (
    echo [ERROR] genesis_committee.toml not found
    pause
    exit /b 1
)

set /a VALIDATOR_SLOTS=0
for /f %%a in ('find /c "[[committee.validators]]" ^< "!GENESIS!"') do set "VALIDATOR_SLOTS=%%a"
if not "!VALIDATOR_SLOTS!"=="1" (
    echo [ERROR] This package is for single-operator genesis only ^(validators=!VALIDATOR_SLOTS!^)
    pause
    exit /b 1
)
set "GENESIS_VALIDATOR_PK="
for /f "tokens=2 delims==" %%a in ('findstr /c:"public_key" "!GENESIS!"') do (
    if not defined GENESIS_VALIDATOR_PK (
        set "RAW=%%a"
        set "GENESIS_VALIDATOR_PK=!RAW:"=!"
        set "GENESIS_VALIDATOR_PK=!GENESIS_VALIDATOR_PK: =!"
    )
)
if not defined GENESIS_VALIDATOR_PK (
    echo [ERROR] Could not read public_key from genesis_committee.toml
    pause
    exit /b 1
)

REM --- First-run setup -------------------------------------------
if not exist "!DATA_DIR!" mkdir "!DATA_DIR!"
if not exist "!DATA_DIR!\validator.key" (
    echo First run: generating ephemeral observer key ^(validator.key^)
)
REM Redirect to temp files so the 3906-char ML-DSA-65 pubkey hex line
REM is captured reliably (cmd for /f has issues with very long output).
set "EMIT_OUT=!TEMP!\misaka_emit_pk_!RANDOM!.txt"
set "EMIT_ERR=!TEMP!\misaka_emit_err_!RANDOM!.txt"
"!BINARY!" --emit-validator-pubkey --data-dir "!DATA_DIR!" --chain-id 2 >"!EMIT_OUT!" 2>"!EMIT_ERR!"
if errorlevel 1 (
    echo [ERROR] misaka-node --emit-validator-pubkey failed
    if exist "!EMIT_ERR!" type "!EMIT_ERR!"
    if exist "!EMIT_OUT!" type "!EMIT_OUT!"
    del "!EMIT_OUT!" 2>nul
    del "!EMIT_ERR!" 2>nul
    pause
    exit /b 1
)
set "LOCAL_VALIDATOR_PK="
for /f "usebackq delims=" %%a in (`findstr /b /c:"0x" "!EMIT_OUT!" 2^>nul`) do set "LOCAL_VALIDATOR_PK=%%a"
if not defined LOCAL_VALIDATOR_PK (
    echo [ERROR] Could not read validator public key
    echo         Delete misaka-data\validator.key and try again.
    echo.
    echo   stdout:
    if exist "!EMIT_OUT!" type "!EMIT_OUT!"
    echo.
    echo   stderr:
    if exist "!EMIT_ERR!" type "!EMIT_ERR!"
    del "!EMIT_OUT!" 2>nul
    del "!EMIT_ERR!" 2>nul
    pause
    exit /b 1
)
del "!EMIT_OUT!" 2>nul
del "!EMIT_ERR!" 2>nul
if /I "!LOCAL_VALIDATOR_PK!"=="!GENESIS_VALIDATOR_PK!" (
    echo [ERROR] validator.key matches genesis validator.
    echo         This package is observer-only. Delete misaka-data\validator.key and restart.
    pause
    exit /b 1
)

REM --- Read seeds + pubkeys --------------------------------------
REM Both files are required and must have the same number of entries.
set "SEEDS="
set /a SEEDS_COUNT=0
if exist "!SEEDS_FILE!" (
    for /f "usebackq eol=# tokens=*" %%a in ("!SEEDS_FILE!") do (
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
if exist "!SEED_PUBKEYS_FILE!" (
    for /f "usebackq eol=# tokens=*" %%a in ("!SEED_PUBKEYS_FILE!") do (
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
if !SEEDS_COUNT! EQU 0 (
    if !PUBKEYS_COUNT! EQU 0 (
        echo [ERROR] seeds.txt and seed-pubkeys.txt are empty.
        echo         This package requires seeds to join the network.
        pause
        exit /b 1
    ) else (
        echo [ERROR] seeds.txt ^(0^) and seed-pubkeys.txt ^(!PUBKEYS_COUNT!^) count mismatch.
        pause
        exit /b 1
    )
) else (
    if !SEEDS_COUNT! EQU !PUBKEYS_COUNT! (
        set "USE_SEEDS=1"
    ) else (
        echo [ERROR] seeds.txt ^(!SEEDS_COUNT!^) and seed-pubkeys.txt ^(!PUBKEYS_COUNT!^) count mismatch.
        pause
        exit /b 1
    )
)

set "RELAY_ADDR="
for /f "tokens=2 delims==" %%a in ('findstr /c:"network_address" "!GENESIS!"') do (
    if not defined RELAY_ADDR (
        set "RAW=%%a"
        set "RELAY_ADDR=!RAW:"=!"
        set "RELAY_ADDR=!RELAY_ADDR: =!"
    )
)
if not defined RELAY_ADDR set "RELAY_ADDR=(unknown)"

echo Startup parameters
echo   Config : !CONFIG!
echo   Genesis: !GENESIS!
if "!USE_SEEDS!"=="1" (
    echo   Seeds  : !SEEDS! ^(with !PUBKEYS_COUNT! pinned pubkey^(s^)^)
)
echo   Data   : !DATA_DIR!
echo   RPC    : http://localhost:3001
echo   Relay  : !RELAY_ADDR! ^(from genesis^)
echo.
echo Starting node...
echo   ^(Press Ctrl+C or close this window to stop^)
echo.

set MISAKA_RPC_AUTH_MODE=open
set RUST_BACKTRACE=1

if "!USE_SEEDS!"=="1" (
    "!BINARY!" --config "!CONFIG!" --data-dir "!DATA_DIR!" --genesis-path "!GENESIS!" --seeds "!SEEDS!" --seed-pubkeys "!SEED_PUBKEYS!" --chain-id 2
) else (
    "!BINARY!" --config "!CONFIG!" --data-dir "!DATA_DIR!" --genesis-path "!GENESIS!" --chain-id 2
)

set "EXIT_CODE=!ERRORLEVEL!"
echo.
if not "!EXIT_CODE!"=="0" (
    echo [ERROR] Node exited with code !EXIT_CODE!
    echo         Check the output above for error details.
) else (
    echo Node stopped normally.
)
echo.
endlocal
pause
