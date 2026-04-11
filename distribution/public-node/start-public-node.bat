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

set /a VALIDATOR_SLOTS=0
for /f %%a in ('find /c "[[committee.validators]]" ^< "%GENESIS%"') do set "VALIDATOR_SLOTS=%%a"
if not "%VALIDATOR_SLOTS%"=="1" (
    echo [ERROR] public observer package は single-operator genesis 専用です ^(validators=%VALIDATOR_SLOTS%^)
    echo         multi-validator / committee genesis では operator / self-host validator 用の導線を使ってください。
    pause
    exit /b 1
)
set "GENESIS_VALIDATOR_PK="
for /f "tokens=2 delims==" %%a in ('findstr /c:"public_key" "%GENESIS%"') do (
    if not defined GENESIS_VALIDATOR_PK (
        set "RAW=%%a"
        set "GENESIS_VALIDATOR_PK=!RAW:"=!"
        set "GENESIS_VALIDATOR_PK=!GENESIS_VALIDATOR_PK: =!"
    )
)
if not defined GENESIS_VALIDATOR_PK (
    echo [ERROR] genesis_committee.toml から validator public_key を取得できません
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
set "LOCAL_VALIDATOR_PK="
for /f %%a in ('"%BINARY%" --emit-validator-pubkey --data-dir "%DATA_DIR%" --chain-id 2 2^>nul') do (
    if not defined LOCAL_VALIDATOR_PK set "LOCAL_VALIDATOR_PK=%%a"
)
if not defined LOCAL_VALIDATOR_PK (
    echo [ERROR] validator.key の公開鍵を取得できませんでした
    echo         misaka-data\validator.key を確認し、必要なら削除して再生成してください。
    pause
    exit /b 1
)
if /I "%LOCAL_VALIDATOR_PK%"=="%GENESIS_VALIDATOR_PK%" (
    echo [ERROR] misaka-data\validator.key が genesis validator と一致しています
    echo         public observer package は observer-only です。operator/shared validator key は使えません。
    echo         misaka-data\validator.key を削除して再起動し、ephemeral observer key を再生成してください。
    pause
    exit /b 1
)

REM --- Read seeds + pubkeys (both required or both skipped) ------
REM Narwhal relay は ML-DSA-65 PK-pinning 必須。stock public-node package
REM では seeds.txt と seed-pubkeys.txt は 1:1 で揃っている前提です。
REM mismatch を warning で握りつぶすと joined のつもりで solo 起動して
REM しまうので、ここでは fail-closed にします。
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
if !SEEDS_COUNT! EQU 0 (
    if !PUBKEYS_COUNT! EQU 0 (
        echo [ERROR] seeds.txt と seed-pubkeys.txt が空です。
        echo [ERROR] public observer package は official/public seed への join 専用です。solo self-host mode には入りません。
        echo         stock package の config を復元して再試行してください。
        exit /b 1
    ) else (
        echo [ERROR] seeds.txt ^(0 entries^) と seed-pubkeys.txt ^(!PUBKEYS_COUNT! entries^) が揃いません。
        echo [ERROR] stock package の current truth が壊れているため、solo fallback せず停止します。
        exit /b 1
    )
) else (
    if !SEEDS_COUNT! EQU !PUBKEYS_COUNT! (
        set "USE_SEEDS=1"
    ) else (
        echo [ERROR] seeds.txt (!SEEDS_COUNT! entries) と seed-pubkeys.txt (!PUBKEYS_COUNT! entries) が揃いません。
        echo [ERROR] stock package の current truth が壊れているため、solo fallback せず停止します。
        echo         config\seeds.txt と config\seed-pubkeys.txt を同じ件数に揃えて再試行してください。
        exit /b 1
    )
)

REM v0.5.11 audit Mid #9: parse the real Narwhal relay address from the
REM first network_address line in genesis_committee.toml. The legacy
REM "p2p.port = 6691" in public-node.toml never matched reality.
set "RELAY_ADDR="
for /f "tokens=2 delims==" %%a in ('findstr /c:"network_address" "%GENESIS%"') do (
    if not defined RELAY_ADDR (
        set "RAW=%%a"
        set "RELAY_ADDR=!RAW:"=!"
        set "RELAY_ADDR=!RELAY_ADDR: =!"
    )
)
if not defined RELAY_ADDR set "RELAY_ADDR=(could not parse genesis network_address)"

echo 起動パラメータ
echo   Config : %CONFIG%
echo   Genesis: %GENESIS%
if "!USE_SEEDS!"=="1" (
    echo   Seeds  : !SEEDS! (with !PUBKEYS_COUNT! pinned pubkey^(s^))
)
echo   Data   : %DATA_DIR%
echo   RPC    : http://localhost:3001
echo   Relay  : !RELAY_ADDR! (from genesis)
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
