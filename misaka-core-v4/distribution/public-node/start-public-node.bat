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
set "BUNDLED_KEY=%SCRIPT_DIR%config\bundled-validator.key"
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
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%DATA_DIR%\validator.key" (
    if exist "%BUNDLED_KEY%" (
        echo 初回起動: bundled validator key をコピー中...
        copy /Y "%BUNDLED_KEY%" "%DATA_DIR%\validator.key" >nul
        REM Restrict the validator key to the current user only.
        REM Windows has no chmod, so use icacls to remove inherited ACLs and
        REM grant Full Control to the current user. Keeps the private key
        REM unreadable by other local users on shared machines.
        icacls "%DATA_DIR%\validator.key" /inheritance:r /grant:r "%USERNAME%:F" >nul 2>&1
    )
)

REM --- Read seeds ------------------------------------------------
set "SEEDS="
if exist "%SEEDS_FILE%" (
    for /f "usebackq eol=# tokens=*" %%a in ("%SEEDS_FILE%") do (
        if defined SEEDS (
            set "SEEDS=!SEEDS!,%%a"
        ) else (
            set "SEEDS=%%a"
        )
    )
)

echo 起動パラメータ
echo   Config : %CONFIG%
echo   Genesis: %GENESIS%
echo   Seeds  : !SEEDS!
echo   Data   : %DATA_DIR%
echo   RPC    : http://localhost:3001
echo   P2P    : 6691
echo.
echo ^> ノードを起動します...
echo   (停止するには Ctrl+C または このウインドウを閉じる)
echo.

set MISAKA_RPC_AUTH_MODE=open

if defined SEEDS (
    "%BINARY%" --config "%CONFIG%" --data-dir "%DATA_DIR%" --genesis-path "%GENESIS%" --seeds "!SEEDS!" --chain-id 2
) else (
    "%BINARY%" --config "%CONFIG%" --data-dir "%DATA_DIR%" --genesis-path "%GENESIS%" --chain-id 2
)

echo.
echo --- 終了しました ---
endlocal
pause
