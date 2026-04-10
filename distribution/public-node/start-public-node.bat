@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion
title MISAKA Testnet - Public Node

echo ================================================================
echo   MISAKA Testnet - Public Node
echo   PQ Signature: ML-DSA-65 (FIPS 204)
echo ================================================================
echo.

set "SCRIPT_DIR=%~dp0"
set "BINARY=%SCRIPT_DIR%misaka-node.exe"
set "CONFIG=%SCRIPT_DIR%config\public-node.toml"
set "SEEDS_FILE=%SCRIPT_DIR%config\seeds.txt"
set "GENESIS=%SCRIPT_DIR%config\genesis_committee.toml"
set "DATA_DIR=%SCRIPT_DIR%misaka-data"

if not exist "%BINARY%" (
    echo ERROR: misaka-node.exe が見つかりません
    echo Release archive を正しく展開してください。
    pause
    exit /b 1
)

if not exist "%GENESIS%" (
    echo ERROR: genesis_committee.toml が見つかりません
    pause
    exit /b 1
)

if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"
if not exist "%DATA_DIR%\validator.key" (
    if exist "%SCRIPT_DIR%config\bundled-validator.key" (
        copy /Y "%SCRIPT_DIR%config\bundled-validator.key" "%DATA_DIR%\validator.key" >nul
    )
)

:: seeds.txt から読み込み
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

echo Config : %CONFIG%
echo Genesis: %GENESIS%
echo Seeds  : !SEEDS!
echo RPC    : http://localhost:3001
echo P2P    : 6691
echo Data   : %DATA_DIR%
echo.
echo 停止するにはこのウインドウを閉じてください
echo ----------------------------------------------------------------
echo.

set MISAKA_RPC_AUTH_MODE=open

"%BINARY%" --config "%CONFIG%" --data-dir "%DATA_DIR%" --genesis-path "%GENESIS%" --seeds "!SEEDS!" --chain-id 2

endlocal
pause
