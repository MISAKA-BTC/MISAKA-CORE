@echo off
chcp 65001 >nul 2>&1
title MISAKA Testnet - Seed Node

set "SCRIPT_DIR=%~dp0"
set "BINARY=%SCRIPT_DIR%misaka-node.exe"
set "CONFIG=%SCRIPT_DIR%config\seed-node.toml"

if not exist "%BINARY%" (
    echo ERROR: misaka-node.exe が見つかりません
    pause
    exit /b 1
)

echo ================================================================
echo   MISAKA Testnet - Seed Node
echo ================================================================
echo.
echo Config : %CONFIG%
echo P2P    : 6690 (seed)
echo RPC    : http://localhost:3001
echo.

set MISAKA_RPC_AUTH_MODE=open

"%BINARY%" --config "%CONFIG%" --data-dir "%SCRIPT_DIR%misaka-data" --mode seed --chain-id 2
pause
