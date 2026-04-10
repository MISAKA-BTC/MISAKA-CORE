@echo off
chcp 65001 >nul 2>&1
title MISAKA Self-Hosted Testnet

echo ================================================================
echo   MISAKA Self-Hosted Testnet (3 Validators, localhost)
echo ================================================================
echo.

set "SCRIPT_DIR=%~dp0"
set "BINARY=%SCRIPT_DIR%misaka-node.exe"
set CHAIN_ID=2
set "GENESIS=%TEMP%\misaka-self-genesis.toml"

if not exist "%BINARY%" (
    echo ERROR: misaka-node.exe が見つかりません
    pause
    exit /b 1
)

set MISAKA_RPC_AUTH_MODE=open

echo ^> Phase 1: Generating validator keys...
mkdir "%TEMP%\misaka-v0" 2>nul
mkdir "%TEMP%\misaka-v1" 2>nul
mkdir "%TEMP%\misaka-v2" 2>nul

for /f "tokens=*" %%a in ('"%BINARY%" --emit-validator-pubkey --data-dir "%TEMP%\misaka-v0" --chain-id %CHAIN_ID% 2^>nul ^| findstr "^0x"') do set PK0=%%a
for /f "tokens=*" %%a in ('"%BINARY%" --emit-validator-pubkey --data-dir "%TEMP%\misaka-v1" --chain-id %CHAIN_ID% 2^>nul ^| findstr "^0x"') do set PK1=%%a
for /f "tokens=*" %%a in ('"%BINARY%" --emit-validator-pubkey --data-dir "%TEMP%\misaka-v2" --chain-id %CHAIN_ID% 2^>nul ^| findstr "^0x"') do set PK2=%%a

echo   V0: %PK0:~0,20%...
echo   V1: %PK1:~0,20%...
echo   V2: %PK2:~0,20%...

echo.
echo ^> Phase 2: Creating genesis committee...

(
echo [committee]
echo epoch = 0
echo.
echo [[committee.validators]]
echo authority_index = 0
echo public_key = "%PK0%"
echo stake = 10000
echo network_address = "127.0.0.1:16110"
echo.
echo [[committee.validators]]
echo authority_index = 1
echo public_key = "%PK1%"
echo stake = 10000
echo network_address = "127.0.0.1:16111"
echo.
echo [[committee.validators]]
echo authority_index = 2
echo public_key = "%PK2%"
echo stake = 10000
echo network_address = "127.0.0.1:16112"
) > "%GENESIS%"

echo.
echo ^> Phase 3: Starting 3 validators...

start "MISAKA-V0" /min "%BINARY%" --data-dir "%TEMP%\misaka-v0" --genesis-path "%GENESIS%" --rpc-port 3010 --p2p-port 16110 --validators 3 --validator-index 0 --chain-id %CHAIN_ID%
start "MISAKA-V1" /min "%BINARY%" --data-dir "%TEMP%\misaka-v1" --genesis-path "%GENESIS%" --rpc-port 3011 --p2p-port 16111 --validators 3 --validator-index 1 --chain-id %CHAIN_ID%
start "MISAKA-V2" /min "%BINARY%" --data-dir "%TEMP%\misaka-v2" --genesis-path "%GENESIS%" --rpc-port 3012 --p2p-port 16112 --validators 3 --validator-index 2 --chain-id %CHAIN_ID%

timeout /t 5 /nobreak >nul

echo.
echo Validators started:
echo   V0: RPC=http://localhost:3010  P2P=16110
echo   V1: RPC=http://localhost:3011  P2P=16111
echo   V2: RPC=http://localhost:3012  P2P=16112
echo.
echo 停止: タスクマネージャーで misaka-node.exe を終了
echo.
pause
