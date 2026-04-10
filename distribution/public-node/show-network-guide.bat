@echo off
chcp 65001 >nul 2>&1
title MISAKA Network Guide

echo ================================================================
echo   MISAKA Network - ネットワーク診断
echo ================================================================
echo.

echo -- LAN 情報 --
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /i "IPv4"') do (
    echo   LAN IP: %%a
)
echo.

echo -- 必要なポート --
echo.
echo   Public Node : TCP 6691 (推奨)
echo   Seed Node   : TCP 6690 (必須)
echo   Validator   : TCP 6690 (必須)
echo   RPC API     : TCP 3001 (任意)
echo.
echo   * 参加するだけならポート開放は不要です
echo.

echo -- ポートチェック --
for %%p in (6690 6691 3001) do (
    netstat -an 2>nul | findstr ":%%p " >nul 2>&1 && (
        echo   Port %%p: OPEN
    ) || (
        echo   Port %%p: CLOSED
    )
)
echo.
pause
