@echo off
set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"
"%SCRIPT_DIR%misaka-launcher.exe" self-host
if errorlevel 1 pause
