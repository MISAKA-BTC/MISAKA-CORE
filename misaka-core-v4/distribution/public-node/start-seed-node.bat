@echo off
set SCRIPT_DIR=%~dp0
cd /d "%SCRIPT_DIR%"
"%SCRIPT_DIR%misaka-launcher.exe" --profile seed
if errorlevel 1 pause
