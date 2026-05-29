@echo off
REM =====================================================================
REM  Log Sentinel — launch with full Administrator power.
REM  Re-launches itself elevated if not already admin.
REM =====================================================================

setlocal enableextensions
cd /d "%~dp0"

net session >nul 2>nul
if %errorlevel% neq 0 (
    echo Requesting Administrator rights...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

call "%~dp0LAUNCH.bat"
